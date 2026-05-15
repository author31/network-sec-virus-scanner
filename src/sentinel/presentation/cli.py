from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from ..application import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_MAX_BYTES,
    DEFAULT_SCHEDULE,
    DaemonConfig,
    ENV_API_KEY,
    ENV_SCHEDULE,
    HashScanResult,
    HeuristicMatch,
    PatternScanResult,
    detach,
    resolve_schedule,
    run_daemon,
    scan_file,
    scan_file_heuristic,
    scan_file_patterns,
)
from ..infrastructure import CronError, walk_files
from ..repository import (
    HeuristicRuleRepository,
    HeuristicRuleValidationError,
    SignatureRepository,
    SignatureValidationError,
)
from .report import build_report, default_report_path, write_report

EXIT_CLEAN = 0
EXIT_INFECTED = 1
EXIT_ERROR = 2

DEFAULT_DB_PATH = Path("data/signatures.json")
DEFAULT_RULES_PATH = Path("data/heuristic_rules.example.json")

logger = logging.getLogger("sentinel")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description=(
            "Sentinel virus scanner: hash, byte-pattern, and heuristic scans "
            "over a directory tree."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    scan = sub.add_parser(
        "scan",
        help="Scan a directory for known signatures and heuristic matches.",
        description="Scan DIR recursively and write a report.",
    )
    scan.add_argument("directory", type=Path, help="Directory to scan.")
    scan.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Signature DB JSON path (default: {DEFAULT_DB_PATH}).",
    )
    scan.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_RULES_PATH,
        help=f"Heuristic rules JSON path (default: {DEFAULT_RULES_PATH}).",
    )
    scan.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Report output path (default: sentinel_report_<UTC>.log in CWD).",
    )
    scan.add_argument(
        "--max-size",
        type=int,
        default=None,
        metavar="BYTES",
        help="Skip files larger than BYTES.",
    )
    scan.add_argument(
        "--bloom",
        action="store_true",
        help=(
            "Enable Bloom-filter pre-check before hash-map lookup. "
            "Off by default."
        ),
    )
    scan.add_argument(
        "--bloom-fp-rate",
        type=float,
        default=0.01,
        metavar="RATE",
        help="Target false-positive rate for the Bloom filter (default: 0.01).",
    )
    scan.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log verbosity (-v info, -vv debug).",
    )

    daemon = sub.add_parser(
        "daemon",
        help="Run sentinel as a long-lived background service.",
        description=(
            "Long-running service that triggers signature DB refreshes on a "
            "cron schedule. Use the 'start' subcommand."
        ),
    )
    daemon_sub = daemon.add_subparsers(
        dest="daemon_command", required=True, metavar="DAEMON_COMMAND"
    )
    daemon_start = daemon_sub.add_parser(
        "start",
        help="Start the daemon scheduler in the foreground.",
        description=(
            "Start the in-process Malshare refresh scheduler. By default the "
            "scheduler runs in the foreground so it integrates with systemd "
            "and container supervisors."
        ),
    )
    daemon_start.add_argument(
        "--schedule",
        default=None,
        help=(
            "Cron expression (5 fields, UTC). Falls back to "
            f"${ENV_SCHEDULE} then '{DEFAULT_SCHEDULE}'."
        ),
    )
    daemon_start.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Path to signature DB JSON (default: data/signatures.json).",
    )
    daemon_start.add_argument(
        "--run-now",
        action="store_true",
        help="Perform an immediate fetch on startup before the first tick.",
    )
    daemon_start.add_argument(
        "--detach",
        action="store_true",
        help="Daemonise (double-fork). Default is foreground.",
    )
    daemon_start.add_argument(
        "--pidfile",
        type=Path,
        default=None,
        help="Write the daemon PID to this path; remove on shutdown.",
    )
    daemon_start.add_argument(
        "--threat-level",
        default="medium",
        choices=("low", "medium", "high", "critical"),
        help="Threat level applied to imported Malshare entries.",
    )
    daemon_start.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="HTTP timeout per fetch in seconds.",
    )
    daemon_start.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log verbosity (-v info, -vv debug).",
    )
    return parser


def _configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _err(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)


def _load_signatures(
    path: Path,
    *,
    enable_bloom: bool = False,
    bloom_fp_rate: float = 0.01,
) -> SignatureRepository:
    if not path.exists():
        raise FileNotFoundError(f"signature DB not found: {path}")
    return SignatureRepository.load(
        path,
        enable_bloom=enable_bloom,
        bloom_fp_rate=bloom_fp_rate,
    )


def _load_rules(path: Path) -> HeuristicRuleRepository:
    if not path.exists():
        raise FileNotFoundError(f"heuristic rules not found: {path}")
    return HeuristicRuleRepository.load(path)


def _scan_directory(
    directory: Path,
    signatures: SignatureRepository,
    rules: HeuristicRuleRepository,
    *,
    max_size: Optional[int],
) -> tuple[
    list[HashScanResult],
    list[PatternScanResult],
    list[HeuristicMatch],
    int,
]:
    hash_hits: list[HashScanResult] = []
    pattern_hits: list[PatternScanResult] = []
    heuristic_hits: list[HeuristicMatch] = []
    total = 0

    for path in walk_files(directory, max_file_size=max_size):
        total += 1
        try:
            h = scan_file(path, signatures, chunk_size=DEFAULT_CHUNK_SIZE)
            if h is not None:
                hash_hits.append(h)
            pattern_hits.extend(
                scan_file_patterns(path, signatures, chunk_size=DEFAULT_CHUNK_SIZE)
            )
            heuristic_hits.extend(
                scan_file_heuristic(path, rules, max_bytes=DEFAULT_MAX_BYTES)
            )
        except OSError as exc:
            logger.warning("skipping %s: %s", path, exc)

    return hash_hits, pattern_hits, heuristic_hits, total


def run_scan(args: argparse.Namespace) -> int:
    directory: Path = args.directory
    if not directory.exists():
        _err(f"directory not found: {directory}")
        return EXIT_ERROR
    if not directory.is_dir():
        _err(f"not a directory: {directory}")
        return EXIT_ERROR
    if args.max_size is not None and args.max_size < 0:
        _err("--max-size must be non-negative")
        return EXIT_ERROR
    if not (0.0 < args.bloom_fp_rate < 1.0):
        _err("--bloom-fp-rate must be in (0, 1)")
        return EXIT_ERROR

    try:
        signatures = _load_signatures(
            args.db,
            enable_bloom=args.bloom,
            bloom_fp_rate=args.bloom_fp_rate,
        )
    except FileNotFoundError as exc:
        _err(str(exc))
        return EXIT_ERROR
    except SignatureValidationError as exc:
        _err(f"invalid signature DB: {exc}")
        return EXIT_ERROR

    try:
        rules = _load_rules(args.rules)
    except FileNotFoundError as exc:
        _err(str(exc))
        return EXIT_ERROR
    except HeuristicRuleValidationError as exc:
        _err(f"invalid heuristic rules: {exc}")
        return EXIT_ERROR

    started_at = datetime.now(tz=timezone.utc)
    try:
        hash_hits, pattern_hits, heuristic_hits, total = _scan_directory(
            directory, signatures, rules, max_size=args.max_size
        )
    except OSError as exc:
        _err(f"scan failed: {exc}")
        return EXIT_ERROR
    ended_at = datetime.now(tz=timezone.utc)

    report = build_report(
        hash_results=hash_hits,
        pattern_results=pattern_hits,
        heuristic_matches=heuristic_hits,
        total_files=total,
        started_at=started_at,
        ended_at=ended_at,
    )

    report_path = args.report if args.report is not None else default_report_path(
        now=ended_at
    )
    try:
        written = write_report(report, report_path)
    except OSError as exc:
        _err(f"failed to write report {report_path}: {exc}")
        return EXIT_ERROR

    print(
        f"Scanned {report.total_files} file(s): "
        f"{report.infected_count} infected, "
        f"{report.suspicious_count} suspicious, "
        f"{report.clean_count} clean. "
        f"Report: {written}"
    )

    if report.infected_count > 0 or report.suspicious_count > 0:
        return EXIT_INFECTED
    return EXIT_CLEAN


def run_daemon_start(args: argparse.Namespace) -> int:
    try:
        schedule = resolve_schedule(args.schedule)
    except CronError as exc:
        _err(f"invalid --schedule: {exc}")
        return EXIT_ERROR

    api_key = os.environ.get(ENV_API_KEY, "")
    if not api_key:
        _err(f"{ENV_API_KEY} is not set")
        return EXIT_ERROR

    output = args.output if args.output is not None else Path("data/signatures.json")
    config = DaemonConfig(
        api_key=api_key,
        schedule=schedule,
        output=output,
        run_now=args.run_now,
        pidfile=args.pidfile,
        threat_level=args.threat_level,
        timeout=args.timeout,
    )

    if args.detach:
        detach()

    return run_daemon(config)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(getattr(args, "verbose", 0))

    if args.command == "scan":
        return run_scan(args)
    if args.command == "daemon":
        if args.daemon_command == "start":
            return run_daemon_start(args)
        parser.error(f"unknown daemon command: {args.daemon_command}")
        return EXIT_ERROR

    parser.error(f"unknown command: {args.command}")
    return EXIT_ERROR
