from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from ..application import (
    DEFAULT_ARCHIVE_DEPTH,
    DEFAULT_CHUNK_SIZE,
    DEFAULT_ENTROPY_THRESHOLD,
    DEFAULT_MAX_BYTES,
    ArchiveFinding,
    ArchiveScanEngine,
    DaemonScanService,
    DockerArchiveBackend,
    EntropyScanResult,
    HashScanResult,
    HeuristicMatch,
    LocalArchiveBackend,
    PatternScanResult,
    refresh,
    scan_file,
    scan_file_entropy,
    scan_file_heuristic,
    scan_file_indexed,
    scan_file_patterns,
)
from ..infrastructure import (
    DEFAULT_IMAGE,
    DEFAULT_MAX_EXTRACTED_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_TIMEOUT_SECONDS,
    DockerSandboxError,
    SandboxLimits,
    daemon_status,
    default_pid_path,
    detect_archive_type,
    ensure_sandbox_image,
    is_docker_available,
    stop_daemon,
    walk_files,
    FetchError,
)
from ..repository import (
    DEFAULT_THREAT_LEVEL,
    FileIndexRepository,
    FileIndexValidationError,
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
DEFAULT_INDEX_PATH = Path("data/sentinel_index.json")

BACKEND_ENV_VAR = "SENTINEL_ARCHIVE_BACKEND"
BACKEND_DOCKER = "docker"
BACKEND_LOCAL = "local"

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
        help="Report output path (default: logs/sentinel_report_<UTC>.log in CWD).",
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
        "--use-index",
        action="store_true",
        help=(
            "Enable index-based scan: maintain a local file index "
            "(path -> size, mtime, cached hashes) and reuse cached hashes "
            "for unchanged files. Hash scan only — byte-pattern and "
            "heuristic scans are skipped in this mode."
        ),
    )
    scan.add_argument(
        "--index-file",
        type=Path,
        default=DEFAULT_INDEX_PATH,
        help=f"Local file-index JSON path (default: {DEFAULT_INDEX_PATH}).",
    )
    scan.add_argument(
        "--unpack-archives",
        action="store_true",
        help=(
            "Unpack archives (zip/tar/gzip/7z/rar) in an isolated Docker "
            "sandbox and scan their contents. Off by default."
        ),
    )
    scan.add_argument(
        "--archive-depth",
        type=int,
        default=DEFAULT_ARCHIVE_DEPTH,
        metavar="N",
        help=(
            "Maximum archive-nesting depth to recurse "
            f"(default: {DEFAULT_ARCHIVE_DEPTH})."
        ),
    )
    scan.add_argument(
        "--archive-max-extracted-bytes",
        type=int,
        default=DEFAULT_MAX_EXTRACTED_BYTES,
        metavar="BYTES",
        help=(
            "Maximum cumulative extracted bytes per archive "
            f"(default: {DEFAULT_MAX_EXTRACTED_BYTES})."
        ),
    )
    scan.add_argument(
        "--archive-max-files",
        type=int,
        default=DEFAULT_MAX_FILES,
        metavar="N",
        help=(
            "Maximum number of files extracted per archive "
            f"(default: {DEFAULT_MAX_FILES})."
        ),
    )
    scan.add_argument(
        "--archive-timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=(
            "Per-archive sandbox timeout in seconds "
            f"(default: {DEFAULT_TIMEOUT_SECONDS})."
        ),
    )
    scan.add_argument(
        "--archive-image",
        default=DEFAULT_IMAGE,
        metavar="IMAGE",
        help=(
            "Docker image used for the archive sandbox "
            f"(default: {DEFAULT_IMAGE})."
        ),
    )
    scan.add_argument(
        "--no-build-sandbox",
        action="store_true",
        help=(
            "Do not auto-build the sandbox image if it is missing locally. "
            "By default, the image is built from Dockerfile.archive-sandbox "
            "when not present."
        ),
    )
    scan.add_argument(
        "--entropy-threshold",
        type=float,
        default=DEFAULT_ENTROPY_THRESHOLD,
        metavar="THRESHOLD",
        help=(
            "Normalised Shannon entropy threshold (0.0-1.0). Files at or "
            f"above this level are flagged suspicious (default: {DEFAULT_ENTROPY_THRESHOLD})."
        ),
    )
    scan.add_argument(
        "--no-entropy",
        action="store_true",
        help="Disable entropy-based heuristic analysis.",
    )
    scan.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log verbosity (-v info, -vv debug).",
    )

    update = sub.add_parser(
        "update",
        help="Fetch the Malshare hash list and merge it into the signature DB.",
        description=(
            "Fetch malware hashes from Malshare's getlist endpoint and merge "
            "them into the local signature DB. Requires the MALSHARE_API_KEY "
            "environment variable."
        ),
    )
    update.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Signature DB JSON path (default: {DEFAULT_DB_PATH}).",
    )
    update.add_argument(
        "--threat-level",
        default=DEFAULT_THREAT_LEVEL,
        choices=("low", "medium", "high", "critical"),
        help="Threat level applied to imported Malshare entries.",
    )
    update.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=f"HTTP timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS}).",
    )
    update.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and validate without writing the output file.",
    )
    update.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log verbosity (-v info, -vv debug).",
    )

    daemon = sub.add_parser(
        "daemon",
        help="Run Sentinel as a background daemon watching a directory.",
        description=(
            "Start, stop, or query a long-running Sentinel daemon that "
            "watches a directory for new/modified files and scans them "
            "with all heuristic engines (regex, entropy) enabled by default."
        ),
    )
    daemon_sub = daemon.add_subparsers(
        dest="daemon_action", required=True, metavar="ACTION"
    )

    daemon_start = daemon_sub.add_parser(
        "start", help="Start the daemon in the background."
    )
    daemon_start.add_argument("directory", type=Path, help="Directory to watch.")
    daemon_start.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Signature DB JSON path (default: {DEFAULT_DB_PATH}).",
    )
    daemon_start.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_RULES_PATH,
        help=f"Heuristic rules JSON path (default: {DEFAULT_RULES_PATH}).",
    )
    daemon_start.add_argument(
        "--log",
        type=Path,
        default=None,
        metavar="PATH",
        help="Daemon findings log path (default: logs/sentinel_daemon.log).",
    )
    daemon_start.add_argument(
        "--pid-file",
        type=Path,
        default=None,
        metavar="PATH",
        help=f"PID file path (default: {default_pid_path()}).",
    )
    daemon_start.add_argument(
        "--entropy-threshold",
        type=float,
        default=DEFAULT_ENTROPY_THRESHOLD,
        metavar="THRESHOLD",
        help=(
            "Normalised Shannon entropy threshold (0.0-1.0). "
            f"(default: {DEFAULT_ENTROPY_THRESHOLD})."
        ),
    )
    daemon_start.add_argument(
        "--foreground",
        action="store_true",
        help="Run in the foreground instead of daemonising.",
    )
    daemon_start.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log verbosity (-v info, -vv debug).",
    )

    daemon_stop = daemon_sub.add_parser("stop", help="Stop the running daemon.")
    daemon_stop.add_argument(
        "--pid-file",
        type=Path,
        default=None,
        metavar="PATH",
        help=f"PID file path (default: {default_pid_path()}).",
    )

    daemon_status_cmd = daemon_sub.add_parser(
        "status", help="Check whether the daemon is running."
    )
    daemon_status_cmd.add_argument(
        "--pid-file",
        type=Path,
        default=None,
        metavar="PATH",
        help=f"PID file path (default: {default_pid_path()}).",
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


def _build_archive_engine(
    args: argparse.Namespace,
    signatures: SignatureRepository,
    rules: HeuristicRuleRepository,
) -> Optional[ArchiveScanEngine]:
    """Construct the archive engine when ``--unpack-archives`` is set.

    Returns ``None`` if archive scanning is disabled. Raises
    :class:`RuntimeError` when Docker is required but unavailable.
    """
    if not args.unpack_archives:
        return None

    limits = SandboxLimits(
        timeout_seconds=args.archive_timeout,
        max_extracted_bytes=args.archive_max_extracted_bytes,
        max_files=args.archive_max_files,
    )

    backend_choice = os.environ.get(BACKEND_ENV_VAR, BACKEND_DOCKER).lower()
    if backend_choice == BACKEND_LOCAL:
        backend = LocalArchiveBackend(
            signatures=signatures,
            rules=rules,
            max_extracted_bytes=args.archive_max_extracted_bytes,
            max_files=args.archive_max_files,
        )
    else:
        if not is_docker_available():
            raise RuntimeError(
                "--unpack-archives requires Docker on PATH (or set "
                f"{BACKEND_ENV_VAR}={BACKEND_LOCAL} for an in-process fallback)"
            )
        if not args.no_build_sandbox:
            try:
                ensure_sandbox_image(image=args.archive_image)
            except DockerSandboxError as exc:
                raise RuntimeError(f"sandbox image unavailable: {exc}") from exc
        rules_dir = _common_rules_dir(args.db, args.rules)
        backend = DockerArchiveBackend(
            image=args.archive_image,
            rules_dir=rules_dir,
            limits=limits,
        )

    return ArchiveScanEngine(backend, max_depth=args.archive_depth)


def _common_rules_dir(db_path: Path, rules_path: Path) -> Path:
    """Pick a directory that contains both the signature DB and rules.

    The Docker sandbox mounts this directory read-only at ``/rules``.
    """
    db = db_path.resolve()
    rules = rules_path.resolve()
    if db.parent == rules.parent:
        return db.parent
    return db.parent


def _scan_directory(
    directory: Path,
    signatures: SignatureRepository,
    rules: HeuristicRuleRepository,
    *,
    max_size: Optional[int],
    archive_engine: Optional[ArchiveScanEngine],
    file_index: Optional[FileIndexRepository] = None,
    entropy_threshold: Optional[float] = DEFAULT_ENTROPY_THRESHOLD,
) -> tuple[
    list[HashScanResult],
    list[PatternScanResult],
    list[HeuristicMatch],
    list[EntropyScanResult],
    list[ArchiveFinding],
    int,
    int,
    int,
    int,
]:
    hash_hits: list[HashScanResult] = []
    pattern_hits: list[PatternScanResult] = []
    heuristic_hits: list[HeuristicMatch] = []
    entropy_hits: list[EntropyScanResult] = []
    archive_findings: list[ArchiveFinding] = []
    total = 0
    archives_unpacked = 0
    archives_skipped = 0
    cache_hits = 0

    for path in walk_files(directory, max_file_size=max_size):
        total += 1
        try:
            if archive_engine is not None and detect_archive_type(path) is not None:
                outcome = archive_engine.scan(path)
                archive_findings.extend(outcome.findings)
                archives_unpacked += outcome.archives_unpacked
                archives_skipped += outcome.archives_skipped
                continue

            if file_index is not None:
                h, cache_hit = scan_file_indexed(
                    path, signatures, file_index, chunk_size=DEFAULT_CHUNK_SIZE
                )
                if h is not None:
                    hash_hits.append(h)
                if cache_hit:
                    cache_hits += 1
                continue

            h = scan_file(path, signatures, chunk_size=DEFAULT_CHUNK_SIZE)
            if h is not None:
                hash_hits.append(h)
            pattern_hits.extend(
                scan_file_patterns(path, signatures, chunk_size=DEFAULT_CHUNK_SIZE)
            )
            heuristic_hits.extend(
                scan_file_heuristic(path, rules, max_bytes=DEFAULT_MAX_BYTES)
            )
            if entropy_threshold is not None:
                e = scan_file_entropy(path, threshold=entropy_threshold)
                if e is not None:
                    entropy_hits.append(e)
        except OSError as exc:
            logger.warning("skipping %s: %s", path, exc)

    return (
        hash_hits,
        pattern_hits,
        heuristic_hits,
        entropy_hits,
        archive_findings,
        total,
        archives_unpacked,
        archives_skipped,
        cache_hits,
    )


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
    if args.unpack_archives:
        if args.archive_depth < 1:
            _err("--archive-depth must be >= 1")
            return EXIT_ERROR
        if args.archive_max_extracted_bytes < 0:
            _err("--archive-max-extracted-bytes must be non-negative")
            return EXIT_ERROR
        if args.archive_max_files < 1:
            _err("--archive-max-files must be >= 1")
            return EXIT_ERROR
        if args.archive_timeout < 1:
            _err("--archive-timeout must be >= 1")
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

    try:
        archive_engine = _build_archive_engine(args, signatures, rules)
    except RuntimeError as exc:
        _err(str(exc))
        return EXIT_ERROR

    file_index: Optional[FileIndexRepository] = None
    if args.use_index:
        try:
            file_index = FileIndexRepository.load(args.index_file)
        except FileIndexValidationError as exc:
            _err(f"invalid file index: {exc}")
            return EXIT_ERROR

    entropy_threshold: Optional[float] = None
    if not args.no_entropy:
        if not (0.0 <= args.entropy_threshold <= 1.0):
            _err("--entropy-threshold must be in [0.0, 1.0]")
            return EXIT_ERROR
        entropy_threshold = args.entropy_threshold

    started_at = datetime.now(tz=timezone.utc)
    try:
        (
            hash_hits,
            pattern_hits,
            heuristic_hits,
            entropy_hits,
            archive_findings,
            total,
            archives_unpacked,
            archives_skipped,
            cache_hits,
        ) = _scan_directory(
            directory,
            signatures,
            rules,
            max_size=args.max_size,
            archive_engine=archive_engine,
            file_index=file_index,
            entropy_threshold=entropy_threshold,
        )
    except OSError as exc:
        _err(f"scan failed: {exc}")
        return EXIT_ERROR
    ended_at = datetime.now(tz=timezone.utc)

    if file_index is not None:
        try:
            file_index.save(args.index_file)
        except OSError as exc:
            _err(f"failed to write index {args.index_file}: {exc}")
            return EXIT_ERROR

    report = build_report(
        hash_results=hash_hits,
        pattern_results=pattern_hits,
        heuristic_matches=heuristic_hits,
        entropy_results=entropy_hits,
        archive_findings=archive_findings,
        total_files=total,
        started_at=started_at,
        ended_at=ended_at,
        archives_unpacked=archives_unpacked,
        archives_skipped=archives_skipped,
    )

    report_path = args.report if args.report is not None else default_report_path(
        now=ended_at
    )
    try:
        written = write_report(report, report_path)
    except OSError as exc:
        _err(f"failed to write report {report_path}: {exc}")
        return EXIT_ERROR

    cache_suffix = (
        f" (cache hits: {cache_hits})" if args.use_index else ""
    )
    print(
        f"Scanned {report.total_files} file(s): "
        f"{report.infected_count} infected, "
        f"{report.suspicious_count} suspicious, "
        f"{report.clean_count} clean.{cache_suffix} "
        f"Report: {written}"
    )

    if report.infected_count > 0 or report.suspicious_count > 0:
        return EXIT_INFECTED
    return EXIT_CLEAN


def run_update(args: argparse.Namespace) -> int:
    api_key = os.environ.get("MALSHARE_API_KEY", "")
    if not api_key:
        _err("MALSHARE_API_KEY is not set")
        return EXIT_ERROR

    if args.timeout <= 0:
        _err("--timeout must be positive")
        return EXIT_ERROR

    try:
        stats = refresh(
            output=args.db,
            api_key=api_key,
            threat_level=args.threat_level,
            timeout=args.timeout,
            dry_run=args.dry_run,
        )
    except FetchError as exc:
        _err(f"update failed: {exc}")
        return EXIT_ERROR
    except SignatureValidationError as exc:
        _err(f"merged signature DB failed validation: {exc}")
        return EXIT_ERROR

    prefix = "Signature DB validated (dry-run)" if args.dry_run else (
        f"Signature DB updated -> {args.db}"
    )
    print(
        f"{prefix}: added={stats.added} deduped={stats.skipped_duplicate} "
        f"invalid={stats.skipped_invalid} total={stats.total}"
    )
    return EXIT_CLEAN


DEFAULT_DAEMON_LOG = Path("logs/sentinel_daemon.log")


def run_daemon(args: argparse.Namespace) -> int:
    action: str = args.daemon_action
    pid_path = args.pid_file if args.pid_file is not None else default_pid_path()

    if action == "stop":
        ok, msg = stop_daemon(pid_path)
        print(msg)
        return EXIT_CLEAN if ok else EXIT_ERROR

    if action == "status":
        alive, msg = daemon_status(pid_path)
        print(msg)
        return EXIT_CLEAN if alive else EXIT_ERROR

    directory: Path = args.directory
    if not directory.exists():
        _err(f"directory not found: {directory}")
        return EXIT_ERROR
    if not directory.is_dir():
        _err(f"not a directory: {directory}")
        return EXIT_ERROR

    running, _ = daemon_status(pid_path)
    if running:
        _err("daemon already running (use 'sentinel daemon stop' first)")
        return EXIT_ERROR

    if not (0.0 <= args.entropy_threshold <= 1.0):
        _err("--entropy-threshold must be in [0.0, 1.0]")
        return EXIT_ERROR

    try:
        signatures = _load_signatures(args.db)
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

    log_path = args.log if args.log is not None else DEFAULT_DAEMON_LOG

    service = DaemonScanService(
        directory=directory.resolve(),
        signatures=signatures,
        rules=rules,
        log_path=log_path.resolve(),
        entropy_threshold=args.entropy_threshold,
        pid_path=pid_path,
    )

    if args.foreground:
        print(f"running in foreground, watching {directory}, log -> {log_path}")
        service.run_foreground()
        return EXIT_CLEAN

    print(f"starting daemon, watching {directory}, log -> {log_path}")
    service.daemonize()
    return EXIT_CLEAN


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(getattr(args, "verbose", 0))

    if args.command == "scan":
        return run_scan(args)
    if args.command == "update":
        return run_update(args)
    if args.command == "daemon":
        return run_daemon(args)

    parser.error(f"unknown command: {args.command}")
    return EXIT_ERROR
