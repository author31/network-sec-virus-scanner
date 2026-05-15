"""In-process daemon that runs the Malshare refresh on a cron schedule.

The daemon owns:

- a parsed :class:`~sentinel.infrastructure.cron.CronSchedule` (default
  ``17 03 * * *`` UTC),
- a :class:`threading.Event` stop signal wired to SIGTERM / SIGINT for
  graceful shutdown,
- an optional pidfile written at startup and removed on exit.

The fetch itself is delegated to :func:`scripts.fetch_malshare.refresh`,
which writes ``data/signatures.json`` atomically (tempfile + rename) — that
guarantee is why we can let any in-flight fetch finish on shutdown without
risking a partial write.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

# ``scripts/fetch_malshare.py`` is not a package import target — make it
# importable when running under ``uv run sentinel``.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS = _REPO_ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from fetch_malshare import (  # noqa: E402
    DEFAULT_OUTPUT,
    DEFAULT_THREAT_LEVEL,
    DEFAULT_TIMEOUT_SECONDS,
    FetchError,
    MergeStats,
    fetch_getlist,
    refresh as _refresh,
)

from ..infrastructure.cron import CronError, CronSchedule, next_run, parse_cron


DEFAULT_SCHEDULE = "17 03 * * *"
ENV_SCHEDULE = "SENTINEL_SCHEDULE"
ENV_API_KEY = "MALSHARE_API_KEY"

EXIT_OK = 0
EXIT_CONFIG = 2

logger = logging.getLogger("sentinel.daemon")


@dataclass
class DaemonConfig:
    api_key: str
    schedule: CronSchedule
    output: Path = field(default_factory=lambda: Path(DEFAULT_OUTPUT))
    run_now: bool = False
    pidfile: Optional[Path] = None
    threat_level: str = DEFAULT_THREAT_LEVEL
    timeout: int = DEFAULT_TIMEOUT_SECONDS


def resolve_schedule(
    explicit: Optional[str], env: Optional[dict] = None
) -> CronSchedule:
    """Pick a cron schedule from ``--schedule`` > ``$SENTINEL_SCHEDULE`` > default."""

    env = os.environ if env is None else env
    raw = explicit or env.get(ENV_SCHEDULE) or DEFAULT_SCHEDULE
    return parse_cron(raw)


def _install_signal_handlers(
    stop_event: threading.Event,
) -> list[tuple[int, object]]:
    """Install SIGTERM/SIGINT handlers that set ``stop_event``."""

    previous: list[tuple[int, object]] = []

    def _handler(signum, _frame):  # pragma: no cover - exercised via signal
        logger.info("received signal %d, requesting shutdown", signum)
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            prev = signal.signal(sig, _handler)
            previous.append((sig, prev))
        except (ValueError, OSError):
            # ValueError: not in main thread; OSError: signal not available.
            pass
    return previous


def _restore_signal_handlers(handlers: list[tuple[int, object]]) -> None:
    for sig, prev in handlers:
        try:
            signal.signal(sig, prev)
        except (ValueError, OSError):
            pass


def _write_pidfile(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{os.getpid()}\n", encoding="utf-8")


def _remove_pidfile(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.warning("failed to remove pidfile %s: %s", path, exc)


def _do_refresh(
    config: DaemonConfig,
    *,
    refresh_fn: Callable[..., MergeStats],
    fetcher: Callable[..., list],
) -> MergeStats:
    return refresh_fn(
        output=config.output,
        api_key=config.api_key,
        threat_level=config.threat_level,
        timeout=config.timeout,
        fetcher=fetcher,
    )


def run_daemon(
    config: DaemonConfig,
    *,
    refresh_fn: Callable[..., MergeStats] = _refresh,
    fetcher: Callable[..., list] = fetch_getlist,
    clock: Optional[Callable[[], datetime]] = None,
    sleeper: Optional[Callable[[float], bool]] = None,
    stop_event: Optional[threading.Event] = None,
    install_signals: bool = True,
) -> int:
    """Run the daemon loop until ``stop_event`` is set.

    Returns ``0`` on clean shutdown, non-zero on config / scheduler errors.
    Scheduled fetch failures are logged and the loop continues — they do not
    crash the daemon.
    """

    if not config.api_key:
        logger.error("%s is not set; refusing to start", ENV_API_KEY)
        return EXIT_CONFIG

    clock = clock or (lambda: datetime.now(tz=timezone.utc))
    stop_event = stop_event or threading.Event()
    sleeper = sleeper or (lambda secs: stop_event.wait(timeout=secs))

    handlers = _install_signal_handlers(stop_event) if install_signals else []

    pidfile_written = False
    if config.pidfile is not None:
        try:
            _write_pidfile(config.pidfile)
            pidfile_written = True
        except OSError as exc:
            logger.error("failed to write pidfile %s: %s", config.pidfile, exc)
            _restore_signal_handlers(handlers)
            return EXIT_CONFIG

    logger.info(
        "sentinel daemon starting: schedule=%r output=%s pidfile=%s",
        config.schedule.expression,
        config.output,
        config.pidfile,
    )

    try:
        if config.run_now and not stop_event.is_set():
            logger.info("--run-now: performing immediate fetch")
            try:
                stats = _do_refresh(
                    config, refresh_fn=refresh_fn, fetcher=fetcher
                )
                logger.info(
                    "fetch ok: added=%d deduped=%d invalid=%d total=%d",
                    stats.added,
                    stats.skipped_duplicate,
                    stats.skipped_invalid,
                    stats.total,
                )
            except FetchError as exc:
                logger.error("initial fetch failed: %s", exc)

        while not stop_event.is_set():
            now = clock()
            try:
                target = next_run(config.schedule, now)
            except CronError as exc:
                logger.error("schedule resolution failed: %s", exc)
                return EXIT_CONFIG
            delay = max(0.0, (target - now).total_seconds())
            logger.info(
                "next refresh scheduled at %s (in %.0fs)",
                target.isoformat(),
                delay,
            )
            if sleeper(delay):
                break
            if stop_event.is_set():
                break
            try:
                stats = _do_refresh(
                    config, refresh_fn=refresh_fn, fetcher=fetcher
                )
                logger.info(
                    "fetch ok: added=%d deduped=%d invalid=%d total=%d",
                    stats.added,
                    stats.skipped_duplicate,
                    stats.skipped_invalid,
                    stats.total,
                )
            except FetchError as exc:
                logger.error("scheduled fetch failed: %s", exc)
        logger.info("sentinel daemon shutting down cleanly")
        return EXIT_OK
    finally:
        if pidfile_written and config.pidfile is not None:
            _remove_pidfile(config.pidfile)
        _restore_signal_handlers(handlers)


def detach() -> None:
    """Daemonise the current process (double-fork) for ``--detach``.

    The parent exits after the second fork so the daemon survives terminal
    detach. ``stdin`` is redirected to ``/dev/null``; ``stdout`` and
    ``stderr`` are kept so log redirection by the supervisor still works.
    """

    if os.fork() != 0:
        os._exit(0)
    os.setsid()
    if os.fork() != 0:
        os._exit(0)
    with open(os.devnull, "rb", 0) as devnull:
        os.dup2(devnull.fileno(), 0)


__all__ = [
    "DEFAULT_SCHEDULE",
    "DaemonConfig",
    "ENV_API_KEY",
    "ENV_SCHEDULE",
    "EXIT_CONFIG",
    "EXIT_OK",
    "FetchError",
    "detach",
    "resolve_schedule",
    "run_daemon",
]
