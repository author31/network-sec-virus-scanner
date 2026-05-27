from __future__ import annotations

import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..infrastructure.filesystem_watcher import DirectoryWatcher
from ..infrastructure.pid_file import default_pid_path, remove_pid, write_pid
from ..repository import HeuristicRuleRepository, SignatureRepository
from .byte_pattern_scan_engine import PatternScanResult, scan_file_patterns
from .entropy_scan_engine import (
    DEFAULT_ENTROPY_THRESHOLD,
    EntropyScanResult,
    scan_file_entropy,
)
from .hash_scan_engine import DEFAULT_CHUNK_SIZE, HashScanResult, scan_file
from .heuristic_scan_engine import DEFAULT_MAX_BYTES, HeuristicMatch, scan_file_heuristic

logger = logging.getLogger("sentinel.daemon")

_TIMESTAMP_FMT = "%Y-%m-%dT%H:%M:%SZ"


class DaemonScanService:
    def __init__(
        self,
        directory: Path,
        signatures: SignatureRepository,
        rules: HeuristicRuleRepository,
        *,
        log_path: Path,
        entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
        pid_path: Optional[Path] = None,
    ) -> None:
        self._directory = directory
        self._signatures = signatures
        self._rules = rules
        self._log_path = log_path
        self._entropy_threshold = entropy_threshold
        self._pid_path = pid_path or default_pid_path()
        self._running = False
        self._watcher: Optional[DirectoryWatcher] = None

    def _scan_file(self, path: Path) -> None:
        ts = datetime.now(tz=timezone.utc).strftime(_TIMESTAMP_FMT)
        findings: list[str] = []

        try:
            h: Optional[HashScanResult] = scan_file(
                path, self._signatures, chunk_size=DEFAULT_CHUNK_SIZE
            )
            if h is not None:
                findings.append(
                    f"{ts} | {path} | {h.detection_method} | "
                    f"{h.signature.name} | {h.signature.threat_level.value}"
                )

            for p in scan_file_patterns(
                path, self._signatures, chunk_size=DEFAULT_CHUNK_SIZE
            ):
                findings.append(
                    f"{ts} | {path} | {p.detection_method} | "
                    f"{p.signature.name} | {p.signature.threat_level.value}"
                )

            for m in scan_file_heuristic(
                path, self._rules, max_bytes=DEFAULT_MAX_BYTES
            ):
                findings.append(
                    f"{ts} | {path} | {m.detection_method} | "
                    f"{m.rule_name} | {m.severity.value}"
                )

            e: Optional[EntropyScanResult] = scan_file_entropy(
                path, threshold=self._entropy_threshold
            )
            if e is not None:
                findings.append(
                    f"{ts} | {path} | {e.detection_method} | "
                    f"high-entropy({e.entropy:.3f}) | {e.threat_level.value}"
                )
        except OSError as exc:
            logger.warning("skipping %s: %s", path, exc)
            return

        if findings:
            self._append_log(findings)
            logger.info("threats found in %s: %d", path, len(findings))
        else:
            logger.debug("clean: %s", path)

    def _append_log(self, lines: list[str]) -> None:
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._log_path, "a", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")

    def _handle_signal(self, signum: int, frame: object) -> None:
        logger.info("received signal %d, shutting down", signum)
        self._running = False

    def run_foreground(self) -> None:
        """Run watcher loop in foreground (used by daemonised child)."""
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        write_pid(self._pid_path)
        self._running = True
        self._watcher = DirectoryWatcher(self._directory, self._scan_file)

        try:
            self._watcher.start()
            logger.info(
                "daemon started (PID %d), watching %s, log -> %s",
                os.getpid(),
                self._directory,
                self._log_path,
            )
            while self._running and self._watcher.is_alive:
                time.sleep(0.5)
        finally:
            self._watcher.stop()
            remove_pid(self._pid_path)
            logger.info("daemon stopped")

    def daemonize(self) -> None:
        """Double-fork to background, then run."""
        pid = os.fork()
        if pid > 0:
            sys.exit(0)

        os.setsid()

        pid = os.fork()
        if pid > 0:
            sys.exit(0)

        sys.stdout.flush()
        sys.stderr.flush()
        devnull = os.open(os.devnull, os.O_RDWR)
        os.dup2(devnull, 0)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        os.close(devnull)

        self.run_foreground()
