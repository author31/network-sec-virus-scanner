from __future__ import annotations

import os
import signal
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.infrastructure.pid_file import (
    daemon_status,
    default_pid_path,
    is_process_alive,
    read_pid,
    remove_pid,
    stop_daemon,
    write_pid,
)
from sentinel.infrastructure.filesystem_watcher import DirectoryWatcher


class TestPidFile:
    def test_write_and_read(self, tmp_path: Path) -> None:
        pid_path = tmp_path / "test.pid"
        write_pid(pid_path, 12345)
        assert read_pid(pid_path) == 12345

    def test_read_missing_returns_none(self, tmp_path: Path) -> None:
        assert read_pid(tmp_path / "nope.pid") is None

    def test_read_corrupt_returns_none(self, tmp_path: Path) -> None:
        pid_path = tmp_path / "bad.pid"
        pid_path.write_text("not-a-number")
        assert read_pid(pid_path) is None

    def test_remove_pid_existing(self, tmp_path: Path) -> None:
        pid_path = tmp_path / "test.pid"
        write_pid(pid_path, 1)
        remove_pid(pid_path)
        assert not pid_path.exists()

    def test_remove_pid_missing_no_error(self, tmp_path: Path) -> None:
        remove_pid(tmp_path / "nope.pid")

    def test_is_process_alive_self(self) -> None:
        assert is_process_alive(os.getpid()) is True

    def test_is_process_alive_bogus(self) -> None:
        assert is_process_alive(2**22) is False

    def test_default_pid_path_is_under_tmp(self) -> None:
        p = default_pid_path()
        assert "sentinel" in str(p)

    def test_daemon_status_not_running(self, tmp_path: Path) -> None:
        alive, msg = daemon_status(tmp_path / "nope.pid")
        assert alive is False
        assert "not running" in msg

    def test_daemon_status_running(self, tmp_path: Path) -> None:
        pid_path = tmp_path / "test.pid"
        write_pid(pid_path, os.getpid())
        alive, msg = daemon_status(pid_path)
        assert alive is True
        assert "running" in msg

    def test_daemon_status_stale(self, tmp_path: Path) -> None:
        pid_path = tmp_path / "test.pid"
        write_pid(pid_path, 2**22)
        alive, msg = daemon_status(pid_path)
        assert alive is False
        assert "stale" in msg
        assert not pid_path.exists()

    def test_stop_daemon_no_pid(self, tmp_path: Path) -> None:
        ok, msg = stop_daemon(tmp_path / "nope.pid")
        assert ok is False

    def test_stop_daemon_stale(self, tmp_path: Path) -> None:
        pid_path = tmp_path / "test.pid"
        write_pid(pid_path, 2**22)
        ok, msg = stop_daemon(pid_path)
        assert ok is False
        assert "stale" in msg


class TestDirectoryWatcher:
    def test_start_stop(self, tmp_path: Path) -> None:
        events: list[Path] = []
        watcher = DirectoryWatcher(tmp_path, events.append)
        watcher.start()
        assert watcher.is_alive
        watcher.stop()
        assert not watcher.is_alive

    def test_detects_new_file(self, tmp_path: Path) -> None:
        events: list[Path] = []
        watcher = DirectoryWatcher(tmp_path, events.append)
        watcher.start()
        try:
            (tmp_path / "newfile.txt").write_text("hello")
            time.sleep(0.5)
        finally:
            watcher.stop()
        paths = [e.name for e in events]
        assert "newfile.txt" in paths

    def test_ignores_directory_creation(self, tmp_path: Path) -> None:
        events: list[Path] = []
        watcher = DirectoryWatcher(tmp_path, events.append)
        watcher.start()
        try:
            (tmp_path / "subdir").mkdir()
            time.sleep(0.3)
        finally:
            watcher.stop()
        dir_events = [e for e in events if e.name == "subdir"]
        assert len(dir_events) == 0


class TestDaemonCli:
    def test_daemon_help(self) -> None:
        from sentinel.presentation.cli import build_parser

        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["daemon", "--help"])

    def test_daemon_start_help(self) -> None:
        from sentinel.presentation.cli import build_parser

        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["daemon", "start", "--help"])

    def test_daemon_status_not_running(self, tmp_path: Path) -> None:
        from sentinel.presentation.cli import main

        pid = tmp_path / "test.pid"
        code = main(["daemon", "status", "--pid-file", str(pid)])
        assert code != 0

    def test_daemon_stop_not_running(self, tmp_path: Path) -> None:
        from sentinel.presentation.cli import main

        pid = tmp_path / "test.pid"
        code = main(["daemon", "stop", "--pid-file", str(pid)])
        assert code != 0

    def test_daemon_start_missing_directory(self, tmp_path: Path) -> None:
        from sentinel.presentation.cli import main

        code = main(["daemon", "start", str(tmp_path / "nope")])
        assert code != 0
