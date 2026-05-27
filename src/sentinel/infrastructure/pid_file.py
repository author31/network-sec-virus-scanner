from __future__ import annotations

import errno
import os
import signal
from pathlib import Path

DEFAULT_PID_DIR = Path("/tmp/sentinel")
DEFAULT_PID_FILENAME = "sentinel-daemon.pid"


def default_pid_path() -> Path:
    return DEFAULT_PID_DIR / DEFAULT_PID_FILENAME


def write_pid(path: Path, pid: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid or os.getpid()), encoding="utf-8")


def read_pid(path: Path) -> int | None:
    if not path.exists():
        return None
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


def is_process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError as exc:
        return exc.errno == errno.EPERM


def remove_pid(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def stop_daemon(path: Path) -> tuple[bool, str]:
    """Send SIGTERM to daemon. Return (success, message)."""
    pid = read_pid(path)
    if pid is None:
        return False, f"no PID file at {path}"
    if not is_process_alive(pid):
        remove_pid(path)
        return False, f"stale PID file (process {pid} not running), removed"
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        remove_pid(path)
        return False, f"process {pid} already exited, removed PID file"
    except PermissionError:
        return False, f"permission denied sending SIGTERM to {pid}"
    return True, f"sent SIGTERM to {pid}"


def daemon_status(path: Path) -> tuple[bool, str]:
    pid = read_pid(path)
    if pid is None:
        return False, "daemon not running (no PID file)"
    if is_process_alive(pid):
        return True, f"daemon running (PID {pid})"
    remove_pid(path)
    return False, f"daemon not running (stale PID {pid}, cleaned up)"
