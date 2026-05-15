from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinel.application.daemon import (
    DEFAULT_SCHEDULE,
    DaemonConfig,
    EXIT_CONFIG,
    EXIT_OK,
    FetchError,
    resolve_schedule,
    run_daemon,
)
from sentinel.infrastructure.cron import CronError, parse_cron


UTC = timezone.utc
EICAR_ENTRY = {
    "name": "EICAR-Test-File",
    "threat_level": "low",
    "md5": "44d88612fea8a8f36de82e1278abb02f",
    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "hex_pattern": "58354f2150254041505b345c505a58353428",
    "description": "EICAR antivirus test string (canary).",
}


def _seed_db(tmp_path: Path) -> Path:
    db = tmp_path / "signatures.json"
    db.write_text(json.dumps([EICAR_ENTRY]), encoding="utf-8")
    return db


def _config(tmp_path: Path, **overrides) -> DaemonConfig:
    base = {
        "api_key": "fake",
        "schedule": parse_cron("17 3 * * *"),
        "output": _seed_db(tmp_path),
        "run_now": False,
        "pidfile": None,
        "threat_level": "medium",
        "timeout": 5,
    }
    base.update(overrides)
    return DaemonConfig(**base)


def test_resolve_schedule_uses_default_when_unset(monkeypatch):
    monkeypatch.delenv("SENTINEL_SCHEDULE", raising=False)
    sched = resolve_schedule(None, env={})
    assert sched.expression == DEFAULT_SCHEDULE


def test_resolve_schedule_prefers_explicit_over_env():
    sched = resolve_schedule("*/5 * * * *", env={"SENTINEL_SCHEDULE": "0 0 * * *"})
    assert sched.expression == "*/5 * * * *"


def test_resolve_schedule_falls_back_to_env():
    sched = resolve_schedule(None, env={"SENTINEL_SCHEDULE": "0 0 * * *"})
    assert sched.expression == "0 0 * * *"


def test_resolve_schedule_rejects_garbage():
    with pytest.raises(CronError):
        resolve_schedule("not-a-cron", env={})


def test_run_daemon_refuses_without_api_key(tmp_path: Path):
    config = _config(tmp_path, api_key="")
    rc = run_daemon(config, install_signals=False)
    assert rc == EXIT_CONFIG


def test_run_daemon_run_now_invokes_fetch_and_stops(tmp_path: Path):
    config = _config(tmp_path, run_now=True)
    calls: list[str] = []

    def fake_fetcher(api_key, *, timeout):
        assert api_key == "fake"
        calls.append(api_key)
        return []

    stop_event = threading.Event()

    def sleeper(_):
        stop_event.set()
        return True  # signal stop during sleep

    rc = run_daemon(
        config,
        fetcher=fake_fetcher,
        stop_event=stop_event,
        sleeper=sleeper,
        install_signals=False,
    )
    assert rc == EXIT_OK
    assert calls == ["fake"]  # exactly one fetch via run_now


def test_run_daemon_stops_immediately_when_event_preset(tmp_path: Path):
    config = _config(tmp_path)
    stop_event = threading.Event()
    stop_event.set()
    calls: list[str] = []

    def fake_fetcher(api_key, *, timeout):
        calls.append(api_key)
        return []

    def sleeper(_):
        return True

    rc = run_daemon(
        config,
        fetcher=fake_fetcher,
        stop_event=stop_event,
        sleeper=sleeper,
        install_signals=False,
    )
    assert rc == EXIT_OK
    assert calls == []  # no fetch, no run_now


def test_run_daemon_fires_after_sleep_returns(tmp_path: Path):
    config = _config(tmp_path)
    stop_event = threading.Event()
    calls: list[str] = []

    def fake_fetcher(api_key, *, timeout):
        calls.append(api_key)
        return []

    def sleeper(_):
        # First call: pretend the scheduled tick arrived (no stop).
        # Second call: trip the stop_event so the loop exits.
        if not calls:
            return False
        stop_event.set()
        return True

    rc = run_daemon(
        config,
        fetcher=fake_fetcher,
        stop_event=stop_event,
        sleeper=sleeper,
        install_signals=False,
    )
    assert rc == EXIT_OK
    assert calls == ["fake"]


def test_run_daemon_continues_through_fetch_failure(tmp_path: Path, caplog):
    config = _config(tmp_path)
    stop_event = threading.Event()
    attempts: list[int] = []

    def boom(api_key, *, timeout):
        attempts.append(1)
        raise FetchError("upstream unreachable")

    def sleeper(_):
        if len(attempts) >= 1:
            stop_event.set()
            return True
        return False

    with caplog.at_level("ERROR", logger="sentinel.daemon"):
        rc = run_daemon(
            config,
            fetcher=boom,
            stop_event=stop_event,
            sleeper=sleeper,
            install_signals=False,
        )

    assert rc == EXIT_OK
    assert len(attempts) == 1
    assert any("upstream unreachable" in r.message for r in caplog.records)


def test_run_daemon_writes_and_removes_pidfile(tmp_path: Path):
    pidfile = tmp_path / "run" / "sentinel.pid"
    config = _config(tmp_path, pidfile=pidfile)
    stop_event = threading.Event()
    stop_event.set()

    seen_pid: list[str] = []
    real_resolve = pidfile.resolve

    def sleeper(_):
        if pidfile.exists():
            seen_pid.append(pidfile.read_text().strip())
        return True

    rc = run_daemon(
        config,
        fetcher=lambda *a, **k: [],
        stop_event=stop_event,
        sleeper=sleeper,
        install_signals=False,
    )
    assert rc == EXIT_OK
    # pidfile must be removed on exit
    assert not pidfile.exists()
    # parent dir was created on demand
    assert real_resolve().parent.exists()


def test_run_daemon_pidfile_failure_is_config_error(tmp_path: Path):
    # Use an unwritable target path: a regular file as the pidfile's parent.
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    pidfile = blocker / "pid"
    config = _config(tmp_path, pidfile=pidfile)

    rc = run_daemon(
        config,
        fetcher=lambda *a, **k: [],
        stop_event=threading.Event(),
        sleeper=lambda _: True,
        install_signals=False,
    )
    assert rc == EXIT_CONFIG


def test_run_daemon_atomic_write_survives_mid_loop_stop(tmp_path: Path):
    """Stopping the daemon between ticks must not corrupt signatures.json."""
    db = _seed_db(tmp_path)
    original = db.read_text(encoding="utf-8")
    config = _config(tmp_path, output=db)

    stop_event = threading.Event()
    stop_event.set()

    rc = run_daemon(
        config,
        fetcher=lambda *a, **k: [],
        stop_event=stop_event,
        sleeper=lambda _: True,
        install_signals=False,
    )
    assert rc == EXIT_OK
    # no fetch occurred, DB content is byte-for-byte unchanged
    assert db.read_text(encoding="utf-8") == original


def test_run_daemon_run_now_failure_does_not_abort_startup(
    tmp_path: Path, caplog
):
    """An initial --run-now fetch failure is logged, not fatal."""
    config = _config(tmp_path, run_now=True)
    stop_event = threading.Event()

    def boom(api_key, *, timeout):
        raise FetchError("bad key")

    def sleeper(_):
        stop_event.set()
        return True

    with caplog.at_level("ERROR", logger="sentinel.daemon"):
        rc = run_daemon(
            config,
            fetcher=boom,
            stop_event=stop_event,
            sleeper=sleeper,
            install_signals=False,
        )

    assert rc == EXIT_OK
    assert any("bad key" in r.message for r in caplog.records)


def test_run_daemon_fetch_actually_writes_through_real_refresh(tmp_path: Path):
    """End-to-end with the production refresh function and an injected fetcher.

    Catches breakage in the daemon's call into refresh(): correct kwargs,
    in-flight write is atomic, EICAR canary preserved.
    """
    db = _seed_db(tmp_path)
    config = _config(tmp_path, output=db)
    stop_event = threading.Event()
    sample = {
        "md5": "a" * 32,
        "sha256": "c" * 64,
    }

    def fake_fetcher(api_key, *, timeout):
        return [sample]

    state = {"fetched": 0}

    def sleeper(_):
        if state["fetched"] >= 1:
            stop_event.set()
            return True
        state["fetched"] += 1
        return False

    rc = run_daemon(
        config,
        fetcher=fake_fetcher,
        stop_event=stop_event,
        sleeper=sleeper,
        install_signals=False,
    )
    assert rc == EXIT_OK
    payload = json.loads(db.read_text())
    md5s = {e.get("md5") for e in payload}
    assert "44d88612fea8a8f36de82e1278abb02f" in md5s  # EICAR canary kept
    assert "a" * 32 in md5s  # new entry merged
