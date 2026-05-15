from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from sentinel.infrastructure import (
    DEFAULT_IMAGE,
    DockerSandboxError,
    SandboxLimits,
    build_docker_command,
    run_sandbox,
)


def _fixture_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    archive = tmp_path / "a.bin"
    archive.write_bytes(b"PK\x03\x04")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    return archive, out_dir, rules_dir


def test_build_docker_command_includes_required_hardening_flags(
    tmp_path: Path,
) -> None:
    archive, out_dir, rules_dir = _fixture_paths(tmp_path)
    limits = SandboxLimits(
        timeout_seconds=42,
        tmpfs_bytes=64 * 1024 * 1024,
        memory="128m",
        cpus="0.5",
        pids_limit=64,
        uid=65534,
        max_extracted_bytes=1024,
        max_files=5,
    )
    cmd = build_docker_command(
        image="sentinel/archive-sandbox:test",
        archive_path=archive,
        out_dir=out_dir,
        rules_dir=rules_dir,
        limits=limits,
        container_name="sentinel-archive-test123",
    )

    assert cmd[0] == "docker"
    assert cmd[1] == "run"
    assert "--rm" in cmd
    assert "--name=sentinel-archive-test123" in cmd
    assert "--network=none" in cmd
    assert "--read-only" in cmd
    assert "--cap-drop=ALL" in cmd
    assert "--security-opt=no-new-privileges" in cmd
    assert "--user=65534" in cmd
    assert "--pids-limit=64" in cmd
    assert "--memory=128m" in cmd
    assert "--cpus=0.5" in cmd
    assert any(c.startswith("--tmpfs=/work:") and "size=67108864" in c for c in cmd)
    assert f"--volume={archive}:/in/archive.bin:ro" in cmd
    assert f"--volume={out_dir}:/out" in cmd
    assert f"--volume={rules_dir}:/rules:ro" in cmd
    assert "--env=SENTINEL_MAX_EXTRACTED_BYTES=1024" in cmd
    assert "--env=SENTINEL_MAX_FILES=5" in cmd
    assert cmd[-1] == "sentinel/archive-sandbox:test"


def test_build_docker_command_appends_extra_env(tmp_path: Path) -> None:
    archive, out_dir, rules_dir = _fixture_paths(tmp_path)
    cmd = build_docker_command(
        image=DEFAULT_IMAGE,
        archive_path=archive,
        out_dir=out_dir,
        rules_dir=rules_dir,
        limits=SandboxLimits(),
        container_name="sentinel-archive-x",
        extra_env={"FOO": "bar"},
    )
    assert "--env=FOO=bar" in cmd


def _fake_proc(stdout: str, *, rc: int = 0, stderr: str = "") -> Any:
    return SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)


def test_run_sandbox_parses_json_stdout(tmp_path: Path) -> None:
    archive, out_dir, rules_dir = _fixture_paths(tmp_path)
    payload = {
        "archive_type": "zip",
        "skipped": False,
        "skip_reason": None,
        "files_extracted": 1,
        "findings": [],
        "nested_archives": [],
    }

    def runner(cmd: list[str], *, timeout: int) -> Any:
        assert "docker" == cmd[0]
        return _fake_proc(json.dumps(payload))

    result = run_sandbox(
        image=DEFAULT_IMAGE,
        archive_path=archive,
        out_dir=out_dir,
        rules_dir=rules_dir,
        limits=SandboxLimits(),
        runner=runner,
    )
    assert result.raw == payload
    assert result.returncode == 0


def test_run_sandbox_nonzero_returncode_raises(tmp_path: Path) -> None:
    archive, out_dir, rules_dir = _fixture_paths(tmp_path)

    def runner(cmd: list[str], *, timeout: int) -> Any:
        return _fake_proc("", rc=2, stderr="boom")

    with pytest.raises(DockerSandboxError, match="exited 2"):
        run_sandbox(
            image=DEFAULT_IMAGE,
            archive_path=archive,
            out_dir=out_dir,
            rules_dir=rules_dir,
            limits=SandboxLimits(),
            runner=runner,
        )


def test_run_sandbox_invalid_json_raises(tmp_path: Path) -> None:
    archive, out_dir, rules_dir = _fixture_paths(tmp_path)

    def runner(cmd: list[str], *, timeout: int) -> Any:
        return _fake_proc("not json {")

    with pytest.raises(DockerSandboxError, match="invalid JSON"):
        run_sandbox(
            image=DEFAULT_IMAGE,
            archive_path=archive,
            out_dir=out_dir,
            rules_dir=rules_dir,
            limits=SandboxLimits(),
            runner=runner,
        )


def test_run_sandbox_timeout_translates_to_error(tmp_path: Path) -> None:
    archive, out_dir, rules_dir = _fixture_paths(tmp_path)

    def runner(cmd: list[str], *, timeout: int) -> Any:
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)

    with pytest.raises(DockerSandboxError, match="timed out"):
        run_sandbox(
            image=DEFAULT_IMAGE,
            archive_path=archive,
            out_dir=out_dir,
            rules_dir=rules_dir,
            limits=SandboxLimits(timeout_seconds=1),
            runner=runner,
        )
