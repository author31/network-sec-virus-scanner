from __future__ import annotations

import json
import logging
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from ..constants import (
    DEFAULT_MAX_EXTRACTED_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_TIMEOUT_SECONDS,
)

logger = logging.getLogger(__name__)

DEFAULT_IMAGE = "sentinel/archive-sandbox:latest"
DEFAULT_TMPFS_BYTES = 512 * 1024 * 1024
DEFAULT_MEMORY = "512m"
DEFAULT_CPUS = "1.0"
DEFAULT_PIDS_LIMIT = 256
DEFAULT_SANDBOX_UID = 65534

CONTAINER_ARCHIVE_PATH = "/in/archive.bin"
CONTAINER_OUT_DIR = "/out"
CONTAINER_RULES_DIR = "/rules"
CONTAINER_WORK_DIR = "/work"


class DockerSandboxError(RuntimeError):
    """Raised when the sandbox container fails to run cleanly."""


@dataclass(frozen=True)
class SandboxLimits:
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    tmpfs_bytes: int = DEFAULT_TMPFS_BYTES
    memory: str = DEFAULT_MEMORY
    cpus: str = DEFAULT_CPUS
    pids_limit: int = DEFAULT_PIDS_LIMIT
    uid: int = DEFAULT_SANDBOX_UID
    max_extracted_bytes: int = DEFAULT_MAX_EXTRACTED_BYTES
    max_files: int = DEFAULT_MAX_FILES


@dataclass(frozen=True)
class SandboxResult:
    raw: dict
    stdout: str
    stderr: str
    returncode: int


def is_docker_available(docker_bin: str = "docker") -> bool:
    return shutil.which(docker_bin) is not None


def build_docker_command(
    *,
    image: str,
    archive_path: Path,
    out_dir: Path,
    rules_dir: Path,
    limits: SandboxLimits,
    container_name: str,
    docker_bin: str = "docker",
    extra_env: Optional[Mapping[str, str]] = None,
) -> list[str]:
    """Compose the ``docker run`` argv for a single archive scan.

    Hardening flags are non-negotiable — every container is launched with
    ``--network=none``, a read-only root filesystem, dropped capabilities,
    ``no-new-privileges``, a non-root UID, and pid / memory / cpu caps.
    """
    cmd: list[str] = [
        docker_bin,
        "run",
        "--rm",
        f"--name={container_name}",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--user={limits.uid}",
        f"--pids-limit={limits.pids_limit}",
        f"--memory={limits.memory}",
        f"--cpus={limits.cpus}",
        f"--tmpfs={CONTAINER_WORK_DIR}:rw,nosuid,nodev,noexec,size={limits.tmpfs_bytes}",
        f"--volume={archive_path}:{CONTAINER_ARCHIVE_PATH}:ro",
        f"--volume={out_dir}:{CONTAINER_OUT_DIR}",
        f"--volume={rules_dir}:{CONTAINER_RULES_DIR}:ro",
        f"--env=SENTINEL_MAX_EXTRACTED_BYTES={limits.max_extracted_bytes}",
        f"--env=SENTINEL_MAX_FILES={limits.max_files}",
    ]
    if extra_env:
        for k, v in extra_env.items():
            cmd.append(f"--env={k}={v}")
    cmd.append(image)
    return cmd


SandboxRunner = Callable[..., "subprocess.CompletedProcess[str]"]


def run_sandbox(
    *,
    image: str,
    archive_path: Path,
    out_dir: Path,
    rules_dir: Path,
    limits: SandboxLimits,
    docker_bin: str = "docker",
    runner: Optional[SandboxRunner] = None,
    extra_env: Optional[Mapping[str, str]] = None,
) -> SandboxResult:
    """Launch a single archive-scan container and return its parsed JSON.

    Raises :class:`DockerSandboxError` if the container exits non-zero,
    times out, or emits invalid JSON.
    """
    name = f"sentinel-archive-{uuid.uuid4().hex[:12]}"
    cmd = build_docker_command(
        image=image,
        archive_path=archive_path,
        out_dir=out_dir,
        rules_dir=rules_dir,
        limits=limits,
        container_name=name,
        docker_bin=docker_bin,
        extra_env=extra_env,
    )
    runner_fn = runner if runner is not None else _default_runner
    try:
        proc = runner_fn(cmd, timeout=limits.timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        _force_kill(docker_bin, name)
        raise DockerSandboxError(
            f"sandbox timed out after {limits.timeout_seconds}s"
        ) from exc

    if proc.returncode != 0:
        raise DockerSandboxError(
            f"sandbox exited {proc.returncode}: {(proc.stderr or '').strip()[:500]}"
        )

    try:
        data: Any = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise DockerSandboxError(
            f"sandbox emitted invalid JSON: {exc}; stdout={proc.stdout[:200]!r}"
        ) from exc
    if not isinstance(data, dict):
        raise DockerSandboxError(
            f"sandbox JSON must be an object, got {type(data).__name__}"
        )
    return SandboxResult(
        raw=data, stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode
    )


def _default_runner(cmd: list[str], *, timeout: int) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )


def _force_kill(docker_bin: str, name: str) -> None:
    try:
        subprocess.run(
            [docker_bin, "kill", name],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


__all__ = [
    "CONTAINER_ARCHIVE_PATH",
    "CONTAINER_OUT_DIR",
    "CONTAINER_RULES_DIR",
    "CONTAINER_WORK_DIR",
    "DEFAULT_IMAGE",
    "DEFAULT_MAX_EXTRACTED_BYTES",
    "DEFAULT_MAX_FILES",
    "DEFAULT_TIMEOUT_SECONDS",
    "DockerSandboxError",
    "SandboxLimits",
    "SandboxResult",
    "build_docker_command",
    "is_docker_available",
    "run_sandbox",
]
