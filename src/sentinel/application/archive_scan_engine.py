"""Archive scan engine.

Orchestrates per-archive scanning:

1.  :func:`detect_archive_type` classifies the input.
2.  An :class:`ArchiveBackend` (Docker sandbox in production, local
    in-process for tests) extracts the archive under resource caps and
    scans the resulting tree with the host's signature / heuristic
    repositories.
3.  Findings are folded into the parent report with **provenance paths**
    of the form ``outer.zip!inner.tar.gz!payload.exe``.
4.  Nested archives discovered during extraction are recursed into in a
    fresh backend invocation, up to :attr:`max_depth`.

Both safety and coverage are handled at the backend boundary: the
host process never executes untrusted unpacker code itself.
"""
from __future__ import annotations

import bz2
import gzip
import logging
import lzma
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, Protocol

from ..constants import DEFAULT_ARCHIVE_DEPTH
from ..infrastructure import (
    ArchiveType,
    SandboxLimits,
    SandboxResult,
    detect_archive_type,
    run_sandbox,
)
from ..infrastructure.docker_sandbox import DEFAULT_IMAGE
from ..repository import (
    HeuristicRuleRepository,
    SignatureRepository,
    ThreatLevel,
)
from .byte_pattern_scan_engine import scan_file_patterns
from .hash_scan_engine import DEFAULT_CHUNK_SIZE, scan_file
from .heuristic_scan_engine import DEFAULT_MAX_BYTES, scan_file_heuristic

logger = logging.getLogger(__name__)

PROVENANCE_SEPARATOR = "!"
DETECTION_METHOD_ARCHIVE_SKIPPED = "archive:skipped"


@dataclass(frozen=True)
class ArchiveFinding:
    """A single detection produced through archive unpacking.

    ``provenance`` is the human-readable path including archive separators
    (e.g. ``/var/scan/outer.zip!inner.tar!eicar.com``). For skipped
    archives, ``is_skipped`` is ``True`` and ``detection_method`` is
    :data:`DETECTION_METHOD_ARCHIVE_SKIPPED`.
    """

    provenance: str
    detection_method: str
    signature_name: str
    threat_level: ThreatLevel
    is_heuristic: bool = False
    is_skipped: bool = False


@dataclass(frozen=True)
class ArchiveScanOutcome:
    findings: tuple[ArchiveFinding, ...] = ()
    archives_unpacked: int = 0
    archives_skipped: int = 0


@dataclass(frozen=True)
class InProcessScanResult:
    """Mirror of the JSON contract emitted by ``sandbox_entrypoint.py``."""

    archive_type: Optional[str]
    skipped: bool
    skip_reason: Optional[str]
    files_extracted: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    nested_archives: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "archive_type": self.archive_type,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "files_extracted": self.files_extracted,
            "findings": list(self.findings),
            "nested_archives": list(self.nested_archives),
        }


class ArchiveBackend(Protocol):
    """Strategy interface for archive unpacking + scanning.

    Production: :class:`DockerArchiveBackend`. Tests: :class:`LocalArchiveBackend`.
    Implementations must mirror the JSON contract documented in
    ``sandbox_entrypoint.py``.
    """

    def run(self, archive_path: Path, out_dir: Path) -> dict[str, Any]:  # pragma: no cover - interface
        ...


class DockerArchiveBackend:
    """Production backend — one Docker container per archive layer."""

    def __init__(
        self,
        *,
        image: str = DEFAULT_IMAGE,
        rules_dir: Path,
        limits: SandboxLimits,
        docker_bin: str = "docker",
        runner: Optional[Any] = None,
    ) -> None:
        self.image = image
        self.rules_dir = rules_dir
        self.limits = limits
        self.docker_bin = docker_bin
        self.runner = runner

    def run(self, archive_path: Path, out_dir: Path) -> dict[str, Any]:
        result: SandboxResult = run_sandbox(
            image=self.image,
            archive_path=archive_path,
            out_dir=out_dir,
            rules_dir=self.rules_dir,
            limits=self.limits,
            docker_bin=self.docker_bin,
            runner=self.runner,
        )
        return result.raw


class LocalArchiveBackend:
    """In-process backend used when Docker is unavailable.

    Performs the same extraction + scanning logic as the container
    entrypoint, but inside the host process — no isolation. Intended for
    tests, CI environments without Docker, and development.
    """

    def __init__(
        self,
        *,
        signatures: SignatureRepository,
        rules: HeuristicRuleRepository,
        max_extracted_bytes: int,
        max_files: int,
    ) -> None:
        self.signatures = signatures
        self.rules = rules
        self.max_extracted_bytes = max_extracted_bytes
        self.max_files = max_files

    def run(self, archive_path: Path, out_dir: Path) -> dict[str, Any]:
        return scan_archive_in_process(
            archive_path=archive_path,
            out_dir=out_dir,
            signatures=self.signatures,
            rules=self.rules,
            max_extracted_bytes=self.max_extracted_bytes,
            max_files=self.max_files,
        ).as_dict()


class ArchiveScanEngine:
    """Orchestrates archive scanning across an :class:`ArchiveBackend`."""

    def __init__(
        self,
        backend: ArchiveBackend,
        *,
        max_depth: int = DEFAULT_ARCHIVE_DEPTH,
    ) -> None:
        if max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        self.backend = backend
        self.max_depth = max_depth

    def scan(self, archive_path: Path) -> ArchiveScanOutcome:
        absolute = Path(archive_path).resolve(strict=False)
        findings: list[ArchiveFinding] = []
        unpacked = 0
        skipped_count = 0

        stack: list[tuple[Path, str, int]] = [(absolute, str(absolute), 1)]
        while stack:
            current_path, provenance, depth = stack.pop()
            with tempfile.TemporaryDirectory(prefix="sentinel-archive-out-") as out_tmp:
                out_dir = Path(out_tmp)
                try:
                    raw = self.backend.run(current_path, out_dir)
                except Exception as exc:  # noqa: BLE001 - sandbox boundary
                    logger.warning("backend failure for %s: %s", provenance, exc)
                    findings.append(
                        _skipped_finding(provenance, f"backend-error:{type(exc).__name__}")
                    )
                    skipped_count += 1
                    continue

                if raw.get("skipped"):
                    findings.append(
                        _skipped_finding(provenance, str(raw.get("skip_reason") or "skipped"))
                    )
                    skipped_count += 1
                    continue

                unpacked += 1

                for f in raw.get("findings", []):
                    findings.append(
                        ArchiveFinding(
                            provenance=f"{provenance}{PROVENANCE_SEPARATOR}{f['path']}",
                            detection_method=str(f["detection_method"]),
                            signature_name=str(f["signature_name"]),
                            threat_level=ThreatLevel(f["threat_level"]),
                            is_heuristic=bool(f.get("is_heuristic", False)),
                        )
                    )

                for nested in raw.get("nested_archives", []):
                    nested_prov = f"{provenance}{PROVENANCE_SEPARATOR}{nested['path']}"
                    out_file = out_dir / nested["out_file"]
                    if depth + 1 > self.max_depth:
                        findings.append(_skipped_finding(nested_prov, "depth-cap"))
                        skipped_count += 1
                        continue
                    if not out_file.is_file():
                        findings.append(
                            _skipped_finding(nested_prov, "nested-missing")
                        )
                        skipped_count += 1
                        continue
                    persist = Path(
                        tempfile.mkstemp(
                            prefix="sentinel-nested-", suffix=".bin"
                        )[1]
                    )
                    shutil.copy2(out_file, persist)
                    stack.append((persist, nested_prov, depth + 1))

        try:
            return ArchiveScanOutcome(
                findings=tuple(findings),
                archives_unpacked=unpacked,
                archives_skipped=skipped_count,
            )
        finally:
            _cleanup_temp_nested(stack)


def _cleanup_temp_nested(stack: Iterable[tuple[Path, str, int]]) -> None:
    for path, _prov, _depth in stack:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def _skipped_finding(provenance: str, reason: str) -> ArchiveFinding:
    detection = f"{DETECTION_METHOD_ARCHIVE_SKIPPED}:{reason}"
    return ArchiveFinding(
        provenance=provenance,
        detection_method=detection,
        signature_name=reason,
        threat_level=ThreatLevel.LOW,
        is_heuristic=False,
        is_skipped=True,
    )


def scan_archive_in_process(
    *,
    archive_path: Path,
    out_dir: Path,
    signatures: SignatureRepository,
    rules: HeuristicRuleRepository,
    max_extracted_bytes: int,
    max_files: int,
) -> InProcessScanResult:
    """Extract ``archive_path`` and scan its contents in the host process.

    The ``out_dir`` is used both as the extraction target and the home of
    any copied-out nested archives. Returns the same shape the Docker
    sandbox entrypoint emits as JSON, so both backends produce identical
    downstream behavior.
    """
    archive_path = Path(archive_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    archive_type = detect_archive_type(archive_path)
    if archive_type is None:
        return _local_skipped("unsupported-format")

    work = out_dir / "_extract"
    work.mkdir(parents=True, exist_ok=True)

    try:
        extracted, was_skipped, reason = _local_extract(
            archive_type, archive_path, work, max_extracted_bytes, max_files
        )
    except Exception as exc:  # noqa: BLE001 - extraction boundary
        return _local_skipped(
            f"extract-error:{type(exc).__name__}:{exc}", archive_type
        )
    if was_skipped:
        return _local_skipped(reason or "skipped", archive_type, files_extracted=extracted)

    findings: list[dict[str, Any]] = []
    nested: list[dict[str, Any]] = []
    nested_n = 0

    for path in _walk(work):
        rel = str(path.relative_to(work))
        inner_type = detect_archive_type(path)
        if inner_type is not None:
            nested_n += 1
            out_name = f"nested_{nested_n:04d}.bin"
            shutil.copy2(path, out_dir / out_name)
            nested.append(
                {
                    "path": rel,
                    "out_file": out_name,
                    "archive_type": inner_type.value,
                }
            )
            continue
        try:
            findings.extend(_local_scan_file(path, rel, signatures, rules))
        except OSError as exc:
            logger.warning("skip %s: %s", rel, exc)

    return InProcessScanResult(
        archive_type=archive_type.value,
        skipped=False,
        skip_reason=None,
        files_extracted=extracted,
        findings=findings,
        nested_archives=nested,
    )


def _local_skipped(
    reason: str,
    archive_type: Optional[ArchiveType] = None,
    *,
    files_extracted: int = 0,
) -> InProcessScanResult:
    return InProcessScanResult(
        archive_type=archive_type.value if archive_type is not None else None,
        skipped=True,
        skip_reason=reason,
        files_extracted=files_extracted,
    )


def _local_scan_file(
    path: Path,
    rel: str,
    signatures: SignatureRepository,
    rules: HeuristicRuleRepository,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    h = scan_file(path, signatures, chunk_size=DEFAULT_CHUNK_SIZE)
    if h is not None:
        out.append(
            {
                "path": rel,
                "detection_method": h.detection_method,
                "signature_name": h.signature.name,
                "threat_level": h.signature.threat_level.value,
                "is_heuristic": False,
            }
        )
    for p in scan_file_patterns(path, signatures, chunk_size=DEFAULT_CHUNK_SIZE):
        out.append(
            {
                "path": rel,
                "detection_method": p.detection_method,
                "signature_name": p.signature.name,
                "threat_level": p.signature.threat_level.value,
                "is_heuristic": False,
            }
        )
    for m in scan_file_heuristic(path, rules, max_bytes=DEFAULT_MAX_BYTES):
        out.append(
            {
                "path": rel,
                "detection_method": m.detection_method,
                "signature_name": m.rule_name,
                "threat_level": m.severity.value,
                "is_heuristic": True,
            }
        )
    return out


def _local_extract(
    archive_type: ArchiveType,
    src: Path,
    dest: Path,
    max_bytes: int,
    max_files: int,
) -> tuple[int, bool, Optional[str]]:
    if archive_type == ArchiveType.ZIP:
        return _extract_zip(src, dest, max_bytes, max_files)
    if archive_type == ArchiveType.TAR:
        return _extract_tar(src, dest, "r:", max_bytes, max_files)
    if archive_type == ArchiveType.GZIP:
        return _extract_compressed_or_tar(src, dest, "r:gz", "gz", max_bytes, max_files)
    if archive_type == ArchiveType.BZIP2:
        return _extract_compressed_or_tar(src, dest, "r:bz2", "bz2", max_bytes, max_files)
    if archive_type == ArchiveType.XZ:
        return _extract_compressed_or_tar(src, dest, "r:xz", "xz", max_bytes, max_files)
    if archive_type == ArchiveType.SEVEN_ZIP:
        return _extract_via_cmd(
            ["7z", "x", str(src), f"-o{dest}", "-y", "-bso0", "-bse0"],
            dest,
            max_bytes,
            max_files,
        )
    if archive_type == ArchiveType.RAR:
        return _extract_via_cmd(
            ["unrar-free", "-x", str(src), str(dest) + "/"],
            dest,
            max_bytes,
            max_files,
        )
    return 0, True, f"unsupported-type:{archive_type.value}"


def _extract_zip(
    src: Path, dest: Path, max_bytes: int, max_files: int
) -> tuple[int, bool, Optional[str]]:
    total_bytes = 0
    total_files = 0
    with zipfile.ZipFile(src, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if _is_unsafe_name(info.filename):
                continue
            if total_bytes + info.file_size > max_bytes:
                return total_files, True, "extracted-bytes-cap"
            if total_files + 1 > max_files:
                return total_files, True, "file-count-cap"
            target = dest / info.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src_fh, open(target, "wb") as out_fh:
                shutil.copyfileobj(src_fh, out_fh, 64 * 1024)
            total_bytes += info.file_size
            total_files += 1
    return total_files, False, None


def _extract_tar(
    src: Path, dest: Path, mode: str, max_bytes: int, max_files: int
) -> tuple[int, bool, Optional[str]]:
    total_bytes = 0
    total_files = 0
    with tarfile.open(src, mode) as tf:
        for member in tf:
            if not member.isfile():
                continue
            if _is_unsafe_name(member.name):
                continue
            if total_bytes + member.size > max_bytes:
                return total_files, True, "extracted-bytes-cap"
            if total_files + 1 > max_files:
                return total_files, True, "file-count-cap"
            tf.extract(member, dest, set_attrs=False, filter="data")
            total_bytes += member.size
            total_files += 1
    return total_files, False, None


def _extract_compressed_or_tar(
    src: Path,
    dest: Path,
    tar_mode: str,
    plain_fmt: str,
    max_bytes: int,
    max_files: int,
) -> tuple[int, bool, Optional[str]]:
    try:
        return _extract_tar(src, dest, tar_mode, max_bytes, max_files)
    except tarfile.ReadError:
        pass
    return _extract_single_compressed(src, dest, plain_fmt, max_bytes)


def _extract_single_compressed(
    src: Path, dest: Path, fmt: str, max_bytes: int
) -> tuple[int, bool, Optional[str]]:
    openers = {"gz": gzip.open, "bz2": bz2.open, "xz": lzma.open}
    opener = openers[fmt]
    out_name = src.stem
    if not out_name or out_name == src.name:
        out_name = f"{src.name}.out"
    target = dest / out_name
    total_bytes = 0
    with opener(src, "rb") as in_fh, open(target, "wb") as out_fh:
        while True:
            chunk = in_fh.read(64 * 1024)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > max_bytes:
                out_fh.close()
                target.unlink(missing_ok=True)
                return 0, True, "extracted-bytes-cap"
            out_fh.write(chunk)
    return 1, False, None


def _extract_via_cmd(
    cmd: list[str], dest: Path, max_bytes: int, max_files: int
) -> tuple[int, bool, Optional[str]]:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
    except FileNotFoundError as exc:
        return 0, True, f"unpacker-missing:{exc.filename}"
    if proc.returncode != 0:
        return 0, True, f"extract-error:rc={proc.returncode}"
    total_files = 0
    total_bytes = 0
    for p in _walk(dest):
        total_files += 1
        total_bytes += p.stat().st_size
        if total_bytes > max_bytes:
            return total_files, True, "extracted-bytes-cap"
        if total_files > max_files:
            return total_files, True, "file-count-cap"
    return total_files, False, None


def _walk(root: Path) -> Iterator[Path]:
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            yield Path(dirpath) / f


def _is_unsafe_name(name: str) -> bool:
    if not name:
        return True
    if name.startswith("/"):
        return True
    return ".." in Path(name).parts


__all__ = [
    "ArchiveBackend",
    "ArchiveFinding",
    "ArchiveScanEngine",
    "ArchiveScanOutcome",
    "DETECTION_METHOD_ARCHIVE_SKIPPED",
    "DEFAULT_ARCHIVE_DEPTH",
    "DockerArchiveBackend",
    "InProcessScanResult",
    "LocalArchiveBackend",
    "PROVENANCE_SEPARATOR",
    "scan_archive_in_process",
]
