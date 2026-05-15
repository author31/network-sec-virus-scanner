#!/usr/bin/env python3
"""Sandbox entrypoint: detect → extract with caps → scan → emit JSON.

This script runs *inside* an isolated archive-scan container. The host
mounts:

    /in/archive.bin (ro) — the archive to inspect
    /work            — tmpfs, extraction target
    /out             — host-bind, where this script writes nested archives
                       extracted from the input + a copy of ``result.json``
    /rules (ro)      — signature DB + heuristic rules, shared with host

The script never recurses into nested archives itself — they are copied
out so the host can launch a fresh container per layer.
"""
from __future__ import annotations

import bz2
import gzip
import json
import logging
import lzma
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Iterator, Optional

from sentinel.application import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_MAX_BYTES,
    scan_file,
    scan_file_heuristic,
    scan_file_patterns,
)
from sentinel.infrastructure import ArchiveType, detect_archive_type
from sentinel.repository import HeuristicRuleRepository, SignatureRepository

ARCHIVE_PATH = Path("/in/archive.bin")
WORK_DIR = Path("/work")
OUT_DIR = Path("/out")
RULES_DIR = Path("/rules")

DEFAULT_SIG_DB_PATHS = (
    RULES_DIR / "signatures.json",
    RULES_DIR / "signatures.example.json",
)
DEFAULT_RULES_PATHS = (
    RULES_DIR / "heuristic_rules.example.json",
    RULES_DIR / "heuristic_rules.json",
)

EXIT_OK = 0
EXIT_ERROR = 2

logger = logging.getLogger("sentinel.sandbox")


def main() -> int:
    max_bytes = _env_int("SENTINEL_MAX_EXTRACTED_BYTES", 512 * 1024 * 1024)
    max_files = _env_int("SENTINEL_MAX_FILES", 10_000)

    if not ARCHIVE_PATH.is_file():
        _emit({"error": f"archive missing at {ARCHIVE_PATH}"})
        return EXIT_ERROR

    archive_type = detect_archive_type(ARCHIVE_PATH)
    if archive_type is None:
        _emit(_skipped("unsupported-format"))
        return EXIT_OK

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    try:
        extracted, skipped, reason = _extract(
            archive_type, ARCHIVE_PATH, WORK_DIR, max_bytes, max_files
        )
    except Exception as exc:  # noqa: BLE001 - sandbox boundary
        _emit(_skipped(f"extract-error:{type(exc).__name__}:{exc}", archive_type))
        return EXIT_OK

    if skipped:
        _emit(_skipped(reason or "skipped", archive_type, files_extracted=extracted))
        return EXIT_OK

    sig_path = _first_existing(DEFAULT_SIG_DB_PATHS)
    rules_path = _first_existing(DEFAULT_RULES_PATHS)
    if sig_path is None or rules_path is None:
        _emit(_skipped("rules-missing", archive_type, files_extracted=extracted))
        return EXIT_OK

    sig_repo = SignatureRepository.load(sig_path)
    rules_repo = HeuristicRuleRepository.load(rules_path)

    findings: list[dict[str, Any]] = []
    nested: list[dict[str, Any]] = []
    nested_n = 0

    for path in _walk(WORK_DIR):
        rel = str(path.relative_to(WORK_DIR))
        inner_type = detect_archive_type(path)
        if inner_type is not None:
            nested_n += 1
            out_name = f"nested_{nested_n:04d}.bin"
            try:
                shutil.copy2(path, OUT_DIR / out_name)
            except OSError as exc:
                logger.warning("cannot copy nested archive %s: %s", rel, exc)
                continue
            nested.append(
                {
                    "path": rel,
                    "out_file": out_name,
                    "archive_type": inner_type.value,
                }
            )
            continue
        try:
            findings.extend(_scan_one(path, rel, sig_repo, rules_repo))
        except OSError as exc:
            logger.warning("skip %s: %s", rel, exc)

    _emit(
        {
            "archive_type": archive_type.value,
            "skipped": False,
            "skip_reason": None,
            "files_extracted": extracted,
            "findings": findings,
            "nested_archives": nested,
        }
    )
    return EXIT_OK


def _scan_one(
    path: Path,
    rel: str,
    sig_repo: SignatureRepository,
    rules_repo: HeuristicRuleRepository,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    h = scan_file(path, sig_repo, chunk_size=DEFAULT_CHUNK_SIZE)
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
    for p in scan_file_patterns(path, sig_repo, chunk_size=DEFAULT_CHUNK_SIZE):
        out.append(
            {
                "path": rel,
                "detection_method": p.detection_method,
                "signature_name": p.signature.name,
                "threat_level": p.signature.threat_level.value,
                "is_heuristic": False,
            }
        )
    for m in scan_file_heuristic(path, rules_repo, max_bytes=DEFAULT_MAX_BYTES):
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


def _extract(
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
        return _extract_compressed_or_tar(
            src, dest, "r:gz", "gz", max_bytes, max_files
        )
    if archive_type == ArchiveType.BZIP2:
        return _extract_compressed_or_tar(
            src, dest, "r:bz2", "bz2", max_bytes, max_files
        )
    if archive_type == ArchiveType.XZ:
        return _extract_compressed_or_tar(
            src, dest, "r:xz", "xz", max_bytes, max_files
        )
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
        proc = subprocess.run(
            cmd, capture_output=True, timeout=30, check=False
        )
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


def _first_existing(candidates: tuple[Path, ...]) -> Optional[Path]:
    for c in candidates:
        if c.is_file():
            return c
    return None


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    try:
        v = int(raw)
    except ValueError:
        return default
    return v if v >= 0 else default


def _skipped(
    reason: str,
    archive_type: Optional[ArchiveType] = None,
    *,
    files_extracted: int = 0,
) -> dict[str, Any]:
    return {
        "archive_type": archive_type.value if archive_type is not None else None,
        "skipped": True,
        "skip_reason": reason,
        "files_extracted": files_extracted,
        "findings": [],
        "nested_archives": [],
    }


def _emit(obj: dict[str, Any]) -> None:
    text = json.dumps(obj)
    sys.stdout.write(text + "\n")
    sys.stdout.flush()
    try:
        with open(OUT_DIR / "result.json", "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(main())
