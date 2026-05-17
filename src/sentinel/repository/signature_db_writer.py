from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from .signature_repository import SignatureValidationError

DEFAULT_THREAT_LEVEL = "medium"


@dataclass(frozen=True)
class MergeStats:
    added: int
    skipped_duplicate: int
    skipped_invalid: int
    total: int


def _is_hex(value: str, length: int) -> bool:
    if len(value) != length:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def normalize_entry(
    raw: object,
    *,
    fetched_at: str,
    threat_level: str = DEFAULT_THREAT_LEVEL,
) -> Optional[dict]:
    """Normalize a single Malshare record into a signature dict.

    Returns ``None`` if the record carries no usable hash.
    """

    md5: Optional[str] = None
    sha256: Optional[str] = None

    if isinstance(raw, dict):
        for key in ("md5", "MD5"):
            v = raw.get(key)
            if isinstance(v, str) and _is_hex(v, 32):
                md5 = v.lower()
                break
        for key in ("sha256", "SHA256"):
            v = raw.get(key)
            if isinstance(v, str) and _is_hex(v, 64):
                sha256 = v.lower()
                break
    elif isinstance(raw, str):
        if _is_hex(raw, 32):
            md5 = raw.lower()
        elif _is_hex(raw, 64):
            sha256 = raw.lower()

    if md5 is None and sha256 is None:
        return None

    fingerprint = sha256 or md5
    name = f"Malshare-{fingerprint[:12]}"
    entry: dict[str, str] = {
        "name": name,
        "threat_level": threat_level,
        "description": f"Imported from Malshare getlist on {fetched_at}.",
    }
    if md5 is not None:
        entry["md5"] = md5
    if sha256 is not None:
        entry["sha256"] = sha256
    return entry


def _dedupe_keys(entry: dict) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    if isinstance(entry.get("md5"), str):
        keys.add(("md5", entry["md5"].lower()))
    if isinstance(entry.get("sha256"), str):
        keys.add(("sha256", entry["sha256"].lower()))
    return keys


def merge_entries(
    existing: list[dict], incoming: Iterable[dict]
) -> tuple[list[dict], MergeStats]:
    """Merge ``incoming`` into ``existing``, deduping by md5/sha256."""

    seen: set[tuple[str, str]] = set()
    for entry in existing:
        seen.update(_dedupe_keys(entry))

    merged = list(existing)
    added = 0
    skipped_dup = 0
    for entry in incoming:
        keys = _dedupe_keys(entry)
        if not keys:
            skipped_dup += 1
            continue
        if keys & seen:
            skipped_dup += 1
            continue
        seen.update(keys)
        merged.append(entry)
        added += 1
    return merged, MergeStats(
        added=added,
        skipped_duplicate=skipped_dup,
        skipped_invalid=0,
        total=len(merged),
    )


def load_existing_signatures(path: Path) -> list[dict]:
    """Read existing signature DB as a raw JSON list, or ``[]`` if absent."""

    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise SignatureValidationError(
            f"invalid JSON in {path}: {exc.msg} (line {exc.lineno}, col {exc.colno})"
        ) from exc
    if not isinstance(data, list):
        raise SignatureValidationError(
            f"existing {path} is not a JSON list"
        )
    return data


def atomic_write_signatures(path: Path, payload: list[dict]) -> None:
    """Write the merged signature list atomically (tempfile + os.replace)."""

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=False)
            fh.write("\n")
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
