from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FileIndexEntry:
    path: str
    size: int
    mtime_ns: int
    md5: str
    sha256: str
    scanned_at: str
