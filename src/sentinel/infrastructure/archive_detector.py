from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Optional

_HEADER_READ_BYTES = 512


class ArchiveType(str, Enum):
    ZIP = "zip"
    TAR = "tar"
    GZIP = "gzip"
    BZIP2 = "bzip2"
    XZ = "xz"
    SEVEN_ZIP = "7z"
    RAR = "rar"


_TAR_USTAR_OFFSET = 257
_TAR_USTAR_MAGIC = b"ustar"


def detect_archive_type_from_bytes(head: bytes) -> Optional[ArchiveType]:
    """Return the archive type implied by the leading magic bytes of ``head``.

    Returns ``None`` when nothing matches. The detector errs on the side of
    *underclaiming*: a file is only flagged as an archive when its magic
    bytes are unambiguous.
    """
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08"):
        return ArchiveType.ZIP
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return ArchiveType.SEVEN_ZIP
    if head.startswith(b"Rar!\x1a\x07\x00") or head.startswith(b"Rar!\x1a\x07\x01\x00"):
        return ArchiveType.RAR
    if head.startswith(b"\x1f\x8b"):
        return ArchiveType.GZIP
    if head.startswith(b"BZh"):
        return ArchiveType.BZIP2
    if head.startswith(b"\xfd7zXZ\x00"):
        return ArchiveType.XZ
    if (
        len(head) >= _TAR_USTAR_OFFSET + len(_TAR_USTAR_MAGIC)
        and head[_TAR_USTAR_OFFSET : _TAR_USTAR_OFFSET + len(_TAR_USTAR_MAGIC)]
        == _TAR_USTAR_MAGIC
    ):
        return ArchiveType.TAR
    return None


def detect_archive_type(path: str | os.PathLike[str]) -> Optional[ArchiveType]:
    """Read the leading bytes of ``path`` and classify it.

    Returns ``None`` if the file cannot be opened or no archive signature
    matches.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(_HEADER_READ_BYTES)
    except OSError:
        return None
    return detect_archive_type_from_bytes(head)


def is_archive(path: str | os.PathLike[str]) -> bool:
    return detect_archive_type(path) is not None


__all__ = [
    "ArchiveType",
    "detect_archive_type",
    "detect_archive_type_from_bytes",
    "is_archive",
]
