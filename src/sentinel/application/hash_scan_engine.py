from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..repository import Signature, SignatureRepository

DEFAULT_CHUNK_SIZE = 64 * 1024

DETECTION_METHOD_MD5 = "hash:md5"
DETECTION_METHOD_SHA256 = "hash:sha256"


@dataclass(frozen=True)
class HashScanResult:
    path: Path
    signature: Signature
    detection_method: str
    md5: str
    sha256: str


def compute_hashes(
    path: str | os.PathLike[str],
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[str, str]:
    """Stream ``path`` once and return ``(md5_hex, sha256_hex)``.

    Reads the file in ``chunk_size`` blocks so memory use stays bounded
    regardless of file size.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def scan_file(
    path: str | os.PathLike[str],
    repository: SignatureRepository,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Optional[HashScanResult]:
    """Hash ``path`` and look it up in ``repository``.

    SHA-256 is checked before MD5 — the stronger digest wins on a tie.
    Returns ``None`` if neither digest matches.
    """
    md5_hex, sha256_hex = compute_hashes(path, chunk_size=chunk_size)

    sig = repository.lookup_sha256(sha256_hex)
    if sig is not None:
        return HashScanResult(
            path=Path(path),
            signature=sig,
            detection_method=DETECTION_METHOD_SHA256,
            md5=md5_hex,
            sha256=sha256_hex,
        )

    sig = repository.lookup_md5(md5_hex)
    if sig is not None:
        return HashScanResult(
            path=Path(path),
            signature=sig,
            detection_method=DETECTION_METHOD_MD5,
            md5=md5_hex,
            sha256=sha256_hex,
        )

    return None
