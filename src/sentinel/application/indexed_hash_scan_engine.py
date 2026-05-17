from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..repository import (
    FileIndexEntry,
    FileIndexRepository,
    SignatureRepository,
)
from .hash_scan_engine import (
    DEFAULT_CHUNK_SIZE,
    HashScanResult,
    compute_hashes,
    lookup_hashes,
)


def scan_file_indexed(
    path: str | os.PathLike[str],
    signatures: SignatureRepository,
    index: FileIndexRepository,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[Optional[HashScanResult], bool]:
    """Hash-scan ``path`` reusing cached hashes when the index entry is fresh.

    Returns ``(result, cache_hit)``. ``cache_hit`` is ``True`` when the
    cached hashes were reused; ``False`` when hashes were recomputed and
    the index was updated.
    """
    file_path = Path(path)
    st = file_path.stat()
    size = st.st_size
    mtime_ns = st.st_mtime_ns

    entry = index.lookup(file_path, size, mtime_ns)
    if entry is not None:
        md5_hex = entry.md5
        sha256_hex = entry.sha256
        cache_hit = True
    else:
        md5_hex, sha256_hex = compute_hashes(file_path, chunk_size=chunk_size)
        index.upsert(
            FileIndexEntry(
                path=str(file_path),
                size=size,
                mtime_ns=mtime_ns,
                md5=md5_hex,
                sha256=sha256_hex,
                scanned_at=datetime.now(tz=timezone.utc).isoformat(),
            )
        )
        cache_hit = False

    return lookup_hashes(file_path, md5_hex, sha256_hex, signatures), cache_hit
