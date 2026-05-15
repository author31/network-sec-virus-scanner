from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..repository import Signature, SignatureRepository

DEFAULT_CHUNK_SIZE = 64 * 1024

DETECTION_METHOD_PATTERN_HEX = "pattern:hex"


@dataclass(frozen=True)
class PatternScanResult:
    path: Path
    signature: Signature
    detection_method: str
    offset: int


def _collect_patterns(
    repository: SignatureRepository,
) -> list[tuple[Signature, bytes]]:
    patterns: list[tuple[Signature, bytes]] = []
    for sig in repository:
        if sig.hex_pattern is not None:
            patterns.append((sig, bytes.fromhex(sig.hex_pattern)))
    return patterns


def _find_all(haystack: bytes, needle: bytes, start: int) -> Iterable[int]:
    pos = start
    while True:
        idx = haystack.find(needle, pos)
        if idx == -1:
            return
        yield idx
        pos = idx + 1


def scan_file_patterns(
    path: str | os.PathLike[str],
    repository: SignatureRepository,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> list[PatternScanResult]:
    """Scan ``path`` for any hex byte patterns held in ``repository``.

    The file is streamed in ``chunk_size`` blocks. A trailing slice of
    ``max_pattern_len - 1`` bytes is carried into the next iteration so that
    a pattern straddling a chunk boundary is still detected. Matches are
    deduplicated by ``(signature_name, absolute_offset)`` and returned sorted
    by offset.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    patterns = _collect_patterns(repository)
    if not patterns:
        return []

    max_pat_len = max(len(pat) for _, pat in patterns)
    overlap = max_pat_len - 1
    read_size = max(chunk_size, max_pat_len)

    results: list[PatternScanResult] = []
    seen: set[tuple[str, int]] = set()

    buffer = b""
    buffer_base = 0

    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(read_size)
            if not chunk:
                break
            buffer += chunk

            for sig, pat in patterns:
                for idx in _find_all(buffer, pat, 0):
                    abs_off = buffer_base + idx
                    key = (sig.name, abs_off)
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append(
                        PatternScanResult(
                            path=Path(path),
                            signature=sig,
                            detection_method=DETECTION_METHOD_PATTERN_HEX,
                            offset=abs_off,
                        )
                    )

            if overlap and len(buffer) > overlap:
                buffer_base += len(buffer) - overlap
                buffer = buffer[-overlap:]
            elif overlap == 0:
                buffer_base += len(buffer)
                buffer = b""

    results.sort(key=lambda r: (r.offset, r.signature.name))
    return results
