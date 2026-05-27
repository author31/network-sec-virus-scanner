from __future__ import annotations

import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..repository import ThreatLevel

DEFAULT_ENTROPY_THRESHOLD = 0.75
DEFAULT_CHUNK_SIZE = 64 * 1024

DETECTION_METHOD_ENTROPY = "heuristic:high-entropy"


@dataclass(frozen=True)
class EntropyScanResult:
    path: Path
    entropy: float
    detection_method: str
    threat_level: ThreatLevel


def compute_entropy(data: bytes) -> float:
    """Return normalized Shannon entropy of *data* in range [0.0, 1.0].

    An empty input returns 0.0.  The value is the raw Shannon entropy
    (base-2, max 8 bits for byte data) divided by 8.
    """
    length = len(data)
    if length == 0:
        return 0.0

    freq: list[int] = [0] * 256
    for b in data:
        freq[b] += 1

    entropy = 0.0
    for count in freq:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)

    return entropy / 8.0


def scan_file_entropy(
    path: str | os.PathLike[str],
    *,
    threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Optional[EntropyScanResult]:
    """Return an :class:`EntropyScanResult` when *path*'s entropy >= *threshold*.

    Reads the entire file in chunks to build byte-frequency counts, then
    computes the normalised Shannon entropy.  Returns ``None`` for files
    below the threshold.
    """
    if not (0.0 <= threshold <= 1.0):
        raise ValueError("threshold must be in [0.0, 1.0]")

    freq: list[int] = [0] * 256
    length = 0

    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            for b in chunk:
                freq[b] += 1
            length += len(chunk)

    if length == 0:
        return None

    entropy = 0.0
    for count in freq:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)

    normalised = entropy / 8.0

    if normalised < threshold:
        return None

    return EntropyScanResult(
        path=Path(path),
        entropy=normalised,
        detection_method=DETECTION_METHOD_ENTROPY,
        threat_level=ThreatLevel.MEDIUM,
    )
