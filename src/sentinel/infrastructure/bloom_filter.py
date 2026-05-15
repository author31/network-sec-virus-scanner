from __future__ import annotations

import hashlib
import math
from typing import Iterable


_MIN_BITS = 8


class BloomFilter:
    """Bit-array Bloom filter sized for a target false-positive rate.

    Uses double hashing over SHA-256: two 64-bit halves of the digest
    derive ``k`` indices via ``(h1 + i*h2) mod m``. Items must be ``str``.
    """

    __slots__ = ("_bits", "_m", "_k", "_count", "_capacity", "_fp_rate")

    def __init__(self, capacity: int, fp_rate: float = 0.01) -> None:
        if capacity < 0:
            raise ValueError("capacity must be non-negative")
        if not (0.0 < fp_rate < 1.0):
            raise ValueError("fp_rate must be in (0, 1)")

        n = max(capacity, 1)
        m = math.ceil(-n * math.log(fp_rate) / (math.log(2) ** 2))
        m = max(m, _MIN_BITS)
        k = max(1, round((m / n) * math.log(2)))

        self._m: int = m
        self._k: int = k
        self._bits: bytearray = bytearray((m + 7) // 8)
        self._count: int = 0
        self._capacity: int = capacity
        self._fp_rate: float = fp_rate

    @classmethod
    def from_iterable(
        cls, items: Iterable[str], *, fp_rate: float = 0.01
    ) -> "BloomFilter":
        items_list = list(items)
        bf = cls(capacity=len(items_list), fp_rate=fp_rate)
        for it in items_list:
            bf.add(it)
        return bf

    @property
    def bit_size(self) -> int:
        return self._m

    @property
    def hash_count(self) -> int:
        return self._k

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def fp_rate(self) -> float:
        return self._fp_rate

    def __len__(self) -> int:
        return self._count

    def _h1_h2(self, item: str) -> tuple[int, int]:
        # Hex-digest fast path: md5/sha256 hex strings already carry full
        # entropy, so reuse their bytes directly instead of hashing again.
        if len(item) >= 32:
            try:
                h1 = int(item[:16], 16)
                h2 = int(item[16:32], 16) or 1
                return h1, h2
            except ValueError:
                pass
        digest = hashlib.sha256(item.encode("utf-8")).digest()
        h1 = int.from_bytes(digest[:8], "big")
        h2 = int.from_bytes(digest[8:16], "big") or 1
        return h1, h2

    def add(self, item: str) -> None:
        h1, h2 = self._h1_h2(item)
        bits = self._bits
        m = self._m
        for i in range(self._k):
            idx = (h1 + i * h2) % m
            bits[idx >> 3] |= 1 << (idx & 7)
        self._count += 1

    def __contains__(self, item: object) -> bool:
        if not isinstance(item, str):
            return False
        h1, h2 = self._h1_h2(item)
        bits = self._bits
        m = self._m
        for i in range(self._k):
            idx = (h1 + i * h2) % m
            if not (bits[idx >> 3] >> (idx & 7)) & 1:
                return False
        return True
