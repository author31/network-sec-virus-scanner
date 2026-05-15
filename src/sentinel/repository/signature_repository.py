from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Iterator, Optional

from ..infrastructure import BloomFilter
from .signature import Signature, ThreatLevel


_MD5_LEN = 32
_SHA256_LEN = 64
_OPTIONAL_FIELDS = {"md5", "sha256", "hex_pattern", "description"}
_REQUIRED_FIELDS = {"name", "threat_level"}
_ALLOWED_FIELDS = _REQUIRED_FIELDS | _OPTIONAL_FIELDS


class SignatureValidationError(ValueError):
    """Raised when a signature entry fails validation."""

    def __init__(self, message: str, *, index: Optional[int] = None) -> None:
        prefix = f"entry[{index}]: " if index is not None else ""
        super().__init__(f"{prefix}{message}")
        self.index = index


def _is_hex(value: str, *, exact_len: Optional[int] = None) -> bool:
    if exact_len is not None and len(value) != exact_len:
        return False
    if exact_len is None and (len(value) == 0 or len(value) % 2 != 0):
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _validate_entry(raw: object, index: int) -> Signature:
    if not isinstance(raw, dict):
        raise SignatureValidationError("must be a JSON object", index=index)

    unknown = set(raw.keys()) - _ALLOWED_FIELDS
    if unknown:
        raise SignatureValidationError(
            f"unknown field(s): {sorted(unknown)}", index=index
        )

    missing = _REQUIRED_FIELDS - raw.keys()
    if missing:
        raise SignatureValidationError(
            f"missing required field(s): {sorted(missing)}", index=index
        )

    name = raw["name"]
    if not isinstance(name, str) or not name.strip():
        raise SignatureValidationError("'name' must be a non-empty string", index=index)

    threat_raw = raw["threat_level"]
    if not isinstance(threat_raw, str):
        raise SignatureValidationError("'threat_level' must be a string", index=index)
    try:
        threat_level = ThreatLevel(threat_raw)
    except ValueError:
        raise SignatureValidationError(
            f"'threat_level' must be one of "
            f"{[lvl.value for lvl in ThreatLevel]}, got {threat_raw!r}",
            index=index,
        ) from None

    md5 = raw.get("md5")
    if md5 is not None:
        if not isinstance(md5, str) or not _is_hex(md5, exact_len=_MD5_LEN):
            raise SignatureValidationError(
                "'md5' must be a 32-char hex string", index=index
            )
        md5 = md5.lower()

    sha256 = raw.get("sha256")
    if sha256 is not None:
        if not isinstance(sha256, str) or not _is_hex(sha256, exact_len=_SHA256_LEN):
            raise SignatureValidationError(
                "'sha256' must be a 64-char hex string", index=index
            )
        sha256 = sha256.lower()

    hex_pattern = raw.get("hex_pattern")
    if hex_pattern is not None:
        if not isinstance(hex_pattern, str) or not _is_hex(hex_pattern):
            raise SignatureValidationError(
                "'hex_pattern' must be a non-empty even-length hex string",
                index=index,
            )
        hex_pattern = hex_pattern.lower()

    if md5 is None and sha256 is None and hex_pattern is None:
        raise SignatureValidationError(
            "at least one of 'md5', 'sha256', 'hex_pattern' is required",
            index=index,
        )

    description = raw.get("description")
    if description is not None and not isinstance(description, str):
        raise SignatureValidationError(
            "'description' must be a string when present", index=index
        )

    return Signature(
        name=name,
        threat_level=threat_level,
        md5=md5,
        sha256=sha256,
        hex_pattern=hex_pattern,
        description=description,
    )


class SignatureRepository:
    """In-memory signature index built from a JSON file.

    Provides O(1) hash lookups and an iterator over byte-pattern signatures.
    """

    def __init__(
        self,
        signatures: Iterable[Signature],
        *,
        enable_bloom: bool = False,
        bloom_fp_rate: float = 0.01,
    ) -> None:
        self._signatures: list[Signature] = []
        self._md5_index: dict[str, Signature] = {}
        self._sha256_index: dict[str, Signature] = {}
        self._patterns: list[tuple[str, bytes]] = []

        for sig in signatures:
            self._signatures.append(sig)
            if sig.md5 is not None:
                self._md5_index[sig.md5] = sig
            if sig.sha256 is not None:
                self._sha256_index[sig.sha256] = sig
            if sig.hex_pattern is not None:
                self._patterns.append((sig.name, bytes.fromhex(sig.hex_pattern)))

        self._bloom: Optional[BloomFilter] = None
        self._bloom_fp_rate: float = bloom_fp_rate
        if enable_bloom:
            keys = list(self._md5_index.keys()) + list(self._sha256_index.keys())
            self._bloom = BloomFilter(capacity=len(keys), fp_rate=bloom_fp_rate)
            for k in keys:
                self._bloom.add(k)

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        enable_bloom: bool = False,
        bloom_fp_rate: float = 0.01,
    ) -> "SignatureRepository":
        path = Path(path)
        with path.open("r", encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise SignatureValidationError(
                    f"invalid JSON in {path}: {exc.msg} (line {exc.lineno}, col {exc.colno})"
                ) from exc

        if not isinstance(data, list):
            raise SignatureValidationError(
                "top-level JSON must be a list of signature entries"
            )

        signatures = [_validate_entry(entry, idx) for idx, entry in enumerate(data)]
        return cls(
            signatures,
            enable_bloom=enable_bloom,
            bloom_fp_rate=bloom_fp_rate,
        )

    @property
    def bloom_enabled(self) -> bool:
        return self._bloom is not None

    @property
    def bloom(self) -> Optional[BloomFilter]:
        return self._bloom

    def might_contain_hash(self, hex_digest: str) -> bool:
        """Bloom pre-check for a hex digest.

        Returns ``True`` when the bloom is disabled (no information),
        a definitive ``False`` only when the bloom rules the key out.
        """
        if self._bloom is None:
            return True
        return hex_digest.lower() in self._bloom

    def lookup_md5(self, hex_digest: str) -> Optional[Signature]:
        return self._md5_index.get(hex_digest.lower())

    def lookup_sha256(self, hex_digest: str) -> Optional[Signature]:
        return self._sha256_index.get(hex_digest.lower())

    def iter_patterns(self) -> Iterator[tuple[str, bytes]]:
        return iter(self._patterns)

    def __len__(self) -> int:
        return len(self._signatures)

    def __iter__(self) -> Iterator[Signature]:
        return iter(self._signatures)
