from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Signature:
    name: str
    threat_level: ThreatLevel
    md5: Optional[str] = None
    sha256: Optional[str] = None
    hex_pattern: Optional[str] = None
    description: Optional[str] = None

    @property
    def pattern_bytes(self) -> Optional[bytes]:
        if self.hex_pattern is None:
            return None
        return bytes.fromhex(self.hex_pattern)
