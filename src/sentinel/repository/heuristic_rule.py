from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .signature import ThreatLevel


@dataclass(frozen=True)
class HeuristicRule:
    name: str
    pattern: re.Pattern[str]
    severity: ThreatLevel
    description: Optional[str] = None
