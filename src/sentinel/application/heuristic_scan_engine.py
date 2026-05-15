from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..repository import HeuristicRule, HeuristicRuleRepository, ThreatLevel

DEFAULT_MAX_BYTES = 4 * 1024 * 1024
DEFAULT_SNIPPET_RADIUS = 40

DETECTION_METHOD_PREFIX = "heuristic:"


@dataclass(frozen=True)
class HeuristicMatch:
    path: Path
    rule_name: str
    severity: ThreatLevel
    detection_method: str
    snippet: str
    offset: int


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="ignore")


def _make_snippet(text: str, start: int, end: int, radius: int) -> str:
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    return text[lo:hi]


def scan_file_heuristic(
    path: str | os.PathLike[str],
    repository: HeuristicRuleRepository,
    *,
    max_bytes: Optional[int] = DEFAULT_MAX_BYTES,
    snippet_radius: int = DEFAULT_SNIPPET_RADIUS,
) -> list[HeuristicMatch]:
    """Apply each rule's regex to the decoded text of ``path``.

    Bytes are decoded as UTF-8 with ``errors='ignore'`` so binary input
    yields a (possibly empty) string instead of raising. ``max_bytes``
    caps how much of the file is read; pass ``None`` to read the whole
    file.
    """
    if snippet_radius < 0:
        raise ValueError("snippet_radius must be non-negative")
    if max_bytes is not None and max_bytes < 0:
        raise ValueError("max_bytes must be non-negative or None")

    if len(repository) == 0:
        return []

    with open(path, "rb") as fh:
        raw = fh.read() if max_bytes is None else fh.read(max_bytes)

    text = _decode(raw)
    if not text:
        return []

    matches: list[HeuristicMatch] = []
    for rule in repository:
        for m in rule.pattern.finditer(text):
            matches.append(
                _build_match(path, rule, m.start(), m.end(), text, snippet_radius)
            )

    matches.sort(key=lambda r: (r.offset, r.rule_name))
    return matches


def _build_match(
    path: str | os.PathLike[str],
    rule: HeuristicRule,
    start: int,
    end: int,
    text: str,
    radius: int,
) -> HeuristicMatch:
    return HeuristicMatch(
        path=Path(path),
        rule_name=rule.name,
        severity=rule.severity,
        detection_method=f"{DETECTION_METHOD_PREFIX}{rule.name}",
        snippet=_make_snippet(text, start, end, radius),
        offset=start,
    )
