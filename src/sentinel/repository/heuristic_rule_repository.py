from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, Iterator, Optional

from .heuristic_rule import HeuristicRule
from .signature import ThreatLevel


_REQUIRED_FIELDS = {"name", "pattern", "severity"}
_OPTIONAL_FIELDS = {"description"}
_ALLOWED_FIELDS = _REQUIRED_FIELDS | _OPTIONAL_FIELDS


class HeuristicRuleValidationError(ValueError):
    """Raised when a heuristic rule entry fails validation."""

    def __init__(self, message: str, *, index: Optional[int] = None) -> None:
        prefix = f"rule[{index}]: " if index is not None else ""
        super().__init__(f"{prefix}{message}")
        self.index = index


def _validate_entry(raw: object, index: int) -> HeuristicRule:
    if not isinstance(raw, dict):
        raise HeuristicRuleValidationError("must be a JSON object", index=index)

    unknown = set(raw.keys()) - _ALLOWED_FIELDS
    if unknown:
        raise HeuristicRuleValidationError(
            f"unknown field(s): {sorted(unknown)}", index=index
        )

    missing = _REQUIRED_FIELDS - raw.keys()
    if missing:
        raise HeuristicRuleValidationError(
            f"missing required field(s): {sorted(missing)}", index=index
        )

    name = raw["name"]
    if not isinstance(name, str) or not name.strip():
        raise HeuristicRuleValidationError(
            "'name' must be a non-empty string", index=index
        )

    pattern_raw = raw["pattern"]
    if not isinstance(pattern_raw, str) or not pattern_raw:
        raise HeuristicRuleValidationError(
            "'pattern' must be a non-empty string", index=index
        )
    try:
        pattern = re.compile(pattern_raw)
    except re.error as exc:
        raise HeuristicRuleValidationError(
            f"'pattern' is not a valid regex: {exc}", index=index
        ) from exc

    severity_raw = raw["severity"]
    if not isinstance(severity_raw, str):
        raise HeuristicRuleValidationError(
            "'severity' must be a string", index=index
        )
    try:
        severity = ThreatLevel(severity_raw)
    except ValueError:
        raise HeuristicRuleValidationError(
            f"'severity' must be one of {[lvl.value for lvl in ThreatLevel]}, "
            f"got {severity_raw!r}",
            index=index,
        ) from None

    description = raw.get("description")
    if description is not None and not isinstance(description, str):
        raise HeuristicRuleValidationError(
            "'description' must be a string when present", index=index
        )

    return HeuristicRule(
        name=name,
        pattern=pattern,
        severity=severity,
        description=description,
    )


class HeuristicRuleRepository:
    """In-memory collection of compiled regex heuristic rules."""

    def __init__(self, rules: Iterable[HeuristicRule]) -> None:
        self._rules: list[HeuristicRule] = []
        seen: set[str] = set()
        for rule in rules:
            if rule.name in seen:
                raise HeuristicRuleValidationError(
                    f"duplicate rule name: {rule.name!r}"
                )
            seen.add(rule.name)
            self._rules.append(rule)

    @classmethod
    def load(cls, path: str | Path) -> "HeuristicRuleRepository":
        path = Path(path)
        with path.open("r", encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise HeuristicRuleValidationError(
                    f"invalid JSON in {path}: {exc.msg} "
                    f"(line {exc.lineno}, col {exc.colno})"
                ) from exc

        if not isinstance(data, list):
            raise HeuristicRuleValidationError(
                "top-level JSON must be a list of rule entries"
            )

        rules = [_validate_entry(entry, idx) for idx, entry in enumerate(data)]
        return cls(rules)

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self) -> Iterator[HeuristicRule]:
        return iter(self._rules)
