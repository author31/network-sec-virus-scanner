"""Minimal cron expression parser and next-tick calculator.

Supports the standard 5-field cron format used by both system ``cron`` and
Kubernetes ``CronJob`` ``schedule``::

    minute  hour  day-of-month  month  day-of-week

Field grammar per element (comma-separated lists allowed)::

    *                any value
    N                literal integer
    A-B              inclusive range
    */S              step over the full range
    A-B/S            step over a sub-range

Day-of-week is 0-6 (Sunday=0). ``7`` is also accepted as Sunday. Month is
1-12.

Unsupported (intentionally): named aliases (``@daily``, ``MON``, ``JAN``),
last-day markers (``L``), seconds field. Sentinel only needs the daily
``17 03 * * *`` style schedule.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import FrozenSet


class CronError(ValueError):
    """Raised when a cron expression cannot be parsed."""


_FIELD_BOUNDS: tuple[tuple[int, int], ...] = (
    (0, 59),   # minute
    (0, 23),   # hour
    (1, 31),   # day-of-month
    (1, 12),   # month
    (0, 7),    # day-of-week (Sun=0; 7 accepted as alias and normalised)
)
_FIELD_NAMES = ("minute", "hour", "day-of-month", "month", "day-of-week")


@dataclass(frozen=True)
class CronSchedule:
    """Parsed cron expression with pre-computed field value sets."""

    expression: str
    minute: FrozenSet[int]
    hour: FrozenSet[int]
    day_of_month: FrozenSet[int]
    month: FrozenSet[int]
    day_of_week: FrozenSet[int]

    def matches(self, when: datetime) -> bool:
        if when.tzinfo is None:
            raise ValueError("naive datetime is not allowed; pass tz-aware")
        return (
            when.minute in self.minute
            and when.hour in self.hour
            and when.day in self.day_of_month
            and when.month in self.month
            and (when.weekday() + 1) % 7 in self.day_of_week
        )

    def next_after(self, after: datetime) -> datetime:
        """Return the next firing time strictly after ``after``."""

        return next_run(self, after)


def _parse_element(elem: str, lo: int, hi: int, field: str) -> set[int]:
    if elem == "*":
        return set(range(lo, hi + 1))

    step = 1
    body = elem
    if "/" in elem:
        body, step_str = elem.split("/", 1)
        if not step_str.isdigit():
            raise CronError(f"invalid step in {field!r}: {elem!r}")
        step = int(step_str)
        if step <= 0:
            raise CronError(f"step must be positive in {field!r}: {elem!r}")

    if body == "*":
        start, end = lo, hi
    elif "-" in body:
        a, b = body.split("-", 1)
        try:
            start, end = int(a), int(b)
        except ValueError as exc:
            raise CronError(
                f"invalid range in {field!r}: {elem!r}"
            ) from exc
    else:
        try:
            start = int(body)
        except ValueError as exc:
            raise CronError(
                f"invalid value in {field!r}: {elem!r}"
            ) from exc
        end = start

    if start > end:
        raise CronError(
            f"range start > end in {field!r}: {elem!r}"
        )
    if start < lo or end > hi:
        raise CronError(
            f"{field!r} value {elem!r} out of range {lo}-{hi}"
        )
    return set(range(start, end + 1, step))


def _parse_field(field_value: str, lo: int, hi: int, field: str) -> frozenset[int]:
    if not field_value:
        raise CronError(f"empty {field} field")
    values: set[int] = set()
    for elem in field_value.split(","):
        elem = elem.strip()
        if not elem:
            raise CronError(f"empty list element in {field!r}")
        values.update(_parse_element(elem, lo, hi, field))
    return frozenset(values)


def parse_cron(expression: str) -> CronSchedule:
    """Parse a 5-field cron expression. Raises :class:`CronError` on failure."""

    if not isinstance(expression, str):
        raise CronError("cron expression must be a string")
    parts = expression.split()
    if len(parts) != 5:
        raise CronError(
            f"cron expression must have exactly 5 fields, got {len(parts)}: "
            f"{expression!r}"
        )
    fields: list[frozenset[int]] = []
    for value, (lo, hi), name in zip(parts, _FIELD_BOUNDS, _FIELD_NAMES):
        parsed = _parse_field(value, lo, hi, name)
        # Day-of-week: accept 7 as Sunday by normalising.
        if name == "day-of-week":
            parsed = frozenset(v % 7 for v in parsed)
        fields.append(parsed)
    return CronSchedule(
        expression=expression,
        minute=fields[0],
        hour=fields[1],
        day_of_month=fields[2],
        month=fields[3],
        day_of_week=fields[4],
    )


def next_run(schedule: CronSchedule, after: datetime) -> datetime:
    """Return the next firing time strictly after ``after`` for ``schedule``."""

    if after.tzinfo is None:
        raise ValueError("naive datetime is not allowed; pass tz-aware")

    candidate = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
    # Hard bound to avoid infinite loops on impossible expressions
    # (e.g. day=31 + month=2 — cron itself silently skips, we raise).
    horizon = candidate + timedelta(days=366 * 4)
    while candidate <= horizon:
        if (
            candidate.month in schedule.month
            and candidate.day in schedule.day_of_month
            and (candidate.weekday() + 1) % 7 in schedule.day_of_week
            and candidate.hour in schedule.hour
            and candidate.minute in schedule.minute
        ):
            return candidate
        candidate += timedelta(minutes=1)
    raise CronError(
        f"no firing time within 4 years for cron {schedule.expression!r}"
    )


__all__ = ["CronError", "CronSchedule", "next_run", "parse_cron"]
