from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sentinel.infrastructure.cron import (
    CronError,
    CronSchedule,
    next_run,
    parse_cron,
)


UTC = timezone.utc


def _dt(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)


def test_parse_default_schedule():
    sched = parse_cron("17 03 * * *")
    assert sched.minute == frozenset({17})
    assert sched.hour == frozenset({3})
    assert sched.day_of_month == frozenset(range(1, 32))
    assert sched.month == frozenset(range(1, 13))
    assert sched.day_of_week == frozenset(range(0, 7))


def test_parse_star_slash_step():
    sched = parse_cron("*/15 * * * *")
    assert sched.minute == frozenset({0, 15, 30, 45})


def test_parse_range_and_list():
    sched = parse_cron("0,30 9-11 * * 1-5")
    assert sched.minute == frozenset({0, 30})
    assert sched.hour == frozenset({9, 10, 11})
    assert sched.day_of_week == frozenset({1, 2, 3, 4, 5})


def test_parse_step_inside_range():
    sched = parse_cron("0-30/10 * * * *")
    assert sched.minute == frozenset({0, 10, 20, 30})


def test_parse_dow_seven_is_sunday():
    sched = parse_cron("0 0 * * 7")
    assert sched.day_of_week == frozenset({0})


@pytest.mark.parametrize(
    "expr",
    [
        "60 * * * *",          # minute out of range
        "* 24 * * *",          # hour out of range
        "* * 0 * *",           # dom out of range
        "* * * 13 *",          # month out of range
        "* * * * 8",           # dow out of range
        "1 2 3 4",             # wrong field count
        "* * * * * *",         # wrong field count
        "*/0 * * * *",         # zero step
        "5-3 * * * *",         # reversed range
        "abc * * * *",         # non-numeric
    ],
)
def test_parse_invalid_expressions_raise(expr: str):
    with pytest.raises(CronError):
        parse_cron(expr)


def test_next_run_daily_same_day():
    sched = parse_cron("17 3 * * *")
    after = _dt(2026, 5, 15, 0, 0)
    nxt = next_run(sched, after)
    assert nxt == _dt(2026, 5, 15, 3, 17)


def test_next_run_daily_rolls_to_next_day():
    sched = parse_cron("17 3 * * *")
    after = _dt(2026, 5, 15, 3, 17)  # at the firing minute, must roll
    nxt = next_run(sched, after)
    assert nxt == _dt(2026, 5, 16, 3, 17)


def test_next_run_every_15_minutes():
    sched = parse_cron("*/15 * * * *")
    after = _dt(2026, 5, 15, 12, 5)
    assert next_run(sched, after) == _dt(2026, 5, 15, 12, 15)


def test_next_run_weekday_only_skips_weekend():
    sched = parse_cron("0 9 * * 1-5")  # Mon-Fri 09:00
    # 2026-05-16 is a Saturday
    after = _dt(2026, 5, 16, 0, 0)
    nxt = next_run(sched, after)
    assert nxt == _dt(2026, 5, 18, 9, 0)  # Monday


def test_next_run_requires_tz_aware():
    sched = parse_cron("0 0 * * *")
    with pytest.raises(ValueError):
        next_run(sched, datetime(2026, 5, 15, 0, 0))  # naive


def test_schedule_matches_only_on_field_alignment():
    sched = parse_cron("17 3 * * *")
    assert sched.matches(_dt(2026, 5, 15, 3, 17))
    assert not sched.matches(_dt(2026, 5, 15, 3, 16))
    assert not sched.matches(_dt(2026, 5, 15, 4, 17))


def test_next_run_advances_monotonically():
    sched = parse_cron("0 * * * *")
    after = _dt(2026, 5, 15, 12, 30)
    seen = []
    for _ in range(3):
        after = next_run(sched, after)
        seen.append(after)
    assert seen == [
        _dt(2026, 5, 15, 13, 0),
        _dt(2026, 5, 15, 14, 0),
        _dt(2026, 5, 15, 15, 0),
    ]


def test_impossible_schedule_raises():
    # day-of-month 31 + only February → never fires
    sched = parse_cron("0 0 31 2 *")
    with pytest.raises(CronError):
        next_run(sched, _dt(2026, 5, 15, 0, 0))


def test_minute_resolution_only():
    """Second / microsecond precision in `after` must be ignored."""
    sched = parse_cron("17 3 * * *")
    after = _dt(2026, 5, 15, 3, 17).replace(second=42, microsecond=123)
    nxt = next_run(sched, after)
    # We are inside the firing minute but after second 0 — implementation
    # uses minute granularity, so this rolls forward.
    assert nxt == _dt(2026, 5, 16, 3, 17)
    # Sanity: nxt is at minute boundary.
    assert nxt.second == 0 and nxt.microsecond == 0


def test_cron_schedule_dataclass_is_hashable_for_caching():
    sched = parse_cron("17 3 * * *")
    assert isinstance(sched, CronSchedule)
    # frozen dataclass → usable as dict key
    {sched: 1}
    # equality on expression+fields
    assert sched == parse_cron("17 3 * * *")
