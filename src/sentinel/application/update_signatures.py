from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from ..infrastructure import DEFAULT_TIMEOUT_SECONDS, fetch_getlist
from ..repository import (
    DEFAULT_THREAT_LEVEL,
    MergeStats,
    SignatureRepository,
    SignatureValidationError,
    atomic_write_signatures,
    load_existing_signatures,
    merge_entries,
    normalize_entry,
)

Fetcher = Callable[..., list]


def refresh(
    *,
    output: Path,
    api_key: str,
    threat_level: str = DEFAULT_THREAT_LEVEL,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    fetcher: Optional[Fetcher] = None,
    now: Optional[datetime] = None,
    dry_run: bool = False,
) -> MergeStats:
    """Fetch Malshare list, normalize, merge, validate, then write the DB.

    ``fetcher`` is dependency-injectable for testing; defaults to
    ``fetch_getlist`` via module-level lookup so tests can monkeypatch it.
    ``api_key`` is required; missing key surfaces as ``FetchError``.
    """

    if fetcher is None:
        fetcher = fetch_getlist
    fetched_at = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d")
    raw_records = fetcher(api_key, timeout=timeout)

    invalid = 0
    normalized: list[dict] = []
    for rec in raw_records:
        entry = normalize_entry(rec, fetched_at=fetched_at, threat_level=threat_level)
        if entry is None:
            invalid += 1
            continue
        normalized.append(entry)

    existing = load_existing_signatures(output)
    merged, stats = merge_entries(existing, normalized)
    stats = MergeStats(
        added=stats.added,
        skipped_duplicate=stats.skipped_duplicate,
        skipped_invalid=invalid,
        total=stats.total,
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        json.dump(merged, tmp)
        tmp_path = Path(tmp.name)
    try:
        SignatureRepository.load(tmp_path)
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass

    if not dry_run:
        atomic_write_signatures(output, merged)
    return stats


__all__ = ["refresh", "SignatureValidationError"]
