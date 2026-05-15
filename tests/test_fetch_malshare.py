from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS = _REPO_ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import fetch_malshare  # noqa: E402
from fetch_malshare import (  # noqa: E402
    FetchError,
    merge_entries,
    normalize_entry,
    refresh,
)


FETCHED_AT = "2026-05-15"

EICAR_ENTRY = {
    "name": "EICAR-Test-File",
    "threat_level": "low",
    "md5": "44d88612fea8a8f36de82e1278abb02f",
    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "hex_pattern": "58354f2150254041505b345c505a58353428",
    "description": "EICAR antivirus test string (canary).",
}

SAMPLE_HASH_A = {
    "md5": "a" * 32,
    "sha1": "b" * 40,
    "sha256": "c" * 64,
}
SAMPLE_HASH_B = {
    "md5": "d" * 32,
    "sha1": "e" * 40,
    "sha256": "f" * 64,
}


def test_normalize_entry_dict_with_hashes():
    entry = normalize_entry(SAMPLE_HASH_A, fetched_at=FETCHED_AT)
    assert entry is not None
    assert entry["md5"] == "a" * 32
    assert entry["sha256"] == "c" * 64
    assert entry["threat_level"] == "medium"
    assert entry["name"].startswith("Malshare-")
    assert FETCHED_AT in entry["description"]


def test_normalize_entry_uppercase_hex_lowercased():
    entry = normalize_entry(
        {"md5": "A" * 32, "sha256": "B" * 64}, fetched_at=FETCHED_AT
    )
    assert entry is not None
    assert entry["md5"] == "a" * 32
    assert entry["sha256"] == "b" * 64


def test_normalize_entry_string_md5():
    entry = normalize_entry("a" * 32, fetched_at=FETCHED_AT)
    assert entry is not None
    assert entry["md5"] == "a" * 32
    assert "sha256" not in entry


def test_normalize_entry_string_sha256():
    entry = normalize_entry("c" * 64, fetched_at=FETCHED_AT)
    assert entry is not None
    assert entry["sha256"] == "c" * 64
    assert "md5" not in entry


def test_normalize_entry_skips_records_with_no_hash():
    assert normalize_entry({"sha1": "b" * 40}, fetched_at=FETCHED_AT) is None
    assert normalize_entry({"md5": "not-hex"}, fetched_at=FETCHED_AT) is None
    assert normalize_entry("hello", fetched_at=FETCHED_AT) is None
    assert normalize_entry(123, fetched_at=FETCHED_AT) is None


def test_normalize_entry_threat_level_passthrough():
    entry = normalize_entry(SAMPLE_HASH_A, fetched_at=FETCHED_AT, threat_level="high")
    assert entry is not None
    assert entry["threat_level"] == "high"


def test_merge_dedupe_by_md5():
    existing = [EICAR_ENTRY]
    incoming = [
        normalize_entry(SAMPLE_HASH_A, fetched_at=FETCHED_AT),
        normalize_entry(
            {"md5": EICAR_ENTRY["md5"], "sha256": "9" * 64}, fetched_at=FETCHED_AT
        ),
    ]
    merged, stats = merge_entries(existing, [e for e in incoming if e])
    assert stats.added == 1
    assert stats.skipped_duplicate == 1
    md5s = {e.get("md5") for e in merged}
    assert "a" * 32 in md5s
    assert merged[0] is EICAR_ENTRY


def test_merge_dedupe_by_sha256():
    existing = [
        normalize_entry(SAMPLE_HASH_A, fetched_at=FETCHED_AT),
    ]
    incoming = [
        normalize_entry(
            {"md5": "9" * 32, "sha256": SAMPLE_HASH_A["sha256"]},
            fetched_at=FETCHED_AT,
        )
    ]
    _, stats = merge_entries(existing, [e for e in incoming if e])
    assert stats.added == 0
    assert stats.skipped_duplicate == 1


def test_merge_dedupe_within_incoming_batch():
    existing: list[dict] = []
    a = normalize_entry(SAMPLE_HASH_A, fetched_at=FETCHED_AT)
    a_again = normalize_entry(SAMPLE_HASH_A, fetched_at=FETCHED_AT)
    b = normalize_entry(SAMPLE_HASH_B, fetched_at=FETCHED_AT)
    merged, stats = merge_entries(existing, [a, a_again, b])
    assert stats.added == 2
    assert stats.skipped_duplicate == 1
    assert len(merged) == 2


def _seed_db(tmp_path: Path, entries: list[dict]) -> Path:
    p = tmp_path / "signatures.json"
    p.write_text(json.dumps(entries), encoding="utf-8")
    return p


def test_refresh_appends_new_entries(tmp_path: Path):
    db = _seed_db(tmp_path, [EICAR_ENTRY])

    def fake_fetcher(api_key: str, *, timeout: int):
        assert api_key == "fake-key"
        return [SAMPLE_HASH_A, SAMPLE_HASH_B]

    stats = refresh(
        output=db,
        api_key="fake-key",
        fetcher=fake_fetcher,
        now=datetime(2026, 5, 15, tzinfo=timezone.utc),
    )
    assert stats.added == 2
    assert stats.skipped_duplicate == 0
    payload = json.loads(db.read_text())
    assert payload[0] == EICAR_ENTRY  # canary preserved at head
    md5s = {e.get("md5") for e in payload}
    assert "a" * 32 in md5s
    assert "d" * 32 in md5s


def test_refresh_is_idempotent(tmp_path: Path):
    db = _seed_db(tmp_path, [EICAR_ENTRY])

    def fake_fetcher(api_key: str, *, timeout: int):
        return [SAMPLE_HASH_A]

    first = refresh(
        output=db, api_key="k", fetcher=fake_fetcher,
        now=datetime(2026, 5, 15, tzinfo=timezone.utc),
    )
    second = refresh(
        output=db, api_key="k", fetcher=fake_fetcher,
        now=datetime(2026, 5, 16, tzinfo=timezone.utc),
    )
    assert first.added == 1
    assert second.added == 0
    assert second.skipped_duplicate == 1
    payload = json.loads(db.read_text())
    assert len(payload) == 2  # EICAR + one Malshare entry


def test_refresh_dry_run_does_not_write(tmp_path: Path):
    db = _seed_db(tmp_path, [EICAR_ENTRY])
    original = db.read_text()

    def fake_fetcher(api_key: str, *, timeout: int):
        return [SAMPLE_HASH_A]

    stats = refresh(
        output=db,
        api_key="k",
        fetcher=fake_fetcher,
        dry_run=True,
        now=datetime(2026, 5, 15, tzinfo=timezone.utc),
    )
    assert stats.added == 1
    assert db.read_text() == original


def test_refresh_skips_records_without_hashes(tmp_path: Path):
    db = _seed_db(tmp_path, [EICAR_ENTRY])

    def fake_fetcher(api_key: str, *, timeout: int):
        return [{"sha1": "b" * 40}, SAMPLE_HASH_A, "not-a-hash"]

    stats = refresh(
        output=db, api_key="k", fetcher=fake_fetcher,
        now=datetime(2026, 5, 15, tzinfo=timezone.utc),
    )
    assert stats.added == 1
    assert stats.skipped_invalid == 2


def test_refresh_requires_api_key(tmp_path: Path):
    db = _seed_db(tmp_path, [EICAR_ENTRY])
    with pytest.raises(FetchError, match="MALSHARE_API_KEY"):
        refresh(output=db, api_key="", fetcher=fetch_malshare.fetch_getlist)


def test_refresh_creates_db_when_missing(tmp_path: Path):
    db = tmp_path / "signatures.json"  # does not exist yet

    def fake_fetcher(api_key: str, *, timeout: int):
        return [SAMPLE_HASH_A]

    stats = refresh(
        output=db, api_key="k", fetcher=fake_fetcher,
        now=datetime(2026, 5, 15, tzinfo=timezone.utc),
    )
    assert stats.added == 1
    assert stats.total == 1
    assert db.exists()


def test_refresh_propagates_fetch_failures(tmp_path: Path):
    db = _seed_db(tmp_path, [EICAR_ENTRY])

    def boom(api_key: str, *, timeout: int):
        raise FetchError("boom")

    with pytest.raises(FetchError, match="boom"):
        refresh(output=db, api_key="k", fetcher=boom)


def test_refresh_loaded_through_signature_repository(tmp_path: Path):
    """End-to-end: writer output must parse via SignatureRepository.load."""

    from sentinel.repository import SignatureRepository

    db = _seed_db(tmp_path, [EICAR_ENTRY])

    def fake_fetcher(api_key: str, *, timeout: int):
        return [SAMPLE_HASH_A, SAMPLE_HASH_B]

    refresh(
        output=db, api_key="k", fetcher=fake_fetcher,
        now=datetime(2026, 5, 15, tzinfo=timezone.utc),
    )
    repo = SignatureRepository.load(db)
    assert len(repo) == 3
    # EICAR canary still resolves end-to-end
    eicar = repo.lookup_md5(EICAR_ENTRY["md5"])
    assert eicar is not None
    assert eicar.name == "EICAR-Test-File"
    assert eicar.pattern_bytes == bytes.fromhex(EICAR_ENTRY["hex_pattern"])
