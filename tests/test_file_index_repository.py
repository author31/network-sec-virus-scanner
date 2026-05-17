from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.repository import (
    FileIndexEntry,
    FileIndexRepository,
    FileIndexValidationError,
)


def _entry(path: str, **overrides) -> FileIndexEntry:
    defaults = dict(
        path=path,
        size=10,
        mtime_ns=123456789,
        md5="0" * 32,
        sha256="0" * 64,
        scanned_at="2026-05-17T00:00:00+00:00",
    )
    defaults.update(overrides)
    return FileIndexEntry(**defaults)


def test_load_missing_file_returns_empty(tmp_path: Path) -> None:
    repo = FileIndexRepository.load(tmp_path / "nope.json")
    assert len(repo) == 0


def test_round_trip_save_then_load(tmp_path: Path) -> None:
    repo = FileIndexRepository([_entry("/a"), _entry("/b", size=42)])
    out = tmp_path / "idx.json"
    repo.save(out)

    reloaded = FileIndexRepository.load(out)
    assert len(reloaded) == 2
    entries = sorted(reloaded, key=lambda e: e.path)
    assert entries[0].path == "/a"
    assert entries[1].path == "/b"
    assert entries[1].size == 42


def test_lookup_matches_size_and_mtime(tmp_path: Path) -> None:
    e = _entry("/x", size=100, mtime_ns=999)
    repo = FileIndexRepository([e])

    assert repo.lookup("/x", 100, 999) == e
    assert repo.lookup("/x", 101, 999) is None  # size mismatch
    assert repo.lookup("/x", 100, 1000) is None  # mtime mismatch
    assert repo.lookup("/y", 100, 999) is None  # path miss


def test_upsert_overwrites_prior_entry(tmp_path: Path) -> None:
    repo = FileIndexRepository([_entry("/x", size=10)])
    repo.upsert(_entry("/x", size=20, mtime_ns=555))
    assert len(repo) == 1
    assert repo.lookup("/x", 20, 555) is not None
    assert repo.lookup("/x", 10, 123456789) is None


def test_load_invalid_json_raises(tmp_path: Path) -> None:
    out = tmp_path / "idx.json"
    out.write_text("{not json", encoding="utf-8")
    with pytest.raises(FileIndexValidationError):
        FileIndexRepository.load(out)


def test_load_non_list_raises(tmp_path: Path) -> None:
    out = tmp_path / "idx.json"
    out.write_text(json.dumps({"k": "v"}), encoding="utf-8")
    with pytest.raises(FileIndexValidationError):
        FileIndexRepository.load(out)


def test_load_missing_field_raises_with_index(tmp_path: Path) -> None:
    out = tmp_path / "idx.json"
    out.write_text(
        json.dumps([{"path": "/a", "size": 1, "mtime_ns": 1, "md5": "0" * 32}]),
        encoding="utf-8",
    )
    with pytest.raises(FileIndexValidationError) as exc:
        FileIndexRepository.load(out)
    assert exc.value.index == 0


def test_load_bad_hash_raises(tmp_path: Path) -> None:
    out = tmp_path / "idx.json"
    out.write_text(
        json.dumps(
            [
                {
                    "path": "/a",
                    "size": 1,
                    "mtime_ns": 1,
                    "md5": "zz",
                    "sha256": "0" * 64,
                    "scanned_at": "now",
                }
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(FileIndexValidationError):
        FileIndexRepository.load(out)


def test_save_atomic_writes_pretty_json(tmp_path: Path) -> None:
    out = tmp_path / "sub" / "idx.json"
    FileIndexRepository([_entry("/a")]).save(out)
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert data[0]["path"] == "/a"


def test_contains_path(tmp_path: Path) -> None:
    repo = FileIndexRepository([_entry("/a")])
    assert "/a" in repo
    assert "/b" not in repo
