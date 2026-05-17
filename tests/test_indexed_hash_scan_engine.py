from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sentinel.application import (
    DETECTION_METHOD_SHA256,
    HashScanResult,
    scan_file_indexed,
)
from sentinel.application import indexed_hash_scan_engine
from sentinel.repository import FileIndexRepository, SignatureRepository


EICAR_BYTES = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _make_repo(tmp_path: Path, entries: list[dict]) -> SignatureRepository:
    db = tmp_path / "signatures.json"
    db.write_text(json.dumps(entries), encoding="utf-8")
    return SignatureRepository.load(db)


def _make_eicar_repo(tmp_path: Path) -> SignatureRepository:
    return _make_repo(
        tmp_path,
        [
            {
                "name": "EICAR-Test-File",
                "threat_level": "low",
                "md5": EICAR_MD5,
                "sha256": EICAR_SHA256,
            }
        ],
    )


def test_first_scan_computes_hashes_and_populates_index(tmp_path: Path) -> None:
    sigs = _make_eicar_repo(tmp_path)
    idx = FileIndexRepository()
    f = tmp_path / "eicar.com"
    f.write_bytes(EICAR_BYTES)

    result, cache_hit = scan_file_indexed(f, sigs, idx)

    assert cache_hit is False
    assert isinstance(result, HashScanResult)
    assert result.detection_method == DETECTION_METHOD_SHA256
    assert len(idx) == 1
    entry = next(iter(idx))
    assert entry.path == str(f)
    assert entry.sha256 == EICAR_SHA256
    assert entry.md5 == EICAR_MD5


def test_second_scan_reuses_cached_hashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sigs = _make_eicar_repo(tmp_path)
    idx = FileIndexRepository()
    f = tmp_path / "eicar.com"
    f.write_bytes(EICAR_BYTES)

    scan_file_indexed(f, sigs, idx)

    def _boom(*a, **kw):
        raise AssertionError("compute_hashes must not be called on cache hit")

    monkeypatch.setattr(indexed_hash_scan_engine, "compute_hashes", _boom)

    result, cache_hit = scan_file_indexed(f, sigs, idx)
    assert cache_hit is True
    assert isinstance(result, HashScanResult)
    assert result.sha256 == EICAR_SHA256


def test_modified_file_invalidates_cache(tmp_path: Path) -> None:
    sigs = _make_eicar_repo(tmp_path)
    idx = FileIndexRepository()
    f = tmp_path / "eicar.com"
    f.write_bytes(EICAR_BYTES)

    scan_file_indexed(f, sigs, idx)

    # bump mtime far enough that nanosecond resolution sees the change
    st = f.stat()
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000))

    _, cache_hit = scan_file_indexed(f, sigs, idx)
    assert cache_hit is False


def test_clean_file_returns_none(tmp_path: Path) -> None:
    sigs = _make_eicar_repo(tmp_path)
    idx = FileIndexRepository()
    f = tmp_path / "clean.txt"
    f.write_bytes(b"definitely benign content")

    result, cache_hit = scan_file_indexed(f, sigs, idx)
    assert result is None
    assert cache_hit is False
    assert len(idx) == 1  # clean files are still indexed


def test_round_trip_persistence(tmp_path: Path) -> None:
    sigs = _make_eicar_repo(tmp_path)
    idx_path = tmp_path / "idx.json"

    idx = FileIndexRepository.load(idx_path)
    f = tmp_path / "eicar.com"
    f.write_bytes(EICAR_BYTES)
    scan_file_indexed(f, sigs, idx)
    idx.save(idx_path)

    reloaded = FileIndexRepository.load(idx_path)
    st = f.stat()
    entry = reloaded.lookup(f, st.st_size, st.st_mtime_ns)
    assert entry is not None
    assert entry.sha256 == EICAR_SHA256
