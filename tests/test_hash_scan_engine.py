from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from sentinel.application import (
    DETECTION_METHOD_MD5,
    DETECTION_METHOD_SHA256,
    HashScanResult,
    compute_hashes,
    scan_file,
)
from sentinel.repository import SignatureRepository


EICAR_BYTES = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA256 = (
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
)


def _make_repo(tmp_path: Path, entries: list[dict]) -> SignatureRepository:
    db = tmp_path / "signatures.json"
    db.write_text(json.dumps(entries), encoding="utf-8")
    return SignatureRepository.load(db)


def _write(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    return path


def test_compute_hashes_known_string(tmp_path: Path) -> None:
    f = _write(tmp_path / "f", b"hello world")
    md5, sha256 = compute_hashes(f)
    assert md5 == hashlib.md5(b"hello world").hexdigest()
    assert sha256 == hashlib.sha256(b"hello world").hexdigest()


def test_compute_hashes_empty_file(tmp_path: Path) -> None:
    f = _write(tmp_path / "empty", b"")
    md5, sha256 = compute_hashes(f)
    assert md5 == "d41d8cd98f00b204e9800998ecf8427e"
    assert sha256 == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_compute_hashes_eicar(tmp_path: Path) -> None:
    f = _write(tmp_path / "eicar.com", EICAR_BYTES)
    md5, sha256 = compute_hashes(f)
    assert md5 == EICAR_MD5
    assert sha256 == EICAR_SHA256


def test_compute_hashes_binary_file_no_error(tmp_path: Path) -> None:
    payload = bytes(range(256)) * 10
    f = _write(tmp_path / "bin", payload)
    md5, sha256 = compute_hashes(f)
    assert md5 == hashlib.md5(payload).hexdigest()
    assert sha256 == hashlib.sha256(payload).hexdigest()


def test_compute_hashes_streams_across_chunk_boundaries(tmp_path: Path) -> None:
    payload = b"a" * (64 * 1024 * 3 + 17)
    f = _write(tmp_path / "big", payload)
    md5, sha256 = compute_hashes(f, chunk_size=1024)
    assert md5 == hashlib.md5(payload).hexdigest()
    assert sha256 == hashlib.sha256(payload).hexdigest()


def test_compute_hashes_chunk_size_must_be_positive(tmp_path: Path) -> None:
    f = _write(tmp_path / "f", b"x")
    with pytest.raises(ValueError):
        compute_hashes(f, chunk_size=0)
    with pytest.raises(ValueError):
        compute_hashes(f, chunk_size=-1)


def test_compute_hashes_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        compute_hashes(tmp_path / "nope")


def test_scan_file_detects_eicar_by_sha256(tmp_path: Path) -> None:
    repo = _make_repo(
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
    f = _write(tmp_path / "eicar.com", EICAR_BYTES)
    result = scan_file(f, repo)
    assert isinstance(result, HashScanResult)
    assert result.signature.name == "EICAR-Test-File"
    assert result.detection_method == DETECTION_METHOD_SHA256
    assert result.md5 == EICAR_MD5
    assert result.sha256 == EICAR_SHA256
    assert result.path == f


def test_scan_file_prefers_sha256_when_both_present(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "Dual-Hash",
                "threat_level": "high",
                "md5": EICAR_MD5,
                "sha256": EICAR_SHA256,
            }
        ],
    )
    f = _write(tmp_path / "e", EICAR_BYTES)
    result = scan_file(f, repo)
    assert result is not None
    assert result.detection_method == DETECTION_METHOD_SHA256


def test_scan_file_falls_back_to_md5(tmp_path: Path) -> None:
    payload = b"only-md5-known"
    md5 = hashlib.md5(payload).hexdigest()
    repo = _make_repo(
        tmp_path,
        [{"name": "MD5-Only", "threat_level": "medium", "md5": md5}],
    )
    f = _write(tmp_path / "f", payload)
    result = scan_file(f, repo)
    assert result is not None
    assert result.signature.name == "MD5-Only"
    assert result.detection_method == DETECTION_METHOD_MD5
    assert result.md5 == md5


def test_scan_file_no_match_returns_none(tmp_path: Path) -> None:
    repo = _make_repo(
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
    f = _write(tmp_path / "clean.txt", b"benign content")
    assert scan_file(f, repo) is None


def test_scan_file_empty_repo_returns_none(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, [])
    f = _write(tmp_path / "anything", b"data")
    assert scan_file(f, repo) is None


def test_scan_file_handles_binary_without_error(tmp_path: Path) -> None:
    payload = os.urandom(4096)
    repo = _make_repo(
        tmp_path,
        [{"name": "junk", "threat_level": "low", "md5": "0" * 32}],
    )
    f = _write(tmp_path / "bin", payload)
    assert scan_file(f, repo) is None


def test_scan_file_with_bloom_detects_known_match(tmp_path: Path) -> None:
    db = tmp_path / "signatures.json"
    db.write_text(
        json.dumps(
            [
                {
                    "name": "EICAR-Test-File",
                    "threat_level": "low",
                    "md5": EICAR_MD5,
                    "sha256": EICAR_SHA256,
                }
            ]
        ),
        encoding="utf-8",
    )
    repo = SignatureRepository.load(db, enable_bloom=True)
    f = _write(tmp_path / "eicar.com", EICAR_BYTES)
    result = scan_file(f, repo)
    assert result is not None
    assert result.detection_method == DETECTION_METHOD_SHA256


def test_scan_file_with_bloom_clean_file_returns_none(tmp_path: Path) -> None:
    db = tmp_path / "signatures.json"
    db.write_text(
        json.dumps(
            [
                {
                    "name": "EICAR-Test-File",
                    "threat_level": "low",
                    "md5": EICAR_MD5,
                    "sha256": EICAR_SHA256,
                }
            ]
        ),
        encoding="utf-8",
    )
    repo = SignatureRepository.load(db, enable_bloom=True)
    f = _write(tmp_path / "clean.txt", b"definitely benign content")
    assert scan_file(f, repo) is None


def test_scan_file_with_bloom_zero_false_negatives_synthetic(tmp_path: Path) -> None:
    """For 500 known md5s, every matching file is still detected with bloom on."""
    entries = []
    payloads: list[tuple[bytes, str]] = []
    for i in range(500):
        payload = f"payload-{i}".encode()
        md5 = hashlib.md5(payload).hexdigest()
        entries.append({"name": f"sig-{i}", "threat_level": "low", "md5": md5})
        payloads.append((payload, md5))

    db = tmp_path / "signatures.json"
    db.write_text(json.dumps(entries), encoding="utf-8")
    repo = SignatureRepository.load(db, enable_bloom=True, bloom_fp_rate=0.01)

    for idx, (payload, md5) in enumerate(payloads):
        f = _write(tmp_path / f"f-{idx}", payload)
        result = scan_file(f, repo)
        assert result is not None, f"missed payload-{idx}"
        assert result.md5 == md5


def test_scan_file_accepts_str_path(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "EICAR-Test-File",
                "threat_level": "low",
                "sha256": EICAR_SHA256,
            }
        ],
    )
    f = _write(tmp_path / "e", EICAR_BYTES)
    result = scan_file(str(f), repo)
    assert result is not None
    assert result.path == Path(str(f))
