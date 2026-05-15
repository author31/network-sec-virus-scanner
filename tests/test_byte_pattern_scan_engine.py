from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sentinel.application import (
    DETECTION_METHOD_PATTERN_HEX,
    PatternScanResult,
    scan_file_patterns,
)
from sentinel.repository import SignatureRepository


EICAR_BYTES = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_HEX = EICAR_BYTES.hex()
EICAR_PREFIX_HEX = "58354f2150254041505b345c505a58353428"
EICAR_PREFIX_BYTES = bytes.fromhex(EICAR_PREFIX_HEX)


def _make_repo(tmp_path: Path, entries: list[dict]) -> SignatureRepository:
    db = tmp_path / "signatures.json"
    db.write_text(json.dumps(entries), encoding="utf-8")
    return SignatureRepository.load(db)


def _write(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    return path


def test_finds_eicar_pattern_in_larger_file(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "EICAR-Test-File",
                "threat_level": "low",
                "hex_pattern": EICAR_PREFIX_HEX,
            }
        ],
    )
    padding_pre = b"A" * 1000
    padding_post = b"B" * 1000
    payload = padding_pre + EICAR_BYTES + padding_post
    f = _write(tmp_path / "infected.bin", payload)

    results = scan_file_patterns(f, repo)

    assert len(results) == 1
    r = results[0]
    assert isinstance(r, PatternScanResult)
    assert r.signature.name == "EICAR-Test-File"
    assert r.detection_method == DETECTION_METHOD_PATTERN_HEX
    assert r.offset == len(padding_pre)
    assert r.path == f


def test_detects_pattern_straddling_chunk_boundary(tmp_path: Path) -> None:
    pattern = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "DeadBeef",
                "threat_level": "high",
                "hex_pattern": pattern.hex(),
            }
        ],
    )
    chunk_size = 16
    pre_len = chunk_size - 3
    payload = b"X" * pre_len + pattern + b"Y" * 20
    f = _write(tmp_path / "boundary.bin", payload)

    results = scan_file_patterns(f, repo, chunk_size=chunk_size)

    assert len(results) == 1
    assert results[0].offset == pre_len
    assert results[0].signature.name == "DeadBeef"


def test_pattern_at_exact_chunk_end(tmp_path: Path) -> None:
    pattern = b"\x01\x02\x03\x04"
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "Tiny",
                "threat_level": "medium",
                "hex_pattern": pattern.hex(),
            }
        ],
    )
    chunk_size = 8
    payload = b"Z" * (chunk_size - len(pattern)) + pattern + b"W" * 5
    f = _write(tmp_path / "edge.bin", payload)

    results = scan_file_patterns(f, repo, chunk_size=chunk_size)
    assert len(results) == 1
    assert results[0].offset == chunk_size - len(pattern)


def test_no_match_returns_empty(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "EICAR-Test-File",
                "threat_level": "low",
                "hex_pattern": EICAR_PREFIX_HEX,
            }
        ],
    )
    f = _write(tmp_path / "clean.txt", b"benign content with no signature")
    assert scan_file_patterns(f, repo) == []


def test_multiple_patterns_multiple_matches(tmp_path: Path) -> None:
    pat_a = b"\xaa\xbb\xcc"
    pat_b = b"\xee\xff"
    repo = _make_repo(
        tmp_path,
        [
            {"name": "A", "threat_level": "low", "hex_pattern": pat_a.hex()},
            {"name": "B", "threat_level": "high", "hex_pattern": pat_b.hex()},
        ],
    )
    payload = (
        b"\x00\x00" + pat_a + b"\x10" + pat_b + b"\x20" + pat_a + b"\x30" + pat_b
    )
    f = _write(tmp_path / "multi.bin", payload)

    results = scan_file_patterns(f, repo, chunk_size=8)

    assert [(r.signature.name, r.offset) for r in results] == [
        ("A", 2),
        ("B", 6),
        ("A", 9),
        ("B", 13),
    ]


def test_repeated_pattern_in_same_file(tmp_path: Path) -> None:
    pattern = b"\x42\x42\x42"
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "TripleB",
                "threat_level": "low",
                "hex_pattern": pattern.hex(),
            }
        ],
    )
    payload = pattern + b"X" + pattern + b"Y" + pattern
    f = _write(tmp_path / "rep.bin", payload)

    results = scan_file_patterns(f, repo, chunk_size=4)
    offsets = [r.offset for r in results]
    assert offsets == [0, 4, 8]


def test_overlapping_match_positions(tmp_path: Path) -> None:
    pattern = b"AAA"
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "Triple-A",
                "threat_level": "low",
                "hex_pattern": pattern.hex(),
            }
        ],
    )
    payload = b"AAAAA"
    f = _write(tmp_path / "over.bin", payload)

    results = scan_file_patterns(f, repo, chunk_size=8)
    assert [r.offset for r in results] == [0, 1, 2]


def test_empty_file_no_results(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "EICAR-Test-File",
                "threat_level": "low",
                "hex_pattern": EICAR_PREFIX_HEX,
            }
        ],
    )
    f = _write(tmp_path / "empty.bin", b"")
    assert scan_file_patterns(f, repo) == []


def test_repo_with_no_pattern_signatures_returns_empty(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "HashOnly",
                "threat_level": "low",
                "md5": "44d88612fea8a8f36de82e1278abb02f",
            }
        ],
    )
    f = _write(tmp_path / "f.bin", b"anything")
    assert scan_file_patterns(f, repo) == []


def test_pattern_longer_than_requested_chunk_size(tmp_path: Path) -> None:
    pattern = b"\x10" * 64
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "Long",
                "threat_level": "low",
                "hex_pattern": pattern.hex(),
            }
        ],
    )
    payload = b"\x00" * 30 + pattern + b"\x00" * 30
    f = _write(tmp_path / "long.bin", payload)

    results = scan_file_patterns(f, repo, chunk_size=8)
    assert len(results) == 1
    assert results[0].offset == 30


def test_invalid_chunk_size(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "EICAR-Test-File",
                "threat_level": "low",
                "hex_pattern": EICAR_PREFIX_HEX,
            }
        ],
    )
    f = _write(tmp_path / "f", b"x")
    with pytest.raises(ValueError):
        scan_file_patterns(f, repo, chunk_size=0)
    with pytest.raises(ValueError):
        scan_file_patterns(f, repo, chunk_size=-1)


def test_missing_file_raises(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "EICAR-Test-File",
                "threat_level": "low",
                "hex_pattern": EICAR_PREFIX_HEX,
            }
        ],
    )
    with pytest.raises(FileNotFoundError):
        scan_file_patterns(tmp_path / "missing", repo)


def test_accepts_str_path(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "EICAR-Test-File",
                "threat_level": "low",
                "hex_pattern": EICAR_PREFIX_HEX,
            }
        ],
    )
    f = _write(tmp_path / "e", EICAR_BYTES)
    results = scan_file_patterns(str(f), repo)
    assert len(results) == 1
    assert results[0].path == Path(str(f))


def test_offsets_consistent_across_chunk_sizes(tmp_path: Path) -> None:
    pattern = b"\xca\xfe\xba\xbe"
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "Java",
                "threat_level": "low",
                "hex_pattern": pattern.hex(),
            }
        ],
    )
    payload = os.urandom(100) + pattern + os.urandom(100) + pattern + os.urandom(50)
    f = _write(tmp_path / "rand.bin", payload)

    baseline = [r.offset for r in scan_file_patterns(f, repo)]
    for cs in (1, 2, 3, 7, 16, 64, 4096):
        offsets = [r.offset for r in scan_file_patterns(f, repo, chunk_size=cs)]
        assert offsets == baseline, f"mismatch at chunk_size={cs}"


def test_large_file_with_embedded_eicar_via_full_hex(tmp_path: Path) -> None:
    """Full EICAR string detected inside a larger surrounding file."""
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "EICAR-Full",
                "threat_level": "low",
                "hex_pattern": EICAR_HEX,
            }
        ],
    )
    pre = b"\x00" * (128 * 1024)
    post = b"\xff" * (32 * 1024)
    payload = pre + EICAR_BYTES + post
    f = _write(tmp_path / "big_infected.bin", payload)

    results = scan_file_patterns(f, repo)
    assert len(results) == 1
    assert results[0].signature.name == "EICAR-Full"
    assert results[0].offset == len(pre)
