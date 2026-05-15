from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.repository import (
    Signature,
    SignatureRepository,
    SignatureValidationError,
    ThreatLevel,
)


VALID_ENTRIES = [
    {
        "name": "EICAR-Test-File",
        "threat_level": "low",
        "md5": "44D88612FEA8A8F36DE82E1278ABB02F",
        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "hex_pattern": "58354f2150254041505b345c505a58353428",
        "description": "EICAR antivirus test string.",
    },
    {
        "name": "Hash-Only-MD5",
        "threat_level": "medium",
        "md5": "0123456789abcdef0123456789abcdef",
    },
    {
        "name": "Pattern-Only",
        "threat_level": "critical",
        "hex_pattern": "deadbeef",
    },
]


def _write_json(tmp_path: Path, data: object) -> Path:
    p = tmp_path / "signatures.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_load_valid_file(tmp_path: Path) -> None:
    repo = SignatureRepository.load(_write_json(tmp_path, VALID_ENTRIES))

    assert len(repo) == 3

    sig = repo.lookup_md5("44D88612FEA8A8F36DE82E1278ABB02F")
    assert sig is not None
    assert sig.name == "EICAR-Test-File"
    assert sig.threat_level is ThreatLevel.LOW
    assert sig.md5 == "44d88612fea8a8f36de82e1278abb02f"

    assert repo.lookup_md5("44d88612fea8a8f36de82e1278abb02f") is sig

    sha_sig = repo.lookup_sha256(
        "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"
    )
    assert sha_sig is sig

    patterns = list(repo.iter_patterns())
    assert ("EICAR-Test-File", bytes.fromhex("58354f2150254041505b345c505a58353428")) in patterns
    assert ("Pattern-Only", b"\xde\xad\xbe\xef") in patterns
    assert len(patterns) == 2


def test_lookup_misses_return_none(tmp_path: Path) -> None:
    repo = SignatureRepository.load(_write_json(tmp_path, VALID_ENTRIES))
    assert repo.lookup_md5("00" * 16) is None
    assert repo.lookup_sha256("00" * 32) is None


def test_signature_pattern_bytes_property() -> None:
    sig = Signature(
        name="x", threat_level=ThreatLevel.HIGH, hex_pattern="cafebabe"
    )
    assert sig.pattern_bytes == b"\xca\xfe\xba\xbe"
    assert Signature(name="y", threat_level=ThreatLevel.LOW, md5="a" * 32).pattern_bytes is None


def test_invalid_json_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(SignatureValidationError, match="invalid JSON"):
        SignatureRepository.load(p)


def test_top_level_must_be_list(tmp_path: Path) -> None:
    with pytest.raises(SignatureValidationError, match="top-level JSON must be a list"):
        SignatureRepository.load(_write_json(tmp_path, {"name": "x"}))


def test_missing_required_field(tmp_path: Path) -> None:
    data = [{"name": "no-threat-level", "md5": "a" * 32}]
    with pytest.raises(SignatureValidationError, match=r"entry\[0\].*missing required"):
        SignatureRepository.load(_write_json(tmp_path, data))


def test_unknown_field_rejected(tmp_path: Path) -> None:
    data = [
        {
            "name": "x",
            "threat_level": "low",
            "md5": "a" * 32,
            "extra": "nope",
        }
    ]
    with pytest.raises(SignatureValidationError, match="unknown field"):
        SignatureRepository.load(_write_json(tmp_path, data))


def test_invalid_threat_level(tmp_path: Path) -> None:
    data = [{"name": "x", "threat_level": "spicy", "md5": "a" * 32}]
    with pytest.raises(SignatureValidationError, match="threat_level"):
        SignatureRepository.load(_write_json(tmp_path, data))


def test_invalid_md5_length(tmp_path: Path) -> None:
    data = [{"name": "x", "threat_level": "low", "md5": "abc"}]
    with pytest.raises(SignatureValidationError, match="'md5' must be a 32-char hex"):
        SignatureRepository.load(_write_json(tmp_path, data))


def test_invalid_md5_non_hex(tmp_path: Path) -> None:
    data = [{"name": "x", "threat_level": "low", "md5": "z" * 32}]
    with pytest.raises(SignatureValidationError, match="'md5' must be a 32-char hex"):
        SignatureRepository.load(_write_json(tmp_path, data))


def test_invalid_sha256_length(tmp_path: Path) -> None:
    data = [{"name": "x", "threat_level": "low", "sha256": "ab" * 16}]
    with pytest.raises(SignatureValidationError, match="'sha256' must be a 64-char hex"):
        SignatureRepository.load(_write_json(tmp_path, data))


def test_invalid_hex_pattern_odd_length(tmp_path: Path) -> None:
    data = [{"name": "x", "threat_level": "low", "hex_pattern": "abc"}]
    with pytest.raises(SignatureValidationError, match="hex_pattern"):
        SignatureRepository.load(_write_json(tmp_path, data))


def test_no_lookup_keys_rejected(tmp_path: Path) -> None:
    data = [{"name": "x", "threat_level": "low"}]
    with pytest.raises(SignatureValidationError, match="at least one of"):
        SignatureRepository.load(_write_json(tmp_path, data))


def test_entry_must_be_object(tmp_path: Path) -> None:
    with pytest.raises(SignatureValidationError, match=r"entry\[1\].*must be a JSON object"):
        SignatureRepository.load(_write_json(tmp_path, [VALID_ENTRIES[0], "oops"]))


def test_empty_name_rejected(tmp_path: Path) -> None:
    data = [{"name": "  ", "threat_level": "low", "md5": "a" * 32}]
    with pytest.raises(SignatureValidationError, match="non-empty string"):
        SignatureRepository.load(_write_json(tmp_path, data))


def test_description_must_be_string(tmp_path: Path) -> None:
    data = [
        {"name": "x", "threat_level": "low", "md5": "a" * 32, "description": 42}
    ]
    with pytest.raises(SignatureValidationError, match="'description' must be a string"):
        SignatureRepository.load(_write_json(tmp_path, data))


def test_error_index_attribute(tmp_path: Path) -> None:
    data = [VALID_ENTRIES[0], {"name": "bad", "threat_level": "extreme", "md5": "a" * 32}]
    with pytest.raises(SignatureValidationError) as ei:
        SignatureRepository.load(_write_json(tmp_path, data))
    assert ei.value.index == 1


def test_empty_signature_list_loads(tmp_path: Path) -> None:
    repo = SignatureRepository.load(_write_json(tmp_path, []))
    assert len(repo) == 0
    assert list(repo.iter_patterns()) == []
    assert repo.lookup_md5("a" * 32) is None


def test_bloom_disabled_by_default(tmp_path: Path) -> None:
    repo = SignatureRepository.load(_write_json(tmp_path, VALID_ENTRIES))
    assert repo.bloom_enabled is False
    assert repo.bloom is None
    assert repo.might_contain_hash("ff" * 16) is True


def test_bloom_enabled_indexes_all_hashes(tmp_path: Path) -> None:
    repo = SignatureRepository.load(
        _write_json(tmp_path, VALID_ENTRIES), enable_bloom=True
    )
    assert repo.bloom_enabled is True
    md5 = "44d88612fea8a8f36de82e1278abb02f"
    sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    assert repo.might_contain_hash(md5) is True
    assert repo.might_contain_hash(md5.upper()) is True
    assert repo.might_contain_hash(sha) is True
    assert repo.might_contain_hash("0123456789abcdef0123456789abcdef") is True


def test_bloom_filters_obvious_negatives(tmp_path: Path) -> None:
    repo = SignatureRepository.load(
        _write_json(tmp_path, VALID_ENTRIES), enable_bloom=True
    )
    negatives = [f"{i:032x}" for i in range(50)]
    not_seen = [n for n in negatives if not repo.might_contain_hash(n)]
    assert len(not_seen) > 0


def test_bloom_lookup_still_returns_signature(tmp_path: Path) -> None:
    repo = SignatureRepository.load(
        _write_json(tmp_path, VALID_ENTRIES),
        enable_bloom=True,
        bloom_fp_rate=0.001,
    )
    sig = repo.lookup_md5("44d88612fea8a8f36de82e1278abb02f")
    assert sig is not None
    assert sig.name == "EICAR-Test-File"
