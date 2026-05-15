from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from sentinel.application import (
    DETECTION_METHOD_PREFIX,
    HeuristicMatch,
    scan_file_heuristic,
)
from sentinel.repository import (
    HeuristicRule,
    HeuristicRuleRepository,
    ThreatLevel,
)


def _make_repo(tmp_path: Path, entries: list[dict]) -> HeuristicRuleRepository:
    db = tmp_path / "rules.json"
    db.write_text(json.dumps(entries), encoding="utf-8")
    return HeuristicRuleRepository.load(db)


def _write(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    return path


SUSPICIOUS_FILE = (
    b"some prelude...\n"
    b"call CreateRemoteThread(handle, 0, 0, payload, 0, 0, 0)\n"
    b"shell: cmd.exe /c del important.txt\n"
    b"powershell -enc QUFBQUFB\n"
    b"finally eval(user_input)\n"
)


def test_flags_synthetic_file_with_suspicious_strings(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "win-api-injection",
                "pattern": "CreateRemoteThread|VirtualAllocEx|WriteProcessMemory",
                "severity": "high",
            },
            {
                "name": "cmd-shell-invoke",
                "pattern": r"(?i)cmd\.exe\s+/c\b",
                "severity": "medium",
            },
            {
                "name": "powershell-encoded",
                "pattern": r"(?i)powershell(\.exe)?\s+-(?:e|en|enc|encodedcommand)\b",
                "severity": "high",
            },
            {
                "name": "shell-eval",
                "pattern": r"\b(?:eval|exec|system)\s*\(",
                "severity": "medium",
            },
        ],
    )
    f = _write(tmp_path / "sus.txt", SUSPICIOUS_FILE)

    matches = scan_file_heuristic(f, repo)

    by_name = {m.rule_name for m in matches}
    assert by_name == {
        "win-api-injection",
        "cmd-shell-invoke",
        "powershell-encoded",
        "shell-eval",
    }
    for m in matches:
        assert isinstance(m, HeuristicMatch)
        assert m.path == f
        assert m.detection_method == f"{DETECTION_METHOD_PREFIX}{m.rule_name}"
        assert m.snippet
        assert m.offset >= 0


def test_severity_propagates_to_match(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [{"name": "high-rule", "pattern": "boom", "severity": "critical"}],
    )
    f = _write(tmp_path / "f.txt", b"goes boom now")

    matches = scan_file_heuristic(f, repo)
    assert len(matches) == 1
    assert matches[0].severity is ThreatLevel.CRITICAL


def test_no_match_returns_empty(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [{"name": "r", "pattern": "needle", "severity": "low"}],
    )
    f = _write(tmp_path / "clean.txt", b"only haystack here")
    assert scan_file_heuristic(f, repo) == []


def test_multiple_matches_per_rule_returned(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [{"name": "tag", "pattern": "AB", "severity": "low"}],
    )
    f = _write(tmp_path / "f.txt", b"AB__AB__AB")

    matches = scan_file_heuristic(f, repo)
    assert [m.offset for m in matches] == [0, 4, 8]
    assert all(m.rule_name == "tag" for m in matches)


def test_results_sorted_by_offset(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {"name": "a", "pattern": "alpha", "severity": "low"},
            {"name": "b", "pattern": "beta", "severity": "low"},
        ],
    )
    f = _write(tmp_path / "f.txt", b"beta then alpha then beta")

    matches = scan_file_heuristic(f, repo)
    offsets = [m.offset for m in matches]
    assert offsets == sorted(offsets)


def test_does_not_crash_on_binary_input(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [
            {"name": "exec", "pattern": r"\bexec\(", "severity": "medium"},
        ],
    )
    binary = bytes(range(256)) * 16 + b"\x00\x00exec(payload)\x00\x00" + os.urandom(512)
    f = _write(tmp_path / "blob.bin", binary)

    matches = scan_file_heuristic(f, repo)
    assert len(matches) == 1
    assert matches[0].rule_name == "exec"


def test_pure_random_binary_yields_no_results(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [{"name": "needle", "pattern": "this-string-not-present", "severity": "low"}],
    )
    f = _write(tmp_path / "rand.bin", os.urandom(2048))
    assert scan_file_heuristic(f, repo) == []


def test_empty_file_returns_empty(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [{"name": "r", "pattern": "x", "severity": "low"}],
    )
    f = _write(tmp_path / "empty", b"")
    assert scan_file_heuristic(f, repo) == []


def test_empty_repository_returns_empty(tmp_path: Path) -> None:
    repo = HeuristicRuleRepository([])
    f = _write(tmp_path / "f.txt", b"any content")
    assert scan_file_heuristic(f, repo) == []


def test_max_bytes_limits_read(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [{"name": "tail", "pattern": "MARKER", "severity": "low"}],
    )
    payload = b"X" * 10_000 + b"MARKER"
    f = _write(tmp_path / "big.txt", payload)

    assert scan_file_heuristic(f, repo, max_bytes=100) == []

    matches = scan_file_heuristic(f, repo, max_bytes=None)
    assert len(matches) == 1


def test_snippet_includes_match_with_radius(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [{"name": "tag", "pattern": "needle", "severity": "low"}],
    )
    f = _write(tmp_path / "f.txt", b"prefix-context-needle-suffix-context")

    matches = scan_file_heuristic(f, repo, snippet_radius=5)
    assert len(matches) == 1
    snippet = matches[0].snippet
    assert "needle" in snippet
    assert len(snippet) <= len("needle") + 10


def test_snippet_radius_zero_equals_match_only(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [{"name": "tag", "pattern": "abc", "severity": "low"}],
    )
    f = _write(tmp_path / "f.txt", b"xxabcyy")
    matches = scan_file_heuristic(f, repo, snippet_radius=0)
    assert matches[0].snippet == "abc"


def test_invalid_snippet_radius(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [{"name": "r", "pattern": "x", "severity": "low"}],
    )
    f = _write(tmp_path / "f.txt", b"x")
    with pytest.raises(ValueError):
        scan_file_heuristic(f, repo, snippet_radius=-1)


def test_invalid_max_bytes(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [{"name": "r", "pattern": "x", "severity": "low"}],
    )
    f = _write(tmp_path / "f.txt", b"x")
    with pytest.raises(ValueError):
        scan_file_heuristic(f, repo, max_bytes=-1)


def test_missing_file_raises(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [{"name": "r", "pattern": "x", "severity": "low"}],
    )
    with pytest.raises(FileNotFoundError):
        scan_file_heuristic(tmp_path / "missing", repo)


def test_accepts_str_path(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [{"name": "r", "pattern": "hit", "severity": "low"}],
    )
    f = _write(tmp_path / "f.txt", b"a hit here")
    matches = scan_file_heuristic(str(f), repo)
    assert len(matches) == 1
    assert matches[0].path == Path(str(f))


def test_inline_regex_flags_supported(tmp_path: Path) -> None:
    """Case-insensitivity via inline ``(?i)`` flag works through JSON."""
    repo = _make_repo(
        tmp_path,
        [{"name": "ci", "pattern": "(?i)PaYlOaD", "severity": "low"}],
    )
    f = _write(tmp_path / "f.txt", b"contains payload here")
    matches = scan_file_heuristic(f, repo)
    assert len(matches) == 1


def test_detection_method_format(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path,
        [{"name": "rule.x_1", "pattern": "z", "severity": "low"}],
    )
    f = _write(tmp_path / "f.txt", b"z")
    matches = scan_file_heuristic(f, repo)
    assert matches[0].detection_method == "heuristic:rule.x_1"


def test_long_base64_blob_pattern(tmp_path: Path) -> None:
    """End-to-end: base64-shape rule from example file detects blob."""
    repo = _make_repo(
        tmp_path,
        [
            {
                "name": "long-base64-blob",
                "pattern": "[A-Za-z0-9+/]{200,}={0,2}",
                "severity": "medium",
            }
        ],
    )
    blob = b"A" * 240 + b"=="
    f = _write(tmp_path / "f.txt", b"prefix " + blob + b" suffix")
    matches = scan_file_heuristic(f, repo)
    assert len(matches) == 1
    assert matches[0].rule_name == "long-base64-blob"


def test_rule_constructed_directly(tmp_path: Path) -> None:
    """HeuristicRuleRepository works without going through JSON."""
    rule = HeuristicRule(
        name="manual",
        pattern=re.compile(r"\bSECRET\b"),
        severity=ThreatLevel.HIGH,
        description="hand-built",
    )
    repo = HeuristicRuleRepository([rule])
    f = _write(tmp_path / "f.txt", b"this is a SECRET token")
    matches = scan_file_heuristic(f, repo)
    assert len(matches) == 1
    assert matches[0].severity is ThreatLevel.HIGH
