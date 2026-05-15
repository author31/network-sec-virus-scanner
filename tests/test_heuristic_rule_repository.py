from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.repository import (
    HeuristicRule,
    HeuristicRuleRepository,
    HeuristicRuleValidationError,
    ThreatLevel,
)


def _write(path: Path, entries: object) -> Path:
    path.write_text(json.dumps(entries), encoding="utf-8")
    return path


def test_loads_rules_from_json(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "rules.json",
        [
            {
                "name": "rule-a",
                "pattern": "foo|bar",
                "severity": "high",
                "description": "demo",
            },
            {
                "name": "rule-b",
                "pattern": r"\d{3,}",
                "severity": "low",
            },
        ],
    )
    repo = HeuristicRuleRepository.load(f)
    rules = list(repo)

    assert len(repo) == 2
    assert all(isinstance(r, HeuristicRule) for r in rules)
    assert rules[0].name == "rule-a"
    assert rules[0].severity is ThreatLevel.HIGH
    assert rules[0].description == "demo"
    assert rules[0].pattern.search("xxfoo") is not None
    assert rules[1].pattern.search("123") is not None
    assert rules[1].description is None


def test_load_rejects_missing_required_fields(tmp_path: Path) -> None:
    f = _write(tmp_path / "r.json", [{"name": "x", "pattern": "y"}])
    with pytest.raises(HeuristicRuleValidationError) as exc:
        HeuristicRuleRepository.load(f)
    assert "severity" in str(exc.value)
    assert exc.value.index == 0


def test_load_rejects_unknown_fields(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "r.json",
        [
            {
                "name": "x",
                "pattern": "y",
                "severity": "low",
                "extra": "nope",
            }
        ],
    )
    with pytest.raises(HeuristicRuleValidationError) as exc:
        HeuristicRuleRepository.load(f)
    assert "extra" in str(exc.value)


def test_load_rejects_bad_severity(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "r.json",
        [{"name": "x", "pattern": "y", "severity": "spicy"}],
    )
    with pytest.raises(HeuristicRuleValidationError) as exc:
        HeuristicRuleRepository.load(f)
    assert "severity" in str(exc.value)


def test_load_rejects_invalid_regex(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "r.json",
        [{"name": "x", "pattern": "(unclosed", "severity": "low"}],
    )
    with pytest.raises(HeuristicRuleValidationError) as exc:
        HeuristicRuleRepository.load(f)
    assert "regex" in str(exc.value)


def test_load_rejects_empty_pattern(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "r.json",
        [{"name": "x", "pattern": "", "severity": "low"}],
    )
    with pytest.raises(HeuristicRuleValidationError):
        HeuristicRuleRepository.load(f)


def test_load_rejects_blank_name(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "r.json",
        [{"name": "   ", "pattern": "y", "severity": "low"}],
    )
    with pytest.raises(HeuristicRuleValidationError):
        HeuristicRuleRepository.load(f)


def test_load_rejects_non_list_top_level(tmp_path: Path) -> None:
    f = _write(tmp_path / "r.json", {"not": "a list"})
    with pytest.raises(HeuristicRuleValidationError):
        HeuristicRuleRepository.load(f)


def test_load_rejects_invalid_json(tmp_path: Path) -> None:
    f = tmp_path / "r.json"
    f.write_text("{not json", encoding="utf-8")
    with pytest.raises(HeuristicRuleValidationError):
        HeuristicRuleRepository.load(f)


def test_load_rejects_duplicate_rule_names(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "r.json",
        [
            {"name": "dup", "pattern": "a", "severity": "low"},
            {"name": "dup", "pattern": "b", "severity": "low"},
        ],
    )
    with pytest.raises(HeuristicRuleValidationError) as exc:
        HeuristicRuleRepository.load(f)
    assert "duplicate" in str(exc.value)


def test_load_rejects_description_wrong_type(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "r.json",
        [
            {
                "name": "x",
                "pattern": "y",
                "severity": "low",
                "description": 123,
            }
        ],
    )
    with pytest.raises(HeuristicRuleValidationError):
        HeuristicRuleRepository.load(f)


def test_load_example_rules_file_succeeds() -> None:
    example = (
        Path(__file__).resolve().parents[1]
        / "data"
        / "heuristic_rules.example.json"
    )
    repo = HeuristicRuleRepository.load(example)
    names = {r.name for r in repo}
    assert "win-api-process-injection" in names
    assert "powershell-encoded-command" in names
    assert len(repo) >= 3


def test_repository_iterable_and_len_match() -> None:
    rules = [
        HeuristicRule(
            name=f"r{i}",
            pattern=__import__("re").compile(str(i)),
            severity=ThreatLevel.LOW,
        )
        for i in range(3)
    ]
    repo = HeuristicRuleRepository(rules)
    assert len(repo) == 3
    assert [r.name for r in repo] == ["r0", "r1", "r2"]
