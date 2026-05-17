from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.presentation.cli import EXIT_CLEAN, EXIT_INFECTED, main


EICAR_BYTES = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_HEX_PATTERN = "58354f2150254041505b345c505a58353428"


@pytest.fixture()
def signature_db(tmp_path: Path) -> Path:
    db = tmp_path / "signatures.json"
    db.write_text(
        json.dumps(
            [
                {
                    "name": "EICAR-Test-File",
                    "threat_level": "low",
                    "md5": EICAR_MD5,
                    "sha256": EICAR_SHA256,
                    "hex_pattern": EICAR_HEX_PATTERN,
                }
            ]
        )
    )
    return db


@pytest.fixture()
def rules_db(tmp_path: Path) -> Path:
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            [
                {
                    "name": "eval-call",
                    "pattern": r"\beval\s*\(",
                    "severity": "medium",
                }
            ]
        )
    )
    return rules


def _argv(target: Path, signature_db: Path, rules_db: Path, idx: Path, report: Path) -> list[str]:
    return [
        "scan",
        str(target),
        "--db",
        str(signature_db),
        "--rules",
        str(rules_db),
        "--report",
        str(report),
        "--use-index",
        "--index-file",
        str(idx),
    ]


def test_use_index_first_run_detects_and_creates_index(
    tmp_path: Path,
    signature_db: Path,
    rules_db: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "tree"
    target.mkdir()
    (target / "eicar.com").write_bytes(EICAR_BYTES)
    idx = tmp_path / "idx.json"
    report = tmp_path / "report.log"

    code = main(_argv(target, signature_db, rules_db, idx, report))

    assert code == EXIT_INFECTED
    assert idx.exists()
    assert report.exists()
    out = capsys.readouterr().out
    assert "1 infected" in out
    assert "cache hits: 0" in out


def test_use_index_second_run_reuses_cache(
    tmp_path: Path,
    signature_db: Path,
    rules_db: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "tree"
    target.mkdir()
    (target / "eicar.com").write_bytes(EICAR_BYTES)
    (target / "clean.txt").write_bytes(b"benign")
    idx = tmp_path / "idx.json"
    report = tmp_path / "report.log"

    code1 = main(_argv(target, signature_db, rules_db, idx, report))
    assert code1 == EXIT_INFECTED
    capsys.readouterr()  # drain first-run output

    code2 = main(_argv(target, signature_db, rules_db, idx, report))
    assert code2 == EXIT_INFECTED
    out = capsys.readouterr().out
    assert "cache hits: 2" in out


def test_use_index_pattern_and_heuristic_are_skipped(
    tmp_path: Path,
    signature_db: Path,
    rules_db: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """File matches hex_pattern + heuristic, but neither should fire in index mode.

    We pick a payload whose hash is NOT in the DB but whose bytes contain the
    EICAR hex pattern, so a non-index scan would surface a pattern hit. In
    index mode, only the hash strategy runs.
    """
    target = tmp_path / "tree"
    target.mkdir()
    # Payload starts with EICAR bytes (so hex_pattern matches) plus garbage so
    # the file hash differs from the EICAR hash.
    (target / "tricky").write_bytes(EICAR_BYTES + b"\x00extra-bytes-to-change-hash")
    idx = tmp_path / "idx.json"
    report = tmp_path / "report.log"

    code = main(_argv(target, signature_db, rules_db, idx, report))
    assert code == EXIT_CLEAN
    body = report.read_text(encoding="utf-8")
    assert "Infected:       0" in body
    assert "Suspicious:     0" in body


def test_use_index_default_path_used_when_not_provided(
    tmp_path: Path,
    signature_db: Path,
    rules_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "tree"
    target.mkdir()
    (target / "clean.txt").write_bytes(b"benign")
    report = tmp_path / "report.log"

    code = main(
        [
            "scan",
            str(target),
            "--db",
            str(signature_db),
            "--rules",
            str(rules_db),
            "--report",
            str(report),
            "--use-index",
        ]
    )
    assert code == EXIT_CLEAN
    assert (tmp_path / "data" / "sentinel_index.json").exists()
