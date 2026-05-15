from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.presentation.cli import (
    EXIT_CLEAN,
    EXIT_ERROR,
    EXIT_INFECTED,
    build_parser,
    main,
)


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
                    "description": "EICAR antivirus test string.",
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


def _scan_target(tmp_path: Path, name: str = "target") -> Path:
    target = tmp_path / name
    target.mkdir()
    return target


def test_build_parser_help_does_not_crash(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "sentinel" in out
    assert "scan" in out


def test_scan_help_lists_options(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for token in ("--db", "--rules", "--report", "--max-size"):
        assert token in out


def test_scan_eicar_exits_infected_and_writes_report(
    tmp_path: Path,
    signature_db: Path,
    rules_db: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _scan_target(tmp_path)
    (target / "eicar.com").write_bytes(EICAR_BYTES)
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
        ]
    )

    assert code == EXIT_INFECTED
    assert report.exists()
    content = report.read_text(encoding="utf-8")
    assert "EICAR-Test-File" in content
    assert "Infected:       1" in content
    out = capsys.readouterr().out
    assert "1 infected" in out


def test_scan_clean_directory_exits_clean(
    tmp_path: Path,
    signature_db: Path,
    rules_db: Path,
) -> None:
    target = _scan_target(tmp_path)
    (target / "benign.txt").write_bytes(b"hello world\n")
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
        ]
    )

    assert code == EXIT_CLEAN
    assert report.exists()
    assert "Infected:       0" in report.read_text(encoding="utf-8")


def test_scan_missing_db_exits_error(
    tmp_path: Path,
    rules_db: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _scan_target(tmp_path)
    missing_db = tmp_path / "does-not-exist.json"
    code = main(
        [
            "scan",
            str(target),
            "--db",
            str(missing_db),
            "--rules",
            str(rules_db),
        ]
    )
    assert code == EXIT_ERROR
    err = capsys.readouterr().err
    assert "signature DB not found" in err


def test_scan_missing_rules_exits_error(
    tmp_path: Path,
    signature_db: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _scan_target(tmp_path)
    missing_rules = tmp_path / "no-rules.json"
    code = main(
        [
            "scan",
            str(target),
            "--db",
            str(signature_db),
            "--rules",
            str(missing_rules),
        ]
    )
    assert code == EXIT_ERROR
    err = capsys.readouterr().err
    assert "heuristic rules not found" in err


def test_scan_bad_directory_exits_error(
    tmp_path: Path,
    signature_db: Path,
    rules_db: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "nope"
    code = main(
        [
            "scan",
            str(missing),
            "--db",
            str(signature_db),
            "--rules",
            str(rules_db),
        ]
    )
    assert code == EXIT_ERROR
    err = capsys.readouterr().err
    assert "directory not found" in err


def test_scan_path_is_file_exits_error(
    tmp_path: Path,
    signature_db: Path,
    rules_db: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "file.txt"
    target.write_bytes(b"x")
    code = main(
        [
            "scan",
            str(target),
            "--db",
            str(signature_db),
            "--rules",
            str(rules_db),
        ]
    )
    assert code == EXIT_ERROR
    err = capsys.readouterr().err
    assert "not a directory" in err


def test_scan_invalid_db_json_exits_error(
    tmp_path: Path,
    rules_db: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _scan_target(tmp_path)
    bad_db = tmp_path / "bad.json"
    bad_db.write_text("{not valid json")
    code = main(
        [
            "scan",
            str(target),
            "--db",
            str(bad_db),
            "--rules",
            str(rules_db),
        ]
    )
    assert code == EXIT_ERROR
    err = capsys.readouterr().err
    assert "invalid signature DB" in err


def test_scan_negative_max_size_exits_error(
    tmp_path: Path,
    signature_db: Path,
    rules_db: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _scan_target(tmp_path)
    code = main(
        [
            "scan",
            str(target),
            "--db",
            str(signature_db),
            "--rules",
            str(rules_db),
            "--max-size",
            "-1",
        ]
    )
    assert code == EXIT_ERROR
    err = capsys.readouterr().err
    assert "max-size" in err


def test_scan_heuristic_match_is_non_clean(
    tmp_path: Path,
    signature_db: Path,
    rules_db: Path,
) -> None:
    target = _scan_target(tmp_path)
    (target / "script.py").write_bytes(b"x = eval(input())\n")
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
        ]
    )
    assert code == EXIT_INFECTED
    text = report.read_text(encoding="utf-8")
    assert "Suspicious:     1" in text
    assert "eval-call" in text


def test_scan_with_bloom_flag_detects_eicar(
    tmp_path: Path,
    signature_db: Path,
    rules_db: Path,
) -> None:
    target = _scan_target(tmp_path)
    (target / "eicar.com").write_bytes(EICAR_BYTES)
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
            "--bloom",
        ]
    )

    assert code == EXIT_INFECTED
    text = report.read_text(encoding="utf-8")
    assert "EICAR-Test-File" in text


def test_scan_with_bloom_clean_dir_exits_clean(
    tmp_path: Path,
    signature_db: Path,
    rules_db: Path,
) -> None:
    target = _scan_target(tmp_path)
    (target / "ok.txt").write_bytes(b"clean content")
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
            "--bloom",
            "--bloom-fp-rate",
            "0.001",
        ]
    )
    assert code == EXIT_CLEAN


def test_scan_invalid_bloom_fp_rate_exits_error(
    tmp_path: Path,
    signature_db: Path,
    rules_db: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _scan_target(tmp_path)
    code = main(
        [
            "scan",
            str(target),
            "--db",
            str(signature_db),
            "--rules",
            str(rules_db),
            "--bloom",
            "--bloom-fp-rate",
            "0",
        ]
    )
    assert code == EXIT_ERROR
    err = capsys.readouterr().err
    assert "bloom-fp-rate" in err


def test_scan_default_report_path_when_omitted(
    tmp_path: Path,
    signature_db: Path,
    rules_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    target = _scan_target(tmp_path)
    (target / "ok.txt").write_bytes(b"clean")

    code = main(
        [
            "scan",
            str(target),
            "--db",
            str(signature_db),
            "--rules",
            str(rules_db),
        ]
    )
    assert code == EXIT_CLEAN
    reports = list(tmp_path.glob("sentinel_report_*.log"))
    assert len(reports) == 1
