from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.presentation.cli import EXIT_INFECTED, main

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "demo_tree"
SIGNATURE_DB = REPO_ROOT / "data" / "signatures.json"
HEURISTIC_RULES = REPO_ROOT / "data" / "heuristic_rules.example.json"

EXPECTED_FLAGGED = ("eicar.com", "with_pattern.bin", "suspicious.txt")
EXPECTED_CLEAN = ("clean1.txt", "clean2.bin")


def test_demo_tree_full_scan_flags_expected_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert FIXTURE_DIR.is_dir(), f"missing fixture tree: {FIXTURE_DIR}"
    assert SIGNATURE_DB.is_file(), f"missing signature DB: {SIGNATURE_DB}"
    assert HEURISTIC_RULES.is_file(), f"missing rules: {HEURISTIC_RULES}"

    report_path = tmp_path / "demo_report.log"

    exit_code = main(
        [
            "scan",
            str(FIXTURE_DIR),
            "--db",
            str(SIGNATURE_DB),
            "--rules",
            str(HEURISTIC_RULES),
            "--report",
            str(report_path),
        ]
    )

    assert exit_code == EXIT_INFECTED, (
        f"expected EXIT_INFECTED ({EXIT_INFECTED}), got {exit_code}"
    )

    assert report_path.is_file(), "report file was not written"
    report_text = report_path.read_text(encoding="utf-8")

    finding_lines = [
        line
        for line in report_text.splitlines()
        if line and not line.startswith("===") and " | " in line
    ]
    flagged_paths = {line.split(" | ", 2)[1] for line in finding_lines}

    for name in EXPECTED_FLAGGED:
        assert any(name in p for p in flagged_paths), (
            f"expected {name} to be flagged in report, got {flagged_paths}"
        )

    for clean_name in EXPECTED_CLEAN:
        assert not any(clean_name in p for p in flagged_paths), (
            f"clean file {clean_name} was unexpectedly flagged: {flagged_paths}"
        )

    assert "Total scanned:  5" in report_text
    assert "Infected:       2" in report_text
    assert "Suspicious:     1" in report_text
    assert "Clean:          2" in report_text

    stdout = capsys.readouterr().out
    assert "2 infected" in stdout
    assert "1 suspicious" in stdout
