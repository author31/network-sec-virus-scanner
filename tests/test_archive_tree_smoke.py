from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.presentation.cli import (
    BACKEND_ENV_VAR,
    BACKEND_LOCAL,
    EXIT_INFECTED,
    main,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "archive_tree"
SIGNATURE_DB = REPO_ROOT / "data" / "signatures.json"
HEURISTIC_RULES = REPO_ROOT / "data" / "heuristic_rules.example.json"

# Cap small enough that zipbomb_small.zip (200 KiB extracted) is skipped,
# but large enough for EICAR (~70 B) and the inner zip (~200 B) to fit.
ARCHIVE_BYTES_CAP = 32 * 1024


def test_archive_tree_smoke_with_local_backend(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert FIXTURE_DIR.is_dir(), f"missing fixture tree: {FIXTURE_DIR}"
    assert SIGNATURE_DB.is_file(), f"missing signature DB: {SIGNATURE_DB}"
    assert HEURISTIC_RULES.is_file(), f"missing rules: {HEURISTIC_RULES}"

    monkeypatch.setenv(BACKEND_ENV_VAR, BACKEND_LOCAL)
    report_path = tmp_path / "archive_report.log"

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
            "--unpack-archives",
            "--archive-max-extracted-bytes",
            str(ARCHIVE_BYTES_CAP),
        ]
    )

    assert exit_code == EXIT_INFECTED, (
        f"expected EXIT_INFECTED ({EXIT_INFECTED}), got {exit_code}"
    )
    assert report_path.is_file()
    text = report_path.read_text(encoding="utf-8")

    finding_lines = [
        line
        for line in text.splitlines()
        if line and not line.startswith("===") and " | " in line
    ]

    flagged_paths = {line.split(" | ", 2)[1] for line in finding_lines}
    flat_hits = [p for p in flagged_paths if "flat_eicar.zip!eicar.com" in p]
    nested_hits = [
        p
        for p in flagged_paths
        if "nested_eicar.tar.gz!" in p and "payload/eicar.com" in p
    ]
    assert flat_hits, f"expected flat archive hit, got: {flagged_paths}"
    assert nested_hits, f"expected nested archive hit, got: {flagged_paths}"

    skipped_lines = [line for line in finding_lines if "archive:skipped" in line]
    assert len(skipped_lines) >= 1, (
        f"expected an archive:skipped line for zipbomb, got: {finding_lines}"
    )
    assert any("zipbomb_small.zip" in line for line in skipped_lines)

    assert "Infected:       2" in text
    assert "Archives unpacked:" in text
    assert "Archives skipped:" in text

    stdout = capsys.readouterr().out
    assert "2 infected" in stdout


def test_archive_unpack_disabled_falls_back_to_opaque_scan(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.log"
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
    text = report_path.read_text(encoding="utf-8")
    assert "Archives unpacked: 0" in text
    assert "Archives skipped:  0" in text
    assert exit_code in (0, 1)
