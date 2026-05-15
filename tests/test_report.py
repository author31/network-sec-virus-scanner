from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.application import (
    DETECTION_METHOD_MD5,
    DETECTION_METHOD_PATTERN_HEX,
    DETECTION_METHOD_PREFIX,
    DETECTION_METHOD_SHA256,
    HashScanResult,
    HeuristicMatch,
    PatternScanResult,
)
from sentinel.presentation import (
    REPORT_FILENAME_PREFIX,
    REPORT_FILENAME_SUFFIX,
    SUMMARY_FOOTER,
    SUMMARY_HEADER,
    ScanReport,
    build_report,
    default_report_path,
    render_report,
    write_report,
)
from sentinel.repository import Signature, ThreatLevel


T0 = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(seconds=2, microseconds=500_000)


def _sig(name: str, level: ThreatLevel, **kw: object) -> Signature:
    return Signature(name=name, threat_level=level, **kw)  # type: ignore[arg-type]


def _hash_result(path: Path, name: str, level: ThreatLevel) -> HashScanResult:
    return HashScanResult(
        path=path,
        signature=_sig(name, level, sha256="a" * 64),
        detection_method=DETECTION_METHOD_SHA256,
        md5="0" * 32,
        sha256="a" * 64,
    )


def _pattern_result(path: Path, name: str, level: ThreatLevel) -> PatternScanResult:
    return PatternScanResult(
        path=path,
        signature=_sig(name, level, hex_pattern="deadbeef"),
        detection_method=DETECTION_METHOD_PATTERN_HEX,
        offset=128,
    )


def _heuristic(path: Path, rule: str, level: ThreatLevel) -> HeuristicMatch:
    return HeuristicMatch(
        path=path,
        rule_name=rule,
        severity=level,
        detection_method=f"{DETECTION_METHOD_PREFIX}{rule}",
        snippet="exec(",
        offset=0,
    )


def test_build_report_counts_and_paths(tmp_path: Path) -> None:
    infected_a = tmp_path / "a"
    infected_b = tmp_path / "b"
    suspicious_c = tmp_path / "c"
    infected_a.write_bytes(b"x")
    infected_b.write_bytes(b"x")
    suspicious_c.write_bytes(b"x")

    report = build_report(
        hash_results=[_hash_result(infected_a, "Mal-A", ThreatLevel.HIGH)],
        pattern_results=[_pattern_result(infected_b, "Mal-B", ThreatLevel.CRITICAL)],
        heuristic_matches=[_heuristic(suspicious_c, "eval-call", ThreatLevel.MEDIUM)],
        total_files=10,
        started_at=T0,
        ended_at=T1,
        timestamp=T0,
    )

    assert report.total_files == 10
    assert report.infected_count == 2
    assert report.suspicious_count == 1
    assert report.clean_count == 7
    assert report.duration_seconds == pytest.approx(2.5)


def test_signature_match_overrides_heuristic_for_same_path(tmp_path: Path) -> None:
    p = tmp_path / "dup"
    p.write_bytes(b"x")

    report = build_report(
        hash_results=[_hash_result(p, "Mal", ThreatLevel.HIGH)],
        heuristic_matches=[_heuristic(p, "eval", ThreatLevel.MEDIUM)],
        total_files=1,
        started_at=T0,
        ended_at=T1,
        timestamp=T0,
    )

    assert report.infected_count == 1
    assert report.suspicious_count == 0
    assert report.clean_count == 0


def test_render_emits_one_line_per_finding_plus_summary(tmp_path: Path) -> None:
    f1 = tmp_path / "a"
    f2 = tmp_path / "b"
    f1.write_bytes(b"x")
    f2.write_bytes(b"x")

    report = build_report(
        hash_results=[_hash_result(f1, "Mal-A", ThreatLevel.HIGH)],
        heuristic_matches=[_heuristic(f2, "eval-call", ThreatLevel.LOW)],
        total_files=2,
        started_at=T0,
        ended_at=T1,
        timestamp=T0,
    )

    text = render_report(report)
    body, _, _ = text.partition("\n\n")
    body_lines = body.splitlines()
    assert len(body_lines) == 2

    assert str(f1.resolve()) in body_lines[0]
    assert "Mal-A" in body_lines[0]
    assert DETECTION_METHOD_SHA256 in body_lines[0]
    assert "high" in body_lines[0]

    assert str(f2.resolve()) in body_lines[1]
    assert "eval-call" in body_lines[1]
    assert f"{DETECTION_METHOD_PREFIX}eval-call" in body_lines[1]

    assert SUMMARY_HEADER in text
    assert SUMMARY_FOOTER in text
    assert "Total scanned:  2" in text
    assert "Infected:       1" in text
    assert "Suspicious:     1" in text
    assert "Clean:          0" in text
    assert "Duration:       2.500s" in text


def test_render_uses_absolute_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    rel = Path("nested/file.bin")
    abs_p = tmp_path / rel
    abs_p.parent.mkdir(parents=True)
    abs_p.write_bytes(b"x")

    report = build_report(
        hash_results=[_hash_result(rel, "Mal", ThreatLevel.HIGH)],
        total_files=1,
        started_at=T0,
        ended_at=T1,
        timestamp=T0,
    )
    line = render_report(report).splitlines()[0]
    assert str(abs_p.resolve()) in line
    assert not line.startswith("nested/")


def test_render_timestamps_are_iso_utc(tmp_path: Path) -> None:
    p = tmp_path / "a"
    p.write_bytes(b"x")
    report = build_report(
        hash_results=[_hash_result(p, "Mal", ThreatLevel.HIGH)],
        total_files=1,
        started_at=T0,
        ended_at=T1,
        timestamp=T0,
    )
    line = render_report(report).splitlines()[0]
    ts = line.split(" | ", 1)[0]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", ts)
    assert ts == "2026-05-15T12:00:00Z"


def test_write_report_creates_file_with_expected_content(tmp_path: Path) -> None:
    p = tmp_path / "a"
    p.write_bytes(b"x")
    report = build_report(
        hash_results=[_hash_result(p, "Mal-A", ThreatLevel.HIGH)],
        total_files=1,
        started_at=T0,
        ended_at=T1,
        timestamp=T0,
    )
    out = tmp_path / "out.log"
    returned = write_report(report, out)
    assert returned == out
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert content.endswith("\n")
    assert "Mal-A" in content
    assert SUMMARY_HEADER in content


def test_write_report_creates_parent_dirs(tmp_path: Path) -> None:
    p = tmp_path / "a"
    p.write_bytes(b"x")
    report = build_report(
        hash_results=[_hash_result(p, "Mal", ThreatLevel.HIGH)],
        total_files=1,
        started_at=T0,
        ended_at=T1,
        timestamp=T0,
    )
    nested = tmp_path / "reports" / "2026" / "out.log"
    write_report(report, nested)
    assert nested.exists()


def test_default_report_path_format(tmp_path: Path) -> None:
    fixed = datetime(2026, 5, 15, 13, 4, 5, tzinfo=timezone.utc)
    path = default_report_path(now=fixed, base_dir=tmp_path)
    assert path.parent == tmp_path
    assert path.name == f"{REPORT_FILENAME_PREFIX}20260515T130405Z{REPORT_FILENAME_SUFFIX}"


def test_default_report_path_uses_cwd_when_no_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    fixed = datetime(2026, 5, 15, 13, 4, 5, tzinfo=timezone.utc)
    path = default_report_path(now=fixed)
    assert path.parent == tmp_path
    assert path.name.startswith(REPORT_FILENAME_PREFIX)
    assert path.name.endswith(REPORT_FILENAME_SUFFIX)


def test_empty_findings_still_renders_summary(tmp_path: Path) -> None:
    report = ScanReport(
        findings=(),
        total_files=3,
        started_at=T0,
        ended_at=T1,
    )
    text = render_report(report)
    assert SUMMARY_HEADER in text
    assert "Total scanned:  3" in text
    assert "Clean:          3" in text
    assert "Infected:       0" in text
    assert "Suspicious:     0" in text


def test_md5_detection_method_recorded(tmp_path: Path) -> None:
    p = tmp_path / "a"
    p.write_bytes(b"x")
    res = HashScanResult(
        path=p,
        signature=_sig("Mal-MD5", ThreatLevel.LOW, md5="b" * 32),
        detection_method=DETECTION_METHOD_MD5,
        md5="b" * 32,
        sha256="c" * 64,
    )
    report = build_report(
        hash_results=[res],
        total_files=1,
        started_at=T0,
        ended_at=T1,
        timestamp=T0,
    )
    line = render_report(report).splitlines()[0]
    assert DETECTION_METHOD_MD5 in line
    assert "low" in line


def test_multiple_findings_same_path_one_signature_keeps_infected(
    tmp_path: Path,
) -> None:
    p = tmp_path / "a"
    p.write_bytes(b"x")
    report = build_report(
        hash_results=[_hash_result(p, "Mal-Hash", ThreatLevel.HIGH)],
        pattern_results=[_pattern_result(p, "Mal-Pat", ThreatLevel.CRITICAL)],
        heuristic_matches=[_heuristic(p, "eval", ThreatLevel.MEDIUM)],
        total_files=1,
        started_at=T0,
        ended_at=T1,
        timestamp=T0,
    )
    assert report.infected_count == 1
    assert report.suspicious_count == 0
    assert report.clean_count == 0
    text = render_report(report)
    assert "Mal-Hash" in text
    assert "Mal-Pat" in text
    assert "eval" in text
    assert text.count(str(p.resolve())) == 3
