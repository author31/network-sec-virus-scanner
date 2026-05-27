from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional, Sequence

from ..application import (
    ArchiveFinding,
    EntropyScanResult,
    HashScanResult,
    HeuristicMatch,
    PatternScanResult,
)
from ..repository import ThreatLevel

REPORT_FILENAME_PREFIX = "sentinel_report_"
REPORT_FILENAME_SUFFIX = ".log"
DEFAULT_LOG_DIRNAME = "logs"
_TIMESTAMP_FILENAME_FMT = "%Y%m%dT%H%M%SZ"
_TIMESTAMP_FIELD_FMT = "%Y-%m-%dT%H:%M:%SZ"

SUMMARY_HEADER = "=== Scan Summary ==="
SUMMARY_FOOTER = "====================="


@dataclass(frozen=True)
class Finding:
    path: Path
    detection_method: str
    signature_name: str
    threat_level: ThreatLevel
    timestamp: datetime
    is_heuristic: bool = False
    is_skipped: bool = False


@dataclass(frozen=True)
class ScanReport:
    findings: Sequence[Finding]
    total_files: int
    started_at: datetime
    ended_at: datetime
    archives_unpacked: int = 0
    archives_skipped: int = 0
    extra_scanned_paths: Sequence[Path] = field(default_factory=tuple)

    @property
    def duration_seconds(self) -> float:
        return (self.ended_at - self.started_at).total_seconds()

    @property
    def infected_count(self) -> int:
        return len(self._infected_paths())

    @property
    def suspicious_count(self) -> int:
        infected = self._infected_paths()
        suspicious: set[Path] = set()
        for f in self.findings:
            if f.is_skipped:
                continue
            if f.is_heuristic and f.path not in infected:
                suspicious.add(f.path)
        return len(suspicious)

    @property
    def clean_count(self) -> int:
        return max(0, self.total_files - self.infected_count - self.suspicious_count)

    def _infected_paths(self) -> set[Path]:
        return {
            f.path
            for f in self.findings
            if not f.is_heuristic and not f.is_skipped
        }


def finding_from_hash(
    result: HashScanResult, *, timestamp: Optional[datetime] = None
) -> Finding:
    return Finding(
        path=_abs(result.path),
        detection_method=result.detection_method,
        signature_name=result.signature.name,
        threat_level=result.signature.threat_level,
        timestamp=_now(timestamp),
        is_heuristic=False,
    )


def finding_from_pattern(
    result: PatternScanResult, *, timestamp: Optional[datetime] = None
) -> Finding:
    return Finding(
        path=_abs(result.path),
        detection_method=result.detection_method,
        signature_name=result.signature.name,
        threat_level=result.signature.threat_level,
        timestamp=_now(timestamp),
        is_heuristic=False,
    )


def finding_from_heuristic(
    match: HeuristicMatch, *, timestamp: Optional[datetime] = None
) -> Finding:
    return Finding(
        path=_abs(match.path),
        detection_method=match.detection_method,
        signature_name=match.rule_name,
        threat_level=match.severity,
        timestamp=_now(timestamp),
        is_heuristic=True,
    )


def finding_from_entropy(
    result: EntropyScanResult, *, timestamp: Optional[datetime] = None
) -> Finding:
    return Finding(
        path=_abs(result.path),
        detection_method=result.detection_method,
        signature_name=f"high-entropy({result.entropy:.3f})",
        threat_level=result.threat_level,
        timestamp=_now(timestamp),
        is_heuristic=True,
    )


def finding_from_archive(
    archive_finding: ArchiveFinding,
    *,
    timestamp: Optional[datetime] = None,
) -> Finding:
    """Convert an :class:`ArchiveFinding` to a report :class:`Finding`.

    Provenance paths (``outer.zip!inner.tar!payload.exe``) are stored
    verbatim — they are virtual paths, not filesystem paths, so we do not
    resolve them.
    """
    return Finding(
        path=Path(archive_finding.provenance),
        detection_method=archive_finding.detection_method,
        signature_name=archive_finding.signature_name,
        threat_level=archive_finding.threat_level,
        timestamp=_now(timestamp),
        is_heuristic=archive_finding.is_heuristic,
        is_skipped=archive_finding.is_skipped,
    )


def default_report_path(
    *, now: Optional[datetime] = None, base_dir: Optional[Path] = None
) -> Path:
    stamp = _now(now).strftime(_TIMESTAMP_FILENAME_FMT)
    directory = base_dir if base_dir is not None else Path.cwd() / DEFAULT_LOG_DIRNAME
    return directory / f"{REPORT_FILENAME_PREFIX}{stamp}{REPORT_FILENAME_SUFFIX}"


def render_report(report: ScanReport) -> str:
    lines: list[str] = []
    for f in report.findings:
        lines.append(_format_finding(f))
    lines.append("")
    lines.extend(_format_summary(report))
    return "\n".join(lines) + "\n"


def write_report(
    report: ScanReport, path: str | os.PathLike[str]
) -> Path:
    out = Path(path)
    parent = out.parent
    if str(parent) and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_report(report), encoding="utf-8")
    return out


def build_report(
    *,
    hash_results: Iterable[HashScanResult] = (),
    pattern_results: Iterable[PatternScanResult] = (),
    heuristic_matches: Iterable[HeuristicMatch] = (),
    entropy_results: Iterable[EntropyScanResult] = (),
    archive_findings: Iterable[ArchiveFinding] = (),
    total_files: int,
    started_at: datetime,
    ended_at: datetime,
    archives_unpacked: int = 0,
    archives_skipped: int = 0,
    timestamp: Optional[datetime] = None,
) -> ScanReport:
    """Convert engine results into a :class:`ScanReport`.

    ``timestamp`` overrides per-finding detection time (used by tests for
    deterministic output); when ``None``, the current UTC time is recorded.
    """
    findings: list[Finding] = []
    for r in hash_results:
        findings.append(finding_from_hash(r, timestamp=timestamp))
    for r in pattern_results:
        findings.append(finding_from_pattern(r, timestamp=timestamp))
    for m in heuristic_matches:
        findings.append(finding_from_heuristic(m, timestamp=timestamp))
    for e in entropy_results:
        findings.append(finding_from_entropy(e, timestamp=timestamp))
    for a in archive_findings:
        findings.append(finding_from_archive(a, timestamp=timestamp))

    findings.sort(key=lambda f: (str(f.path), f.timestamp, f.signature_name))

    return ScanReport(
        findings=tuple(findings),
        total_files=total_files,
        started_at=started_at,
        ended_at=ended_at,
        archives_unpacked=archives_unpacked,
        archives_skipped=archives_skipped,
    )


def _format_finding(f: Finding) -> str:
    return " | ".join(
        [
            _fmt_ts(f.timestamp),
            str(f.path),
            f.detection_method,
            f.signature_name,
            f.threat_level.value,
        ]
    )


def _format_summary(report: ScanReport) -> list[str]:
    return [
        SUMMARY_HEADER,
        f"Started:        {_fmt_ts(report.started_at)}",
        f"Ended:          {_fmt_ts(report.ended_at)}",
        f"Duration:       {report.duration_seconds:.3f}s",
        f"Total scanned:  {report.total_files}",
        f"Clean:          {report.clean_count}",
        f"Infected:       {report.infected_count}",
        f"Suspicious:     {report.suspicious_count}",
        f"Archives unpacked: {report.archives_unpacked}",
        f"Archives skipped:  {report.archives_skipped}",
        SUMMARY_FOOTER,
    ]


def _abs(path: Path) -> Path:
    p = Path(path)
    try:
        return p.resolve(strict=False)
    except OSError:
        return p.absolute()


def _now(value: Optional[datetime]) -> datetime:
    if value is not None:
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.now(tz=timezone.utc)


def _fmt_ts(value: datetime) -> str:
    aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return aware.astimezone(timezone.utc).strftime(_TIMESTAMP_FIELD_FMT)
