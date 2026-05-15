from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from sentinel.application import (
    ArchiveScanEngine,
    LocalArchiveBackend,
    scan_archive_in_process,
)
from sentinel.application.archive_scan_engine import _skipped_finding
from sentinel.repository import (
    HeuristicRuleRepository,
    SignatureRepository,
)

EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_HEX_PATTERN = "58354f2150254041505b345c505a58353428"


@pytest.fixture()
def repos(tmp_path: Path) -> tuple[SignatureRepository, HeuristicRuleRepository]:
    sig_path = tmp_path / "sig.json"
    sig_path.write_text(
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
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(json.dumps([]))
    return (
        SignatureRepository.load(sig_path),
        HeuristicRuleRepository.load(rules_path),
    )


def _write_flat_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("eicar.com", EICAR)


def _write_nested_zip(path: Path) -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as iz:
        iz.writestr("payload/eicar.com", EICAR)
    inner_bytes = inner.getvalue()
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as outer:
        outer.writestr("inner.zip", inner_bytes)


def test_scan_archive_in_process_finds_eicar_inside_zip(
    tmp_path: Path,
    repos: tuple[SignatureRepository, HeuristicRuleRepository],
) -> None:
    signatures, rules = repos
    archive = tmp_path / "flat.zip"
    _write_flat_zip(archive)

    out = tmp_path / "out"
    result = scan_archive_in_process(
        archive_path=archive,
        out_dir=out,
        signatures=signatures,
        rules=rules,
        max_extracted_bytes=1024 * 1024,
        max_files=100,
    )
    assert result.skipped is False
    assert result.archive_type == "zip"
    detection_methods = {f["detection_method"] for f in result.findings}
    assert "hash:sha256" in detection_methods
    assert "pattern:hex" in detection_methods
    assert result.nested_archives == []


def test_scan_archive_in_process_reports_nested_archive(
    tmp_path: Path,
    repos: tuple[SignatureRepository, HeuristicRuleRepository],
) -> None:
    signatures, rules = repos
    archive = tmp_path / "nested.zip"
    _write_nested_zip(archive)

    out = tmp_path / "out"
    result = scan_archive_in_process(
        archive_path=archive,
        out_dir=out,
        signatures=signatures,
        rules=rules,
        max_extracted_bytes=1024 * 1024,
        max_files=100,
    )
    assert result.skipped is False
    assert len(result.nested_archives) == 1
    nested = result.nested_archives[0]
    assert nested["path"] == "inner.zip"
    assert nested["archive_type"] == "zip"
    assert (out / nested["out_file"]).is_file()


def test_scan_archive_in_process_skips_when_bytes_cap_exceeded(
    tmp_path: Path,
    repos: tuple[SignatureRepository, HeuristicRuleRepository],
) -> None:
    signatures, rules = repos
    archive = tmp_path / "big.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("blob.bin", b"A" * 16_384)
    out = tmp_path / "out"
    result = scan_archive_in_process(
        archive_path=archive,
        out_dir=out,
        signatures=signatures,
        rules=rules,
        max_extracted_bytes=4096,
        max_files=100,
    )
    assert result.skipped is True
    assert result.skip_reason == "extracted-bytes-cap"


def test_archive_scan_engine_recursion_uses_provenance(
    tmp_path: Path,
    repos: tuple[SignatureRepository, HeuristicRuleRepository],
) -> None:
    signatures, rules = repos
    archive = tmp_path / "nested.zip"
    _write_nested_zip(archive)

    backend = LocalArchiveBackend(
        signatures=signatures,
        rules=rules,
        max_extracted_bytes=1024 * 1024,
        max_files=100,
    )
    engine = ArchiveScanEngine(backend, max_depth=3)
    outcome = engine.scan(archive)

    provenances = {f.provenance for f in outcome.findings}
    expected_inner = str(archive.resolve()) + "!inner.zip!payload/eicar.com"
    assert expected_inner in provenances
    assert outcome.archives_unpacked >= 2
    assert outcome.archives_skipped == 0
    assert not any(f.is_skipped for f in outcome.findings)


def test_archive_scan_engine_emits_skipped_at_depth_cap(
    tmp_path: Path,
    repos: tuple[SignatureRepository, HeuristicRuleRepository],
) -> None:
    signatures, rules = repos
    archive = tmp_path / "nested.zip"
    _write_nested_zip(archive)

    backend = LocalArchiveBackend(
        signatures=signatures,
        rules=rules,
        max_extracted_bytes=1024 * 1024,
        max_files=100,
    )
    engine = ArchiveScanEngine(backend, max_depth=1)
    outcome = engine.scan(archive)

    skipped = [f for f in outcome.findings if f.is_skipped]
    assert len(skipped) == 1
    assert skipped[0].detection_method.startswith("archive:skipped")
    assert "inner.zip" in skipped[0].provenance


def test_archive_scan_engine_propagates_skipped_from_backend(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "weird.bin"
    archive.write_bytes(b"PK\x03\x04xxx")

    class StubBackend:
        def run(self, archive_path: Path, out_dir: Path) -> dict[str, Any]:
            return {
                "archive_type": "zip",
                "skipped": True,
                "skip_reason": "extracted-bytes-cap",
                "files_extracted": 0,
                "findings": [],
                "nested_archives": [],
            }

    engine = ArchiveScanEngine(StubBackend(), max_depth=3)
    outcome = engine.scan(archive)
    assert outcome.archives_skipped == 1
    assert outcome.archives_unpacked == 0
    assert len(outcome.findings) == 1
    assert outcome.findings[0].is_skipped
    assert outcome.findings[0].detection_method == "archive:skipped:extracted-bytes-cap"


def test_archive_scan_engine_backend_exception_yields_skipped(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "weird.bin"
    archive.write_bytes(b"PK\x03\x04xxx")

    class ExplodingBackend:
        def run(self, archive_path: Path, out_dir: Path) -> dict[str, Any]:
            raise RuntimeError("docker not running")

    engine = ArchiveScanEngine(ExplodingBackend(), max_depth=3)
    outcome = engine.scan(archive)
    assert outcome.archives_skipped == 1
    assert outcome.findings[0].is_skipped
    assert "backend-error" in outcome.findings[0].detection_method


def test_skipped_finding_helper() -> None:
    f = _skipped_finding("/x/y.zip", "timeout")
    assert f.is_skipped is True
    assert f.detection_method == "archive:skipped:timeout"


def test_archive_scan_engine_rejects_zero_depth() -> None:
    class _Stub:
        def run(self, *_args, **_kw):  # pragma: no cover
            return {}

    with pytest.raises(ValueError):
        ArchiveScanEngine(_Stub(), max_depth=0)
