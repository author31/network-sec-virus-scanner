from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.infrastructure import FetchError
from sentinel.presentation.cli import EXIT_CLEAN, EXIT_ERROR, main


EICAR_ENTRY = {
    "name": "EICAR-Test-File",
    "threat_level": "low",
    "md5": "44d88612fea8a8f36de82e1278abb02f",
    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "hex_pattern": "58354f2150254041505b345c505a58353428",
    "description": "EICAR antivirus test string (canary).",
}

SAMPLE_HASH = {
    "md5": "a" * 32,
    "sha256": "c" * 64,
}


@pytest.fixture()
def signature_db(tmp_path: Path) -> Path:
    db = tmp_path / "signatures.json"
    db.write_text(json.dumps([EICAR_ENTRY]), encoding="utf-8")
    return db


def _patch_fetcher(monkeypatch: pytest.MonkeyPatch, records):
    def fake_fetcher(api_key: str, *, timeout: int):
        return records

    monkeypatch.setattr(
        "sentinel.application.update_signatures.fetch_getlist",
        fake_fetcher,
    )


def test_update_help_lists_options(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["update", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for token in ("--db", "--threat-level", "--timeout", "--dry-run"):
        assert token in out


def test_update_missing_api_key_exits_error(
    signature_db: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("MALSHARE_API_KEY", raising=False)
    code = main(["update", "--db", str(signature_db)])
    assert code == EXIT_ERROR
    assert "MALSHARE_API_KEY is not set" in capsys.readouterr().err


def test_update_dry_run_does_not_modify_db(
    signature_db: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("MALSHARE_API_KEY", "fake-key")
    original = signature_db.read_text()
    _patch_fetcher(monkeypatch, [SAMPLE_HASH])

    code = main(["update", "--db", str(signature_db), "--dry-run"])
    assert code == EXIT_CLEAN
    assert signature_db.read_text() == original
    out = capsys.readouterr().out
    assert "validated (dry-run)" in out
    assert "added=1" in out


def test_update_writes_parseable_db(
    signature_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sentinel.repository import SignatureRepository

    monkeypatch.setenv("MALSHARE_API_KEY", "fake-key")
    _patch_fetcher(monkeypatch, [SAMPLE_HASH])

    code = main(["update", "--db", str(signature_db)])
    assert code == EXIT_CLEAN

    repo = SignatureRepository.load(signature_db)
    assert repo.lookup_md5("a" * 32) is not None
    assert repo.lookup_md5(EICAR_ENTRY["md5"]) is not None


def test_update_fetch_error_exits_error(
    signature_db: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("MALSHARE_API_KEY", "fake-key")

    def boom(api_key: str, *, timeout: int):
        raise FetchError("network down")

    monkeypatch.setattr(
        "sentinel.application.update_signatures.fetch_getlist", boom
    )

    code = main(["update", "--db", str(signature_db)])
    assert code == EXIT_ERROR
    assert "network down" in capsys.readouterr().err


def test_update_bad_timeout_exits_error(
    signature_db: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("MALSHARE_API_KEY", "fake-key")
    code = main(["update", "--db", str(signature_db), "--timeout", "0"])
    assert code == EXIT_ERROR
    assert "timeout" in capsys.readouterr().err
