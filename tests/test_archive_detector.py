from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from sentinel.infrastructure import (
    ArchiveType,
    detect_archive_type,
    detect_archive_type_from_bytes,
    is_archive,
)


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (b"PK\x03\x04rest...", ArchiveType.ZIP),
        (b"PK\x05\x06rest...", ArchiveType.ZIP),
        (b"PK\x07\x08rest...", ArchiveType.ZIP),
        (b"7z\xbc\xaf\x27\x1cmore", ArchiveType.SEVEN_ZIP),
        (b"Rar!\x1a\x07\x00", ArchiveType.RAR),
        (b"Rar!\x1a\x07\x01\x00", ArchiveType.RAR),
        (b"\x1f\x8b\x08\x00", ArchiveType.GZIP),
        (b"BZh91AY", ArchiveType.BZIP2),
        (b"\xfd7zXZ\x00", ArchiveType.XZ),
    ],
)
def test_detect_from_bytes_magic_matches(head: bytes, expected: ArchiveType) -> None:
    assert detect_archive_type_from_bytes(head) == expected


def test_detect_from_bytes_returns_none_for_plain_text() -> None:
    assert detect_archive_type_from_bytes(b"hello world, no magic here") is None


def test_detect_from_bytes_returns_none_for_empty() -> None:
    assert detect_archive_type_from_bytes(b"") is None


def test_detect_tar_ustar_at_offset() -> None:
    head = b"\x00" * 257 + b"ustar" + b"\x00" * 3
    assert detect_archive_type_from_bytes(head) == ArchiveType.TAR


def test_detect_archive_type_on_zip_file(tmp_path: Path) -> None:
    p = tmp_path / "a.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("x.txt", "hi")
    assert detect_archive_type(p) == ArchiveType.ZIP
    assert is_archive(p) is True


def test_detect_archive_type_on_tar_gz_file(tmp_path: Path) -> None:
    p = tmp_path / "a.tar.gz"
    with tarfile.open(p, "w:gz") as tf:
        info = tarfile.TarInfo("f.txt")
        data = b"hi"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    # gzip header dominates; entrypoint will decompress + retry as tar
    assert detect_archive_type(p) == ArchiveType.GZIP


def test_detect_archive_type_missing_file(tmp_path: Path) -> None:
    assert detect_archive_type(tmp_path / "missing") is None
    assert is_archive(tmp_path / "missing") is False


def test_detect_archive_type_on_plain_text_file(tmp_path: Path) -> None:
    p = tmp_path / "note.txt"
    p.write_text("just a note\n")
    assert detect_archive_type(p) is None
