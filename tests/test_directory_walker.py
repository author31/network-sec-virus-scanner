from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from sentinel.infrastructure import walk_files


def _write(path: Path, content: bytes = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def test_walks_nested_dirs(tmp_path: Path) -> None:
    a = _write(tmp_path / "a.txt")
    b = _write(tmp_path / "sub" / "b.txt")
    c = _write(tmp_path / "sub" / "deep" / "c.txt")

    result = set(walk_files(tmp_path))
    assert result == {a, b, c}


def test_returns_iterator_of_paths(tmp_path: Path) -> None:
    _write(tmp_path / "only.bin", b"\x00")
    it = walk_files(tmp_path)
    assert iter(it) is it
    items = list(it)
    assert len(items) == 1
    assert isinstance(items[0], Path)


def test_empty_directory(tmp_path: Path) -> None:
    assert list(walk_files(tmp_path)) == []


def test_root_must_exist(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        list(walk_files(tmp_path / "missing"))


def test_root_must_be_directory(tmp_path: Path) -> None:
    f = _write(tmp_path / "file.txt")
    with pytest.raises(NotADirectoryError):
        list(walk_files(f))


def test_negative_max_size_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        list(walk_files(tmp_path, max_file_size=-1))


def test_skips_file_symlink(tmp_path: Path) -> None:
    target = _write(tmp_path / "real.txt", b"data")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    result = set(walk_files(tmp_path))
    assert result == {target}


def test_skips_directory_symlink(tmp_path: Path) -> None:
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    inside = _write(real_dir / "inside.txt")

    other = tmp_path / "other"
    other.mkdir()
    linked = other / "linked_dir"
    linked.symlink_to(real_dir, target_is_directory=True)

    result = set(walk_files(tmp_path))
    assert result == {inside}


def test_does_not_follow_symlink_loop(tmp_path: Path) -> None:
    sub = tmp_path / "sub"
    sub.mkdir()
    _write(sub / "f.txt")
    loop = sub / "loop"
    loop.symlink_to(tmp_path, target_is_directory=True)

    files = list(walk_files(tmp_path))
    assert len(files) == 1


def test_max_file_size_skips_large(tmp_path: Path) -> None:
    small = _write(tmp_path / "small.txt", b"x" * 10)
    _write(tmp_path / "big.txt", b"x" * 1000)

    result = set(walk_files(tmp_path, max_file_size=100))
    assert result == {small}


def test_max_file_size_boundary_inclusive(tmp_path: Path) -> None:
    exact = _write(tmp_path / "exact.bin", b"x" * 50)
    result = set(walk_files(tmp_path, max_file_size=50))
    assert result == {exact}


def test_max_file_size_zero_skips_all(tmp_path: Path) -> None:
    _write(tmp_path / "f.txt", b"x")
    assert list(walk_files(tmp_path, max_file_size=0)) == []


def test_skips_special_files(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    try:
        os.mkfifo(fifo)
    except (AttributeError, OSError):
        pytest.skip("mkfifo not supported")
    reg = _write(tmp_path / "real.txt")
    result = set(walk_files(tmp_path))
    assert result == {reg}


@pytest.mark.skipif(
    os.geteuid() == 0 if hasattr(os, "geteuid") else False,
    reason="root bypasses permission checks",
)
@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX-only permissions")
def test_unreadable_file_skipped_with_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    readable = _write(tmp_path / "ok.txt", b"data")
    blocked = _write(tmp_path / "blocked.txt", b"secret")
    blocked.chmod(0)
    try:
        with caplog.at_level("WARNING", logger="sentinel.infrastructure.directory_walker"):
            result = set(walk_files(tmp_path))
        assert result == {readable}
        assert any("blocked.txt" in rec.message for rec in caplog.records)
    finally:
        blocked.chmod(0o644)


@pytest.mark.skipif(
    os.geteuid() == 0 if hasattr(os, "geteuid") else False,
    reason="root bypasses permission checks",
)
@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX-only permissions")
def test_unreadable_subdir_does_not_crash(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    top = _write(tmp_path / "top.txt", b"a")
    sub = tmp_path / "locked"
    sub.mkdir()
    _write(sub / "inside.txt", b"b")
    sub.chmod(0)
    try:
        with caplog.at_level("WARNING", logger="sentinel.infrastructure.directory_walker"):
            result = set(walk_files(tmp_path))
        assert top in result
    finally:
        sub.chmod(0o755)


def test_broken_symlink_skipped(tmp_path: Path) -> None:
    link = tmp_path / "dangling"
    link.symlink_to(tmp_path / "nonexistent")
    real = _write(tmp_path / "real.txt")
    result = set(walk_files(tmp_path))
    assert result == {real}


def test_accepts_str_root(tmp_path: Path) -> None:
    f = _write(tmp_path / "a.txt")
    result = set(walk_files(str(tmp_path)))
    assert result == {f}
