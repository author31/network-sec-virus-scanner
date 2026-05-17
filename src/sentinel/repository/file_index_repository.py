from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Iterable, Iterator, Optional

from .file_index_entry import FileIndexEntry

_MD5_LEN = 32
_SHA256_LEN = 64
_REQUIRED_FIELDS = {"path", "size", "mtime_ns", "md5", "sha256", "scanned_at"}


class FileIndexValidationError(ValueError):
    """Raised when a file-index entry fails validation."""

    def __init__(self, message: str, *, index: Optional[int] = None) -> None:
        prefix = f"entry[{index}]: " if index is not None else ""
        super().__init__(f"{prefix}{message}")
        self.index = index


def _is_hex(value: str, *, exact_len: int) -> bool:
    if len(value) != exact_len:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _validate_entry(raw: object, index: int) -> FileIndexEntry:
    if not isinstance(raw, dict):
        raise FileIndexValidationError("must be a JSON object", index=index)

    missing = _REQUIRED_FIELDS - raw.keys()
    if missing:
        raise FileIndexValidationError(
            f"missing required field(s): {sorted(missing)}", index=index
        )

    path = raw["path"]
    if not isinstance(path, str) or not path:
        raise FileIndexValidationError("'path' must be a non-empty string", index=index)

    size = raw["size"]
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise FileIndexValidationError(
            "'size' must be a non-negative integer", index=index
        )

    mtime_ns = raw["mtime_ns"]
    if not isinstance(mtime_ns, int) or isinstance(mtime_ns, bool):
        raise FileIndexValidationError(
            "'mtime_ns' must be an integer", index=index
        )

    md5 = raw["md5"]
    if not isinstance(md5, str) or not _is_hex(md5, exact_len=_MD5_LEN):
        raise FileIndexValidationError(
            "'md5' must be a 32-char hex string", index=index
        )

    sha256 = raw["sha256"]
    if not isinstance(sha256, str) or not _is_hex(sha256, exact_len=_SHA256_LEN):
        raise FileIndexValidationError(
            "'sha256' must be a 64-char hex string", index=index
        )

    scanned_at = raw["scanned_at"]
    if not isinstance(scanned_at, str) or not scanned_at:
        raise FileIndexValidationError(
            "'scanned_at' must be a non-empty string", index=index
        )

    return FileIndexEntry(
        path=path,
        size=size,
        mtime_ns=mtime_ns,
        md5=md5.lower(),
        sha256=sha256.lower(),
        scanned_at=scanned_at,
    )


class FileIndexRepository:
    """Persistent local index of scanned files.

    Maps absolute path -> (size, mtime_ns, md5, sha256). Acts like a DB
    index: on rescan, ``lookup`` returns the cached hashes when both size
    and mtime_ns match, letting the caller skip recomputing them.
    """

    def __init__(self, entries: Iterable[FileIndexEntry] = ()) -> None:
        self._by_path: dict[str, FileIndexEntry] = {}
        for entry in entries:
            self._by_path[entry.path] = entry

    @classmethod
    def load(cls, path: str | Path) -> "FileIndexRepository":
        path = Path(path)
        if not path.exists():
            return cls()
        with path.open("r", encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise FileIndexValidationError(
                    f"invalid JSON in {path}: {exc.msg} "
                    f"(line {exc.lineno}, col {exc.colno})"
                ) from exc

        if not isinstance(data, list):
            raise FileIndexValidationError(
                "top-level JSON must be a list of file-index entries"
            )

        entries = [_validate_entry(raw, idx) for idx, raw in enumerate(data)]
        return cls(entries)

    def lookup(
        self,
        path: str | os.PathLike[str],
        size: int,
        mtime_ns: int,
    ) -> Optional[FileIndexEntry]:
        key = os.fspath(path)
        entry = self._by_path.get(key)
        if entry is None:
            return None
        if entry.size != size or entry.mtime_ns != mtime_ns:
            return None
        return entry

    def upsert(self, entry: FileIndexEntry) -> None:
        self._by_path[entry.path] = entry

    def save(self, path: str | Path) -> None:
        path = Path(path)
        payload = [
            {
                "path": e.path,
                "size": e.size,
                "mtime_ns": e.mtime_ns,
                "md5": e.md5,
                "sha256": e.sha256,
                "scanned_at": e.scanned_at,
            }
            for e in self._by_path.values()
        ]
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=False)
                fh.write("\n")
            os.replace(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def __len__(self) -> int:
        return len(self._by_path)

    def __iter__(self) -> Iterator[FileIndexEntry]:
        return iter(self._by_path.values())

    def __contains__(self, path: object) -> bool:
        if not isinstance(path, (str, os.PathLike)):
            return False
        return os.fspath(path) in self._by_path
