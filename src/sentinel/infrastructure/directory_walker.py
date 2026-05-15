from __future__ import annotations

import logging
import os
import stat
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


def walk_files(
    root: str | os.PathLike[str],
    *,
    max_file_size: Optional[int] = None,
) -> Iterator[Path]:
    """Recursively yield regular files under ``root``.

    Skips symlinks (both directory and file) to avoid loops and traversal
    outside the intended tree. Skips files that cannot be stat'd or read
    (permission errors, races, broken links), logging a warning and
    continuing.

    Args:
        root: Directory to walk.
        max_file_size: When set, files larger than this many bytes are
            skipped. ``None`` (default) disables the guard.

    Yields:
        ``pathlib.Path`` objects for each eligible regular file.

    Raises:
        FileNotFoundError: ``root`` does not exist.
        NotADirectoryError: ``root`` exists but is not a directory.
    """
    root_path = Path(root)
    if not root_path.exists():
        raise FileNotFoundError(f"directory not found: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"not a directory: {root_path}")
    if max_file_size is not None and max_file_size < 0:
        raise ValueError("max_file_size must be non-negative")

    for dirpath, dirnames, filenames in os.walk(
        root_path, followlinks=False, onerror=_on_walk_error
    ):
        dirnames[:] = [d for d in dirnames if not _is_symlink(Path(dirpath) / d)]

        for name in filenames:
            candidate = Path(dirpath) / name
            try:
                if candidate.is_symlink():
                    continue
                st = candidate.stat()
            except OSError as exc:
                logger.warning("skipping %s: %s", candidate, exc)
                continue

            if not _is_regular_file(st.st_mode):
                continue

            if max_file_size is not None and st.st_size > max_file_size:
                logger.warning(
                    "skipping %s: size %d exceeds max_file_size %d",
                    candidate,
                    st.st_size,
                    max_file_size,
                )
                continue

            if not os.access(candidate, os.R_OK):
                logger.warning("skipping %s: not readable", candidate)
                continue

            yield candidate


def _on_walk_error(exc: OSError) -> None:
    logger.warning("walk error at %s: %s", getattr(exc, "filename", "?"), exc)


def _is_symlink(path: Path) -> bool:
    try:
        return path.is_symlink()
    except OSError:
        return False


def _is_regular_file(mode: int) -> bool:
    return stat.S_ISREG(mode)
