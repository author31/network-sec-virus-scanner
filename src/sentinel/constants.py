"""Shared default constants used across sentinel modules."""
from __future__ import annotations

DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_FILES = 10_000
DEFAULT_ARCHIVE_DEPTH = 3

__all__ = [
    "DEFAULT_ARCHIVE_DEPTH",
    "DEFAULT_MAX_EXTRACTED_BYTES",
    "DEFAULT_MAX_FILES",
    "DEFAULT_TIMEOUT_SECONDS",
]
