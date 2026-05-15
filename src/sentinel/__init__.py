from __future__ import annotations

import sys
from typing import Optional, Sequence

from .presentation.cli import main as _cli_main


def main(argv: Optional[Sequence[str]] = None) -> int:
    exit_code = _cli_main(argv)
    if argv is None:
        sys.exit(exit_code)
    return exit_code


__all__ = ["main"]
