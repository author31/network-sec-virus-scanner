from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger("sentinel.watcher")


class _ScanHandler(FileSystemEventHandler):
    def __init__(self, callback: Callable[[Path], None]) -> None:
        super().__init__()
        self._callback = callback

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._dispatch(event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._dispatch(event.src_path)

    def _dispatch(self, src_path: str) -> None:
        path = Path(src_path)
        if path.is_symlink() or not path.is_file():
            return
        logger.debug("file event: %s", path)
        try:
            self._callback(path)
        except Exception:
            logger.exception("callback error for %s", path)


class DirectoryWatcher:
    def __init__(
        self,
        directory: Path,
        callback: Callable[[Path], None],
        *,
        recursive: bool = True,
    ) -> None:
        self._directory = directory
        self._handler = _ScanHandler(callback)
        self._observer = Observer()
        self._recursive = recursive

    def start(self) -> None:
        self._observer.schedule(
            self._handler,
            str(self._directory),
            recursive=self._recursive,
        )
        self._observer.start()
        logger.info("watching %s (recursive=%s)", self._directory, self._recursive)

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join(timeout=5)
        logger.info("watcher stopped")

    @property
    def is_alive(self) -> bool:
        return self._observer.is_alive()
