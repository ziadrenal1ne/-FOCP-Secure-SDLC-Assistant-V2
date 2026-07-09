"""Real-time file watcher to trigger incremental scans."""

import logging
import time
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers import Observer

from focp_sec.core.config import get_config

logger = logging.getLogger(__name__)


class ScanTriggerHandler(FileSystemEventHandler):
    """Handler that triggers scans on file modifications."""

    def __init__(self, callback: Callable[[], None], debounce_seconds: float = 2.0):
        super().__init__()
        self.callback = callback
        self.debounce_seconds = debounce_seconds
        self.last_trigger = 0.0
        self.config = get_config()

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        # Simple ignore pattern check
        path = Path(event.src_path)
        if any(part in self.config.exclude_dirs for part in path.parts):
            return
            
        if path.suffix in self.config.exclude_extensions:
            return

        current_time = time.time()
        if current_time - self.last_trigger > self.debounce_seconds:
            self.last_trigger = current_time
            logger.info("Detected change in %s, triggering scan...", event.src_path)
            self.callback()


class ProjectWatcher:
    """Watches a project directory and triggers scans."""

    def __init__(self, project_path: str | Path, callback: Callable[[], None]):
        self.project_path = str(Path(project_path).resolve())
        self.config = get_config()
        debounce = float(self.config.get("realtime.watch_delay", 2.0))
        self.handler = ScanTriggerHandler(callback, debounce_seconds=debounce)
        self.observer = Observer()

    def start(self) -> None:
        """Start the file watcher."""
        self.observer.schedule(self.handler, self.project_path, recursive=True)
        self.observer.start()
        logger.info("Started real-time file watcher on %s", self.project_path)

    def stop(self) -> None:
        """Stop the file watcher."""
        self.observer.stop()
        self.observer.join()
        logger.info("Stopped file watcher.")
