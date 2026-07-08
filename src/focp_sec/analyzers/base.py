"""Base analyzer interface."""

from __future__ import annotations

import abc
import logging
from pathlib import Path

from focp_sec.core.models import SecurityFinding
from focp_sec.core.scanner import ScannedFile

logger = logging.getLogger(__name__)


class BaseAnalyzer(abc.ABC):
    """Abstract base class for security analyzers."""

    name: str = "base"

    @abc.abstractmethod
    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Run analysis and return findings."""
        ...

    def _get_content_files(
        self, files: list[ScannedFile], extensions: set[str] | None = None
    ) -> list[ScannedFile]:
        """Filter files with content and optional extension filter."""
        result = [f for f in files if f.content is not None]
        if extensions:
            result = [f for f in result if f.extension in extensions]
        return result

    def _find_pattern_in_files(
        self,
        files: list[ScannedFile],
        patterns: list[tuple[str, str]],
        extensions: set[str] | None = None,
    ) -> list[tuple[ScannedFile, int, str, str]]:
        """Search for regex patterns in files. Returns (file, line, match, pattern_name)."""
        import re

        results: list[tuple[ScannedFile, int, str, str]] = []
        target_files = self._get_content_files(files, extensions)
        for f in target_files:
            if not f.content:
                continue
            for line_num, line in enumerate(f.content.splitlines(), 1):
                for pattern, name in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        results.append((f, line_num, line.strip(), name))
        return results
