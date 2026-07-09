"""Project file scanner utilities."""

from __future__ import annotations

import logging
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from focp_sec.core.config import AppConfig, get_config

logger = logging.getLogger(__name__)


@dataclass
class ScannedFile:
    """Represents a scanned file."""

    path: Path
    relative_path: str
    extension: str
    size: int
    lines: int
    content: str | None = None


class ProjectScanner:
    """Recursively scans project files with exclusion rules."""

    LANGUAGE_EXTENSIONS: dict[str, str] = {
        ".py": "Python",
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".java": "Java",
        ".php": "PHP",
        ".cs": "C#",
        ".go": "Go",
        ".rb": "Ruby",
        ".rs": "Rust",
        ".vue": "Vue",
        ".html": "HTML",
        ".css": "CSS",
        ".scss": "SCSS",
        ".sql": "SQL",
        ".yaml": "YAML",
        ".yml": "YAML",
        ".json": "JSON",
        ".xml": "XML",
        ".env": "Environment",
        ".toml": "TOML",
        ".dockerfile": "Docker",
        ".sh": "Shell",
        ".bash": "Shell",
    }

    CONFIG_FILES: set[str] = {
        "package.json",
        "requirements.txt",
        "pyproject.toml",
        "Pipfile",
        "composer.json",
        "pom.xml",
        "build.gradle",
        "Cargo.toml",
        "go.mod",
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        ".env",
        ".env.example",
        "web.config",
        "appsettings.json",
        "next.config.js",
        "next.config.mjs",
        "vite.config.js",
        "vite.config.ts",
        "webpack.config.js",
        "tsconfig.json",
        "application.properties",
        "application.yml",
        "nginx.conf",
        "httpd.conf",
        ".htaccess",
        "Gemfile",
        "Rakefile",
    }

    def __init__(self, project_path: Path, config: AppConfig | None = None) -> None:
        self.project_path = project_path.resolve()
        self.config = config or get_config()
        self.max_size = self.config.max_file_size_mb * 1024 * 1024

    def should_exclude(self, path: Path) -> bool:
        """Check if path should be excluded from scanning."""
        parts = set(path.parts)
        if parts & self.config.exclude_dirs:
            return True
        if path.suffix.lower() in self.config.exclude_extensions:
            return True
        if path.is_file() and path.stat().st_size > self.max_size:
            return True
        return False

    def discover_files(self, read_content: bool = True) -> list[ScannedFile]:
        """Discover all scannable files in the project."""
        import hashlib
        import json
        
        files: list[ScannedFile] = []
        is_incremental = self.config.get("scan.incremental", False)
        state_file = self.project_path / ".focp-sec-state.json"
        previous_state = {}
        new_state = {}
        
        if is_incremental and state_file.exists():
            try:
                previous_state = json.loads(state_file.read_text())
                logger.info("Loaded previous scan state for incremental scanning.")
            except Exception as e:
                logger.warning("Failed to load state file: %s", e)

        for root, dirs, filenames in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in self.config.exclude_dirs]
            for filename in filenames:
                if filename == ".focp-sec-state.json":
                    continue
                file_path = Path(root) / filename
                if self.should_exclude(file_path):
                    continue
                try:
                    stat = file_path.stat()
                    rel = str(file_path.relative_to(self.project_path))
                    content = None
                    lines = 0
                    
                    if read_content and self._is_text_file(file_path):
                        try:
                            content = file_path.read_text(encoding="utf-8", errors="replace")
                            lines = content.count("\n") + (1 if content and not content.endswith("\n") else 0)
                        except OSError:
                            continue
                    
                    file_hash = ""
                    if content:
                        file_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
                    else:
                        # For binary files, use mtime and size
                        file_hash = f"{stat.st_size}_{stat.st_mtime}"
                        
                    new_state[rel] = file_hash
                    
                    # Skip if incremental and file hasn't changed
                    if is_incremental and previous_state.get(rel) == file_hash:
                        continue
                        
                    files.append(
                        ScannedFile(
                            path=file_path,
                            relative_path=rel,
                            extension=file_path.suffix.lower(),
                            size=stat.st_size,
                            lines=lines,
                            content=content,
                        )
                    )
                except OSError as e:
                    logger.debug("Skipping %s: %s", file_path, e)
        
        if is_incremental or files:
            try:
                state_file.write_text(json.dumps(new_state))
            except Exception as e:
                logger.debug("Failed to write state file: %s", e)
                
        logger.info("Discovered %d changed/new files in %s", len(files), self.project_path)
        return files

    def _is_text_file(self, path: Path) -> bool:
        """Heuristic check if file is text."""
        try:
            with open(path, "rb") as f:
                chunk = f.read(8192)
            if b"\x00" in chunk:
                return False
            return True
        except OSError:
            return False

    def get_config_files(self, files: list[ScannedFile]) -> list[ScannedFile]:
        """Filter files that are configuration files."""
        return [f for f in files if f.path.name in self.CONFIG_FILES or f.path.name.lower() == "dockerfile"]

    def detect_languages(self, files: list[ScannedFile]) -> list[str]:
        """Detect programming languages from file extensions."""
        lang_counts: dict[str, int] = {}
        for f in files:
            lang = self.LANGUAGE_EXTENSIONS.get(f.extension)
            if lang:
                lang_counts[lang] = lang_counts.get(lang, 0) + 1
        return [lang for lang, _ in sorted(lang_counts.items(), key=lambda x: -x[1])]

    @staticmethod
    def read_file_worker(args: tuple[str, str]) -> tuple[str, str | None]:
        """Worker function for parallel file reading."""
        path_str, _ = args
        try:
            content = Path(path_str).read_text(encoding="utf-8", errors="replace")
            return path_str, content
        except OSError:
            return path_str, None

    def read_files_parallel(self, file_paths: list[Path]) -> dict[str, str]:
        """Read multiple files in parallel using multiprocessing."""
        results: dict[str, str] = {}
        args = [(str(p), "") for p in file_paths]
        with ProcessPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {executor.submit(self.read_file_worker, a): a[0] for a in args}
            for future in as_completed(futures):
                path_str, content = future.result()
                if content is not None:
                    results[path_str] = content
        return results
