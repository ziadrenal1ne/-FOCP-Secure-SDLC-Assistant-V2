"""Project technology and framework detection."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

try:
    import git
except ImportError:
    git = None  # type: ignore

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.models import ProjectInfo, SecurityFinding
from focp_sec.core.scanner import ProjectScanner, ScannedFile

logger = logging.getLogger(__name__)


class ProjectDetector(BaseAnalyzer):
    """Detects languages, frameworks, dependencies, Docker, and Git info."""

    name = "project_detector"

    FRAMEWORK_INDICATORS: dict[str, list[tuple[str, str]]] = {
        "Django": [("requirements.txt", r"django"), ("pyproject.toml", r"django"), ("manage.py", r".")],
        "Flask": [("requirements.txt", r"flask"), ("pyproject.toml", r"flask")],
        "FastAPI": [("requirements.txt", r"fastapi"), ("pyproject.toml", r"fastapi")],
        "Spring Boot": [("pom.xml", r"spring-boot"), ("build.gradle", r"spring-boot")],
        "Express": [("package.json", r'"express"')],
        "React": [("package.json", r'"react"')],
        "Next.js": [("package.json", r'"next"'), ("next.config.js", r".")],
        "Vue.js": [("package.json", r'"vue"')],
        "Angular": [("package.json", r'"@angular/core"')],
        "Laravel": [("composer.json", r"laravel/framework")],
        "Symfony": [("composer.json", r"symfony/")],
        ".NET": [("*.csproj", r"Microsoft.NET"), ("*.sln", r".")],
        "Ruby on Rails": [("Gemfile", r"rails")],
    }

    DEPENDENCY_FILES: dict[str, str] = {
        "requirements.txt": "pip",
        "pyproject.toml": "pip",
        "Pipfile": "pipenv",
        "package.json": "npm",
        "package-lock.json": "npm",
        "yarn.lock": "yarn",
        "pnpm-lock.yaml": "pnpm",
        "composer.json": "composer",
        "pom.xml": "maven",
        "build.gradle": "gradle",
        "Cargo.toml": "cargo",
        "go.mod": "go",
        "Gemfile": "bundler",
    }

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Project detector does not produce security findings."""
        return []

    def detect(self, project_path: Path, files: list[ScannedFile]) -> ProjectInfo:
        """Detect project characteristics."""
        scanner = ProjectScanner(project_path)
        languages = scanner.detect_languages(files)
        frameworks = self._detect_frameworks(project_path, files)
        dependencies = self._extract_dependencies(files)
        has_docker = self._has_docker(project_path, files)
        has_git = (project_path / ".git").exists()
        config_files = [f.relative_path for f in scanner.get_config_files(files)]
        git_info = self._get_git_info(project_path) if has_git else {}

        return ProjectInfo(
            path=str(project_path),
            name=project_path.name,
            languages=languages,
            frameworks=frameworks,
            dependencies=dependencies,
            has_docker=has_docker,
            has_git=has_git,
            config_files=config_files,
            file_count=len(files),
            total_lines=sum(f.lines for f in files),
            git_info=git_info,
        )

    def _detect_frameworks(self, project_path: Path, files: list[ScannedFile]) -> list[str]:
        """Detect frameworks from indicator files."""
        detected: list[str] = []
        file_map = {f.path.name: f for f in files}
        for framework, indicators in self.FRAMEWORK_INDICATORS.items():
            for filename, pattern in indicators:
                if filename.startswith("*"):
                    ext = filename[1:]
                    for f in files:
                        if f.path.name.endswith(ext) and f.content and re.search(pattern, f.content, re.I):
                            detected.append(framework)
                            break
                elif filename in file_map:
                    f = file_map[filename]
                    if f.content and (pattern == "." or re.search(pattern, f.content, re.I)):
                        detected.append(framework)
                        break
                elif (project_path / filename).exists():
                    try:
                        content = (project_path / filename).read_text(encoding="utf-8", errors="replace")
                        if pattern == "." or re.search(pattern, content, re.I):
                            detected.append(framework)
                            break
                    except OSError:
                        pass
        return list(dict.fromkeys(detected))

    def _extract_dependencies(self, files: list[ScannedFile]) -> list[dict[str, str]]:
        """Extract dependencies from manifest files."""
        deps: list[dict[str, str]] = []
        for f in files:
            if f.path.name not in self.DEPENDENCY_FILES or not f.content:
                continue
            manager = self.DEPENDENCY_FILES[f.path.name]
            if f.path.name == "requirements.txt":
                for line in f.content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("-"):
                        pkg = re.split(r"[>=<!\[]", line)[0].strip()
                        if pkg:
                            deps.append({"name": pkg, "manager": manager, "file": f.relative_path})
            elif f.path.name == "package.json":
                import json
                try:
                    data = json.loads(f.content)
                    for section in ("dependencies", "devDependencies"):
                        for name, version in data.get(section, {}).items():
                            deps.append({"name": name, "version": str(version), "manager": manager, "file": f.relative_path})
                except json.JSONDecodeError:
                    pass
            elif f.path.name == "composer.json":
                import json
                try:
                    data = json.loads(f.content)
                    for name in data.get("require", {}):
                        if name != "php":
                            deps.append({"name": name, "manager": manager, "file": f.relative_path})
                except json.JSONDecodeError:
                    pass
        return deps[:200]

    def _has_docker(self, project_path: Path, files: list[ScannedFile]) -> bool:
        """Check for Docker configuration."""
        docker_names = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"}
        return any(f.path.name in docker_names for f in files) or (project_path / "Dockerfile").exists()

    def _get_git_info(self, project_path: Path) -> dict[str, Any]:
        """Extract Git repository information."""
        if git is None:
            return {}
        try:
            repo = git.Repo(project_path, search_parent_directories=False)
            return {
                "branch": repo.active_branch.name if not repo.head.is_detached else "detached",
                "remote_url": repo.remotes[0].url if repo.remotes else None,
                "commit_count": len(list(repo.iter_commits(max_count=1000))),
                "is_dirty": repo.is_dirty(),
            }
        except Exception as e:
            logger.debug("Git info unavailable: %s", e)
            return {}
