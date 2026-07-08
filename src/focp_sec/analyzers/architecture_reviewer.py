"""Architecture review and project structure analysis."""

from __future__ import annotations

import re
from pathlib import Path

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.models import ArchitectureSummary, SecurityFinding
from focp_sec.core.scanner import ScannedFile


class ArchitectureReviewer(BaseAnalyzer):
    """Generates architecture summary and project tree."""

    name = "architecture_reviewer"

    ENTRY_POINT_PATTERNS = [
        r"(?i)(if\s+__name__\s*==\s*['\"]__main__['\"])",
        r"(?i)(app\.listen|server\.listen|uvicorn\.run|gunicorn)",
        r"(?i)(public\s+static\s+void\s+main|SpringApplication\.run)",
        r"(?i)(index\.php|artisan\s+serve)",
    ]

    DATA_STORE_PATTERNS = [
        (r"(?i)(postgres|mysql|sqlite|mongodb|redis|elasticsearch)", "Database"),
        (r"(?i)(s3://|aws\.s3|azure\.blob|gcs://)", "Cloud Storage"),
        (r"(?i)(kafka|rabbitmq|sqs|redis.*pub)", "Message Queue"),
    ]

    EXTERNAL_SERVICE_PATTERNS = [
        (r"(?i)(stripe|paypal|braintree)", "Payment"),
        (r"(?i)(sendgrid|mailgun|ses|smtp)", "Email"),
        (r"(?i)(auth0|okta|cognito|firebase.*auth)", "Identity Provider"),
        (r"(?i)(openai|anthropic|google.*ai)", "AI Service"),
    ]

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Architecture reviewer produces summary, not direct findings."""
        return []

    def review(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> ArchitectureSummary:
        """Generate architecture summary."""
        tree = self._build_tree(project_path, max_depth=4)
        all_content = "\n".join(f.content or "" for f in files)

        entry_points = self._detect_patterns(all_content, self.ENTRY_POINT_PATTERNS, "Entry Point")
        data_stores = self._detect_data_stores(all_content)
        external_services = self._detect_external_services(all_content)
        dep_graph = self._build_dependency_graph(project_info)
        summary = self._generate_summary(project_info, entry_points, data_stores, external_services)

        return ArchitectureSummary(
            project_tree=tree,
            dependency_graph=dep_graph,
            summary=summary,
            entry_points=entry_points,
            data_stores=data_stores,
            external_services=external_services,
        )

    def _build_tree(self, path: Path, prefix: str = "", max_depth: int = 4, depth: int = 0) -> str:
        """Build ASCII project tree."""
        if depth >= max_depth:
            return ""
        lines: list[str] = []
        try:
            entries = sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except PermissionError:
            return ""
        skip = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".tox"}
        entries = [e for e in entries if e.name not in skip]
        for i, entry in enumerate(entries[:30]):
            is_last = i == len(entries) - 1
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{entry.name}{'/' if entry.is_dir() else ''}")
            if entry.is_dir():
                extension = "    " if is_last else "│   "
                lines.append(self._build_tree(entry, prefix + extension, max_depth, depth + 1))
        return "\n".join(lines)

    def _detect_patterns(self, content: str, patterns: list[str], label: str) -> list[str]:
        """Detect patterns in content."""
        found = []
        for p in patterns:
            if re.search(p, content):
                found.append(label)
                break
        return found

    def _detect_data_stores(self, content: str) -> list[str]:
        """Detect data store references."""
        stores: list[str] = []
        for pattern, label in self.DATA_STORE_PATTERNS:
            if re.search(pattern, content):
                stores.append(label)
        return list(dict.fromkeys(stores))

    def _detect_external_services(self, content: str) -> list[str]:
        """Detect external service integrations."""
        services: list[str] = []
        for pattern, label in self.EXTERNAL_SERVICE_PATTERNS:
            if re.search(pattern, content):
                services.append(label)
        return list(dict.fromkeys(services))

    def _build_dependency_graph(self, project_info: dict) -> str:
        """Build text dependency graph."""
        deps = project_info.get("dependencies", [])
        if not deps:
            return "No dependencies detected."
        lines = ["Project Dependencies:", "─" * 40]
        managers: dict[str, list[str]] = {}
        for dep in deps[:50]:
            mgr = dep.get("manager", "unknown")
            managers.setdefault(mgr, []).append(dep.get("name", "?"))
        for mgr, pkgs in managers.items():
            lines.append(f"\n[{mgr}]")
            for pkg in pkgs[:20]:
                lines.append(f"  ├── {pkg}")
        return "\n".join(lines)

    def _generate_summary(
        self, project_info: dict, entry_points: list[str],
        data_stores: list[str], external_services: list[str],
    ) -> str:
        """Generate architecture narrative summary."""
        langs = ", ".join(project_info.get("languages", [])[:5]) or "Unknown"
        frameworks = ", ".join(project_info.get("frameworks", [])[:5]) or "None detected"
        return (
            f"This project uses {langs} with frameworks: {frameworks}. "
            f"It contains {project_info.get('file_count', 0)} files "
            f"({project_info.get('total_lines', 0)} lines). "
            f"Entry points: {', '.join(entry_points) or 'Not detected'}. "
            f"Data stores: {', '.join(data_stores) or 'Not detected'}. "
            f"External services: {', '.join(external_services) or 'Not detected'}. "
            f"Docker: {'Yes' if project_info.get('has_docker') else 'No'}. "
            f"Git: {'Yes' if project_info.get('has_git') else 'No'}."
        )
