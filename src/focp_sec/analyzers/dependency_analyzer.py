"""Dependency analysis orchestrating external tools."""

from __future__ import annotations

import logging
import re
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.config import get_config
from focp_sec.core.models import OWASPCategory, SecurityFinding, Severity
from focp_sec.core.scanner import ScannedFile
from focp_sec.integrations.bandit_runner import BanditRunner
from focp_sec.integrations.semgrep_runner import SemgrepRunner
from focp_sec.integrations.trivy_runner import TrivyRunner

logger = logging.getLogger(__name__)

KNOWN_VULNERABLE_PATTERNS = [
    (r"(?i)(django==1\.|django==2\.0|django==2\.1)", "Outdated Django version", Severity.HIGH),
    (r"(?i)(flask==0\.|flask==1\.0)", "Outdated Flask version", Severity.MEDIUM),
    (r"(?i)(lodash@[~^]?4\.17\.(0|1|1[0-9])\.)", "Vulnerable Lodash version", Severity.HIGH),
    (r"(?i)(express@[~^]?4\.(0|1[0-6])\.)", "Potentially outdated Express", Severity.MEDIUM),
    (r"(?i)(log4j.*2\.(0|1[0-4])|log4j-core.*2\.(0|1[0-4]))", "Log4Shell vulnerable version", Severity.CRITICAL),
    (r"(?i)(spring-boot.*1\.|spring-boot.*2\.0\.)", "Outdated Spring Boot", Severity.HIGH),
    (r"(?i)(requests==2\.(2[0-5]|2[0-9])\.|urllib3==1\.(2[0-5]))", "Outdated Python HTTP libraries", Severity.MEDIUM),
]


class DependencyAnalyzer(BaseAnalyzer):
    """Runs Bandit, Semgrep, Trivy and static dependency checks."""

    name = "dependency_analyzer"

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Run all dependency analysis tools."""
        config = get_config()
        findings: list[SecurityFinding] = []

        findings.extend(self._check_known_vulnerable_deps(files))

        runners = []
        if config.bandit_enabled:
            runners.append(("bandit", BanditRunner()))
        if config.semgrep_enabled:
            runners.append(("semgrep", SemgrepRunner()))
        if config.trivy_enabled:
            runners.append(("trivy", TrivyRunner()))

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            for name, runner in runners:
                if runner.is_available():
                    futures[executor.submit(runner.run, project_path)] = name
                else:
                    logger.info("%s not available, using built-in checks only", name)

            for future in as_completed(futures):
                tool_name = futures[future]
                try:
                    tool_findings = future.result()
                    findings.extend(tool_findings)
                except Exception as e:
                    logger.error("%s scan failed: %s", tool_name, e)

        return self._deduplicate(findings)

    def _check_known_vulnerable_deps(self, files: list[ScannedFile]) -> list[SecurityFinding]:
        """Check dependency files for known vulnerable versions."""
        findings: list[SecurityFinding] = []
        dep_files = {"requirements.txt", "package.json", "pom.xml", "build.gradle", "composer.json"}

        for f in files:
            if f.path.name not in dep_files or not f.content:
                continue
            for pattern, title, severity in KNOWN_VULNERABLE_PATTERNS:
                if re.search(pattern, f.content):
                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4())[:8],
                        title=f"Dependency Risk: {title}",
                        severity=severity,
                        category="Dependencies",
                        owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                        description=f"Potentially vulnerable dependency detected in {f.relative_path}",
                        risk="Known vulnerable dependency versions may have published CVEs.",
                        recommendation="Update to the latest patched version and run vulnerability scan.",
                        example_fix="# Check https://nvd.nist.gov/ for CVE details and upgrade",
                        references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
                        file_path=f.relative_path,
                        analyzer=self.name,
                    ))
        return findings

    def _deduplicate(self, findings: list[SecurityFinding]) -> list[SecurityFinding]:
        """Remove duplicate findings."""
        seen: set[tuple] = set()
        unique: list[SecurityFinding] = []
        for f in findings:
            key = (f.title, f.file_path, f.line_number)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
