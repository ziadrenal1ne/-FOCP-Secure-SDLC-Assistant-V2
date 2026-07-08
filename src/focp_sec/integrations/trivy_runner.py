"""Trivy vulnerability scanner integration."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import uuid
from pathlib import Path

from focp_sec.core.models import OWASPCategory, SecurityFinding, Severity

logger = logging.getLogger(__name__)

TRIVY_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class TrivyRunner:
    """Runs Trivy for dependency and container vulnerability scanning."""

    def is_available(self) -> bool:
        """Check if Trivy is installed."""
        return shutil.which("trivy") is not None

    def run(self, project_path: Path) -> list[SecurityFinding]:
        """Run Trivy filesystem scan and return findings."""
        findings: list[SecurityFinding] = []
        if not self.is_available():
            logger.warning("Trivy not available, skipping")
            return findings

        try:
            cmd = [
                "trivy", "fs",
                "--format", "json",
                "--scanners", "vuln,secret,misconfig",
                "--severity", "LOW,MEDIUM,HIGH,CRITICAL",
                str(project_path),
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            output = result.stdout.strip()
            if output:
                data = json.loads(output)
                for scan_result in data.get("Results", []):
                    target = scan_result.get("Target", "")
                    for vuln in scan_result.get("Vulnerabilities", []) or []:
                        findings.append(self._vuln_to_finding(vuln, target))
                    for secret in scan_result.get("Secrets", []) or []:
                        findings.append(self._secret_to_finding(secret, target))
                    for misconfig in scan_result.get("Misconfigurations", []) or []:
                        findings.append(self._misconfig_to_finding(misconfig, target))
        except subprocess.TimeoutExpired:
            logger.error("Trivy scan timed out")
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Trivy scan failed: %s", e)

        logger.info("Trivy found %d issues", len(findings))
        return findings

    def _vuln_to_finding(self, vuln: dict, target: str) -> SecurityFinding:
        """Convert Trivy vulnerability to SecurityFinding."""
        pkg = vuln.get("PkgName", "unknown")
        return SecurityFinding(
            id=str(uuid.uuid4())[:8],
            title=f"Trivy: {vuln.get('VulnerabilityID', 'CVE')} in {pkg}",
            severity=TRIVY_SEVERITY.get(vuln.get("Severity", "UNKNOWN"), Severity.MEDIUM),
            category="Dependencies",
            owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
            description=vuln.get("Description", f"Vulnerability in {pkg}")[:500],
            risk=f"Known vulnerability {vuln.get('VulnerabilityID')} with severity {vuln.get('Severity')}",
            recommendation=f"Upgrade {pkg} to version {vuln.get('FixedVersion', 'latest patched version')}",
            example_fix=f"# Update {pkg}\n# Current: {vuln.get('InstalledVersion')}\n# Fixed: {vuln.get('FixedVersion', 'check advisory')}",
            references=[vuln.get("PrimaryURL", "https://avd.aquasec.com/")],
            file_path=target,
            analyzer="trivy",
            metadata={"cve": vuln.get("VulnerabilityID"), "package": pkg, "installed_version": vuln.get("InstalledVersion")},
        )

    def _secret_to_finding(self, secret: dict, target: str) -> SecurityFinding:
        """Convert Trivy secret finding."""
        return SecurityFinding(
            id=str(uuid.uuid4())[:8],
            title=f"Trivy: Secret detected ({secret.get('RuleID', 'unknown')})",
            severity=Severity.HIGH,
            category="Secrets",
            owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
            description=secret.get("Title", "Secret detected by Trivy"),
            risk="Hardcoded secret detected in project files.",
            recommendation="Remove secret from codebase and rotate credentials.",
            example_fix="# Move to environment variables or secrets manager",
            references=["https://aquasec.github.io/trivy/latest/docs/scanner/secret/"],
            file_path=target,
            line_number=secret.get("StartLine"),
            analyzer="trivy",
        )

    def _misconfig_to_finding(self, misconfig: dict, target: str) -> SecurityFinding:
        """Convert Trivy misconfiguration finding."""
        return SecurityFinding(
            id=str(uuid.uuid4())[:8],
            title=f"Trivy: {misconfig.get('Title', 'Misconfiguration')}",
            severity=TRIVY_SEVERITY.get(misconfig.get("Severity", "MEDIUM"), Severity.MEDIUM),
            category="Configuration",
            owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
            description=misconfig.get("Description", "Configuration issue detected"),
            risk=misconfig.get("Message", "Security misconfiguration detected"),
            recommendation=misconfig.get("Resolution", "Review and fix configuration"),
            example_fix=misconfig.get("Resolution", "# Fix configuration"),
            references=["https://aquasec.github.io/trivy/latest/docs/scanner/misconfiguration/"],
            file_path=target,
            analyzer="trivy",
        )
