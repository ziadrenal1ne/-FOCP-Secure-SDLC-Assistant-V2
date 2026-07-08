"""Bandit static analysis integration."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import uuid
from pathlib import Path

from focp_sec.core.models import OWASPCategory, SecurityFinding, Severity

logger = logging.getLogger(__name__)

BANDIT_SEVERITY = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

BANDIT_OWASP = {
    "B101": OWASPCategory.A03_INJECTION,
    "B102": OWASPCategory.A03_INJECTION,
    "B103": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    "B104": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    "B105": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "B106": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "B107": OWASPCategory.A07_AUTH_FAILURES,
    "B108": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    "B110": OWASPCategory.A03_INJECTION,
    "B201": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    "B301": OWASPCategory.A08_INTEGRITY_FAILURES,
    "B302": OWASPCategory.A08_INTEGRITY_FAILURES,
    "B303": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "B304": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "B305": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "B306": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "B307": OWASPCategory.A03_INJECTION,
    "B308": OWASPCategory.A03_INJECTION,
    "B310": OWASPCategory.A10_SSRF,
    "B311": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "B312": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "B313": OWASPCategory.A08_INTEGRITY_FAILURES,
    "B314": OWASPCategory.A08_INTEGRITY_FAILURES,
    "B315": OWASPCategory.A08_INTEGRITY_FAILURES,
    "B501": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "B502": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "B503": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "B504": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "B505": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "B506": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "B507": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "B601": OWASPCategory.A03_INJECTION,
    "B602": OWASPCategory.A03_INJECTION,
    "B603": OWASPCategory.A03_INJECTION,
    "B604": OWASPCategory.A03_INJECTION,
    "B605": OWASPCategory.A03_INJECTION,
    "B606": OWASPCategory.A03_INJECTION,
    "B607": OWASPCategory.A03_INJECTION,
    "B608": OWASPCategory.A03_INJECTION,
    "B609": OWASPCategory.A03_INJECTION,
}


class BanditRunner:
    """Runs Bandit Python security linter."""

    def is_available(self) -> bool:
        """Check if Bandit is installed."""
        return shutil.which("bandit") is not None or self._python_module_available()

    def _python_module_available(self) -> bool:
        try:
            import bandit  # noqa: F401
            return True
        except ImportError:
            return False

    def run(self, project_path: Path) -> list[SecurityFinding]:
        """Run Bandit on project and return findings."""
        findings: list[SecurityFinding] = []
        if not self.is_available():
            logger.warning("Bandit not available, skipping")
            return findings

        try:
            cmd = [
                "bandit", "-r", str(project_path),
                "-f", "json", "-q",
                "--exclude", ".venv,venv,node_modules,.git",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.stdout.strip():
                data = json.loads(result.stdout)
                for item in data.get("results", []):
                    test_id = item.get("test_id", "")
                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4())[:8],
                        title=f"Bandit: {item.get('issue_text', 'Security Issue')}",
                        severity=BANDIT_SEVERITY.get(item.get("issue_severity", "LOW"), Severity.LOW),
                        category="Dependencies",
                        owasp_category=BANDIT_OWASP.get(test_id, OWASPCategory.A05_SECURITY_MISCONFIGURATION),
                        description=item.get("issue_text", ""),
                        risk=item.get("issue_text", "Python security issue detected by Bandit"),
                        recommendation=f"Review Bandit test {test_id} and fix the identified issue.",
                        example_fix=f"# See Bandit documentation for {test_id}",
                        references=[f"https://bandit.readthedocs.io/en/latest/plugins/{test_id.lower()}.html"],
                        file_path=item.get("filename"),
                        line_number=item.get("line_number"),
                        code_snippet=item.get("code", "")[:200],
                        analyzer="bandit",
                        metadata={"test_id": test_id, "confidence": item.get("issue_confidence")},
                    ))
        except subprocess.TimeoutExpired:
            logger.error("Bandit scan timed out")
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Bandit scan failed: %s", e)

        logger.info("Bandit found %d issues", len(findings))
        return findings
