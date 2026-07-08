"""Semgrep static analysis integration."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import uuid
from pathlib import Path

from focp_sec.core.models import OWASPCategory, SecurityFinding, Severity

logger = logging.getLogger(__name__)

SEMGREP_SEVERITY = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepRunner:
    """Runs Semgrep multi-language static analysis."""

    def is_available(self) -> bool:
        """Check if Semgrep is installed."""
        return shutil.which("semgrep") is not None

    def run(self, project_path: Path) -> list[SecurityFinding]:
        """Run Semgrep on project and return findings."""
        findings: list[SecurityFinding] = []
        if not self.is_available():
            logger.warning("Semgrep not available, skipping")
            return findings

        try:
            cmd = [
                "semgrep", "scan",
                "--config", "auto",
                "--json",
                "--quiet",
                str(project_path),
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            output = result.stdout.strip()
            if output:
                data = json.loads(output)
                for item in data.get("results", []):
                    extra = item.get("extra", {})
                    metadata = extra.get("metadata", {})
                    owasp = metadata.get("owasp", [])
                    owasp_cat = None
                    if owasp:
                        owasp_cat = self._map_owasp(owasp[0] if isinstance(owasp, list) else owasp)

                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4())[:8],
                        title=f"Semgrep: {extra.get('message', 'Security Issue')}",
                        severity=SEMGREP_SEVERITY.get(extra.get("severity", "INFO"), Severity.MEDIUM),
                        category="Dependencies",
                        owasp_category=owasp_cat,
                        description=extra.get("message", ""),
                        risk=extra.get("message", "Security pattern detected by Semgrep"),
                        recommendation=metadata.get("fix", "Review and fix the identified security pattern."),
                        example_fix=metadata.get("fix", "# See Semgrep rule documentation"),
                        references=[metadata.get("source", "https://semgrep.dev/docs/")],
                        file_path=item.get("path"),
                        line_number=item.get("start", {}).get("line"),
                        code_snippet=extra.get("lines", "")[:200],
                        analyzer="semgrep",
                        metadata={"rule_id": item.get("check_id"), "cwe": metadata.get("cwe", [])},
                    ))
        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out")
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Semgrep scan failed: %s", e)

        logger.info("Semgrep found %d issues", len(findings))
        return findings

    @staticmethod
    def _map_owasp(owasp_ref: str) -> OWASPCategory | None:
        """Map OWASP reference string to category."""
        mapping = {
            "A01": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
            "A02": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
            "A03": OWASPCategory.A03_INJECTION,
            "A04": OWASPCategory.A04_INSECURE_DESIGN,
            "A05": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
            "A06": OWASPCategory.A06_VULNERABLE_COMPONENTS,
            "A07": OWASPCategory.A07_AUTH_FAILURES,
            "A08": OWASPCategory.A08_INTEGRITY_FAILURES,
            "A09": OWASPCategory.A09_LOGGING_FAILURES,
            "A10": OWASPCategory.A10_SSRF,
        }
        for key, cat in mapping.items():
            if key in owasp_ref:
                return cat
        return None
