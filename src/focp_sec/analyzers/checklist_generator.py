"""Security checklist generator."""

from __future__ import annotations

import uuid
from pathlib import Path

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.models import ChecklistItem, SecurityFinding, Severity
from focp_sec.core.scanner import ScannedFile

OWASP_CHECKLIST = [
    ("A01", "Broken Access Control", "Server-side authorization on every request"),
    ("A01", "Broken Access Control", "Deny access by default"),
    ("A01", "Broken Access Control", "Rate limiting on API endpoints"),
    ("A02", "Cryptographic Failures", "Encrypt sensitive data at rest"),
    ("A02", "Cryptographic Failures", "Use TLS 1.2+ for data in transit"),
    ("A02", "Cryptographic Failures", "No hardcoded secrets in source code"),
    ("A03", "Injection", "Parameterized queries for all database access"),
    ("A03", "Injection", "Input validation on all user inputs"),
    ("A03", "Injection", "Output encoding for XSS prevention"),
    ("A04", "Insecure Design", "Threat modeling performed"),
    ("A04", "Insecure Design", "Security requirements defined"),
    ("A05", "Security Misconfiguration", "Security headers configured"),
    ("A05", "Security Misconfiguration", "Debug mode disabled in production"),
    ("A05", "Security Misconfiguration", "Default credentials removed"),
    ("A06", "Vulnerable Components", "Dependencies scanned for vulnerabilities"),
    ("A06", "Vulnerable Components", "Dependencies kept up to date"),
    ("A07", "Authentication Failures", "Strong password hashing implemented"),
    ("A07", "Authentication Failures", "Multi-factor authentication available"),
    ("A07", "Authentication Failures", "Account lockout after failed attempts"),
    ("A08", "Integrity Failures", "CI/CD pipeline secured"),
    ("A08", "Integrity Failures", "Code signing implemented"),
    ("A09", "Logging Failures", "Security events logged"),
    ("A09", "Logging Failures", "Logs protected from tampering"),
    ("A10", "SSRF", "URL validation on server-side requests"),
    ("A10", "SSRF", "Internal network access restricted"),
]

SDLC_CHECKLIST = [
    ("SDLC", "Requirements", "Security requirements documented"),
    ("SDLC", "Requirements", "Privacy requirements identified"),
    ("SDLC", "Design", "Threat model created"),
    ("SDLC", "Design", "Security architecture reviewed"),
    ("SDLC", "Development", "Secure coding guidelines followed"),
    ("SDLC", "Development", "Static analysis integrated in CI"),
    ("SDLC", "Testing", "Security testing performed"),
    ("SDLC", "Testing", "Penetration testing scheduled"),
    ("SDLC", "Deployment", "Production configuration hardened"),
    ("SDLC", "Deployment", "Secrets managed securely"),
    ("SDLC", "Operations", "Incident response plan exists"),
    ("SDLC", "Operations", "Security monitoring active"),
]

DEPLOYMENT_CHECKLIST = [
    ("Deploy", "Infrastructure", "HTTPS enforced"),
    ("Deploy", "Infrastructure", "Firewall rules configured"),
    ("Deploy", "Infrastructure", "Database not publicly accessible"),
    ("Deploy", "Application", "Error pages do not leak information"),
    ("Deploy", "Application", "CORS properly configured"),
    ("Deploy", "Application", "File permissions restricted"),
    ("Deploy", "Monitoring", "Log aggregation configured"),
    ("Deploy", "Monitoring", "Alerting for security events"),
    ("Deploy", "Backup", "Regular backups performed"),
    ("Deploy", "Backup", "Backup restoration tested"),
]


class ChecklistGenerator(BaseAnalyzer):
    """Generates security checklists based on scan results."""

    name = "checklist_generator"

    FINDING_CATEGORY_MAP = {
        "Authentication": ["A07", "Strong password hashing", "Multi-factor authentication"],
        "Authorization": ["A01", "Server-side authorization"],
        "Secrets": ["A02", "No hardcoded secrets"],
        "Injection": ["A03", "Parameterized queries", "Input validation"],
        "XSS": ["A03", "Output encoding"],
        "Security Headers": ["A05", "Security headers configured"],
        "File Upload": ["A04", "Security requirements defined"],
        "Dependencies": ["A06", "Dependencies scanned"],
        "OWASP Top 10": ["A05", "Debug mode disabled"],
    }

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Checklist generator produces checklists, not findings."""
        return []

    def generate(
        self,
        findings: list[SecurityFinding],
        project_info: dict,
    ) -> dict[str, list[ChecklistItem]]:
        """Generate checklists with pass/fail status."""
        failing_categories = {f.category for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)}
        failing_titles = {f.title.lower() for f in findings}

        checklists = {
            "owasp": self._evaluate_checklist(OWASP_CHECKLIST, failing_categories, failing_titles),
            "sdlc": self._evaluate_checklist(SDLC_CHECKLIST, failing_categories, failing_titles),
            "deployment": self._evaluate_checklist(DEPLOYMENT_CHECKLIST, failing_categories, failing_titles),
        }
        return checklists

    def _evaluate_checklist(
        self,
        items: list[tuple[str, str, str]],
        failing_categories: set[str],
        failing_titles: set[str],
    ) -> list[ChecklistItem]:
        """Evaluate checklist items against findings."""
        result: list[ChecklistItem] = []
        for i, (category, group, item) in enumerate(items):
            status = "pass"
            notes = ""

            for fail_cat, mapped_items in self.FINDING_CATEGORY_MAP.items():
                if fail_cat in failing_categories and item in mapped_items:
                    status = "fail"
                    notes = f"Related finding in {fail_cat} category"
                    break

            if "debug" in item.lower() and any("debug" in t for t in failing_titles):
                status = "fail"
                notes = "Debug mode detected in code"

            if "secrets" in item.lower() and "Secrets" in failing_categories:
                status = "fail"
                notes = "Secrets detected in codebase"

            if "dependencies" in item.lower() and "Dependencies" in failing_categories:
                status = "warning"
                notes = "Dependency vulnerabilities may exist"

            result.append(ChecklistItem(
                id=str(uuid.uuid4())[:8],
                category=f"{category}: {group}",
                item=item,
                status=status,
                notes=notes,
            ))
        return result
