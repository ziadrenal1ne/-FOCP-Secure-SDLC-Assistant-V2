"""OWASP Top 10 2021 comprehensive analyzer."""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.models import OWASPCategory, SecurityFinding, Severity
from focp_sec.core.scanner import ScannedFile

CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".cs", ".rb", ".go", ".yaml", ".yml", ".json", ".xml", ".properties"}


class OWASPAnalyzer(BaseAnalyzer):
    """Analyzes code against OWASP Top 10 2021 categories."""

    name = "owasp_analyzer"

    OWASP_CHECKS: list[dict] = [
        {
            "category": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
            "patterns": [(r"(?i)(IDOR|Insecure Direct Object|horizontal.*privilege|vertical.*privilege)", "IDOR/Privilege Pattern")],
            "severity": Severity.HIGH,
            "title": "Broken Access Control Pattern",
            "risk": "Users can access resources or perform actions outside their permissions.",
            "fix": "Implement server-side authorization checks for every resource access.",
        },
        {
            "category": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
            "patterns": [(r"(?i)(DES|RC4|ECB\s*mode|ssl\.PROTOCOL_SSLv|TLSv1\.0|TLSv1\.1)", "Weak Cryptography")],
            "severity": Severity.HIGH,
            "title": "Cryptographic Failure",
            "risk": "Weak cryptography can be broken, exposing sensitive data.",
            "fix": "Use AES-256-GCM, TLS 1.2+, and modern key exchange algorithms.",
        },
        {
            "category": OWASPCategory.A03_INJECTION,
            "patterns": [(r"(?i)(os\.system|subprocess\.call.*shell\s*=\s*True|exec\s*\(|eval\s*\()", "Command Injection")],
            "severity": Severity.CRITICAL,
            "title": "Command Injection Risk",
            "risk": "Attackers can execute arbitrary system commands on the server.",
            "fix": "Use subprocess with shell=False and validate/sanitize all inputs.",
        },
        {
            "category": OWASPCategory.A04_INSECURE_DESIGN,
            "patterns": [(r"(?i)(rate[_-]?limit|throttle|brute[_-]?force|lockout)", "Rate Limiting")],
            "severity": Severity.INFO,
            "title": "Rate Limiting Reference",
            "risk": "N/A - informational",
            "fix": "N/A",
            "inverse": True,
        },
        {
            "category": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
            "patterns": [(r"(?i)(debug\s*=\s*True|DEBUG\s*=\s*true|app\.run\s*\(.*debug\s*=\s*True)", "Debug Mode Enabled")],
            "severity": Severity.HIGH,
            "title": "Debug Mode in Production",
            "risk": "Debug mode exposes stack traces, configuration, and internal paths.",
            "fix": "Disable debug mode in production. Set DEBUG=False via environment variables.",
        },
        {
            "category": OWASPCategory.A06_VULNERABLE_COMPONENTS,
            "patterns": [(r"(?i)(requirements\.txt|package\.json|pom\.xml)", "Dependency Manifest")],
            "severity": Severity.INFO,
            "title": "Dependency Manifest Found",
            "risk": "N/A",
            "fix": "Run dependency vulnerability scans regularly.",
            "inverse": True,
        },
        {
            "category": OWASPCategory.A07_AUTH_FAILURES,
            "patterns": [(r"(?i)(default[_-]?password|admin:admin|password123|test123)", "Default Credentials")],
            "severity": Severity.CRITICAL,
            "title": "Default or Weak Credentials",
            "risk": "Default credentials are easily guessed by attackers.",
            "fix": "Remove default credentials. Enforce strong password policies.",
        },
        {
            "category": OWASPCategory.A08_INTEGRITY_FAILURES,
            "patterns": [(r"(?i)(pickle\.loads|yaml\.load\s*\(|unserialize\s*\(|ObjectInputStream)", "Unsafe Deserialization")],
            "severity": Severity.CRITICAL,
            "title": "Insecure Deserialization",
            "risk": "Deserialization of untrusted data can lead to remote code execution.",
            "fix": "Use safe deserialization (json.loads, yaml.safe_load). Never deserialize untrusted data.",
        },
        {
            "category": OWASPCategory.A09_LOGGING_FAILURES,
            "patterns": [(r"(?i)(logging\.|logger\.|log4j|winston|structlog|audit[_-]?log)", "Logging Framework")],
            "severity": Severity.INFO,
            "title": "Logging Framework Detected",
            "risk": "N/A",
            "fix": "Ensure security events are logged with appropriate retention.",
            "inverse": True,
        },
        {
            "category": OWASPCategory.A10_SSRF,
            "patterns": [(r"(?i)(requests\.(get|post|put)\s*\(.*request\.|fetch\s*\(.*req\.|urllib.*urlopen.*user)", "SSRF Pattern")],
            "severity": Severity.HIGH,
            "title": "Server-Side Request Forgery Risk",
            "risk": "Attackers can make the server request internal resources.",
            "fix": "Validate and whitelist URLs. Block internal IP ranges and metadata endpoints.",
        },
    ]

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Run OWASP Top 10 checks."""
        findings: list[SecurityFinding] = []
        code_files = self._get_content_files(files, CODE_EXTENSIONS)
        all_content = "\n".join(f.content or "" for f in code_files)

        for check in self.OWASP_CHECKS:
            is_inverse = check.get("inverse", False)
            matched = False

            for f in code_files:
                if not f.content:
                    continue
                for pattern, label in check["patterns"]:
                    for line_num, line in enumerate(f.content.splitlines(), 1):
                        if re.search(pattern, line):
                            matched = True
                            if not is_inverse:
                                findings.append(SecurityFinding(
                                    id=str(uuid.uuid4())[:8],
                                    title=f"OWASP: {check['title']}",
                                    severity=check["severity"],
                                    category="OWASP Top 10",
                                    owasp_category=check["category"],
                                    description=f"{label} detected ({check['category'].value}).",
                                    risk=check["risk"],
                                    recommendation=check["fix"],
                                    example_fix=check["fix"],
                                    references=[f"https://owasp.org/Top10/{check['category'].name.split('_')[0].lower()}/"],
                                    file_path=f.relative_path,
                                    line_number=line_num,
                                    code_snippet=line[:200],
                                    business_impact=f"Related to {check['category'].value}.",
                                    analyzer=self.name,
                                ))

            if is_inverse and not matched and check["category"] == OWASPCategory.A04_INSECURE_DESIGN:
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4())[:8],
                    title="OWASP: No Rate Limiting Detected",
                    severity=Severity.MEDIUM,
                    category="OWASP Top 10",
                    owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                    description="No rate limiting or throttling patterns were detected.",
                    risk="Applications without rate limiting are vulnerable to brute force and DoS attacks.",
                    recommendation="Implement rate limiting on authentication and sensitive endpoints.",
                    example_fix="# Flask-Limiter\nfrom flask_limiter import Limiter\nlimiter = Limiter(app, default_limits=['200/day', '50/hour'])",
                    references=["https://owasp.org/Top10/A04_2021-Insecure_Design/"],
                    analyzer=self.name,
                ))

            if is_inverse and not matched and check["category"] == OWASPCategory.A09_LOGGING_FAILURES:
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4())[:8],
                    title="OWASP: Insufficient Security Logging",
                    severity=Severity.MEDIUM,
                    category="OWASP Top 10",
                    owasp_category=OWASPCategory.A09_LOGGING_FAILURES,
                    description="No logging framework or audit logging patterns detected.",
                    risk="Without logging, security incidents cannot be detected or investigated.",
                    recommendation="Implement structured logging for authentication, authorization, and input validation failures.",
                    example_fix="import logging\nsecurity_logger = logging.getLogger('security')\nsecurity_logger.warning('Failed login attempt', extra={'user': username, 'ip': request.remote_addr})",
                    references=["https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"],
                    analyzer=self.name,
                ))

        return findings
