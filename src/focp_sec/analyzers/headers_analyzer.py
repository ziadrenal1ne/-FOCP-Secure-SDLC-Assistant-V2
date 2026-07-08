"""Security headers configuration analyzer."""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.models import OWASPCategory, SecurityFinding, Severity
from focp_sec.core.scanner import ScannedFile

CONFIG_EXTENSIONS = {".py", ".js", ".ts", ".java", ".php", ".cs", ".conf", ".yaml", ".yml", ".json", ".html"}


class HeadersAnalyzer(BaseAnalyzer):
    """Checks security header configuration."""

    name = "headers_analyzer"

    REQUIRED_HEADERS = {
        "Content-Security-Policy": {
            "patterns": [r"(?i)content-security-policy", r"(?i)CSP"],
            "severity": Severity.MEDIUM,
            "recommendation": "Define a strict CSP to mitigate XSS and data injection attacks.",
            "example": "Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none'",
        },
        "Strict-Transport-Security": {
            "patterns": [r"(?i)strict-transport-security", r"(?i)HSTS"],
            "severity": Severity.MEDIUM,
            "recommendation": "Enable HSTS to force HTTPS connections.",
            "example": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        },
        "X-Frame-Options": {
            "patterns": [r"(?i)x-frame-options", r"(?i)frame-ancestors"],
            "severity": Severity.LOW,
            "recommendation": "Set X-Frame-Options or CSP frame-ancestors to prevent clickjacking.",
            "example": "X-Frame-Options: DENY",
        },
        "X-Content-Type-Options": {
            "patterns": [r"(?i)x-content-type-options"],
            "severity": Severity.LOW,
            "recommendation": "Set nosniff to prevent MIME type sniffing.",
            "example": "X-Content-Type-Options: nosniff",
        },
        "Referrer-Policy": {
            "patterns": [r"(?i)referrer-policy"],
            "severity": Severity.LOW,
            "recommendation": "Configure Referrer-Policy to limit information leakage.",
            "example": "Referrer-Policy: strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "patterns": [r"(?i)permissions-policy", r"(?i)feature-policy"],
            "severity": Severity.LOW,
            "recommendation": "Restrict browser features with Permissions-Policy.",
            "example": "Permissions-Policy: geolocation=(), camera=(), microphone=()",
        },
    }

    INSECURE_PATTERNS = [
        (r"(?i)access-control-allow-origin\s*[=:]\s*['\"]?\*['\"]?", "CORS Wildcard Origin", Severity.MEDIUM),
        (r"(?i)X-Powered-By", "X-Powered-By Header Exposed", Severity.LOW),
        (r"(?i)Server:\s*(Apache|nginx|IIS)", "Server Version Exposed", Severity.LOW),
    ]

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Analyze security header configuration."""
        findings: list[SecurityFinding] = []
        all_content = "\n".join(f.content or "" for f in files)
        config_files = self._get_content_files(files, CONFIG_EXTENSIONS)

        for header, config in self.REQUIRED_HEADERS.items():
            found = any(re.search(p, all_content) for p in config["patterns"])
            if not found:
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4())[:8],
                    title=f"Missing Security Header: {header}",
                    severity=config["severity"],
                    category="Security Headers",
                    owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                    description=f"No configuration found for the {header} security header.",
                    risk=f"Missing {header} reduces defense-in-depth against web attacks.",
                    recommendation=config["recommendation"],
                    example_fix=config["example"],
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"],
                    analyzer=self.name,
                ))

        for f in config_files:
            if not f.content:
                continue
            for pattern, title, severity in self.INSECURE_PATTERNS:
                for line_num, line in enumerate(f.content.splitlines(), 1):
                    if re.search(pattern, line):
                        findings.append(SecurityFinding(
                            id=str(uuid.uuid4())[:8],
                            title=f"Insecure Header Configuration: {title}",
                            severity=severity,
                            category="Security Headers",
                            owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                            description=f"Insecure header setting detected: {title}",
                            risk="Misconfigured headers can expose server information or weaken CORS policy.",
                            recommendation="Restrict CORS origins, remove X-Powered-By, hide server version.",
                            example_fix="Access-Control-Allow-Origin: https://trusted-domain.com",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"],
                            file_path=f.relative_path,
                            line_number=line_num,
                            code_snippet=line[:200],
                            analyzer=self.name,
                        ))

        return findings
