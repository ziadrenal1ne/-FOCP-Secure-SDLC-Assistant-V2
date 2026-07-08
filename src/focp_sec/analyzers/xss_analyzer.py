"""Cross-Site Scripting (XSS) vulnerability analyzer."""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.models import OWASPCategory, SecurityFinding, Severity
from focp_sec.core.scanner import ScannedFile

WEB_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".cs", ".html", ".vue"}


class XSSAnalyzer(BaseAnalyzer):
    """Detects XSS vulnerabilities."""

    name = "xss_analyzer"

    UNSAFE_PATTERNS = [
        (r"(?i)dangerouslySetInnerHTML", "React dangerouslySetInnerHTML", Severity.HIGH),
        (r"(?i)\.innerHTML\s*=", "Direct innerHTML Assignment", Severity.HIGH),
        (r"(?i)document\.write\s*\(", "document.write Usage", Severity.HIGH),
        (r"(?i)\$\(\s*['\"]<", "jQuery HTML Injection", Severity.MEDIUM),
        (r"(?i)v-html\s*=", "Vue v-html Directive", Severity.MEDIUM),
        (r"(?i)\[innerHTML\]\s*=", "Angular innerHTML Binding", Severity.MEDIUM),
        (r"(?i)Markup\s*\(\s*@", "ASP.NET Raw HTML", Severity.HIGH),
        (r"(?i)render_template_string\s*\(", "Flask render_template_string", Severity.HIGH),
        (r"(?i)\|\s*safe\b", "Jinja2 |safe Filter", Severity.MEDIUM),
        (r"(?i)echo\s+\$_(GET|POST|REQUEST)", "PHP Echo User Input", Severity.CRITICAL),
        (r"(?i)res\.send\s*\(\s*req\.", "Express Direct Response", Severity.HIGH),
        (r"(?i)\{\{\{.*\}\}\}", "Triple Mustache (Unescaped)", Severity.MEDIUM),
    ]

    SANITIZE_PATTERNS = [
        r"(?i)(sanitize|escape|DOMPurify|bleach\.clean|html\.Escape|encodeURIComponent)",
        r"(?i)(markupsafe|htmlspecialchars|strip_tags)",
    ]

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Analyze for XSS patterns."""
        findings: list[SecurityFinding] = []
        web_files = self._get_content_files(files, WEB_EXTENSIONS)

        for f in web_files:
            if not f.content:
                continue
            for pattern, title, severity in self.UNSAFE_PATTERNS:
                for line_num, line in enumerate(f.content.splitlines(), 1):
                    if re.search(pattern, line):
                        context_start = max(0, line_num - 5)
                        context = "\n".join(f.content.splitlines()[context_start:line_num + 3])
                        if any(re.search(sp, context) for sp in self.SANITIZE_PATTERNS):
                            severity = Severity.LOW if severity != Severity.CRITICAL else Severity.MEDIUM
                        findings.append(SecurityFinding(
                            id=str(uuid.uuid4())[:8],
                            title=f"XSS Risk: {title}",
                            severity=severity,
                            category="XSS",
                            owasp_category=OWASPCategory.A03_INJECTION,
                            description="Potentially unsafe HTML rendering or output encoding issue detected.",
                            risk="XSS allows attackers to inject malicious scripts executed in users' browsers.",
                            recommendation="Encode all output contextually. Use framework auto-escaping. Sanitize HTML with DOMPurify or bleach.",
                            example_fix="# React - avoid dangerouslySetInnerHTML\n// Use text content instead\n<div>{userInput}</div>\n\n# Python\nfrom markupsafe import escape\nreturn escape(user_input)",
                            references=[
                                "https://owasp.org/Top10/A03_2021-Injection/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            ],
                            file_path=f.relative_path,
                            line_number=line_num,
                            code_snippet=line[:200],
                            business_impact="XSS enables session hijacking, credential theft, and malware delivery.",
                            analyzer=self.name,
                        ))

        has_csp = any(
            re.search(r"(?i)content-security-policy", f.content or "")
            for f in files if f.content
        )
        if not has_csp:
            findings.append(SecurityFinding(
                id=str(uuid.uuid4())[:8],
                title="No Content Security Policy Detected",
                severity=Severity.MEDIUM,
                category="XSS",
                owasp_category=OWASPCategory.A03_INJECTION,
                description="No Content-Security-Policy header configuration found.",
                risk="Without CSP, XSS attacks have fewer browser-level mitigations.",
                recommendation="Implement a strict Content-Security-Policy header.",
                example_fix="Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
                analyzer=self.name,
            ))

        return findings
