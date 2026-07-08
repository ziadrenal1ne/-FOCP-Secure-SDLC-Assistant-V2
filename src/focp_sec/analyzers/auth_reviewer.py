"""Authentication security review analyzer."""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.models import OWASPCategory, SecurityFinding, Severity
from focp_sec.core.scanner import ScannedFile

CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".cs", ".rb", ".go"}


class AuthReviewer(BaseAnalyzer):
    """Reviews authentication implementation patterns."""

    name = "auth_reviewer"

    WEAK_HASH_PATTERNS = [
        (r"(?i)(md5|sha1)\s*\(", "Weak Hash Algorithm (MD5/SHA1)", Severity.HIGH),
        (r"(?i)hashlib\.(md5|sha1)\(", "Weak Hash Algorithm", Severity.HIGH),
        (r"(?i)password\s*==\s*", "Plaintext Password Comparison", Severity.CRITICAL),
        (r"(?i)bcrypt\.hashpw|argon2|scrypt|pbkdf2", "STRONG_HASH", Severity.INFO),
    ]

    JWT_PATTERNS = [
        (r"(?i)jwt\.decode\s*\([^)]*verify\s*=\s*False", "JWT Verification Disabled", Severity.CRITICAL),
        (r"(?i)algorithm\s*=\s*['\"]none['\"]", "JWT Algorithm None", Severity.CRITICAL),
        (r"(?i)jwt\.encode\s*\(", "JWT Usage Detected", Severity.INFO),
    ]

    SESSION_PATTERNS = [
        (r"(?i)session\[.cookie.\]\s*=\s*\{[^}]*secure\s*:\s*false", "Insecure Session Cookie", Severity.HIGH),
        (r"(?i)httponly\s*:\s*false", "Session Cookie Missing HttpOnly", Severity.MEDIUM),
        (r"(?i)samesite\s*:\s*['\"]none['\"]", "SameSite=None Without Secure", Severity.MEDIUM),
    ]

    MFA_PATTERNS = [
        (r"(?i)(totp|mfa|2fa|two[_-]factor|multi[_-]factor)", "MFA Reference", Severity.INFO),
    ]

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Analyze authentication patterns."""
        findings: list[SecurityFinding] = []
        code_files = self._get_content_files(files, CODE_EXTENSIONS)

        for f in code_files:
            if not f.content:
                continue
            for pattern, title, severity in self.WEAK_HASH_PATTERNS:
                if title == "STRONG_HASH":
                    continue
                for line_num, line in enumerate(f.content.splitlines(), 1):
                    if re.search(pattern, line):
                        findings.append(self._make_finding(f, line_num, line, title, severity))

            for pattern, title, severity in self.JWT_PATTERNS:
                if severity == Severity.INFO:
                    continue
                for line_num, line in enumerate(f.content.splitlines(), 1):
                    if re.search(pattern, line):
                        findings.append(self._make_finding(f, line_num, line, title, severity, "JWT"))

            for pattern, title, severity in self.SESSION_PATTERNS:
                for line_num, line in enumerate(f.content.splitlines(), 1):
                    if re.search(pattern, line):
                        findings.append(self._make_finding(f, line_num, line, title, severity, "Session"))

        has_strong_hash = any(
            re.search(r"(?i)bcrypt|argon2|scrypt|pbkdf2", f.content or "")
            for f in code_files
        )
        has_mfa = any(
            re.search(r"(?i)(totp|mfa|2fa|two[_-]factor)", f.content or "")
            for f in code_files
        )

        if not has_strong_hash and code_files:
            findings.append(SecurityFinding(
                id=str(uuid.uuid4())[:8],
                title="No Strong Password Hashing Detected",
                severity=Severity.MEDIUM,
                category="Authentication",
                owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                description="No evidence of bcrypt, Argon2, scrypt, or PBKDF2 password hashing was found.",
                risk="Weak or missing password hashing allows offline cracking if credentials are compromised.",
                recommendation="Use bcrypt, Argon2id, or PBKDF2 with appropriate work factors for password storage.",
                example_fix="# Python\nfrom passlib.hash import bcrypt\nhashed = bcrypt.hash(password)\nbcrypt.verify(password, hashed)",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"],
                analyzer=self.name,
            ))

        if not has_mfa:
            findings.append(SecurityFinding(
                id=str(uuid.uuid4())[:8],
                title="Multi-Factor Authentication Not Detected",
                severity=Severity.LOW,
                category="Authentication",
                owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                description="No MFA/2FA implementation patterns were detected in the codebase.",
                risk="Single-factor authentication is vulnerable to credential stuffing and phishing.",
                recommendation="Implement TOTP-based MFA or WebAuthn for sensitive operations.",
                example_fix="# Use pyotp for TOTP\nimport pyotp\ntotp = pyotp.TOTP(user.mfa_secret)\nif totp.verify(token): ...",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html"],
                analyzer=self.name,
            ))

        return findings

    def _make_finding(
        self, f: ScannedFile, line_num: int, line: str, title: str,
        severity: Severity, subcategory: str = "Authentication",
    ) -> SecurityFinding:
        """Create authentication finding."""
        fixes = {
            "Weak Hash Algorithm (MD5/SHA1)": "Use bcrypt.hashpw() or passlib with bcrypt/argon2.",
            "Plaintext Password Comparison": "Never compare passwords directly; use constant-time hash verification.",
            "JWT Verification Disabled": "Always verify JWT signatures: jwt.decode(token, key, algorithms=['HS256'])",
            "JWT Algorithm None": "Reject tokens with 'none' algorithm; whitelist allowed algorithms.",
            "Insecure Session Cookie": "Set secure=True, httponly=True, samesite='Lax' on session cookies.",
        }
        return SecurityFinding(
            id=str(uuid.uuid4())[:8],
            title=title,
            severity=severity,
            category="Authentication",
            owasp_category=OWASPCategory.A07_AUTH_FAILURES,
            description=f"{subcategory} issue detected in application code.",
            risk="Authentication weaknesses can lead to account takeover and unauthorized access.",
            recommendation=fixes.get(title, "Review and fix authentication implementation."),
            example_fix=fixes.get(title, "# See OWASP Authentication Cheat Sheet"),
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"],
            file_path=f.relative_path,
            line_number=line_num,
            code_snippet=line[:200],
            business_impact="Authentication failures expose user accounts and sensitive data.",
            analyzer=self.name,
        )
