"""Secrets and credential detection scanner."""

from __future__ import annotations

import logging
import math
import re
import uuid
from collections import Counter
from pathlib import Path

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.config import get_config
from focp_sec.core.models import OWASPCategory, SecurityFinding, Severity
from focp_sec.core.scanner import ScannedFile

logger = logging.getLogger(__name__)


class SecretsScanner(BaseAnalyzer):
    """Detects hardcoded secrets, API keys, and credentials."""

    name = "secrets_scanner"

    SECRET_PATTERNS: list[tuple[str, str, Severity, str]] = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity.CRITICAL, "AWS"),
        (r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"][A-Za-z0-9/+=]{40}['\"]", "AWS Secret Access Key", Severity.CRITICAL, "AWS"),
        (r"(?i)azure[_-]?(?:storage|account)[_-]?key\s*[=:]\s*['\"][A-Za-z0-9+/=]{40,}['\"]", "Azure Storage Key", Severity.CRITICAL, "Azure"),
        (r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "API Key", Severity.HIGH, "API Key"),
        (r"(?i)(?:secret[_-]?key|secret_key)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "Secret Key", Severity.HIGH, "Secret"),
        (r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]", "Hardcoded Password", Severity.CRITICAL, "Password"),
        (r"(?i)(?:jwt[_-]?secret|token[_-]?secret)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "JWT Secret", Severity.CRITICAL, "JWT"),
        (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key", Severity.CRITICAL, "Private Key"),
        (r"(?i)(?:github|gitlab|bitbucket)[_-]?token\s*[=:]\s*['\"][A-Za-z0-9_\-]{20,}['\"]", "VCS Token", Severity.HIGH, "VCS"),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", Severity.CRITICAL, "GitHub"),
        (r"glpat-[A-Za-z0-9\-_]{20,}", "GitLab Personal Access Token", Severity.CRITICAL, "GitLab"),
        (r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}", "OpenAI API Key", Severity.HIGH, "OpenAI"),
        (r"(?i)stripe[_-]?(?:secret|api)[_-]?key\s*[=:]\s*['\"]sk_(?:live|test)_[A-Za-z0-9]{20,}['\"]", "Stripe Secret Key", Severity.CRITICAL, "Stripe"),
        (r"(?i)slack[_-]?(?:token|webhook)\s*[=:]\s*['\"]https?://hooks\.slack\.com/[^'\"]+['\"]", "Slack Webhook", Severity.HIGH, "Slack"),
        (r"(?i)database[_-]?url\s*[=:]\s*['\"]postgres(?:ql)?://[^'\"]+['\"]", "Database Connection String", Severity.HIGH, "Database"),
        (r"(?i)mongodb(?:\+srv)?://[^\s'\"]+:[^\s'\"@]+@", "MongoDB Credentials in URI", Severity.HIGH, "Database"),
        (r"(?i)sendgrid[_-]?api[_-]?key\s*[=:]\s*['\"]SG\.[A-Za-z0-9_\-]{20,}['\"]", "SendGrid API Key", Severity.HIGH, "SendGrid"),
    ]

    FALSE_POSITIVE_PATTERNS = [
        r"(?i)(example|placeholder|changeme|your[_-]?key|xxx|<.*>|dummy|test|sample|fake)",
        r"\$\{",
        r"process\.env",
        r"os\.environ",
        r"getenv\(",
        r"config\(",
        r"settings\.",
    ]

    SKIP_FILES = {".env.example", ".env.sample", ".env.template", "README.md", "CHANGELOG.md"}

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Scan files for hardcoded secrets."""
        findings: list[SecurityFinding] = []
        threshold = get_config().secrets_entropy_threshold

        for f in files:
            if f.path.name in self.SKIP_FILES:
                continue
            if not f.content:
                continue
            if f.path.name == ".env":
                findings.append(self._env_file_finding(f))
                continue

            for pattern, title, severity, secret_type in self.SECRET_PATTERNS:
                for line_num, line in enumerate(f.content.splitlines(), 1):
                    if self._is_false_positive(line):
                        continue
                    match = re.search(pattern, line)
                    if match:
                        findings.append(self._create_finding(f, line_num, line, title, severity, secret_type, match.group()))

            for line_num, line in enumerate(f.content.splitlines(), 1):
                if self._is_false_positive(line):
                    continue
                if "=" in line or ":" in line:
                    for part in re.split(r"[=:]", line, maxsplit=1):
                        part = part.strip().strip("'\"")
                        if 16 <= len(part) <= 128 and self._shannon_entropy(part) > threshold:
                            if not any(re.search(p, line, re.I) for p, _, _, _ in self.SECRET_PATTERNS):
                                findings.append(
                                    self._create_finding(
                                        f, line_num, line,
                                        "High Entropy String (Possible Secret)",
                                        Severity.MEDIUM, "Entropy",
                                        part[:20] + "...",
                                    )
                                )
                            break

        return self._deduplicate(findings)

    def _shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in counter.values())

    def _is_false_positive(self, line: str) -> bool:
        """Check if line is likely a false positive."""
        return any(re.search(p, line) for p in self.FALSE_POSITIVE_PATTERNS)

    def _env_file_finding(self, f: ScannedFile) -> SecurityFinding:
        """Create finding for committed .env file."""
        return SecurityFinding(
            id=str(uuid.uuid4())[:8],
            title="Environment File Committed to Repository",
            severity=Severity.HIGH,
            category="Secrets",
            owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
            description=f"The file '{f.relative_path}' appears to be an environment file committed to source control.",
            risk="Environment files often contain production credentials, API keys, and database passwords.",
            recommendation="Remove .env from version control, add it to .gitignore, and rotate all exposed credentials.",
            example_fix="# .gitignore\n.env\n.env.local\n.env.production\n\n# Use .env.example for templates",
            references=[
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            ],
            file_path=f.relative_path,
            business_impact="Credential exposure can lead to data breaches and unauthorized access.",
            analyzer=self.name,
        )

    def _create_finding(
        self, f: ScannedFile, line_num: int, line: str,
        title: str, severity: Severity, secret_type: str, matched: str,
    ) -> SecurityFinding:
        """Create a secret finding."""
        masked = matched[:4] + "*" * min(len(matched) - 4, 20) if len(matched) > 4 else "****"
        return SecurityFinding(
            id=str(uuid.uuid4())[:8],
            title=f"{title} Detected",
            severity=severity,
            category="Secrets",
            owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
            description=f"A potential {secret_type} was found hardcoded in source code.",
            risk="Hardcoded secrets can be extracted from source code, version history, or decompiled binaries.",
            recommendation="Move secrets to environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager).",
            example_fix=f"# Bad\n{secret_type.lower()}_key = '{masked}'\n\n# Good\nimport os\n{secret_type.lower()}_key = os.environ['{secret_type.upper()}_KEY']",
            references=[
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            ],
            file_path=f.relative_path,
            line_number=line_num,
            code_snippet=line[:200],
            business_impact="Exposed credentials enable unauthorized access and potential data breaches.",
            analyzer=self.name,
            metadata={"secret_type": secret_type},
        )

    def _deduplicate(self, findings: list[SecurityFinding]) -> list[SecurityFinding]:
        """Remove duplicate findings at same location."""
        seen: set[tuple[str | None, int | None, str]] = set()
        unique: list[SecurityFinding] = []
        for f in findings:
            key = (f.file_path, f.line_number, f.title)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
