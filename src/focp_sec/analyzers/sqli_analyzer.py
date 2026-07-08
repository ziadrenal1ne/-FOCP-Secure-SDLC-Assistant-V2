"""SQL injection vulnerability analyzer."""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.models import OWASPCategory, SecurityFinding, Severity
from focp_sec.core.scanner import ScannedFile

CODE_EXTENSIONS = {".py", ".js", ".ts", ".java", ".php", ".cs", ".rb", ".go"}


class SQLInjectionAnalyzer(BaseAnalyzer):
    """Detects SQL injection vulnerabilities."""

    name = "sqli_analyzer"

    UNSAFE_PATTERNS = [
        (r"(?i)(execute|query|raw)\s*\(\s*f['\"]", "Python f-string SQL", Severity.CRITICAL),
        (r"(?i)(execute|query)\s*=\s*f['\"]", "Python f-string SQL Assignment", Severity.CRITICAL),
        (r"(?i)(execute|query)\s*=\s*['\"].*%[sd]", "Python % Formatting SQL", Severity.CRITICAL),
        (r"(?i)(execute|query)\s*\(\s*['\"].*%[sd]", "Python % Formatting SQL", Severity.CRITICAL),
        (r"(?i)(execute|query)\s*=\s*['\"].*\+", "SQL String Concatenation", Severity.CRITICAL),
        (r"(?i)(execute|query)\s*\(\s*['\"].*\+", "SQL String Concatenation", Severity.CRITICAL),
        (r"(?i)\.format\s*\(\s*.*\)\s*$", "SQL .format() Injection", Severity.HIGH),
        (r"(?i)(mysql_query|mysqli_query)\s*\(\s*\$", "PHP Direct Query", Severity.CRITICAL),
        (r"(?i)\$_(GET|POST|REQUEST)\[.*\].*(query|sql)", "PHP User Input in SQL", Severity.CRITICAL),
        (r'(?i)(query|execute)\s*\(\s*`[^`]*\$\{', "JS Template Literal SQL", Severity.CRITICAL),
        (r"(?i)createQuery\s*\(\s*['\"].*\+", "Java Query Concatenation", Severity.CRITICAL),
        (r"(?i)Statement\.execute\s*\(\s*['\"].*\+", "Java Statement Concatenation", Severity.CRITICAL),
        (r"(?i)db\.Execute\s*\(\s*fmt\.Sprintf", "Go fmt.Sprintf SQL", Severity.CRITICAL),
    ]

    SAFE_PATTERNS = [
        r"(?i)(prepare|prepared|parameterized|\?\s*,|:\w+\s*,|%s\s*,)",
        r"(?i)(sqlalchemy\.text|cursor\.execute\s*\(\s*['\"][^'\"]*\?\s*['\"])",
        r"(?i)(ORM|Model\.objects|findOne|findMany|knex|prisma)",
    ]

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Analyze for SQL injection patterns."""
        findings: list[SecurityFinding] = []
        code_files = self._get_content_files(files, CODE_EXTENSIONS)

        for f in code_files:
            if not f.content:
                continue
            for pattern, title, severity in self.UNSAFE_PATTERNS:
                for line_num, line in enumerate(f.content.splitlines(), 1):
                    if re.search(pattern, line):
                        if any(re.search(sp, line) for sp in self.SAFE_PATTERNS):
                            continue
                        findings.append(SecurityFinding(
                            id=str(uuid.uuid4())[:8],
                            title=f"SQL Injection Risk: {title}",
                            severity=severity,
                            category="Injection",
                            owasp_category=OWASPCategory.A03_INJECTION,
                            description="Dynamic SQL construction with user input detected.",
                            risk="Attackers can manipulate SQL queries to read, modify, or delete database data.",
                            recommendation="Use parameterized queries or ORM methods. Never concatenate user input into SQL.",
                            example_fix="# Bad\ncursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n\n# Good\ncursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                            references=[
                                "https://owasp.org/Top10/A03_2021-Injection/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            ],
                            file_path=f.relative_path,
                            line_number=line_num,
                            code_snippet=line[:200],
                            business_impact="SQL injection can lead to complete database compromise.",
                            analyzer=self.name,
                        ))

        return findings
