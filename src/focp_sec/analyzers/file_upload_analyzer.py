"""File upload security review analyzer."""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.models import OWASPCategory, SecurityFinding, Severity
from focp_sec.core.scanner import ScannedFile

CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".cs", ".rb", ".go"}


class FileUploadAnalyzer(BaseAnalyzer):
    """Reviews file upload security controls."""

    name = "file_upload_analyzer"

    UPLOAD_PATTERNS = [
        (r"(?i)(upload|multipart|FormData|file\.save|save_uploaded|multer|UploadFile)", "File Upload Handler"),
        (r"(?i)(request\.files|req\.file|$_FILES)", "File Input Access"),
    ]

    VALIDATION_PATTERNS = [
        (r"(?i)(allowed_extensions|ALLOWED_EXTENSIONS|file_type|mimetype|content_type|magic)", "Extension/MIME Validation"),
        (r"(?i)(max_size|MAX_FILE_SIZE|file\.size|limit.*mb)", "Size Limit"),
        (r"(?i)(secure_filename|sanitize.*filename|path\.basename)", "Filename Sanitization"),
        (r"(?i)(virus|clamav|scan.*file)", "Malware Scanning"),
    ]

    UNSAFE_PATTERNS = [
        (r"(?i)(upload.*\.\./|path\.join.*filename|os\.path\.join.*upload)", "Path Traversal in Upload", Severity.CRITICAL),
        (r"(?i)(\.php|\.jsp|\.asp|\.aspx|\.exe|\.sh|\.bat)", "Dangerous Extension Allowed", Severity.HIGH),
        (r"(?i)(public/uploads|www/uploads|webroot)", "Upload to Web-Accessible Directory", Severity.MEDIUM),
    ]

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Analyze file upload security."""
        findings: list[SecurityFinding] = []
        code_files = self._get_content_files(files, CODE_EXTENSIONS)
        has_upload = False
        validations_found: set[str] = set()

        for f in code_files:
            if not f.content:
                continue

            for pattern, label in self.UPLOAD_PATTERNS:
                if re.search(pattern, f.content):
                    has_upload = True

            for pattern, label in self.VALIDATION_PATTERNS:
                if re.search(pattern, f.content):
                    validations_found.add(label)

            for pattern, title, severity in self.UNSAFE_PATTERNS:
                for line_num, line in enumerate(f.content.splitlines(), 1):
                    if re.search(pattern, line):
                        findings.append(SecurityFinding(
                            id=str(uuid.uuid4())[:8],
                            title=f"File Upload Risk: {title}",
                            severity=severity,
                            category="File Upload",
                            owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                            description=f"Unsafe file upload pattern: {title}",
                            risk="Insecure file uploads can lead to remote code execution or data exposure.",
                            recommendation="Validate file type by content (magic bytes), restrict extensions, limit size, store outside webroot.",
                            example_fix="from werkzeug.utils import secure_filename\nimport magic\n\nfilename = secure_filename(file.filename)\nmime = magic.from_buffer(file.read(2048), mime=True)\nif mime not in ALLOWED_MIMES: raise ValueError('Invalid file type')",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"],
                            file_path=f.relative_path,
                            line_number=line_num,
                            code_snippet=line[:200],
                            business_impact="Malicious file uploads can compromise server infrastructure.",
                            analyzer=self.name,
                        ))

        if has_upload:
            missing = {"Extension/MIME Validation", "Size Limit", "Filename Sanitization"} - validations_found
            for check in missing:
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4())[:8],
                    title=f"Missing File Upload Control: {check}",
                    severity=Severity.MEDIUM,
                    category="File Upload",
                    owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                    description=f"File upload functionality detected but {check} not found.",
                    risk="Missing upload validation increases risk of malicious file uploads.",
                    recommendation=f"Implement {check.lower()} for all file upload endpoints.",
                    example_fix="# See OWASP File Upload Cheat Sheet",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"],
                    analyzer=self.name,
                ))

        return findings
