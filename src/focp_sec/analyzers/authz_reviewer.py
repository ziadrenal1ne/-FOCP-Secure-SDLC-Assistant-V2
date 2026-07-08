"""Authorization and access control review analyzer."""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.models import OWASPCategory, SecurityFinding, Severity
from focp_sec.core.scanner import ScannedFile

CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".cs", ".rb", ".go"}


class AuthzReviewer(BaseAnalyzer):
    """Reviews authorization, RBAC, and access control patterns."""

    name = "authz_reviewer"

    MISSING_AUTHZ_PATTERNS = [
        (r"@app\.(route|get|post|put|delete|patch)\s*\(", "Flask Route"),
        (r"@router\.(get|post|put|delete|patch)", "FastAPI Route"),
        (r"app\.(get|post|put|delete|patch)\s*\(", "Express Route"),
        (r"@RequestMapping|@GetMapping|@PostMapping", "Spring Route"),
    ]

    ADMIN_PATTERNS = [
        (r"(?i)(/admin|/manage|/superuser|/root|/internal)", "Admin Endpoint Path"),
        (r"(?i)(is_admin|isAdmin|role\s*==\s*['\"]admin['\"])", "Admin Role Check"),
    ]

    PRIV_ESC_PATTERNS = [
        (r"(?i)(user\.id\s*=\s*request|params\[.id.\]|req\.body\.role)", "User-Controlled ID/Role"),
        (r"(?i)(setattr|eval|exec)\s*\(", "Dynamic Code Execution"),
        (r"(?i)mass[_-]?assign", "Mass Assignment"),
    ]

    RBAC_PATTERNS = [
        (r"(?i)(@requires_role|@permission_required|@authorize|has_permission|check_permission)", "RBAC Decorator"),
        (r"(?i)(RBAC|RoleBased|AccessControl|PolicyBased)", "RBAC Framework"),
    ]

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Analyze authorization patterns."""
        findings: list[SecurityFinding] = []
        code_files = self._get_content_files(files, CODE_EXTENSIONS)
        has_rbac = False
        admin_endpoints: list[tuple[ScannedFile, int, str]] = []

        for f in code_files:
            if not f.content:
                continue

            for pattern, _ in self.RBAC_PATTERNS:
                if re.search(pattern, f.content):
                    has_rbac = True

            for pattern, label in self.ADMIN_PATTERNS:
                for line_num, line in enumerate(f.content.splitlines(), 1):
                    if re.search(pattern, line):
                        admin_endpoints.append((f, line_num, line))

            for pattern, label in self.PRIV_ESC_PATTERNS:
                for line_num, line in enumerate(f.content.splitlines(), 1):
                    if re.search(pattern, line):
                        findings.append(SecurityFinding(
                            id=str(uuid.uuid4())[:8],
                            title=f"Potential Privilege Escalation: {label}",
                            severity=Severity.HIGH,
                            category="Authorization",
                            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                            description=f"Code pattern '{label}' may allow privilege escalation.",
                            risk="Attackers can elevate privileges by manipulating user IDs, roles, or object references.",
                            recommendation="Validate authorization server-side for every request. Never trust client-supplied roles or IDs.",
                            example_fix="# Verify user owns resource\nif resource.owner_id != current_user.id:\n    raise Forbidden()",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"],
                            file_path=f.relative_path,
                            line_number=line_num,
                            code_snippet=line[:200],
                            business_impact="Privilege escalation can grant attackers admin access.",
                            analyzer=self.name,
                        ))

        for f, line_num, line in admin_endpoints:
            context_start = max(0, line_num - 10)
            context_lines = f.content.splitlines()[context_start:line_num + 5] if f.content else []
            context = "\n".join(context_lines)
            has_auth_check = bool(re.search(
                r"(?i)(@login_required|@requires_role|@permission_required|@authorize|"
                r"has_permission|check_permission|authenticate\(|is_authenticated|"
                r"login_required|permission_required|requires_auth)",
                context,
            ))
            if not has_auth_check:
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4())[:8],
                    title="Admin Endpoint Without Visible Authorization",
                    severity=Severity.HIGH,
                    category="Authorization",
                    owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                    description="An admin or privileged endpoint was found without nearby authorization checks.",
                    risk="Unprotected admin endpoints allow unauthorized access to sensitive operations.",
                    recommendation="Add role-based authorization checks before all admin endpoints.",
                    example_fix="@app.route('/admin/users')\n@login_required\n@requires_role('admin')\ndef admin_users(): ...",
                    references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
                    file_path=f.relative_path,
                    line_number=line_num,
                    code_snippet=line[:200],
                    business_impact="Unauthorized admin access can compromise entire application.",
                    analyzer=self.name,
                ))

        if not has_rbac and code_files:
            findings.append(SecurityFinding(
                id=str(uuid.uuid4())[:8],
                title="No RBAC Framework Detected",
                severity=Severity.MEDIUM,
                category="Authorization",
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                description="No role-based access control patterns were detected.",
                risk="Without RBAC, authorization logic may be inconsistent or missing.",
                recommendation="Implement centralized RBAC with defined roles and permissions.",
                example_fix="# Define roles\nROLES = {'admin': ['read', 'write', 'delete'], 'user': ['read']}",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"],
                analyzer=self.name,
            ))

        return findings
