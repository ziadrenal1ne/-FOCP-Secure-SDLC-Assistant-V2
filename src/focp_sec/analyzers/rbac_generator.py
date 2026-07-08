"""RBAC matrix generator."""

from __future__ import annotations

import re
from pathlib import Path

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.models import RBACEntry, SecurityFinding
from focp_sec.core.scanner import ScannedFile

CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".cs", ".rb", ".go"}


class RBACGenerator(BaseAnalyzer):
    """Generates RBAC matrix from detected patterns."""

    name = "rbac_generator"

    DEFAULT_ROLES = [
        RBACEntry(role="Guest", resource="Public Pages", permissions=["read"], description="Unauthenticated users"),
        RBACEntry(role="User", resource="User Profile", permissions=["read", "update"], description="Authenticated standard user"),
        RBACEntry(role="User", resource="User Data", permissions=["read", "create", "update"], description="Own data only"),
        RBACEntry(role="Admin", resource="User Management", permissions=["read", "create", "update", "delete"], description="Administrative user management"),
        RBACEntry(role="Admin", resource="System Configuration", permissions=["read", "update"], description="System settings"),
        RBACEntry(role="Admin", resource="Audit Logs", permissions=["read"], description="Security audit access"),
        RBACEntry(role="Service", resource="Internal API", permissions=["read", "create"], description="Service-to-service communication"),
    ]

    ROLE_PATTERNS = [
        (r"(?i)role\s*[=:]\s*['\"](\w+)['\"]", "role_assignment"),
        (r"(?i)@requires_role\s*\(\s*['\"](\w+)['\"]", "role_decorator"),
        (r"(?i)hasRole\s*\(\s*['\"](\w+)['\"]", "spring_role"),
        (r"(?i)is_(\w+)\s*\(", "role_check"),
    ]

    PERMISSION_PATTERNS = [
        (r"(?i)permission\s*[=:]\s*['\"](\w+)['\"]", "permission"),
        (r"(?i)can_(\w+)", "can_permission"),
        (r"(?i)@permission_required\s*\(\s*['\"](\w+)['\"]", "permission_decorator"),
    ]

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """RBAC generator produces matrix, not findings."""
        return []

    def generate(
        self,
        project_path: Path,
        files: list[ScannedFile],
    ) -> list[RBACEntry]:
        """Generate RBAC matrix from code analysis."""
        entries: list[RBACEntry] = []
        detected_roles: set[str] = set()
        detected_permissions: set[str] = set()
        code_files = self._get_content_files(files, CODE_EXTENSIONS)

        for f in code_files:
            if not f.content:
                continue
            for pattern, _ in self.ROLE_PATTERNS:
                for match in re.finditer(pattern, f.content):
                    role = match.group(1)
                    if role.lower() not in ("self", "none", "true", "false"):
                        detected_roles.add(role.lower())

            for pattern, _ in self.PERMISSION_PATTERNS:
                for match in re.finditer(pattern, f.content):
                    perm = match.group(1)
                    detected_permissions.add(perm.lower())

        if detected_roles:
            for role in sorted(detected_roles):
                perms = sorted(detected_permissions) if detected_permissions else ["read"]
                entries.append(RBACEntry(
                    role=role.capitalize(),
                    resource="Application Resources",
                    permissions=perms[:10],
                    description=f"Detected role '{role}' in codebase",
                ))
        else:
            entries = list(self.DEFAULT_ROLES)

        return entries
