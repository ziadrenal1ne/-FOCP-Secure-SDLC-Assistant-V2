"""AI-enhanced recommendation engine for findings."""

from __future__ import annotations

from focp_sec.core.models import SecurityFinding, Severity

SEVERITY_IMPACT = {
    Severity.CRITICAL: "Critical business impact: potential data breach, regulatory fines, and reputational damage.",
    Severity.HIGH: "High business impact: service disruption, data exposure, or compliance violations likely.",
    Severity.MEDIUM: "Medium business impact: increased attack surface, potential for exploitation under specific conditions.",
    Severity.LOW: "Low business impact: defense-in-depth improvement recommended.",
    Severity.INFO: "Informational: best practice recommendation for security maturity.",
}

CATEGORY_CONTEXT = {
    "Secrets": "Credential exposure is among the most common causes of cloud breaches.",
    "Authentication": "Authentication is the front door to your application.",
    "Authorization": "Broken access control is OWASP #1 for good reason.",
    "Injection": "Injection flaws remain in the OWASP Top 10 due to their severe impact.",
    "XSS": "Cross-site scripting affects users directly and erodes trust.",
    "Dependencies": "Supply chain attacks through dependencies are rapidly increasing.",
    "Security Headers": "Security headers provide browser-level defense-in-depth.",
    "File Upload": "Unrestricted file upload is a common path to remote code execution.",
    "OWASP Top 10": "Addressing OWASP Top 10 findings significantly reduces risk.",
}


class RecommendationEngine:
    """Enhances findings with detailed recommendations."""

    def enhance(self, findings: list[SecurityFinding]) -> list[SecurityFinding]:
        """Enhance all findings with business impact and detailed guidance."""
        enhanced: list[SecurityFinding] = []
        for finding in findings:
            enhanced.append(self._enhance_finding(finding))
        return enhanced

    def _enhance_finding(self, finding: SecurityFinding) -> SecurityFinding:
        """Enhance a single finding."""
        if not finding.business_impact:
            finding.business_impact = SEVERITY_IMPACT.get(
                finding.severity,
                "Review and remediate this finding to improve security posture.",
            )

        context = CATEGORY_CONTEXT.get(finding.category, "")
        if context and context not in finding.description:
            finding.description = f"{finding.description} {context}"

        if not finding.example_fix or finding.example_fix.startswith("# See"):
            finding.example_fix = self._generate_example(finding)

        if len(finding.references) < 2:
            finding.references.extend(self._default_references(finding))

        return finding

    def _generate_example(self, finding: SecurityFinding) -> str:
        """Generate contextual code example."""
        examples = {
            "Secrets": "# Use environment variables\nimport os\napi_key = os.environ.get('API_KEY')\nif not api_key:\n    raise ValueError('API_KEY not configured')",
            "Authentication": "# Secure password verification\nfrom passlib.hash import bcrypt\nif bcrypt.verify(password, stored_hash):\n    create_session(user)",
            "Authorization": "# Server-side authorization\n@requires_permission('users:delete')\ndef delete_user(user_id):\n    if not current_user.can_delete(user_id):\n        raise Forbidden()",
            "Injection": "# Parameterized query\n cursor.execute('SELECT * FROM users WHERE email = %s', (email,))",
            "XSS": "# Context-aware output encoding\nfrom markupsafe import escape\nreturn f'<p>{escape(user_input)}</p>'",
            "Security Headers": "# Flask security headers\n@app.after_request\ndef set_headers(response):\n    response.headers['X-Content-Type-Options'] = 'nosniff'\n    response.headers['X-Frame-Options'] = 'DENY'\n    return response",
            "File Upload": "# Secure file upload\nfrom werkzeug.utils import secure_filename\nfilename = secure_filename(upload.filename)\nif not allowed_file(filename):\n    abort(400)",
            "Dependencies": "# Pin dependencies\n# requirements.txt\nrequests==2.31.0\ncryptography==41.0.0",
        }
        return examples.get(finding.category, finding.example_fix or "# Refer to OWASP cheat sheets for remediation guidance")

    def _default_references(self, finding: SecurityFinding) -> list[str]:
        """Add default references based on category."""
        refs = {
            "Secrets": ["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
            "Authentication": ["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"],
            "Authorization": ["https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"],
            "Injection": ["https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"],
            "XSS": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
            "Dependencies": ["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
        }
        return refs.get(finding.category, ["https://owasp.org/www-project-top-ten/"])
