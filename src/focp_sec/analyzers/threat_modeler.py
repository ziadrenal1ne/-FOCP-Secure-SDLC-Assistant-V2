"""STRIDE threat modeling generator."""

from __future__ import annotations

from pathlib import Path

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.models import SecurityFinding, ThreatModelEntry
from focp_sec.core.scanner import ScannedFile


class ThreatModeler(BaseAnalyzer):
    """Generates STRIDE-based threat model."""

    name = "threat_modeler"

    STRIDE_TEMPLATES: list[dict] = [
        {"asset": "User Credentials", "threat": "Credential theft via phishing or breach", "stride": "Spoofing", "surface": "Login API", "likelihood": "High", "impact": "Critical", "mitigation": "MFA, rate limiting, secure password storage"},
        {"asset": "Session Tokens", "threat": "Session hijacking or fixation", "stride": "Spoofing", "surface": "Web Application", "likelihood": "Medium", "impact": "High", "mitigation": "Secure cookies, token rotation, HTTPS only"},
        {"asset": "User Data", "threat": "Unauthorized data modification", "stride": "Tampering", "surface": "API Endpoints", "likelihood": "Medium", "impact": "High", "mitigation": "Input validation, authorization checks, audit logging"},
        {"asset": "Application Logs", "threat": "Log tampering to hide attacks", "stride": "Tampering", "surface": "Logging System", "likelihood": "Low", "impact": "Medium", "mitigation": "Centralized logging, log integrity verification"},
        {"asset": "Transaction Records", "threat": "Transaction repudiation", "stride": "Repudiation", "surface": "Business Logic", "likelihood": "Medium", "impact": "Medium", "mitigation": "Digital signatures, audit trails, non-repudiation controls"},
        {"asset": "Sensitive Data (PII)", "threat": "Data exposure via insufficient access controls", "stride": "Information Disclosure", "surface": "Database/API", "likelihood": "High", "impact": "Critical", "mitigation": "Encryption at rest, RBAC, data minimization"},
        {"asset": "Error Messages", "threat": "Information leakage via verbose errors", "stride": "Information Disclosure", "surface": "Error Handlers", "likelihood": "Medium", "impact": "Low", "mitigation": "Generic error messages in production"},
        {"asset": "Application Services", "threat": "Denial of service via resource exhaustion", "stride": "Denial of Service", "surface": "Public Endpoints", "likelihood": "High", "impact": "High", "mitigation": "Rate limiting, WAF, auto-scaling, input size limits"},
        {"asset": "Admin Functions", "threat": "Privilege escalation to admin", "stride": "Elevation of Privilege", "surface": "Admin Panel", "likelihood": "Medium", "impact": "Critical", "mitigation": "Strong RBAC, MFA for admin, principle of least privilege"},
        {"asset": "File Upload", "threat": "Remote code execution via malicious upload", "stride": "Elevation of Privilege", "surface": "Upload Endpoint", "likelihood": "Medium", "impact": "Critical", "mitigation": "File type validation, sandbox storage, antivirus scanning"},
        {"asset": "Internal Services", "threat": "SSRF to access internal resources", "stride": "Information Disclosure", "surface": "URL Fetching", "likelihood": "Medium", "impact": "High", "mitigation": "URL validation, network segmentation, block metadata endpoints"},
        {"asset": "Dependencies", "threat": "Supply chain attack via compromised package", "stride": "Tampering", "surface": "Build Pipeline", "likelihood": "Medium", "impact": "Critical", "mitigation": "Dependency pinning, SBOM, vulnerability scanning"},
    ]

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Threat modeler generates model, not direct findings."""
        return []

    def generate(
        self,
        project_info: dict,
        findings: list,
    ) -> list[ThreatModelEntry]:
        """Generate threat model based on project profile and findings."""
        entries: list[ThreatModelEntry] = []
        categories_found = {f.category for f in findings} if findings else set()

        for tmpl in self.STRIDE_TEMPLATES:
            likelihood = tmpl["likelihood"]
            if tmpl["surface"] == "Upload Endpoint" and "File Upload" in categories_found:
                likelihood = "High"
            if tmpl["surface"] == "Database/API" and any(c in categories_found for c in ("Injection", "Secrets", "Authorization")):
                likelihood = "High"

            entries.append(ThreatModelEntry(
                asset=tmpl["asset"],
                threat=tmpl["threat"],
                stride_category=tmpl["stride"],
                attack_surface=tmpl["surface"],
                likelihood=likelihood,
                impact=tmpl["impact"],
                mitigation=tmpl["mitigation"],
            ))

        if project_info.get("has_docker"):
            entries.append(ThreatModelEntry(
                asset="Container Runtime",
                threat="Container escape or misconfiguration",
                stride_category="Elevation of Privilege",
                attack_surface="Docker/Kubernetes",
                likelihood="Low",
                impact="Critical",
                mitigation="Run as non-root, read-only filesystem, seccomp profiles, image scanning",
            ))

        return entries
