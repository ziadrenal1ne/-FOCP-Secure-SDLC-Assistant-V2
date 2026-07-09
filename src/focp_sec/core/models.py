"""Core data models for security analysis results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OWASPCategory(str, Enum):
    """OWASP Top 10 2021 categories."""

    A01_BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021-Cryptographic Failures"
    A03_INJECTION = "A03:2021-Injection"
    A04_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021-Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021-Identification and Authentication Failures"
    A08_INTEGRITY_FAILURES = "A08:2021-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021-Server-Side Request Forgery"


@dataclass
class SecurityFinding:
    """A single security finding from analysis."""

    id: str
    title: str
    severity: Severity
    category: str
    owasp_category: OWASPCategory | None
    description: str
    risk: str
    recommendation: str
    example_fix: str
    references: list[str]
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None
    business_impact: str = ""
    analyzer: str = ""
    compliance_tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "owasp_category": self.owasp_category.value if self.owasp_category else None,
            "description": self.description,
            "risk": self.risk,
            "recommendation": self.recommendation,
            "example_fix": self.example_fix,
            "references": self.references,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "business_impact": self.business_impact,
            "analyzer": self.analyzer,
            "compliance_tags": self.compliance_tags,
            "metadata": self.metadata,
        }


@dataclass
class ProjectInfo:
    """Detected project information."""

    path: str
    name: str
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    dependencies: list[dict[str, str]] = field(default_factory=list)
    has_docker: bool = False
    has_git: bool = False
    config_files: list[str] = field(default_factory=list)
    file_count: int = 0
    total_lines: int = 0
    git_info: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert project info to dictionary."""
        return {
            "path": self.path,
            "name": self.name,
            "languages": self.languages,
            "frameworks": self.frameworks,
            "dependencies": self.dependencies,
            "has_docker": self.has_docker,
            "has_git": self.has_git,
            "config_files": self.config_files,
            "file_count": self.file_count,
            "total_lines": self.total_lines,
            "git_info": self.git_info,
        }


@dataclass
class SecurityScore:
    """Overall security score breakdown."""

    overall: float = 0.0
    authentication: float = 0.0
    authorization: float = 0.0
    configuration: float = 0.0
    dependencies: float = 0.0
    secrets: float = 0.0
    logging: float = 0.0
    encryption: float = 0.0
    grade: str = "F"

    def to_dict(self) -> dict[str, Any]:
        """Convert score to dictionary."""
        return {
            "overall": round(self.overall, 1),
            "authentication": round(self.authentication, 1),
            "authorization": round(self.authorization, 1),
            "configuration": round(self.configuration, 1),
            "dependencies": round(self.dependencies, 1),
            "secrets": round(self.secrets, 1),
            "logging": round(self.logging, 1),
            "encryption": round(self.encryption, 1),
            "grade": self.grade,
        }


@dataclass
class RiskItem:
    """Risk matrix item."""

    id: str
    title: str
    likelihood: int  # 1-5
    impact: int  # 1-5
    risk_score: int = 0
    category: str = ""
    mitigation: str = ""

    def __post_init__(self) -> None:
        self.risk_score = self.likelihood * self.impact

    def to_dict(self) -> dict[str, Any]:
        """Convert risk item to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "risk_score": self.risk_score,
            "category": self.category,
            "mitigation": self.mitigation,
        }


@dataclass
class ThreatModelEntry:
    """STRIDE threat model entry."""

    asset: str
    threat: str
    stride_category: str
    attack_surface: str
    likelihood: str
    impact: str
    mitigation: str

    def to_dict(self) -> dict[str, Any]:
        """Convert threat model entry to dictionary."""
        return {
            "asset": self.asset,
            "threat": self.threat,
            "stride_category": self.stride_category,
            "attack_surface": self.attack_surface,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "mitigation": self.mitigation,
        }


@dataclass
class RBACEntry:
    """RBAC matrix entry."""

    role: str
    resource: str
    permissions: list[str]
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert RBAC entry to dictionary."""
        return {
            "role": self.role,
            "resource": self.resource,
            "permissions": self.permissions,
            "description": self.description,
        }


@dataclass
class ChecklistItem:
    """Security checklist item."""

    id: str
    category: str
    item: str
    status: str  # pass, fail, warning, na
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert checklist item to dictionary."""
        return {
            "id": self.id,
            "category": self.category,
            "item": self.item,
            "status": self.status,
            "notes": self.notes,
        }


@dataclass
class ArchitectureSummary:
    """Architecture review summary."""

    project_tree: str = ""
    dependency_graph: str = ""
    summary: str = ""
    entry_points: list[str] = field(default_factory=list)
    data_stores: list[str] = field(default_factory=list)
    external_services: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert architecture summary to dictionary."""
        return {
            "project_tree": self.project_tree,
            "dependency_graph": self.dependency_graph,
            "summary": self.summary,
            "entry_points": self.entry_points,
            "data_stores": self.data_stores,
            "external_services": self.external_services,
        }


@dataclass
class ScanResult:
    """Complete scan result."""

    scan_id: str
    project: ProjectInfo
    findings: list[SecurityFinding] = field(default_factory=list)
    score: SecurityScore = field(default_factory=SecurityScore)
    risk_matrix: list[RiskItem] = field(default_factory=list)
    threat_model: list[ThreatModelEntry] = field(default_factory=list)
    rbac_matrix: list[RBACEntry] = field(default_factory=list)
    checklists: dict[str, list[ChecklistItem]] = field(default_factory=dict)
    architecture: ArchitectureSummary = field(default_factory=ArchitectureSummary)
    dependency_findings: list[SecurityFinding] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def all_findings(self) -> list[SecurityFinding]:
        """Return all findings including dependency findings."""
        return self.findings + self.dependency_findings

    def to_dict(self) -> dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "scan_id": self.scan_id,
            "project": self.project.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "dependency_findings": [f.to_dict() for f in self.dependency_findings],
            "score": self.score.to_dict(),
            "risk_matrix": [r.to_dict() for r in self.risk_matrix],
            "threat_model": [t.to_dict() for t in self.threat_model],
            "rbac_matrix": [r.to_dict() for r in self.rbac_matrix],
            "checklists": {
                k: [c.to_dict() for c in v] for k, v in self.checklists.items()
            },
            "architecture": self.architecture.to_dict(),
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
            "timestamp": self.timestamp.isoformat(),
            "summary": {
                "total_findings": len(self.all_findings),
                "critical": sum(1 for f in self.all_findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in self.all_findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in self.all_findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in self.all_findings if f.severity == Severity.LOW),
                "info": sum(1 for f in self.all_findings if f.severity == Severity.INFO),
            },
        }
