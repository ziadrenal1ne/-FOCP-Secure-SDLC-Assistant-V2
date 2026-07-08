"""Risk matrix generator."""

from __future__ import annotations

import uuid
from pathlib import Path

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.models import RiskItem, SecurityFinding, Severity
from focp_sec.core.scanner import ScannedFile

SEVERITY_LIKELIHOOD = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

SEVERITY_IMPACT = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class RiskMatrixGenerator(BaseAnalyzer):
    """Generates risk matrix from findings."""

    name = "risk_matrix"

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Risk matrix generator produces matrix items, not findings."""
        return []

    def generate(self, findings: list[SecurityFinding]) -> list[RiskItem]:
        """Generate risk matrix from security findings."""
        items: list[RiskItem] = []
        seen_titles: set[str] = set()

        for finding in findings:
            if finding.title in seen_titles:
                continue
            seen_titles.add(finding.title)

            likelihood = SEVERITY_LIKELIHOOD.get(finding.severity, 3)
            impact = SEVERITY_IMPACT.get(finding.severity, 3)

            if finding.category in ("Secrets", "Injection"):
                impact = min(5, impact + 1)
            if finding.category == "Authentication" and finding.severity in (Severity.CRITICAL, Severity.HIGH):
                likelihood = min(5, likelihood + 1)

            items.append(RiskItem(
                id=str(uuid.uuid4())[:8],
                title=finding.title,
                likelihood=likelihood,
                impact=impact,
                category=finding.category,
                mitigation=finding.recommendation[:200],
            ))

        items.sort(key=lambda x: -x.risk_score)
        return items[:50]

    @staticmethod
    def risk_level(score: int) -> str:
        """Convert risk score to level label."""
        if score >= 20:
            return "Critical"
        if score >= 12:
            return "High"
        if score >= 6:
            return "Medium"
        return "Low"
