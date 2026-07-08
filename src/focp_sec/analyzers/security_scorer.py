"""Security score calculator."""

from __future__ import annotations

from pathlib import Path

from focp_sec.analyzers.base import BaseAnalyzer
from focp_sec.core.config import get_config
from focp_sec.core.models import SecurityFinding, SecurityScore, Severity
from focp_sec.core.scanner import ScannedFile

CATEGORY_MAP = {
    "Authentication": "authentication",
    "Authorization": "authorization",
    "Security Headers": "configuration",
    "File Upload": "configuration",
    "OWASP Top 10": "configuration",
    "Dependencies": "dependencies",
    "Secrets": "secrets",
    "Injection": "encryption",
    "XSS": "encryption",
    "SQL Injection": "encryption",
}

SEVERITY_PENALTY = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

GRADE_THRESHOLDS = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


class SecurityScorer(BaseAnalyzer):
    """Calculates overall security score."""

    name = "security_scorer"

    def analyze(
        self,
        project_path: Path,
        files: list[ScannedFile],
        project_info: dict,
    ) -> list[SecurityFinding]:
        """Scorer produces score, not findings."""
        return []

    def calculate(
        self,
        findings: list[SecurityFinding],
        dependency_findings: list[SecurityFinding] | None = None,
    ) -> SecurityScore:
        """Calculate security score from all findings."""
        weights = get_config().scoring_weights
        all_findings = findings + (dependency_findings or [])

        category_penalties: dict[str, float] = {k: 0.0 for k in weights}
        category_counts: dict[str, int] = {k: 0 for k in weights}

        for finding in all_findings:
            cat_key = CATEGORY_MAP.get(finding.category, "configuration")
            if cat_key not in category_penalties:
                cat_key = "configuration"
            penalty = SEVERITY_PENALTY.get(finding.severity, 0)
            category_penalties[cat_key] += penalty
            category_counts[cat_key] += 1

        score = SecurityScore()
        total_weight = sum(weights.values()) or 100
        weighted_sum = 0.0

        for cat, weight in weights.items():
            penalty = min(100, category_penalties.get(cat, 0))
            cat_score = max(0, 100 - penalty)
            setattr(score, cat, cat_score)
            weighted_sum += cat_score * weight

        score.overall = weighted_sum / total_weight
        score.grade = self._grade(score.overall)
        return score

    @staticmethod
    def _grade(overall: float) -> str:
        """Convert numeric score to letter grade."""
        for threshold, grade in GRADE_THRESHOLDS:
            if overall >= threshold:
                return grade
        return "F"
