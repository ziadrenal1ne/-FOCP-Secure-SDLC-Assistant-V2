"""Unit tests for FOCP Secure SDLC Assistant."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from focp_sec.analyzers.auth_reviewer import AuthReviewer
from focp_sec.analyzers.authz_reviewer import AuthzReviewer
from focp_sec.analyzers.checklist_generator import ChecklistGenerator
from focp_sec.analyzers.project_detector import ProjectDetector
from focp_sec.analyzers.recommendation_engine import RecommendationEngine
from focp_sec.analyzers.risk_matrix import RiskMatrixGenerator
from focp_sec.analyzers.secrets_scanner import SecretsScanner
from focp_sec.analyzers.security_scorer import SecurityScorer
from focp_sec.analyzers.sqli_analyzer import SQLInjectionAnalyzer
from focp_sec.analyzers.xss_analyzer import XSSAnalyzer
from focp_sec.core.config import AppConfig, get_config
from focp_sec.core.models import SecurityFinding, Severity
from focp_sec.core.scanner import ProjectScanner
from focp_sec.reports.generator import ReportGenerator

SAMPLE_PROJECT = Path(__file__).parent / "sample_project"


@pytest.fixture
def config() -> AppConfig:
    return AppConfig()


@pytest.fixture
def sample_files(config):
    scanner = ProjectScanner(SAMPLE_PROJECT, config)
    return scanner.discover_files(read_content=True)


@pytest.fixture
def project_info(sample_files):
    detector = ProjectDetector()
    return detector.detect(SAMPLE_PROJECT, sample_files).to_dict()


class TestConfig:
    def test_default_config(self, config):
        assert config.app_name == "FOCP Secure SDLC Assistant"
        assert config.max_workers >= 1
        assert "node_modules" in config.exclude_dirs

    def test_singleton(self):
        c1 = get_config()
        c2 = get_config()
        assert c1 is c2


class TestProjectScanner:
    def test_discover_files(self, sample_files):
        assert len(sample_files) > 0
        py_files = [f for f in sample_files if f.extension == ".py"]
        assert len(py_files) >= 1

    def test_detect_languages(self, sample_files, config):
        scanner = ProjectScanner(SAMPLE_PROJECT, config)
        langs = scanner.detect_languages(sample_files)
        assert "Python" in langs


class TestProjectDetector:
    def test_detect_frameworks(self, sample_files):
        detector = ProjectDetector()
        info = detector.detect(SAMPLE_PROJECT, sample_files)
        assert info.name == "sample_project"
        assert "Python" in info.languages
        assert info.file_count > 0


class TestSecretsScanner:
    def test_detect_hardcoded_secrets(self, sample_files, project_info):
        scanner = SecretsScanner()
        findings = scanner.analyze(SAMPLE_PROJECT, sample_files, project_info)
        assert len(findings) > 0
        titles = [f.title for f in findings]
        assert any("password" in t.lower() or "secret" in t.lower() or "api" in t.lower() for t in titles)

    def test_shannon_entropy(self):
        scanner = SecretsScanner()
        assert scanner._shannon_entropy("aaaa") < 1.0
        assert scanner._shannon_entropy("aB3$xZ9!mK2@pL5") > 3.0


class TestSQLInjectionAnalyzer:
    def test_detect_sqli(self, sample_files, project_info):
        analyzer = SQLInjectionAnalyzer()
        findings = analyzer.analyze(SAMPLE_PROJECT, sample_files, project_info)
        assert len(findings) > 0
        assert any("SQL" in f.title for f in findings)


class TestXSSAnalyzer:
    def test_detect_xss(self, sample_files, project_info):
        analyzer = XSSAnalyzer()
        findings = analyzer.analyze(SAMPLE_PROJECT, sample_files, project_info)
        assert len(findings) > 0


class TestAuthReviewer:
    def test_detect_weak_hash(self, sample_files, project_info):
        reviewer = AuthReviewer()
        findings = reviewer.analyze(SAMPLE_PROJECT, sample_files, project_info)
        assert any("hash" in f.title.lower() or "MD5" in f.title for f in findings)


class TestAuthzReviewer:
    def test_detect_admin_endpoint(self, sample_files, project_info):
        reviewer = AuthzReviewer()
        findings = reviewer.analyze(SAMPLE_PROJECT, sample_files, project_info)
        assert any("admin" in f.title.lower() for f in findings)


class TestSecurityScorer:
    def test_calculate_score(self):
        scorer = SecurityScorer()
        findings = [
            SecurityFinding(
                id="1", title="Test", severity=Severity.HIGH, category="Secrets",
                owasp_category=None, description="", risk="", recommendation="",
                example_fix="", references=[],
            )
        ]
        score = scorer.calculate(findings)
        assert 0 <= score.overall <= 100
        assert score.grade in ("A", "B", "C", "D", "F")

    def test_perfect_score(self):
        scorer = SecurityScorer()
        score = scorer.calculate([])
        assert score.overall == 100.0
        assert score.grade == "A"


class TestRiskMatrix:
    def test_generate_matrix(self):
        gen = RiskMatrixGenerator()
        findings = [
            SecurityFinding(
                id="1", title="Critical Issue", severity=Severity.CRITICAL,
                category="Secrets", owasp_category=None, description="", risk="",
                recommendation="Fix it", example_fix="", references=[],
            )
        ]
        matrix = gen.generate(findings)
        assert len(matrix) == 1
        assert matrix[0].risk_score >= 20


class TestChecklistGenerator:
    def test_generate_checklists(self, sample_files, project_info):
        secrets = SecretsScanner()
        findings = secrets.analyze(SAMPLE_PROJECT, sample_files, project_info)
        gen = ChecklistGenerator()
        checklists = gen.generate(findings, project_info)
        assert "owasp" in checklists
        assert "sdlc" in checklists
        assert len(checklists["owasp"]) > 0


class TestRecommendationEngine:
    def test_enhance_findings(self):
        engine = RecommendationEngine()
        findings = [
            SecurityFinding(
                id="1", title="Test Secret", severity=Severity.HIGH,
                category="Secrets", owasp_category=None,
                description="A secret was found", risk="Exposure",
                recommendation="Remove it", example_fix="", references=[],
            )
        ]
        enhanced = engine.enhance(findings)
        assert enhanced[0].business_impact
        assert enhanced[0].example_fix


class TestReportGenerator:
    def test_generate_json_report(self, sample_files, project_info, tmp_path):
        from focp_sec.core.orchestrator import ScanOrchestrator

        orchestrator = ScanOrchestrator()
        result = orchestrator.scan(SAMPLE_PROJECT, save_to_db=False)

        generator = ReportGenerator(tmp_path)
        paths = generator.generate_all(result)

        assert "json" in paths
        assert paths["json"].exists()
        data = json.loads(paths["json"].read_text())
        assert "scan_id" in data
        assert "findings" in data

    def test_generate_html_report(self, sample_files, project_info, tmp_path):
        from focp_sec.core.orchestrator import ScanOrchestrator

        result = ScanOrchestrator().scan(SAMPLE_PROJECT, save_to_db=False)
        generator = ReportGenerator(tmp_path)
        paths = generator.generate_all(result)

        if "html" in paths:
            html = paths["html"].read_text()
            assert "Security Assessment Report" in html
            assert result.project.name in html


class TestOrchestrator:
    def test_full_scan(self):
        from focp_sec.core.orchestrator import ScanOrchestrator

        orchestrator = ScanOrchestrator()
        result = orchestrator.scan(SAMPLE_PROJECT, save_to_db=False)

        assert result.scan_id
        assert result.project.name == "sample_project"
        assert len(result.all_findings) > 0
        assert result.score.overall < 100
        assert len(result.threat_model) > 0
        assert len(result.rbac_matrix) > 0
        assert "owasp" in result.checklists

    def test_scan_nonexistent_path(self):
        from focp_sec.core.orchestrator import ScanOrchestrator

        with pytest.raises(FileNotFoundError):
            ScanOrchestrator().scan("/nonexistent/path/12345")
