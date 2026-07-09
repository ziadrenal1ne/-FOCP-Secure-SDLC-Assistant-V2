"""Scan orchestrator coordinating all analyzers."""

from __future__ import annotations

import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from focp_sec.analyzers.architecture_reviewer import ArchitectureReviewer
from focp_sec.analyzers.auth_reviewer import AuthReviewer
from focp_sec.analyzers.authz_reviewer import AuthzReviewer
from focp_sec.analyzers.checklist_generator import ChecklistGenerator
from focp_sec.analyzers.dependency_analyzer import DependencyAnalyzer
from focp_sec.analyzers.file_upload_analyzer import FileUploadAnalyzer
from focp_sec.analyzers.headers_analyzer import HeadersAnalyzer
from focp_sec.analyzers.owasp_analyzer import OWASPAnalyzer
from focp_sec.analyzers.project_detector import ProjectDetector
from focp_sec.analyzers.rbac_generator import RBACGenerator
from focp_sec.analyzers.recommendation_engine import RecommendationEngine
from focp_sec.analyzers.risk_matrix import RiskMatrixGenerator
from focp_sec.analyzers.secrets_scanner import SecretsScanner
from focp_sec.analyzers.security_scorer import SecurityScorer
from focp_sec.analyzers.sqli_analyzer import SQLInjectionAnalyzer
from focp_sec.analyzers.threat_modeler import ThreatModeler
from focp_sec.analyzers.xss_analyzer import XSSAnalyzer
from focp_sec.analyzers.tree_sitter_analyzer import TreeSitterAnalyzer
from focp_sec.core.config import AppConfig, get_config
from focp_sec.core.database import ScanDatabase
from focp_sec.core.models import ScanResult, SecurityFinding
from focp_sec.core.scanner import ProjectScanner
from focp_sec.core.plugin_manager import PluginManager
from focp_sec.core.custom_rules import CustomRuleAnalyzer

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Orchestrates complete security scan pipeline."""

    def __init__(self, config: AppConfig | None = None) -> None:
        self.config = config or get_config()
        
        # Base analyzers
        self.ANALYZERS = [
            SecretsScanner(),
            AuthReviewer(),
            AuthzReviewer(),
            OWASPAnalyzer(),
            SQLInjectionAnalyzer(),
            XSSAnalyzer(),
            FileUploadAnalyzer(),
            HeadersAnalyzer(),
            TreeSitterAnalyzer(),
            CustomRuleAnalyzer(),
        ]
        
        # Load third party plugins dynamically
        self.plugin_manager = PluginManager()
        self.ANALYZERS.extend(self.plugin_manager.discover_and_load())
        
        self.scanner = ProjectScanner(Path("."), self.config)
        self.project_detector = ProjectDetector()
        self.dependency_analyzer = DependencyAnalyzer()
        self.architecture_reviewer = ArchitectureReviewer()
        self.threat_modeler = ThreatModeler()
        self.risk_generator = RiskMatrixGenerator()
        self.rbac_generator = RBACGenerator()
        self.checklist_generator = ChecklistGenerator()
        self.security_scorer = SecurityScorer()
        self.recommendation_engine = RecommendationEngine()
        self.database = ScanDatabase(self.config.database_path)

    def scan(
        self,
        project_path: str | Path,
        progress_callback: Callable[[str, float], None] | None = None,
        save_to_db: bool = True,
    ) -> ScanResult:
        """Run complete security scan on project."""
        start_time = time.time()
        project_path = Path(project_path).resolve()

        if not project_path.exists():
            raise FileNotFoundError(f"Project path not found: {project_path}")
        if not project_path.is_dir():
            raise ValueError(f"Project path is not a directory: {project_path}")

        scan_id = str(uuid.uuid4())[:12]
        self._report_progress(progress_callback, "Discovering files...", 0.05)

        self.scanner = ProjectScanner(project_path, self.config)
        files = self.scanner.discover_files(read_content=True)

        self._report_progress(progress_callback, "Detecting project technologies...", 0.10)
        project = self.project_detector.detect(project_path, files)
        project_info = project.to_dict()

        self._report_progress(progress_callback, "Running security analyzers...", 0.15)
        findings = self._run_analyzers(project_path, files, project_info, progress_callback)

        self._report_progress(progress_callback, "Analyzing dependencies...", 0.70)
        dependency_findings = self.dependency_analyzer.analyze(project_path, files, project_info)

        self._report_progress(progress_callback, "Enhancing recommendations...", 0.80)
        all_findings = findings + dependency_findings
        enhanced_findings = self.recommendation_engine.enhance(findings)
        enhanced_dep = self.recommendation_engine.enhance(dependency_findings)

        self._report_progress(progress_callback, "Generating reports data...", 0.85)
        architecture = self.architecture_reviewer.review(project_path, files, project_info)
        threat_model = self.threat_modeler.generate(project_info, all_findings)
        risk_matrix = self.risk_generator.generate(all_findings)
        rbac_matrix = self.rbac_generator.generate(project_path, files)
        checklists = self.checklist_generator.generate(all_findings, project_info)
        score = self.security_scorer.calculate(enhanced_findings, enhanced_dep)

        duration = time.time() - start_time
        self._report_progress(progress_callback, "Scan complete!", 1.0)

        result = ScanResult(
            scan_id=scan_id,
            project=project,
            findings=enhanced_findings,
            dependency_findings=enhanced_dep,
            score=score,
            risk_matrix=risk_matrix,
            threat_model=threat_model,
            rbac_matrix=rbac_matrix,
            checklists=checklists,
            architecture=architecture,
            scan_duration_seconds=duration,
        )

        if save_to_db:
            self.database.save_scan(result)

        logger.info(
            "Scan %s completed in %.1fs: %d findings, score %.1f",
            scan_id, duration, len(result.all_findings), score.overall,
        )
        return result

    def _run_analyzers(
        self,
        project_path: Path,
        files: list,
        project_info: dict,
        progress_callback: Callable[[str, float], None] | None,
    ) -> list[SecurityFinding]:
        """Run all security analyzers in parallel."""
        findings: list[SecurityFinding] = []
        total = len(self.ANALYZERS)

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {
                executor.submit(analyzer.analyze, project_path, files, project_info): analyzer.name
                for analyzer in self.ANALYZERS
            }
            completed = 0
            for future in as_completed(futures):
                name = futures[future]
                try:
                    analyzer_findings = future.result()
                    findings.extend(analyzer_findings)
                    logger.info("%s: %d findings", name, len(analyzer_findings))
                except Exception as e:
                    logger.error("Analyzer %s failed: %s", name, e)
                completed += 1
                progress = 0.15 + (0.55 * completed / total)
                self._report_progress(progress_callback, f"Running {name}...", progress)

        return findings

    @staticmethod
    def _report_progress(
        callback: Callable[[str, float], None] | None,
        message: str,
        progress: float,
    ) -> None:
        """Report scan progress."""
        if callback:
            callback(message, progress)
        logger.debug("%s (%.0f%%)", message, progress * 100)
