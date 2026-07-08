"""Main application window."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QButtonGroup,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from focp_sec.core.config import get_config
from focp_sec.core.models import ScanResult
from focp_sec.core.orchestrator import ScanOrchestrator
from focp_sec.gui.dashboard import DashboardView
from focp_sec.gui.findings_view import FindingsView, RiskMatrixView
from focp_sec.gui.styles import DARK_THEME
from focp_sec.reports.generator import ReportGenerator

logger = logging.getLogger(__name__)


class ScanWorker(QThread):
    """Background thread for running scans."""

    progress = Signal(str, float)
    finished_scan = Signal(object)
    error = Signal(str)

    def __init__(self, project_path: Path) -> None:
        super().__init__()
        self.project_path = project_path

    def run(self) -> None:
        """Execute scan in background."""
        try:
            orchestrator = ScanOrchestrator()
            result = orchestrator.scan(
                self.project_path,
                progress_callback=lambda msg, pct: self.progress.emit(msg, pct),
            )
            self.finished_scan.emit(result)
        except Exception as e:
            logger.exception("Scan failed")
            self.error.emit(str(e))


class MainWindow(QMainWindow):
    """Main application window with sidebar navigation."""

    def __init__(self) -> None:
        super().__init__()
        self.config = get_config()
        self.current_result: ScanResult | None = None
        self.project_path: Path | None = None
        self.scan_worker: ScanWorker | None = None

        self.setWindowTitle(f"{self.config.app_name} v{self.config.app_version}")
        self.setMinimumSize(1200, 800)
        self.resize(self.config.gui_width, self.config.gui_height)
        self.setStyleSheet(DARK_THEME)

        self._setup_menu()
        self._setup_ui()
        self._setup_statusbar()

    def _setup_menu(self) -> None:
        """Create menu bar."""
        menubar = self.menuBar()

        file_menu = menubar.addMenu("&File")
        open_action = QAction("&Open Project...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self._select_project)
        file_menu.addAction(open_action)

        export_action = QAction("&Export Report...", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self._export_report)
        file_menu.addAction(export_action)

        file_menu.addSeparator()
        quit_action = QAction("&Quit", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        scan_menu = menubar.addMenu("&Scan")
        scan_action = QAction("&Run Scan", self)
        scan_action.setShortcut("F5")
        scan_action.triggered.connect(self._run_scan)
        scan_menu.addAction(scan_action)

        help_menu = menubar.addMenu("&Help")
        about_action = QAction("&About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _setup_ui(self) -> None:
        """Setup main UI layout."""
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(8, 8, 8, 8)
        sidebar_layout.setSpacing(4)

        title = QLabel("FOCP Secure\nSDLC Assistant")
        title.setObjectName("sidebarTitle")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #58a6ff; padding: 16px;")
        sidebar_layout.addWidget(title)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        nav_items = [
            ("dashboard", "Dashboard"),
            ("findings", "Findings"),
            ("risk", "Risk Matrix"),
            ("threats", "Threat Model"),
            ("rbac", "RBAC Matrix"),
            ("checklist", "Checklists"),
            ("architecture", "Architecture"),
        ]

        self.nav_buttons: dict[str, QPushButton] = {}
        for key, label in nav_items:
            btn = QPushButton(label)
            btn.setProperty("class", "sidebarButton")
            btn.setCheckable(True)
            btn.setStyleSheet("""
                QPushButton { background: transparent; color: #c9d1d9; border: none; border-radius: 6px; padding: 12px 16px; text-align: left; }
                QPushButton:hover { background-color: #21262d; }
                QPushButton:checked { background-color: #388bfd; color: white; }
            """)
            btn.clicked.connect(lambda checked, k=key: self._navigate(k))
            self.nav_group.addButton(btn)
            self.nav_buttons[key] = btn
            sidebar_layout.addWidget(btn)

        sidebar_layout.addStretch()

        self.scan_btn = QPushButton("Scan Project")
        self.scan_btn.clicked.connect(self._run_scan)
        sidebar_layout.addWidget(self.scan_btn)

        self.export_btn = QPushButton("Export Report")
        self.export_btn.setObjectName("secondaryButton")
        self.export_btn.setStyleSheet("background-color: #21262d; border: 1px solid #30363d; color: #c9d1d9; border-radius: 6px; padding: 8px 16px;")
        self.export_btn.clicked.connect(self._export_report)
        self.export_btn.setEnabled(False)
        sidebar_layout.addWidget(self.export_btn)

        self.project_label = QLabel("No project selected")
        self.project_label.setWordWrap(True)
        self.project_label.setStyleSheet("color: #8b949e; font-size: 11px; padding: 8px;")
        sidebar_layout.addWidget(self.project_label)

        main_layout.addWidget(sidebar)

        content = QWidget()
        content.setObjectName("contentArea")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(20, 20, 20, 20)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet("color: #8b949e;")
        self.progress_label.setVisible(False)
        content_layout.addWidget(self.progress_label)
        content_layout.addWidget(self.progress_bar)

        self.stack = QStackedWidget()
        self.dashboard = DashboardView()
        self.findings_view = FindingsView()
        self.risk_view = RiskMatrixView()
        self.threat_view = self._create_table_view("Threat Model (STRIDE)", ["Asset", "Threat", "STRIDE", "Surface", "Likelihood", "Impact", "Mitigation"])
        self.rbac_view = self._create_table_view("RBAC Matrix", ["Role", "Resource", "Permissions", "Description"])
        self.checklist_view = self._create_table_view("Security Checklists", ["Category", "Item", "Status", "Notes"])
        self.architecture_view = self._create_text_view("Architecture")

        self.stack.addWidget(self.dashboard)
        self.stack.addWidget(self.findings_view)
        self.stack.addWidget(self.risk_view)
        self.stack.addWidget(self.threat_view)
        self.stack.addWidget(self.rbac_view)
        self.stack.addWidget(self.checklist_view)
        self.stack.addWidget(self.architecture_view)

        content_layout.addWidget(self.stack)
        main_layout.addWidget(content, 1)

        self.nav_buttons["dashboard"].setChecked(True)

    def _create_table_view(self, title: str, columns: list[str]) -> QWidget:
        """Create a generic table view page."""
        from PySide6.QtWidgets import QTableWidget

        widget = QWidget()
        layout = QVBoxLayout(widget)
        label = QLabel(title)
        label.setStyleSheet("font-size: 24px; font-weight: bold; color: #f0f6fc;")
        layout.addWidget(label)

        table = QTableWidget()
        table.setColumnCount(len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.horizontalHeader().setStretchLastSection(True)
        table.setAlternatingRowColors(True)
        layout.addWidget(table)
        widget.table = table  # type: ignore
        return widget

    def _create_text_view(self, title: str) -> QWidget:
        """Create a text view page."""
        from PySide6.QtWidgets import QTextEdit

        widget = QWidget()
        layout = QVBoxLayout(widget)
        label = QLabel(title)
        label.setStyleSheet("font-size: 24px; font-weight: bold; color: #f0f6fc;")
        layout.addWidget(label)

        text = QTextEdit()
        text.setReadOnly(True)
        text.setStyleSheet("background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; font-family: monospace;")
        layout.addWidget(text)
        widget.text = text  # type: ignore
        return widget

    def _setup_statusbar(self) -> None:
        """Setup status bar."""
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage("Ready — Select a project to begin")

    def _navigate(self, page: str) -> None:
        """Navigate to page."""
        pages = {"dashboard": 0, "findings": 1, "risk": 2, "threats": 3, "rbac": 4, "checklist": 5, "architecture": 6}
        self.stack.setCurrentIndex(pages.get(page, 0))

    def _select_project(self) -> None:
        """Open project folder dialog."""
        path = QFileDialog.getExistingDirectory(self, "Select Project Directory")
        if path:
            self.project_path = Path(path)
            self.project_label.setText(str(self.project_path))
            self.statusbar.showMessage(f"Project: {self.project_path.name}")
            self._run_scan()

    def _run_scan(self) -> None:
        """Start security scan."""
        if not self.project_path:
            self._select_project()
            if not self.project_path:
                return

        if self.scan_worker and self.scan_worker.isRunning():
            QMessageBox.warning(self, "Scan in Progress", "A scan is already running.")
            return

        self.scan_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_label.setVisible(True)
        self.progress_bar.setValue(0)
        self.statusbar.showMessage("Scanning...")

        self.scan_worker = ScanWorker(self.project_path)
        self.scan_worker.progress.connect(self._on_scan_progress)
        self.scan_worker.finished_scan.connect(self._on_scan_complete)
        self.scan_worker.error.connect(self._on_scan_error)
        self.scan_worker.start()

    def _on_scan_progress(self, message: str, pct: float) -> None:
        """Update scan progress."""
        self.progress_label.setText(message)
        self.progress_bar.setValue(int(pct * 100))
        self.statusbar.showMessage(message)

    def _on_scan_complete(self, result: ScanResult) -> None:
        """Handle scan completion."""
        self.current_result = result
        self.scan_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)

        self.dashboard.update_scan(result)
        self.findings_view.update_findings(result)
        self.risk_view.update_data(result)
        self._update_threat_view(result)
        self._update_rbac_view(result)
        self._update_checklist_view(result)
        self._update_architecture_view(result)

        summary = result.to_dict()["summary"]
        self.statusbar.showMessage(
            f"Scan complete — Score: {result.score.overall:.1f}/100 | "
            f"{summary['total_findings']} findings | ID: {result.scan_id}"
        )
        self.stack.setCurrentIndex(0)
        self.nav_buttons["dashboard"].setChecked(True)

    def _on_scan_error(self, error: str) -> None:
        """Handle scan error."""
        self.scan_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        self.statusbar.showMessage("Scan failed")
        QMessageBox.critical(self, "Scan Error", f"Scan failed:\n{error}")

    def _update_threat_view(self, result: ScanResult) -> None:
        """Update threat model table."""
        from PySide6.QtWidgets import QTableWidgetItem

        table = self.threat_view.table
        entries = result.threat_model
        table.setRowCount(len(entries))
        for row, tm in enumerate(entries):
            table.setItem(row, 0, QTableWidgetItem(tm.asset))
            table.setItem(row, 1, QTableWidgetItem(tm.threat))
            table.setItem(row, 2, QTableWidgetItem(tm.stride_category))
            table.setItem(row, 3, QTableWidgetItem(tm.attack_surface))
            table.setItem(row, 4, QTableWidgetItem(tm.likelihood))
            table.setItem(row, 5, QTableWidgetItem(tm.impact))
            table.setItem(row, 6, QTableWidgetItem(tm.mitigation[:80]))

    def _update_rbac_view(self, result: ScanResult) -> None:
        """Update RBAC table."""
        from PySide6.QtWidgets import QTableWidgetItem
        table = self.rbac_view.table
        entries = result.rbac_matrix
        table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            table.setItem(row, 0, QTableWidgetItem(entry.role))
            table.setItem(row, 1, QTableWidgetItem(entry.resource))
            table.setItem(row, 2, QTableWidgetItem(", ".join(entry.permissions)))
            table.setItem(row, 3, QTableWidgetItem(entry.description))

    def _update_checklist_view(self, result: ScanResult) -> None:
        """Update checklist table."""
        from PySide6.QtGui import QColor
        from PySide6.QtWidgets import QTableWidgetItem

        table = self.checklist_view.table
        all_items = []
        for cl_type, items in result.checklists.items():
            for item in items:
                all_items.append((cl_type, item))

        table.setRowCount(len(all_items))
        status_colors = {"pass": "#3fb950", "fail": "#f85149", "warning": "#d29922", "na": "#8b949e"}
        for row, (cl_type, item) in enumerate(all_items):
            table.setItem(row, 0, QTableWidgetItem(f"[{cl_type}] {item.category}"))
            table.setItem(row, 1, QTableWidgetItem(item.item))
            status_item = QTableWidgetItem(item.status.upper())
            status_item.setForeground(QColor(status_colors.get(item.status, "#c9d1d9")))
            table.setItem(row, 2, status_item)
            table.setItem(row, 3, QTableWidgetItem(item.notes))

    def _update_architecture_view(self, result: ScanResult) -> None:
        """Update architecture view."""
        arch = result.architecture
        text = (
            f"{arch.summary}\n\n"
            f"{'=' * 60}\n"
            f"ENTRY POINTS\n{'=' * 60}\n"
            f"{chr(10).join(arch.entry_points) or 'None detected'}\n\n"
            f"{'=' * 60}\n"
            f"DATA STORES\n{'=' * 60}\n"
            f"{chr(10).join(arch.data_stores) or 'None detected'}\n\n"
            f"{'=' * 60}\n"
            f"EXTERNAL SERVICES\n{'=' * 60}\n"
            f"{chr(10).join(arch.external_services) or 'None detected'}\n\n"
            f"{'=' * 60}\n"
            f"PROJECT TREE\n{'=' * 60}\n"
            f"{arch.project_tree}\n\n"
            f"{'=' * 60}\n"
            f"DEPENDENCY GRAPH\n{'=' * 60}\n"
            f"{arch.dependency_graph}"
        )
        self.architecture_view.text.setPlainText(text)

    def _export_report(self) -> None:
        """Export scan report."""
        if not self.current_result:
            QMessageBox.warning(self, "No Scan", "Run a scan first before exporting.")
            return

        output_dir = QFileDialog.getExistingDirectory(self, "Select Report Output Directory")
        if not output_dir:
            return

        try:
            generator = ReportGenerator(Path(output_dir))
            paths = generator.generate_all(self.current_result)
            msg = "Reports generated:\n" + "\n".join(f"  {fmt}: {path}" for fmt, path in paths.items())
            QMessageBox.information(self, "Export Complete", msg)
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to generate reports:\n{e}")

    def _show_about(self) -> None:
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About FOCP Secure SDLC Assistant",
            f"<h3>FOCP Secure SDLC Assistant</h3>"
            f"<p>Version {self.config.app_version}</p>"
            f"<p>Professional security analysis tool for software projects.</p>"
            f"<p>Analyzes projects against OWASP Top 10, detects secrets, "
            f"vulnerabilities, and generates comprehensive security reports.</p>"
            f"<p><b>Note:</b> This tool analyzes and recommends only. "
            f"It never modifies project files.</p>",
        )
