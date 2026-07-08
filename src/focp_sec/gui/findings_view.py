"""Findings list and detail view."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from focp_sec.core.models import ScanResult, SecurityFinding
from focp_sec.gui.styles import SEVERITY_COLORS


class FindingsView(QWidget):
    """Displays security findings in a table with detail panel."""

    finding_selected = Signal(object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.findings: list[SecurityFinding] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        title = QLabel("Security Findings")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #f0f6fc;")
        layout.addWidget(title)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Severity", "Title", "Category", "File"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        splitter.addWidget(self.table)

        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        detail_title = QLabel("Finding Details")
        detail_title.setStyleSheet("font-weight: 600; color: #f0f6fc; font-size: 14px;")
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setStyleSheet("background-color: #161b22; border: 1px solid #30363d; border-radius: 8px;")
        detail_layout.addWidget(detail_title)
        detail_layout.addWidget(self.detail_text)
        splitter.addWidget(detail)

        splitter.setSizes([600, 400])
        layout.addWidget(splitter)

    def update_findings(self, result: ScanResult) -> None:
        """Populate findings table."""
        self.findings = result.all_findings
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(self.findings, key=lambda f: severity_order.get(f.severity.value, 5))

        self.table.setRowCount(len(sorted_findings))
        for row, finding in enumerate(sorted_findings):
            sev_item = QTableWidgetItem(finding.severity.value.upper())
            color = SEVERITY_COLORS.get(finding.severity.value, "#c9d1d9")
            sev_item.setForeground(QColor(color))
            sev_item.setData(Qt.ItemDataRole.UserRole, row)

            self.table.setItem(row, 0, sev_item)
            self.table.setItem(row, 1, QTableWidgetItem(finding.title[:80]))
            self.table.setItem(row, 2, QTableWidgetItem(finding.category))
            loc = finding.file_path or "N/A"
            if finding.line_number:
                loc += f":{finding.line_number}"
            self.table.setItem(row, 3, QTableWidgetItem(loc[:50]))

        self.table.resizeColumnsToContents()

    def _on_selection_changed(self) -> None:
        """Show finding details on selection."""
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        if row >= len(self.findings):
            return

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(self.findings, key=lambda f: severity_order.get(f.severity.value, 5))
        finding = sorted_findings[row]

        html = f"""
        <h2 style="color: {SEVERITY_COLORS.get(finding.severity.value, '#c9d1d9')}">
            [{finding.severity.value.upper()}] {finding.title}
        </h2>
        <p><b>Category:</b> {finding.category}</p>
        {'<p><b>OWASP:</b> ' + finding.owasp_category.value + '</p>' if finding.owasp_category else ''}
        {'<p><b>Location:</b> ' + finding.file_path + (':' + str(finding.line_number) if finding.line_number else '') + '</p>' if finding.file_path else ''}
        <hr>
        <p><b>Description:</b><br>{finding.description}</p>
        <p><b>Risk:</b><br>{finding.risk}</p>
        <p><b>Business Impact:</b><br>{finding.business_impact}</p>
        <p><b>Recommendation:</b><br>{finding.recommendation}</p>
        {'<pre style="background:#0d1117;padding:8px;border-radius:4px;">' + finding.example_fix + '</pre>' if finding.example_fix else ''}
        {'<pre style="background:#0d1117;padding:8px;border-radius:4px;">' + finding.code_snippet + '</pre>' if finding.code_snippet else ''}
        <p><b>References:</b><br>{'<br>'.join(f'<a href="{r}">{r}</a>' for r in finding.references)}</p>
        """
        self.detail_text.setHtml(html)
        self.finding_selected.emit(finding)


class RiskMatrixView(QWidget):
    """Risk matrix table view."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        title = QLabel("Risk Matrix")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #f0f6fc;")
        layout.addWidget(title)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Title", "Category", "Likelihood", "Impact", "Score", "Level"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)

    def update_data(self, result: ScanResult) -> None:
        """Populate risk matrix."""
        items = result.risk_matrix
        self.table.setRowCount(len(items))
        for row, item in enumerate(items):
            level = "Critical" if item.risk_score >= 20 else "High" if item.risk_score >= 12 else "Medium" if item.risk_score >= 6 else "Low"
            color = {"Critical": "#f85149", "High": "#ff7b72", "Medium": "#d29922", "Low": "#3fb950"}[level]

            self.table.setItem(row, 0, QTableWidgetItem(item.title[:60]))
            self.table.setItem(row, 1, QTableWidgetItem(item.category))
            self.table.setItem(row, 2, QTableWidgetItem(f"{item.likelihood}/5"))
            self.table.setItem(row, 3, QTableWidgetItem(f"{item.impact}/5"))
            score_item = QTableWidgetItem(str(item.risk_score))
            score_item.setForeground(QColor(color))
            self.table.setItem(row, 4, score_item)
            level_item = QTableWidgetItem(level)
            level_item.setForeground(QColor(color))
            self.table.setItem(row, 5, level_item)

        self.table.resizeColumnsToContents()
