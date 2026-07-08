"""Dashboard view widget."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from focp_sec.core.models import ScanResult
from focp_sec.gui.charts import CategoryBarChart, ScoreGauge, SeverityBarChart


class StatCard(QFrame):
    """Statistics card widget."""

    def __init__(self, title: str, value: str = "0", css_class: str = "", parent=None) -> None:
        super().__init__(parent)
        self.setProperty("class", "card")
        self.setStyleSheet("QFrame { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }")

        layout = QVBoxLayout(self)
        self.title_label = QLabel(title)
        self.title_label.setProperty("class", "cardTitle")
        self.title_label.setStyleSheet("color: #8b949e; font-size: 11px; text-transform: uppercase; font-weight: 600;")

        self.value_label = QLabel(value)
        self.value_label.setProperty("class", f"cardValue {css_class}")
        color = {"cardValueCritical": "#f85149", "cardValueHigh": "#ff7b72",
                 "cardValueMedium": "#d29922", "cardValueLow": "#3fb950",
                 "cardValueGood": "#3fb950"}.get(css_class, "#f0f6fc")
        self.value_label.setStyleSheet(f"font-size: 28px; font-weight: bold; color: {color};")

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)

    def set_value(self, value: str) -> None:
        """Update card value."""
        self.value_label.setText(value)


class DashboardView(QWidget):
    """Main dashboard displaying scan overview."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setSpacing(20)

        header = QHBoxLayout()
        title = QLabel("Dashboard")
        title.setObjectName("pageTitle")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #f0f6fc;")
        self.subtitle = QLabel("Select a project and run a scan to begin")
        self.subtitle.setObjectName("subtitle")
        self.subtitle.setStyleSheet("color: #8b949e;")

        header_col = QVBoxLayout()
        header_col.addWidget(title)
        header_col.addWidget(self.subtitle)
        header.addLayout(header_col)
        header.addStretch()
        layout.addLayout(header)

        cards = QGridLayout()
        cards.setSpacing(12)
        self.score_gauge = ScoreGauge()
        self.critical_card = StatCard("Critical", "0", "cardValueCritical")
        self.high_card = StatCard("High", "0", "cardValueHigh")
        self.medium_card = StatCard("Medium", "0", "cardValueMedium")
        self.low_card = StatCard("Low", "0", "cardValueLow")
        self.total_card = StatCard("Total Findings", "0")
        self.files_card = StatCard("Files Scanned", "0")

        cards.addWidget(self.score_gauge, 0, 0, 2, 1)
        cards.addWidget(self.critical_card, 0, 1)
        cards.addWidget(self.high_card, 0, 2)
        cards.addWidget(self.medium_card, 0, 3)
        cards.addWidget(self.low_card, 1, 1)
        cards.addWidget(self.total_card, 1, 2)
        cards.addWidget(self.files_card, 1, 3)
        layout.addLayout(cards)

        charts = QHBoxLayout()
        self.severity_chart = SeverityBarChart()
        self.severity_chart.setStyleSheet("background-color: #161b22; border: 1px solid #30363d; border-radius: 8px;")
        self.category_chart = CategoryBarChart()
        self.category_chart.setStyleSheet("background-color: #161b22; border: 1px solid #30363d; border-radius: 8px;")

        sev_container = QVBoxLayout()
        sev_title = QLabel("Findings by Severity")
        sev_title.setStyleSheet("font-weight: 600; color: #f0f6fc; font-size: 14px;")
        sev_container.addWidget(sev_title)
        sev_container.addWidget(self.severity_chart)

        cat_container = QVBoxLayout()
        cat_title = QLabel("Score by Category")
        cat_title.setStyleSheet("font-weight: 600; color: #f0f6fc; font-size: 14px;")
        cat_container.addWidget(cat_title)
        cat_container.addWidget(self.category_chart)

        charts.addLayout(sev_container)
        charts.addLayout(cat_container)
        layout.addLayout(charts)

        self.project_info = QLabel("")
        self.project_info.setWordWrap(True)
        self.project_info.setStyleSheet(
            "background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; color: #c9d1d9;"
        )
        layout.addWidget(self.project_info)
        layout.addStretch()

        scroll.setWidget(container)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(scroll)

    def update_scan(self, result: ScanResult) -> None:
        """Update dashboard with scan results."""
        summary = result.to_dict()["summary"]
        score = result.score

        self.subtitle.setText(f"Last scan: {result.project.name} — {result.scan_duration_seconds:.1f}s")
        self.score_gauge.set_score(score.overall, score.grade)
        self.critical_card.set_value(str(summary["critical"]))
        self.high_card.set_value(str(summary["high"]))
        self.medium_card.set_value(str(summary["medium"]))
        self.low_card.set_value(str(summary["low"]))
        self.total_card.set_value(str(summary["total_findings"]))
        self.files_card.set_value(str(result.project.file_count))

        self.severity_chart.set_data({
            "critical": summary["critical"],
            "high": summary["high"],
            "medium": summary["medium"],
            "low": summary["low"],
            "info": summary["info"],
        })

        self.category_chart.set_data({
            "AuthN": score.authentication,
            "AuthZ": score.authorization,
            "Config": score.configuration,
            "Deps": score.dependencies,
            "Secrets": score.secrets,
            "Logging": score.logging,
            "Crypto": score.encryption,
        })

        langs = ", ".join(result.project.languages[:5]) or "N/A"
        frameworks = ", ".join(result.project.frameworks[:5]) or "None"
        self.project_info.setText(
            f"<b>Project:</b> {result.project.name}<br>"
            f"<b>Path:</b> {result.project.path}<br>"
            f"<b>Languages:</b> {langs}<br>"
            f"<b>Frameworks:</b> {frameworks}<br>"
            f"<b>Lines of Code:</b> {result.project.total_lines:,}<br>"
            f"<b>Docker:</b> {'Yes' if result.project.has_docker else 'No'} | "
            f"<b>Git:</b> {'Yes' if result.project.has_git else 'No'}"
        )
