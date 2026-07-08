"""Chart widgets for the dashboard."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QWidget

from focp_sec.gui.styles import SEVERITY_COLORS


class ScoreGauge(QWidget):
    """Circular score gauge widget."""

    def __init__(self, score: float = 0, grade: str = "F", parent=None) -> None:
        super().__init__(parent)
        self.score = score
        self.grade = grade
        self.setMinimumSize(180, 180)

    def set_score(self, score: float, grade: str) -> None:
        """Update score display."""
        self.score = score
        self.grade = grade
        self.update()

    def paintEvent(self, event) -> None:
        """Draw the gauge."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        size = min(w, h) - 20
        x = (w - size) / 2
        y = (h - size) / 2

        painter.setPen(QPen(QColor("#30363d"), 8))
        painter.drawArc(int(x), int(y), int(size), int(size), 0, 360 * 16)

        color = QColor("#3fb950") if self.score >= 80 else QColor("#d29922") if self.score >= 60 else QColor("#f85149")
        painter.setPen(QPen(color, 8))
        span = int((self.score / 100) * 360 * 16)
        painter.drawArc(int(x), int(y), int(size), int(size), 90 * 16, -span)

        painter.setPen(QColor("#f0f6fc"))
        font = QFont("Segoe UI", 28, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, f"{self.score:.0f}")

        font.setPointSize(14)
        painter.setFont(font)
        painter.setPen(color)
        rect = self.rect()
        painter.drawText(rect.adjusted(0, 50, 0, 0), Qt.AlignmentFlag.AlignCenter, f"Grade {self.grade}")


class SeverityBarChart(QWidget):
    """Horizontal bar chart for severity distribution."""

    def __init__(self, data: dict[str, int] | None = None, parent=None) -> None:
        super().__init__(parent)
        self.data = data or {}
        self.setMinimumHeight(200)

    def set_data(self, data: dict[str, int]) -> None:
        """Update chart data."""
        self.data = data
        self.update()

    def paintEvent(self, event) -> None:
        """Draw bar chart."""
        if not self.data:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        max_val = max(self.data.values()) if self.data.values() else 1
        bar_height = 30
        spacing = 10
        label_width = 80
        margin = 20
        chart_width = self.width() - label_width - margin * 2 - 50

        y = margin
        for severity, count in self.data.items():
            color = QColor(SEVERITY_COLORS.get(severity, "#8b949e"))
            bar_width = int((count / max_val) * chart_width) if max_val > 0 else 0

            painter.setPen(QColor("#8b949e"))
            font = QFont("Segoe UI", 11)
            painter.setFont(font)
            painter.drawText(margin, y + bar_height - 8, label_width, bar_height,
                             Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                             severity.capitalize())

            painter.fillRect(label_width + margin + 5, y, bar_width, bar_height, color)

            painter.setPen(QColor("#c9d1d9"))
            painter.drawText(label_width + margin + bar_width + 10, y + bar_height - 8,
                             40, bar_height, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                             str(count))

            y += bar_height + spacing


class CategoryBarChart(QWidget):
    """Vertical bar chart for category scores."""

    def __init__(self, data: dict[str, float] | None = None, parent=None) -> None:
        super().__init__(parent)
        self.data = data or {}
        self.setMinimumHeight(250)

    def set_data(self, data: dict[str, float]) -> None:
        """Update chart data."""
        self.data = data
        self.update()

    def paintEvent(self, event) -> None:
        """Draw category score bars."""
        if not self.data:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        categories = list(self.data.keys())
        n = len(categories)
        if n == 0:
            return

        margin = 30
        bottom_margin = 60
        chart_height = self.height() - margin - bottom_margin
        bar_width = max(20, (self.width() - margin * 2) // n - 10)
        spacing = ((self.width() - margin * 2) - bar_width * n) // max(n - 1, 1)

        for i, (cat, score) in enumerate(self.data.items()):
            x = margin + i * (bar_width + spacing)
            bar_h = int((score / 100) * chart_height)
            y = margin + chart_height - bar_h

            color = QColor("#3fb950") if score >= 80 else QColor("#d29922") if score >= 60 else QColor("#f85149")
            painter.fillRect(x, y, bar_width, bar_h, color)

            painter.setPen(QColor("#c9d1d9"))
            font = QFont("Segoe UI", 9)
            painter.setFont(font)
            painter.drawText(x - 10, margin + chart_height + 5, bar_width + 20, 40,
                             Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignTop,
                             cat[:10])

            painter.drawText(x, y - 18, bar_width, 16,
                             Qt.AlignmentFlag.AlignCenter, f"{score:.0f}")
