"""Dark theme styles for the GUI."""

DARK_THEME = """
QMainWindow, QWidget {
    background-color: #0d1117;
    color: #c9d1d9;
    font-family: 'Segoe UI', 'SF Pro Display', sans-serif;
    font-size: 13px;
}

QMenuBar {
    background-color: #161b22;
    color: #c9d1d9;
    border-bottom: 1px solid #30363d;
    padding: 4px;
}

QMenuBar::item:selected {
    background-color: #21262d;
}

QMenu {
    background-color: #161b22;
    color: #c9d1d9;
    border: 1px solid #30363d;
}

QMenu::item:selected {
    background-color: #388bfd;
}

#sidebar {
    background-color: #161b22;
    border-right: 1px solid #30363d;
    min-width: 220px;
    max-width: 220px;
}

#sidebarTitle {
    font-size: 16px;
    font-weight: bold;
    color: #58a6ff;
    padding: 16px;
}

.sidebarButton {
    background-color: transparent;
    color: #c9d1d9;
    border: none;
    border-radius: 6px;
    padding: 12px 16px;
    text-align: left;
    font-size: 13px;
}

.sidebarButton:hover {
    background-color: #21262d;
}

.sidebarButton:checked {
    background-color: #388bfd;
    color: white;
}

#contentArea {
    background-color: #0d1117;
}

.card {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px;
}

.cardTitle {
    font-size: 12px;
    color: #8b949e;
    text-transform: uppercase;
    font-weight: 600;
}

.cardValue {
    font-size: 28px;
    font-weight: bold;
    color: #f0f6fc;
}

.cardValueCritical { color: #f85149; }
.cardValueHigh { color: #ff7b72; }
.cardValueMedium { color: #d29922; }
.cardValueLow { color: #3fb950; }
.cardValueGood { color: #3fb950; }

QPushButton {
    background-color: #238636;
    color: white;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #2ea043;
}

QPushButton:pressed {
    background-color: #196c2e;
}

QPushButton#secondaryButton {
    background-color: #21262d;
    border: 1px solid #30363d;
    color: #c9d1d9;
}

QPushButton#secondaryButton:hover {
    background-color: #30363d;
}

QPushButton#dangerButton {
    background-color: #da3633;
}

QPushButton#dangerButton:hover {
    background-color: #f85149;
}

QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px;
    color: #c9d1d9;
}

QLineEdit:focus {
    border-color: #58a6ff;
}

QTableWidget {
    background-color: #0d1117;
    alternate-background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    gridline-color: #30363d;
    selection-background-color: #388bfd;
}

QTableWidget::item {
    padding: 8px;
}

QHeaderView::section {
    background-color: #161b22;
    color: #8b949e;
    border: none;
    border-bottom: 1px solid #30363d;
    padding: 8px;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 11px;
}

QScrollBar:vertical {
    background-color: #0d1117;
    width: 10px;
}

QScrollBar::handle:vertical {
    background-color: #30363d;
    border-radius: 5px;
    min-height: 30px;
}

QScrollBar::handle:vertical:hover {
    background-color: #484f58;
}

QProgressBar {
    background-color: #21262d;
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
}

QProgressBar::chunk {
    background-color: #388bfd;
    border-radius: 4px;
}

QTabWidget::pane {
    border: 1px solid #30363d;
    border-radius: 8px;
    background-color: #0d1117;
}

QTabBar::tab {
    background-color: #161b22;
    color: #8b949e;
    padding: 8px 16px;
    border: 1px solid #30363d;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
}

QTabBar::tab:selected {
    background-color: #0d1117;
    color: #c9d1d9;
    border-bottom: 2px solid #388bfd;
}

QGroupBox {
    border: 1px solid #30363d;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 16px;
    font-weight: 600;
}

QGroupBox::title {
    subcontrol-origin: margin;
    padding: 0 8px;
    color: #8b949e;
}

QStatusBar {
    background-color: #161b22;
    color: #8b949e;
    border-top: 1px solid #30363d;
}

QLabel#pageTitle {
    font-size: 24px;
    font-weight: bold;
    color: #f0f6fc;
    padding: 8px 0;
}

QLabel#subtitle {
    color: #8b949e;
    font-size: 14px;
}
"""

SEVERITY_COLORS = {
    "critical": "#f85149",
    "high": "#ff7b72",
    "medium": "#d29922",
    "low": "#3fb950",
    "info": "#58a6ff",
}
