"""GUI application entry point."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from focp_sec.core.logging_setup import setup_logging
from focp_sec.gui.main_window import MainWindow


def main() -> None:
    """Launch the FOCP Secure SDLC Assistant GUI."""
    setup_logging()
    app = QApplication(sys.argv)
    app.setApplicationName("FOCP Secure SDLC Assistant")
    app.setOrganizationName("FOCP Security")

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
