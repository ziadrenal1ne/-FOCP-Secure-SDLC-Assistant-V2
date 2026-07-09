"""Application configuration management."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATHS = [
    Path("config.yaml"),
    Path.home() / ".focp-sec" / "config.yaml",
]


class AppConfig:
    """Application configuration loaded from YAML."""

    def __init__(self, config_path: Path | None = None) -> None:
        self._config: dict[str, Any] = {}
        self._path = config_path or self._find_config()
        self.load()

    def _find_config(self) -> Path | None:
        """Find first available config file."""
        for path in DEFAULT_CONFIG_PATHS:
            if path.exists():
                return path
        return DEFAULT_CONFIG_PATHS[0]

    def load(self) -> None:
        """Load configuration from YAML file."""
        if self._path and self._path.exists():
            with open(self._path, encoding="utf-8") as f:
                self._config = yaml.safe_load(f) or {}
            logger.info("Loaded configuration from %s", self._path)
        else:
            self._config = self._default_config()
            logger.warning("Using default configuration")

    def _default_config(self) -> dict[str, Any]:
        """Return default configuration."""
        return {
            "app": {"name": "FOCP Secure SDLC Assistant", "version": "1.0.0", "log_level": "INFO", "max_workers": 4},
            "scan": {
                "exclude_dirs": ["node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"],
                "exclude_extensions": [".pyc", ".jpg", ".png", ".gif", ".zip", ".tar", ".gz"],
                "max_file_size_mb": 5,
                "secrets_entropy_threshold": 4.5,
                "incremental": False,
            },
            "tools": {
                "bandit": {"enabled": True, "severity": "low", "confidence": "low"},
                "semgrep": {"enabled": True, "config": "auto"},
                "trivy": {"enabled": True, "severity": "LOW,MEDIUM,HIGH,CRITICAL"},
            },
            "plugins": {
                "directory": "./plugins",
                "enabled": True,
            },
            "custom_rules": {
                "path": "./rules.yaml",
                "enabled": True,
            },
            "compliance": {
                "frameworks": ["PCI-DSS", "HIPAA", "SOC2", "OWASP"],
            },
            "scoring": {
                "weights": {
                    "authentication": 15,
                    "authorization": 15,
                    "configuration": 10,
                    "dependencies": 20,
                    "secrets": 20,
                    "logging": 5,
                    "encryption": 15,
                }
            },
            "report": {"output_dir": "./reports", "formats": ["html", "markdown", "pdf", "json", "sarif"], "company_name": "FOCP Security"},
            "database": {"path": "~/.focp-sec/scans.db"},
            "gui": {"theme": "dark", "window_width": 1400, "window_height": 900},
            "realtime": {"host": "127.0.0.1", "port": 8080, "watch_delay": 2.0},
        }

    def get(self, key: str, default: Any = None) -> Any:
        """Get nested config value using dot notation."""
        keys = key.split(".")
        value: Any = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        return value if value is not None else default

    @property
    def app_name(self) -> str:
        return str(self.get("app.name", "FOCP Secure SDLC Assistant"))

    @property
    def app_version(self) -> str:
        return str(self.get("app.version", "1.0.0"))

    @property
    def log_level(self) -> str:
        return str(self.get("app.log_level", "INFO"))

    @property
    def max_workers(self) -> int:
        return int(self.get("app.max_workers", 4))

    @property
    def exclude_dirs(self) -> set[str]:
        return set(self.get("scan.exclude_dirs", []))

    @property
    def exclude_extensions(self) -> set[str]:
        return set(self.get("scan.exclude_extensions", []))

    @property
    def max_file_size_mb(self) -> int:
        return int(self.get("scan.max_file_size_mb", 5))

    @property
    def secrets_entropy_threshold(self) -> float:
        return float(self.get("scan.secrets_entropy_threshold", 4.5))

    @property
    def bandit_enabled(self) -> bool:
        return bool(self.get("tools.bandit.enabled", True))

    @property
    def semgrep_enabled(self) -> bool:
        return bool(self.get("tools.semgrep.enabled", True))

    @property
    def trivy_enabled(self) -> bool:
        return bool(self.get("tools.trivy.enabled", True))

    @property
    def scoring_weights(self) -> dict[str, int]:
        return dict(self.get("scoring.weights", {}))

    @property
    def report_output_dir(self) -> Path:
        return Path(self.get("report.output_dir", "./reports"))

    @property
    def report_formats(self) -> list[str]:
        return list(self.get("report.formats", ["html", "markdown", "pdf", "json"]))

    @property
    def company_name(self) -> str:
        return str(self.get("report.company_name", "FOCP Security"))

    @property
    def database_path(self) -> Path:
        path = Path(os.path.expanduser(str(self.get("database.path", "~/.focp-sec/scans.db"))))
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def gui_theme(self) -> str:
        return str(self.get("gui.theme", "dark"))

    @property
    def gui_width(self) -> int:
        return int(self.get("gui.window_width", 1400))

    @property
    def gui_height(self) -> int:
        return int(self.get("gui.window_height", 900))


_config_instance: AppConfig | None = None


def get_config(config_path: Path | None = None) -> AppConfig:
    """Get or create singleton config instance."""
    global _config_instance
    if _config_instance is None or config_path is not None:
        _config_instance = AppConfig(config_path)
    return _config_instance
