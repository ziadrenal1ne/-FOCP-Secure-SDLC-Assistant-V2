"""Plugin Manager for dynamically loading third-party analyzers."""

from __future__ import annotations

import importlib.util
import logging
import os
import sys
from pathlib import Path
from typing import Any

from focp_sec.core.config import get_config

logger = logging.getLogger(__name__)


class PluginManager:
    """Discovers and loads external analyzer plugins."""

    def __init__(self) -> None:
        self.config = get_config()
        self.plugin_dir = Path(self.config.get("plugins.directory", "./plugins"))
        self.enabled = self.config.get("plugins.enabled", True)
        self.plugins: list[Any] = []

    def discover_and_load(self) -> list[Any]:
        """Discover and load all Python modules in the plugins directory."""
        if not self.enabled or not self.plugin_dir.exists():
            return []

        self.plugins = []
        for item in self.plugin_dir.glob("*.py"):
            if item.is_file() and not item.name.startswith("__"):
                plugin = self._load_module(item)
                if plugin:
                    self._extract_analyzers(plugin)
        
        logger.info("Loaded %d third-party analyzer plugins", len(self.plugins))
        return self.plugins

    def _load_module(self, path: Path) -> Any:
        """Dynamically load a Python module from a file path."""
        module_name = f"focp_sec.plugins.{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, str(path))
        if spec and spec.loader:
            try:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
                return module
            except Exception as e:
                logger.error("Failed to load plugin module %s: %s", path.name, e)
        return None

    def _extract_analyzers(self, module: Any) -> None:
        """Find analyzer classes in the module and instantiate them."""
        # Simple heuristic: any class ending in 'Analyzer' that has an 'analyze' method
        for name in dir(module):
            obj = getattr(module, name)
            if isinstance(obj, type) and name.endswith("Analyzer") and hasattr(obj, "analyze"):
                try:
                    analyzer_instance = obj()
                    self.plugins.append(analyzer_instance)
                    logger.debug("Registered external analyzer: %s", name)
                except Exception as e:
                    logger.error("Failed to instantiate analyzer %s: %s", name, e)
