"""Custom rules parser and analyzer for YAML defined rules."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml

from focp_sec.core.config import get_config
from focp_sec.core.models import SecurityFinding, Severity

logger = logging.getLogger(__name__)


class CustomRuleAnalyzer:
    """Loads and applies custom regex-based security rules from YAML."""
    
    name = "CustomRuleAnalyzer"

    def __init__(self) -> None:
        self.config = get_config()
        self.rules_path = Path(self.config.get("custom_rules.path", "./rules.yaml"))
        self.enabled = self.config.get("custom_rules.enabled", True)
        self.rules: list[dict[str, Any]] = []
        self._load_rules()

    def _load_rules(self) -> None:
        """Load rules from the YAML file."""
        if not self.enabled or not self.rules_path.exists():
            return

        try:
            with open(self.rules_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and isinstance(data, dict) and "rules" in data:
                    self.rules = data["rules"]
                    # Pre-compile regexes
                    for rule in self.rules:
                        if "pattern" in rule:
                            rule["_regex"] = re.compile(rule["pattern"], re.MULTILINE)
            logger.info("Loaded %d custom rules from %s", len(self.rules), self.rules_path)
        except Exception as e:
            logger.error("Failed to load custom rules from %s: %s", self.rules_path, e)

    def analyze(self, project_path: Path, files: list[Path], project_info: dict) -> list[SecurityFinding]:
        """Apply custom rules to all files."""
        findings = []
        if not self.rules:
            return findings

        for file_path in files:
            # Only analyze text-like files based on a simple extension check or try-except
            try:
                content = file_path.read_text(encoding="utf-8")
                
                for rule in self.rules:
                    # Optional: filter by file extension if specified in rule
                    if "extensions" in rule and file_path.suffix not in rule["extensions"]:
                        continue

                    if "_regex" in rule:
                        for match in rule["_regex"].finditer(content):
                            line_number = content[:match.start()].count("\n") + 1
                            severity_str = rule.get("severity", "medium").lower()
                            try:
                                severity = Severity(severity_str)
                            except ValueError:
                                severity = Severity.MEDIUM

                            findings.append(
                                SecurityFinding(
                                    title=rule.get("name", "Custom Rule Violation"),
                                    description=rule.get("description", f"Matched custom pattern: {rule['pattern']}"),
                                    severity=severity,
                                    category=rule.get("category", "Custom"),
                                    file_path=str(file_path),
                                    line_number=line_number,
                                    recommendation=rule.get("recommendation", "Review the matching code and apply best practices."),
                                    cwe_id=rule.get("cwe", None)
                                )
                            )
            except UnicodeDecodeError:
                pass # Skip binary files
            except Exception as e:
                logger.debug("CustomRuleAnalyzer error reading %s: %s", file_path, e)
                
        return findings
