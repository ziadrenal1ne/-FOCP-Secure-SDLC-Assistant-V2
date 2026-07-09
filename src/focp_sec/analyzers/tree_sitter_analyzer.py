"""Tree-sitter AST-based security analyzer."""

from __future__ import annotations

import logging
from pathlib import Path

try:
    import tree_sitter
    import tree_sitter_python
    import tree_sitter_javascript
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

from focp_sec.core.models import SecurityFinding, Severity

logger = logging.getLogger(__name__)


class TreeSitterAnalyzer:
    """Uses Tree-sitter to parse source code into AST and detect vulnerabilities."""

    name = "TreeSitterAnalyzer"

    def __init__(self) -> None:
        self.enabled = TREE_SITTER_AVAILABLE
        self.parsers = {}
        
        if self.enabled:
            try:
                # Initialize parsers
                self.parsers["python"] = tree_sitter.Language(tree_sitter_python.language())
                self.parsers["javascript"] = tree_sitter.Language(tree_sitter_javascript.language())
                # Setup more parsers here
            except Exception as e:
                logger.error("Failed to initialize Tree-sitter languages: %s", e)
                self.enabled = False

    def analyze(self, project_path: Path, files: list, project_info: dict) -> list[SecurityFinding]:
        findings = []
        if not self.enabled:
            logger.warning("Tree-sitter is not available, skipping AST analysis.")
            return findings

        for file_obj in files:
            if not file_obj.content:
                continue
            
            ext = file_obj.extension
            lang = None
            if ext in [".py"]:
                lang = "python"
            elif ext in [".js", ".jsx", ".ts", ".tsx"]:
                lang = "javascript"

            if not lang or lang not in self.parsers:
                continue

            try:
                parser = tree_sitter.Parser(self.parsers[lang])
                tree = parser.parse(file_obj.content.encode("utf-8"))
                root_node = tree.root_node
                
                # Perform deep AST queries here
                # Example: Find hardcoded assignments (this is simplified)
                findings.extend(self._analyze_node(root_node, file_obj.path, file_obj.content, lang))
                
            except Exception as e:
                logger.debug("TreeSitterAnalyzer failed on %s: %s", file_obj.path, e)

        return findings

    def _analyze_node(self, node: tree_sitter.Node, file_path: Path, content: str, lang: str) -> list[SecurityFinding]:
        """Recursively analyze AST nodes for specific patterns."""
        findings = []
        
        # In a real implementation, we would use tree-sitter Queries:
        # query = self.parsers[lang].query("(assignment_statement ... )")
        # captures = query.captures(node)
        
        # Simplified recursive walk (for demonstration)
        if node.type == "assignment" or node.type == "variable_declarator":
            text = node.text.decode('utf8', errors='replace').lower()
            if "password" in text and ("'" in text or '"' in text):
                line_number = node.start_point.row + 1
                findings.append(
                    SecurityFinding(
                        title="Hardcoded Password Detected (AST)",
                        description=f"Potential hardcoded credential found via AST in assignment: {text[:50]}",
                        severity=Severity.HIGH,
                        category="Secrets",
                        owasp_category=None,
                        risk="Hardcoded secrets can be easily extracted from source code.",
                        recommendation="Use environment variables or a secure secret manager (e.g., AWS Secrets Manager, HashiCorp Vault) instead of hardcoding credentials.",
                        example_fix="import os\npassword = os.environ.get('DB_PASSWORD')",
                        references=["https://cwe.mitre.org/data/definitions/798.html"],
                        file_path=str(file_path),
                        line_number=line_number,
                        code_snippet=text[:100],
                        analyzer=self.name,
                    )
                )

        for child in node.children:
            findings.extend(self._analyze_node(child, file_path, content, lang))
            
        return findings
