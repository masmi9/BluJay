#!/usr/bin/env python3
"""
MITRE Integrity Checker - Single Source of Truth Validation
===========================================================

Validates that all MITRE ATT&CK mappings come from the centralized
configuration file and detects any hardcoded mapping duplicates.

Features:
- Startup validation of MITRE mapping sources
- Detection of hardcoded mapping tables
- Single source of truth enforcement
- Configuration integrity monitoring

Author: AODS Architecture Team
Version: 1.0.0
"""

import os
import ast
from typing import List, Dict, Any
from pathlib import Path

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


class MITREIntegrityChecker:
    """
    Validates MITRE mapping integrity and single source of truth compliance.
    """

    def __init__(self, project_root: str = None):
        self.logger = logger

        if not project_root:
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

        self.project_root = Path(project_root)
        self.violations = []

        # Allow-list for plugin/local configs that are intentionally separate and not MITRE SSoT
        self.duplicate_config_allowlist = set(
            [str((self.project_root / "plugins" / "attack_surface_analysis" / "attack_patterns_config.yaml").resolve())]
        )

        # Patterns that indicate hardcoded MITRE mappings
        self.suspicious_patterns = [
            "cwe_mitre_mappings",
            "mitre_techniques",
            "pattern_mitre_mappings",
            "threat_actors",
            "threat_campaigns",
        ]

        # MITRE technique patterns
        self.mitre_technique_patterns = [
            r"T\d{4}",  # T1575, T1406, etc.
            "TA0027",
            "TA0028",
            "TA0029",
            "TA0030",
            "TA0031",  # Tactic IDs
        ]

        self.logger.info("MITREIntegrityChecker initialized")

    def check_project_integrity(self) -> Dict[str, Any]:
        """
        Perform full MITRE mapping integrity check.

        Returns:
            Dictionary with integrity check results
        """
        self.logger.info("Starting MITRE mapping integrity check")

        results = {
            "status": "PASS",
            "violations": [],
            "warnings": [],
            "files_checked": 0,
            "suspicious_files": [],
            "recommendations": [],
        }

        try:
            # Check Python files for hardcoded mappings
            python_files = self._find_python_files()
            results["files_checked"] = len(python_files)

            for file_path in python_files:
                violations = self._check_file_for_violations(file_path)
                if violations:
                    results["violations"].extend(violations)
                    results["suspicious_files"].append(str(file_path))

            # Check for configuration file existence
            config_file = self.project_root / "config" / "mitre_attack_mappings.yaml"
            if not config_file.exists():
                results["violations"].append(
                    {
                        "type": "missing_config",
                        "file": str(config_file),
                        "message": "Primary MITRE configuration file not found",
                    }
                )

            # Check for duplicate configuration files
            duplicate_configs = self._find_duplicate_configs()
            if duplicate_configs:
                results["warnings"].extend(
                    [
                        {
                            "type": "duplicate_config",
                            "file": str(config),
                            "message": "Potential duplicate MITRE configuration file",
                        }
                        for config in duplicate_configs
                    ]
                )

            # Determine overall status
            if results["violations"]:
                results["status"] = "FAIL"
                results["recommendations"].append("Remove hardcoded MITRE mappings and use centralized configuration")
            elif results["warnings"]:
                results["status"] = "WARN"
                results["recommendations"].append("Review potential duplicate configuration files")

            # Log results
            self._log_results(results)

            return results

        except Exception as e:
            self.logger.error(f"Integrity check failed: {e}")
            results["status"] = "ERROR"
            results["violations"].append({"type": "check_error", "message": str(e)})
            return results

    def _find_python_files(self) -> List[Path]:
        """Find all Python files in the project."""
        python_files = []

        # Core directories to check
        check_dirs = ["core", "plugins", "roadmap"]

        for check_dir in check_dirs:
            dir_path = self.project_root / check_dir
            if dir_path.exists():
                python_files.extend(dir_path.rglob("*.py"))

        # Also check root level Python files
        python_files.extend(self.project_root.glob("*.py"))

        return python_files

    def _check_file_for_violations(self, file_path: Path) -> List[Dict[str, Any]]:
        """Check a single file for MITRE mapping violations."""
        violations = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Skip if file is the config loader itself
            if "mitre_config_loader.py" in str(file_path):
                return violations

            # Skip if file is the configuration checker
            if "mitre_integrity_checker.py" in str(file_path):
                return violations

            # Parse AST to find dictionary definitions
            try:
                tree = ast.parse(content)
                violations.extend(self._check_ast_for_mappings(tree, file_path))
            except SyntaxError:
                # Skip files with syntax errors
                pass

            # Check for hardcoded MITRE technique IDs
            violations.extend(self._check_hardcoded_techniques(content, file_path))

        except Exception as e:
            self.logger.debug(f"Error checking file {file_path}: {e}")

        return violations

    def _check_ast_for_mappings(self, tree: ast.AST, file_path: Path) -> List[Dict[str, Any]]:
        """Check AST for hardcoded MITRE mapping dictionaries."""
        violations = []

        class MappingVisitor(ast.NodeVisitor):
            def __init__(self, checker):
                self.checker = checker
                self.violations = []

            def visit_Assign(self, node):
                # Check for suspicious variable assignments
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        if var_name in self.checker.suspicious_patterns:
                            # Check if it's a dictionary with MITRE-like content
                            if isinstance(node.value, ast.Dict):
                                if self._looks_like_mitre_mapping(node.value):
                                    self.violations.append(
                                        {
                                            "type": "hardcoded_mapping",
                                            "file": str(file_path),
                                            "line": node.lineno,
                                            "variable": var_name,
                                            "message": f"Hardcoded MITRE mapping detected: {var_name}",
                                        }
                                    )

                self.generic_visit(node)

            def _looks_like_mitre_mapping(self, dict_node):
                """Check if dictionary looks like MITRE mapping."""
                if not dict_node.keys:
                    return False

                # Check for CWE keys or MITRE technique IDs
                for key in dict_node.keys:
                    if isinstance(key, ast.Constant):
                        key_str = str(key.value)
                        if key_str.startswith("CWE-") or key_str.startswith("T"):
                            return True

                return False

        visitor = MappingVisitor(self)
        visitor.visit(tree)
        violations.extend(visitor.violations)

        return violations

    def _check_hardcoded_techniques(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Check for hardcoded MITRE technique IDs in string literals."""
        violations = []

        # Skip test files, configuration files, and malware_detection (legitimate MITRE technique references)
        if any(skip in str(file_path).lower() for skip in ["test_", "_test", "config", "mitre_attack_mappings", "malware_detection"]):
            return violations

        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            # Skip comments and imports
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("from ") or stripped.startswith("import "):
                continue

            # Look for patterns that suggest hardcoded technique mappings
            if any(pattern in line for pattern in ["T1575", "T1406", "T1533", "T1411"]):
                # Check if it's in a dictionary or list context (suspicious)
                if any(char in line for char in ["{", "[", ":", "="]):
                    # Skip if it's clearly a comment or documentation
                    if not any(marker in line for marker in ["#", '"""', "'''"]):
                        violations.append(
                            {
                                "type": "hardcoded_technique",
                                "file": str(file_path),
                                "line": line_num,
                                "content": line.strip(),
                                "message": "Potential hardcoded MITRE technique ID",
                            }
                        )

        return violations

    def _find_duplicate_configs(self) -> List[Path]:
        """Find potential duplicate MITRE configuration files."""
        duplicates = []

        # Look for YAML/JSON files with MITRE-related names
        patterns = ["*mitre*.yaml", "*mitre*.yml", "*mitre*.json", "*attack*.yaml", "*attack*.yml"]

        for pattern in patterns:
            for file_path in self.project_root.rglob(pattern):
                # Skip the primary config file
                if file_path.name == "mitre_attack_mappings.yaml":
                    continue
                # Skip allow-listed configs
                try:
                    if str(file_path.resolve()) in self.duplicate_config_allowlist:
                        continue
                except Exception:
                    pass
                duplicates.append(file_path)

        return duplicates

    def _log_results(self, results: Dict[str, Any]) -> None:
        """Log integrity check results."""
        status = results["status"]

        if status == "PASS":
            self.logger.info("MITRE mapping integrity check PASSED", files_checked=results["files_checked"])

        elif status == "WARN":
            self.logger.warning(
                "MITRE mapping integrity check completed with WARNINGS",
                files_checked=results["files_checked"],
                warning_count=len(results["warnings"]),
            )

            for warning in results["warnings"]:
                self.logger.warning("MITRE integrity warning", message=warning["message"], file=warning["file"])

        elif status == "FAIL":
            self.logger.error(
                "MITRE mapping integrity check FAILED",
                files_checked=results["files_checked"],
                violation_count=len(results["violations"]),
            )

            for violation in results["violations"]:
                self.logger.error(
                    "MITRE integrity violation", message=violation["message"], file=violation.get("file", "unknown")
                )

            self.logger.error("ACTION REQUIRED: Remove hardcoded MITRE mappings")

        # Log recommendations
        for recommendation in results["recommendations"]:
            self.logger.info("Recommendation", recommendation=recommendation)


def check_mitre_integrity(project_root: str = None) -> Dict[str, Any]:
    """Convenience function to perform MITRE integrity check."""
    checker = MITREIntegrityChecker(project_root)
    return checker.check_project_integrity()


def startup_mitre_validation() -> bool:
    """Perform startup MITRE validation and return success status."""
    try:
        logger.info("Performing startup MITRE integrity validation")

        results = check_mitre_integrity()

        if results["status"] == "FAIL":
            logger.error("STARTUP VALIDATION FAILED - MITRE mapping violations detected")
            logger.error("System may have inconsistent threat intelligence data")
            return False

        elif results["status"] == "WARN":
            logger.warning("STARTUP VALIDATION completed with warnings")
            logger.warning("Review MITRE configuration for potential issues")

        else:
            logger.info("STARTUP VALIDATION PASSED - MITRE integrity confirmed")

        return True

    except Exception as e:
        logger.error("Startup MITRE validation failed", error=str(e))
        return False


# Integration with AODS startup
if __name__ == "__main__":
    logger.info("Testing MITRE Integrity Checker")

    results = check_mitre_integrity()

    logger.info(
        "Integrity check results",
        status=results["status"],
        files_checked=results["files_checked"],
        violations=len(results["violations"]),
        warnings=len(results["warnings"]),
    )

    if results["violations"]:
        for violation in results["violations"]:
            logger.error("Violation", message=violation["message"])

    if results["warnings"]:
        for warning in results["warnings"]:
            logger.warning("Warning", message=warning["message"])

    logger.info("MITRE Integrity Checker test completed")
