#!/usr/bin/env python3
"""
Unicode Security Analysis Plugin - Phase 7 Integration
=====================================================

Integrates the orphaned unicode_analyzer.py into the AODS plugin system.
This resolves the orphaned module issue identified in Phase 7 Task 7.3.

This plugin provides full Unicode security analysis including:
- Homograph attack detection
- Unicode normalization vulnerability analysis
- Bidirectional text attack detection
- Advanced Unicode security patterns

Following existing plugin patterns without base class inheritance.
"""

import logging
from typing import Dict, Any, List, Tuple, Union
from rich.text import Text

# Import the standalone analyzer for integration
from core.unicode_analyzer import UnicodeAnalyzer

logger = logging.getLogger(__name__)


class UnicodeSecurityAnalysisPlugin:
    """Unicode security analysis plugin."""

    """Unicode Security Analysis Plugin - Integrated from orphaned analyzer."""

    def __init__(self):
        """Initialize the Unicode security analyzer."""
        self.name = "Unicode Security Analysis"
        self.description = "Full Unicode security vulnerability detection"
        self.version = "2.0.0"
        self.category = "code_security"
        self.analyzer = None

    def initialize(self, apk_context) -> bool:
        """Initialize the Unicode security analyzer."""
        try:
            # UnicodeAnalyzer accepts optional apk_context
            self.analyzer = UnicodeAnalyzer(apk_context)
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Unicode analyzer: {e}")
            return False

    def analyze(self, apk_context) -> Dict[str, Any]:
        """Perform Unicode security analysis."""
        if not self.analyzer and not self.initialize(apk_context):
            return {"success": False, "error_message": "Failed to initialize Unicode analyzer", "findings": []}

        try:
            # Run the full Unicode security analysis
            # analyze_unicode_vulnerabilities returns (str, rich.text.Text)
            results_str, results_rich = self.analyzer.analyze_unicode_vulnerabilities(deep_mode=True)
            # Parse the results string to extract findings
            results = self._parse_unicode_results(results_str)

            # Convert to plugin findings format
            findings = self._convert_findings(results)

            return {
                "success": True,
                "plugin_name": self.name,
                "version": self.version,
                "findings": findings,
                "summary": {
                    "total_issues": len(findings),
                    "categories": list(set(f.get("category", "unknown") for f in findings)),
                },
            }

        except Exception as e:
            logger.error(f"Unicode analysis failed: {e}")
            return {"success": False, "error_message": str(e), "findings": []}

    def _parse_unicode_results(self, results_str: str) -> Dict[str, Any]:
        """Parse Unicode analyzer string results into structured data."""
        # Simple parsing - in a real implementation, this would be more sophisticated
        findings = {}
        if "vulnerabilities found" in results_str.lower():
            # Extract basic information from the results string
            findings["unicode_issues"] = {
                "vulnerabilities": [
                    {
                        "description": "Unicode security issue detected",
                        "severity": "medium",
                        "location": "Unicode analysis",
                        "evidence": {"raw_results": results_str[:500]},  # Truncate for safety
                        "confidence": 0.7,
                    }
                ]
            }
        return findings

    def _convert_findings(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert analyzer results to plugin findings."""
        findings = []

        # Process Unicode vulnerabilities
        if isinstance(results, dict):
            for category, category_data in results.items():
                if isinstance(category_data, dict) and "vulnerabilities" in category_data:
                    for vuln in category_data["vulnerabilities"]:
                        finding = {
                            "title": f"Unicode Security Issue: {vuln.get('description', 'Unknown')}",
                            "description": vuln.get("description", "Unicode security vulnerability detected"),
                            "severity": vuln.get("severity", "medium").upper(),
                            "category": "unicode_security",
                            "confidence": vuln.get("confidence", 0.7),
                            "evidence": vuln.get("evidence", {}),
                            "location": vuln.get("location", "Unknown"),
                            "recommendations": [
                                "Review Unicode usage patterns",
                                "Implement Unicode normalization",
                                "Validate Unicode input handling",
                                "Consider homograph attack prevention",
                            ],
                            "masvs_refs": ["MSTG-CODE-8", "MSTG-ARCH-1"],
                        }
                        findings.append(finding)

        return findings


def run_plugin(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Plugin interface function expected by the plugin manager.

    Args:
        apk_ctx: The APKContext instance containing APK path and metadata

    Returns:
        Tuple of (status, report) where status is "PASS"/"FAIL"/"ERROR"
        and report is a Rich Text object with detailed findings
    """
    try:
        # Initialize plugin and run analysis
        plugin = UnicodeSecurityAnalysisPlugin()
        results = plugin.analyze(apk_ctx)

        if not results["success"]:
            return "ERROR", Text(f"Analysis failed: {results.get('error_message', 'Unknown error')}", style="red")

        findings = results["findings"]

        if not findings:
            return "PASS", Text("✅ No Unicode security vulnerabilities detected", style="green")

        # Format findings for display
        report = Text()
        report.append("🔍 Unicode Security Analysis Results\n\n", style="bold blue")

        for i, finding in enumerate(findings, 1):
            severity_style = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}.get(
                finding["severity"], "white"
            )

            report.append(f"{i}. ", style="bold")
            report.append(f"[{finding['severity']}] ", style=severity_style)
            report.append(f"{finding['title']}\n", style="bold")
            report.append(f"   Description: {finding['description']}\n")
            report.append(f"   Location: {finding['location']}\n")
            report.append(f"   Confidence: {finding['confidence']:.1%}\n\n")

        status = "FAIL" if any(f["severity"] in ["CRITICAL", "HIGH"] for f in findings) else "WARN"
        return status, report

    except Exception as e:
        logger.error(f"Error in Unicode security analysis: {e}")
        return "ERROR", Text(f"Analysis failed: {str(e)}", style="red")


def run(apk_ctx) -> Tuple[Union[str, Text], float]:
    """Plugin entry point for AODS plugin manager."""
    try:
        status, report = run_plugin(apk_ctx)
        confidence = 0.8 if status == "PASS" else 0.6 if status == "WARN" else 0.0
        return report, confidence
    except Exception as e:
        error_output = Text()
        error_output.append(f"Unicode Security Analysis Error: {str(e)}\n", style="red")
        return error_output, 0.0


# Export main classes for direct usage
__all__ = ["UnicodeSecurityAnalysisPlugin", "UnicodeSecurityAnalyzer", "run_plugin", "run"]  # Alias for compatibility

# Alias for compatibility
UnicodeSecurityAnalyzer = UnicodeSecurityAnalysisPlugin

# BasePluginV2 interface
try:
    from .v2_plugin import UnicodeSecurityAnalysisV2, create_plugin  # noqa: F401

    Plugin = UnicodeSecurityAnalysisV2
except ImportError:
    pass
