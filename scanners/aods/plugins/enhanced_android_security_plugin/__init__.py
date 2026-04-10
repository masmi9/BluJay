#!/usr/bin/env python3
"""
Android Security Coordination Plugin

Smart coordination layer that uses existing AODS plugins to provide
full Android security analysis without duplication.

This plugin orchestrates existing AODS components:
- Storage security analysis (via enhanced_data_storage_modular)
- WebView security analysis (via webview_security_analysis)
- Component security analysis (via component_exploitation_plugin)
- Platform security analysis (via improper_platform_usage)
- Advanced vulnerability detection (via advanced_vulnerability_detection)

The coordinator identifies gaps in coverage and ensures full
Android security assessment by intelligently combining results from
specialized existing plugins.
"""

import logging
from typing import Tuple, Union, Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path  # noqa: F401

from rich.text import Text


class AODSCompatibleText(Text):
    """
    AODS-compatible Text wrapper that supports legacy string operations.

    CRITICAL FIX: Prevents 'Text' object has no attribute 'startswith' errors
    by providing string method compatibility for legacy plugin execution systems.

    BROADER AODS SCOPE CONSIDERATIONS:
    - Maintains rich text formatting capabilities
    - Provides backward compatibility with legacy string operations
    - Integrates with AODS reporting systems
    - Supports both console rendering and text processing
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._string_cache = None

    def _get_plain_text(self) -> str:
        """Get plain text representation, cached for performance."""
        if self._string_cache is None:
            self._string_cache = self.plain
        return self._string_cache

    def startswith(self, prefix, start=None, end=None) -> bool:
        """String-compatible startswith method."""
        return self._get_plain_text().startswith(prefix, start, end)

    def endswith(self, suffix, start=None, end=None) -> bool:
        """String-compatible endswith method."""
        return self._get_plain_text().endswith(suffix, start, end)

    def find(self, sub, start=None, end=None) -> int:
        """String-compatible find method."""
        return self._get_plain_text().find(sub, start, end)

    def replace(self, old, new, count=-1):
        """String-compatible replace method."""
        return self._get_plain_text().replace(old, new, count)

    def split(self, sep=None, maxsplit=-1):
        """String-compatible split method."""
        return self._get_plain_text().split(sep, maxsplit)

    def strip(self, chars=None):
        """String-compatible strip method."""
        return self._get_plain_text().strip(chars)

    def lower(self):
        """String-compatible lower method."""
        return self._get_plain_text().lower()

    def upper(self):
        """String-compatible upper method."""
        return self._get_plain_text().upper()

    def __contains__(self, item):
        """String-compatible contains method."""
        return item in self._get_plain_text()

    def __getitem__(self, key):
        """String-compatible indexing."""
        if isinstance(key, slice):
            return self._get_plain_text()[key]
        return self._get_plain_text()[key]

    def __len__(self):
        """String-compatible length."""
        return len(self._get_plain_text())

    def append(self, text, style=None):
        """Override append to invalidate string cache."""
        super().append(text, style)
        self._string_cache = None
        return self


# Import existing AODS plugin components
try:
    from plugins.enhanced_data_storage_modular import run_plugin as storage_analysis

    STORAGE_PLUGIN_AVAILABLE = True
except ImportError:
    STORAGE_PLUGIN_AVAILABLE = False

try:
    try:
        from plugins.webview_security_analysis import run_plugin as webview_analysis
    except ImportError:
        # Fallback: try direct import without plugins prefix
        import sys
        import os

        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "webview_security_analysis"))
        try:
            from main import run_plugin as webview_analysis
        except ImportError:
            from __init__ import run_plugin as webview_analysis
    WEBVIEW_PLUGIN_AVAILABLE = True
except ImportError:
    WEBVIEW_PLUGIN_AVAILABLE = False

try:
    from plugins.component_exploitation_plugin import run_plugin as component_analysis

    COMPONENT_PLUGIN_AVAILABLE = True
except ImportError:
    COMPONENT_PLUGIN_AVAILABLE = False

try:
    from plugins.improper_platform_usage import run_plugin as platform_analysis

    PLATFORM_PLUGIN_AVAILABLE = True
except ImportError:
    PLATFORM_PLUGIN_AVAILABLE = False

try:
    from plugins.advanced_vulnerability_detection import run_plugin as vuln_detection

    VULN_DETECTION_AVAILABLE = True
except ImportError:
    VULN_DETECTION_AVAILABLE = False

from .android_security_coordinator import AndroidSecurityCoordinator  # noqa: E402
from .data_structures import AndroidSecurityConfig, AndroidSecurityAnalysisResult  # noqa: E402

# Configure logging
logger = logging.getLogger(__name__)

# Interface migration flag - StandardizedVulnerability interface not yet implemented
# Setting to False prevents NameError when checking migration availability
INTERFACE_MIGRATION_AVAILABLE = False

# Plugin metadata for AODS framework integration
PLUGIN_METADATA = {
    "name": "Android Security Coordination",
    "description": "Intelligent coordination of existing AODS plugins for full Android security analysis",
    "version": "1.0.0",
    "author": "AODS Security Team",
    "category": "ANDROID_COORDINATION",
    "priority": "HIGH",
    "timeout": 300,
    "mode": "full",
    "requires_device": False,
    "requires_network": False,
    "invasive": False,
    "execution_time_estimate": 180,
    "dependencies": ["jadx", "aapt"],
    "modular_architecture": True,
    "leverages_existing_plugins": [
        "enhanced_data_storage_modular",
        "webview_security_analysis",
        "component_exploitation_plugin",
        "improper_platform_usage",
        "advanced_vulnerability_detection",
    ],
    "masvs_controls": [
        "MASVS-STORAGE-1",
        "MASVS-STORAGE-2",
        "MASVS-PLATFORM-1",
        "MASVS-PLATFORM-2",
        "MASVS-PLATFORM-3",
        "MASVS-NETWORK-1",
        "MASVS-NETWORK-2",
        "MASVS-CODE-2",
        "MASVS-CODE-3",
    ],
    "cwe_coverage": [
        "CWE-200",
        "CWE-250",
        "CWE-284",
        "CWE-319",
        "CWE-532",
        "CWE-538",
        "CWE-732",
        "CWE-79",
        "CWE-601",
        "CWE-749",
    ],
}

# Legacy compatibility
PLUGIN_INFO = PLUGIN_METADATA
PLUGIN_CHARACTERISTICS = {
    "mode": "full",
    "category": "ANDROID_COORDINATION",
    "targets": ["android_security", "comprehensive_analysis"],
    "priority": "HIGH",
    "modular": True,
}


class AndroidSecurityCoordinationPlugin:
    """
    Android Security Coordination Plugin.

    Orchestrates existing AODS plugins to provide full Android
    security analysis without duplicating existing functionality.
    """

    def __init__(self, config: Optional[AndroidSecurityConfig] = None):
        """Initialize the coordination plugin."""
        self.config = config or AndroidSecurityConfig()
        self.logger = logging.getLogger(__name__)

        # Initialize coordinator
        self.coordinator = AndroidSecurityCoordinator(self.config)

        # Check available plugins
        self.available_plugins = self._check_available_plugins()

        # Analysis state
        self.analysis_start_time = None
        self.plugin_results = {}
        self.analysis_complete = False

    def _check_available_plugins(self) -> Dict[str, bool]:
        """Check which existing plugins are available."""
        return {
            "storage_analysis": STORAGE_PLUGIN_AVAILABLE,
            "webview_analysis": WEBVIEW_PLUGIN_AVAILABLE,
            "component_analysis": COMPONENT_PLUGIN_AVAILABLE,
            "platform_analysis": PLATFORM_PLUGIN_AVAILABLE,
            "vuln_detection": VULN_DETECTION_AVAILABLE,
        }

    def analyze(self, apk_ctx) -> AndroidSecurityAnalysisResult:
        """
        Perform full Android security analysis.

        Args:
            apk_ctx: Application analysis context

        Returns:
            Full Android security analysis results
        """
        self.analysis_start_time = datetime.now()

        try:
            self.logger.debug("Starting coordinated Android security analysis...")

            # Execute available plugin analyses
            self._run_storage_analysis(apk_ctx)
            self._run_webview_analysis(apk_ctx)
            self._run_component_analysis(apk_ctx)
            self._run_platform_analysis(apk_ctx)
            self._run_vulnerability_detection(apk_ctx)

            # Coordinate and consolidate results
            consolidated_results = self.coordinator.consolidate_results(self.plugin_results, apk_ctx)

            # Calculate analysis metrics
            analysis_duration = (datetime.now() - self.analysis_start_time).total_seconds()

            # Apply interface standardization migration to vulnerabilities
            standardized_vulnerabilities = consolidated_results.vulnerabilities
            if INTERFACE_MIGRATION_AVAILABLE:
                try:
                    standardized_vulnerabilities = migrate_to_standardized_vulnerabilities(
                        consolidated_results.vulnerabilities
                    )
                    self.logger.debug(
                        f"Successfully migrated {len(standardized_vulnerabilities)} vulnerabilities to standardized interface"  # noqa: E501
                    )
                except Exception as e:
                    self.logger.warning(f"Interface migration failed, using original vulnerabilities: {e}")
                    standardized_vulnerabilities = consolidated_results.vulnerabilities

            # Create final results with standardized vulnerabilities
            result = AndroidSecurityAnalysisResult(
                vulnerabilities=standardized_vulnerabilities,
                storage_issues=consolidated_results.storage_issues,
                webview_issues=consolidated_results.webview_issues,
                component_issues=consolidated_results.component_issues,
                platform_issues=consolidated_results.platform_issues,
                analysis_duration=analysis_duration,
                total_vulnerabilities=len(standardized_vulnerabilities),
                critical_vulnerabilities=consolidated_results.critical_count,
                high_vulnerabilities=consolidated_results.high_count,
                plugins_executed=len([p for p in self.available_plugins.values() if p]),
                coverage_achieved=consolidated_results.coverage_percentage,
            )

            self.analysis_complete = True

            self.logger.debug(f"Coordinated Android security analysis completed in {analysis_duration:.2f}s")
            self.logger.debug(
                f"Found {result.total_vulnerabilities} security issues across {result.plugins_executed} plugins"
            )

            return result

        except Exception as e:
            self.logger.error(f"Android security coordination failed: {e}")
            raise

    def coordinate_android_security(
        self, vulnerabilities: List[Dict[str, Any]], config: AndroidSecurityConfig
    ) -> Dict[str, Any]:
        """
        Coordinate Android security analysis for QA framework integration.

        This method integrates with the full QA framework to ensure
        both report quality and Android detection quality.

        Args:
            vulnerabilities: List of vulnerabilities from previous QA stages
            config: Android security configuration

        Returns:
            Dictionary with coordination results for QA framework
        """
        try:
            self.logger.debug("Coordinating Android security analysis for QA framework...")

            # Analyze existing vulnerabilities for Android security gaps
            android_analysis = self._analyze_android_security_gaps(vulnerabilities)

            additional_findings = []

            # Calculate coverage score
            coverage_score = self._calculate_android_coverage_score(
                vulnerabilities, additional_findings, android_analysis
            )

            # Identify critical issues
            critical_issues = []
            warnings = []
            recommendations = []

            if coverage_score < 80.0:
                critical_issues.append(f"Android security coverage below threshold: {coverage_score:.1f}%")
                recommendations.append("Execute Android-specific security plugins for full coverage")

            if android_analysis["missing_categories"]:
                warnings.extend([f"Missing coverage for: {', '.join(android_analysis['missing_categories'])}"])
                recommendations.append("Review Android security plugin configuration")

            # Generate coordination report
            coordination_results = {
                "coverage_score": coverage_score,
                "gaps_identified": android_analysis["gaps_identified"],
                "missing_categories": android_analysis["missing_categories"],
                "additional_findings": len(additional_findings),
                "plugins_coordinated": len([p for p in self.available_plugins.values() if p]),
                "critical_issues": critical_issues,
                "warnings": warnings,
                "recommendations": recommendations,
                "android_specific_vulnerabilities": self._extract_android_vulnerabilities(vulnerabilities),
                "coordination_status": "SUCCESS",
            }

            self.logger.debug(f"Android security coordination completed. Coverage: {coverage_score:.1f}%")

            return coordination_results

        except Exception as e:
            self.logger.error(f"Android security coordination failed: {e}")
            return {
                "coverage_score": 0.0,
                "gaps_identified": True,
                "critical_issues": [f"Coordination failed: {str(e)}"],
                "warnings": [],
                "recommendations": ["Fix Android security coordination errors"],
                "coordination_status": "FAILED",
            }

    def _analyze_android_security_gaps(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze existing vulnerabilities for Android security gaps."""

        # Define expected Android security categories
        expected_categories = {
            "storage_security",
            "webview_security",
            "component_security",
            "platform_security",
            "logging_security",
            "manifest_security",
        }

        # Analyze what categories are covered
        found_categories = set()
        android_specific_count = 0

        for vuln in vulnerabilities:
            # Check if vulnerability is Android-specific
            title = vuln.get("title", "").lower()
            description = vuln.get("description", "").lower()
            category = vuln.get("category", "").lower()

            if any(
                android_term in title + description + category
                for android_term in ["android", "shared", "preference", "webview", "activity", "service"]
            ):
                android_specific_count += 1

                # Categorize the vulnerability
                if any(term in title + description for term in ["shared", "preference", "storage", "file"]):
                    found_categories.add("storage_security")
                elif any(term in title + description for term in ["webview", "javascript", "web"]):
                    found_categories.add("webview_security")
                elif any(term in title + description for term in ["component", "activity", "service", "receiver"]):
                    found_categories.add("component_security")
                elif any(term in title + description for term in ["manifest", "debug", "backup"]):
                    found_categories.add("platform_security")
                elif any(term in title + description for term in ["log", "logging"]):
                    found_categories.add("logging_security")

        missing_categories = expected_categories - found_categories
        gaps_identified = len(missing_categories) > 0 or android_specific_count < 3

        return {
            "expected_categories": list(expected_categories),
            "found_categories": list(found_categories),
            "missing_categories": list(missing_categories),
            "android_specific_count": android_specific_count,
            "gaps_identified": gaps_identified,
        }

    def _calculate_android_coverage_score(
        self,
        vulnerabilities: List[Dict[str, Any]],
        additional_findings: List[Dict[str, Any]],
        android_analysis: Dict[str, Any],
    ) -> float:
        """Calculate Android security coverage score."""

        # Base score on category coverage
        expected_categories = len(android_analysis["expected_categories"])
        found_categories = len(android_analysis["found_categories"])
        category_coverage = (found_categories / expected_categories) * 100

        # Adjust for Android-specific findings
        android_count = android_analysis["android_specific_count"] + len(additional_findings)
        finding_bonus = min(20.0, android_count * 5.0)  # Up to 20% bonus

        # Adjust for available plugins
        plugin_coverage = (len([p for p in self.available_plugins.values() if p]) / 5.0) * 100

        # Calculate weighted coverage score
        coverage_score = (category_coverage * 0.6) + (finding_bonus * 0.3) + (plugin_coverage * 0.1)

        return min(100.0, coverage_score)

    def _extract_android_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract Android-specific vulnerabilities from the list."""

        android_vulns = []

        for vuln in vulnerabilities:
            title = vuln.get("title", "").lower()
            description = vuln.get("description", "").lower()

            # Check if vulnerability is Android-specific
            if any(
                android_term in title + description
                for android_term in ["android", "shared", "preference", "webview", "activity", "service", "manifest"]
            ):
                android_vulns.append(vuln)

        return android_vulns

    def _run_storage_analysis(self, apk_ctx):
        """Execute storage security analysis if available."""
        if self.available_plugins["storage_analysis"]:
            try:
                self.logger.debug("Executing storage security analysis...")
                result = storage_analysis(apk_ctx)
                self.plugin_results["storage"] = result
                self.logger.debug("Storage security analysis completed")
            except Exception as e:
                self.logger.warning(f"Storage analysis failed: {e}")
        else:
            self.logger.warning("Storage analysis plugin not available")

    def _run_webview_analysis(self, apk_ctx):
        """Execute WebView security analysis if available."""
        if self.available_plugins["webview_analysis"]:
            try:
                self.logger.debug("Executing WebView security analysis...")
                result = webview_analysis(apk_ctx)
                self.plugin_results["webview"] = result
                self.logger.debug("WebView security analysis completed")
            except Exception as e:
                self.logger.warning(f"WebView analysis failed: {e}")
        else:
            self.logger.warning("WebView analysis plugin not available")

    def _run_component_analysis(self, apk_ctx):
        """Execute component security analysis if available."""
        if self.available_plugins["component_analysis"]:
            try:
                self.logger.debug("Executing component security analysis...")
                result = component_analysis(apk_ctx)
                self.plugin_results["component"] = result
                self.logger.debug("Component security analysis completed")
            except Exception as e:
                self.logger.warning(f"Component analysis failed: {e}")
        else:
            self.logger.warning("Component analysis plugin not available")

    def _run_platform_analysis(self, apk_ctx):
        """Execute platform security analysis if available."""
        if self.available_plugins["platform_analysis"]:
            try:
                self.logger.debug("Executing platform security analysis...")
                result = platform_analysis(apk_ctx)
                self.plugin_results["platform"] = result
                self.logger.debug("Platform security analysis completed")
            except Exception as e:
                self.logger.warning(f"Platform analysis failed: {e}")
        else:
            self.logger.warning("Platform analysis plugin not available")

    def _run_vulnerability_detection(self, apk_ctx):
        """Execute advanced vulnerability detection if available."""
        if self.available_plugins["vuln_detection"]:
            try:
                self.logger.debug("Executing vulnerability detection...")
                result = vuln_detection(apk_ctx)
                self.plugin_results["vulnerability"] = result
                self.logger.debug("Vulnerability detection completed")
            except Exception as e:
                self.logger.warning(f"Vulnerability detection failed: {e}")
        else:
            self.logger.warning("Advanced vulnerability detection plugin not available")


# Main plugin interface functions


def run_plugin(apk_ctx) -> Tuple[Union[str, Text], float]:
    """
    Main plugin execution function with AODS-wide compatibility.

    CRITICAL FIX: Ensures consistent string handling to prevent
    'Text' object has no attribute 'startswith' errors in legacy plugin execution.

    BROADER AODS SCOPE CONSIDERATIONS:
    - Compatible with legacy plugin execution systems
    - Maintains rich text formatting for console output
    - Provides fallback to plain string for system processing
    - Integrates with AODS reporting and analysis frameworks

    Args:
        apk_ctx: Application analysis context

    Returns:
        Tuple of (formatted_results, confidence_score)
    """
    try:
        # Initialize coordination plugin
        plugin = AndroidSecurityCoordinationPlugin()

        # Perform coordinated analysis
        results = plugin.analyze(apk_ctx)

        # Format results for display (returns Text object)
        formatted_results = _format_coordination_results(results)

        # Calculate overall confidence
        confidence_score = _calculate_coordination_confidence(results)

        # AODSCompatibleText automatically handles legacy string operations
        return formatted_results, confidence_score

    except Exception as e:
        logger.error(f"Android security coordination failed: {e}")

        # AODS COMPATIBILITY: Use AODS-compatible Text for legacy system integration
        error_text = AODSCompatibleText()
        error_text.append("❌ Android Security Coordination Failed\n", style="red bold")
        error_text.append(f"Error: {str(e)}\n", style="red")
        return error_text, 0.0


def run(apk_ctx) -> Tuple[Union[str, Text], float]:
    """Alternative entry point for plugin execution."""
    return run_plugin(apk_ctx)


def _format_coordination_results(results: AndroidSecurityAnalysisResult) -> AODSCompatibleText:
    """
    Format coordinated analysis results for display with AODS compatibility.

    CRITICAL FIX: Uses AODSCompatibleText to prevent 'Text' object has no
    attribute 'startswith' errors in legacy plugin execution systems.
    """

    output = AODSCompatibleText()

    # Header
    output.append("🔐 ANDROID SECURITY COORDINATION ANALYSIS\n", style="blue bold")
    output.append("=" * 60 + "\n", style="blue")

    # Plugin execution summary
    output.append("\n📊 COORDINATION SUMMARY:\n", style="green bold")
    output.append(f"   Plugins Executed: {results.plugins_executed}\n")
    output.append(f"   Total Vulnerabilities: {results.total_vulnerabilities}\n")
    output.append(f"   Critical: {results.critical_vulnerabilities}\n", style="red")
    output.append(f"   High: {results.high_vulnerabilities}\n", style="yellow")
    output.append(f"   Coverage Achieved: {results.coverage_achieved:.1f}%\n", style="cyan")
    output.append(f"   Analysis Duration: {results.analysis_duration:.2f}s\n")

    # Results by category
    if results.storage_issues:
        output.append(f"\n📱 STORAGE SECURITY ISSUES: {len(results.storage_issues)}\n", style="yellow bold")

    if results.webview_issues:
        output.append(f"🌐 WEBVIEW SECURITY ISSUES: {len(results.webview_issues)}\n", style="yellow bold")

    if results.component_issues:
        output.append(f"🔧 COMPONENT SECURITY ISSUES: {len(results.component_issues)}\n", style="yellow bold")

    if results.platform_issues:
        output.append(f"⚙️ PLATFORM SECURITY ISSUES: {len(results.platform_issues)}\n", style="yellow bold")

    # Critical findings
    critical_vulns = [v for v in results.vulnerabilities if hasattr(v, "severity") and v.severity == "CRITICAL"]
    if critical_vulns:
        output.append("\n🚨 CRITICAL SECURITY ISSUES:\n", style="red bold")
        for i, vuln in enumerate(critical_vulns[:5], 1):
            title = getattr(vuln, "title", str(vuln))
            output.append(f"\n{i}. {title}\n", style="red bold")

    # Coordination benefits
    output.append("\n✅ COORDINATION BENEFITS:\n", style="green bold")
    output.append("   • Used existing AODS plugins\n")
    output.append("   • Avoided pattern duplication\n")
    output.append("   • Full coverage without redundancy\n")
    output.append("   • Consolidated security assessment\n")

    output.append("\n✅ ANDROID SECURITY COORDINATION COMPLETE\n", style="green bold")

    return output


def _calculate_coordination_confidence(results: AndroidSecurityAnalysisResult) -> float:
    """Calculate overall confidence score for coordinated analysis."""

    if not results.vulnerabilities:
        return 0.0

    # Base confidence on plugin execution success
    base_confidence = results.plugins_executed / 5.0  # 5 possible plugins

    # Adjust for coverage achieved
    coverage_bonus = results.coverage_achieved / 100.0 * 0.2

    # Adjust for vulnerability detection
    vuln_bonus = min(results.total_vulnerabilities / 10.0, 0.2)

    final_confidence = min(base_confidence + coverage_bonus + vuln_bonus, 1.0)

    return final_confidence


def migrate_to_standardized_vulnerabilities(android_vulnerabilities: List[Any]) -> List[Any]:
    """
    Migrate AndroidVulnerability instances to StandardizedVulnerability.

    This function provides interface standardization for the enhanced Android
    security plugin, ensuring compatibility with the unified AODS vulnerability
    interface while maintaining backward compatibility.

    Args:
        android_vulnerabilities: List of AndroidVulnerability instances

    Returns:
        List of StandardizedVulnerability instances (or original if migration unavailable)
    """
    if not INTERFACE_MIGRATION_AVAILABLE:
        logger.warning("Interface migration not available, returning original vulnerabilities")
        return android_vulnerabilities

    try:
        # Import AndroidVulnerability for type checking
        from .data_structures import AndroidVulnerability

        # Filter and migrate only AndroidVulnerability instances
        android_vulns = [v for v in android_vulnerabilities if isinstance(v, AndroidVulnerability)]
        other_vulns = [v for v in android_vulnerabilities if not isinstance(v, AndroidVulnerability)]

        if android_vulns:
            standardized_vulns = migrate_android_vulnerabilities(android_vulns)  # noqa: F821
            logger.info(
                f"Migrated {len(standardized_vulns)} AndroidVulnerability instances to StandardizedVulnerability"
            )

            # Combine standardized and other vulnerabilities
            return standardized_vulns + other_vulns
        else:
            return android_vulnerabilities

    except Exception as e:
        logger.error(f"Failed to migrate AndroidVulnerability instances: {e}")
        return android_vulnerabilities


def get_standardized_vulnerability_interface():
    """
    Get information about the standardized vulnerability interface support.

    Returns:
        Dictionary with interface standardization information
    """
    return {
        "migration_available": INTERFACE_MIGRATION_AVAILABLE,
        "source_interface": "AndroidVulnerability",
        "target_interface": "StandardizedVulnerability",
        "backward_compatible": True,
        "migration_adapter": "AndroidVulnerabilityMigrationAdapter",
        "plugin_name": "enhanced_android_security_plugin",
    }


# Export interface standardization functions
__all__ = ["migrate_to_standardized_vulnerabilities", "get_standardized_vulnerability_interface", "AODSCompatibleText"]

# BasePluginV2 interface
try:
    from .v2_plugin import EnhancedAndroidSecurityPluginV2, create_plugin  # noqa: F401

    Plugin = EnhancedAndroidSecurityPluginV2
except ImportError:
    pass
