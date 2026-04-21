"""
Privacy Leak Detection Plugin - Modular Implementation
Full privacy leak detection including clipboard monitoring, screenshot security,
location tracking, and analytics SDK analysis.

This module orchestrates all privacy analysis components:
- Location data privacy analysis (MASTG-TEST-PRIVACY-04)
- Contact data privacy analysis (MASTG-TEST-PRIVACY-01)
- Device information privacy analysis (MASTG-TEST-PRIVACY-05)
- Network privacy analysis (MASTG-TEST-PRIVACY-02)
- Analytics tracking analysis (MASTG-TEST-PRIVACY-02)
"""

import logging  # noqa: F401
from typing import List, Tuple, Union, Dict, Any, Optional

from rich.text import Text

from core.apk_ctx import APKContext
from core.logging_config import get_logger
from .data_structures import PrivacyFinding, PrivacyAnalysisResult, PrivacyCategory
from .location_analyzer import LocationAnalyzer
from .contact_analyzer import ContactAnalyzer
from .device_analyzer import DeviceAnalyzer
from .network_privacy_analyzer import NetworkPrivacyAnalyzer
from .formatters import PrivacyAnalysisFormatter

logger = get_logger(__name__)

# Import dynamic analysis capabilities from core analyzer
try:
    from core.privacy_leak_analyzer import PrivacyLeakAnalyzer

    DYNAMIC_ANALYSIS_AVAILABLE = True
except ImportError:
    DYNAMIC_ANALYSIS_AVAILABLE = False
    logger.warning("dynamic_privacy_analysis_unavailable", reason="core_analyzer_not_found")

# Characteristics to inform decompilation policy elevation
PLUGIN_CHARACTERISTICS = {
    "category": "PRIVACY",
    # Needs resources for XML/prefs; imports aid cross-file reference resolution
    "decompilation_requirements": ["res", "imports"],
}


class PrivacyLeakDetectionPlugin:
    """
    Main privacy leak detection plugin that orchestrates all analysis components.

    This class provides a unified interface for full privacy analysis
    while maintaining clean separation of concerns through specialized analyzers.
    """

    def __init__(self):
        """Initialize all analysis components with dependency injection."""
        self.findings = []

        # Initialize specialized analyzers
        self.location_analyzer = LocationAnalyzer()
        self.contact_analyzer = ContactAnalyzer()
        self.device_analyzer = DeviceAnalyzer()
        self.network_analyzer = NetworkPrivacyAnalyzer()

        # Initialize dynamic analyzer if available
        self.dynamic_analyzer: Optional[PrivacyLeakAnalyzer] = None

        # Initialize formatter
        self.formatter = PrivacyAnalysisFormatter()

        # Plugin metadata
        self.name = "Privacy Leak Detection"
        self.description = "Full privacy analysis including clipboard, location, and analytics tracking"
        self.version = "2.1.0"  # Updated version to reflect dynamic analysis integration
        self.author = "AODS Security Team"

        logger.debug("Privacy leak detection plugin initialized with all components")

    def run_tests(self, apk_ctx: APKContext, enable_dynamic: bool = True) -> Dict[str, Any]:
        """
        Execute full privacy leak detection tests.

        Args:
            apk_ctx: APK context containing analysis data
            enable_dynamic: Whether to enable dynamic analysis with Frida hooks

        Returns:
            Dict containing privacy analysis results and recommendations
        """
        results = {
            "plugin_name": self.name,
            "version": self.version,
            "timestamp": None,
            "privacy_analysis": {},
            "vulnerabilities": [],
            "recommendations": [],
            "masvs_compliance": {},
            "privacy_score": 0.0,
            "summary": {
                "total_privacy_issues": 0,
                "critical_issues": 0,
                "high_issues": 0,
                "medium_issues": 0,
                "low_issues": 0,
            },
        }

        try:
            logger.debug(f"Starting {self.name} analysis...")

            # Set dynamic analysis flag
            self._enable_dynamic = enable_dynamic and DYNAMIC_ANALYSIS_AVAILABLE

            # Run all analysis components
            self.findings = self.analyze_privacy_leaks(apk_ctx)

            # Process results
            self._process_privacy_results(results)

            # Generate MASVS compliance report
            self._generate_masvs_compliance(results)

            # Generate summary and recommendations
            self._generate_summary_and_recommendations(results)

            logger.debug(f"{self.name} analysis completed successfully")

        except Exception as e:
            logger.error(f"{self.name} analysis failed: {e}")
            results["error"] = str(e)

        return results

    def analyze_privacy_leaks(self, apk_ctx: APKContext) -> List[PrivacyFinding]:
        """
        Main analysis method that coordinates all privacy leak detection.

        Args:
            apk_ctx: APK context containing source files and metadata

        Returns:
            List of privacy findings found
        """
        logger.debug("Starting full privacy leak analysis")

        self.findings = []

        try:
            # Run all static analysis components
            self.findings.extend(self._analyze_location_privacy(apk_ctx))
            self.findings.extend(self._analyze_contact_privacy(apk_ctx))
            self.findings.extend(self._analyze_device_privacy(apk_ctx))
            self.findings.extend(self._analyze_network_privacy(apk_ctx))

            # Run dynamic analysis if available and enabled
            if hasattr(self, "_enable_dynamic") and self._enable_dynamic:
                self.findings.extend(self._analyze_dynamic_privacy(apk_ctx))

            logger.debug(f"Privacy analysis completed. Found {len(self.findings)} privacy issues.")

        except Exception as e:
            logger.error(f"Error during privacy analysis: {e}")
            raise

        return self.findings

    def _analyze_location_privacy(self, apk_ctx: APKContext) -> List[PrivacyFinding]:
        """Analyze location data privacy."""
        logger.debug("Analyzing location data privacy")
        try:
            return self.location_analyzer.analyze_location_privacy(apk_ctx)
        except Exception as e:
            logger.error(f"Error in location privacy analysis: {e}")
            return []

    def _analyze_contact_privacy(self, apk_ctx: APKContext) -> List[PrivacyFinding]:
        """Analyze contact data privacy."""
        logger.debug("Analyzing contact data privacy")
        try:
            return self.contact_analyzer.analyze_contact_privacy(apk_ctx)
        except Exception as e:
            logger.error(f"Error in contact privacy analysis: {e}")
            return []

    def _analyze_device_privacy(self, apk_ctx: APKContext) -> List[PrivacyFinding]:
        """Analyze device information privacy."""
        logger.debug("Analyzing device information privacy")
        try:
            return self.device_analyzer.analyze_device_privacy(apk_ctx)
        except Exception as e:
            logger.error(f"Error in device privacy analysis: {e}")
            return []

    def _analyze_network_privacy(self, apk_ctx: APKContext) -> List[PrivacyFinding]:
        """Analyze network privacy."""
        logger.debug("Analyzing network privacy")
        try:
            return self.network_analyzer.analyze_network_privacy(apk_ctx)
        except Exception as e:
            logger.error(f"Error in network privacy analysis: {e}")
            return []

    def _process_privacy_results(self, results: Dict[str, Any]):
        """Process privacy analysis results into standardized format."""
        analysis_result = PrivacyAnalysisResult.create_from_findings(self.findings)

        results["privacy_analysis"] = {
            "privacy_score": analysis_result.privacy_score,
            "total_findings": analysis_result.total_issues,
            "findings_by_category": self._group_findings_by_category(),
            "compliance_frameworks": analysis_result.compliance_frameworks,
        }

        results["privacy_score"] = analysis_result.privacy_score
        results["summary"] = {
            "total_privacy_issues": analysis_result.total_issues,
            "critical_issues": analysis_result.critical_issues,
            "high_issues": analysis_result.high_issues,
            "medium_issues": analysis_result.medium_issues,
            "low_issues": analysis_result.low_issues,
        }

        # Convert findings to vulnerability format
        for finding in self.findings:
            vulnerability = {
                "id": finding.finding_id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity.value,
                "category": finding.category.value,
                "data_types": [dt.value for dt in finding.data_types],
                "evidence": finding.evidence,
                "affected_components": finding.affected_components,
                "recommendations": finding.recommendations,
                "confidence": finding.confidence,
                "mastg_test_id": finding.mastg_test_id.value,
                "risk_score": finding.risk_factors.overall_risk_score,
                "compliance_impacts": [
                    {"framework": ci.framework.value, "impact_level": ci.impact_level, "description": ci.description}
                    for ci in finding.compliance_impacts
                ],
            }
            results["vulnerabilities"].append(vulnerability)

    def _group_findings_by_category(self) -> Dict[str, int]:
        """Group findings by category for summary."""
        grouped = {}
        for finding in self.findings:
            category = finding.category.value
            if category not in grouped:
                grouped[category] = 0
            grouped[category] += 1
        return grouped

    def _generate_masvs_compliance(self, results: Dict[str, Any]):
        """Generate MASVS compliance report."""
        analysis_result = PrivacyAnalysisResult.create_from_findings(self.findings)
        results["masvs_compliance"] = analysis_result.masvs_compliance

    def _generate_summary_and_recommendations(self, results: Dict[str, Any]):
        """Generate summary and recommendations."""
        # Generate category-specific recommendations
        recommendations = []

        category_counts = self._group_findings_by_category()

        if category_counts.get(PrivacyCategory.LOCATION.value, 0) > 0:
            recommendations.extend(
                [
                    "Review location data usage and implement user consent mechanisms",
                    "Consider using coarse location if fine precision is not required",
                    "Implement location access controls in app settings",
                ]
            )

        if category_counts.get(PrivacyCategory.CONTACTS.value, 0) > 0:
            recommendations.extend(
                [
                    "Implement contact selection instead of bulk access",
                    "Provide clear explanation of contact data usage",
                    "Cache contact data locally to reduce repeated access",
                ]
            )

        if category_counts.get(PrivacyCategory.DEVICE_INFO.value, 0) > 0:
            recommendations.extend(
                [
                    "Consider using less identifying alternatives to device IDs",
                    "Implement secure storage for device identifiers",
                    "Provide user controls for identifier deletion",
                ]
            )

        if category_counts.get(PrivacyCategory.ANALYTICS.value, 0) > 0:
            recommendations.extend(
                [
                    "Review analytics SDK privacy policies and data handling",
                    "Implement user consent for analytics data collection",
                    "Provide opt-out mechanisms for analytics tracking",
                ]
            )

        if category_counts.get(PrivacyCategory.CLIPBOARD.value, 0) > 0:
            recommendations.extend(
                [
                    "Implement user consent before clipboard access",
                    "Provide clear indication of clipboard usage",
                    "Clear clipboard after use to prevent data leakage",
                ]
            )

        if category_counts.get(PrivacyCategory.SCREENSHOT.value, 0) > 0:
            recommendations.extend(
                [
                    "Implement FLAG_SECURE for sensitive screens",
                    "Test screenshot prevention effectiveness",
                    "Monitor screenshot attempts on sensitive screens",
                ]
            )

        # Add general privacy recommendations
        if self.findings:
            recommendations.extend(
                [
                    "Conduct regular privacy impact assessments",
                    "Implement privacy by design principles",
                    "Provide full privacy policy covering all data collection",
                    "Implement data minimization and purpose limitation",
                    "Regular audit of third-party integrations for privacy compliance",
                ]
            )

        results["recommendations"] = recommendations

    def get_analysis_summary(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """Get analysis summary with component details."""
        findings = self.analyze_privacy_leaks(apk_ctx)
        analysis_result = PrivacyAnalysisResult.create_from_findings(findings)

        return {
            "privacy_score": analysis_result.privacy_score,
            "total_findings": analysis_result.total_issues,
            "findings_by_severity": {
                "critical": analysis_result.critical_issues,
                "high": analysis_result.high_issues,
                "medium": analysis_result.medium_issues,
                "low": analysis_result.low_issues,
            },
            "findings_by_category": self._group_findings_by_category(),
            "masvs_compliance": analysis_result.masvs_compliance,
            "compliance_frameworks": {
                framework.value: status for framework, status in analysis_result.compliance_frameworks.items()
            },
            "component_analysis": {
                "location": len([f for f in findings if f.category == PrivacyCategory.LOCATION]),
                "contacts": len([f for f in findings if f.category == PrivacyCategory.CONTACTS]),
                "device_info": len([f for f in findings if f.category == PrivacyCategory.DEVICE_INFO]),
                "analytics": len([f for f in findings if f.category == PrivacyCategory.ANALYTICS]),
                "clipboard": len([f for f in findings if f.category == PrivacyCategory.CLIPBOARD]),
                "screenshot": len([f for f in findings if f.category == PrivacyCategory.SCREENSHOT]),
                "network": len([f for f in findings if f.category == PrivacyCategory.NETWORK]),
            },
        }

    def _analyze_dynamic_privacy(self, apk_ctx: APKContext) -> List[PrivacyFinding]:
        """
        Perform dynamic privacy analysis using Frida-based monitoring.

        Args:
            apk_ctx: APK context containing analysis data

        Returns:
            List of privacy findings from dynamic analysis
        """
        dynamic_findings = []

        if not DYNAMIC_ANALYSIS_AVAILABLE:
            logger.warning("Dynamic analysis not available - core analyzer not found")
            return dynamic_findings

        try:
            logger.debug("Starting dynamic privacy analysis with Frida")

            # Initialize dynamic analyzer
            if not self.dynamic_analyzer:
                self.dynamic_analyzer = PrivacyLeakAnalyzer(apk_ctx)

            # Run dynamic analysis
            dynamic_results = self.dynamic_analyzer.analyze_privacy_leaks(enable_dynamic=True)

            # Convert core analyzer results to plugin findings format
            dynamic_findings = self._convert_dynamic_results(dynamic_results)

            logger.debug(f"Dynamic analysis completed. Found {len(dynamic_findings)} dynamic privacy issues.")

        except Exception as e:
            logger.error(f"Error during dynamic privacy analysis: {e}")
            # Don't raise - continue with static analysis results

        return dynamic_findings

    def _convert_dynamic_results(self, dynamic_results: Dict[str, Any]) -> List[PrivacyFinding]:
        """Convert core analyzer results to plugin findings format."""
        findings = []

        try:
            # Extract clipboard findings
            if "clipboard_analysis" in dynamic_results:
                clipboard_data = dynamic_results["clipboard_analysis"]
                for finding_data in clipboard_data.get("findings", []):
                    finding = PrivacyFinding(
                        title=finding_data.get("title", "Clipboard Privacy Issue"),
                        description=finding_data.get(
                            "description", "Dynamic clipboard monitoring detected privacy issue"
                        ),
                        severity=finding_data.get("severity", "MEDIUM").upper(),
                        category=PrivacyCategory.CLIPBOARD,
                        confidence=finding_data.get("confidence", 0.8),
                        evidence=finding_data.get("evidence", []),
                        masvs_refs=["MSTG-PRIVACY-01"],
                        recommendations=["Review clipboard access patterns", "Implement clipboard security controls"],
                    )
                    findings.append(finding)

            # Extract location findings
            if "location_analysis" in dynamic_results:
                location_data = dynamic_results["location_analysis"]
                for finding_data in location_data.get("findings", []):
                    finding = PrivacyFinding(
                        title=finding_data.get("title", "Location Privacy Issue"),
                        description=finding_data.get(
                            "description", "Dynamic location monitoring detected privacy issue"
                        ),
                        severity=finding_data.get("severity", "HIGH").upper(),
                        category=PrivacyCategory.LOCATION,
                        confidence=finding_data.get("confidence", 0.9),
                        evidence=finding_data.get("evidence", []),
                        masvs_refs=["MSTG-PRIVACY-04"],
                        recommendations=["Review location access patterns", "Implement location privacy controls"],
                    )
                    findings.append(finding)

            # Extract screenshot findings
            if "screenshot_analysis" in dynamic_results:
                screenshot_data = dynamic_results["screenshot_analysis"]
                for finding_data in screenshot_data.get("findings", []):
                    finding = PrivacyFinding(
                        title=finding_data.get("title", "Screenshot Security Issue"),
                        description=finding_data.get(
                            "description", "Screenshot security analysis detected privacy issue"
                        ),
                        severity=finding_data.get("severity", "MEDIUM").upper(),
                        category=PrivacyCategory.SCREENSHOT,
                        confidence=finding_data.get("confidence", 0.7),
                        evidence=finding_data.get("evidence", []),
                        masvs_refs=["MSTG-PRIVACY-01"],
                        recommendations=[
                            "Implement FLAG_SECURE for sensitive activities",
                            "Review screenshot prevention controls",
                        ],
                    )
                    findings.append(finding)

        except Exception as e:
            logger.error(f"Error converting dynamic results: {e}")

        return findings


def run(apk_ctx: APKContext) -> Tuple[str, Union[str, Text]]:
    """
    Main plugin execution function.

    Args:
        apk_ctx: APK context containing source files and metadata

    Returns:
        Tuple of (status, report) where status is "PASS"/"FAIL"/"ERROR"
        and report is a Rich Text object with detailed findings
    """
    try:
        # Initialize plugin and run analysis
        plugin = PrivacyLeakDetectionPlugin()
        findings = plugin.analyze_privacy_leaks(apk_ctx)

        # Format and return results
        return plugin.formatter.format_plugin_result(findings)

    except Exception as e:
        logger.error(f"Error in privacy leak detection: {e}")
        return "⚠️ ERROR", Text(f"Analysis failed: {str(e)}", style="red")


def run_plugin(apk_ctx: APKContext) -> Tuple[str, Union[str, Text]]:
    """
    Plugin interface function expected by the plugin manager.

    Args:
        apk_ctx: The APKContext instance containing APK path and metadata

    Returns:
        Tuple[str, Union[str, Text]]: Plugin execution result
    """
    return run(apk_ctx)


# Export main classes for direct usage
__all__ = [
    "PrivacyLeakDetectionPlugin",
    "PrivacyFinding",
    "PrivacyAnalysisResult",
    "LocationAnalyzer",
    "ContactAnalyzer",
    "DeviceAnalyzer",
    "NetworkPrivacyAnalyzer",
    "PrivacyAnalysisFormatter",
    "run",
    "run_plugin",
]

# BasePluginV2 interface
try:
    from .v2_plugin import PrivacyLeakDetectionV2, create_plugin  # noqa: F401

    Plugin = PrivacyLeakDetectionV2
except ImportError:
    pass
