#!/usr/bin/env python3
"""
Enhanced Android 14+ Security Analysis Plugin
============================================

Plugin wrapper for the Enhanced Android 14+ Security Analyzer with expanded
vulnerability categories. Integrates cleanly with the AODS plugin system.

NEW CATEGORIES COVERED:
1. Credential Manager API Security
2. Health Connect API Vulnerabilities
3. Partial Photo Access Issues
4. Foreground Service Type Violations
5. Data Safety Label Compliance
6. App Compatibility Framework Bypasses
7. Restricted Storage Access Issues
8. Runtime Permission Escalation
9. Package Visibility Filtering Bypasses
10. Keystore/Hardware Security Module Issues

Total Coverage: 20 Android 14+ vulnerability categories (10 base + 10 enhanced)
"""

import logging
import time
from typing import Dict, Any, List, Optional, Tuple  # noqa: F401

from core.apk_ctx import APKContext

logger = logging.getLogger(__name__)


class EnhancedAndroid14SecurityAnalysisPlugin:
    """Enhanced Android 14+ Security Analysis Plugin for AODS."""

    def __init__(self):
        self.name = "enhanced_android_14_security_analysis"
        self.version = "2.0.0"
        self.description = "Full Android 14+ security analysis with 20 vulnerability categories"
        self.logger = logging.getLogger(f"{__name__}.{self.name}")

        # Plugin metadata
        self.metadata = {
            "plugin_type": "security_analyzer",
            "target_platform": "android",
            "min_api_level": 34,
            "max_api_level": None,
            "categories_covered": 20,
            "base_categories": 10,
            "enhanced_categories": 10,
            "severity_levels": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            "masvs_compliance": True,
            "owasp_mobile_top10_coverage": True,
        }

    def analyze(self, apk_ctx: APKContext) -> Tuple[str, Dict[str, Any]]:
        """
        Main analysis entry point for the plugin.

        Args:
            apk_ctx: APK analysis context

        Returns:
            Tuple of (status_message, analysis_results)
        """
        start_time = time.time()

        try:
            self.logger.info("🔍 Starting enhanced Android 14+ security analysis")

            # Check if app targets Android 14+
            target_sdk = self._get_target_sdk_version(apk_ctx)
            if target_sdk < 34:
                self.logger.info(f"App targets SDK {target_sdk} < 34, performing compatibility analysis")

            # Import and initialize enhanced analyzer
            from core.android_14_enhanced_security_analyzer import EnhancedAndroid14SecurityAnalyzer

            analyzer = EnhancedAndroid14SecurityAnalyzer()

            # Perform analysis
            enhanced_result = analyzer.analyze_enhanced_android14_security(apk_ctx)

            # Convert results to plugin format
            plugin_results = self._convert_to_plugin_format(enhanced_result)

            # Calculate execution metrics
            execution_time = time.time() - start_time

            # Generate summary statistics
            stats = enhanced_result.get_enhanced_summary_stats()

            # Create full results
            results = {
                "analysis_results": plugin_results,
                "summary_statistics": stats,
                "execution_metrics": {
                    "execution_time_seconds": execution_time,
                    "categories_analyzed": 20,
                    "findings_detected": stats["total_findings"],
                    "coverage_score": stats["coverage_score"],
                },
                "plugin_metadata": self.metadata,
                "target_sdk_version": target_sdk,
                "android_14_compatible": target_sdk >= 34,
            }

            # Generate status message
            if stats["total_findings"] > 0:
                severity_summary = ", ".join(
                    [
                        f"{count} {severity.lower()}"
                        for severity, count in stats["severity_distribution"].items()
                        if count > 0
                    ]
                )
                status_msg = f"✅ Enhanced Android 14+ analysis complete: {stats['total_findings']} findings ({severity_summary})"  # noqa: E501
            else:
                status_msg = "✅ Enhanced Android 14+ analysis complete: No security issues detected"

            self.logger.info(f"{status_msg} in {execution_time:.2f}s")

            return status_msg, results

        except Exception as e:
            error_msg = f"❌ Enhanced Android 14+ analysis failed: {e}"
            self.logger.error(error_msg)

            return error_msg, {
                "error": str(e),
                "execution_time_seconds": time.time() - start_time,
                "plugin_metadata": self.metadata,
            }

    def _get_target_sdk_version(self, apk_ctx: APKContext) -> int:
        """Get target SDK version from APK context."""
        try:
            if hasattr(apk_ctx, "get_target_sdk"):
                return apk_ctx.get_target_sdk()
            elif hasattr(apk_ctx, "target_sdk"):
                return apk_ctx.target_sdk
            else:
                # Try to extract from manifest
                manifest_content = apk_ctx.get_manifest_content() if hasattr(apk_ctx, "get_manifest_content") else ""

                import re

                target_sdk_match = re.search(r'android:targetSdkVersion="(\d+)"', manifest_content)
                if target_sdk_match:
                    return int(target_sdk_match.group(1))

                # Default to latest if not found
                return 34

        except Exception as e:
            self.logger.debug(f"Could not determine target SDK version: {e}")
            return 34

    def _convert_to_plugin_format(self, enhanced_result) -> Dict[str, Any]:
        """Convert enhanced analysis results to plugin format."""

        # Get all findings
        all_findings = enhanced_result.get_all_enhanced_findings()

        # Group findings by category
        findings_by_category = {}
        vulnerabilities = []

        for finding in all_findings:
            # Add to category grouping
            if finding.category not in findings_by_category:
                findings_by_category[finding.category] = []
            findings_by_category[finding.category].append(finding)

            # Convert to vulnerability format
            vulnerability = {
                "id": finding.finding_id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "category": finding.category,
                "api_level_impact": finding.api_level_impact,
                "security_impact": finding.security_impact,
                "evidence": finding.evidence,
                "affected_components": finding.affected_components,
                "recommendations": finding.recommendations,
                "masvs_references": finding.masvs_refs,
                "timestamp": finding.timestamp,
                "plugin_source": "enhanced_android_14_security_analysis",
            }
            vulnerabilities.append(vulnerability)

        # Create category summaries
        category_summaries = {}
        for category, findings in findings_by_category.items():
            category_summaries[category] = {
                "total_findings": len(findings),
                "severity_distribution": {
                    severity: len([f for f in findings if f.severity == severity])
                    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                },
                "highest_severity": (
                    max(
                        [f.severity for f in findings],
                        key=lambda x: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x),
                    )
                    if findings
                    else "INFO"
                ),
            }

        return {
            "vulnerabilities": vulnerabilities,
            "findings_by_category": {
                category: [
                    {"id": f.finding_id, "title": f.title, "severity": f.severity, "confidence": f.confidence}
                    for f in findings
                ]
                for category, findings in findings_by_category.items()
            },
            "category_summaries": category_summaries,
            "total_categories_analyzed": 20,
            "categories_with_findings": len(findings_by_category),
            "base_analyzer_findings": len(enhanced_result.base_result.get_all_findings()),
            "enhanced_analyzer_findings": len(all_findings) - len(enhanced_result.base_result.get_all_findings()),
        }

    def get_plugin_info(self) -> Dict[str, Any]:
        """Get plugin information and capabilities."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "metadata": self.metadata,
            "capabilities": {
                "android_14_plus_support": True,
                "comprehensive_coverage": True,
                "masvs_compliance_checking": True,
                "modern_api_analysis": True,
                "privacy_framework_analysis": True,
                "security_model_analysis": True,
            },
            "supported_categories": [
                # Base categories (from original analyzer)
                "predictive_back",
                "themed_icons",
                "notification_permissions",
                "regional_preferences",
                "grammatical_inflection",
                "privacy_sandbox",
                "scoped_storage",
                "restricted_settings",
                "photo_picker",
                "background_activity",
                # Enhanced categories (new)
                "credential_manager",
                "health_connect",
                "partial_photo_access",
                "foreground_service",
                "data_safety_compliance",
                "app_compatibility",
                "restricted_storage",
                "runtime_permission_escalation",
                "package_visibility",
                "keystore_hsm",
            ],
        }


# Plugin factory function


def create_plugin() -> EnhancedAndroid14SecurityAnalysisPlugin:
    """Factory function to create the enhanced Android 14+ security analysis plugin."""
    return EnhancedAndroid14SecurityAnalysisPlugin()


# Plugin entry points for AODS


def run(apk_ctx: APKContext) -> Tuple[str, Dict[str, Any]]:
    """Main plugin entry point for AODS plugin manager."""
    plugin = create_plugin()
    return plugin.analyze(apk_ctx)


def analyze(apk_ctx: APKContext) -> Tuple[str, Dict[str, Any]]:
    """Alternative plugin entry point for AODS plugin manager."""
    plugin = create_plugin()
    return plugin.analyze(apk_ctx)


def execute(apk_ctx: APKContext) -> Tuple[str, Dict[str, Any]]:
    """Alternative plugin entry point for AODS plugin manager."""
    plugin = create_plugin()
    return plugin.analyze(apk_ctx)


def analyze_android_14_enhanced_security(apk_ctx: APKContext) -> Tuple[str, Dict[str, Any]]:
    """
    Main entry point for enhanced Android 14+ security analysis.

    Args:
        apk_ctx: APK analysis context

    Returns:
        Tuple of (status_message, analysis_results)
    """
    plugin = create_plugin()
    return plugin.analyze(apk_ctx)


# Export plugin interface
__all__ = [
    "EnhancedAndroid14SecurityAnalysisPlugin",
    "create_plugin",
    "run",
    "analyze",
    "execute",
    "analyze_android_14_enhanced_security",
]

# BasePluginV2 interface
try:
    from .v2_plugin import EnhancedAndroid14SecurityAnalysisV2, create_plugin  # noqa: F811

    Plugin = EnhancedAndroid14SecurityAnalysisV2
except ImportError:
    pass
