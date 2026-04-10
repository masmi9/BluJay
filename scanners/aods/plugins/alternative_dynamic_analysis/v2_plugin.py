#!/usr/bin/env python3
"""
Alternative Dynamic Analysis Plugin - BasePluginV2 Implementation
================================================================

BasePluginV2 migration of the alternative dynamic analysis plugin.
Demonstrates proper migration from legacy plugin interface to standardized v2.

Features:
- BasePluginV2 compliant interface
- Metadata declaration
- Standardized finding generation
- Legacy function integration
- Performance monitoring
"""

import time
from typing import List, Optional, Dict, Any

import sys
from pathlib import Path

# Path setup for standalone execution
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.plugins.base_plugin_v2 import (
    BasePluginV2,
    PluginMetadata,
    PluginResult,
    PluginFinding,
    PluginCapability,
    PluginStatus,
    PluginPriority,
    PluginDependency,
)
from core.external.integration_adapters import ADBExecutorAdapter

# Import legacy analyzer
from .main import AlternativeDynamicAnalyzer

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


class AlternativeDynamicAnalysisV2(BasePluginV2):
    """
    Alternative Dynamic Analysis Plugin implementing BasePluginV2 interface.

    Provides dynamic analysis capabilities without Frida dependency,
    using ADB, logcat, and static analysis for security insights.
    """

    def get_metadata(self) -> PluginMetadata:
        """Get full plugin metadata."""
        return PluginMetadata(
            name="alternative_dynamic_analysis",
            version="2.0.0",
            description="Dynamic analysis without Frida dependency using ADB and static patterns",
            author="AODS Team",
            capabilities=[
                PluginCapability.DYNAMIC_ANALYSIS,
                PluginCapability.BEHAVIORAL_ANALYSIS,
                PluginCapability.NETWORK_ANALYSIS,
            ],
            dependencies=[
                PluginDependency(name="adb", version_min="1.0.0", optional=True, description="Android Debug Bridge"),
                PluginDependency(name="android_device", optional=True, description="Android device connection"),
            ],
            priority=PluginPriority.NORMAL,
            timeout_seconds=180,  # 3 minutes timeout
            tags=["dynamic", "runtime", "adb", "alternative"],
            supported_platforms=["android"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        """Execute alternative dynamic analysis."""
        start_time = time.time()

        try:
            self.logger.info("🔄 Starting alternative dynamic analysis")

            # Extract package name
            package_name = getattr(apk_ctx, "package_name", "unknown.package")
            if not package_name or package_name == "unknown.package":
                return PluginResult(
                    status=PluginStatus.SKIPPED,
                    findings=[],
                    metadata={"error": "Package name not available", "execution_time": time.time() - start_time},
                )

            # Create legacy analyzer and run analysis
            analyzer = AlternativeDynamicAnalyzer(
                package_name=package_name, config=self.config.__dict__ if self.config else {}
            )

            legacy_results = analyzer.analyze(apk_ctx)

            # Convert legacy results to BasePluginV2 format
            findings = self._convert_legacy_findings(legacy_results.get("findings", []))

            execution_time = time.time() - start_time

            # Determine status based on results
            if legacy_results.get("success", False):
                status = PluginStatus.SUCCESS
            elif legacy_results.get("error"):
                status = PluginStatus.FAILURE
            else:
                status = PluginStatus.PARTIAL_SUCCESS

            return PluginResult(
                status=status,
                findings=findings,
                metadata={
                    "execution_time": execution_time,
                    "analysis_method": legacy_results.get("analysis_method", "alternative"),
                    "device_connected": legacy_results.get("device_connected", False),
                    "total_findings": len(findings),
                    "legacy_success": legacy_results.get("success", False),
                    "package_name": package_name,
                },
            )

        except Exception as e:
            self.logger.error(f"Alternative dynamic analysis failed: {e}")
            return PluginResult(
                status=PluginStatus.FAILURE,
                findings=[],
                metadata={"error": str(e), "execution_time": time.time() - start_time},
            )

    def _convert_legacy_findings(self, legacy_findings: List[Dict[str, Any]]) -> List[PluginFinding]:
        """Convert legacy findings to PluginFinding objects."""
        findings = []

        for idx, legacy_finding in enumerate(legacy_findings):
            try:
                # Map legacy severity to standard severity
                severity_mapping = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}

                severity = severity_mapping.get(legacy_finding.get("severity", "MEDIUM").upper(), "medium")

                # Normalize confidence to float [0.0-1.0]
                confidence_value = legacy_finding.get("confidence", 0.5)
                confidence = max(0.0, min(1.0, float(confidence_value)))

                # Extract location information
                location_info = legacy_finding.get("location", {})
                location = location_info.get("source", "unknown")
                if "file_path" in location_info:
                    location = f"{location} ({location_info['file_path']})"

                finding = PluginFinding(
                    finding_id=f"alternative_dynamic_{idx:03d}",
                    title=legacy_finding.get("title", "Security Issue"),
                    description=legacy_finding.get("description", "No description available"),
                    severity=severity,
                    confidence=confidence,
                    file_path=location,
                    cwe_id=legacy_finding.get("cwe_id"),
                    owasp_category=self._map_vulnerability_type_to_owasp(
                        legacy_finding.get("vulnerability_type", "UNKNOWN")
                    ),
                    remediation=legacy_finding.get("recommendation", "Review and fix the identified issue"),
                    references=[],
                    evidence={
                        "vulnerability_type": legacy_finding.get("vulnerability_type"),
                        "original_confidence": confidence_value,
                        "analysis_source": location_info.get("source", "unknown"),
                    },
                )

                findings.append(finding)

            except Exception as e:
                self.logger.warning(f"Failed to convert legacy finding: {e}")
                # Create a generic finding for failed conversions
                findings.append(
                    PluginFinding(
                        finding_id=f"alternative_dynamic_err_{idx:03d}",
                        title="Conversion Error",
                        description=f"Failed to convert legacy finding: {str(legacy_finding)[:100]}...",
                        severity="low",
                        confidence=0.3,
                        file_path="conversion_error",
                    )
                )

        return findings

    def _map_vulnerability_type_to_owasp(self, vuln_type: str) -> Optional[str]:
        """Map vulnerability type to OWASP Mobile Top 10 category."""
        mapping = {
            "RUNTIME_PERMISSION": "M2_INSECURE_DATA_STORAGE",
            "NETWORK_BEHAVIOR": "M4_INSECURE_COMMUNICATION",
            "STORAGE_SECURITY": "M2_INSECURE_DATA_STORAGE",
            "RUNTIME_LOGGING": "M10_EXTRANEOUS_FUNCTIONALITY",
            "WEBVIEW_SECURITY": "M7_CLIENT_CODE_QUALITY",
            "CERTIFICATE_VALIDATION": "M4_INSECURE_COMMUNICATION",
        }

        return mapping.get(vuln_type)

    def validate_dependencies(self) -> Dict[str, bool]:
        """Validate plugin dependencies."""
        dependencies = {}

        # Check ADB availability
        try:
            adapter = ADBExecutorAdapter(timeout=5.0)
            result = adapter.execute_command(["version"], timeout=5.0)
            dependencies["adb"] = result.get("returncode", 1) == 0
        except Exception:
            dependencies["adb"] = False

        # Android device is optional
        dependencies["android_device"] = True  # Always available (optional)

        return dependencies


# Plugin factory function for backward compatibility


def create_plugin() -> AlternativeDynamicAnalysisV2:
    """Create an instance of the BasePluginV2 plugin."""
    return AlternativeDynamicAnalysisV2()


# Export the plugin class
__all__ = ["AlternativeDynamicAnalysisV2", "create_plugin"]
