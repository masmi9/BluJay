#!/usr/bin/env python3
"""
frida_dynamic_analysis - BasePluginV2 Implementation
=========================================================

BasePluginV2 migration providing standardized interface.
"""

import time
from typing import List, Any

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
)

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


class FridaDynamicAnalysisV2(BasePluginV2):
    """
    Frida Dynamic Analysis - BasePluginV2 Implementation
    """

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="frida_dynamic_analysis",
            version="2.0.0",
            description="Frida Dynamic Analysis - Migrated to BasePluginV2",
            author="AODS Team",
            capabilities=[PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=300,
            supported_platforms=["android"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        """Execute plugin analysis."""
        start_time = time.time()

        try:
            # Try to call legacy function
            legacy_result = self._call_legacy_function(apk_ctx)
            findings = self._convert_legacy_result(legacy_result)

            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={"execution_time": time.time() - start_time, "plugin_version": "2.0.0"},
            )

        except Exception as e:
            self.logger.error(f"Plugin execution failed: {e}")
            return PluginResult(
                status=PluginStatus.FAILURE,
                findings=[],
                metadata={"error": str(e), "execution_time": time.time() - start_time},
            )

    def _call_legacy_function(self, apk_ctx) -> Any:
        """Call the legacy run_plugin() from __init__.py."""
        try:
            from plugins.frida_dynamic_analysis import run_plugin
            return run_plugin(apk_ctx)
        except Exception as e:
            self.logger.debug("Legacy call failed for frida_dynamic_analysis: %s", e)
            return []

    def _convert_legacy_result(self, legacy_result: Any) -> List[PluginFinding]:
        """Convert legacy result to PluginFinding objects."""
        findings = []

        try:
            if isinstance(legacy_result, tuple) and len(legacy_result) >= 2:
                # Tuple format (findings, metadata)
                findings_data = legacy_result[0]
                if isinstance(findings_data, (list, dict)):
                    findings.extend(self._process_findings_data(findings_data))

            elif isinstance(legacy_result, (list, dict)):
                findings.extend(self._process_findings_data(legacy_result))

            elif isinstance(legacy_result, str) and legacy_result.strip():
                # String result
                findings.append(
                    PluginFinding(
                        finding_id="frida_dynamic_analysis_001",
                        title="Plugin Result",
                        description=legacy_result[:200],
                        severity="info",
                        confidence=0.5,
                        file_path="plugin_output",
                        line_number=None,  # Track 34: string results have no line info
                    )
                )

        except Exception as e:
            logger.debug(f"Failed to convert legacy result: {e}")

        return findings

    def _process_findings_data(self, data: Any) -> List[PluginFinding]:
        """Process findings data into PluginFinding objects."""
        findings = []

        if isinstance(data, list):
            for i, item in enumerate(data):
                findings.append(self._create_finding_from_item(item, i))
        elif isinstance(data, dict):
            findings.append(self._create_finding_from_item(data, 0))

        return findings

    def _create_finding_from_item(self, item: Any, index: int) -> PluginFinding:
        """Create PluginFinding from individual item."""
        if isinstance(item, dict):
            return PluginFinding(
                finding_id=f"frida_dynamic_analysis_{index:03d}",
                title=str(item.get("title", "Security Issue")),
                description=str(item.get("description", "No description"))[:500],
                severity=self._normalize_severity(item.get("severity", "medium")),
                confidence=self._normalize_confidence(item.get("confidence", "medium")),
                file_path=str(item.get("location", "unknown")),
                line_number=self._extract_line_number(item),
                cwe_id=item.get("cwe_id"),
                remediation=str(item.get("recommendation", ""))[:200] if item.get("recommendation") else None,
            )
        else:
            return PluginFinding(
                finding_id=f"frida_dynamic_analysis_{index:03d}",
                title="Security Finding",
                description=str(item)[:500],
                severity="medium",
                confidence=0.5,
                file_path="unknown",
                line_number=self._extract_line_number(item),
            )

    def _normalize_severity(self, severity: Any) -> str:
        """Normalize severity value to valid string."""
        if isinstance(severity, str):
            severity_lower = severity.lower()
            if severity_lower in ["critical", "high", "medium", "low", "info"]:
                return severity_lower
        return "medium"

    def _normalize_confidence(self, confidence: Any) -> float:
        """Normalize confidence value to float [0.0-1.0]."""
        if isinstance(confidence, (int, float)):
            return max(0.0, min(1.0, float(confidence)))
        if isinstance(confidence, str):
            confidence_lower = confidence.lower()
            return {"high": 0.9, "medium": 0.5, "low": 0.3}.get(confidence_lower, 0.5)
        return 0.5


# Plugin factory


def create_plugin() -> FridaDynamicAnalysisV2:
    """Create plugin instance."""
    return FridaDynamicAnalysisV2()


__all__ = ["FridaDynamicAnalysisV2", "create_plugin"]
