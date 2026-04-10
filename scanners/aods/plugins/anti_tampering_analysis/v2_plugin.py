#!/usr/bin/env python3
"""
anti_tampering_analysis - BasePluginV2 Implementation
==========================================================

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


class AntiTamperingAnalysisV2(BasePluginV2):
    """
    Anti Tampering Analysis - BasePluginV2 Implementation
    """

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="anti_tampering_analysis",
            version="2.0.0",
            description="Anti Tampering Analysis - Migrated to BasePluginV2",
            author="AODS Team",
            capabilities=[PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=300,
            supported_platforms=["android"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        """Execute structured anti-tampering analysis."""
        start_time = time.time()

        try:
            findings = self._run_structured_analysis(apk_ctx)
            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    "execution_time": time.time() - start_time,
                    "plugin_version": "3.0.0",
                    "bridge": "structured",
                },
            )
        except Exception as e:
            logger.error("anti_tampering_analysis failed: %s", e)
            return PluginResult(
                status=PluginStatus.FAILURE,
                findings=[],
                metadata={"error": type(e).__name__, "execution_time": time.time() - start_time},
            )

    def _run_structured_analysis(self, apk_ctx) -> List[PluginFinding]:
        """Call AntiTamperingAnalysisPlugin.analyze() and extract structured findings."""
        try:
            from plugins.anti_tampering_analysis import AntiTamperingAnalysisPlugin

            plugin = AntiTamperingAnalysisPlugin(apk_ctx)
            result = plugin.analyze(apk_ctx)

            findings = []
            # result.findings contains structured finding objects
            raw_findings = getattr(result, "findings", None) or []
            if not raw_findings:
                # Try vulnerabilities attribute
                raw_findings = getattr(result, "vulnerabilities", None) or []

            for i, f in enumerate(raw_findings):
                title = getattr(f, "title", str(f))
                desc = getattr(f, "description", "")
                sev = getattr(f, "severity", "medium")
                if hasattr(sev, "name"):
                    sev = sev.name.lower()
                elif hasattr(sev, "value"):
                    sev = str(sev.value).lower()
                else:
                    sev = str(sev).lower()

                cwe = getattr(f, "cwe_id", None) or getattr(f, "cwe", None)
                if not cwe:
                    tl = (str(title) + " " + str(desc)).lower()
                    if any(k in tl for k in ["debug", "ptrace"]):
                        cwe = "CWE-489"
                    elif any(k in tl for k in ["hook", "frida", "xposed", "root"]):
                        cwe = "CWE-693"
                    elif any(k in tl for k in ["tamper", "integrity", "checksum"]):
                        cwe = "CWE-354"

                findings.append(PluginFinding(
                    finding_id=f"anti_tampering_analysis_{i:03d}",
                    title=str(title)[:200],
                    description=str(desc)[:500],
                    severity=sev if sev in ("critical", "high", "medium", "low", "info") else "medium",
                    confidence=float(getattr(f, "confidence", 0.5)),
                    file_path=str(getattr(f, "location", getattr(f, "file_path", "unknown"))),
                    line_number=getattr(f, "line_number", None),
                    cwe_id=cwe,
                    remediation=str(getattr(f, "recommendation", ""))[:500] or None,
                ))

            return findings

        except Exception as e:
            logger.debug("Structured analysis failed, falling back to run_plugin: %s", e)
            # Fallback to legacy
            try:
                from plugins.anti_tampering_analysis import run_plugin
                run_plugin(apk_ctx)  # Discard (str, Text) - can't extract structured data
            except Exception:
                pass
            return []

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


def create_plugin() -> AntiTamperingAnalysisV2:
    """Create plugin instance."""
    return AntiTamperingAnalysisV2()


__all__ = ["AntiTamperingAnalysisV2", "create_plugin"]
