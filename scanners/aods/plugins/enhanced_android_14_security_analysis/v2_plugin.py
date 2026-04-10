#!/usr/bin/env python3
"""
enhanced_android_14_security_analysis - BasePluginV2 Implementation
========================================================================

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
from core.android_14_enhanced_security_analyzer import EnhancedAndroid14SecurityAnalyzer

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


class EnhancedAndroid14SecurityAnalysisV2(BasePluginV2):
    """
    Enhanced Android 14 Security Analysis - BasePluginV2 Implementation
    """

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="enhanced_android_14_security_analysis",
            version="2.0.0",
            description="Enhanced Android 14 Security Analysis - Migrated to BasePluginV2",
            author="AODS Team",
            capabilities=[PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=300,
            supported_platforms=["android"],
        )

    def execute(self, apk_ctx, *args, **kwargs) -> PluginResult:
        """Execute plugin analysis.

        Accepts optional extra args for compatibility with executors that pass
        a deep_mode flag or configuration as a second positional parameter.
        """
        start_time = time.time()

        try:
            # Preferred path: use the enhanced analyzer directly
            analyzer = EnhancedAndroid14SecurityAnalyzer()
            enhanced_result = analyzer.analyze_enhanced_android14_security(apk_ctx)
            findings = self._convert_enhanced_result(enhanced_result)

            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    "execution_time": time.time() - start_time,
                    "plugin_version": "2.0.0",
                    "source": "enhanced_analyzer",
                },
            )

        except Exception as primary_error:
            # Fallback to legacy paths if the enhanced analyzer is unavailable
            try:
                legacy_result = self._call_legacy_function(apk_ctx)
                findings = self._convert_legacy_result(legacy_result)

                return PluginResult(
                    status=PluginStatus.SUCCESS,
                    findings=findings,
                    metadata={
                        "execution_time": time.time() - start_time,
                        "plugin_version": "2.0.0",
                        "source": "legacy_fallback",
                        "primary_error": str(primary_error),
                    },
                )
            except Exception as fallback_error:
                self.logger.error(
                    f"EnhancedAndroid14SecurityAnalysisV2 failed: {primary_error}; "
                    f"legacy fallback failed: {fallback_error}"
                )
                return PluginResult(
                    status=PluginStatus.FAILURE,
                    findings=[],
                    metadata={
                        "error": f"primary={primary_error}; fallback={fallback_error}",
                        "execution_time": time.time() - start_time,
                    },
                )

    def _call_legacy_function(self, apk_ctx) -> Any:
        """Call legacy plugin function."""
        # Try different legacy function names
        legacy_functions = ["run", "run_plugin", "analyze"]

        for func_name in legacy_functions:
            try:
                # Try importing from main module
                from . import main

                if hasattr(main, func_name):
                    return getattr(main, func_name)(apk_ctx)
            except ImportError:
                pass

            try:
                # Try importing from current module
                import importlib

                current_module = importlib.import_module("plugins.enhanced_android_14_security_analysis")
                if hasattr(current_module, func_name):
                    return getattr(current_module, func_name)(apk_ctx)
            except (ImportError, AttributeError):
                pass

        # If no legacy function found, return empty result
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
                        finding_id="enhanced_android_14_security_analysis_001",
                        title="Plugin Result",
                        description=legacy_result[:200],
                        severity="info",
                        confidence=0.7,
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
            title = str(item.get("title", "Security Issue"))
            description = str(item.get("description", "No description"))[:500]
            severity = self._normalize_severity(item.get("severity", "medium"))
            confidence = self._normalize_confidence_numeric(item.get("confidence", "medium"))
            location = str(item.get("location", "unknown"))

            # Conservative CWE inference for Android 14+ manifest/platform changes
            tl = (title + " " + description).lower()
            inferred_cwe = item.get("cwe_id")
            if not inferred_cwe:
                if any(k in tl for k in ["exported", "component exposure", "provider exposure"]):
                    inferred_cwe = "CWE-925"  # Improper Control of Dynamically-Managed Code Resources (closest)
                elif any(k in tl for k in ["permission", "dangerous permission", "signature permission"]):
                    inferred_cwe = "CWE-732"  # Incorrect Permission Assignment for Critical Resource
                elif any(k in tl for k in ["backup", "allowbackup"]):
                    inferred_cwe = "CWE-200"  # Exposure of Sensitive Information

            refs = list(item.get("references", [])) if isinstance(item.get("references"), list) else []

            def add_ref(url: str):
                if url not in refs:
                    refs.append(url)

            if "android 14" in tl or "api 34" in tl or "target sdk 34" in tl:
                add_ref("https://developer.android.com/about/versions/14/behavior-changes-all")
            if "component" in tl or "exported" in tl:
                add_ref("https://developer.android.com/guide/components/intents-filters#improving-intent-security")

            evidence = dict(item.get("evidence", {})) if isinstance(item.get("evidence"), dict) else {}
            if "impact" not in evidence:
                if "exported" in tl:
                    evidence["impact"] = "unauthorized_component_access"
                elif "permission" in tl:
                    evidence["impact"] = "privilege_escalation"
            if "exploitability" not in evidence:
                if "debuggable" in tl or "backup" in tl:
                    evidence["exploitability"] = "medium"

            return PluginFinding(
                finding_id=f"enhanced_android_14_security_analysis_{index:03d}",
                title=title,
                description=description,
                severity=severity,
                confidence=confidence,
                file_path=location,
                line_number=self._extract_line_number(item),
                cwe_id=inferred_cwe,
                references=refs,
                evidence=evidence,
                remediation=str(item.get("recommendation", ""))[:200] if item.get("recommendation") else None,
            )
        else:
            return PluginFinding(
                finding_id=f"enhanced_android_14_security_analysis_{index:03d}",
                title="Security Finding",
                description=str(item)[:500],
                severity="medium",
                confidence=0.6,
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

    def _normalize_confidence_numeric(self, confidence: Any) -> float:
        """Normalize confidence to a numeric value in [0,1]."""
        if isinstance(confidence, (int, float)):
            try:
                val = float(confidence)
                return max(0.0, min(1.0, val))
            except Exception:
                return 0.7
        if isinstance(confidence, str):
            c = confidence.strip().lower()
            if c == "high":
                return 0.9
            if c == "medium":
                return 0.7
            if c == "low":
                return 0.4
            try:
                return max(0.0, min(1.0, float(confidence)))
            except Exception:
                return 0.7
        return 0.7

    def _convert_enhanced_result(self, enhanced_result: Any) -> List[PluginFinding]:
        """Convert EnhancedAndroid14AnalysisResult to PluginFinding list."""
        findings: List[PluginFinding] = []
        try:
            get_all = getattr(enhanced_result, "get_all_enhanced_findings", None)
            if callable(get_all):
                base_findings = get_all()
            else:
                # If structure unexpected, return empty
                base_findings = []

            for idx, bf in enumerate(base_findings):
                # Safely extract attributes with defaults
                finding_id = getattr(bf, "finding_id", f"enhanced_android14_{idx:03d}")
                title = getattr(bf, "title", "Android 14+ Security Issue")
                description = getattr(bf, "description", "")
                severity = str(getattr(bf, "severity", "medium")).lower()
                confidence = getattr(bf, "confidence", 0.7)
                try:
                    conf_num = float(confidence)
                except Exception:
                    conf_num = self._normalize_confidence_numeric(confidence)
                file_path = None
                # Attempt to derive location from affected_components/evidence
                affected = getattr(bf, "affected_components", None)
                if isinstance(affected, list) and affected:
                    file_path = str(affected[0])

                findings.append(
                    PluginFinding(
                        finding_id=str(finding_id),
                        title=str(title),
                        description=str(description)[:500],
                        severity=severity,
                        confidence=conf_num,
                        file_path=file_path,
                        line_number=self._extract_line_number(bf),
                    )
                )
        except Exception as e:
            self.logger.debug(f"Failed converting enhanced result: {e}")
        return findings


# Plugin factory


def create_plugin() -> EnhancedAndroid14SecurityAnalysisV2:
    """Create plugin instance."""
    return EnhancedAndroid14SecurityAnalysisV2()


__all__ = ["EnhancedAndroid14SecurityAnalysisV2", "create_plugin"]
