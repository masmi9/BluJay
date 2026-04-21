#!/usr/bin/env python3
"""
insecure_data_storage - BasePluginV2 Implementation
========================================================

Directly calls InsecureDataStoragePlugin.analyze() and converts
StorageVulnerability dataclass objects to PluginFinding instances.
"""

import logging
import time
from pathlib import Path  # noqa: E402

import sys

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


class InsecureDataStorageV2(BasePluginV2):
    """
    Insecure Data Storage - BasePluginV2 Implementation
    """

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="insecure_data_storage",
            version="2.0.0",
            description="Insecure Data Storage - Migrated to BasePluginV2",
            author="AODS Team",
            capabilities=[PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=300,
            supported_platforms=["android"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        """Execute plugin analysis by calling InsecureDataStoragePlugin directly."""
        start_time = time.time()

        try:
            from core.shared_infrastructure.dependency_injection import AnalysisContext
            from . import InsecureDataStoragePlugin

            # Build AnalysisContext from apk_ctx
            apk_path_str = None
            for attr_name in ["apk_path_str", "apk_path", "apk_file", "file_path", "path"]:
                if hasattr(apk_ctx, attr_name):
                    apk_path_str = getattr(apk_ctx, attr_name, None)
                    if apk_path_str:
                        break

            if not apk_path_str:
                return PluginResult(
                    status=PluginStatus.SUCCESS,
                    findings=[],
                    metadata={
                        "execution_time": time.time() - start_time,
                        "plugin_version": "2.0.0",
                        "note": "APK path not available",
                    },
                )

            context = AnalysisContext(
                apk_path=Path(apk_path_str),
                decompiled_path=(
                    Path(getattr(apk_ctx, "decompiled_path", ""))
                    if getattr(apk_ctx, "decompiled_path", "")
                    else None
                ),
                logger=logging.getLogger(__name__),
                config={},
                max_analysis_time=120,
            )

            plugin = InsecureDataStoragePlugin(context)
            vulnerabilities = plugin.analyze(apk_ctx)

            findings = []
            if vulnerabilities and isinstance(vulnerabilities, list):
                for i, vuln in enumerate(vulnerabilities):
                    findings.append(self._convert_storage_vuln(vuln, i))

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

    def _convert_storage_vuln(self, vuln, index: int) -> PluginFinding:
        """Convert a StorageVulnerability dataclass to PluginFinding."""
        # StorageVulnerabilitySeverity is an enum with values like "Critical", "High", etc.
        severity_raw = getattr(vuln, "severity", "medium")
        if hasattr(severity_raw, "value"):
            severity = self._normalize_severity(severity_raw.value)
        else:
            severity = self._normalize_severity(severity_raw)

        confidence = getattr(vuln, "confidence", 0.5) or 0.5

        # Extract file_path from affected_files or file_path field
        file_path = getattr(vuln, "file_path", "") or ""
        if not file_path:
            affected = getattr(vuln, "affected_files", [])
            file_path = affected[0] if affected else "unknown"

        # Line number
        line_number = getattr(vuln, "line_number", 0) or 0

        # CWE
        cwe_id = getattr(vuln, "cwe_id", None) or "CWE-922"

        # Evidence
        evidence_raw = getattr(vuln, "evidence", None)
        if isinstance(evidence_raw, list):
            evidence = {"description": evidence_raw[0] if evidence_raw else "", "file_path": file_path}
            if len(evidence_raw) > 1:
                evidence["code_snippet"] = str(evidence_raw[1])
        elif isinstance(evidence_raw, dict):
            evidence = evidence_raw
        elif isinstance(evidence_raw, str):
            evidence = {"description": evidence_raw, "file_path": file_path}
        else:
            evidence = {}

        # Storage type
        storage_type = getattr(vuln, "storage_type", None)
        if storage_type and hasattr(storage_type, "value"):
            evidence["vulnerability_type"] = storage_type.value

        # Code snippet extraction
        code_snippet = None
        if isinstance(evidence_raw, str) and evidence_raw.startswith("Line ") and ": " in evidence_raw:
            code_snippet = evidence_raw.split(": ", 1)[1]
        elif isinstance(evidence_raw, list) and len(evidence_raw) > 1:
            code_snippet = str(evidence_raw[1])

        return PluginFinding(
            finding_id=f"insecure_data_storage_{index:03d}",
            title=getattr(vuln, "title", "Storage Security Issue"),
            description=getattr(vuln, "description", "No description")[:500],
            severity=severity,
            confidence=confidence,
            file_path=file_path,
            line_number=line_number if line_number else None,
            cwe_id=cwe_id,
            owasp_category="M02-Insecure-Data-Storage",
            remediation=getattr(vuln, "remediation", None) or None,
            code_snippet=code_snippet,
            evidence=evidence,
        )

    def _normalize_severity(self, severity) -> str:
        """Normalize severity value to valid string."""
        if isinstance(severity, str):
            severity_lower = severity.lower()
            if severity_lower in ["critical", "high", "medium", "low", "info"]:
                return severity_lower
        return "medium"

    def _normalize_confidence(self, confidence) -> float:
        """Normalize confidence value to float [0.0-1.0]."""
        if isinstance(confidence, (int, float)):
            return max(0.0, min(1.0, float(confidence)))
        if isinstance(confidence, str):
            confidence_lower = confidence.lower()
            return {"high": 0.9, "medium": 0.5, "low": 0.3}.get(confidence_lower, 0.5)
        return 0.5


# Plugin factory


def create_plugin() -> InsecureDataStorageV2:
    """Create plugin instance."""
    return InsecureDataStorageV2()


__all__ = ["InsecureDataStorageV2", "create_plugin"]
