#!/usr/bin/env python3
"""
traversal_vulnerabilities - BasePluginV2 Implementation
============================================================

Directly calls EnhancedTraversalAnalyzer and converts TraversalVulnerability
dataclass objects to PluginFinding instances.
"""

import time

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


class TraversalVulnerabilitiesV2(BasePluginV2):
    """
    Traversal Vulnerabilities - BasePluginV2 Implementation
    """

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="traversal_vulnerabilities",
            version="2.0.0",
            description="Traversal Vulnerabilities - Migrated to BasePluginV2",
            author="AODS Team",
            capabilities=[PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=300,
            supported_platforms=["android"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        """Execute plugin analysis by calling EnhancedTraversalAnalyzer directly."""
        start_time = time.time()

        try:
            from . import EnhancedTraversalAnalyzer

            analyzer = EnhancedTraversalAnalyzer(apk_ctx)
            analyzer.analyze()

            # Extract TraversalVulnerability dataclass objects from analyzer state
            findings = []
            for i, vuln in enumerate(analyzer.vulnerabilities):
                findings.append(self._convert_traversal_vuln(vuln, i))

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

    def _convert_traversal_vuln(self, vuln, index: int) -> PluginFinding:
        """Convert a TraversalVulnerability dataclass to PluginFinding."""
        severity = self._normalize_severity(getattr(vuln, "severity", "medium"))
        confidence = getattr(vuln, "confidence", 0.5)
        if not isinstance(confidence, (int, float)):
            confidence = self._normalize_confidence(confidence)

        cwe_id = getattr(vuln, "cwe_id", None) or None
        # Infer CWE from title/description if not set
        if not cwe_id:
            tl = (getattr(vuln, "title", "") + " " + getattr(vuln, "description", "")).lower()
            if any(k in tl for k in ["../", "..\\", "path traversal", "directory traversal"]):
                cwe_id = "CWE-22"
            elif any(k in tl for k in ["zip slip", "zip traversal", "tar traversal"]):
                cwe_id = "CWE-22"
            elif any(k in tl for k in ["content provider", "path permission"]):
                cwe_id = "CWE-639"

        refs = list(getattr(vuln, "masvs_refs", []))
        if cwe_id == "CWE-22" and "https://cwe.mitre.org/data/definitions/22.html" not in refs:
            refs.append("https://cwe.mitre.org/data/definitions/22.html")
        if cwe_id == "CWE-639" and "https://cwe.mitre.org/data/definitions/639.html" not in refs:
            refs.append("https://cwe.mitre.org/data/definitions/639.html")

        evidence = {}
        evidence_str = getattr(vuln, "evidence", "")
        if evidence_str:
            evidence["description"] = str(evidence_str)[:500]
        traversal_type = getattr(vuln, "traversal_type", "")
        if traversal_type:
            evidence["traversal_type"] = traversal_type
        impact = getattr(vuln, "impact_assessment", "")
        if impact:
            evidence["impact"] = impact

        return PluginFinding(
            finding_id=f"traversal_vulnerabilities_{index:03d}",
            title=getattr(vuln, "title", "Traversal Vulnerability"),
            description=getattr(vuln, "description", "No description")[:500],
            severity=severity,
            confidence=confidence,
            file_path=getattr(vuln, "location", "unknown"),
            line_number=self._extract_line_number(vuln),
            cwe_id=cwe_id,
            references=refs,
            evidence=evidence,
            remediation=getattr(vuln, "remediation", None) or None,
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


def create_plugin() -> TraversalVulnerabilitiesV2:
    """Create plugin instance."""
    return TraversalVulnerabilitiesV2()


__all__ = ["TraversalVulnerabilitiesV2", "create_plugin"]
