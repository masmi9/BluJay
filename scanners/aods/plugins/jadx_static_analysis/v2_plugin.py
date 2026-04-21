#!/usr/bin/env python3
"""
jadx_static_analysis - BasePluginV2 Implementation
=======================================================

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


class JadxStaticAnalysisV2(BasePluginV2):
    """
    Jadx Static Analysis - BasePluginV2 Implementation
    """

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="jadx_static_analysis",
            version="2.0.0",
            description="Jadx Static Analysis - Migrated to BasePluginV2",
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
            from plugins.jadx_static_analysis import run_plugin
            return run_plugin(apk_ctx)
        except Exception as e:
            self.logger.debug("Legacy call failed for jadx_static_analysis: %s", e)
            return []

    def _convert_legacy_result(self, legacy_result: Any) -> List[PluginFinding]:
        """Convert legacy result to PluginFinding objects."""
        findings = []

        try:
            if isinstance(legacy_result, (list, dict)):
                findings.extend(self._process_findings_data(legacy_result))

            elif isinstance(legacy_result, tuple) and len(legacy_result) >= 2:
                # Legacy run() returns (plugin_name_str, dict_with_vulnerabilities)
                findings_data = legacy_result[0]
                if isinstance(findings_data, (list, dict)):
                    findings.extend(self._process_findings_data(findings_data))
                elif isinstance(legacy_result[1], dict):
                    # (str, dict) - extract vulnerabilities list from dict
                    vuln_list = legacy_result[1].get("vulnerabilities", [])
                    if isinstance(vuln_list, list) and vuln_list:
                        findings.extend(self._process_findings_data(vuln_list))
                    elif not vuln_list:
                        # Try the whole dict as findings data
                        findings.extend(self._process_findings_data(legacy_result[1]))

            elif isinstance(legacy_result, str) and legacy_result.strip():
                findings.append(
                    PluginFinding(
                        finding_id="jadx_static_analysis_001",
                        title="Plugin Result",
                        description=legacy_result[:200],
                        severity="info",
                        confidence=0.5,
                        file_path="plugin_output",
                        line_number=None,
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
            confidence = self._normalize_confidence(item.get("confidence", "medium"))
            location = str(item.get("file_path", "") or item.get("location", "unknown"))

            tl = (title + " " + description).lower()
            inferred_cwe = item.get("cwe_id")
            if not inferred_cwe:
                if any(k in tl for k in ["sql injection", "rawquery", "execsql"]):
                    inferred_cwe = "CWE-89"
                elif any(k in tl for k in ["path traversal", "../", "..\\"]):
                    inferred_cwe = "CWE-22"
                elif any(k in tl for k in ["webview", "addjavascriptinterface"]):
                    inferred_cwe = "CWE-749"
                elif any(k in tl for k in ["hardcoded", "api key", "password", "secret", "private key"]):
                    inferred_cwe = "CWE-798"
                elif any(k in tl for k in [
                    "rc4", "md5", "sha1", "sha-1", "ecb mode", "ecb cipher",
                    "des cipher", "des/", "3des", "weak crypto", "weak cipher",
                    "deprecated ssl", "deprecated tls", "insecure cipher",
                ]):
                    inferred_cwe = "CWE-327"
                elif any(k in tl for k in ["weak random", "java.util.random", "math.random"]):
                    inferred_cwe = "CWE-330"

            refs = list(item.get("references", [])) if isinstance(item.get("references"), list) else []

            def add_ref(url: str):
                if url not in refs:
                    refs.append(url)

            cwe_to_ref = {
                "CWE-89": "https://cwe.mitre.org/data/definitions/89.html",
                "CWE-22": "https://cwe.mitre.org/data/definitions/22.html",
                "CWE-749": "https://cwe.mitre.org/data/definitions/749.html",
                "CWE-798": "https://cwe.mitre.org/data/definitions/798.html",
                "CWE-327": "https://cwe.mitre.org/data/definitions/327.html",
            }
            if inferred_cwe in cwe_to_ref:
                add_ref(cwe_to_ref[inferred_cwe])

            evidence = dict(item.get("evidence", {})) if isinstance(item.get("evidence"), dict) else {}
            if "impact" not in evidence:
                if inferred_cwe in ["CWE-89", "CWE-22", "CWE-749"]:
                    evidence["impact"] = "code_execution_or_data_exposure"
                elif inferred_cwe in ["CWE-798", "CWE-327"]:
                    evidence["impact"] = "credential_compromise_or_crypto_weakness"
            if "exploitability" not in evidence:
                if inferred_cwe in ["CWE-89", "CWE-22"]:
                    evidence["exploitability"] = "high"
                elif inferred_cwe in ["CWE-749", "CWE-798", "CWE-327"]:
                    evidence["exploitability"] = "medium"

            return PluginFinding(
                finding_id=f"jadx_static_analysis_{index:03d}",
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
                code_snippet=item.get("code_snippet"),
            )
        else:
            return PluginFinding(
                finding_id=f"jadx_static_analysis_{index:03d}",
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


def create_plugin() -> JadxStaticAnalysisV2:
    """Create plugin instance."""
    return JadxStaticAnalysisV2()


__all__ = ["JadxStaticAnalysisV2", "create_plugin"]
