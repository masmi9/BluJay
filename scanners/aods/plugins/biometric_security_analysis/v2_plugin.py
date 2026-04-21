#!/usr/bin/env python3
"""
biometric_security_analysis - V2 Structured Bridge (Phase 3)
=================================================================
"""

import time
from typing import List

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.plugins.base_plugin_v2 import (
    BasePluginV2, PluginMetadata, PluginResult, PluginFinding,
    PluginCapability, PluginStatus, PluginPriority,
)

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)


class BiometricSecurityAnalysisV2(BasePluginV2):
    """Biometric authentication security - BiometricPrompt, fallback auth (CWE-287)"""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="biometric_security_analysis", version="3.0.0",
            description="Biometric authentication security - BiometricPrompt, fallback auth (CWE-287)",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL, timeout_seconds=120,
            supported_platforms=["android"], tags=["biometric", "auth", "cwe-287"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start = time.time()
        try:
            findings = self._run_structured(apk_ctx)
            return PluginResult(
                status=PluginStatus.SUCCESS, findings=findings,
                metadata={"execution_time": time.time() - start, "plugin_version": "3.0.0", "bridge": "structured"},
            )
        except Exception as e:
            logger.error("biometric_security_analysis failed: %s", e)
            return PluginResult(status=PluginStatus.FAILURE, findings=[],
                                metadata={"error": type(e).__name__, "execution_time": time.time() - start})

    def _run_structured(self, apk_ctx):
        try:
            from plugins.biometric_security_analysis import BiometricSecurityPlugin
            plugin = BiometricSecurityPlugin(apk_ctx)
            result = plugin.analyze(apk_ctx) if 'analyze' == 'analyze' else plugin.analyze()
            raw = result
            if hasattr(result, 'findings'):
                raw = result.findings
            elif hasattr(result, 'vulnerabilities'):
                raw = result.vulnerabilities
            elif hasattr(result, 'security_issues'):
                raw = result.security_issues
            elif isinstance(result, dict):
                raw = result.get('findings', result.get('vulnerabilities', []))
            if not isinstance(raw, list):
                raw = [raw] if raw else []
            return self._convert_list(raw)
        except Exception as e:
            logger.debug("Structured failed for biometric_security_analysis: %s", e)
            return self._run_legacy(apk_ctx)

    def _run_legacy(self, apk_ctx):
        try:
            from plugins.biometric_security_analysis import run_plugin
            result = run_plugin(apk_ctx)
            if isinstance(result, (list, dict)):
                return self._convert_list(result if isinstance(result, list) else [result])
            if isinstance(result, tuple) and len(result) >= 2:
                if isinstance(result[1], dict):
                    vulns = result[1].get("vulnerabilities", result[1].get("findings", []))
                    if isinstance(vulns, list):
                        return self._convert_list(vulns)
            return []
        except Exception as e:
            logger.debug("Legacy failed for biometric_security_analysis: %s", e)
            return []

    def _convert_list(self, items) -> List[PluginFinding]:
        findings = []
        for i, v in enumerate(items):
            if isinstance(v, str):
                findings.append(PluginFinding(
                    finding_id=f"biometric_security_analysis_{i:03d}", title=v[:200], description=v[:500],
                    severity="medium", confidence=0.5, file_path="unknown", line_number=None,
                    cwe_id="CWE-287",
                ))
            elif isinstance(v, dict):
                sev = str(v.get("severity", "medium")).lower()
                if sev not in ("critical", "high", "medium", "low", "info"):
                    sev = "medium"
                findings.append(PluginFinding(
                    finding_id=f"biometric_security_analysis_{i:03d}",
                    title=str(v.get("title", "Finding"))[:200],
                    description=str(v.get("description", ""))[:500],
                    severity=sev,
                    confidence=float(v.get("confidence", 0.5)),
                    file_path=str(v.get("location", v.get("file_path", "unknown"))),
                    line_number=v.get("line_number"),
                    cwe_id=v.get("cwe_id", "CWE-287"),
                    remediation=str(v.get("remediation", v.get("recommendation", "")))[:500] or None,
                ))
            else:
                title = str(getattr(v, "title", str(v)))
                sev = getattr(v, "severity", "medium")
                if hasattr(sev, "name"):
                    sev = sev.name.lower()
                elif hasattr(sev, "value"):
                    sev = str(sev.value).lower()
                else:
                    sev = str(sev).lower()
                if sev not in ("critical", "high", "medium", "low", "info"):
                    sev = "medium"
                findings.append(PluginFinding(
                    finding_id=f"biometric_security_analysis_{i:03d}",
                    title=title[:200],
                    description=str(getattr(v, "description", ""))[:500],
                    severity=sev,
                    confidence=float(getattr(v, "confidence", 0.5)),
                    file_path=str(getattr(v, "location", getattr(v, "file_path", "unknown"))),
                    line_number=getattr(v, "line_number", None),
                    cwe_id=getattr(v, "cwe_id", "CWE-287"),
                    remediation=str(getattr(v, "remediation", ""))[:500] or None,
                ))
        return findings


def create_plugin():
    return BiometricSecurityAnalysisV2()


__all__ = ["BiometricSecurityAnalysisV2", "create_plugin"]
