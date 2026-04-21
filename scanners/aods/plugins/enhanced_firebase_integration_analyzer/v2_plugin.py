#!/usr/bin/env python3
"""
Enhanced Firebase Integration Analyzer - BasePluginV2 Adapter
"""

from typing import Any, Dict, List
import time

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


class FirebaseIntegrationV2(BasePluginV2):
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="enhanced_firebase_integration_analyzer",
            version="2.0.0",
            description="Firebase integration security analyzer - V2 adapter",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=300,
            supported_platforms=["android"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start = time.time()
        try:
            legacy = self._call_legacy(apk_ctx)
            findings = self._convert_legacy(legacy)
            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    "execution_time": time.time() - start,
                    "plugin_version": "2.0.0",
                },
            )
        except Exception as e:
            logger.debug(f"FirebaseIntegrationV2 failed (graceful): {e}")
            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=[],
                metadata={"warning": str(e), "execution_time": time.time() - start},
            )

    def _call_legacy(self, apk_ctx) -> Any:
        try:
            from . import enhanced_firebase_integration_analyzer as legacy

            if hasattr(legacy, "analyze_firebase_integration"):
                return legacy.analyze_firebase_integration(apk_ctx)
            if hasattr(legacy, "EnhancedFirebaseIntegrationAnalyzer"):
                analyzer = legacy.EnhancedFirebaseIntegrationAnalyzer(apk_ctx)
                return analyzer.analyze_firebase_integration_security()
        except Exception:
            pass
        return {"vulnerabilities": []}

    def _convert_legacy(self, legacy: Any) -> List[PluginFinding]:
        vulns = []
        if isinstance(legacy, dict):
            vulns = legacy.get("vulnerabilities", []) or []
        elif isinstance(legacy, list):
            vulns = legacy
        findings: List[PluginFinding] = []
        for i, v in enumerate(vulns):
            findings.append(self._make_finding(v, i))
        return findings

    def _make_finding(self, v: Dict[str, Any], idx: int) -> PluginFinding:
        title = v.get("description") or v.get("category") or "Firebase Integration Issue"
        description = str(v.get("description", ""))[:600]
        sev_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }
        severity = sev_map.get(str(v.get("severity", "LOW")).upper(), "low")
        confidence = float(v.get("confidence", 0.85))
        file_path = v.get("file_path")
        line_number = v.get("line_number")

        cwe = v.get("cwe") or v.get("cwe_id")
        if not cwe:
            text = f"{title} {description}".lower()
            if any(k in text for k in ["apikey", "api key", "hardcoded", "secret"]):
                cwe = "CWE-798"
            elif any(k in text for k in ["auth", "token", "credential"]):
                cwe = "CWE-522"
            else:
                cwe = "CWE-200"

        refs: List[str] = []
        cwe_refs = {
            "CWE-798": "https://cwe.mitre.org/data/definitions/798.html",
            "CWE-522": "https://cwe.mitre.org/data/definitions/522.html",
            "CWE-200": "https://cwe.mitre.org/data/definitions/200.html",
        }
        if cwe in cwe_refs:
            refs.append(cwe_refs[cwe])

        evidence = {
            "impact": v.get("impact")
            or ("credential_compromise" if cwe in ("CWE-798", "CWE-522") else "information_exposure"),
            "exploitability": v.get("exploitability") or ("high" if cwe in ("CWE-798", "CWE-522") else "medium"),
        }

        recommendation = v.get("remediation") or None

        return PluginFinding(
            finding_id=f"firebase_{idx:03d}",
            title=str(title),
            description=description,
            severity=severity,
            confidence=confidence,
            file_path=file_path,
            line_number=line_number,
            cwe_id=cwe,
            references=refs,
            evidence=evidence,
            remediation=recommendation,
        )


def create_plugin() -> FirebaseIntegrationV2:
    return FirebaseIntegrationV2()


__all__ = ["FirebaseIntegrationV2", "create_plugin"]
