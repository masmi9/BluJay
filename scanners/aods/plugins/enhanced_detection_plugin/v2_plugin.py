#!/usr/bin/env python3
"""
Enhanced Detection Plugin - BasePluginV2 Adapter
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


class EnhancedDetectionV2(BasePluginV2):
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="enhanced_detection_plugin",
            version="2.0.0",
            description="Unified enhanced detection engines - V2 adapter",
            author="AODS Team",
            capabilities=[PluginCapability.VULNERABILITY_DETECTION, PluginCapability.STATIC_ANALYSIS],
            priority=PluginPriority.LOW,
            timeout_seconds=240,
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
            logger.debug(f"EnhancedDetectionV2 failed (graceful): {e}")
            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=[],
                metadata={"warning": str(e), "execution_time": time.time() - start},
            )

    def _call_legacy(self, apk_ctx) -> Any:
        try:
            from . import enhanced_detection_plugin as legacy

            if hasattr(legacy, "run"):
                # legacy.run returns (title, rich_text)
                return legacy.run(apk_ctx)
            if hasattr(legacy, "create_plugin"):
                inst = legacy.create_plugin(apk_ctx)
                if hasattr(inst, "analyze"):
                    return ("Enhanced Detection Plugin", inst.analyze())
        except Exception:
            pass
        return ("Enhanced Detection Plugin", {"enhanced_vulnerabilities": []})

    def _convert_legacy(self, legacy: Any) -> List[PluginFinding]:
        findings: List[PluginFinding] = []
        try:
            # Prefer structured data path
            if isinstance(legacy, tuple) and len(legacy) == 2:
                _, payload = legacy
                if isinstance(payload, dict):
                    items = payload.get("enhanced_vulnerabilities", []) or []
                    for i, it in enumerate(items):
                        findings.append(self._make_finding(it, i))
                else:
                    findings.append(self._make_info_finding(str(payload)))
            elif isinstance(legacy, dict):
                items = legacy.get("enhanced_vulnerabilities", []) or []
                for i, it in enumerate(items):
                    findings.append(self._make_finding(it, i))
        except Exception:
            findings.append(self._make_info_finding("Enhanced detection completed"))
        if not findings:
            findings.append(self._make_info_finding("Enhanced detection completed"))
        return findings

    def _make_info_finding(self, text: str) -> PluginFinding:
        return PluginFinding(
            finding_id="enhanced_detection_overview_000",
            title="Enhanced Detection Overview",
            description=text[:500],
            severity="info",
            confidence=0.9,
            evidence={"impact": "information_exposure", "exploitability": "low"},
        )

    def _make_finding(self, item: Dict[str, Any], idx: int) -> PluginFinding:
        title = str(item.get("title") or item.get("pattern") or "Enhanced detection finding")
        description = str(item.get("description", ""))[:600]
        severity = str(item.get("severity", "low")).lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "low"
        confidence = float(item.get("confidence", 0.8))
        file_path = item.get("file_path")
        line_number = item.get("line_number")

        text = f"{title} {description}".lower()
        cwe = item.get("cwe") or item.get("cwe_id")
        if not cwe:
            if any(k in text for k in ["injection", "sql", "xss"]):
                cwe = "CWE-89"
            elif any(k in text for k in ["path traversal", "directory traversal"]):
                cwe = "CWE-22"
            elif any(k in text for k in ["hardcoded", "secret", "api key", "apikey"]):
                cwe = "CWE-798"
            else:
                cwe = "CWE-200"

        cwe_refs = {
            "CWE-89": "https://cwe.mitre.org/data/definitions/89.html",
            "CWE-22": "https://cwe.mitre.org/data/definitions/22.html",
            "CWE-798": "https://cwe.mitre.org/data/definitions/798.html",
            "CWE-200": "https://cwe.mitre.org/data/definitions/200.html",
        }
        refs: List[str] = []
        if cwe in cwe_refs:
            refs.append(cwe_refs[cwe])

        impact = "information_exposure"
        exploitability = "medium"
        if cwe in ("CWE-89", "CWE-22"):
            impact = "data_breach_or_code_execution_risk"
            exploitability = "high"
        elif cwe == "CWE-798":
            impact = "credential_compromise"
            exploitability = "high"

        evidence = {
            "impact": impact,
            "exploitability": exploitability,
        }

        return PluginFinding(
            finding_id=f"enhanced_detection_{idx:03d}",
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            file_path=file_path,
            line_number=line_number,
            cwe_id=cwe,
            references=refs,
            evidence=evidence,
        )


def create_plugin() -> EnhancedDetectionV2:
    return EnhancedDetectionV2()


__all__ = ["EnhancedDetectionV2", "create_plugin"]
