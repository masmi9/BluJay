#!/usr/bin/env python3
"""
enhanced_data_storage_modular - Structured Result Bridge (V2 Phase 2)
==========================================================================

Calls the legacy plugin's structured analysis method directly,
bypassing the (str, Text) formatter to preserve full field data.
"""

import time
from typing import List

import sys
from pathlib import Path

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


class EnhancedDataStorageModularV2(BasePluginV2):
    """Data storage security - PII detection, file perms, encryption (CWE-922/312)"""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="enhanced_data_storage_modular",
            version="3.0.0",
            description="Data storage security - PII detection, file perms, encryption (CWE-922/312)",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["storage", "pii", "masvs-storage-1", "cwe-922"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        try:
            findings = self._run_structured(apk_ctx)
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
            logger.error("enhanced_data_storage_modular failed: %s", e)
            return PluginResult(
                status=PluginStatus.FAILURE,
                findings=[],
                metadata={"error": type(e).__name__, "execution_time": time.time() - start_time},
            )

    def _run_structured(self, apk_ctx) -> List[PluginFinding]:
        """Call structured analysis and convert results to PluginFinding."""
        try:
            from plugins.enhanced_data_storage_modular import EnhancedDataStorageAnalyzer

            plugin = EnhancedDataStorageAnalyzer(apk_ctx)
            result = plugin.analyze()

            # Extract findings/vulnerabilities from result
            raw = getattr(result, "security_issues", None) or []
            if not raw:
                # Try alternative attribute names
                for attr in ("findings", "vulnerabilities", "security_findings", "security_issues"):
                    raw = getattr(result, attr, None)
                    if raw:
                        break
                if not raw:
                    raw = []

            findings = []
            for i, v in enumerate(raw):
                findings.append(self._convert_finding(v, i))
            return findings

        except Exception as e:
            logger.debug("Structured analysis failed, trying run_plugin: %s", e)
            try:
                from plugins.enhanced_data_storage_modular import run_plugin
                run_plugin(apk_ctx)
            except Exception:
                pass
            return []

    def _convert_finding(self, v, index: int) -> PluginFinding:
        """Convert a structured vulnerability/finding object to PluginFinding."""
        # Handle both dataclass objects and dicts
        if isinstance(v, dict):
            title = str(v.get("title", "Security Issue"))
            desc = str(v.get("description", ""))
            sev = str(v.get("severity", "medium"))
            conf = float(v.get("confidence", 0.5))
            loc = str(v.get("location", v.get("file_path", "unknown")))
            line = v.get("line_number")
            cwe = v.get("cwe_id", v.get("cwe", ""))
            remed = str(v.get("remediation", v.get("recommendation", "")))
            refs = v.get("references", [])
            evidence = v.get("evidence", {})
            snippet = v.get("code_snippet")
        elif isinstance(v, str):
            # String findings (from security_issues lists)
            return PluginFinding(
                finding_id=f"enhanced_data_storage_modular_{index:03d}",
                title=str(v)[:200],
                description=str(v)[:500],
                severity="medium",
                confidence=0.5,
                file_path="unknown",
                line_number=None,
                cwe_id=None,
            )
        else:
            title = str(getattr(v, "title", "Security Issue"))
            desc = str(getattr(v, "description", ""))
            sev = getattr(v, "severity", "medium")
            conf = float(getattr(v, "confidence", 0.5))
            loc = str(getattr(v, "location", getattr(v, "file_path", "unknown")))
            line = getattr(v, "line_number", None)
            cwe = getattr(v, "cwe_id", getattr(v, "cwe", ""))
            remed = str(getattr(v, "remediation", getattr(v, "recommendation", "")))
            refs = getattr(v, "references", [])
            evidence = getattr(v, "evidence", {})
            snippet = getattr(v, "code_snippet", None)

        # Normalize severity
        if hasattr(sev, "name"):
            sev = sev.name.lower()
        elif hasattr(sev, "value"):
            val = sev.value
            if isinstance(val, int):
                sev = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}.get(val, "medium")
            else:
                sev = str(val).lower()
        else:
            sev = str(sev).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "medium"

        # CWE inference if missing
        if not cwe:
            tl = (title + " " + desc).lower()
            if any(k in tl for k in ["pii", "personal"]):
                cwe = "CWE-359"
            elif any(k in tl for k in ["permission", "world"]):
                cwe = "CWE-732"
            elif any(k in tl for k in ["encrypt", "plain"]):
                cwe = "CWE-312"
            else:
                cwe = "CWE-922"

        # Evidence normalization
        if isinstance(evidence, str):
            evidence = {"description": evidence}
        elif not isinstance(evidence, dict):
            evidence = {}

        return PluginFinding(
            finding_id=f"enhanced_data_storage_modular_{index:03d}",
            title=title[:200],
            description=desc[:500],
            severity=sev,
            confidence=max(0.0, min(1.0, conf)),
            file_path=loc,
            line_number=line,
            cwe_id=str(cwe) if cwe else None,
            remediation=remed[:500] if remed else None,
            references=refs if isinstance(refs, list) else [],
            evidence=evidence,
            code_snippet=snippet,
        )


def create_plugin():
    return EnhancedDataStorageModularV2()


__all__ = ["EnhancedDataStorageModularV2", "create_plugin"]
