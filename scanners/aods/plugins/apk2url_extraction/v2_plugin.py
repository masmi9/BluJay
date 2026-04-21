#!/usr/bin/env python3
"""
apk2url_extraction - BasePluginV2 Implementation
=====================================================

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


class Apk2urlExtractionV2(BasePluginV2):
    """
    Apk2Url Extraction - BasePluginV2 Implementation
    """

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="apk2url_extraction",
            version="2.0.0",
            description="Apk2Url Extraction - Migrated to BasePluginV2",
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

            # Enrich findings with threat intelligence IoC lookups (best-effort)
            findings = self._enrich_with_threat_intel(apk_ctx, findings)

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

                current_module = importlib.import_module("plugins.apk2url_extraction")
                if hasattr(current_module, func_name):
                    return getattr(current_module, func_name)(apk_ctx)
            except (ImportError, AttributeError):
                pass

        # If no legacy function found, return empty result
        return []

    def _enrich_with_threat_intel(self, apk_ctx, findings: List[PluginFinding]) -> List[PluginFinding]:
        """
        Enrich findings with threat intelligence IoC lookups.

        Attempts to look up extracted IPs and domains against configured threat
        intelligence feeds. Best-effort - never breaks the plugin if threat
        intel is unavailable.
        """
        try:
            from core.unified_threat_intelligence import get_unified_threat_intelligence
        except ImportError:
            logger.debug("Threat intelligence system not available, skipping IoC enrichment")
            return findings

        try:
            threat_intel = get_unified_threat_intelligence()
            if not threat_intel or not threat_intel.threat_processor:
                return findings

            # Collect IPs and domains from cached extraction results
            indicators_to_check = set()
            cached_findings = None
            try:
                cached_findings = apk_ctx.get_cache("apk2url_findings")
            except Exception:
                pass

            if cached_findings and isinstance(cached_findings, dict):
                for ip in cached_findings.get("ips", []):
                    indicators_to_check.add(str(ip))
                for domain in cached_findings.get("domains", []):
                    indicators_to_check.add(str(domain))

            if not indicators_to_check:
                return findings

            # Look up each indicator against threat intel feeds
            threat_matches = {}
            for indicator in indicators_to_check:
                try:
                    results = threat_intel.threat_processor.lookup_ioc(indicator)
                    if results:
                        # Take the highest-confidence match
                        best = max(results, key=lambda r: getattr(r, "confidence", 0.0))
                        threat_matches[indicator] = {
                            "indicator": indicator,
                            "risk_score": getattr(best, "risk_score", 0.0),
                            "threat_type": getattr(best, "threat_type", "unknown"),
                            "source": getattr(best, "source", "unknown"),
                            "campaigns": getattr(best, "campaigns", []),
                        }
                except Exception as e:
                    logger.debug(f"Threat intel lookup failed for {indicator}: {e}")

            if not threat_matches:
                return findings

            # Enrich findings that reference matched indicators
            for finding in findings:
                desc = finding.description or ""
                title = finding.title or ""
                file_path = finding.file_path or ""
                search_text = f"{title} {desc} {file_path}"

                for indicator, match_data in threat_matches.items():
                    if indicator in search_text:
                        # Add threat intel match to finding evidence
                        if not hasattr(finding, "evidence") or finding.evidence is None:
                            finding.evidence = {}
                        if not isinstance(finding.evidence, dict):
                            finding.evidence = {}
                        finding.evidence["threat_intel_match"] = match_data
                        break  # One match per finding is sufficient

            logger.info(
                f"IoC enrichment complete: {len(threat_matches)} indicators matched "
                f"out of {len(indicators_to_check)} checked"
            )
        except Exception as e:
            logger.debug(f"Threat intel enrichment failed (non-fatal): {e}")

        return findings

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
                        finding_id="apk2url_extraction_001",
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
                finding_id=f"apk2url_extraction_{index:03d}",
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
                finding_id=f"apk2url_extraction_{index:03d}",
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


def create_plugin() -> Apk2urlExtractionV2:
    """Create plugin instance."""
    return Apk2urlExtractionV2()


__all__ = ["Apk2urlExtractionV2", "create_plugin"]
