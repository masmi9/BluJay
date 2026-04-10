"""
IPAAnalyzer – coordinates extraction and plugin execution for an IPA.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logging_config import get_logger
from core.ipa.ipa_context import IPAContext
from core.ipa.ipa_extractor import IPAExtractor

logger = get_logger(__name__)


class IPAAnalyzer:
    """
    Top-level coordinator: extracts the IPA, runs plugins,
    and returns aggregated results for the EVRE reporting engine.
    """

    def __init__(self, ipa_ctx: IPAContext) -> None:
        self.ctx = ipa_ctx
        self.extractor = IPAExtractor(ipa_ctx)
        self.all_findings: List[Dict[str, Any]] = []

    def prepare(self) -> bool:
        """Extract the IPA and prepare for analysis. Returns True on success."""
        return self.extractor.extract()

    def run_static_plugins(self, plugin_manager) -> List[Dict[str, Any]]:
        """
        Run all selected static analysis plugins via the plugin manager.
        Returns list of normalized finding dicts.
        """
        results = plugin_manager.run_static_plugins(self.ctx)
        for r in results:
            self.all_findings.extend(r.get("findings", []))
        return self.all_findings

    def run_dynamic_plugins(self, plugin_manager) -> List[Dict[str, Any]]:
        """Run dynamic analysis plugins (requires device + Frida)."""
        results = plugin_manager.run_dynamic_plugins(self.ctx)
        for r in results:
            self.all_findings.extend(r.get("findings", []))
        return self.all_findings

    def get_findings(self) -> List[Dict[str, Any]]:
        return self.all_findings

    def get_summary(self) -> Dict[str, Any]:
        severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.all_findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        return {
            "ipa_context": self.ctx.summary(),
            "total_findings": len(self.all_findings),
            "severity_counts": severity_counts,
        }
