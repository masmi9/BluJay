"""EVRE Report Generation Mixin – builds the final report data structure."""
from __future__ import annotations

import time
from typing import Any, Dict, List


class EVREReportGenMixin:
    def _build_report_data(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assemble the final report dict."""
        ipa_ctx = getattr(self, "ipa_ctx", None)
        severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        risk_score = self._compute_risk_score(severity_counts)

        return {
            "report_version": "1.0",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "scanner": "IODS",
            "scanner_version": "1.0.0",
            "app": ipa_ctx.summary() if ipa_ctx else {},
            "binary_security": {
                "pie": ipa_ctx.has_pie if ipa_ctx else None,
                "arc": ipa_ctx.has_arc if ipa_ctx else None,
                "stack_canary": ipa_ctx.has_stack_canary if ipa_ctx else None,
                "symbols_stripped": ipa_ctx.symbols_stripped if ipa_ctx else None,
                "bitcode": ipa_ctx.bitcode_enabled if ipa_ctx else None,
            } if ipa_ctx else {},
            "summary": {
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "risk_score": risk_score,
                "risk_level": self._risk_level(risk_score),
            },
            "findings": findings,
        }

    @staticmethod
    def _compute_risk_score(counts: Dict[str, int]) -> float:
        weights = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "info": 0.1}
        total = sum(counts.get(s, 0) * w for s, w in weights.items())
        return round(min(total, 100.0), 1)

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 50:
            return "CRITICAL"
        if score >= 25:
            return "HIGH"
        if score >= 10:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "NONE"
