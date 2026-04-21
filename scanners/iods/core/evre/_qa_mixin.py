"""EVRE QA Mixin – deduplication, filtering, and confidence thresholding."""
from __future__ import annotations

from typing import Any, Dict, List, Set


class EVREQAMixin:
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings based on (title, file_path, line_number)."""
        seen: Set[tuple] = set()
        deduplicated = []
        for f in findings:
            key = (
                f.get("title", ""),
                f.get("file_path", ""),
                f.get("line_number"),
            )
            if key not in seen:
                seen.add(key)
                deduplicated.append(f)
        return deduplicated

    def _filter_low_confidence(
        self, findings: List[Dict[str, Any]], min_confidence: float = 0.3
    ) -> List[Dict[str, Any]]:
        """Remove findings below minimum confidence, except critical/high."""
        result = []
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in ("critical", "high"):
                result.append(f)
            elif f.get("confidence", 1.0) >= min_confidence:
                result.append(f)
        return result

    def _apply_qa_filters(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = self._deduplicate_findings(findings)
        findings = self._filter_low_confidence(findings)
        return findings
