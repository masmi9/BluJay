"""EVRE Patterns Mixin – run configured patterns against source files."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List


class EVREPatternsMixin:
    def _run_pattern_detection(self) -> List[Dict[str, Any]]:
        """Run all configured patterns and return raw findings."""
        raw_findings: List[Dict[str, Any]] = []
        ipa_ctx = getattr(self, "ipa_ctx", None)
        if ipa_ctx is None:
            return raw_findings

        pattern_sections = self._pattern_data.get("patterns", {})
        for section_name, section in pattern_sections.items():
            if not isinstance(section, list):
                continue
            for pat in section:
                try:
                    matches = self._apply_pattern(pat, ipa_ctx)
                    raw_findings.extend(matches)
                except Exception:
                    pass
        return raw_findings

    def _apply_pattern(self, pat: Dict[str, Any], ipa_ctx) -> List[Dict[str, Any]]:
        pattern_str = pat.get("pattern", "")
        if not pattern_str:
            return []

        compiled = re.compile(pattern_str, re.IGNORECASE)
        results = []
        for match in ipa_ctx.source_files.search_pattern(pattern_str):
            pid = pat.get("id", "unknown")
            if pid in self._used_finding_ids:
                continue
            results.append({
                "finding_id": f"{pid}_{len(results)}",
                "title": pat.get("title", pid),
                "description": pat.get("description", ""),
                "severity": pat.get("severity", "medium").lower(),
                "confidence": pat.get("confidence", 0.8),
                "cwe_id": pat.get("cwe_id"),
                "masvs_control": pat.get("masvs_control"),
                "owasp_category": pat.get("owasp_category"),
                "vulnerability_type": pat.get("vulnerability_type", pid),
                "file_path": match.get("file"),
                "line_number": match.get("line_number"),
                "code_snippet": match.get("line"),
                "evidence": {"matched_line": match.get("line")},
                "remediation": pat.get("remediation"),
            })
        return results
