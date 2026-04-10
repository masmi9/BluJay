"""EVRE Finalize Mixin – final cleanup and formatting of report data."""
from __future__ import annotations

from typing import Any, Dict, List


class EVREFinalizeMixin:
    def _finalize_report(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Final pass: clean up None values, truncate very long snippets."""
        findings = report_data.get("findings", [])
        for f in findings:
            # Truncate long code snippets
            snippet = f.get("code_snippet", "")
            if snippet and len(snippet) > 500:
                f["code_snippet"] = snippet[:497] + "..."
            context = f.get("evidence", {}).get("code_context", "")
            if context and len(context) > 2000:
                f["evidence"]["code_context"] = context[:1997] + "..."
        report_data["findings"] = findings
        return report_data
