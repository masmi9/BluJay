"""EVRE Vulnerability Creation Mixin – normalize and annotate findings."""
from __future__ import annotations

from typing import Any, Dict, List

_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


class EVREVulnCreationMixin:
    def _normalize_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize severity, ensure required fields, sort by severity."""
        normalized = []
        for f in findings:
            f.setdefault("finding_id", f"iods_{len(normalized):04d}")
            f.setdefault("title", "Unknown Vulnerability")
            f.setdefault("description", "")
            f.setdefault("severity", "info")
            f.setdefault("confidence", 0.8)
            f.setdefault("evidence", {})
            f.setdefault("references", [])

            # Normalize severity
            sev = str(f["severity"]).lower()
            if sev not in _SEVERITY_RANK:
                sev = "info"
            f["severity"] = sev

            # Add MASVS reference if available
            if f.get("masvs_control") and "references" not in f.get("evidence", {}):
                f.setdefault("references", [
                    f"https://mas.owasp.org/MASVS/controls/{f['masvs_control']}"
                ])

            normalized.append(f)

        # Sort: critical → high → medium → low → info
        normalized.sort(key=lambda x: _SEVERITY_RANK.get(x["severity"], 0), reverse=True)
        return normalized
