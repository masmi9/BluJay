"""EVRE Pipeline Mixin – orchestrates all mixin stages."""
from __future__ import annotations

from typing import Any, Dict, List


class EVREPipelineMixin:
    def run_pipeline(self) -> Dict[str, Any]:
        """
        Execute the full EVRE pipeline:
          1. Init (source discovery, pattern loading)
          2. Pattern detection
          3. Merge with plugin findings
          4. Evidence enrichment
          5. Normalization
          6. Remediation attachment
          7. QA filtering (dedup, confidence)
          8. Report structure assembly
          9. Finalization
        """
        self._init_engine()

        # Pattern-based detection (EVRE patterns from YAML)
        pattern_findings = self._run_pattern_detection()

        # Merge with plugin findings
        plugin_findings = getattr(self, "findings", [])
        all_findings = plugin_findings + pattern_findings

        # Evidence enrichment
        all_findings = self._enrich_evidence(all_findings)

        # Normalize
        all_findings = self._normalize_findings(all_findings)

        # Remediation
        all_findings = self._attach_remediation(all_findings)

        # QA
        all_findings = self._apply_qa_filters(all_findings)

        # Build report
        report_data = self._build_report_data(all_findings)

        # Finalize
        report_data = self._finalize_report(report_data)

        return report_data
