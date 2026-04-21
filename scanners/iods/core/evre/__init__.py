"""
IODS Enhanced Vulnerability Reporting Engine (EVRE).

Composed from mixin modules following the same pattern as AODS EVRE.
"""
from __future__ import annotations

from typing import Any, Dict, List

from core.evre._init_mixin import EVREInitMixin
from core.evre._patterns_mixin import EVREPatternsMixin
from core.evre._evidence_mixin import EVREEvidenceMixin
from core.evre._vuln_creation_mixin import EVREVulnCreationMixin
from core.evre._remediation_mixin import EVRERemediationMixin
from core.evre._qa_mixin import EVREQAMixin
from core.evre._report_gen_mixin import EVREReportGenMixin
from core.evre._finalize_mixin import EVREFinalizeMixin
from core.evre._pipeline_mixin import EVREPipelineMixin


class IOSReportingEngine(
    EVREInitMixin,
    EVREPatternsMixin,
    EVREEvidenceMixin,
    EVREVulnCreationMixin,
    EVRERemediationMixin,
    EVREQAMixin,
    EVREReportGenMixin,
    EVREFinalizeMixin,
    EVREPipelineMixin,
):
    """
    iOS Enhanced Vulnerability Reporting Engine.

    Combines pattern detection, plugin findings, evidence enrichment,
    normalization, remediation, deduplication, and report generation.
    """

    def __init__(
        self,
        ipa_ctx,
        findings: List[Dict[str, Any]],
        config: Dict[str, Any],
    ) -> None:
        self.ipa_ctx = ipa_ctx
        self.findings = findings
        self.config = config

        # Initialized by EVREInitMixin
        self._source_files = []
        self._pattern_data = {}
        self._used_finding_ids: set = set()

    # `run_pipeline()` is provided by EVREPipelineMixin
