"""Enhanced Vulnerability Reporting Engine - decomposed into mixin modules.

This package composes the full EnhancedVulnerabilityReportingEngine from focused
mixin classes.  The original monolith (core/enhanced_vulnerability_reporting_engine.py)
is now a backward-compat re-export shim that imports from here.
"""

from core.evre._dataclasses import EnhancedVulnerabilityReport
from core.evre._dynamic_package_filter import DynamicPackageFilter
from core.evre._utils_mixin import UtilsMixin
from core.evre._init_mixin import InitMixin
from core.evre._patterns_mixin import PatternsMixin
from core.evre._evidence_mixin import EvidenceMixin
from core.evre._vuln_creation_mixin import VulnCreationMixin
from core.evre._remediation_mixin import RemediationMixin
from core.evre._report_gen_mixin import ReportGenMixin
from core.evre._qa_mixin import QAMixin
from core.evre._finalize_mixin import FinalizeMixin
from core.evre._pipeline_mixin import PipelineMixin


class EnhancedVulnerabilityReportingEngine(
    UtilsMixin,  # Must be first: _safe_extract used by all others
    InitMixin,  # __init__ lives here
    PatternsMixin,  # Pattern loading + detection
    EvidenceMixin,  # Code evidence extraction
    VulnCreationMixin,  # Vulnerability creation + descriptions
    RemediationMixin,  # Remediation generation
    ReportGenMixin,  # Report generation (exec summary, HTML, etc.)
    QAMixin,  # QA/filtering/dedup
    FinalizeMixin,  # Report finalization
    PipelineMixin,  # Main entry point: enhance_vulnerability_report
):
    """Full enhanced vulnerability reporting engine, composed from mixin modules."""


__all__ = [
    "EnhancedVulnerabilityReportingEngine",
    "EnhancedVulnerabilityReport",
    "DynamicPackageFilter",
]
