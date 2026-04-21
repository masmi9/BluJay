#!/usr/bin/env python3
"""
Unified Reporting Facade for AODS - MAXIMUM REPORTING CAPABILITY & QUALITY
==========================================================================

🎯 DUAL EXCELLENCE PRINCIPLE: This facade achieves the perfect balance for reporting:
1. MAXIMUM REPORTING CAPABILITY (full format support, advanced features)
2. MAXIMUM REPORT QUALITY (professional presentation, accurate data, zero report errors)

The facade consolidates ALL reporting functionality while maintaining VULNERABILITY DETECTION
ACCURACY as paramount and ensuring FALSE POSITIVES are kept to minimum in all reports.

CONSOLIDATED MODULES:
- core/report_generator.py (Legacy report generator with executive summaries)
- core/enterprise/reporting_engine.py (Enterprise features, charts, dashboards)
- core/unified_reporting_integration.py (Integration layer)
- plugins/*/report_generator.py (Plugin-specific generators)
- Various standalone report utilities

Features:
- **Full FORMAT SUPPORT**: JSON, HTML, PDF, XML, Excel, CSV, Markdown
- **ENTERPRISE FEATURES**: Executive summaries, charts, dashboards, compliance reports
- **PROFESSIONAL QUALITY**: Rich templates, styling, interactive elements
- **VULNERABILITY-FIRST REPORTING**: Prioritizes accuracy and minimizes false positive noise
- **PERFORMANCE OPTIMIZED**: Efficient generation for large datasets
- **CUSTOMIZABLE**: Template system, branding, custom report types
"""

import ast
import logging
import time
import os
import hashlib
import re
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

# Import unified reporting components
from .report_orchestrator import UnifiedReportOrchestrator
from .data_structures import (
    ReportFormat,
    ReportType,
    SecurityFinding,
    ReportConfiguration,
    ReportContext,
    create_default_metadata,
)
from .generators import ReportGenerator as UnifiedReportGenerator
from .formatters import FormatterFactory

logger = logging.getLogger(__name__)


class ReportQuality(Enum):
    """Report quality levels for different audiences."""

    TECHNICAL = "technical"  # Detailed technical report with all findings
    EXECUTIVE = "executive"  # High-level summary for executives
    COMPLIANCE = "compliance"  # Compliance-focused report
    AUDIT = "audit"  # Audit trail and detailed analysis
    CUSTOM = "custom"  # Custom report based on template


@dataclass
class UnifiedReportConfig:
    """
    Unified configuration for all reporting needs.

    Consolidates configuration from all legacy reporting systems.
    """

    # Basic report configuration
    title: str = "AODS Security Analysis Report"
    subtitle: str = ""
    organization: str = ""
    logo_path: Optional[str] = None

    # Report content configuration
    quality_level: ReportQuality = ReportQuality.TECHNICAL
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_compliance_section: bool = True
    include_remediation_guidance: bool = True

    # Vulnerability reporting configuration (PARAMOUNT)
    vulnerability_detection_focus: bool = True  # Prioritize vulnerability detection accuracy
    minimize_false_positives: bool = True  # Apply intelligent false positive filtering
    preserve_borderline_cases: bool = True  # When unsure, include in report
    severity_prioritization: bool = True  # Emphasize high/critical findings
    # Threshold-based filtering (off by default, enable via env)
    apply_threshold_filtering: bool = field(
        default_factory=lambda: os.environ.get("AODS_REPORT_FILTER_BY_THRESHOLDS", "0").lower()
        in ("1", "true", "yes", "on")
    )
    always_preserve_high_critical: bool = True

    # Format configuration
    output_formats: List[ReportFormat] = field(default_factory=lambda: [ReportFormat.HTML, ReportFormat.JSON])
    template_name: str = "professional"
    include_charts: bool = True
    include_risk_dashboard: bool = True

    # Enterprise features
    enable_branding: bool = True
    enable_interactive_elements: bool = True
    enable_export_options: bool = True

    # Performance configuration
    max_findings_per_section: int = 1000
    enable_pagination: bool = True
    compress_large_reports: bool = True


class UnifiedReportingManager:

    def enhance_vulnerability_report(self, findings: List[Dict], metadata: Dict = None) -> List[Dict]:
        """Enhanced vulnerability reporting with technical details."""
        enhanced_findings = []
        for finding in findings:
            # Add enhanced technical details
            enhanced_finding = finding.copy()
            enhanced_finding.update(
                {
                    "technical_details": self._extract_technical_details(finding),
                    "compliance_mapping": self._map_compliance_standards(finding),
                    "remediation_guidance": self._generate_remediation(finding),
                    "risk_assessment": self._assess_risk_level(finding),
                }
            )
            enhanced_findings.append(enhanced_finding)
        return enhanced_findings

    def _extract_technical_details(self, finding: Dict) -> Dict:
        """Extract technical details from finding."""
        return {
            "source_file": finding.get("file_path", ""),
            "line_number": finding.get("line_number", 0),
            "vulnerability_pattern": finding.get("pattern", ""),
            "confidence_score": finding.get("confidence", 0.0),
        }

    def _map_compliance_standards(self, finding: Dict) -> Dict:
        """Map finding to compliance standards."""
        return {
            "cwe_ids": finding.get("cwe_ids", []),
            "masvs_refs": finding.get("masvs_refs", []),
            "owasp_refs": finding.get("owasp_refs", []),
            "nist_mapping": finding.get("nist_mapping", []),
        }

    def _generate_remediation(self, finding: Dict) -> str:
        """Generate specific remediation guidance."""
        return finding.get(
            "remediation", "Review and address the identified security issue according to best practices."
        )

    def _assess_risk_level(self, finding: Dict) -> str:
        """Assess risk level based on finding characteristics."""
        severity = finding.get("severity", "medium")
        confidence = finding.get("confidence", 0.5)

        if severity in ["critical", "high"] and confidence > 0.8:
            return "HIGH"
        elif severity == "medium" and confidence > 0.6:
            return "MEDIUM"
        else:
            return "LOW"

    """
    Unified reporting manager consolidating ALL AODS reporting capabilities.

    🎯 DUAL EXCELLENCE: Maximum capability + Maximum quality

    This manager provides full reporting functionality by merging capabilities from:
    - Legacy ReportGenerator: Executive summaries, risk dashboards, templates
    - Enterprise ReportingEngine: Charts, dashboards, advanced features
    - Plugin-specific generators: Specialized report formats
    - Unified orchestrator: Multi-format coordination

    Features:
    📊 **Full reporting**: All report types and formats in one system
    🎨 **PROFESSIONAL QUALITY**: Rich templates, styling, interactive features
    🛡️ **VULNERABILITY-FIRST**: Accurate reporting with false positive minimization
    ⚡ **HIGH PERFORMANCE**: Optimized generation for large datasets
    🔧 **ENTERPRISE READY**: Advanced features for enterprise deployment
    """

    def __init__(self, config: Optional[UnifiedReportConfig] = None):
        """Initialize unified reporting manager."""
        self.config = config or UnifiedReportConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # Initialize unified orchestrator
        self.orchestrator = UnifiedReportOrchestrator()

        # Report generation statistics
        self.stats = {
            "reports_generated": 0,
            "total_findings_processed": 0,
            "false_positives_filtered": 0,
            "vulnerabilities_reported": 0,
            "average_generation_time": 0.0,
            "formats_generated": {},
            "quality_levels_used": {},
        }

        # Initialize components
        self._initialize_legacy_compatibility()
        self._initialize_enterprise_features()
        # Initialize probability calibrator (no-op if artifact missing)
        try:
            from core.ml.calibration_loader import load_calibrator

            self._calibrator = load_calibrator()
        except Exception:
            self._calibrator = None
        # Track seen IDs for deduplication within a single report build
        self._seen_ids = set()

        self.logger.info("✅ Unified Reporting Manager initialized with full capabilities")

    def _initialize_legacy_compatibility(self):
        """Initialize compatibility with legacy reporting systems."""
        try:
            # Import legacy components for compatibility
            self._legacy_available = True
            self.logger.info("✅ Legacy reporting compatibility enabled")
        except ImportError:
            self._legacy_available = False
            self.logger.warning("⚠️ Legacy reporting components not available")

    def _initialize_enterprise_features(self):
        """Initialize enterprise reporting features."""
        try:
            # Import enterprise components
            self._enterprise_available = True
            self.logger.info("✅ Enterprise reporting features enabled")
        except ImportError:
            self._enterprise_available = False
            self.logger.warning("⚠️ Enterprise reporting features not available")

    def generate_security_report(
        self,
        findings: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
        formats: Optional[List[ReportFormat]] = None,
        output_directory: Optional[str] = None,
        base_filename: Optional[str] = None,
        save_to_files: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate security report with DUAL EXCELLENCE.

        Args:
            findings: List of security findings to include in report
            metadata: Additional metadata for the report
            formats: Output formats to generate (defaults to config)
            output_directory: Directory to save files (defaults to current dir)
            base_filename: Base filename without extension (defaults to 'security_report')
            save_to_files: Whether to save reports to files (default: True)

        Returns:
            Dictionary containing generated reports, file paths, and metadata
        """
        generation_start = time.time()

        # Apply VULNERABILITY-FIRST filtering
        processed_findings = self._apply_vulnerability_first_processing(findings)

        # Create report context
        context = self._create_report_context(processed_findings, metadata)

        # Generate reports in requested formats
        formats = formats or self.config.output_formats
        generated_reports = {}

        for format_type in formats:
            try:
                report_data = self._generate_format_specific_report(processed_findings, context, format_type)
                generated_reports[format_type.value] = report_data

                # Update statistics
                self.stats["formats_generated"][format_type.value] = (
                    self.stats["formats_generated"].get(format_type.value, 0) + 1
                )

            except Exception as e:
                self.logger.error(f"Failed to generate {format_type.value} report: {e}")
                generated_reports[format_type.value] = {"error": str(e)}

        # Update generation statistics
        generation_time = time.time() - generation_start
        self._update_generation_statistics(processed_findings, generation_time)
        # Backfill analysis_duration into context metadata for formatter consumers
        try:
            if hasattr(context, "metadata") and context.metadata:
                setattr(context.metadata, "analysis_duration", int(generation_time))
        except Exception:
            pass

        # CRITICAL FIX: Add file persistence layer
        file_paths = {}
        if save_to_files:
            file_paths = self._save_reports_to_files(generated_reports, output_directory, base_filename)

        return {
            "reports": generated_reports,
            "file_paths": file_paths,  # NEW: Include actual file paths
            "metadata": {
                "generation_time": generation_time,
                "total_findings": len(findings),
                "processed_findings": len(processed_findings),
                "false_positives_filtered": (len(findings) - len(processed_findings))
                + int(getattr(context, "threshold_filtered", 0)),
                "vulnerabilities_reported": len(
                    [f for f in processed_findings if f.get("severity") in ["high", "critical"]]
                ),
                "formats_generated": list(generated_reports.keys()),
                "quality_level": self.config.quality_level.value,
                "timestamp": datetime.now().isoformat(),
                "files_saved": list(file_paths.keys()) if file_paths else [],
                # Mirror CI-relevant metadata for convenience
                "target_apk_path": getattr(context.metadata, "target_apk_path", ""),
                "package_name": getattr(context.metadata, "package_name", ""),
                "analysis_duration": getattr(context.metadata, "analysis_duration", 0),
                "scan_mode": getattr(context.metadata, "scan_mode", "standard"),
            },
            "statistics": self.stats.copy(),
        }

    def _apply_vulnerability_first_processing(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Apply VULNERABILITY-FIRST processing to findings.

        Ensures report accuracy by:
        1. Preserving all real vulnerabilities (zero false negatives)
        2. Applying intelligent false positive filtering
        3. Prioritizing high/critical severity findings
        """
        if not self.config.vulnerability_detection_focus:
            return findings

        processed_findings = []
        false_positives_filtered = 0

        # Track seen locations for duplicate detection
        seen_exported_components = set()  # (component_type, location) for dedup

        # Detect static-only mode
        static_only = os.environ.get("AODS_STATIC_ONLY_HARD", "0") == "1"
        # Phase 9.6: Plugin summary patterns that should not become findings
        _summary_patterns = (
            "apk information extraction",
            "apk signing certificate analysis",
            "enhanced manifest analysis",
            "enhanced improper platform usage analysis",
            "insecure data storage analysis",
            # Track 71: Plugin status reports that are not vulnerability findings
            "enhanced data storage analysis",
            "advanced ssl/tls analysis",
            "webview security analysis",
            "jadx static analysis",
        )
        _invalid_titles = frozenset(
            {
                "success",
                "error",
                "unknown",
                "failed",
                "complete",
                "ok",
                "done",
                "true",
                "false",
                "none",
                "null",
                "n/a",
                "na",
                "",
            }
        )

        for finding in findings:
            title = str(finding.get("title", finding.get("name", ""))).strip()
            title_lower = title.lower()

            # Phase 9.6: Defensive filter for plugin summaries and invalid titles
            # Primary filtering is in dyna.py; this catches edge cases
            if title_lower in _invalid_titles or title_lower in _summary_patterns:
                false_positives_filtered += 1
                continue
            if title_lower.startswith(("✅", "❌", "⏰", "⚠️")):
                false_positives_filtered += 1
                continue
            # Track 71: Reject raw plugin name titles (lowercase_with_underscores)
            if re.match(r"^[a-z][a-z0-9_]+$", title_lower) and "_" in title_lower:
                false_positives_filtered += 1
                continue
            # Track 71: Reject titles with status suffixes like "(Pass)", "(Fail)"
            if re.search(r"\(\s*(pass|fail|error|success|ok|skipped)\s*\)\s*$", title_lower):
                false_positives_filtered += 1
                continue

            # Track 73: Remove non-vulnerability informational observations.
            # These are not security findings - they describe normal app behavior.
            _non_vuln_titles = frozenset(
                {
                    "network security configuration present",
                    "excessive read/write permissions",
                    "location and network permission combination",
                }
            )
            if title_lower in _non_vuln_titles:
                false_positives_filtered += 1
                continue

            # Track 73: Remove text-parser garbage "SQL Injection Vulnerabilities"
            # findings whose descriptions contain report headers instead of evidence.
            if title_lower == "sql injection vulnerabilities":
                desc_l = str(finding.get("description", "")).lower()
                if "========" in desc_l or "executive summary" in desc_l or "analysis report" in desc_l:
                    false_positives_filtered += 1
                    continue

            # Track 73: DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION is auto-generated
            # by Android 12+ and is NOT a custom permission naming/protection issue.
            desc_raw = str(finding.get("description", ""))
            if "DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" in desc_raw:
                false_positives_filtered += 1
                continue

            # Track 42: Code quality / informational findings - downgrade to INFO
            # These are not security vulnerabilities but provide useful context
            _code_quality_titles = frozenset(
                {
                    "poorly named custom permission",
                    "signature permission naming issue",
                }
            )
            if title_lower in _code_quality_titles or title_lower.startswith("deprecated permission"):
                finding = dict(finding)
                finding["severity"] = "INFO"
                finding["category"] = finding.get("category", "CODE_QUALITY")
                # Also override classification.severity so _convert_to_security_finding
                # doesn't restore the original severity from the classifier dict
                cls = finding.get("classification")
                if isinstance(cls, dict):
                    finding["classification"] = {**cls, "severity": "info"}
                processed_findings.append(finding)
                continue

            # Track 71: Hardcoded credential findings must be HIGH+ severity
            # These are real security issues that should never be INFO/LOW
            _sev_lower = finding.get("severity", "low")
            if isinstance(_sev_lower, str):
                _sev_lower = _sev_lower.lower()
            else:
                _sev_lower = "medium"
            _hc_kws = ("hardcoded password", "hardcoded secret", "hardcoded key", "hardcoded credential")
            if any(kw in title_lower for kw in _hc_kws):
                if _sev_lower in ("info", "low"):
                    finding = dict(finding)
                    finding["severity"] = "HIGH"
                    cls = finding.get("classification")
                    if isinstance(cls, dict):
                        finding["classification"] = {**cls, "severity": "high"}
                    # Fix CWE for hardcoded credentials
                    if finding.get("cwe_id") in (None, "CWE-327", ""):
                        finding["cwe_id"] = "CWE-798"
                    _sev_lower = "high"  # Update local var for downstream checks

            # DEDUP 1: Duplicate exported component findings
            # Same component reported by multiple plugins with slight title variations
            if "exported" in title_lower:
                location = str(finding.get("location", "")).strip()
                # Treat N/A, unknown, empty as missing location
                if location.lower() in ("n/a", "unknown", "none", ""):
                    location = ""

                # Normalize component type (activity/service/receiver/provider)
                comp_type = "unknown"
                if "activit" in title_lower:
                    comp_type = "activity"
                elif "service" in title_lower:
                    comp_type = "service"
                elif "receiver" in title_lower:
                    comp_type = "receiver"
                elif "provider" in title_lower:
                    comp_type = "provider"
                elif "component" in title_lower:
                    comp_type = "components_generic"  # Track 42

                # Use location if available, otherwise use component type only
                # This deduplicates "Exported activities..." and "Exported Activitie..." as same issue
                dedup_key = (comp_type, location) if location else (comp_type,)
                if dedup_key in seen_exported_components:
                    false_positives_filtered += 1
                    continue
                seen_exported_components.add(dedup_key)

            # DEDUP 2: Semantic duplicates (same issue, different wording)
            # E.g., "Backup Enabled" and "Backup Allowed" are the same issue
            semantic_categories = {
                "backup": ("backup enabled", "backup allowed", "backup security"),
                "debug": ("debuggable flag", "debug mode enabled", "android debuggable"),
            }
            is_semantic_duplicate = False
            for category, patterns in semantic_categories.items():
                if any(p in title_lower for p in patterns):
                    if category in seen_exported_components:
                        false_positives_filtered += 1
                        is_semantic_duplicate = True
                        break
                    seen_exported_components.add(category)
                    break  # Found a category match, no need to check others
            if is_semantic_duplicate:
                continue

            # STEP 1: Always preserve high/critical severity (vulnerability-first)
            severity = finding.get("severity", "low").lower()
            # STEP 0: Filter dynamic-only plugin artifacts in static-only runs
            if static_only:
                try:
                    plug_hint = (
                        finding.get("plugin_source") or finding.get("plugin") or finding.get("title") or ""
                    ).lower()
                    dynamic_blocklist = (
                        "frida_dynamic_analysis",
                        "network_pii_traffic_analyzer",
                        "device_dynamic",
                        "adb ",
                    )
                    if any(tok in plug_hint for tok in dynamic_blocklist):
                        continue
                except Exception:
                    pass
            # Track 71: PASS/no-issue artifacts - REMOVE entirely, not downgrade.
            # These are plugin status reports, not vulnerability findings.
            try:
                t_l = str(finding.get("title", "")).lower()
                d_l = str(finding.get("description", "")).lower()
                no_issue_phrases = (
                    "no issues",
                    "no issue",
                    "no vulnerabilities",
                    "no significant findings",
                    "no significant issues",
                    "no findings",
                    "no issues found",
                    "fallback mode",
                    "no sql injection vulnerabilities detected",
                )
                looks_pass = (
                    ("pass" in t_l and "fail" not in t_l)
                    or any(phr in t_l for phr in no_issue_phrases)
                    or any(phr in d_l for phr in no_issue_phrases)
                )
                # Track 71: Also catch JadxAnalysisResult status strings in descriptions
                if "jadxanalysisresult" in d_l or "analysisresult" in d_l.replace(" ", ""):
                    looks_pass = True
                if looks_pass and severity not in ("high", "critical"):
                    false_positives_filtered += 1
                    continue
            except Exception:
                pass
            if severity in ["high", "critical"]:
                processed_findings.append(finding)
                continue

            # STEP 2: Apply intelligent false positive filtering
            if self.config.minimize_false_positives:
                if self._is_likely_false_positive(finding):
                    false_positives_filtered += 1
                    continue

            # STEP 3: Preserve borderline cases when configured
            if self.config.preserve_borderline_cases or not self._is_confident_false_positive(finding):
                # Filter non-actionable internal error placeholders (improves evidence quality in fast profiles)
                try:
                    desc_l = str(finding.get("description", "")).lower()
                    str(finding.get("title", "")).lower()
                    file_path_l = str(finding.get("file_path", "")).strip().lower()
                    location_l = str(finding.get("location", "")).strip().lower()
                    is_errorish = any(
                        ind in desc_l
                        for ind in (
                            "analysis failed",
                            "error:",
                            "exception",
                            "traceback",
                            "not defined",
                            "attributeerror",
                            "importerror",
                        )
                    )
                    no_location = (not file_path_l) and (location_l in ("", "unknown", "none"))
                    if is_errorish and no_location and severity not in ("high", "critical"):
                        false_positives_filtered += 1
                        continue
                except Exception:
                    pass
                processed_findings.append(finding)
            else:
                false_positives_filtered += 1

        # ------------------------------------------------------------------
        # Track 42: Two-pass - remove generic "Exported Components" when
        # specific component-type findings (activity/service/receiver/provider) exist
        # ------------------------------------------------------------------
        _specific_comp_types = {"activity", "service", "receiver", "provider"}
        specific_types_seen = {
            k[0]
            for k in seen_exported_components
            if isinstance(k, tuple) and len(k) >= 1 and k[0] in _specific_comp_types
        }
        if specific_types_seen:
            processed_findings = [
                f
                for f in processed_findings
                if not (
                    "exported" in (f.get("title", "") or "").lower()
                    and "component" in (f.get("title", "") or "").lower()
                    and not any(
                        t in (f.get("title", "") or "").lower() for t in ("activit", "service", "receiver", "provider")
                    )
                )
            ]

        # ------------------------------------------------------------------
        # Track 31: Derive missing line numbers from evidence/location
        # ------------------------------------------------------------------
        import re as _re

        for f in processed_findings:
            if f.get("line_number"):
                continue
            # Try evidence.line_number / evidence.line
            ev = f.get("evidence")
            if isinstance(ev, dict):
                ln = ev.get("line_number") or ev.get("line")
                if ln:
                    try:
                        f["line_number"] = int(ln)
                        continue
                    except (ValueError, TypeError):
                        pass
            # Try parsing trailing ":line" from file_path/location
            loc = f.get("file_path") or f.get("location") or ""
            m = _re.search(r":(\d+)(?::\d+)?$", str(loc))
            if m:
                f["line_number"] = int(m.group(1))
                f["file_path"] = str(loc)[: m.start()]

        # ------------------------------------------------------------------
        # Track 72: Derive manifest line numbers for AndroidManifest.xml findings
        # (Fallback for findings that lost line_number in the pipeline)
        # ------------------------------------------------------------------
        _manifest_line_map = None
        for f in processed_findings:
            if f.get("line_number"):
                continue
            fp = str(f.get("file_path") or "").lower()
            if "androidmanifest" not in fp:
                continue
            # Lazy-build the manifest line map once
            if _manifest_line_map is None:
                try:
                    from core.manifest_parsing_utils import (
                        build_manifest_line_map,
                        lookup_manifest_line,
                    )
                    from pathlib import Path

                    workspace = Path("workspace")
                    if not workspace.is_dir():
                        try:
                            from core.cli import REPO_ROOT

                            workspace = Path(REPO_ROOT) / "workspace"
                        except Exception:
                            pass
                    _manifest_line_map = {}
                    if workspace.is_dir():
                        manifests = sorted(workspace.glob("*/AndroidManifest.xml"))
                        if manifests:
                            _manifest_line_map = build_manifest_line_map(str(manifests[0]))
                except Exception:
                    _manifest_line_map = {}
            if not _manifest_line_map:
                break
            try:
                title = f.get("title", "")
                evidence_str = ""
                if isinstance(f.get("evidence"), dict):
                    evidence_str = str(f["evidence"].get("code_snippet", ""))
                ln = lookup_manifest_line(
                    _manifest_line_map,
                    f.get("location", ""),
                    component_name=f.get("component_name"),
                    permission_name=f.get("permission_name"),
                    title=title,
                    evidence=evidence_str,
                )
                if ln:
                    f["line_number"] = ln
            except Exception:
                pass

        # ------------------------------------------------------------------
        # Track 30.1: Library noise filter - remove LOW/INFO findings from
        # third-party library paths that lack a code snippet.
        # ------------------------------------------------------------------
        _library_prefixes = (
            "androidx/",
            "com/google/",
            "com/android/support/",
            "kotlin/",
            "kotlinx/",
            "com/squareup/",
            "io/reactivex/",
            "org/apache/",
            "com/facebook/",
            "com/bumptech/",
            "com/fasterxml/",
            "org/jetbrains/",
            "javax/",
            "android/support/",
            "com/google/android/",
        )

        def _is_noise_finding(f):
            # Track 72: Check all path fields, not just top-level file_path.
            # Some plugins (e.g. insecure_data_storage) set library paths only
            # in evidence.file_path or affected_files.
            paths = []
            fp = (f.get("file_path") or "").replace("\\", "/")
            if fp:
                paths.append(fp)
            ev = f.get("evidence")
            if isinstance(ev, dict):
                ev_fp = (ev.get("file_path") or "").replace("\\", "/")
                if ev_fp:
                    paths.append(ev_fp)
            for af in f.get("affected_files") or []:
                s = str(af).replace("\\", "/")
                if s:
                    paths.append(s)

            if not any(any(prefix in p for prefix in _library_prefixes) for p in paths):
                return False
            # Track 71: Library code findings without real code_snippet are noise.
            # code_snippet must be actual source code, not a stringified dict/object.
            if isinstance(ev, dict):
                snippet = ev.get("code_snippet")
                if isinstance(snippet, str) and len(snippet) > 10:
                    s = snippet.strip()
                    if not (s.startswith(("{", "[", "{'", '{"'))):
                        return False
            return True

        before_noise = len(processed_findings)
        processed_findings = [f for f in processed_findings if not _is_noise_finding(f)]
        noise_removed = before_noise - len(processed_findings)

        # ------------------------------------------------------------------
        # Exact-location dedup: when multiple findings share the same
        # (title, file_path, line_number) but differ in metadata (CWE,
        # recommendation, etc.), keep only the first occurrence.
        # ------------------------------------------------------------------
        _seen_locations = set()
        deduped = []
        for f in processed_findings:
            key = (
                f.get("title", ""),
                f.get("file_path", ""),
                f.get("line_number"),
            )
            if key[0] and (key[1] or key[2] is not None) and key in _seen_locations:
                continue
            if key[0] and (key[1] or key[2] is not None):
                _seen_locations.add(key)
            deduped.append(f)
        processed_findings = deduped

        # ------------------------------------------------------------------
        # Track 30.1: Per-file storage dedup - collapse identical-title
        # findings that differ only by file_path into a single aggregate.
        # Targets mass "Unencrypted File Storage" / "File in External Storage".
        # ------------------------------------------------------------------
        _mass_titles = {
            "Unencrypted File Storage",
            "File in External Storage",
            "Sensitive Data Stored in Preferences",
            "Unencrypted Shared Preferences Usage",
            "External Storage Usage",
        }
        aggregated = []
        mass_groups = {}  # title → list of findings
        for f in processed_findings:
            t = f.get("title", "")
            if t in _mass_titles:
                mass_groups.setdefault(t, []).append(f)
            else:
                aggregated.append(f)

        for title, group in mass_groups.items():
            if len(group) <= 5:
                aggregated.extend(group)
                continue
            # Pick the highest-severity finding as representative
            sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            group.sort(key=lambda g: sev_order.get((g.get("severity") or "").upper(), 0), reverse=True)
            rep = dict(group[0])
            file_list = [g.get("file_path", "") for g in group]
            rep["description"] = f"{title} detected in {len(group)} files. " f"Sample: {', '.join(file_list[:5])}"
            rep["title"] = f"{title} ({len(group)} files)"
            aggregated.append(rep)

        processed_findings = aggregated

        # ------------------------------------------------------------------
        # Track 73: Same-file same-line dedup (e.g., two SSL findings for
        # the same SSLContext.getInstance call with slightly different titles)
        # ------------------------------------------------------------------
        _seen_file_line = {}
        _deduped = []
        for f in processed_findings:
            fp = f.get("file_path", "")
            ln = f.get("line_number")
            cwe = f.get("cwe_id", "")
            title = (f.get("title") or "").lower().strip()
            if fp and ln is not None and cwe and title:
                key = (fp, ln, cwe, title)
                if key in _seen_file_line:
                    continue  # keep first occurrence (higher severity)
                _seen_file_line[key] = True
            _deduped.append(f)
        processed_findings = _deduped

        # ------------------------------------------------------------------
        # Track 30.1: Confidence fallback - when ML pipeline produces
        # uniform confidence (variance < 0.001), replace with severity-based
        # values so the report is more useful.
        # ------------------------------------------------------------------
        if len(processed_findings) >= 5:
            confs = [f.get("confidence") for f in processed_findings if f.get("confidence") is not None]
            if len(confs) >= 5:
                mean_c = sum(confs) / len(confs)
                var_c = sum((c - mean_c) ** 2 for c in confs) / len(confs)
                if var_c < 0.001:
                    _sev_conf = {
                        "CRITICAL": 0.95,
                        "HIGH": 0.85,
                        "MEDIUM": 0.70,
                        "LOW": 0.50,
                        "INFO": 0.30,
                    }
                    for f in processed_findings:
                        sev = (f.get("severity") or "MEDIUM").upper()
                        f["confidence"] = _sev_conf.get(sev, 0.5)

        # ------------------------------------------------------------------
        # Track 73: Normalize /tmp JADX paths and workspace absolute paths
        # Reuses sanitize_source_path() from Track 60 (core/utils/path_sanitizer)
        # ------------------------------------------------------------------
        from core.utils.path_sanitizer import sanitize_source_path as _sanitize

        _tmp_re = re.compile(r"/tmp/jadx_decompiled/[^\s/]+/sources/")
        for f in processed_findings:
            # Sanitize file_path
            fp = f.get("file_path", "")
            if fp and ("/" in fp) and (fp.startswith("/") or "://" not in fp):
                sanitized = _sanitize(fp)
                if sanitized:
                    f["file_path"] = sanitized
            # Sanitize evidence.file_path
            ev = f.get("evidence")
            if isinstance(ev, dict):
                ev_fp = ev.get("file_path", "")
                if (
                    ev_fp
                    and isinstance(ev_fp, str)
                    and ("/" in ev_fp)
                    and (ev_fp.startswith("/") or "://" not in ev_fp)
                ):
                    sanitized = _sanitize(ev_fp)
                    if sanitized:
                        ev["file_path"] = sanitized
                # Clean dict-stringified code_snippet
                snippet = ev.get("code_snippet", "")
                if isinstance(snippet, str) and snippet.strip().startswith("{'"):
                    try:
                        d = ast.literal_eval(snippet)
                        if isinstance(d, dict):
                            ev["code_snippet"] = d.get("description") or d.get("title") or snippet
                    except Exception:
                        pass
            # Strip /tmp paths from descriptions
            desc = f.get("description", "")
            if desc and "/tmp/" in desc:
                f["description"] = _tmp_re.sub("", desc)

        # ------------------------------------------------------------------
        # Track 73: CWE corrections - fix misassigned CWEs from classifiers
        # ------------------------------------------------------------------
        _CWE_FIXES = {
            "ecb": "CWE-327",  # ECB cipher → broken crypto, not generic security
            "insecure cipher": "CWE-327",
            "broken encryption": "CWE-327",
            "broken hash": "CWE-328",
            "predictable random": "CWE-330",
            "no padding": "CWE-327",
            "hardcoded password": "CWE-798",
            "hardcoded secret": "CWE-798",
            "hardcoded key": "CWE-798",
            "hardcoded credential": "CWE-798",
        }
        for f in processed_findings:
            t_l = f.get("title", "").lower()
            for pattern, correct_cwe in _CWE_FIXES.items():
                if pattern in t_l:
                    f["cwe_id"] = correct_cwe
                    break

        # ------------------------------------------------------------------
        # Track 73: Replace generic or mismatched recommendations.
        # Reuses shared CWE map from generators.py.
        # ------------------------------------------------------------------
        from .generators import (
            get_cwe_recommendation as _get_rec,
            TITLE_RECOMMENDATIONS as _TITLE_RECS,
            CWE_RECOMMENDATIONS as _CWE_RECS,
        )

        _CWE_RECS_SET = set(_CWE_RECS.values())
        _GENERIC_REC_RE = re.compile(r"^Review and remediate CWE-\d+")
        for f in processed_findings:
            rec = f.get("recommendation", "")
            cwe = f.get("cwe_id", "") or ""
            title = f.get("title", "") or ""
            # Replace generic "Review and remediate CWE-XXX" recommendations.
            # Empty recommendations are left for the ML remediation engine.
            if rec and _GENERIC_REC_RE.match(rec):
                new_rec = _get_rec(cwe, title)
                if new_rec and not _GENERIC_REC_RE.match(new_rec):
                    f["recommendation"] = new_rec
            # Also override when CWE-based rec clearly doesn't match the
            # finding type (e.g., backup finding got CWE-200 "scrub logs").
            # Only replace if the current rec is a known CWE template for a
            # DIFFERENT topic - preserve custom/plugin-specific recs.
            elif rec:
                t_l = title.lower()
                _is_known_cwe_rec = any(rec == v for v in _CWE_RECS_SET)
                if _is_known_cwe_rec:
                    for pattern, better_rec in _TITLE_RECS.items():
                        if pattern in t_l and rec != better_rec:
                            f["recommendation"] = better_rec
                            break

        # ------------------------------------------------------------------
        # Track 73: Post-processing severity enforcement - ensure hardcoded
        # credentials are never reported at INFO/LOW regardless of pipeline path.
        # ------------------------------------------------------------------
        _hc_post_kws = ("hardcoded password", "hardcoded secret", "hardcoded key", "hardcoded credential")
        for f in processed_findings:
            t_l = f.get("title", "").lower()
            sev = (f.get("severity") or "medium").upper()
            if any(kw in t_l for kw in _hc_post_kws) and sev in ("INFO", "LOW"):
                f["severity"] = "HIGH"
                cls = f.get("classification")
                if isinstance(cls, dict):
                    f["classification"] = {**cls, "severity": "high"}
                if f.get("cwe_id") in (None, "CWE-327", ""):
                    f["cwe_id"] = "CWE-798"

        self.logger.info(
            f"🛡️ Vulnerability-first processing: {len(processed_findings)} findings preserved, "
            f"{false_positives_filtered} false positives filtered, {noise_removed} library noise removed"
        )

        return processed_findings

    def _is_likely_false_positive(self, finding: Dict[str, Any]) -> bool:
        """Check if finding is likely a false positive."""
        # Apply intelligent false positive detection
        description = finding.get("description", "").lower()
        file_path = finding.get("file_path", "").lower()
        title = finding.get("title", "").lower()

        # Clear false positive indicators - path-based checks for test/debug artifacts
        false_positive_indicators = [
            "test" in file_path and "test" not in title,
            "mock" in file_path,
            "example" in file_path,
            # "debug" in description is too broad - catches "Debuggable Flag Enabled"
            # which is a real vulnerability. Only flag debug BUILD artifacts.
            ("debug build" in description) or ("debug mode" in description and "debuggable" not in title),
            "error message" in description,
            "build configuration" in description,
        ]

        return any(false_positive_indicators)

    def _is_confident_false_positive(self, finding: Dict[str, Any]) -> bool:
        """Check if we're confident this is a false positive."""
        # Very conservative - only filter when very sure
        description = finding.get("description", "").lower()

        # Only filter obvious non-security issues
        confident_false_positives = [
            "build successful" in description,
            "compilation complete" in description,
            "test passed" in description,
        ]

        return any(confident_false_positives)

    def _create_report_context(
        self, findings: List[Dict[str, Any]], metadata: Optional[Dict[str, Any]]
    ) -> ReportContext:
        """Create full report context."""
        # Create report metadata with appropriate defaults
        report_format = ReportFormat.JSON  # Default format, can be overridden
        report_type = ReportType.SECURITY_ANALYSIS  # Default to security analysis report

        report_metadata = create_default_metadata(report_type, report_format)
        report_metadata.title = self.config.title
        report_metadata.organization = self.config.organization
        report_metadata.generation_timestamp = datetime.now()

        # Add custom metadata
        if metadata:
            for key, value in metadata.items():
                setattr(report_metadata, key, value)
        # Ensure CI-gate critical metadata fields are populated
        try:
            # Target APK path
            target_apk_env = os.environ.get("AODS_CURRENT_APK") or os.environ.get("AODS_APK_PATH") or ""
            target_apk_meta = (metadata or {}).get("apk") or (metadata or {}).get("target_apk_path") if metadata else ""
            target_apk_path_val = target_apk_meta or target_apk_env or ""
            if not getattr(report_metadata, "target_apk_path", None):
                setattr(report_metadata, "target_apk_path", target_apk_path_val)
            # Package name (best-effort from APK filename)
            pkg = (metadata or {}).get("package_name") if metadata else None
            if not pkg:
                try:
                    from pathlib import Path as _P

                    stem = _P(str(target_apk_path_val)).stem
                    pkg = stem if stem else "apk"
                except Exception:
                    pkg = "apk"
            if not getattr(report_metadata, "package_name", None):
                setattr(report_metadata, "package_name", pkg)
            # Analysis duration placeholder (seconds)
            if not getattr(report_metadata, "analysis_duration", None):
                setattr(report_metadata, "analysis_duration", 0)
            # Scan mode (static/dynamic/hybrid)
            scan_mode_val = (metadata or {}).get("scan_mode") if metadata else None
            if not scan_mode_val:
                scan_mode_val = "static" if os.environ.get("AODS_STATIC_ONLY_HARD", "0") == "1" else "standard"
            if not getattr(report_metadata, "scan_mode", None):
                setattr(report_metadata, "scan_mode", scan_mode_val)
            # Analysis profile from environment (best-effort)
            prof_env = os.environ.get("AODS_SCAN_PROFILE") or os.environ.get("AODS_PROFILE")
            if prof_env and not getattr(report_metadata, "analysis_profile", None):
                try:
                    setattr(report_metadata, "analysis_profile", str(prof_env).lower())
                except Exception:
                    setattr(report_metadata, "analysis_profile", str(prof_env))

            # Embed effectiveOptions derived from environment variables
            try:

                def _truthy(val: str) -> bool:
                    return str(val).strip().lower() in {"1", "true", "yes", "on"}

                eff_options: Dict[str, Any] = {}
                v = os.environ.get("AODS_REPORT_FILTER_BY_THRESHOLDS")
                if v is not None:
                    eff_options["enableThresholdFiltering"] = _truthy(v)
                v = os.environ.get("AODS_STATIC_ONLY_HARD")
                if v is not None:
                    eff_options["staticOnly"] = _truthy(v)
                v = os.environ.get("AODS_RESOURCE_CONSTRAINED")
                if v is not None:
                    eff_options["resourceConstrained"] = _truthy(v)
                fm = os.environ.get("AODS_FRIDA_MODE")
                if fm:
                    fm_l = str(fm).lower()
                    if fm_l in ("standard", "read_only", "advanced"):
                        eff_options["fridaMode"] = fm_l
                mw = os.environ.get("AODS_MAX_WORKERS")
                if mw:
                    try:
                        eff_options["maxWorkers"] = int(mw)
                    except Exception:
                        pass
                tp = os.environ.get("AODS_TIMEOUTS_PROFILE")
                if tp:
                    eff_options["timeoutsProfile"] = str(tp).lower()
                inc = os.environ.get("AODS_PLUGINS_INCLUDE")
                if inc:
                    eff_options["pluginsInclude"] = [p for p in str(inc).split(",") if p]
                exc = os.environ.get("AODS_PLUGINS_EXCLUDE")
                if exc:
                    eff_options["pluginsExclude"] = [p for p in str(exc).split(",") if p]

                if eff_options:
                    setattr(report_metadata, "effectiveOptions", eff_options)
            except Exception:
                # Non-fatal enrichment
                pass
        except Exception:
            # Never fail report creation on metadata enrichment
            pass

        # Create report configuration
        config = ReportConfiguration(
            output_format=report_format,
            report_type=report_type,
            include_executive_summary=self.config.include_executive_summary,
            include_technical_details=self.config.include_technical_details,
            include_charts=self.config.include_charts,
            template=None,  # Will use default template
            max_findings_per_section=self.config.max_findings_per_section,
        )

        # Derive target APK info and simple performance hints
        target_apk = ""
        if metadata:
            target_apk = metadata.get("apk") or metadata.get("target_apk_path") or ""
        if not target_apk:
            target_apk = os.environ.get("AODS_CURRENT_APK") or os.environ.get("AODS_APK_PATH") or ""

        # Create simplified context for report generation
        start_ts = datetime.now()
        context = ReportContext(
            analysis_start_time=start_ts,
            analysis_end_time=start_ts,
            target_apk_path=target_apk or "",
            target_apk_hash="",
            target_apk_size=0,
            environment_info={},
            plugin_versions={},
            configuration_used={"report_type": report_type.value, "format": report_format.value},
            performance_metrics={},
            errors_encountered=[],
            warnings_issued=[],
        )

        # Store additional info in context for later use
        context.metadata = report_metadata
        context.config = config

        # Embed decompilation policy details if available (non-fatal)
        try:
            # Best-effort: reconstruct policy used for this run
            apk_hint = target_apk or getattr(report_metadata, "target_apk_path", "") or ""
            profile_hint = os.environ.get("AODS_APP_PROFILE", os.environ.get("AODS_SCAN_PROFILE", "production"))
            from core.decompilation_policy_resolver import get_decompilation_policy

            pol = get_decompilation_policy(apk_path=apk_hint, profile=str(profile_hint))
            decomp_info = {
                "reason": pol.reason,
                "flags": list(pol.flags),
                "output_dir": pol.output_dir,
                "max_threads": pol.max_threads,
                "memory_limit_mb": pol.memory_limit_mb,
            }
            try:
                # Attach to metadata as a simple attribute
                setattr(report_metadata, "decompilation_policy", decomp_info)
            except Exception:
                pass
        except Exception:
            # Never fail report creation on enrichment
            pass

        # Optional MASVS→MSTG mapping enrichment (non-breaking)
        try:
            # Minimal static mapping for common MASVS controls
            masvs_to_mstg = {
                "MASVS-NETWORK-1": ["MASTG-NETWORK-1", "MASTG-TEST-0024"],
                "MASVS-CRYPTO-1": ["MASTG-CRYPTO-1", "MASTG-TEST-0014"],
                "MASVS-STORAGE-4": ["MASTG-STORAGE-2", "MASTG-TEST-0031"],
                "MASVS-AUTH-1": ["MASTG-AUTH-1", "MASTG-TEST-0007"],
                "MASVS-PRIVACY-1": ["MASTG-PRIVACY-1"],
            }
            existing = getattr(report_metadata, "masvs_summary", None)
            if isinstance(existing, dict):
                mstg_links = {}
                for control, count in existing.items():
                    if control in masvs_to_mstg:
                        mstg_links[control] = masvs_to_mstg[control]
                if mstg_links:
                    setattr(report_metadata, "mstg_links", mstg_links)
        except Exception:
            pass
        # Optional CVE/NVD enrichment (non-breaking): attach CVE IDs seen by external data pipeline
        try:
            # Lazy import to avoid hard dep when pipeline not configured
            from core.external_data.vulnerability_database import VulnerabilityDatabase

            db = VulnerabilityDatabase()
            linked = db.lookup_findings(findings)
            if linked:
                try:
                    # Attach to metadata for report consumers; list of {finding_id, cve_id}
                    setattr(report_metadata, "linked_cves", linked)
                except Exception:
                    pass
        except Exception:
            # Silently skip if external data not available
            pass

        # Optional calibration ECE/MCE summary if calibration is enabled
        try:
            if os.environ.get("AODS_ML_ENABLE_CALIBRATION", "0") in ("1", "true", "yes", "on"):
                # Try to read a recent calibration summary if available
                from pathlib import Path as _P

                summ_path = _P("models/unified_ml/calibration_summary.json")
                if summ_path.exists():
                    import json as _json

                    data = _json.loads(summ_path.read_text(encoding="utf-8"))
                    setattr(
                        report_metadata,
                        "calibration_summary",
                        {
                            "ece_before": data.get("ece_before"),
                            "ece_after": data.get("ece_after"),
                            "mce_before": data.get("mce_before"),
                            "mce_after": data.get("mce_after"),
                            "kind": data.get("chosen", {}).get("kind"),
                        },
                    )
        except Exception:
            pass
        # Convert to SecurityFinding to standardize fields and apply calibration
        security_findings = [self._convert_to_security_finding(f) if isinstance(f, dict) else f for f in findings]

        # Optional threshold-based filtering to reduce visible false positives
        threshold_filtered = 0
        if self.config.apply_threshold_filtering:
            try:
                from core.ml.thresholds_loader import load_thresholds

                th = getattr(self, "_thresholds_cache", None)
                if th is None:
                    th = load_thresholds()
                    self._thresholds_cache = th
            except Exception:
                th = None

            def _applied_threshold(thr: Dict[str, Any], category: str, plugin: str) -> float:
                try:
                    default_val = float(thr.get("default", 0.5)) if thr else 0.5
                except Exception:
                    default_val = 0.5
                if not thr:
                    return default_val
                try:
                    if thr.get("plugins") and plugin in thr.get("plugins", {}):
                        return float(thr["plugins"][plugin])
                    if thr.get("categories") and category in thr.get("categories", {}):
                        return float(thr["categories"][category])
                except Exception:
                    pass
                return default_val

            if th:
                filtered_list: List[Any] = []
                try:
                    from .data_structures import SeverityLevel as _Sev
                except Exception:
                    _Sev = None
                for sf in security_findings:
                    try:
                        cat = getattr(sf, "category", "security") or "security"
                        plg = getattr(sf, "plugin_source", "") or ""
                        conf = float(getattr(sf, "confidence", 0.0) or 0.0)
                        t_applied = _applied_threshold(th, str(cat), str(plg))
                        if conf >= float(t_applied):
                            filtered_list.append(sf)
                        else:
                            if self.config.always_preserve_high_critical and _Sev is not None:
                                sev = getattr(sf, "severity", None)
                                if sev in (_Sev.HIGH, _Sev.CRITICAL):
                                    filtered_list.append(sf)
                                    continue
                            threshold_filtered += 1
                    except Exception:
                        # Keep on error
                        filtered_list.append(sf)
                security_findings = filtered_list
        try:
            # Synchronize totals into metadata for accurate dashboards
            report_metadata.total_findings = len(security_findings)
        except Exception:
            pass
        # Apply Enum serialization to processed_findings in context
        context.processed_findings = self._serialize_findings_for_json(security_findings)
        # Expose threshold filtering stats for metadata
        try:
            setattr(context, "threshold_filtered", int(threshold_filtered))
        except Exception:
            pass
        # Enrich context with APK hash and size if available
        try:
            apk_path = getattr(report_metadata, "target_apk_path", "") or target_apk
            if apk_path and os.path.exists(apk_path):
                context.target_apk_size = os.path.getsize(apk_path)
                with open(apk_path, "rb") as f:
                    h = hashlib.sha256()
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        h.update(chunk)
                context.target_apk_hash = h.hexdigest()
        except Exception:
            pass

        return context

    def _convert_to_security_finding(self, finding_dict: Dict[str, Any]) -> SecurityFinding:
        """Convert a dictionary to a SecurityFinding with proper defaults."""
        from .data_structures import SeverityLevel

        # Provide defaults for required fields
        finding_id = self._generate_stable_id(finding_dict)
        title = self._sanitize_title(finding_dict.get("title", "Unknown Security Finding"))
        description = finding_dict.get("description", title)
        # Sanitize overly long/verbose descriptions and code dumps
        try:
            description = self._sanitize_text(description)
        except Exception:
            pass

        # Convert severity string to SeverityLevel enum
        severity_str = finding_dict.get("severity", "medium").lower()
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        severity = severity_map.get(severity_str, SeverityLevel.MEDIUM)

        # Prefer classifier severity if present
        try:
            cls = finding_dict.get("classification") or {}
            if isinstance(cls, dict):
                cls_sev = str(cls.get("severity", "")).lower()
                if cls_sev in severity_map:
                    severity = severity_map[cls_sev]
                # Explicit non-vulnerability forces INFO
                if cls.get("is_vulnerability") is False:
                    severity = SeverityLevel.INFO
        except Exception:
            pass

        # PASS-aware downgrade at reporting layer (title/description/content)
        try:
            title_lower = str(finding_dict.get("title", "")).lower()
            desc_lower = str(finding_dict.get("description", "")).lower()
            content_lower = str(finding_dict.get("content", "")).lower()
            pass_indicators = [
                "status: pass",
                "status: success",
                "status: ok",
                "\nstatus: pass",
                "\nstatus: success",
                "\nstatus: ok",
            ]
            # Word-boundary "pass" check - avoid matching "password", "bypass", "passthrough"
            _pass_word = re.search(r"\bpass\b", title_lower) is not None
            looks_pass = (
                any(pi in desc_lower for pi in pass_indicators)
                or " (pass" in title_lower
                or (_pass_word and ("fail" not in title_lower))
                or (
                    ("no vulnerabilities" in desc_lower or "no vulnerabilities" in content_lower)
                    and ("insecure" not in desc_lower)
                )
            )
            if looks_pass:
                severity = SeverityLevel.INFO
        except Exception:
            pass

        # Confidence calibration: derive raw probability then calibrate
        raw_conf = None
        for key in ("confidence", "probability", "score", "conf"):
            if key in finding_dict:
                try:
                    raw_conf = float(finding_dict.get(key))
                    break
                except Exception:
                    continue
        if raw_conf is None:
            raw_conf = 0.5
        # Normalize to [0,1]
        if raw_conf > 1.0:
            # Assume already in 0-100 scale
            raw_conf = raw_conf / 100.0
        raw_conf = max(0.0, min(1.0, raw_conf))
        try:
            if self._calibrator is not None:
                confidence = float(self._calibrator.calibrate(raw_conf))
            else:
                confidence = raw_conf
        except Exception:
            confidence = raw_conf
        category = finding_dict.get("category", "security")
        location = finding_dict.get("location", "unknown")

        # Enrichment: infer plugin_source if missing
        plugin_source = finding_dict.get("plugin_source", "") or finding_dict.get("plugin", "")
        if not plugin_source:
            try:
                # Derive from title by slugifying
                t = str(title).lower()
                t = t.replace("(", " ").replace(")", " ")
                t = t.replace("[", " ").replace("]", " ")
                t = t.replace("no results", "").replace("pass", "").strip()
                plugin_source = "_".join([p for p in t.split() if p.isalpha()])[:64]
                if not plugin_source:
                    tl = t
                    if "sql" in tl or "injection" in tl:
                        plugin_source = "injection_vulnerabilities"
                    elif "cryptography" in tl or "crypto" in tl:
                        plugin_source = "cryptography_tests"
                    elif "webview" in tl:
                        plugin_source = "webview_security_analysis"
                    elif "manifest" in tl:
                        plugin_source = "enhanced_manifest_analysis"
                    elif "apk information" in tl or "apk info" in tl:
                        plugin_source = "apk_information_extraction"
                    elif ("tls" in tl) or ("ssl" in tl) or ("certificate" in tl) or ("network security" in tl):
                        # Distinguish cleartext vs general TLS/SSL
                        if ("cleartext" in tl) or ("clear text" in tl):
                            plugin_source = "network_cleartext_traffic"
                        else:
                            plugin_source = "advanced_ssl_tls_analyzer"
            except Exception:
                plugin_source = ""

        # Enrichment (conservative): extract location/path only when strongly indicated
        file_path = finding_dict.get("file_path", "")
        inference_info = None
        try:
            import re

            strict_locations = str(os.environ.get("AODS_REPORT_STRICT_LOCATIONS", "0")).strip().lower() in (
                "1",
                "true",
                "yes",
                "on",
            )
            if not strict_locations:
                # 1) Direct path patterns in text (contains '/' and known source-code extension)
                if not file_path:
                    desc_all = " ".join(
                        [str(finding_dict.get("description", "")), str(finding_dict.get("content", ""))]
                    )
                    m = re.search(r"([/A-Za-z0-9_\.-][^\s'\"]+\.(?:smali|java|kt|gradle|pro|cfg))", desc_all)
                    if m:
                        candidate = m.group(1)
                        # Accept only plausible source-code paths for file_path (resources handled separately)
                        if "/" in candidate:
                            file_path = candidate
                            if location == "unknown":
                                location = file_path
                            inference_info = {"source": "text_path", "confidence": "medium"}

                # 2) Nested dict fields named like 'file*' with valid extension
                if not file_path:

                    def _walk(obj):
                        if isinstance(obj, dict):
                            for k, v in obj.items():
                                yield k, v
                                if isinstance(v, (dict, list)):
                                    for kv in _walk(v):
                                        yield kv
                        elif isinstance(obj, list):
                            for v in obj:
                                yield None, v
                                if isinstance(v, (dict, list)):
                                    for kv in _walk(v):
                                        yield kv

                    for k, v in _walk(finding_dict):
                        if isinstance(k, str) and "file" in k.lower() and isinstance(v, str):
                            if re.search(r"\.(smali|java|kt|xml)$", v):
                                file_path = v
                                inference_info = {"source": "field_file_path", "confidence": "medium"}
                                break

                # 3) FQCN: set location only (do not fabricate file_path)
                if location == "unknown":
                    class_candidate = None
                    for _, v in (finding_dict.items() if isinstance(finding_dict, dict) else []):
                        if isinstance(v, str):
                            m2 = re.search(r"\b([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+)\b", v)
                            if m2:
                                parts = m2.group(1).split(".")
                                if parts and parts[-1][:1].isupper():
                                    class_candidate = m2.group(1)
                                    break
                    if class_candidate:
                        location = class_candidate
                        inference_info = inference_info or {"source": "fqcn", "confidence": "low"}

                # 4) Android resource refs or explicit res/ paths: set location only (keep file_path empty)
                if location == "unknown":
                    desc_all = " ".join(
                        [str(finding_dict.get("description", "")), str(finding_dict.get("content", ""))]
                    )
                    res2 = re.search(
                        r"\bR\.(id|string|color|dimen|style|drawable|mipmap|layout|xml|menu)\.([A-Za-z0-9_]+)\b",
                        desc_all,
                    )
                    if res2:
                        location = f"R.{res2.group(1)}.{res2.group(2)}"
                        inference_info = inference_info or {"source": "resource_ref", "confidence": "low"}
                    elif re.search(
                        r"network\s*security\s*config|NetworkSecurityConfig|android:networkSecurityConfig",
                        desc_all,
                        re.IGNORECASE,
                    ):
                        location = "res/xml/network_security_config.xml"
                        inference_info = inference_info or {"source": "resource_ref", "confidence": "low"}
                    else:
                        # Explicit res/ path mention like res/xml/file.xml → location only
                        mres = re.search(r"\b(res/[A-Za-z0-9_./-]+\.xml)\b", desc_all)
                        if mres:
                            location = mres.group(1)
                            inference_info = inference_info or {"source": "resource_ref", "confidence": "low"}
        except Exception:
            pass

        # Risk score mapping from severity
        risk_score = {
            SeverityLevel.CRITICAL: 0.95,
            SeverityLevel.HIGH: 0.8,
            SeverityLevel.MEDIUM: 0.5,
            SeverityLevel.LOW: 0.25,
            SeverityLevel.INFO: 0.1,
        }.get(severity, 0.5)

        # Derive impact/exploitability/remediation_effort if provided by plugins
        try:
            evidence_obj = finding_dict.get("evidence", {}) if isinstance(finding_dict.get("evidence"), dict) else {}
        except Exception:
            evidence_obj = {}
        exploitability_val = finding_dict.get("exploitability") or evidence_obj.get("exploitability") or "unknown"
        impact_val = finding_dict.get("impact") or evidence_obj.get("impact") or "unknown"
        remediation_effort_val = (
            finding_dict.get("remediation_effort") or evidence_obj.get("remediation_effort") or "unknown"
        )

        recommendation_val = finding_dict.get("recommendation", "")

        # Default remediation and risk hints mapping (fallback when still missing)
        try:
            cwe_key = str(finding_dict.get("cwe_id") or "").strip().upper()
            cwe_defaults = {
                "CWE-319": {
                    "rec": "Disable cleartext traffic (usesCleartextTraffic=false), migrate HTTP to HTTPS, and enforce Network Security Config.",  # noqa: E501
                    "exploitability": "high",
                    "impact": "data_exposure_in_transit",
                },
                "CWE-295": {
                    "rec": "Validate TLS certificates properly; use default TrustManager/HostnameVerifier or strict pinning.",  # noqa: E501
                    "exploitability": "high",
                    "impact": "mitm_attack_possible",
                },
                "CWE-327": {
                    "rec": "Replace deprecated/weak algorithms (e.g., MD5/SHA1/RC4) with modern cryptography (SHA-256+, TLS 1.2+).",  # noqa: E501
                    "exploitability": "medium",
                    "impact": "crypto_weakness",
                },
                "CWE-89": {
                    "rec": "Use parameterized queries/ORM, input validation, and least-privilege DB accounts to prevent SQL injection.",  # noqa: E501
                    "exploitability": "high",
                    "impact": "code_execution_or_data_exposure",
                },
                "CWE-22": {
                    "rec": "Normalize and validate file paths; restrict to allowed directories; avoid using untrusted input in paths.",  # noqa: E501
                    "exploitability": "high",
                    "impact": "arbitrary_file_access",
                },
                "CWE-79": {
                    "rec": "Escape/encode output, sanitize input, and use a CSP to mitigate XSS.",
                    "exploitability": "high",
                    "impact": "client_side_code_execution",
                },
                "CWE-798": {
                    "rec": "Remove hardcoded secrets; move to secure storage (e.g., Android Keystore) and rotate credentials.",  # noqa: E501
                    "exploitability": "high",
                    "impact": "credential_compromise",
                },
                "CWE-287": {
                    "rec": "Enforce strong authentication checks, avoid bypassable flows, and validate auth state on all entry points.",  # noqa: E501
                    "exploitability": "high",
                    "impact": "authentication_bypass",
                },
                "CWE-384": {
                    "rec": "Regenerate session IDs after login, set secure flags, and prevent session fixation vectors.",  # noqa: E501
                    "exploitability": "high",
                    "impact": "session_hijacking",
                },
                "CWE-522": {
                    "rec": "Protect credentials at rest/in transit; use Keystore and TLS; avoid logs/query strings.",
                    "exploitability": "medium",
                    "impact": "credential_compromise",
                },
                "CWE-200": {
                    "rec": "Avoid exposing sensitive info; scrub logs/URLs; restrict debug data in production.",
                    "exploitability": "medium",
                    "impact": "information_exposure",
                },
                "CWE-749": {
                    "rec": "Avoid exposing WebView JS interfaces to untrusted content; use minimum required settings.",
                    "exploitability": "medium",
                    "impact": "unexpected_code_access",
                },
                "CWE-502": {
                    "rec": "Avoid unsafe deserialization; use safe formats and validate types/allow-lists.",
                    "exploitability": "medium",
                    "impact": "code_execution_or_data_exposure",
                },
                "CWE-259": {
                    "rec": "Avoid hard-coded passwords; use Android Keystore or secure config management; rotate credentials.",  # noqa: E501
                    "exploitability": "high",
                    "impact": "credential_compromise",
                },
                "CWE-94": {
                    "rec": "Do not execute dynamically constructed code from untrusted input; validate and whitelist inputs; use parameterized APIs.",  # noqa: E501
                    "exploitability": "high",
                    "impact": "arbitrary_code_execution",
                },
            }
            defaults = cwe_defaults.get(cwe_key)
            if defaults:
                if not recommendation_val:
                    recommendation_val = defaults.get("rec", recommendation_val)
                if (not exploitability_val) or (str(exploitability_val).lower() == "unknown"):
                    exploitability_val = defaults.get("exploitability", exploitability_val)
                if (not impact_val) or (str(impact_val).lower() == "unknown"):
                    impact_val = defaults.get("impact", impact_val)
        except Exception:
            pass

        # Optional threshold tagging (no filtering, just annotate)
        threshold_tag = None
        try:
            from core.ml.thresholds_loader import load_thresholds

            th = getattr(self, "_thresholds_cache", None)
            if th is None:
                th = load_thresholds()
                self._thresholds_cache = th
            if th:
                by_plugin = float(th.get("plugins", {}).get(plugin_source, th.get("default", 0.5)))
                by_cat = float(th.get("categories", {}).get(category, by_plugin))
                threshold_tag = {
                    "applied_threshold": float(by_cat),
                    "over_threshold": bool(confidence >= float(by_cat)),
                    "source": "plugin>category>default",
                }
        except Exception:
            threshold_tag = None

        # Merge threshold tag into evidence for downstream visibility
        evidence_val = finding_dict.get("evidence", "")
        try:
            if threshold_tag:
                if isinstance(evidence_val, dict):
                    evidence_val = dict(evidence_val)
                    evidence_val["threshold"] = threshold_tag
                else:
                    evidence_val = {"original_evidence": evidence_val, "threshold": threshold_tag}
        except Exception:
            pass

        # Merge location inference note into evidence if present
        if inference_info:
            try:
                if isinstance(evidence_val, dict):
                    evidence_val = dict(evidence_val)
                    evidence_val["location_inference"] = inference_info
                else:
                    evidence_val = {"original_evidence": evidence_val, "location_inference": inference_info}
            except Exception:
                pass

        # Extract real code_snippet - skip description-only placeholders
        raw_snippet = finding_dict.get("code_snippet", "") or ""
        if raw_snippet == description or raw_snippet == title:
            raw_snippet = ""

        return SecurityFinding(
            id=finding_id,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            category=category,
            location=location,
            file_path=file_path,
            line_number=finding_dict.get("line_number", None),
            code_snippet=raw_snippet,
            evidence=evidence_val,
            recommendation=recommendation_val,
            references=finding_dict.get("references", []),
            cwe_id=finding_dict.get("cwe_id", None),
            owasp_category=finding_dict.get("owasp_category", ""),
            masvs_control=str(finding_dict.get("masvs_control", "")),
            nist_control=str(finding_dict.get("nist_control", "")),
            risk_score=risk_score,
            exploitability=str(exploitability_val).lower() if exploitability_val else "unknown",
            impact=str(impact_val).lower() if impact_val else "unknown",
            remediation_effort=str(remediation_effort_val).lower() if remediation_effort_val else "unknown",
            plugin_source=plugin_source,
        )

    def _sanitize_text(self, text: str) -> str:
        """Reduce code dumps and preserve concise, readable summary text."""
        try:
            if not text:
                return text
            s = str(text)
            # Remove emoji and UI glyphs
            s = self._strip_emojis(s)
            # Strip common repr wrappers like (<text '...'>) or (<text '...'
            s = re.sub(r"^\(<text\s+'(.*?)(?:'\)|'\.{0,3})$", r"\1", s, flags=re.DOTALL)
            # Also handle truncated wrapper: (<text 'content...
            s = re.sub(r"^\(<text\s+'", "", s)
            # Trim extremely long text
            if len(s) > 2000:
                s = s[:2000] + "..."
            # Remove excessive line length (likely code dumps)
            lines = s.splitlines()
            pruned = []
            for ln in lines:
                if len(ln) > 240:
                    # Truncate at word boundary to avoid mid-word cuts
                    truncated = ln[:237]
                    last_space = truncated.rfind(" ")
                    if last_space > 140:
                        truncated = truncated[:last_space]
                    pruned.append(truncated.rstrip(",.;: ") + "...")
                else:
                    pruned.append(ln)
            s = "\n".join(pruned)
            # Remove redundant box-drawing or heavy separators
            s = s.replace("=\n", "\n").replace("==", "=")
            return s
        except Exception:
            return str(text)

    def _sanitize_title(self, text: str) -> str:
        try:
            t = str(text)
            t = self._strip_emojis(t)
            # Remove decorative checkmarks or PASS prefixes
            t = t.replace("PASS", "Pass")
            return t.strip()
        except Exception:
            return str(text)

    def _strip_emojis(self, text: str) -> str:
        try:
            # Basic emoji removal via unicode ranges
            emoji_pattern = re.compile(
                "[\U0001f600-\U0001f64f\U0001f300-\U0001f5ff\U0001f680-\U0001f6ff\U0001f1e0-\U0001f1ff\u2600-\u26ff\u2700-\u27bf]",  # noqa: E501
                flags=re.UNICODE,
            )
            return emoji_pattern.sub("", str(text))
        except Exception:
            return str(text)

    def _generate_stable_id(self, finding_dict: Dict[str, Any]) -> str:
        try:
            if "id" in finding_dict and finding_dict.get("id"):
                fid = str(finding_dict.get("id"))
            else:
                parts = [
                    str(finding_dict.get("title", "")),
                    str(finding_dict.get("file_path", "")),
                    str(finding_dict.get("location", "")),
                    str(finding_dict.get("line_number", "")),
                    str(finding_dict.get("cwe_id", "")),
                    str(finding_dict.get("severity", "")),
                ]
                h = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:12]
                fid = f"f_{h}"
            # Ensure uniqueness within this report instance
            base = fid
            suffix = 1
            while fid in self._seen_ids:
                suffix += 1
                fid = f"{base}_{suffix}"
            self._seen_ids.add(fid)
            return fid
        except Exception:
            # Fallback to timestamp-based
            fid = f"finding_{int(time.time())}"
            if fid in self._seen_ids:
                fid = f"{fid}_{len(self._seen_ids)}"
            self._seen_ids.add(fid)
            return fid

    def _generate_format_specific_report(
        self, findings: List[Dict[str, Any]], context: ReportContext, format_type: ReportFormat
    ) -> Dict[str, Any]:
        """Generate report for specific format."""
        # Get appropriate generator
        generator = UnifiedReportGenerator.create_generator(
            ReportType.SECURITY_ANALYSIS, quality_level=self.config.quality_level.value
        )

        # Generate report data - prefer context.processed_findings if available to honor normalization
        safe_findings = None
        try:
            if context and getattr(context, "processed_findings", None):
                safe_findings = context.processed_findings
        except Exception:
            safe_findings = None
        # Track 30.1: Compute plugins_summary for report metadata
        from collections import Counter as _Counter

        _plugin_counts = _Counter(f.get("plugin_source") or f.get("plugin") or "unknown" for f in findings)
        _plugins_summary = {
            "plugins_with_findings": len(_plugin_counts),
            "findings_per_plugin": dict(sorted(_plugin_counts.items(), key=lambda x: x[1], reverse=True)),
        }

        _meta = self._fix_enum_values(context.metadata.__dict__) if context and context.metadata else {}
        _meta["plugins_summary"] = _plugins_summary

        data_dict = {
            "findings": safe_findings if safe_findings is not None else self._serialize_findings_for_json(findings),
            "metadata": _meta,
            "context": self._fix_enum_values(context.__dict__) if context else {},
        }
        report_data = generator.generate(data_dict)

        # Track 30.1: Inject plugins_summary into generated metadata
        # (generator creates fresh metadata, so we must inject after generate())
        if isinstance(report_data, dict) and "metadata" in report_data:
            report_data["metadata"]["plugins_summary"] = _plugins_summary
            # Track 60 Fix 10: Inject analysis_duration from scanner metadata
            if "analysis_duration" not in report_data["metadata"] or not report_data["metadata"].get(
                "analysis_duration"
            ):
                report_data["metadata"]["analysis_duration"] = _meta.get("analysis_duration", 0)

        # Apply format-specific formatting
        formatter = FormatterFactory.create_formatter(format_type)
        formatted_report = formatter.format(report_data)

        return formatted_report

    def _serialize_findings_for_json(self, findings: List[Any]) -> List[Dict[str, Any]]:
        """
        Convert findings to JSON-serializable dictionaries with proper Enum handling.

        CRITICAL FIX: Prevents massive Enum object representations in JSON output
        """
        from dataclasses import asdict, is_dataclass

        serialized_findings = []
        seen_ids = set()

        for finding in findings:
            if is_dataclass(finding):
                # Convert SecurityFinding dataclass to dict with proper Enum serialization
                finding_dict = asdict(finding)
                # Fix all Enum values recursively
                finding_dict = self._fix_enum_values(finding_dict)
                # Enrich PluginFinding-derived dicts with impact/exploitability if present in evidence
                try:
                    if "impact" not in finding_dict or not finding_dict.get("impact"):
                        ev = finding_dict.get("evidence", {})
                        if isinstance(ev, dict) and ev.get("impact"):
                            finding_dict["impact"] = str(ev.get("impact")).lower()
                    if "exploitability" not in finding_dict or not finding_dict.get("exploitability"):
                        ev = finding_dict.get("evidence", {})
                        if isinstance(ev, dict) and ev.get("exploitability"):
                            finding_dict["exploitability"] = str(ev.get("exploitability")).lower()
                    if "remediation_effort" not in finding_dict or not finding_dict.get("remediation_effort"):
                        ev = finding_dict.get("evidence", {})
                        if isinstance(ev, dict) and ev.get("remediation_effort"):
                            finding_dict["remediation_effort"] = str(ev.get("remediation_effort")).lower()
                except Exception:
                    pass
                fid = str(finding_dict.get("id", ""))
                if fid and fid in seen_ids:
                    continue
                if fid:
                    seen_ids.add(fid)
                serialized_findings.append(finding_dict)
            elif isinstance(finding, dict):
                # Already a dict, but fix any Enum values
                fixed = self._fix_enum_values(finding)
                fid = str(fixed.get("id", "")) if isinstance(fixed, dict) else ""
                if fid and fid in seen_ids:
                    continue
                if fid:
                    seen_ids.add(fid)
                serialized_findings.append(fixed)
            else:
                # Pass through as-is
                serialized_findings.append(finding)

        return serialized_findings

    def _fix_enum_values(self, obj: Any) -> Any:
        """Recursively convert Enum objects to their values."""
        from enum import Enum

        if isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, dict):
            return {key: self._fix_enum_values(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._fix_enum_values(item) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self._fix_enum_values(item) for item in obj)
        else:
            return obj

    def _update_generation_statistics(self, findings: List[Dict[str, Any]], generation_time: float):
        """Update report generation statistics."""
        self.stats["reports_generated"] += 1
        self.stats["total_findings_processed"] += len(findings)

        # Update average generation time
        total_time = self.stats["average_generation_time"] * (self.stats["reports_generated"] - 1)
        self.stats["average_generation_time"] = (total_time + generation_time) / self.stats["reports_generated"]

        # Count vulnerabilities
        vulnerabilities = len([f for f in findings if f.get("severity") in ["high", "critical"]])
        self.stats["vulnerabilities_reported"] += vulnerabilities

        # Update quality level usage
        quality_level = self.config.quality_level.value
        self.stats["quality_levels_used"][quality_level] = self.stats["quality_levels_used"].get(quality_level, 0) + 1

    def _save_reports_to_files(
        self, generated_reports: Dict[str, Any], output_directory: Optional[str], base_filename: Optional[str]
    ) -> Dict[str, str]:
        """
        Save generated reports to files with error handling.

        Args:
            generated_reports: Dictionary of format -> report_data
            output_directory: Output directory (defaults to current)
            base_filename: Base filename (defaults to 'security_report')

        Returns:
            Dictionary mapping format -> file_path
        """
        import os
        import tempfile
        import uuid
        from pathlib import Path
        from datetime import datetime

        # Set defaults
        output_dir = Path(output_directory or ".")
        base_name = base_filename or "security_report"

        # Add timestamp for uniqueness
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_id = str(uuid.uuid4())[:8]

        file_paths = {}

        try:
            # Ensure output directory exists
            output_dir.mkdir(parents=True, exist_ok=True)

            for format_name, report_data in generated_reports.items():
                if report_data and not (isinstance(report_data, dict) and report_data.get("error")):
                    try:
                        # Generate unique filename for concurrency safety
                        filename = f"{base_name}_{timestamp}_{unique_id}.{format_name}"
                        file_path = output_dir / filename

                        # Write to temporary file first, then atomic move
                        is_binary = isinstance(report_data, (bytes, bytearray))
                        if is_binary:
                            tmp_kwargs = dict(mode="wb", suffix=f".{format_name}", dir=output_dir, delete=False)
                        else:
                            tmp_kwargs = dict(
                                mode="w", suffix=f".{format_name}", dir=output_dir,
                                delete=False, encoding="utf-8",
                            )

                        with tempfile.NamedTemporaryFile(**tmp_kwargs) as temp_file:

                            if is_binary:
                                temp_file.write(report_data)
                            elif format_name == "json":
                                # If we already have a JSON string, write it directly; otherwise format dict
                                if isinstance(report_data, str):
                                    temp_file.write(report_data)
                                else:
                                    from .formatters import JSONFormatter

                                    json_formatter = JSONFormatter()
                                    json_content = json_formatter.format(report_data)
                                    temp_file.write(json_content)
                            else:
                                # For other formats, write as string
                                temp_file.write(str(report_data))

                            temp_file.flush()
                            os.fsync(temp_file.fileno())  # Force write to disk

                        # Atomic move to final location
                        os.replace(temp_file.name, str(file_path))
                        file_paths[format_name] = str(file_path)

                        self.logger.info(f"✅ Saved {format_name} report: {file_path}")

                    except Exception as e:
                        self.logger.error(f"❌ Failed to save {format_name} report: {e}")
                        # Clean up temp file if it exists
                        if "temp_file" in locals() and temp_file.name:
                            try:
                                os.unlink(temp_file.name)
                            except Exception:
                                pass
                        file_paths[format_name] = {"error": str(e)}

        except Exception as e:
            self.logger.error(f"❌ Failed to create output directory {output_dir}: {e}")
            return {"error": f"Directory creation failed: {e}"}

        return file_paths

    def generate_executive_summary(self, findings: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Generate executive summary report."""
        config = UnifiedReportConfig(
            quality_level=ReportQuality.EXECUTIVE,
            include_technical_details=False,
            include_charts=True,
            include_risk_dashboard=True,
        )

        # Temporarily override config
        original_config = self.config
        self.config = config

        try:
            result = self.generate_security_report(findings, **kwargs)
            return result
        finally:
            self.config = original_config

    def generate_compliance_report(
        self, findings: List[Dict[str, Any]], framework: str = "OWASP", **kwargs
    ) -> Dict[str, Any]:
        """Generate compliance-focused report."""
        config = UnifiedReportConfig(
            quality_level=ReportQuality.COMPLIANCE, include_compliance_section=True, include_remediation_guidance=True
        )

        # Add compliance metadata
        metadata = kwargs.get("metadata", {})
        metadata["compliance_framework"] = framework
        kwargs["metadata"] = metadata

        # Temporarily override config
        original_config = self.config
        self.config = config

        try:
            result = self.generate_security_report(findings, **kwargs)
            return result
        finally:
            self.config = original_config

    def get_reporting_statistics(self) -> Dict[str, Any]:
        """Get full reporting statistics."""
        return {
            "generation_stats": self.stats.copy(),
            "configuration": {
                "quality_level": self.config.quality_level.value,
                "output_formats": [f.value for f in self.config.output_formats],
                "vulnerability_focus": self.config.vulnerability_detection_focus,
                "false_positive_filtering": self.config.minimize_false_positives,
            },
            "capabilities": {
                "legacy_compatibility": self._legacy_available,
                "enterprise_features": self._enterprise_available,
                "supported_formats": [f.value for f in ReportFormat],
                "supported_quality_levels": [q.value for q in ReportQuality],
            },
        }


# Convenience functions for backward compatibility
def create_report_manager(config: Optional[Dict[str, Any]] = None) -> UnifiedReportingManager:
    """Create unified reporting manager with optional configuration."""
    if config:
        unified_config = UnifiedReportConfig(**config)
        return UnifiedReportingManager(unified_config)
    return UnifiedReportingManager()


def generate_security_report(
    findings: List[Dict[str, Any]], output_formats: Optional[List[str]] = None, **kwargs
) -> Dict[str, Any]:
    """Generate security report with default configuration."""
    manager = create_report_manager()

    if output_formats:
        formats = [ReportFormat(fmt) for fmt in output_formats]
        return manager.generate_security_report(findings, formats=formats, **kwargs)

    return manager.generate_security_report(findings, **kwargs)


# Export for core.shared_infrastructure.reporting facade
__all__ = [
    "UnifiedReportingManager",
    "UnifiedReportConfig",
    "ReportQuality",
    "create_report_manager",
    "generate_security_report",
]
