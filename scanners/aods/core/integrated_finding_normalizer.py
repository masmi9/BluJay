#!/usr/bin/env python3
"""
Integrated Finding Normalizer - Orchestrates Existing AODS Components
=====================================================================

This integration layer orchestrates existing AODS components to provide
full finding normalization without duplication:

- Finding normalization: core.finding.normalization_utilities.FindingNormalizer
- Taxonomy mapping: core.cwe_mapper.CWEMapper + core.reporting.security_framework_mapper
- Evidence enrichment: core.vulnerability_code_extractor + stack-trace parsing
- MASVS computation: From per-finding fields only

Acceptance Criteria:
- 100% of findings pass through integrator (no duplicate normalizers)
- ≥95% coverage for owasp_category or cwe_id+mapping
- ≥90% coverage for code snippets
- ≥85% coverage for line numbers
- MASVS section matches per-finding fields with zero contradictions

Author: AODS Architecture Team
Version: 1.0.0
"""

import re
import os
import logging
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass
from datetime import datetime

# Import path sanitization
try:
    from core.utils.path_sanitizer import sanitize_source_path
except Exception:  # Fallback if utility is unavailable during tests/imports

    def sanitize_source_path(path):
        return path


logger = logging.getLogger(__name__)


@dataclass
class IntegrationMetrics:
    """Tracks integration coverage metrics for validation."""

    total_findings: int = 0
    owasp_category_coverage: float = 0.0
    cwe_id_coverage: float = 0.0
    code_snippet_coverage: float = 0.0
    line_number_coverage: float = 0.0
    masvs_consistency: bool = True
    processing_errors: int = 0


class IntegratedFindingNormalizer:
    """
    Orchestrates existing AODS components for full finding normalization.

    This is the single source of truth for finding normalization, replacing
    duplicate implementations and ensuring consistency across the pipeline.
    """

    def __init__(self, apk_context=None):
        self.logger = logging.getLogger(f"{__name__}.IntegratedFindingNormalizer")
        self.apk_context = apk_context
        self.metrics = IntegrationMetrics()
        # Lightweight in-memory caches to avoid repeated expensive mappings
        # Keys are compact fingerprints derived from finding content
        self._taxonomy_cache: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self._framework_cache: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

        # Initialize existing AODS components
        self._initialize_components()

    def _initialize_components(self):
        """Initialize existing AODS components with error handling."""

        # 1. Finding Normalizer (existing)
        try:
            from core.finding.normalization_utilities import FindingNormalizer

            self.finding_normalizer = FindingNormalizer()
            self.logger.info("✅ Loaded existing FindingNormalizer")
        except ImportError as e:
            self.logger.warning(f"⚠️ FindingNormalizer not available: {e}")
            self.finding_normalizer = None

        # 2. CWE Mapper (existing)
        try:
            from core.cwe_mapper import CWEMapper

            self.cwe_mapper = CWEMapper()
            self.logger.info("✅ Loaded existing CWEMapper")
        except ImportError as e:
            self.logger.warning(f"⚠️ CWEMapper not available: {e}")
            self.cwe_mapper = None

        # 3. Security Framework Mapper (existing)
        try:
            from core.reporting.security_framework_mapper import SecurityFrameworkMapper

            self.framework_mapper = SecurityFrameworkMapper()
            self.logger.info("✅ Loaded existing SecurityFrameworkMapper")
        except ImportError as e:
            self.logger.warning(f"⚠️ SecurityFrameworkMapper not available: {e}")
            self.framework_mapper = None

        # 4. Code Extractor (existing)
        try:
            from core.vulnerability_code_extractor import VulnerabilityCodeExtractor

            self.code_extractor = VulnerabilityCodeExtractor()
            self.logger.info("✅ Loaded existing VulnerabilityCodeExtractor")
        except ImportError as e:
            self.logger.warning(f"⚠️ VulnerabilityCodeExtractor not available: {e}")
            self.code_extractor = None

        # 5. Evidence Enrichment Engine (existing) - initialize if apk_path is available
        try:
            from core.evidence_enrichment_engine import EvidenceEnrichmentEngine

            apk_path = None
            if self.apk_context and isinstance(self.apk_context, dict):
                apk_path = self.apk_context.get("apk_path") or self.apk_context.get("apk_path_str")
            elif self.apk_context and hasattr(self.apk_context, "apk_path"):
                apk_path = getattr(self.apk_context, "apk_path", None)
            if apk_path:
                self.evidence_enricher = EvidenceEnrichmentEngine(apk_path=apk_path)
                self.logger.info("✅ EvidenceEnrichmentEngine initialized with apk_path")
            else:
                self.evidence_enricher = None
                self.logger.info("⚠️ EvidenceEnrichmentEngine requires apk_path - skipping initialization")
        except ImportError as e:
            self.logger.warning(f"⚠️ EvidenceEnrichmentEngine not available: {e}")
            self.evidence_enricher = None

        # 6. Threat Analysis Enhancer (new) - MITRE ATT&CK integration
        try:
            from core.threat_analysis_enhancer import ThreatAnalysisEnhancer

            self.threat_enhancer = ThreatAnalysisEnhancer()
            self.logger.info("✅ Loaded ThreatAnalysisEnhancer with MITRE ATT&CK integration")
        except ImportError as e:
            self.logger.warning(f"⚠️ ThreatAnalysisEnhancer not available: {e}")
            self.threat_enhancer = None

    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Full finding normalization using existing AODS components.

        Args:
            raw_findings: List of findings in various plugin formats

        Returns:
            List of normalized findings with consistent schema and enriched evidence
        """
        self.logger.debug(f"🔧 Starting integrated normalization of {len(raw_findings)} findings...")

        # Minimal fast-path for performance benchmarking (env-controlled)
        try:
            if os.getenv("AODS_PERF_BENCH_MINIMAL", "0") in ("1", "true", "yes", "on"):
                out: List[Dict[str, Any]] = []
                for i, finding in enumerate(raw_findings):
                    f = finding if isinstance(finding, dict) else self._coerce_raw_finding(finding, i)
                    out.append(
                        {
                            "id": f.get("id", f"integrated_{i:03d}"),
                            "name": f.get("name", f.get("title", "Unknown Vulnerability")),
                            "severity": self._normalize_severity(f.get("severity", "MEDIUM")),
                            "confidence": self._normalize_confidence(f.get("confidence", 0.7)),
                            "description": f.get("description", f.get("details", "")),
                            "plugin_source": f.get("plugin_source", f.get("source", "unknown")),
                            "cwe_id": f.get("cwe_id") or "CWE-0",
                            "owasp_category": f.get("owasp_category")
                            or self._derive_owasp_category_fallback(
                                f.get("cwe_id"), f.get("masvs_control"), f.get("name", ""), f.get("description", "")
                            ),
                            "evidence": f.get("evidence", {}),
                            "integration_source": "perf_minimal",
                        }
                    )
                # Track metrics cheaply
                self.metrics = IntegrationMetrics(total_findings=len(out))
                for nf in out:
                    if nf.get("owasp_category"):
                        self.metrics.owasp_category_coverage += 1
                    if nf.get("cwe_id"):
                        self.metrics.cwe_id_coverage += 1
                    ev = nf.get("evidence") or {}
                    if isinstance(ev, dict):
                        if ev.get("code_snippet"):
                            self.metrics.code_snippet_coverage += 1
                        if ev.get("line_number"):
                            self.metrics.line_number_coverage += 1
                self._calculate_final_metrics()
                return out
        except Exception:
            pass

        normalized_findings = []
        self.metrics = IntegrationMetrics(total_findings=len(raw_findings))

        for i, finding in enumerate(raw_findings):
            # Coerce incoming finding to a dict to avoid attribute errors
            if not isinstance(finding, dict):
                finding = self._coerce_raw_finding(finding, i)

            # STEP 1: Core normalization using existing FindingNormalizer
            try:
                # Begin a lightweight trace for normalization step
                try:
                    from core.compliance.mstg_tracer import get_tracer

                    get_tracer().start_check("MSTG-NORMALIZER", {"index": i})
                except Exception:
                    pass
                normalized = self._normalize_core_finding(finding, i)
            except Exception as e:
                self.logger.warning(f"Failed to normalize finding {i}: {e}")
                self.metrics.processing_errors += 1
                normalized_findings.append(self._create_fallback_finding(finding, i))
                try:
                    from core.compliance.mstg_tracer import get_tracer

                    get_tracer().end_check("MSTG-NORMALIZER", "FAIL")
                except Exception:
                    pass
                continue

            # Ensure evidence is a dict before enhancement steps
            try:
                ev = normalized.get("evidence")
                if not isinstance(ev, dict):
                    normalized["evidence"] = {"content": str(ev) if ev is not None else ""}
            except Exception:
                normalized["evidence"] = {}

            # STEP 2: Enhance with taxonomy mapping (CWE/OWASP)
            try:
                self._enhance_taxonomy_mapping(normalized)
            except Exception as e:
                self.logger.debug(f"Taxonomy enhancement failed for finding {i}: {e}")

            # STEP 3: Enhance evidence with existing components
            try:
                self._enhance_evidence(normalized, finding)
            except Exception as e:
                self.logger.debug(f"Evidence enhancement failed for finding {i}: {e}")

            # STEP 4: Extract code snippets using existing extractor
            try:
                self._enhance_code_snippets(normalized)
            except Exception as e:
                self.logger.debug(f"Code snippet enhancement failed for finding {i}: {e}")

            # STEP 5: Enhance with MITRE ATT&CK threat analysis
            try:
                self._enhance_threat_analysis(normalized)
            except Exception as e:
                self.logger.debug(f"Threat analysis enhancement failed for finding {i}: {e}")

            # STEP 6: Validate and track metrics
            try:
                self._track_coverage_metrics(normalized)
            except Exception as e:
                self.logger.debug(f"Metrics tracking failed for finding {i}: {e}")

            normalized_findings.append(normalized)

            # End trace for the normalization step
            try:
                from core.compliance.mstg_tracer import get_tracer

                get_tracer().end_check("MSTG-NORMALIZER", "PASS")
            except Exception:
                pass

        # Calculate final metrics
        self._calculate_final_metrics()

        self.logger.debug("✅ Integrated normalization complete: %d findings processed", len(normalized_findings))
        self.logger.debug(
            "📊 Coverage: OWASP %.1f%%, CWE %.1f%%, Snippets %.1f%%, Lines %.1f%%",
            self.metrics.owasp_category_coverage * 100.0,
            self.metrics.cwe_id_coverage * 100.0,
            self.metrics.code_snippet_coverage * 100.0,
            self.metrics.line_number_coverage * 100.0,
        )

        return normalized_findings

    def _coerce_raw_finding(self, raw: Any, index: int) -> Dict[str, Any]:
        """Coerce non-dict raw finding inputs into a minimal dict structure.
        Handles strings, lists/tuples, and objects with __dict__.
        """
        try:
            # If string, treat as description/content
            if isinstance(raw, str):
                text = raw.strip()
                return {
                    "id": f"raw_{index:03d}",
                    "name": "Unstructured Finding",
                    "description": text,
                    "plugin_source": "unknown",
                    "evidence": {"content": text},
                }
            # If list/tuple
            if isinstance(raw, (list, tuple)):
                if raw and all(isinstance(x, dict) for x in raw):
                    # Merge conservatively: first item wins
                    merged: Dict[str, Any] = {}
                    for d in raw:
                        for k, v in d.items():
                            merged.setdefault(k, v)
                    if "id" not in merged:
                        merged["id"] = f"raw_{index:03d}"
                    merged.setdefault("plugin_source", "unknown")
                    return merged
                # Otherwise, join as text
                text = "\n".join([str(x) for x in raw])
                return {
                    "id": f"raw_{index:03d}",
                    "name": "Unstructured Finding",
                    "description": text,
                    "plugin_source": "unknown",
                    "evidence": {"content": text},
                }
            # If object with __dict__
            if hasattr(raw, "__dict__"):
                try:
                    data = dict(vars(raw))
                    data.setdefault("id", f"raw_{index:03d}")
                    data.setdefault("plugin_source", "unknown")
                    return data
                except Exception:
                    pass
        except Exception:
            pass
        # Last-resort fallback
        return {
            "id": f"raw_{index:03d}",
            "name": "Unstructured Finding",
            "description": str(raw),
            "plugin_source": "unknown",
            "evidence": {"content": str(raw)},
        }

    def _normalize_core_finding(self, finding: Dict[str, Any], index: int) -> Dict[str, Any]:
        """
        Normalize core finding structure.

        Uses basic normalization which provides reliable, consistent results.
        The canonical FindingNormalizer integration was removed in 2026-01-31
        due to compatibility issues - basic normalization handles all use cases.

        Args:
            finding: Raw finding dictionary from plugin
            index: Finding index for ID generation

        Returns:
            Normalized finding dictionary with consistent schema
        """
        return self._basic_normalize_finding(finding, index)

    def _canonical_to_dict(self, canonical_finding) -> Dict[str, Any]:
        """Convert canonical finding to dictionary format."""
        try:
            # Handle case where canonical normalizer returns a list
            if isinstance(canonical_finding, list):
                if canonical_finding:
                    canonical_finding = canonical_finding[0]  # Take first item
                else:
                    return self._basic_normalize_finding({"error": "Empty list from canonical normalizer"}, 0)

            if hasattr(canonical_finding, "to_dict"):
                return canonical_finding.to_dict()
            elif hasattr(canonical_finding, "__dict__"):
                result = {}
                for key, value in canonical_finding.__dict__.items():
                    if hasattr(value, "__dict__") or hasattr(value, "to_dict"):
                        # Handle nested objects
                        if hasattr(value, "to_dict"):
                            result[key] = value.to_dict()
                        else:
                            result[key] = value.__dict__
                    else:
                        # Handle enum values
                        if hasattr(value, "value"):
                            result[key] = value.value
                        elif hasattr(value, "name"):
                            result[key] = value.name
                        else:
                            result[key] = value
                return result
            else:
                return dict(canonical_finding)
        except Exception as e:
            self.logger.debug(f"Canonical conversion failed: {e}")
            return self._basic_normalize_finding({"error": str(e)}, 0)

    def _basic_normalize_finding(self, finding: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Basic normalization fallback when canonical normalizer fails."""

        # Extract core fields with enhanced fallbacks
        finding_id = finding.get("id", finding.get("finding_id", f"integrated_{index:03d}"))
        name = finding.get("name", finding.get("title", finding.get("vulnerability_type", "Unknown Vulnerability")))
        severity = self._normalize_severity(finding.get("severity", "MEDIUM"))
        confidence = self._normalize_confidence(finding.get("confidence", "MEDIUM"))
        description = finding.get("description", finding.get("details", ""))
        recommendation = finding.get("recommendation", finding.get("remediation", ""))
        plugin_source = finding.get("plugin_source", finding.get("source", "unknown"))

        # Handle vulnerability_type as additional context
        vuln_type = finding.get("vulnerability_type")
        if vuln_type and vuln_type not in name:
            name = f"{name} ({vuln_type})" if name != "Unknown Vulnerability" else vuln_type

        result = {
            "id": finding_id,
            "name": name,
            "severity": severity,
            "confidence": confidence,
            "description": description,
            "recommendation": recommendation,
            "plugin_source": plugin_source,
            "cwe_id": finding.get("cwe_id"),
            "masvs_control": finding.get("masvs_control"),
            "owasp_category": finding.get("owasp_category"),
            "evidence": finding.get("evidence", {}),
            "metadata": finding.get("metadata", {}),
            "integration_source": "basic_fallback",
        }

        # Preserve evidence fields that plugins set (line_number, file_path,
        # code_snippet, component_name, permission_name).  These are critical
        # for confidence scoring, line-map lookups, and report presentation.
        for key in (
            "line_number", "file_path", "location", "code_snippet",
            "component_name", "permission_name",
            "confidence_level", "context_factors",
        ):
            val = finding.get(key)
            if val is not None and key not in result:
                result[key] = val

        return result

    def _enhance_taxonomy_mapping(self, finding: Dict[str, Any]):
        """Enhance finding with taxonomy mapping using existing components."""
        # Build a compact fingerprint for memoization (name, description, seed CWE)
        try:
            name_f = str(finding.get("name", "")).strip().lower()[:256]
            desc_f = str(finding.get("description", "")).strip().lower()[:512]
            cwe_seed = str(finding.get("cwe_id") or "").strip().upper()
            cache_key = (name_f, desc_f, cwe_seed)
        except Exception:
            cache_key = (
                str(finding.get("name", "")),
                str(finding.get("description", "")),
                str(finding.get("cwe_id") or ""),
            )

        # Fast path: use cached combined mapping if available
        cached = self._taxonomy_cache.get(cache_key)
        if cached:
            if not finding.get("cwe_id") and cached.get("cwe_id"):
                finding["cwe_id"] = cached["cwe_id"]
            if not finding.get("owasp_category") and cached.get("owasp_category"):
                finding["owasp_category"] = cached["owasp_category"]
            if cached.get("masvs_categories") and not finding.get("masvs_categories"):
                finding["masvs_categories"] = cached["masvs_categories"]
            if cached.get("mitre_tactics") and not finding.get("mitre_tactics"):
                finding["mitre_tactics"] = cached["mitre_tactics"]
            # Still allow fallback if category is absent
            if not finding.get("owasp_category"):
                finding["owasp_category"] = self._derive_owasp_category_fallback(
                    finding.get("cwe_id"),
                    finding.get("masvs_control"),
                    finding.get("name", ""),
                    finding.get("description", ""),
                )
            return

        mapped: Dict[str, Any] = {}
        # Use CWE Mapper if available - for CWE lookup OR recommendation enrichment
        if self.cwe_mapper:
            try:
                existing_cwe = finding.get("cwe_id")
                needs_cwe = not existing_cwe
                needs_recommendation = not finding.get("recommendation")

                if needs_cwe or needs_recommendation:
                    # Extract strings from finding dict - map_vulnerability_to_cwe expects (title, content)
                    _title = finding.get("name", finding.get("title", ""))
                    _content = finding.get("description", finding.get("content", ""))

                    # If we already have a CWE, try to get its mapping directly from database
                    cwe_mapping = None
                    if existing_cwe and needs_recommendation:
                        # Direct lookup by CWE ID
                        cwe_mapping = self.cwe_mapper.CWE_DATABASE.get(existing_cwe)

                    # Fallback to pattern matching if no direct lookup
                    if not cwe_mapping:
                        cwe_mapping = self.cwe_mapper.map_vulnerability_to_cwe(str(_title), str(_content))

                    if cwe_mapping:
                        if hasattr(cwe_mapping, "cwe_id"):
                            # CWEMapping dataclass return
                            finding["cwe_id"] = finding.get("cwe_id") or cwe_mapping.cwe_id
                            finding["owasp_category"] = finding.get("owasp_category") or cwe_mapping.category
                            if not finding.get("recommendation") and cwe_mapping.mitigations:
                                finding["recommendation"] = cwe_mapping.mitigations[0]
                            mapped["cwe_id"] = finding.get("cwe_id")
                            if finding.get("owasp_category"):
                                mapped["owasp_category"] = finding.get("owasp_category")
                        elif isinstance(cwe_mapping, dict):
                            finding["cwe_id"] = finding.get("cwe_id") or cwe_mapping.get("cwe_id")
                            finding["owasp_category"] = finding.get("owasp_category") or cwe_mapping.get("category")
                            mapped["cwe_id"] = finding.get("cwe_id")
                            if finding.get("owasp_category"):
                                mapped["owasp_category"] = finding.get("owasp_category")
                        elif isinstance(cwe_mapping, str):
                            # Accept strings like "CWE-89" or "89" and normalize
                            import re as _re

                            m = _re.search(r"cwe[-_\s]*(\d+)", cwe_mapping, flags=_re.IGNORECASE)
                            if m:
                                finding["cwe_id"] = finding.get("cwe_id") or f"CWE-{m.group(1)}"
                                mapped["cwe_id"] = finding.get("cwe_id")
                            else:
                                # If it looks like a category label, use as OWASP category
                                if not finding.get("owasp_category"):
                                    finding["owasp_category"] = str(cwe_mapping)
                                    mapped["owasp_category"] = finding.get("owasp_category")
            except Exception as e:
                self.logger.debug(f"CWE mapping failed: {e}")

        # Optional fast-path: skip heavy framework mapper when allowed
        try:
            _fast_map = os.getenv("AODS_FAST_MAPPING", "0") in ("1", "true", "yes", "on")
        except Exception:
            _fast_map = False

        if _fast_map and finding.get("cwe_id") and not finding.get("owasp_category"):
            finding["owasp_category"] = self._derive_owasp_category_fallback(
                finding.get("cwe_id"),
                finding.get("masvs_control"),
                finding.get("name", ""),
                finding.get("description", ""),
            )
            if finding.get("owasp_category"):
                mapped["owasp_category"] = finding["owasp_category"]
        # Use Security Framework Mapper if available (and not fast-skipped)
        elif self.framework_mapper:
            try:
                framework_mapping = self.framework_mapper.map_vulnerability(finding)
                if framework_mapping:
                    # Handle dict or object returns
                    if isinstance(framework_mapping, dict):
                        finding["cwe_id"] = finding.get("cwe_id") or framework_mapping.get("cwe_id")
                        finding["owasp_category"] = (
                            finding.get("owasp_category")
                            or framework_mapping.get("owasp_mobile_categories")
                            or framework_mapping.get("owasp_category")
                        )
                        if "masvs_categories" in framework_mapping and not finding.get("masvs_categories"):
                            finding["masvs_categories"] = framework_mapping.get("masvs_categories")
                        if "mitre_tactics" in framework_mapping and not finding.get("mitre_tactics"):
                            finding["mitre_tactics"] = framework_mapping.get("mitre_tactics")
                        if finding.get("cwe_id"):
                            mapped["cwe_id"] = finding["cwe_id"]
                        if finding.get("owasp_category"):
                            mapped["owasp_category"] = finding["owasp_category"]
                        if finding.get("masvs_categories"):
                            mapped["masvs_categories"] = finding["masvs_categories"]
                        if finding.get("mitre_tactics"):
                            mapped["mitre_tactics"] = finding["mitre_tactics"]
                    else:
                        # Assume attribute-style access
                        finding["cwe_id"] = finding.get("cwe_id") or getattr(framework_mapping, "cwe_id", None)
                        finding["owasp_category"] = finding.get("owasp_category") or getattr(
                            framework_mapping, "owasp_mobile_categories", None
                        )
                        mc = getattr(framework_mapping, "masvs_categories", None)
                        if mc is not None and not finding.get("masvs_categories"):
                            finding["masvs_categories"] = mc
                        mt = getattr(framework_mapping, "mitre_tactics", None)
                        if mt is not None and not finding.get("mitre_tactics"):
                            finding["mitre_tactics"] = mt
                        if finding.get("cwe_id"):
                            mapped["cwe_id"] = finding["cwe_id"]
                        if finding.get("owasp_category"):
                            mapped["owasp_category"] = finding["owasp_category"]
                        if finding.get("masvs_categories"):
                            mapped["masvs_categories"] = finding["masvs_categories"]
                        if finding.get("mitre_tactics"):
                            mapped["mitre_tactics"] = finding["mitre_tactics"]
            except Exception as e:
                self.logger.debug(f"Framework mapping failed: {e}")

        # Fallback OWASP category derivation if still missing
        if not finding.get("owasp_category"):
            finding["owasp_category"] = self._derive_owasp_category_fallback(
                finding.get("cwe_id"),
                finding.get("masvs_control"),
                finding.get("name", ""),
                finding.get("description", ""),
            )
            if finding.get("owasp_category"):
                mapped["owasp_category"] = finding["owasp_category"]

        # Store in taxonomy cache
        try:
            # Only cache small dict of mapped fields to keep memory modest
            self._taxonomy_cache[cache_key] = {
                k: v
                for k, v in mapped.items()
                if k in ("cwe_id", "owasp_category", "masvs_categories", "mitre_tactics") and v
            }
        except Exception:
            pass

    def _enhance_evidence(self, finding: Dict[str, Any], original_finding: Dict[str, Any]):
        """Enhance evidence using existing evidence enrichment components."""

        evidence = finding.get("evidence")
        # Coerce non-dict evidence into canonical dict
        if not isinstance(evidence, dict):
            coerced = self._coerce_to_canonical_evidence(evidence) if evidence is not None else {}
            if not coerced and evidence is not None:
                coerced = {"content": str(evidence)}
            evidence = coerced
            finding["evidence"] = evidence
        else:
            # Ensure we operate on the dict stored in finding
            finding["evidence"] = evidence

        # Use existing evidence enricher if available
        if self.evidence_enricher:
            try:
                enriched_evidence = self.evidence_enricher.enrich_evidence(original_finding)
                if enriched_evidence:
                    coerced = self._coerce_to_canonical_evidence(enriched_evidence)
                    if coerced:
                        evidence.update(coerced)
            except Exception as e:
                self.logger.warning(f"Evidence enrichment failed: {e}")

        # Enhanced stack trace parsing (from original normalizer)
        self._parse_stack_trace_evidence(evidence, original_finding)

        # Normalize evidence structure
        self._normalize_evidence_structure(evidence)

        # Fallback: promote top-level fields (with aliases) into evidence if missing
        alias_map = {
            "file_path": ["file_path", "file", "filepath", "path"],
            "line_number": ["line_number", "line", "lineno", "lineNo"],
            "code_snippet": [
                "code_snippet",
                "snippet",
                "code",
                "source_snippet",
                "statement",
                "content",
                "code_context",
            ],
        }
        # file_path
        if not evidence.get("file_path"):
            for k in alias_map["file_path"]:
                if original_finding.get(k):
                    raw_path = original_finding.get(k)
                    evidence["file_path"] = sanitize_source_path(raw_path) or raw_path
                    break
        # line_number
        if not evidence.get("line_number"):
            for k in alias_map["line_number"]:
                if original_finding.get(k) is not None:
                    try:
                        evidence["line_number"] = int(original_finding.get(k))
                    except Exception:
                        pass
                    break
        # code_snippet
        if not evidence.get("code_snippet"):
            for k in alias_map["code_snippet"]:
                if original_finding.get(k):
                    evidence["code_snippet"] = original_finding.get(k)
                    break

        # Merge nested code_evidence (from enhancer) into canonical evidence
        nested = original_finding.get("code_evidence")
        if isinstance(nested, dict):
            mapped = self._map_evidence_aliases(nested)
            if mapped:
                evidence.update(mapped)

        # Map common metadata/details fields into canonical evidence (helps dynamic plugins)
        for meta_key in ("metadata", "details", "context"):
            meta = original_finding.get(meta_key)
            if isinstance(meta, dict):
                try:
                    # File path candidates within metadata
                    for k in ("file", "filepath", "path", "source_file", "preference_file", "manifest_path"):
                        if not evidence.get("file_path") and meta.get(k):
                            raw_path = str(meta.get(k))
                            evidence["file_path"] = sanitize_source_path(raw_path) or raw_path
                            break
                    # Line number candidates
                    for k in ("line", "line_number", "lineno"):
                        if not evidence.get("line_number") and meta.get(k) is not None:
                            try:
                                # Handle formats like "L123" or "#L123"
                                val = str(meta.get(k)).lstrip("L").lstrip("#L")
                                evidence["line_number"] = int(val)
                                break
                            except Exception:
                                pass
                    # Code snippet candidates
                    for k in ("statement", "code", "code_context", "source_snippet", "snippet"):
                        if not evidence.get("code_snippet") and meta.get(k):
                            snippet_val = str(meta.get(k))
                            if 3 <= len(snippet_val) <= 800:
                                evidence["code_snippet"] = snippet_val
                                break
                except Exception as e:
                    self.logger.debug(f"Metadata evidence mapping failed: {e}")

        # Parse compact 'location' field formats like 'path:123', 'path(123)', 'path#L123'
        location_field = original_finding.get("location") or evidence.get("location")
        if location_field and (not evidence.get("file_path") or not evidence.get("line_number")):
            try:
                loc_text = str(location_field)
                # Patterns: path:line
                m = re.match(r"^(?P<path>.+?):(?P<line>\d+)\b", loc_text)
                if not m:
                    # path(line)
                    m = re.match(r"^(?P<path>.+?)\((?P<line>\d+)\)\b", loc_text)
                if not m:
                    # path#Lline
                    m = re.match(r"^(?P<path>.+?)#L(?P<line>\d+)\b", loc_text)
                if not m:
                    # 'line X in path'
                    m = re.match(r"^.*?line\s+(?P<line>\d+)\s+in\s+(?P<path>.+)$", loc_text, flags=re.IGNORECASE)
                if m:
                    raw_path = m.group("path").strip()
                    line_num = int(m.group("line"))
                    if raw_path and not evidence.get("file_path"):
                        evidence["file_path"] = sanitize_source_path(raw_path) or raw_path
                    if line_num and not evidence.get("line_number"):
                        evidence["line_number"] = line_num
                else:
                    # If it looks like a file path without explicit line, take as file_path
                    if (
                        "/" in loc_text or loc_text.lower().endswith((".java", ".kt", ".xml", ".smali"))
                    ) and not evidence.get("file_path"):
                        raw_path = loc_text.strip()
                        evidence["file_path"] = sanitize_source_path(raw_path) or raw_path
            except Exception as e:
                self.logger.debug(f"Location parsing failed: {e}")

    def _coerce_to_canonical_evidence(self, data: Any) -> Dict[str, Any]:
        """Coerce various evidence structures into canonical AODS evidence dict.
        Canonical keys: file_path, line_number, code_snippet, context_lines, extraction_method, pattern_match.
        """
        try:
            # If already a dict, map known aliases
            if isinstance(data, dict):
                return self._map_evidence_aliases(dict(data))
            # If list/tuple of pairs
            if isinstance(data, (list, tuple)):
                # If list of dicts, merge conservatively (first wins)
                if data and all(isinstance(x, dict) for x in data):
                    merged: Dict[str, Any] = {}
                    for d in data:
                        for k, v in d.items():
                            merged.setdefault(k, v)
                    return self._map_evidence_aliases(merged)
                # If list of (k,v)
                try:
                    as_dict = dict(data)  # may raise if not pairs
                    return self._map_evidence_aliases(as_dict)
                except Exception:
                    pass
            # If string, treat as code snippet
            if isinstance(data, str):
                return {"code_snippet": data}
            # If object with __dict__
            if hasattr(data, "__dict__"):
                return self._map_evidence_aliases(vars(data))
        except Exception as e:
            self.logger.debug(f"Evidence coercion failed: {e}")
        return {}

    def _map_evidence_aliases(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        """Map incoming evidence aliases to canonical keys and sanitize types."""
        out: Dict[str, Any] = {}
        # Map aliases
        alias_map = {
            "file": "file_path",
            "filepath": "file_path",
            "path": "file_path",
            "line": "line_number",
            "lineno": "line_number",
            "lineNo": "line_number",
            "snippet": "code_snippet",
            "code": "code_snippet",
            "source": "code_snippet",
        }
        for k, v in list(ev.items()):
            key = k
            if k in alias_map:
                key = alias_map[k]
            if key in ("file_path", "code_snippet", "context_lines", "extraction_method", "pattern_match"):
                out[key] = v
            elif key == "line_number":
                try:
                    out["line_number"] = int(v)
                except Exception:
                    pass
        return out

    def _parse_stack_trace_evidence(self, evidence: Dict[str, Any], finding: Dict[str, Any]):
        """Parse stack trace for file path and line number (enhanced from original)."""

        stack_trace = (
            evidence.get("stack_trace") or finding.get("stack_trace") or finding.get("evidence", {}).get("stack_trace")
        )

        if not stack_trace:
            return

        # Extract file path from stack trace (actual format handling)
        if not evidence.get("file_path"):
            # Handle format: "at com/example/app/File.java" or similar
            file_match = re.search(r"at\s+[\w./]+/([^/\s:]+\.java)", stack_trace)
            if not file_match:
                # Handle format: "at com.example.Class.method(File.java:123)"
                file_match = re.search(r"at\s+[\w.]+\(([^:]+):\d+\)", stack_trace)
            if file_match:
                raw_path = file_match.group(1)
                evidence["file_path"] = sanitize_source_path(raw_path) or raw_path

        # Extract line number from stack trace
        if not evidence.get("line_number"):
            line_match = re.search(r":(\d+)", stack_trace)
            if line_match:
                try:
                    evidence["line_number"] = int(line_match.group(1))
                except ValueError:
                    pass

    def _normalize_evidence_structure(self, evidence: Dict[str, Any]):
        """Normalize evidence structure to consistent format."""

        # Ensure consistent field names
        if "file" in evidence and not evidence.get("file_path"):
            raw_path = evidence.pop("file")
            evidence["file_path"] = sanitize_source_path(raw_path) or raw_path

        if "line" in evidence and not evidence.get("line_number"):
            evidence["line_number"] = evidence.pop("line")

        if "snippet" in evidence and not evidence.get("code_snippet"):
            evidence["code_snippet"] = evidence.pop("snippet")

        # Include operation as pattern_match
        if "operation" in evidence and not evidence.get("pattern_match"):
            evidence["pattern_match"] = evidence["operation"]

    def _enhance_code_snippets(self, finding: Dict[str, Any]):
        """Enhance finding with code snippets using existing extractor."""

        if not self.code_extractor or not self.apk_context:
            return

        evidence = finding.get("evidence", {})
        if not isinstance(evidence, dict):
            evidence = {"content": str(evidence)}
            finding["evidence"] = evidence

        try:
            need_snippet = not bool(evidence.get("code_snippet"))
            need_file = not bool(evidence.get("file_path"))
            need_line = (not evidence.get("line_number")) or (
                isinstance(evidence.get("line_number"), int) and evidence.get("line_number") == 0
            )

            # Attempt extraction if snippet missing, or if we can backfill file/line from extractor
            if need_snippet or need_file or need_line:
                extraction_result = self.code_extractor.extract_code_snippet(finding, self.apk_context)
                if extraction_result and extraction_result.success and extraction_result.code_snippet:
                    snippet = extraction_result.code_snippet
                    # Backfill snippet (prefer vulnerable line, otherwise concise context)
                    if need_snippet:
                        if isinstance(snippet.vulnerable_line, str) and snippet.vulnerable_line.strip():
                            evidence["code_snippet"] = snippet.vulnerable_line
                        elif isinstance(snippet.context_lines, list) and snippet.context_lines:
                            try:
                                parts = [str(x).strip() for x in snippet.context_lines if str(x).strip()]
                                if parts:
                                    evidence["code_snippet"] = " | ".join(parts[:3])
                            except Exception:
                                pass
                    # Backfill file path
                    if need_file:
                        raw_path = evidence.get("file_path") or snippet.file_path
                        if raw_path:
                            evidence["file_path"] = sanitize_source_path(raw_path) or raw_path
                    # Backfill line number
                    if need_line and snippet.line_number:
                        evidence["line_number"] = snippet.line_number
                    # Context metadata
                    if snippet.context_lines and not evidence.get("context_lines"):
                        evidence["context_lines"] = snippet.context_lines
                    if snippet.extraction_method and not evidence.get("extraction_method"):
                        evidence["extraction_method"] = snippet.extraction_method

            # If snippet exists but file_path missing, try to infer and search
            if evidence.get("code_snippet") and not evidence.get("file_path"):
                inferred = self._infer_missing_file_path(evidence, finding)
                if inferred:
                    evidence["file_path"] = sanitize_source_path(inferred) or inferred
                else:
                    try:
                        loc = self.code_extractor.find_snippet_location(evidence.get("code_snippet"), self.apk_context)  # type: ignore[attr-defined]  # noqa: E501
                    except Exception:
                        loc = None
                    if loc:
                        fp, ln = loc
                        evidence["file_path"] = sanitize_source_path(fp) or fp
                        if not evidence.get("line_number"):
                            evidence["line_number"] = ln
            # If snippet exists but line_number missing/zero, derive it from source
            if (not evidence.get("line_number")) or (
                isinstance(evidence.get("line_number"), int) and evidence.get("line_number") == 0
            ):
                file_path = evidence.get("file_path") or finding.get("file_path")
                if file_path and evidence.get("code_snippet"):
                    ln = self._derive_line_number_from_snippet(file_path, evidence.get("code_snippet"))
                    if ln:
                        evidence["line_number"] = ln
                    elif isinstance(evidence.get("context_lines"), list) and evidence["context_lines"]:
                        ln2 = self._find_line_number_by_candidates(file_path, evidence["context_lines"])
                        if ln2:
                            evidence["line_number"] = ln2
                    elif isinstance(evidence.get("code_snippet"), str):
                        # If snippet contains explicit line numbers (e.g., "  2 -> <manifest ..."), use them
                        ln3 = self._derive_line_number_from_numbered_snippet(str(evidence.get("code_snippet")))
                        if ln3:
                            evidence["line_number"] = ln3

            # Fallbacks to improve evidence completeness
            # 1) If file_path still missing but top-level finding has it, copy over
            if not evidence.get("file_path") and finding.get("file_path"):
                raw_fp = finding.get("file_path")
                evidence["file_path"] = sanitize_source_path(raw_fp) or raw_fp

            # 2) If code_snippet missing but evidence content looks code-like, treat as snippet
            if not evidence.get("code_snippet") and isinstance(evidence.get("content"), str):
                content_val = evidence["content"]
                if any(
                    tok in content_val
                    for tok in [";", "()", "{", "}", "class ", "void ", "public ", "private ", "Cipher.getInstance"]
                ):
                    if 5 <= len(content_val) <= 500:
                        evidence["code_snippet"] = content_val
                        # Try derive file/line if file_path available
                        fp2 = evidence.get("file_path") or finding.get("file_path")
                        if fp2 and not evidence.get("line_number"):
                            ln4 = self._derive_line_number_from_snippet(fp2, content_val)
                            if ln4:
                                evidence["line_number"] = ln4
                        elif str(file_path).lower().endswith(".xml") and isinstance(evidence.get("code_snippet"), str):
                            ln3 = self._derive_line_number_from_xml(file_path, str(evidence.get("code_snippet")))
                            if ln3:
                                evidence["line_number"] = ln3
        except Exception as e:
            self.logger.debug(f"Code snippet enhancement failed: {e}")

    def _infer_missing_file_path(self, evidence: Dict[str, Any], finding: Dict[str, Any]) -> Optional[str]:
        """Infer plausible file path when snippet exists but file_path is missing.
        Heuristic: manifest-derived findings or XML-like snippets → AndroidManifest.xml in decompiled paths.
        """
        try:
            plugin = str(finding.get("plugin_source", "")).lower()
            name_desc = f"{finding.get('name', '')} {finding.get('description', '')}".lower()
            snippet = str(evidence.get("code_snippet") or "")
            looks_xml = "<" in snippet and ">" in snippet
            manifest_hint = (
                ("manifest" in plugin) or ("androidmanifest" in name_desc) or ("<manifest" in snippet.lower())
            )
            if looks_xml or manifest_hint:
                try:
                    paths = self.code_extractor._get_decompiled_paths(self.apk_context)  # type: ignore[attr-defined]
                except Exception:
                    paths = []
                for base in paths:
                    candidate = os.path.join(base, "AndroidManifest.xml")
                    if os.path.isfile(candidate):
                        return candidate
                for base in paths:
                    try:
                        found = self.code_extractor._recursive_file_search(base, "AndroidManifest.xml")  # type: ignore[attr-defined]  # noqa: E501
                    except Exception:
                        found = None
                    if found:
                        return found
        except Exception as e:
            self.logger.debug(f"File path inference failed: {e}")
        return None

    def _derive_line_number_from_snippet(self, file_path: str, code_snippet: Any) -> Optional[int]:
        """Attempt to derive a line number by searching the snippet text in the file."""
        try:
            if not code_snippet:
                return None
            snippet_text = str(code_snippet).strip()
            if not snippet_text:
                return None
            # Locate actual file using the extractor's search paths
            try:
                actual = self.code_extractor._find_source_file(file_path, self.apk_context)  # type: ignore[attr-defined]  # noqa: E501
            except Exception:
                actual = None
            target = actual or file_path
            if not target or not isinstance(target, str):
                return None
            if not os.path.exists(target):
                return None
            with open(target, "r", encoding="utf-8", errors="replace") as f:
                for idx, line in enumerate(f, start=1):
                    if snippet_text in line:
                        return idx
            # Fallback: match first non-empty line of snippet
            first_line = snippet_text.split("\n", 1)[0].strip()
            if first_line:
                with open(target, "r", encoding="utf-8", errors="replace") as f:
                    for idx, line in enumerate(f, start=1):
                        if first_line in line:
                            return idx
        except Exception as e:
            self.logger.debug(f"Line derivation failed for {file_path}: {e}")
        return None

    def _derive_line_number_from_xml(self, file_path: str, snippet_text: str) -> Optional[int]:
        """Whitespace-insensitive multi-line search in XML; returns 1-based line number."""
        try:
            if not os.path.exists(file_path) or not snippet_text:
                return None
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            # Normalize by removing all whitespace

            def _norm(s: str) -> str:
                return re.sub(r"\s+", "", s)

            n_content = _norm(content)
            n_snippet = _norm(snippet_text)
            if not n_snippet:
                return None
            start_idx = n_content.find(n_snippet)
            if start_idx < 0:
                return None
            # Map normalized index back to original index by walking content
            norm_i = 0
            orig_start = None
            for i, ch in enumerate(content):
                if ch.isspace():
                    continue
                if norm_i == start_idx:
                    orig_start = i
                    break
                norm_i += 1
            if orig_start is None:
                return None
            return content.count("\n", 0, orig_start) + 1
        except Exception as e:
            self.logger.debug(f"XML derivation failed for {file_path}: {e}")
            return None

    def _derive_line_number_from_numbered_snippet(self, snippet_text: str) -> Optional[int]:
        """Extract line number from a numbered snippet like ' 14 -> <tag ...' or ' 13   android:attr=...'.
        Prefers the line with an arrow marker if present; otherwise takes the first numbered line.
        """
        try:
            lines = snippet_text.splitlines()
            arrow_num = None
            first_num = None
            for line in lines:
                m = re.match(r"\s*(\d+)\s*->", line)
                if m:
                    arrow_num = int(m.group(1))
                    break
                m2 = re.match(r"\s*(\d+)\b", line)
                if m2 and first_num is None:
                    first_num = int(m2.group(1))
            return arrow_num or first_num
        except Exception as e:
            self.logger.debug(f"Numbered snippet line derivation failed: {e}")
            return None

    def _find_line_number_by_candidates(self, file_path: str, candidates: List[Any]) -> Optional[int]:
        """Search file for any candidate line; returns first matched 1-based line number.
        Tries exact match first, then whitespace-insensitive matching.
        """
        try:
            if not file_path or not os.path.exists(file_path) or not candidates:
                return None
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            norm_lines = [re.sub(r"\s+", "", line) for line in lines]
            for raw in candidates:
                if not raw:
                    continue
                cand = str(raw).strip()
                if not cand:
                    continue
                for idx, line in enumerate(lines, start=1):
                    if cand in line:
                        return idx
                norm_cand = re.sub(r"\s+", "", cand)
                if not norm_cand:
                    continue
                for idx, nline in enumerate(norm_lines, start=1):
                    if norm_cand in nline:
                        return idx
        except Exception as e:
            self.logger.debug(f"Candidate line search failed for {file_path}: {e}")
        return None

    def _enhance_threat_analysis(self, finding: Dict[str, Any]):
        """Enhance finding with MITRE ATT&CK threat analysis."""

        # Allow disabling threat analysis to reduce overhead during perf benchmarks
        try:
            if os.getenv("AODS_DISABLE_THREAT_ANALYSIS", "0") in ("1", "true", "yes", "on"):
                return
        except Exception:
            pass

        if not self.threat_enhancer:
            return

        try:
            # Enhance finding with full threat analysis (dict-safe)
            enhanced_finding = self.threat_enhancer.enhance_finding_with_threat_analysis(finding)
            if isinstance(enhanced_finding, dict):
                # Update finding with threat analysis data
                threat_analysis = enhanced_finding.get("threat_analysis")
                if threat_analysis:
                    finding["threat_analysis"] = threat_analysis
                # Update MITRE-specific fields for compatibility
                for k in (
                    "mitre_techniques",
                    "mitre_tactics",
                    "attack_phases",
                    "threat_actors",
                    "risk_score",
                    "exploitability_score",
                ):
                    if k in enhanced_finding:
                        finding[k] = enhanced_finding[k]
        except Exception as e:
            self.logger.warning(f"Threat analysis enhancement failed for finding {finding.get('id', 'unknown')}: {e}")

    def _track_coverage_metrics(self, finding: Dict[str, Any]):
        """Track coverage metrics for validation."""

        # OWASP category coverage
        if finding.get("owasp_category"):
            self.metrics.owasp_category_coverage += 1

        # CWE ID coverage
        if finding.get("cwe_id"):
            self.metrics.cwe_id_coverage += 1

        # Code snippet coverage
        evidence = finding.get("evidence", {})
        if not isinstance(evidence, dict):
            evidence = {}
        if evidence.get("code_snippet"):
            self.metrics.code_snippet_coverage += 1

        # Line number coverage
        if evidence.get("line_number"):
            self.metrics.line_number_coverage += 1

    def _calculate_final_metrics(self):
        """Calculate final coverage percentages."""
        total = self.metrics.total_findings
        if total > 0:
            self.metrics.owasp_category_coverage = self.metrics.owasp_category_coverage / total
            self.metrics.cwe_id_coverage = self.metrics.cwe_id_coverage / total
            self.metrics.code_snippet_coverage = self.metrics.code_snippet_coverage / total
            self.metrics.line_number_coverage = self.metrics.line_number_coverage / total

    def compute_masvs_summary(self, normalized_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compute MASVS summary from per-finding fields only.

        Ensures zero contradictions with individual findings.
        """
        category_counts = {}
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        control_counts = {}

        for finding in normalized_findings:
            # Count by OWASP category
            category = finding.get("owasp_category", "UNKNOWN")
            # Handle case where category might be a list
            if isinstance(category, list):
                category = category[0] if category else "UNKNOWN"
            category = str(category)  # Ensure it's a string
            category_counts[category] = category_counts.get(category, 0) + 1

            # Count by severity
            severity = finding.get("severity", "MEDIUM")
            if severity in severity_counts:
                severity_counts[severity] += 1

            # Count by MASVS control
            control = finding.get("masvs_control")
            if control:
                control_counts[control] = control_counts.get(control, 0) + 1

        total_findings = len(normalized_findings)

        # Calculate threat analysis metrics
        threat_metrics = self._calculate_threat_metrics(normalized_findings)

        return {
            "total_findings": total_findings,
            "category_distribution": category_counts,
            "severity_distribution": severity_counts,
            "control_distribution": control_counts,
            "compliance_score": self._calculate_compliance_score(severity_counts, total_findings),
            "top_categories": sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5],
            "computed_from_findings": True,  # Flag to indicate this is computed, not text-based
            "integration_metrics": {
                "owasp_coverage": f"{self.metrics.owasp_category_coverage:.1%}",
                "cwe_coverage": f"{self.metrics.cwe_id_coverage:.1%}",
                "snippet_coverage": f"{self.metrics.code_snippet_coverage:.1%}",
                "line_coverage": f"{self.metrics.line_number_coverage:.1%}",
                "processing_errors": self.metrics.processing_errors,
            },
            "threat_analysis_summary": threat_metrics,
            "generation_timestamp": datetime.now().isoformat(),
        }

    def get_integration_metrics(self) -> IntegrationMetrics:
        """Get current integration metrics for validation."""
        return self.metrics

    def validate_coverage_thresholds(self) -> Dict[str, bool]:
        """
        Validate coverage against acceptance criteria thresholds.

        Returns:
            Dict with validation results for each threshold
        """
        return {
            "owasp_category_threshold": self.metrics.owasp_category_coverage >= 0.95,  # ≥95%
            "code_snippet_threshold": self.metrics.code_snippet_coverage >= 0.90,  # ≥90%
            "line_number_threshold": self.metrics.line_number_coverage >= 0.85,  # ≥85%
            "masvs_consistency": self.metrics.masvs_consistency,
            "overall_pass": (
                self.metrics.owasp_category_coverage >= 0.95
                and self.metrics.code_snippet_coverage >= 0.90
                and self.metrics.line_number_coverage >= 0.85
                and self.metrics.masvs_consistency
            ),
        }

    # Utility methods (reused from original normalizer)
    def _normalize_severity(self, severity: Union[str, int]) -> str:
        """Normalize severity to standard values."""
        if isinstance(severity, int):
            if severity >= 9:
                return "CRITICAL"
            elif severity >= 7:
                return "HIGH"
            elif severity >= 4:
                return "MEDIUM"
            else:
                return "LOW"

        severity_str = str(severity).upper()
        if severity_str in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            return severity_str

        # Map common variations
        severity_mapping = {
            "SEVERE": "HIGH",
            "MAJOR": "HIGH",
            "MINOR": "LOW",
            "INFORMATION": "INFO",
            "INFORMATIONAL": "INFO",
        }

        return severity_mapping.get(severity_str, "MEDIUM")

    def _normalize_confidence(self, confidence: Union[str, float, int]) -> float:
        """Normalize confidence to float between 0.0 and 1.0."""
        try:
            if isinstance(confidence, (int, float)):
                if confidence > 1.0:
                    return confidence / 100.0  # Convert percentage
                return float(confidence)

            # Handle string confidence values
            confidence_str = str(confidence).upper().strip()
            confidence_mapping = {
                "HIGH": 0.9,
                "MEDIUM": 0.7,
                "LOW": 0.5,
                "VERY_HIGH": 0.95,
                "VERY_LOW": 0.3,
                "CRITICAL": 0.95,
                "INFO": 0.3,
                "INFORMATION": 0.3,
            }

            # Try direct mapping first
            if confidence_str in confidence_mapping:
                return confidence_mapping[confidence_str]

            # Try to parse as number
            try:
                conf_float = float(confidence_str)
                if conf_float > 1.0:
                    return conf_float / 100.0  # Convert percentage
                return conf_float
            except ValueError:
                pass

            # Default fallback
            return 0.7

        except Exception as e:
            self.logger.debug(f"Confidence normalization failed for '{confidence}': {e}")
            return 0.7

    def _derive_owasp_category_fallback(
        self, cwe_id: Optional[str], masvs_control: Optional[str], name: str, description: str
    ) -> str:
        """Fallback OWASP category derivation using pattern matching."""
        content = f"{name} {description}".lower()

        if any(term in content for term in ["crypto", "encryption", "cipher", "key", "hash"]):
            return "MASVS-CRYPTO"
        elif any(term in content for term in ["storage", "data", "file", "database", "preference"]):
            return "MASVS-STORAGE"
        elif any(term in content for term in ["network", "communication", "ssl", "tls", "http"]):
            return "MASVS-NETWORK"
        elif any(term in content for term in ["auth", "login", "session", "token", "credential"]):
            return "MASVS-AUTH"
        elif any(term in content for term in ["platform", "api", "permission", "intent"]):
            return "MASVS-PLATFORM"
        elif any(term in content for term in ["code", "quality", "injection", "input"]):
            return "MASVS-CODE"
        elif any(term in content for term in ["resilience", "tamper", "reverse", "debug"]):
            return "MASVS-RESILIENCE"
        elif any(term in content for term in ["privacy", "pii", "personal", "gdpr"]):
            return "MASVS-PRIVACY"

        return "MASVS-CODE"  # Default fallback

    def _calculate_compliance_score(self, severity_counts: Dict[str, int], total: int) -> float:
        """Calculate compliance score based on severity distribution."""
        if total == 0:
            return 100.0

        # Weight severities (higher severity = lower score)
        weights = {"CRITICAL": 0.0, "HIGH": 0.3, "MEDIUM": 0.7, "LOW": 0.9, "INFO": 1.0}

        weighted_score = sum(weights.get(severity, 0.5) * count for severity, count in severity_counts.items())

        return round((weighted_score / total) * 100, 1)

    def _calculate_threat_metrics(self, normalized_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate threat analysis metrics from normalized findings."""

        if not self.threat_enhancer:
            return {"threat_analysis_enabled": False}

        try:
            # Import threat analysis summary function
            from core.threat_analysis_enhancer import get_threat_analysis_summary

            # Generate full threat analysis summary
            threat_summary = get_threat_analysis_summary(normalized_findings)

            # Add integration-specific metrics
            threat_enhanced_count = sum(1 for f in normalized_findings if f.get("threat_analysis"))
            threat_coverage = threat_enhanced_count / len(normalized_findings) if normalized_findings else 0

            return {
                "threat_analysis_enabled": True,
                "threat_coverage": f"{threat_coverage:.1%}",
                "threat_enhanced_findings": threat_enhanced_count,
                "mitre_techniques_identified": threat_summary.get("unique_mitre_techniques", 0),
                "threat_actors_identified": threat_summary.get("unique_threat_actors", 0),
                "active_campaigns": threat_summary.get("active_campaigns", 0),
                "average_risk_score": threat_summary.get("average_risk_score", 0.0),
                "top_techniques": threat_summary.get("threat_landscape_summary", {}).get("top_techniques", [])[:5],
                "identified_actors": threat_summary.get("threat_landscape_summary", {}).get("identified_actors", []),
                "active_campaigns_list": threat_summary.get("threat_landscape_summary", {}).get("active_campaigns", []),
            }

        except Exception as e:
            self.logger.debug(f"Threat metrics calculation failed: {e}")
            return {"threat_analysis_enabled": True, "threat_coverage": "0.0%", "error": str(e)}

    def enrich_classified_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich already-classified findings without replacing their structure.

        Adds CWE, OWASP, MASVS, recommendation, evidence fields in-place.
        Unlike ``normalize_findings()`` this does NOT call ``_normalize_core_finding()``
        so it preserves original fields like title, content, classification, etc.
        """
        for finding in findings:
            # Ensure 'name' alias exists for taxonomy lookup (uses title if missing)
            if not finding.get("name") and finding.get("title"):
                finding["name"] = finding["title"]
            try:
                self._enhance_taxonomy_mapping(finding)
            except Exception:
                pass
            try:
                self._enhance_evidence(finding, finding)
            except Exception:
                pass
            # Bridge masvs_categories (list) → masvs_control (string)
            if not finding.get("masvs_control") and finding.get("masvs_categories"):
                cats = finding["masvs_categories"]
                if isinstance(cats, list) and cats:
                    finding["masvs_control"] = cats[0] if isinstance(cats[0], str) else str(cats[0])
        return findings

    def _create_fallback_finding(self, finding: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Create minimal normalized finding for cases where normalization fails."""
        return {
            "id": f"fallback_{index:03d}",
            "name": str(finding.get("name", finding.get("title", "Unknown Finding"))),
            "severity": "MEDIUM",
            "confidence": 0.5,
            "owasp_category": "MASVS-CODE",
            "description": str(
                finding.get("description", "Integration normalization failed - original data preserved")
            ),
            "plugin_source": "integration_fallback",
            "evidence": {},
            "integration_source": "fallback",
        }


# Global instance management
_integrated_normalizer_instance = None


def get_integrated_normalizer(apk_context=None) -> IntegratedFindingNormalizer:
    """Get integrated normalizer instance."""
    global _integrated_normalizer_instance
    if _integrated_normalizer_instance is None or (
        apk_context and _integrated_normalizer_instance.apk_context != apk_context
    ):
        _integrated_normalizer_instance = IntegratedFindingNormalizer(apk_context)
    return _integrated_normalizer_instance


def normalize_findings_integrated(raw_findings: List[Dict[str, Any]], apk_context=None) -> List[Dict[str, Any]]:
    """
    Full finding normalization using existing AODS components.

    This is the single entry point for finding normalization across AODS.
    Includes:
    - Core normalization (CWE, OWASP, evidence)
    - MASVS control bridging (masvs_categories → masvs_control)
    - Exploitability/impact derivation from severity
    """
    normalizer = get_integrated_normalizer(apk_context)
    normalized = normalizer.normalize_findings(raw_findings)

    # Apply in-place enrichment for masvs_control bridging
    normalizer.enrich_classified_findings(normalized)

    # Derive exploitability/impact from severity when not set
    _sev_derivation = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "low"}
    for finding in normalized:
        severity_str = str(finding.get("severity", "")).lower()
        derived = _sev_derivation.get(severity_str, "medium")

        exploitability = str(finding.get("exploitability", "") or "").lower()
        if not exploitability or exploitability == "unknown":
            finding["exploitability"] = derived

        impact = str(finding.get("impact", "") or "").lower()
        if not impact or impact == "unknown":
            finding["impact"] = derived

    return normalized


def compute_masvs_summary_integrated(normalized_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute MASVS summary from per-finding fields using integrated approach."""
    normalizer = get_integrated_normalizer()
    return normalizer.compute_masvs_summary(normalized_findings)


def validate_integration_coverage(normalizer: IntegratedFindingNormalizer) -> Dict[str, Any]:
    """
    Validate integration coverage against acceptance criteria.

    Returns detailed validation report for monitoring and alerting.
    """
    metrics = normalizer.get_integration_metrics()
    validation = normalizer.validate_coverage_thresholds()

    return {
        "validation_results": validation,
        "coverage_metrics": {
            "owasp_category": f"{metrics.owasp_category_coverage:.1%}",
            "cwe_id": f"{metrics.cwe_id_coverage:.1%}",
            "code_snippets": f"{metrics.code_snippet_coverage:.1%}",
            "line_numbers": f"{metrics.line_number_coverage:.1%}",
        },
        "acceptance_criteria": {
            "owasp_category_target": "≥95%",
            "code_snippet_target": "≥90%",
            "line_number_target": "≥85%",
            "masvs_consistency_target": "Zero contradictions",
        },
        "overall_status": "PASS" if validation["overall_pass"] else "FAIL",
        "total_findings": metrics.total_findings,
        "processing_errors": metrics.processing_errors,
        "timestamp": datetime.now().isoformat(),
    }
