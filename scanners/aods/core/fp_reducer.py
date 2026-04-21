#!/usr/bin/env python3
"""
Canonical False Positive Reducer for AODS
==========================================

Single entry point for all FP reduction during scans.  Replaces the previous
7-system chain (UnifiedFalsePositiveCoordinator) with a clean 3-stage pipeline:

  Stage 1 - Confidence dampening for known-noisy plugin/CWE sources
  Stage 2 - ML 8-classifier ensemble prediction
  Stage 3 - Lightweight heuristic rules for obvious FPs the ML may miss

Each stage degrades gracefully if its backing module is unavailable.

Usage::

    from core.fp_reducer import reduce_false_positives
    filtered = reduce_false_positives(findings, scan_context)
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class FPReductionResult:
    """Statistics from a single FP reduction pass."""

    original_count: int = 0
    filtered_count: int = 0
    reduction_percentage: float = 0.0
    stages_applied: List[str] = field(default_factory=list)
    processing_time: float = 0.0


# ---------------------------------------------------------------------------
# Stage 3 heuristic patterns (absorbed from legacy systems)
# ---------------------------------------------------------------------------

# Titles/descriptions that indicate error messages, not vulnerabilities
_ERROR_PATTERNS: List[re.Pattern] = [
    re.compile(r"^error\s*:?\s", re.IGNORECASE),
    re.compile(r"^exception\s*:?\s", re.IGNORECASE),
    re.compile(r"^traceback\s", re.IGNORECASE),
    re.compile(r"^warning\s*:?\s", re.IGNORECASE),
    re.compile(r"failed to (?:parse|load|read|connect)", re.IGNORECASE),
    re.compile(r"^stack trace", re.IGNORECASE),
]

# Titles that are status reports / scan metadata, not findings
_STATUS_PATTERNS: List[re.Pattern] = [
    re.compile(r"^\d+\s+(?:issues?|findings?|results?|items?)\s*$", re.IGNORECASE),
    re.compile(r"^scan (?:completed?|started|summary|status)", re.IGNORECASE),
    re.compile(r"^analysis (?:completed?|summary|results?)\b", re.IGNORECASE),
    re.compile(r"^(?:total|count)\s*:?\s*\d+", re.IGNORECASE),
]

# Titles describing positive security features, not vulnerabilities
_POSITIVE_INDICATOR_PATTERNS: List[re.Pattern] = [
    re.compile(r"positive security indicator", re.IGNORECASE),
    re.compile(r"^network security configuration present", re.IGNORECASE),
    re.compile(r"^app implements \d+ .+detection checks", re.IGNORECASE),
    # Individual emulator/root/proc detection findings (defensive anti-RE features)
    re.compile(r"^(?:emulator string|root binary|debug property|/proc inspection) check:", re.IGNORECASE),
]

# RESILIENCE detection mechanisms (strengths, not weaknesses) - only at LOW/INFO
_RESILIENCE_STRENGTH_PATTERNS: List[re.Pattern] = [
    re.compile(r"MSTG-RESILIENCE-\d+:.*(?:integrity verification|key generation).*detected", re.IGNORECASE),
]

# Description patterns that indicate the finding is a defensive feature, not a vuln
_DEFENSIVE_DESCRIPTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"defensive anti-reverse-engineering feature, not a vulnerability", re.IGNORECASE),
    re.compile(r"no action needed.*recommended resilience practice", re.IGNORECASE),
]

# Android framework auto-generated permission - not a real naming/protection issue
_ANDROID_FRAMEWORK_FP_PATTERN = re.compile(
    r"DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION", re.IGNORECASE,
)

# Path segments indicating test / build artifact code
_TEST_PATH_SEGMENTS = frozenset({
    "test", "tests", "testing", "mock", "mocks", "fixture",
    "fixtures", "sample", "example", "demo", "build",
    "generated", "__pycache__",
})


# ---------------------------------------------------------------------------
# Canonical reducer
# ---------------------------------------------------------------------------

class CanonicalFPReducer:
    """3-stage false positive reduction pipeline.

    Instantiate once per scan.  Thread-safe for the read-only stages;
    the dampener mutates per-finding confidence in-place (acceptable).
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self._config = config or {}
        self._dampener = self._init_dampener()
        self._ml_reducer = self._init_ml_reducer()

    # -- lazy init helpers --------------------------------------------------

    def _init_dampener(self):
        try:
            from core.noise_source_dampener import NoiseSourceDampener
            return NoiseSourceDampener(self._config.get("dampening"))
        except Exception as exc:
            logger.debug("Noise dampener unavailable: %s", exc)
            return None

    def _init_ml_reducer(self):
        if os.environ.get("AODS_DISABLE_ML", "0") == "1":
            logger.info("ML FP reducer skipped (AODS_DISABLE_ML=1)")
            return None
        try:
            from core.ml_false_positive_reducer import OptimizedMLFalsePositiveReducer
            fp_config = {"ml_enhancement": {"model_dir": "models/unified_ml/false_positive"}}
            return OptimizedMLFalsePositiveReducer(fp_config)
        except Exception as exc:
            logger.debug("ML FP reducer unavailable: %s", exc)
            return None

    # -- public API ---------------------------------------------------------

    def reduce(
        self,
        findings: List[Dict[str, Any]],
        _scan_context: Optional[Dict[str, Any]] = None,
    ) -> tuple[List[Dict[str, Any]], FPReductionResult]:
        """Run the 3-stage pipeline and return (filtered_findings, stats).

        ``_scan_context`` is accepted for interface compatibility but not
        currently used - the individual stages extract context from findings.
        """
        start = time.time()
        original_count = len(findings)
        stages: List[str] = []

        # Stage 1: confidence dampening for noisy sources
        if self._dampener is not None:
            try:
                before = len(findings)
                findings = self._dampener.reduce_false_positives(findings)
                if len(findings) != before:
                    stages.append("noise_dampener")
            except Exception as exc:
                logger.warning("Stage 1 (dampener) failed: %s", exc)

        # Stage 2: ML ensemble
        if self._ml_reducer is not None:
            try:
                before = len(findings)
                findings = self._ml_reducer.reduce_false_positives(findings)
                if len(findings) != before:
                    stages.append("ml_ensemble")
            except Exception as exc:
                logger.warning("Stage 2 (ML) failed: %s", exc)

        # Stage 3: heuristic pattern rules
        before = len(findings)
        findings = _apply_heuristic_rules(findings)
        if len(findings) != before:
            stages.append("heuristic_rules")

        # Stage 4: location-based semantic dedup
        before = len(findings)
        findings = dedup_by_location(findings)
        if len(findings) != before:
            stages.append("location_dedup")

        # Stage 5: cross-detector semantic overlap dedup
        before = len(findings)
        findings = dedup_semantic_overlaps(findings)
        if len(findings) != before:
            stages.append("semantic_overlap")

        filtered_count = len(findings)
        elapsed = time.time() - start
        reduction = (
            (original_count - filtered_count) / original_count * 100
            if original_count > 0
            else 0.0
        )

        result = FPReductionResult(
            original_count=original_count,
            filtered_count=filtered_count,
            reduction_percentage=round(reduction, 2),
            stages_applied=stages,
            processing_time=round(elapsed, 4),
        )

        if stages:
            logger.info(
                "FP reduction complete: %d → %d (%.1f%%) via %s",
                original_count, filtered_count, reduction, ", ".join(stages),
            )
            # ML audit trail - log aggregate FP reduction decision
            try:
                from core.api.auth_helpers import _audit_ml_decision
                _audit_ml_decision(
                    finding_id=f"batch:{original_count}_findings",
                    stage="fp_pipeline",
                    decision="reduce",
                    details={
                        "original": original_count,
                        "filtered": filtered_count,
                        "removed": original_count - filtered_count,
                        "stages": stages,
                        "reduction_pct": round(reduction, 1),
                    },
                )
            except Exception:
                pass
        else:
            logger.debug("FP reduction: no findings removed (%d total)", filtered_count)

        return findings, result


# ---------------------------------------------------------------------------
# Stage 3 implementation
# ---------------------------------------------------------------------------

def dedup_by_location(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove semantic duplicates: same file + CWE from different detectors.

    When two findings point to the same code location with the same CWE,
    keeps the one with higher confidence. This eliminates double-counting
    when both a plugin and a semgrep rule detect the same issue.

    Args:
        findings: List of finding dicts.

    Returns:
        Deduplicated list (may be shorter than input).
    """
    if not findings:
        return findings

    seen: Dict[tuple, Dict[str, Any]] = {}
    seen_broad: Dict[tuple, Dict[str, Any]] = {}  # (file, CWE) → finding
    no_location: List[Dict[str, Any]] = []
    removed = 0

    for f in findings:
        file_path = f.get("file_path", f.get("file", f.get("location", "")))
        cwe = f.get("cwe_id", f.get("cwe", ""))
        line = f.get("line_number")

        # Can't dedup without at least file + CWE
        if not file_path or not cwe:
            no_location.append(f)
            continue

        # Primary key: exact match (file, CWE, line)
        key = (str(file_path), str(cwe), line)
        # Secondary key: file + CWE only (catches cross-plugin overlap where
        # one plugin reports a line number and the other doesn't)
        broad_key = (str(file_path), str(cwe))
        existing = seen.get(key)

        # Check broad key if exact key doesn't match
        if existing is None and broad_key in seen_broad:
            existing = seen_broad[broad_key]
            # Treat as duplicate - same file + CWE from different plugins
            existing_conf = float(existing.get("confidence", 0))
            new_conf = float(f.get("confidence", 0))
            existing_has_line = existing.get("line_number") is not None
            new_has_line = line is not None
            # Prefer the finding with a line number; break ties by confidence
            if (new_has_line and not existing_has_line) or (
                new_has_line == existing_has_line and new_conf > existing_conf
            ):
                # Replace in both indexes
                old_key = (str(existing.get("file_path", "")), str(existing.get("cwe_id", "")),
                           existing.get("line_number"))
                seen.pop(old_key, None)
                seen[key] = f
                seen_broad[broad_key] = f
            removed += 1
            continue

        if existing is None:
            seen[key] = f
            seen_broad[broad_key] = f
        else:
            # Keep the one with higher confidence
            existing_conf = float(existing.get("confidence", 0))
            new_conf = float(f.get("confidence", 0))
            if new_conf > existing_conf:
                seen[key] = f
                seen_broad[broad_key] = f
            removed += 1

    result = list(seen.values()) + no_location

    if removed > 0:
        logger.info(
            "Location dedup: %d → %d (%d semantic duplicates removed)",
            len(findings), len(result), removed,
        )

    return result


# ---------------------------------------------------------------------------
# Stage 5: cross-detector semantic overlap dedup
# ---------------------------------------------------------------------------

# Known concept overlaps between semgrep MSTG rules and v2 plugins.
# Each entry: (plugin_title_regex, semgrep_title_regex, description).
# When two findings match the same overlap pair AND share a CWE prefix,
# the lower-confidence one is removed.
_SEMANTIC_OVERLAP_PATTERNS: List[tuple] = [
    # Exported components
    (
        re.compile(r"Exported\s+(Activity|Service|Receiver|Provider|Component)", re.IGNORECASE),
        re.compile(r"MSTG-PLATFORM-1", re.IGNORECASE),
    ),
    # Cleartext traffic
    (
        re.compile(r"Cleartext\s+Traffic|HTTP\s+Traffic|usesCleartextTraffic", re.IGNORECASE),
        re.compile(r"MSTG-NETWORK-1", re.IGNORECASE),
    ),
    # WebView JavaScript
    (
        re.compile(r"WebView.*JavaScript|JavaScript.*Enabled|setJavaScriptEnabled", re.IGNORECASE),
        re.compile(r"MSTG-PLATFORM-6", re.IGNORECASE),
    ),
    # Insecure storage
    (
        re.compile(r"Insecure.*Storage|SharedPreferences|MODE_WORLD|External\s+Storage", re.IGNORECASE),
        re.compile(r"MSTG-STORAGE-[12]", re.IGNORECASE),
    ),
    # Weak crypto
    (
        re.compile(r"Weak\s+Crypt|DES\b|RC4\b|MD5\b|ECB\s+Mode|Insecure\s+(?:Cipher|Hash)", re.IGNORECASE),
        re.compile(r"MSTG-CRYPTO-[123]", re.IGNORECASE),
    ),
    # Hardcoded secrets
    (
        re.compile(r"Hardcoded\s+(?:Secret|Credential|Key|Password|API)", re.IGNORECASE),
        re.compile(r"MSTG-STORAGE-14|MSTG-CRYPTO-1", re.IGNORECASE),
    ),
    # Insecure logging
    (
        re.compile(r"Insecure\s+Logging|Log\.\w+\s*\(|Sensitive.*Log", re.IGNORECASE),
        re.compile(r"MSTG-STORAGE-3", re.IGNORECASE),
    ),
    # Certificate pinning
    (
        re.compile(r"Certificate\s+Pin|SSL\s+Pin|TrustManager", re.IGNORECASE),
        re.compile(r"MSTG-NETWORK-[34]", re.IGNORECASE),
    ),
]

_SEMGREP_TITLE_PREFIX = re.compile(r"^MSTG-[A-Z]+-\d+:")


def dedup_semantic_overlaps(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge findings from different detectors that describe the same vulnerability concept.

    Identifies semgrep findings (title starts with ``MSTG-*:``) and plugin findings,
    then checks if any pair matches a known semantic overlap pattern.  When a match is
    found, the finding with lower confidence is removed.

    This handles the case where e.g. ``enhanced_manifest_analysis`` reports
    "Exported Activity: MainActivity" and semgrep reports "MSTG-PLATFORM-1:
    Exported component found" - same issue, different detectors.
    """
    if len(findings) < 2:
        return findings

    # Partition into semgrep vs plugin findings
    semgrep_findings: List[tuple] = []  # (index, finding)
    plugin_findings: List[tuple] = []   # (index, finding)

    for i, f in enumerate(findings):
        title = str(f.get("title", ""))
        if _SEMGREP_TITLE_PREFIX.match(title):
            semgrep_findings.append((i, f))
        else:
            plugin_findings.append((i, f))

    if not semgrep_findings or not plugin_findings:
        return findings

    # For each overlap pattern, check if both sides have a match
    to_remove: set = set()

    for plugin_re, semgrep_re in _SEMANTIC_OVERLAP_PATTERNS:
        # Collect matches on each side
        matched_semgrep = [
            (i, f) for i, f in semgrep_findings
            if i not in to_remove and semgrep_re.search(str(f.get("title", "")))
        ]
        matched_plugin = [
            (i, f) for i, f in plugin_findings
            if i not in to_remove and plugin_re.search(str(f.get("title", "")))
        ]

        if not matched_semgrep or not matched_plugin:
            continue

        # For each semgrep match, find the best-matching plugin finding
        # (same file if possible, otherwise any match) and remove the weaker one
        for si, sf in matched_semgrep:
            sf_file = str(sf.get("file_path", sf.get("file", sf.get("location", ""))))
            sf_conf = float(sf.get("confidence", 0))

            best_plugin = None
            best_plugin_conf = -1.0
            best_plugin_idx = -1

            for pi, pf in matched_plugin:
                if pi in to_remove:
                    continue
                pf_file = str(pf.get("file_path", pf.get("file", pf.get("location", ""))))
                pf_conf = float(pf.get("confidence", 0))

                # Prefer same-file matches
                same_file = pf_file and sf_file and (
                    pf_file == sf_file
                    or pf_file.endswith(sf_file.split("/")[-1])
                    or sf_file.endswith(pf_file.split("/")[-1])
                )
                if same_file or best_plugin is None:
                    if pf_conf > best_plugin_conf or same_file:
                        best_plugin = pf
                        best_plugin_conf = pf_conf
                        best_plugin_idx = pi

            if best_plugin is not None:
                # Remove the lower-confidence duplicate
                if sf_conf >= best_plugin_conf:
                    to_remove.add(best_plugin_idx)
                else:
                    to_remove.add(si)

    if to_remove:
        result = [f for i, f in enumerate(findings) if i not in to_remove]
        logger.info(
            "Semantic overlap dedup: %d → %d (%d cross-detector duplicates removed)",
            len(findings), len(result), len(to_remove),
        )
        return result

    return findings


def _apply_heuristic_rules(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove obvious non-vulnerability findings the ML may miss."""
    result: List[Dict[str, Any]] = []
    _ml_audit_fn = None
    try:
        import os as _os
        if _os.environ.get("AODS_ML_AUDIT", "0") in ("1", "true"):
            from core.api.auth_helpers import _audit_ml_decision
            _ml_audit_fn = _audit_ml_decision
    except Exception:
        pass

    for f in findings:
        title = str(f.get("title", ""))
        description = str(f.get("description", ""))
        file_path = str(f.get("file_path", f.get("location", "")))
        _rule_matched = None

        # Rule 1: error messages masquerading as findings
        if _matches_any(title, _ERROR_PATTERNS):
            _rule_matched = "error_message"
            logger.debug("Heuristic: dropped error-message finding: %s", title[:80])

        # Rule 2: status/count reports
        elif _matches_any(title, _STATUS_PATTERNS):
            _rule_matched = "status_report"
            logger.debug("Heuristic: dropped status-report finding: %s", title[:80])

        # Rule 3: test / build artifact paths (only if LOW or INFO severity)
        else:
            severity = str(f.get("severity", "")).upper()
            if severity in ("LOW", "INFO") and _is_test_path(file_path):
                _rule_matched = "test_path"
                logger.debug("Heuristic: dropped test-path finding: %s", file_path[:80])

            # Rule 4: positive security indicators (any severity)
            elif _matches_any(title, _POSITIVE_INDICATOR_PATTERNS):
                _rule_matched = "positive_indicator"
                logger.debug("Heuristic: dropped positive-indicator finding: %s", title[:80])

            # Rule 5: RESILIENCE detection mechanisms at LOW/INFO
            elif severity in ("LOW", "INFO") and _matches_any(title, _RESILIENCE_STRENGTH_PATTERNS):
                _rule_matched = "resilience_strength"
                logger.debug("Heuristic: dropped resilience-strength finding: %s", title[:80])

            # Rule 6: defensive features description
            elif severity in ("LOW", "INFO") and _matches_any(description, _DEFENSIVE_DESCRIPTION_PATTERNS):
                _rule_matched = "defensive_feature"
                logger.debug("Heuristic: dropped defensive-feature finding: %s", title[:80])

            # Rule 7: Android framework auto-generated permission
            elif _ANDROID_FRAMEWORK_FP_PATTERN.search(title) or _ANDROID_FRAMEWORK_FP_PATTERN.search(description):
                _rule_matched = "framework_permission"
                logger.debug("Heuristic: dropped framework-generated permission: %s", title[:80])

        if _rule_matched:
            if _ml_audit_fn:
                _ml_audit_fn(
                    finding_id=title[:200],
                    stage="heuristic_rules",
                    decision="filter",
                    details={"rule": _rule_matched},
                )
            continue

        result.append(f)

    return result


def _matches_any(text: str, patterns: List[re.Pattern]) -> bool:
    return any(p.search(text) for p in patterns)


def _is_test_path(path: str) -> bool:
    if not path:
        return False
    parts = set(path.replace("\\", "/").lower().split("/"))
    return bool(parts & _TEST_PATH_SEGMENTS)


# ---------------------------------------------------------------------------
# Convenience function (drop-in replacement for legacy coordinator)
# ---------------------------------------------------------------------------

_instance: Optional[CanonicalFPReducer] = None


def get_fp_reducer(config: Optional[Dict[str, Any]] = None) -> CanonicalFPReducer:
    """Singleton accessor - reuse across a scan to avoid re-loading ML models."""
    global _instance
    if _instance is None:
        _instance = CanonicalFPReducer(config)
    return _instance


def reduce_false_positives(
    findings: List[Dict[str, Any]],
    scan_context: Optional[Dict[str, Any]] = None,
) -> tuple[List[Dict[str, Any]], FPReductionResult]:
    """Convenience function: create/reuse reducer and run pipeline."""
    reducer = get_fp_reducer()
    return reducer.reduce(findings, scan_context)


def reset_fp_reducer() -> None:
    """Reset the singleton (for testing)."""
    global _instance
    _instance = None
