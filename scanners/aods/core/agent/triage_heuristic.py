"""
core.agent.triage_heuristic - Rule-based triage fallback (no LLM required).

Classifies scan findings using deterministic heuristics when no LLM API key
is available.  Uses severity, confidence, CWE mapping, and library-code
detection to produce a TriageResult compatible with the LLM-based triage.

Public API:
    run_heuristic_triage(report_file, report_dir) -> TriageResult
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from .triage import (
    ClassifiedFinding,
    FindingGroup,
    TriageResult,
    save_triage_to_report,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHT = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

# Patterns that indicate informational (non-vulnerability) findings
_INFORMATIONAL_PATTERNS = (
    re.compile(r"(?i)debug.*flag"),
    re.compile(r"(?i)version\s+info"),
    re.compile(r"(?i)app\s+metadata"),
    re.compile(r"(?i)configuration\s+observation"),
    re.compile(r"(?i)build\s+information"),
    re.compile(r"(?i)manifest\s+analysis\s+summary"),
)

# Patterns that indicate likely false positives
_FP_PATTERNS = (
    re.compile(r"(?i)debug.*release\s+build"),
    re.compile(r"(?i)test\s+key"),
    re.compile(r"(?i)example\s+code"),
    re.compile(r"(?i)sample\s+implementation"),
)

# Library path prefixes (mirrors BasePluginV2._LIBRARY_PATH_PREFIXES)
_LIBRARY_PATH_PREFIXES = (
    "android/", "androidx/",
    "com/google/",
    # NOTE: "com/android/" removed - too broad, matches real app packages like
    # com.android.insecurebankv2. Specific SDK paths added below instead.
    "com/android/internal/", "com/android/support/", "com/android/tools/",
    "kotlin/", "kotlinx/",
    "com/squareup/", "io/reactivex/",
    "org/apache/", "com/facebook/",
    "com/bumptech/", "com/fasterxml/",
    "org/jetbrains/", "javax/", "java/",
    "okhttp3/", "retrofit2/",
    "com/airbnb/", "dagger/", "butterknife/",
    "org/greenrobot/", "com/tencent/", "com/bytedance/",
    "com/applovin/", "com/appsflyer/",
    "com/ironsource/", "com/mbridge/", "com/mintegral/",
    "com/unity3d/", "com/chartboost/", "com/vungle/",
    "com/inmobi/", "com/smaato/", "com/adjust/",
    "com/amazon/device/ads/",
    "com/ttnet/", "com/lynx/", "com/pgl/", "com/bef/",
    "okio/",
    # Google Play Services / Firebase
    "com/google/android/gms/", "com/google/firebase/",
    "com/google/android/play/",
    # Huawei / Samsung SDKs
    "com/huawei/", "com/samsung/",
    # Additional ad/analytics SDKs
    "com/crashlytics/", "io/fabric/",
    "com/newrelic/", "com/braze/",
)

# Category groupings by title prefix patterns
_TITLE_GROUP_PATTERNS = (
    (re.compile(r"(?i)^exported\s+(activity|service|receiver|provider)"), "Exported Components"),
    (re.compile(r"(?i)^insecure\s+storage"), "Insecure Storage"),
    (re.compile(r"(?i)^hardcoded\s+(key|secret|credential|password)"), "Hardcoded Secrets"),
    (re.compile(r"(?i)^weak\s+crypto"), "Weak Cryptography"),
    (re.compile(r"(?i)^missing\s+certificate\s+pin"), "Certificate Pinning"),
    (re.compile(r"(?i)^webview"), "WebView Issues"),
    (re.compile(r"(?i)^sql\s+injection"), "SQL Injection"),
    (re.compile(r"(?i)^intent\s+(injection|redirect)"), "Intent Handling"),
    (re.compile(r"(?i)^cleartext\s+(traffic|communication|http)"), "Cleartext Traffic"),
    (re.compile(r"(?i)^(logging|log\s+)"), "Logging Issues"),
)


# ---------------------------------------------------------------------------
# Classification logic
# ---------------------------------------------------------------------------


def _is_library_path(file_path: str) -> bool:
    """Check if a file path belongs to third-party library/SDK code."""
    normalized = file_path.replace("\\", "/").lower()
    for prefix in ("sources/", "src/main/java/", "src/"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
            break
    for marker in ("/sources/", "/src/main/java/", "/src/"):
        idx = normalized.rfind(marker)
        if idx >= 0:
            normalized = normalized[idx + len(marker):]
            break
    return any(normalized.startswith(p) for p in _LIBRARY_PATH_PREFIXES)


def _classify_finding(finding: Dict[str, Any]) -> ClassifiedFinding:
    """Classify a single finding using deterministic heuristics.

    Rules applied in order:
    1. informational - severity INFO or matches informational patterns
    2. likely_fp - low confidence, library code, or FP patterns
    3. confirmed_tp - HIGH/CRITICAL + high confidence + CWE mapping
    4. likely_tp - HIGH/MEDIUM + moderate confidence
    5. needs_review - everything else
    """
    title = finding.get("title", "")
    severity = str(finding.get("severity", "MEDIUM")).upper()
    try:
        confidence = float(finding.get("confidence", 0.5))
    except (ValueError, TypeError):
        confidence = 0.5
    cwe_id = finding.get("cwe_id", "") or finding.get("cwe", "")

    # Apply calibration from LLM comparison data (if available)
    try:
        from .heuristic_calibration import get_calibrated_confidence
        if cwe_id:
            confidence = get_calibrated_confidence(cwe_id, confidence)
    except Exception:
        pass  # calibration is best-effort
    file_path = finding.get("file", "") or finding.get("file_path", "") or ""

    # Rule 1: Informational
    if severity == "INFO":
        return ClassifiedFinding(
            finding_title=title,
            classification="informational",
            severity=severity,
            confidence=confidence,
            reasoning="Severity is INFO - informational finding",
        )
    # Only demote to informational if severity is LOW or below - HIGH/CRITICAL/MEDIUM
    # findings matching these patterns are real vulnerabilities, not just metadata
    if severity in ("LOW", "INFO"):
        for pat in _INFORMATIONAL_PATTERNS:
            if pat.search(title):
                return ClassifiedFinding(
                    finding_title=title,
                    classification="informational",
                    severity=severity,
                confidence=confidence,
                reasoning=f"Title matches informational pattern: {pat.pattern}",
            )

    # Rule 2: Likely false positive
    # Threshold 0.2 aligns with the ML FP reducer threshold (0.15 default)
    # to avoid a gap where low-confidence findings slip through as needs_review
    if confidence < 0.2:
        return ClassifiedFinding(
            finding_title=title,
            classification="likely_fp",
            severity=severity,
            confidence=confidence,
            reasoning=f"Low confidence ({confidence:.2f} < 0.2)",
        )
    if file_path and _is_library_path(file_path):
        return ClassifiedFinding(
            finding_title=title,
            classification="likely_fp",
            severity=severity,
            confidence=confidence,
            reasoning=f"Finding in library code: {file_path}",
        )
    for pat in _FP_PATTERNS:
        if pat.search(title):
            return ClassifiedFinding(
                finding_title=title,
                classification="likely_fp",
                severity=severity,
                confidence=confidence,
                reasoning=f"Title matches FP pattern: {pat.pattern}",
            )

    # Rule 3: Confirmed true positive
    if severity in ("CRITICAL", "HIGH") and confidence >= 0.8 and cwe_id:
        return ClassifiedFinding(
            finding_title=title,
            classification="confirmed_tp",
            severity=severity,
            confidence=confidence,
            reasoning=f"High severity ({severity}), high confidence ({confidence:.2f}), CWE mapped ({cwe_id})",
        )

    # Rule 4: Likely true positive
    if severity in ("CRITICAL", "HIGH", "MEDIUM") and confidence >= 0.5:
        return ClassifiedFinding(
            finding_title=title,
            classification="likely_tp",
            severity=severity,
            confidence=confidence,
            reasoning=f"Severity {severity} with confidence {confidence:.2f}",
        )

    # Rule 5: Needs review
    return ClassifiedFinding(
        finding_title=title,
        classification="needs_review",
        severity=severity,
        confidence=confidence,
        reasoning="Does not match any deterministic classification rule",
    )


def _group_findings(
    classified: List[ClassifiedFinding],
    original_findings: Optional[List[Dict[str, Any]]] = None,
) -> List[FindingGroup]:
    """Group findings by CWE and title patterns.

    Args:
        classified: List of classified findings from heuristic triage.
        original_findings: Optional list of original finding dicts from the
            report. Used to extract actual CWE fields for grouping (more
            reliable than regex on reasoning text).
    """
    cwe_groups: Dict[str, List[str]] = defaultdict(list)
    title_groups: Dict[str, List[str]] = defaultdict(list)
    grouped_titles = set()

    # Build a title→CWE lookup from original findings (preferred source)
    title_to_cwe: Dict[str, str] = {}
    if original_findings:
        for f in original_findings:
            title = f.get("title", "")
            cwe = f.get("cwe_id", "") or f.get("cwe", "")
            if title and cwe:
                # Normalise to CWE-NNN format
                normalized = cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
                title_to_cwe[title] = normalized

    # Pass 1: Group by CWE - prefer original finding's CWE, fall back to reasoning
    for f in classified:
        cwe_id = title_to_cwe.get(f.finding_title, "")
        if not cwe_id:
            cwe_match = re.search(r"CWE[- ]?(\d+)", f.reasoning)
            if cwe_match:
                cwe_id = f"CWE-{cwe_match.group(1)}"
        if cwe_id:
            cwe_groups[cwe_id].append(f.finding_title)
            grouped_titles.add(f.finding_title)

    # Pass 2: Group remaining by title patterns
    for f in classified:
        if f.finding_title in grouped_titles:
            continue
        for pat, label in _TITLE_GROUP_PATTERNS:
            if pat.search(f.finding_title):
                title_groups[label].append(f.finding_title)
                grouped_titles.add(f.finding_title)
                break

    groups: List[FindingGroup] = []
    group_idx = 1

    for cwe_id, titles in sorted(cwe_groups.items()):
        if len(titles) >= 2:
            groups.append(FindingGroup(
                id=f"cwe-{group_idx}",
                label=cwe_id,
                root_cause=f"Shared vulnerability class: {cwe_id}",
                finding_titles=titles,
            ))
            group_idx += 1

    for label, titles in sorted(title_groups.items()):
        if len(titles) >= 2:
            groups.append(FindingGroup(
                id=f"title-{group_idx}",
                label=label,
                root_cause=f"Common category: {label}",
                finding_titles=titles,
            ))
            group_idx += 1

    # Assign group IDs back to classified findings
    title_to_group: Dict[str, str] = {}
    for g in groups:
        for t in g.finding_titles:
            title_to_group[t] = g.id
    for f in classified:
        if f.finding_title in title_to_group:
            f.group_id = title_to_group[f.finding_title]

    return groups


def _priority_score(finding: ClassifiedFinding) -> float:
    """Compute a priority score for sorting (higher = more urgent)."""
    weight = _SEVERITY_WEIGHT.get(finding.severity, 1)
    return weight * finding.confidence


def _build_summary(classified: List[ClassifiedFinding]) -> str:
    """Build a human-readable triage summary."""
    counts: Dict[str, int] = defaultdict(int)
    for f in classified:
        counts[f.classification] += 1

    parts = [
        f"Heuristic triage of {len(classified)} findings:",
    ]
    for label in ("confirmed_tp", "likely_tp", "needs_review", "likely_fp", "informational"):
        if counts[label]:
            parts.append(f"  {label}: {counts[label]}")

    parts.append(
        "Note: This triage was performed using rule-based heuristics "
        "(no LLM). Results may benefit from human review."
    )
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_heuristic_triage(
    report_file: str,
    report_dir: str = "reports",
) -> TriageResult:
    """Run rule-based triage without an LLM.

    Reads the scan report JSON, classifies each finding using deterministic
    rules, groups related findings, and sorts by priority.

    Args:
        report_file: Path to the JSON scan report.
        report_dir: Directory containing report files (unused but kept for
            API compatibility with run_triage).

    Returns:
        TriageResult with classified findings, groups, and priority order.
    """
    logger.info("heuristic_triage_start", report_file=report_file)

    rp = Path(report_file)
    if not rp.exists():
        logger.warning("heuristic_triage_report_not_found", path=report_file)
        return TriageResult(
            summary=f"Report file not found: {report_file}",
            triage_notes={"mode": "heuristic", "error": "report_not_found"},
            method="heuristic",
        )

    try:
        with open(rp, "r") as f:
            report_data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("heuristic_triage_read_error", path=report_file, error=str(e))
        return TriageResult(
            summary=f"Failed to read report: {e}",
            triage_notes={"mode": "heuristic", "error": str(e)},
            method="heuristic",
        )

    # Extract findings from report (try both keys)
    findings = report_data.get("vulnerabilities", report_data.get("findings", []))
    if not findings:
        return TriageResult(
            summary="No findings to triage",
            triage_notes={"mode": "heuristic"},
            method="heuristic",
        )

    # Classify each finding
    classified = [_classify_finding(f) for f in findings]

    # Group related findings (pass originals for CWE field access)
    groups = _group_findings(classified, original_findings=findings)

    # Sort by priority score (descending)
    sorted_findings = sorted(classified, key=_priority_score, reverse=True)
    priority_order = [f.finding_title for f in sorted_findings]

    summary = _build_summary(classified)

    result = TriageResult(
        classified_findings=classified,
        groups=groups,
        priority_order=priority_order,
        summary=summary,
        triage_notes={"mode": "heuristic", "finding_count": str(len(findings))},
        method="heuristic",
    )

    # Save to report
    save_triage_to_report(result, report_file)

    logger.info(
        "heuristic_triage_complete",
        findings=len(classified),
        groups=len(groups),
    )
    return result
