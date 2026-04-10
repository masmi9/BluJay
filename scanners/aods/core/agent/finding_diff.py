"""
core.agent.finding_diff - Compute diff between current and previously triaged findings.

Enables incremental triage: only new/changed findings are sent to the LLM,
while unchanged findings carry forward their previous classifications.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Tuple

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)


def _finding_hash(finding: Dict[str, Any]) -> str:
    """Compute a stable identity + content hash for a finding.

    Hash covers fields that, if changed, should trigger re-triage.
    """
    key_fields = (
        finding.get("title", ""),
        str(finding.get("severity", "")),
        str(finding.get("cwe_id", finding.get("cwe", ""))),
        str(finding.get("file_path", finding.get("file", ""))),
        str(finding.get("confidence", "")),
    )
    return hashlib.sha256("|".join(key_fields).encode()).hexdigest()[:16]


def compute_finding_diff(
    current_findings: List[Dict[str, Any]],
    previous_triage: Dict[str, Any],
) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """Compare current findings against previous triage classifications.

    Args:
        current_findings: Findings from the current scan report.
        previous_triage: Previous triage section from the report
            (with classified_findings list).

    Returns:
        Tuple of (new_findings, changed_findings, unchanged_findings):
        - new: title not in previous triage (needs fresh classification)
        - changed: title matches but content hash differs (needs re-classification)
        - unchanged: identical to previous (carry forward classification)
    """
    previous_classified = previous_triage.get("classified_findings", [])
    if not previous_classified:
        return current_findings, [], []

    # Build lookup: title → (classification dict, content hash)
    previous_map: Dict[str, Dict[str, Any]] = {}
    previous_hashes: Dict[str, str] = {}
    for cf in previous_classified:
        title = cf.get("finding_title", "")
        if title:
            previous_map[title] = cf
            # Reconstruct a finding-like dict for hashing from the classification
            pseudo_finding = {
                "title": title,
                "severity": cf.get("severity", ""),
                "cwe_id": cf.get("cwe_id", cf.get("cwe", "")),
                "file_path": cf.get("file_path", cf.get("file", "")),
                "confidence": cf.get("confidence", ""),
            }
            previous_hashes[title] = _finding_hash(pseudo_finding)

    new_findings = []
    changed_findings = []
    unchanged_findings = []

    for finding in current_findings:
        title = finding.get("title", "")
        if not title:
            new_findings.append(finding)
            continue

        if title not in previous_map:
            new_findings.append(finding)
        else:
            current_hash = _finding_hash(finding)
            if current_hash != previous_hashes.get(title, ""):
                changed_findings.append(finding)
            else:
                unchanged_findings.append(finding)

    logger.debug(
        "finding_diff_computed",
        total=len(current_findings),
        new=len(new_findings),
        changed=len(changed_findings),
        unchanged=len(unchanged_findings),
    )

    return new_findings, changed_findings, unchanged_findings


def get_carried_forward_classifications(
    unchanged_findings: List[Dict[str, Any]],
    previous_triage: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Get previous classifications for unchanged findings.

    Returns a list of ClassifiedFinding-compatible dicts with
    "[Carried forward]" prepended to the reasoning.

    Args:
        unchanged_findings: Findings that haven't changed.
        previous_triage: Previous triage section from the report.

    Returns:
        List of classification dicts ready to merge into TriageResult.
    """
    previous_classified = previous_triage.get("classified_findings", [])
    prev_map = {cf.get("finding_title", ""): cf for cf in previous_classified}

    carried = []
    for finding in unchanged_findings:
        title = finding.get("title", "")
        prev_cf = prev_map.get(title)
        if prev_cf:
            cf = dict(prev_cf)  # shallow copy
            original_reasoning = cf.get("reasoning", "")
            cf["reasoning"] = f"[Carried forward] {original_reasoning}"
            carried.append(cf)

    return carried
