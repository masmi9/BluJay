"""
core.agent.narration_heuristic - Rule-based narration fallback (no LLM required).

Produces a structured Narrative from scan report data using deterministic
heuristics when no LLM API key is available.  Extracts severity distribution,
top CWEs, and priority findings to build an executive summary and risk
assessment.

Public API:
    run_heuristic_narration(report_file, report_dir) -> Narrative
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from .narration import (
    Narrative,
    PriorityFinding,
    save_narrative_to_report,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_SEVERITY_WEIGHT = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_findings(report_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract the findings list from a report, trying both common keys."""
    findings = report_data.get("findings", report_data.get("vulnerabilities", []))
    if not isinstance(findings, list):
        return []
    return findings


def _count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings by severity level."""
    counts: Dict[str, int] = Counter()
    for f in findings:
        sev = str(f.get("severity", "MEDIUM")).upper()
        counts[sev] += 1
    return dict(counts)


def _top_cwes(findings: List[Dict[str, Any]], limit: int = 5) -> List[str]:
    """Identify the top N most frequent CWEs."""
    cwe_counter: Counter = Counter()
    for f in findings:
        cwe = f.get("cwe_id", "") or f.get("cwe", "")
        if cwe:
            normalized = cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
            cwe_counter[normalized] += 1
    return [cwe for cwe, _ in cwe_counter.most_common(limit)]


def _finding_sort_key(f: Dict[str, Any]) -> float:
    """Sort key for findings: higher = more important."""
    sev = str(f.get("severity", "MEDIUM")).upper()
    conf = float(f.get("confidence", 0.5))
    return _SEVERITY_WEIGHT.get(sev, 1) * conf


def _determine_risk_rating(severity_counts: Dict[str, int]) -> str:
    """Determine overall risk rating from severity distribution."""
    if severity_counts.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    if severity_counts.get("HIGH", 0) > 0:
        return "HIGH"
    if severity_counts.get("MEDIUM", 0) > 0:
        return "MEDIUM"
    return "LOW"


def _build_risk_rationale(
    severity_counts: Dict[str, int], top_cwes: List[str]
) -> str:
    """Build a human-readable risk rationale."""
    parts: List[str] = []

    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)

    if critical:
        parts.append(
            f"{critical} critical-severity finding(s) require immediate attention."
        )
    if high:
        parts.append(
            f"{high} high-severity finding(s) present significant risk."
        )
    if not critical and not high:
        parts.append(
            "No critical or high severity findings detected. "
            "Medium and lower findings should still be reviewed."
        )

    if top_cwes:
        parts.append(f"Top CWEs: {', '.join(top_cwes)}.")

    return " ".join(parts)


def _build_executive_summary(
    total: int, severity_counts: Dict[str, int]
) -> str:
    """Build the executive summary string."""
    parts: List[str] = []
    for sev in _SEVERITY_ORDER:
        count = severity_counts.get(sev, 0)
        if count:
            parts.append(f"{count} {sev.lower()}")

    severity_breakdown = ", ".join(parts) if parts else "no categorized findings"
    return f"{total} findings ({severity_breakdown})."


def _build_full_narrative(
    total: int,
    severity_counts: Dict[str, int],
    top_cwes: List[str],
    priority_titles: List[str],
) -> str:
    """Build a formatted full-text narrative."""
    lines: List[str] = [
        "# Heuristic Security Narrative",
        "",
        "## Overview",
        "",
        f"This scan produced {total} findings.",
        "",
        "## Severity Distribution",
        "",
    ]
    for sev in _SEVERITY_ORDER:
        count = severity_counts.get(sev, 0)
        if count:
            lines.append(f"- **{sev}**: {count}")
    lines.append("")

    if top_cwes:
        lines.append("## Top Vulnerability Classes")
        lines.append("")
        for cwe in top_cwes:
            lines.append(f"- {cwe}")
        lines.append("")

    if priority_titles:
        lines.append("## Priority Findings")
        lines.append("")
        for i, title in enumerate(priority_titles, 1):
            lines.append(f"{i}. {title}")
        lines.append("")

    lines.append(
        "Note: This narrative was generated using rule-based heuristics "
        "(no LLM). A full agent-powered analysis may provide deeper "
        "attack chain and remediation insights."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_heuristic_narration(
    report_file: str,
    report_dir: str = "reports",
) -> Narrative:
    """Run rule-based narration without an LLM.

    Reads the scan report JSON, extracts severity distribution, identifies
    top CWEs, and builds a structured Narrative with executive summary,
    risk rating, and priority findings.

    Args:
        report_file: Path to the JSON scan report.
        report_dir: Directory containing report files (unused but kept for
            API compatibility with run_narration).

    Returns:
        Narrative with heuristic-generated analysis.
    """
    logger.info("heuristic_narration_start", report_file=report_file)

    rp = Path(report_file)
    if not rp.exists():
        logger.warning("heuristic_narration_report_not_found", path=report_file)
        return Narrative(
            executive_summary=f"Report file not found: {report_file}",
            risk_rating="MEDIUM",
            method="heuristic",
        )

    try:
        with open(rp, "r") as f:
            report_data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("heuristic_narration_read_error", path=report_file, error=str(e))
        return Narrative(
            executive_summary=f"Failed to read report: {e}",
            risk_rating="MEDIUM",
            method="heuristic",
        )

    # Extract and analyze findings
    findings = _extract_findings(report_data)
    if not findings:
        return Narrative(
            executive_summary="No findings to narrate.",
            risk_rating="LOW",
            full_narrative="The scan produced no findings.",
            method="heuristic",
        )

    total = len(findings)
    severity_counts = _count_by_severity(findings)
    top_cwes = _top_cwes(findings, limit=5)

    # Sort findings by importance and take top 5
    sorted_findings = sorted(findings, key=_finding_sort_key, reverse=True)
    top_findings = sorted_findings[:5]

    priority_findings = [
        PriorityFinding(
            title=f.get("title", "Unknown"),
            severity=str(f.get("severity", "MEDIUM")).upper(),
            cwe_id=f.get("cwe_id", "") or f.get("cwe", "") or None,
            exploitability="Assessed by heuristic",
            context=f.get("description", "")[:200] if f.get("description") else "",
        )
        for f in top_findings
    ]

    risk_rating = _determine_risk_rating(severity_counts)
    risk_rationale = _build_risk_rationale(severity_counts, top_cwes)
    executive_summary = _build_executive_summary(total, severity_counts)
    full_narrative = _build_full_narrative(
        total,
        severity_counts,
        top_cwes,
        [f.title for f in priority_findings],
    )

    narrative = Narrative(
        executive_summary=executive_summary,
        risk_rating=risk_rating,
        risk_rationale=risk_rationale,
        priority_findings=priority_findings,
        full_narrative=full_narrative,
        method="heuristic",
    )

    # Save to report
    save_narrative_to_report(narrative, report_file)

    logger.info(
        "heuristic_narration_complete",
        findings=total,
        risk_rating=risk_rating,
    )
    return narrative
