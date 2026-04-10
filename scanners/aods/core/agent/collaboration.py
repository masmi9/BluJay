"""
core.agent.collaboration - Build enriched cross-agent context.

Provides structured context from upstream agent results to downstream agents:
- Remediation gets triage reasoning per finding (why TP/FP)
- Narration gets verification evidence and remediation patch summaries

This is injected into the user message (not system prompt) so it's
specific to the current report and doesn't consume cache space.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)


def build_collaboration_context(agent_type: str, report_file: str) -> str:
    """Build cross-agent context from upstream results in the report.

    Args:
        agent_type: Downstream agent type (remediate, narrate).
        report_file: Path to the JSON scan report.

    Returns:
        Formatted context string to append to user message,
        or empty string if no upstream data is available.
    """
    try:
        rp = Path(report_file)
        if not rp.exists():
            return ""
        with open(rp, "r") as f:
            report = json.load(f)
    except Exception:
        return ""

    if agent_type == "remediate":
        return _build_remediation_collaboration(report)
    elif agent_type == "narrate":
        return _build_narration_collaboration(report)
    return ""


def _build_remediation_collaboration(report: Dict[str, Any]) -> str:
    """Provide remediation agent with triage reasoning per finding.

    Tells remediation WHY each finding was classified, so it can:
    - Skip FPs with confidence (don't waste tokens generating patches)
    - Focus effort on confirmed TPs
    - Understand the attack context for better-targeted patches
    """
    triage = report.get("triage", {})
    classified = triage.get("classified_findings", [])
    if not classified:
        return ""

    # Separate by classification for structured presentation
    confirmed = []
    needs_review = []
    fps = []

    for cf in classified:
        title = cf.get("finding_title", "")
        classification = cf.get("classification", "")
        reasoning = cf.get("reasoning", "")
        severity = cf.get("severity", "")
        if not title:
            continue

        entry = f"**{title}** [{severity}]: {reasoning[:300]}" if reasoning else f"**{title}** [{severity}]"

        if classification in ("confirmed_tp", "likely_tp"):
            confirmed.append(entry)
        elif classification == "needs_review":
            needs_review.append(entry)
        elif classification == "likely_fp":
            fps.append(entry)

    if not confirmed and not fps:
        return ""

    lines = ["## Cross-Agent Context: Triage Reasoning"]

    if confirmed:
        lines.append(f"\n### Confirmed True Positives ({len(confirmed)}) - PRIORITIZE these")
        for entry in confirmed[:15]:
            lines.append(f"- {entry}")

    if needs_review:
        lines.append(f"\n### Needs Review ({len(needs_review)}) - generate patches but flag uncertainty")
        for entry in needs_review[:10]:
            lines.append(f"- {entry}")

    if fps:
        lines.append(f"\n### Likely False Positives ({len(fps)}) - SKIP unless you disagree")
        for entry in fps[:10]:
            lines.append(f"- {entry}")

    return "\n".join(lines)


def _build_narration_collaboration(report: Dict[str, Any]) -> str:
    """Provide narration agent with verification evidence and remediation context.

    Tells narration:
    - Which findings were dynamically verified (with evidence)
    - Which findings have code patches (with difficulty)
    - Triage attack chains (for narrative coherence)
    """
    sections = ["## Cross-Agent Context: Upstream Agent Results"]
    has_content = False

    # Verification evidence
    verif = report.get("verification", {})
    verifications = verif.get("verifications", [])
    if verifications:
        confirmed = [v for v in verifications if v.get("status") == "confirmed"]
        fp_detected = [v for v in verifications if v.get("status") == "likely_fp"]

        if confirmed:
            has_content = True
            sections.append(f"\n### Dynamically Verified Findings ({len(confirmed)})")
            for v in confirmed[:10]:
                title = v.get("finding_title", "")
                evidence = (v.get("evidence", "") or "")[:200]
                method = v.get("verification_method", "dynamic")
                sections.append(f"- **{title}** ({method}): {evidence}")

        if fp_detected:
            has_content = True
            sections.append(f"\n### Verification Found False Positives ({len(fp_detected)})")
            for v in fp_detected[:5]:
                title = v.get("finding_title", "")
                sections.append(f"- **{title}**: {(v.get('reasoning', '') or '')[:150]}")

    # Remediation patches
    remed = report.get("remediation", {})
    remediations = remed.get("remediations", [])
    if remediations:
        patched = [r for r in remediations if r.get("fixed_code")]
        if patched:
            has_content = True
            sections.append(f"\n### Remediation Patches Available ({len(patched)})")
            for r in patched[:10]:
                title = r.get("finding_title", "")
                difficulty = r.get("difficulty", "moderate")
                cwe = r.get("cwe_id", "")
                label = f"**{title}** (difficulty: {difficulty})"
                if cwe:
                    label += f" [{cwe}]"
                sections.append(f"- {label}")
            overall = remed.get("overall_effort", "")
            if overall:
                sections.append(f"\nOverall remediation effort: {overall}")

    # Triage attack chains
    triage = report.get("triage", {})
    chains = triage.get("attack_chains", [])
    if chains:
        has_content = True
        sections.append(f"\n### Attack Chains from Triage ({len(chains)})")
        for chain in chains[:5]:
            name = chain.get("name", "Unnamed")
            steps = chain.get("steps", [])
            impact = chain.get("impact", "")
            likelihood = chain.get("likelihood", "")
            sections.append(f"- **{name}** [{likelihood}]: {' -> '.join(steps[:5])}")
            if impact:
                sections.append(f"  Impact: {impact[:200]}")

    if not has_content:
        return ""

    return "\n".join(sections)
