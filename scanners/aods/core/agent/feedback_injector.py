"""
core.agent.feedback_injector - Query vector DB for historical feedback and
format as few-shot examples for agent system prompts.

Queries ChromaDB for past analyst corrections (accept/reject) on similar
findings and formats them as prompt context. This allows agents to learn
from analyst feedback without retraining.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)

# Severity weights for prioritizing which findings to query feedback for
_SEVERITY_WEIGHT = {
    "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1,
}


def query_relevant_feedback(
    findings: List[Dict[str, Any]],
    agent_type: str,
    max_examples: int = 5,
    min_similarity: float = 0.6,
) -> List[Dict[str, Any]]:
    """Query vector DB for feedback relevant to the given findings.

    Args:
        findings: List of finding dicts from the current report.
        agent_type: Agent type requesting feedback (triage, remediate, etc.).
        max_examples: Maximum number of feedback examples to return.
        min_similarity: Minimum cosine similarity threshold.

    Returns:
        List of feedback dicts with keys: finding_title, action,
        new_classification, reason, user, timestamp, similarity_score.
        Returns empty list if vector DB is unavailable or has no matches.
    """
    if os.environ.get("AODS_VECTOR_DB_ENABLED", "0").lower() not in ("1", "true"):
        return []

    try:
        from core.vector_db import get_semantic_finding_index

        idx = get_semantic_finding_index()
        if idx is None or not idx.is_available():
            return []
    except Exception:
        return []

    # Select top findings by severity for feedback queries
    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_WEIGHT.get(
            str(f.get("severity", "")).upper(), 0
        ),
        reverse=True,
    )
    query_findings = sorted_findings[:10]

    all_feedback: List[Dict[str, Any]] = []
    seen_titles: set = set()

    for finding in query_findings:
        title = finding.get("title", "")
        if not title:
            continue

        try:
            matches = idx.find_similar(finding, n_results=3, include_same_scan=False)
        except Exception:
            continue

        for match in matches:
            score = match.get("score", match.get("similarity", 0))
            if score < min_similarity:
                continue

            metadata = match.get("metadata", {})

            # Only include entries that have feedback data
            feedback_type = metadata.get("type", "")
            classification = metadata.get("triage_classification", "")
            if not feedback_type and not classification:
                continue

            match_title = match.get("title", metadata.get("title", ""))
            if not match_title or match_title in seen_titles:
                continue
            seen_titles.add(match_title)

            entry: Dict[str, Any] = {
                "finding_title": match_title,
                "similarity_score": round(score, 3),
                "query_finding": title,
            }

            # Extract feedback data
            if feedback_type == "triage_feedback":
                entry["action"] = metadata.get("action", "")
                entry["new_classification"] = metadata.get("new_classification", "")
                entry["reason"] = metadata.get("reason", "")
                entry["user"] = metadata.get("user", "")
                entry["timestamp"] = metadata.get("timestamp", "")
            elif classification:
                entry["prior_classification"] = classification
                entry["triage_confidence"] = metadata.get("triage_confidence", "")
                entry["triage_reasoning"] = metadata.get("triage_reasoning", "")

            all_feedback.append(entry)

    # Sort by similarity (highest first), take top max_examples
    all_feedback.sort(key=lambda x: x.get("similarity_score", 0), reverse=True)
    return all_feedback[:max_examples]


def format_feedback_as_few_shot(
    feedback: List[Dict[str, Any]],
    agent_type: str,
) -> str:
    """Format feedback entries as a prompt section for system prompt injection.

    Args:
        feedback: List of feedback dicts from query_relevant_feedback().
        agent_type: Agent type (affects formatting).

    Returns:
        Formatted string to append to system prompt, or empty string.
    """
    if not feedback:
        return ""

    lines = [
        "## Historical Analyst Corrections",
        "",
        "The following are past analyst corrections on similar findings. Use these",
        "to calibrate your analysis - analysts have reviewed these and their",
        "judgment should inform yours.",
        "",
    ]

    for i, entry in enumerate(feedback, 1):
        title = entry.get("finding_title", "Unknown")
        query = entry.get("query_finding", "")
        similarity = entry.get("similarity_score", 0)

        lines.append(f"{i}. Finding: \"{title}\" (similar to \"{query}\", score={similarity:.2f})")

        # Triage-specific feedback
        action = entry.get("action", "")
        new_class = entry.get("new_classification", "")
        reason = entry.get("reason", "")

        if action and agent_type in ("triage", "narrate"):
            if action == "reject" and new_class:
                lines.append(f"   Analyst reclassified to: {new_class}")
            elif action == "accept":
                lines.append("   Analyst confirmed the classification")
            if reason:
                lines.append(f"   Reason: \"{reason}\"")

        # Prior classification data
        prior = entry.get("prior_classification", "")
        if prior:
            lines.append(f"   Prior classification: {prior}")
            reasoning = entry.get("triage_reasoning", "")
            if reasoning:
                lines.append(f"   Prior reasoning: \"{reasoning[:200]}\"")

        # Remediation-specific
        if agent_type == "remediate" and reason:
            lines.append(f"   Analyst note: \"{reason}\"")

        lines.append("")

    return "\n".join(lines)


def inject_feedback_context(
    config: Any,
    agent_type: str,
    report_file: str,
    max_examples: int = 5,
) -> None:
    """Query feedback and inject as few-shot examples into system prompt.

    Reads findings from the report, queries vector DB for similar past
    feedback, formats as prompt context, and appends to the agent's
    system prompt. No-op if vector DB is unavailable or no feedback found.

    Args:
        config: AgentConfig instance (modified in-place).
        agent_type: Agent type name.
        report_file: Path to the JSON scan report.
        max_examples: Maximum feedback examples to inject.
    """
    current_prompt = config.get_agent_system_prompt(agent_type)
    if not current_prompt:
        return

    try:
        import json
        from pathlib import Path

        rp = Path(report_file)
        if not rp.exists():
            return

        with open(rp, "r") as f:
            report = json.load(f)

        findings = report.get("findings", report.get("vulnerabilities", []))
        if not findings or not isinstance(findings, list):
            return

        feedback = query_relevant_feedback(
            findings, agent_type, max_examples=max_examples,
        )
        few_shot = format_feedback_as_few_shot(feedback, agent_type)
        if not few_shot:
            return

        # Append to system prompt
        agent_cfg = config.agents.get(agent_type)
        if agent_cfg:
            agent_cfg.system_prompt = current_prompt + "\n\n" + few_shot
            logger.debug(
                "feedback_injected",
                agent_type=agent_type,
                examples=len(feedback),
            )
    except Exception as exc:
        logger.debug("feedback_injection_failed", agent_type=agent_type, error=str(exc))
