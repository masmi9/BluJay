"""
core.agent.prompt_context - Build dynamic context sections for agent system prompts.

Injects scan-specific context (finding count, severity distribution, CWEs,
app category) into system prompts so agents start with full awareness of the
scan landscape without spending iterations discovering it via tools.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)


def build_scan_context(report_file: str) -> str:
    """Build a scan context section from report data.

    Reads the report and produces a Markdown-formatted context block
    with finding count, severity distribution, top CWEs, and app
    category (if orchestration data is available).

    Args:
        report_file: Path to the JSON scan report.

    Returns:
        Formatted context string, or empty string on error.
    """
    try:
        rp = Path(report_file)
        if not rp.exists():
            return ""

        with open(rp, "r") as f:
            report = json.load(f)
    except Exception:
        return ""

    findings = report.get("findings", report.get("vulnerabilities", []))
    if not isinstance(findings, list):
        return ""

    metadata = report.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    # Severity distribution
    severity_counts: Dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "UNKNOWN")).upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Top CWEs
    cwe_counts: Dict[str, int] = {}
    for f in findings:
        cwe = f.get("cwe_id") or f.get("cwe", "")
        if cwe:
            cwe_counts[str(cwe)] = cwe_counts.get(str(cwe), 0) + 1
    top_cwes = sorted(cwe_counts.items(), key=lambda x: -x[1])[:10]

    # Basic info
    apk_name = metadata.get("apk_name", "Unknown")
    profile = metadata.get("scan_profile", "standard")
    total = len(findings)

    lines = [
        "## Scan Context",
        f"- APK: {apk_name}",
        f"- Scan profile: {profile}",
        f"- Total findings: {total}",
    ]

    if severity_counts:
        sev_str = ", ".join(
            f"{k}={v}" for k, v in sorted(severity_counts.items())
        )
        lines.append(f"- Severity distribution: {sev_str}")

    if top_cwes:
        cwe_str = ", ".join(f"{cwe} ({count})" for cwe, count in top_cwes[:5])
        lines.append(f"- Top CWEs: {cwe_str}")

    # Orchestration context if available
    orch = report.get("orchestration")
    if isinstance(orch, dict):
        app_cat = orch.get("app_category", "")
        if app_cat:
            lines.append(f"- App category: {app_cat}")
        attack_surface = orch.get("attack_surface", [])
        if attack_surface:
            lines.append(f"- Attack surface: {', '.join(attack_surface)}")

    # Triage context if available
    triage = report.get("triage")
    if isinstance(triage, dict):
        classified = triage.get("classified_findings", [])
        if classified:
            tp_count = sum(
                1 for c in classified
                if c.get("classification") in ("confirmed_tp", "likely_tp")
            )
            fp_count = sum(
                1 for c in classified
                if c.get("classification") == "likely_fp"
            )
            lines.append(f"- Triage: {tp_count} true positives, {fp_count} false positives")

    # Guidance based on finding count
    if total > 50:
        lines.append("")
        lines.append(
            "NOTE: This is a large scan with 50+ findings. Focus on CRITICAL and HIGH "
            "findings first. Group related findings aggressively to avoid redundancy."
        )
    elif total == 0:
        lines.append("")
        lines.append(
            "NOTE: This scan produced 0 findings. This may indicate a well-secured app "
            "or limited scan coverage. Comment on which areas were not covered."
        )

    return "\n".join(lines)


def build_remediation_context(report_file: str) -> str:
    """Build CWE-specific remediation hints from heuristic templates.

    Reads the report to identify detected CWEs, then pulls relevant
    fix templates from the remediation heuristic to give the LLM a
    head start on generating patches.

    Args:
        report_file: Path to the JSON scan report.

    Returns:
        Formatted remediation context string, or empty string.
    """
    try:
        rp = Path(report_file)
        if not rp.exists():
            return ""

        with open(rp, "r") as f:
            report = json.load(f)
    except Exception:
        return ""

    findings = report.get("findings", report.get("vulnerabilities", []))
    if not isinstance(findings, list) or not findings:
        return ""

    detected_cwes: set = set()
    for f in findings:
        cwe = f.get("cwe_id") or f.get("cwe", "")
        if cwe:
            detected_cwes.add(str(cwe))

    if not detected_cwes:
        return ""

    try:
        from core.agent.remediation_heuristic import _CWE_FIX_TEMPLATES
    except ImportError:
        return ""

    lines = ["## CWE-Specific Remediation Guidance"]
    matched = 0
    for cwe in sorted(detected_cwes):
        template = _CWE_FIX_TEMPLATES.get(cwe)
        if template:
            matched += 1
            vuln_type = template.get("vulnerability_type", cwe)
            difficulty = template.get("difficulty", "moderate")
            explanation = (template.get("explanation", "") or "")[:200]
            lines.append(f"\n### {cwe}: {vuln_type}")
            lines.append(f"Difficulty: {difficulty}")
            if explanation:
                lines.append(f"Fix approach: {explanation}")

    if matched == 0:
        return ""

    return "\n".join(lines)


def inject_scan_context(config: Any, agent_type: str, report_file: str) -> None:
    """Append dynamic scan context to an agent's system prompt.

    Modifies the config in-place by appending scan context and (for
    remediation agents) CWE-specific guidance to the system prompt.

    Args:
        config: AgentConfig instance (modified in-place).
        agent_type: Agent type name.
        report_file: Path to the JSON scan report.
    """
    current_prompt = config.get_agent_system_prompt(agent_type)
    if not current_prompt:
        return

    sections = []

    # Scan context for all agents
    scan_ctx = build_scan_context(report_file)
    if scan_ctx:
        sections.append(scan_ctx)

    # CWE-specific guidance for remediation agent
    if agent_type == "remediate":
        remed_ctx = build_remediation_context(report_file)
        if remed_ctx:
            sections.append(remed_ctx)

    if not sections:
        return

    # Append context to the system prompt
    agent_cfg = config.agents.get(agent_type)
    if agent_cfg:
        agent_cfg.system_prompt = current_prompt + "\n\n" + "\n\n".join(sections)
