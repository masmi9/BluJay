"""
core.agent.narration - Narration agent for structured scan analysis (Track 91).

Wraps AgentLoop with a security-analyst system prompt that produces structured
JSON output (Narrative), per-agent tool filtering, and report integration.

Public API:
    Narrative - Pydantic model for structured narrative output
    run_narration() - Synchronous entry point for CLI use
    run_narration_background() - Background thread entry for API use
    parse_narrative() - Extract structured Narrative from agent response
    save_narrative_to_report() - Persist agentic_analysis to JSON report
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class AttackChain(BaseModel):
    """A potential attack chain combining multiple findings."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Short descriptive name for the attack chain")
    steps: List[str] = Field(default_factory=list, description="Ordered attack steps")
    impact: str = Field("", description="Business impact if exploited")
    likelihood: str = Field("LOW", description="Likelihood: CRITICAL, HIGH, MEDIUM, LOW")


class PriorityFinding(BaseModel):
    """A prioritised finding with exploitability context."""

    model_config = ConfigDict(extra="forbid")

    title: str
    severity: str = "MEDIUM"
    exploitability: str = Field("", description="How easily exploitable")
    context: str = Field("", description="Why this finding matters")
    cwe_id: Optional[str] = None


class RemediationStep(BaseModel):
    """A single remediation action item."""

    model_config = ConfigDict(extra="forbid")

    priority: int = Field(1, ge=1, description="1 = highest priority")
    title: str
    description: str = ""
    effort: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH effort estimate")
    findings_addressed: List[str] = Field(default_factory=list)


class Narrative(BaseModel):
    """Structured narrative output from the narration agent."""

    model_config = ConfigDict(extra="forbid")

    executive_summary: str = ""
    risk_rating: str = Field("LOW", description="Overall: CRITICAL, HIGH, MEDIUM, LOW")
    risk_rationale: str = ""
    attack_chains: List[AttackChain] = Field(default_factory=list)
    priority_findings: List[PriorityFinding] = Field(default_factory=list)
    remediation_plan: List[RemediationStep] = Field(default_factory=list)
    app_context: str = Field("", description="Application context and observations")
    historical_comparison: str = Field("", description="Comparison with prior scans")
    full_narrative: str = Field("", description="Full natural-language narrative")
    token_usage: Dict[str, int] = Field(default_factory=dict)
    task_id: str = ""
    method: str = Field("llm", description="Execution method: llm, heuristic, heuristic_fallback")


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

NARRATION_SYSTEM_PROMPT = """You are a senior mobile security analyst producing a structured \
vulnerability assessment narrative for an Android application scan.

Your audience is a technical security team lead who needs to understand:
1. The overall security posture and risk level
2. Which findings form exploitable attack chains
3. What to fix first and why

## Output Format

You MUST produce a JSON object wrapped in <narrative_json> tags. The JSON schema is:

```json
{
  "executive_summary": "2-3 paragraph executive summary",
  "risk_rating": "CRITICAL | HIGH | MEDIUM | LOW",
  "risk_rationale": "Why this risk rating was assigned",
  "attack_chains": [
    {
      "name": "Chain name",
      "steps": ["Step 1", "Step 2"],
      "impact": "Business impact",
      "likelihood": "HIGH | MEDIUM | LOW"
    }
  ],
  "priority_findings": [
    {
      "title": "Finding title",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
      "exploitability": "How easy to exploit",
      "context": "Why it matters in this app's context",
      "cwe_id": "CWE-XXX"
    }
  ],
  "remediation_plan": [
    {
      "priority": 1,
      "title": "Fix title",
      "description": "What to do",
      "effort": "LOW | MEDIUM | HIGH",
      "findings_addressed": ["Finding 1", "Finding 2"]
    }
  ],
  "app_context": "Observations about the application architecture",
  "historical_comparison": "Comparison with prior scans if available",
  "full_narrative": "Complete narrative in natural language"
}
```

## Instructions

1. Use the available tools to read the scan report, examine findings, and \
inspect decompiled source code when relevant.
2. Look for combinations of findings that could form attack chains \
(e.g., insecure storage + exported activity = data theft chain).
3. Prioritize findings by real-world exploitability, not just severity labels. \
A MEDIUM finding that is trivially exploitable in context may be more urgent \
than a HIGH finding behind authentication.
4. Consider the app's purpose and architecture when assessing impact. \
A banking app with insecure crypto is more critical than a calculator app.
5. Provide specific, actionable remediation steps ordered by priority and effort.
6. The full_narrative field should be a polished, readable report suitable for \
stakeholders.

## Critical Requirements

- Call list_findings with limit=100 to get findings. If has_more is true, call again with offset to get remaining.
- You MUST analyze EVERY finding - do not stop at a subset.
- For CRITICAL and HIGH findings, use read_decompiled_source to examine the actual code.
- Do NOT produce your final JSON until you have examined ALL findings.

## Risk Rating Decision Tree

Assign risk_rating using these criteria (check top-down, stop at first match):

- **CRITICAL**: At least one finding is remotely exploitable without authentication AND \
leads to data theft, RCE, or account takeover. Confirmed attack chains with HIGH \
likelihood automatically elevate to CRITICAL.

- **HIGH**: Multiple HIGH-severity confirmed TPs exist, OR a single finding enables \
significant data exfiltration or privilege escalation. Attack chains with MEDIUM \
likelihood that lead to data theft qualify.

- **MEDIUM**: Findings exist but are either locally exploitable only, mitigated by \
other controls, or limited to information disclosure. No viable remote attack chains.

- **LOW**: Only informational findings, library-level issues without exploitation \
path, or findings fully mitigated. The app demonstrates reasonable security posture.

When in doubt between two ratings, choose the higher one and note the uncertainty \
in risk_rationale.

## Remediation Plan Alignment

Your remediation_plan MUST address attack chains in order:
1. Break the highest-impact attack chain first
2. Then address standalone CRITICAL/HIGH findings
3. Then remaining findings by severity

For each remediation item, reference which attack chain it breaks (if any).

## Model Compatibility

Wrap your final JSON output in <narrative_json>...</narrative_json> tags.
If you cannot use XML tags, wrap your JSON in a ```json code block instead."""


# Tools allowed for the narrate agent
NARRATION_TOOLS = frozenset({
    "list_findings",
    "get_finding_detail",
    "get_report_section",
    "get_executive_summary",
    "read_decompiled_source",
    "search_source",
    "get_manifest",
    "semantic_search",
    "find_similar_findings",
})


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def parse_narrative(response_text: str, task_id: str = "", token_usage: Optional[Dict[str, int]] = None) -> Narrative:
    """Extract structured Narrative from agent response text.

    Uses shared output parser with 3 strategies (XML tags, code blocks,
    bare JSON via raw_decode). Falls back to minimal Narrative on failure.
    """
    from .output_parser import parse_structured_output

    usage = token_usage or {}
    parse_error = ""

    data = parse_structured_output(
        response_text,
        xml_tag="narrative_json",
        expected_fields={"executive_summary", "risk_rating"},
        agent_name="narration",
    )
    if data is not None:
        try:
            data["task_id"] = task_id
            data["token_usage"] = usage
            return Narrative(**data)
        except Exception as e:
            logger.warning("narrative_model_validation_failed", error=str(e))
            parse_error = str(e)

    # Fallback: wrap raw text
    logger.info("narrative_parse_fallback", task_id=task_id)
    summary = "Agent analysis completed (unstructured output)."
    if parse_error:
        summary = f"Agent analysis completed (parse error: {parse_error[:200]})."
    return Narrative(
        full_narrative=response_text,
        executive_summary=summary,
        task_id=task_id,
        token_usage=usage,
    )


def save_narrative_to_report(narrative: Narrative, report_path: str) -> bool:
    """Persist agentic_analysis to an existing JSON report.

    Uses atomic write (write to .tmp then rename) to avoid corruption.
    Acquires report_write_lock to prevent concurrent write races.

    Returns:
        True if saved successfully, False otherwise.
    """
    from .report_lock import report_write_lock

    rp = Path(report_path)
    if not rp.exists():
        logger.warning("narrative_report_not_found", path=report_path)
        return False

    with report_write_lock:
        try:
            with open(rp, "r") as f:
                report_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("narrative_report_read_error", path=report_path, error=str(e))
            return False

        report_data["agentic_analysis"] = narrative.model_dump()

        tmp_path = str(rp) + ".tmp"
        try:
            with open(tmp_path, "w") as f:
                json.dump(report_data, f, indent=2, default=str)
            os.rename(tmp_path, str(rp))
            logger.info("narrative_saved_to_report", path=report_path)
            return True
        except OSError as e:
            logger.error("narrative_save_error", path=report_path, error=str(e))
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return False


def _has_api_key(config: Any) -> bool:
    """Check whether an LLM API key is available for the configured provider."""
    from .providers import has_api_key

    return has_api_key(
        provider_name=getattr(config, "provider", "anthropic"),
        api_key_env=getattr(config, "api_key_env", "") or None,
    )


def run_narration(
    report_file: str,
    config: Any = None,
    source_dir: Optional[str] = None,
    report_dir: str = "reports",
    force_heuristic: bool = False,
) -> Narrative:
    """Run the narration agent synchronously (CLI entry point).

    When no LLM API key is available (or ``force_heuristic=True``), falls
    back to rule-based heuristic narration automatically.

    Args:
        report_file: Path to the JSON scan report.
        config: AgentConfig instance. If None, loads from default location.
        source_dir: Optional path to decompiled source directory.
        report_dir: Directory containing report files.
        force_heuristic: If True, always use heuristic mode regardless of API key.

    Returns:
        Narrative with structured analysis.
    """
    from .config import load_agent_config
    from .loop import AgentLoop
    from .state import create_agent_task, update_agent_task
    from .tools import ToolContext

    if config is None:
        config = load_agent_config()

    # Auto-fallback: use heuristic when no API key is available
    if force_heuristic or not _has_api_key(config):
        logger.info(
            "narration_heuristic_fallback",
            reason="force" if force_heuristic else "no_api_key",
            provider=getattr(config, "provider", "anthropic"),
            api_key_env=getattr(config, "api_key_env", "AUTO"),
        )
        from .narration_heuristic import run_heuristic_narration

        return run_heuristic_narration(report_file, report_dir=report_dir)

    # Inject narration system prompt into config if not already set
    _inject_narration_prompt(config)
    from .prompt_context import inject_scan_context
    inject_scan_context(config, "narrate", report_file)
    from .feedback_injector import inject_feedback_context
    inject_feedback_context(config, "narrate", report_file)
    from .model_router import apply_model_routing
    apply_model_routing(config, "narrate", _count_findings(report_file))

    task_id = create_agent_task(agent_type="narrate", params={"report_file": report_file})

    # Build enhanced user message
    user_message = _build_narration_message(report_file, source_dir)

    # Set up tool context
    tool_context = ToolContext(report_dir=report_dir)
    if source_dir:
        tool_context.source_dir = source_dir

    from .output_parser import make_parse_check

    # Create loop with narration system prompt override
    loop = AgentLoop(
        config=config,
        agent_type="narrate",
        task_id=task_id,
        tool_context=tool_context,
    )
    result = loop.run(
        user_message,
        parse_check=make_parse_check("narrative_json", {"executive_summary", "risk_rating"}),
    )

    # Parse response into structured Narrative
    narrative = parse_narrative(
        result.response,
        task_id=task_id,
        token_usage={
            "input_tokens": result.token_usage.input_tokens,
            "output_tokens": result.token_usage.output_tokens,
        },
    )

    # Save to report
    save_narrative_to_report(narrative, report_file)

    # Update task with structured result
    update_agent_task(
        task_id,
        status="completed" if result.success else "failed",
        result=narrative.executive_summary or result.response,
        error=result.error,
    )

    return narrative


def run_narration_background(
    task_id: str,
    config: Any,
    user_message: str,
    tool_context: Any,
    report_file: Optional[str] = None,
) -> None:
    """Run narration agent in a background thread (API entry point).

    Called from the API route's _run_agent_background when agent_type == "narrate".
    Falls back to heuristic mode when no API key is available.
    """
    from .state import update_agent_task

    try:
        # Auto-fallback to heuristic mode
        if not _has_api_key(config) and report_file:
            logger.info("narration_background_heuristic_fallback", task_id=task_id)
            from .narration_heuristic import run_heuristic_narration

            narrative = run_heuristic_narration(report_file)
            narrative.task_id = task_id
            update_agent_task(
                task_id,
                status="completed",
                result=json.dumps(narrative.model_dump(), default=str),
            )
            return

        from .loop import AgentLoop
        from .output_parser import make_parse_check as _mk_check

        _inject_narration_prompt(config)

        loop = AgentLoop(
            config=config,
            agent_type="narrate",
            task_id=task_id,
            tool_context=tool_context,
        )
        result = loop.run(
            user_message,
            parse_check=_mk_check("narrative_json", {"executive_summary", "risk_rating"}),
        )

        narrative = parse_narrative(
            result.response,
            task_id=task_id,
            token_usage={
                "input_tokens": result.token_usage.input_tokens,
                "output_tokens": result.token_usage.output_tokens,
            },
        )

        # Save to report if path provided
        if report_file:
            save_narrative_to_report(narrative, report_file)

        update_agent_task(
            task_id,
            status="completed" if result.success else "failed",
            result=json.dumps(narrative.model_dump(), default=str),
            error=result.error,
        )
    except ImportError as e:
        # SDK not installed - try heuristic fallback
        if report_file:
            try:
                from .narration_heuristic import run_heuristic_narration

                narrative = run_heuristic_narration(report_file)
                narrative.task_id = task_id
                update_agent_task(
                    task_id,
                    status="completed",
                    result=json.dumps(narrative.model_dump(), default=str),
                )
                return
            except Exception:
                pass
        update_agent_task(task_id, status="failed", error=f"Missing dependency: {e}")
    except Exception as e:
        logger.error("narration_background_failed", task_id=task_id, error=str(e))
        update_agent_task(task_id, status="failed", error=str(e))


def _inject_narration_prompt(config: Any) -> None:
    """Ensure the narrate agent has a system prompt.

    Uses the config-provided prompt (YAML inline or file) if set,
    otherwise falls back to the code-defined default.
    """
    from .config import AgentSpecificConfig

    if "narrate" not in config.agents:
        config.agents["narrate"] = AgentSpecificConfig(system_prompt=NARRATION_SYSTEM_PROMPT)
    elif not config.agents["narrate"].system_prompt:
        if not config.get_agent_system_prompt("narrate"):
            config.agents["narrate"].system_prompt = NARRATION_SYSTEM_PROMPT


def _count_findings(report_file: str) -> int:
    """Count findings in a report file. Returns 0 on error."""
    try:
        rp = Path(report_file)
        if not rp.exists():
            return 0
        with open(rp, "r") as f:
            data = json.load(f)
        findings = data.get("findings", data.get("vulnerabilities", []))
        return len(findings) if isinstance(findings, list) else 0
    except Exception:
        return 0


def _build_narration_message(report_file: str, source_dir: Optional[str] = None) -> str:
    """Build the initial user message for narration with context hints."""
    finding_count = _count_findings(report_file)

    parts = [
        "Analyze the scan results and produce a structured security narrative.",
        f"The report file is: {report_file}",
    ]
    if finding_count:
        parts.append(
            f"IMPORTANT: The report contains {finding_count} findings. "
            f"You MUST analyze ALL {finding_count} findings."
        )
    if source_dir:
        parts.append(f"Decompiled source code is available at: {source_dir}")

    # Vector DB: inject historical context from past scans
    historical = _get_historical_context(report_file)
    if historical:
        parts.append("")
        parts.append("## Historical Context from Past Scans")
        parts.append(historical)
        parts.append(
            "Use this historical context to compare the current scan against "
            "prior results and note patterns that recur."
        )

    # Inject cross-agent collaboration context
    from .collaboration import build_collaboration_context
    collab = build_collaboration_context("narrate", report_file)
    if collab:
        parts.append("")
        parts.append(collab)

    parts.append(
        "Use the available tools to read findings, examine the report, "
        "and inspect source code. Then produce your analysis in the "
        "required <narrative_json> format."
    )
    return "\n".join(parts)


def _get_historical_context(report_file: str) -> str:
    """Query vector DB for historical similar findings from past scans.

    Returns a formatted string of historical matches, or empty string if
    vector DB is unavailable or has no relevant data.
    """
    if os.environ.get("AODS_VECTOR_DB_ENABLED", "0").lower() not in ("1", "true"):
        return ""

    try:
        rp = Path(report_file)
        if not rp.exists():
            return ""

        with open(rp, "r") as f:
            report_data = json.load(f)

        findings = report_data.get("findings", report_data.get("vulnerabilities", []))
        if not findings:
            return ""

        from core.vector_db import get_semantic_finding_index

        idx = get_semantic_finding_index()
        if idx is None or not idx.is_available():
            return ""

        # Query top-3 HIGH+ findings against vector DB for historical matches
        high_findings = [
            f for f in findings
            if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")
        ][:3]
        if not high_findings:
            high_findings = findings[:2]

        lines: List[str] = []
        seen_titles: set = set()
        for finding in high_findings:
            title = finding.get("title", "Unknown")
            similar = idx.find_similar(finding, n_results=3, include_same_scan=False)
            for match in similar:
                score = match.get("score", match.get("similarity", 0))
                # Skip low-similarity matches to reduce noise
                if score < 0.7:
                    continue
                match_title = match.get("title", match.get("metadata", {}).get("title", ""))
                if not match_title or match_title in seen_titles:
                    continue
                seen_titles.add(match_title)
                scan_id = match.get("scan_id", match.get("metadata", {}).get("scan_id", "unknown"))
                classification = match.get("metadata", {}).get("type", "finding")
                lines.append(
                    f"- Finding \"{title}\" is similar to \"{match_title}\" "
                    f"(scan={scan_id}, similarity={score:.2f}, type={classification})"
                )

        if not lines:
            return ""

        return "\n".join(lines)
    except Exception as exc:
        logger.debug("narration_historical_context_failed", error=str(exc))
        return ""
