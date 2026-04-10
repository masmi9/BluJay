"""
core.agent.triage - Triage agent for auto-classifying scan findings (Track 99).

Wraps AgentLoop with a security-triage system prompt that classifies findings
(TP/FP/needs review), groups related findings by root cause, and prioritizes
by exploitability.

Public API:
    TriageResult - Pydantic model for structured triage output
    run_triage() - Synchronous entry point for CLI use
    run_triage_background() - Background thread entry for API use
    parse_triage() - Extract structured TriageResult from agent response
    save_triage_to_report() - Persist triage data to JSON report
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

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

ClassificationLabel = Literal[
    "confirmed_tp", "likely_tp", "needs_review", "likely_fp", "informational"
]


class ClassifiedFinding(BaseModel):
    """A finding with triage classification."""

    model_config = ConfigDict(extra="forbid")

    finding_title: str
    classification: ClassificationLabel
    severity: str = "MEDIUM"
    confidence: float = Field(0.5, ge=0.0, le=1.0, description="Triage confidence")
    reasoning: str = ""
    group_id: Optional[str] = None


class FindingGroup(BaseModel):
    """A group of related findings sharing a root cause."""

    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    root_cause: str = ""
    finding_titles: List[str] = Field(default_factory=list)


class AttackChain(BaseModel):
    """A multi-step exploitation path combining multiple findings."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Short name for the attack chain")
    steps: List[str] = Field(default_factory=list, description="Ordered finding titles forming the chain")
    impact: str = Field("", description="What an attacker achieves via this chain")
    likelihood: str = Field("unknown", description="Exploitation likelihood: low|medium|high|unknown")


class TriageResult(BaseModel):
    """Structured triage output from the triage agent."""

    model_config = ConfigDict(extra="forbid")

    classified_findings: List[ClassifiedFinding] = Field(default_factory=list)
    groups: List[FindingGroup] = Field(default_factory=list)
    attack_chains: List[AttackChain] = Field(default_factory=list)
    priority_order: List[str] = Field(default_factory=list)
    summary: str = ""
    triage_notes: Dict[str, str] = Field(default_factory=dict)
    token_usage: Dict[str, int] = Field(default_factory=dict)
    task_id: str = ""
    method: str = Field("llm", description="Execution method: llm, heuristic, heuristic_fallback")


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

TRIAGE_SYSTEM_PROMPT = """You are a senior mobile security triage analyst. Your job is to \
classify scan findings, group related findings by root cause, and prioritize them by \
real-world exploitability - saving analysts significant manual review time.

## Output Format

You MUST produce a JSON object wrapped in <triage_json> tags. The JSON schema is:

```json
{
  "classified_findings": [
    {
      "finding_title": "Finding title from scan report",
      "classification": "confirmed_tp | likely_tp | needs_review | likely_fp | informational",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
      "confidence": 0.0-1.0,
      "reasoning": "Why this classification was assigned",
      "group_id": "optional group identifier"
    }
  ],
  "groups": [
    {
      "id": "group-1",
      "label": "Short group label",
      "root_cause": "Shared root cause description",
      "finding_titles": ["Finding 1", "Finding 2"]
    }
  ],
  "attack_chains": [
    {
      "name": "Remote Data Exfiltration via Deep Link",
      "steps": ["Exported Activity", "Deep Link Handler SQL Injection"],
      "impact": "Remote attacker can exfiltrate database contents",
      "likelihood": "high"
    }
  ],
  "priority_order": ["Most critical finding first", "Second most critical", "..."],
  "summary": "Overall triage summary",
  "triage_notes": {
    "key_observation": "Any important notes for the analyst"
  }
}
```

## Classification Guidelines

- **confirmed_tp**: Clear true positive with strong evidence of exploitability. \
Code paths are reachable, inputs are attacker-controlled, impact is tangible.
- **likely_tp**: Probable true positive but needs minor verification. Pattern matches \
known vulnerability but dynamic confirmation is not yet available.
- **needs_review**: Ambiguous finding requiring human analyst review. Could go either way \
 -  insufficient context to decide automatically.
- **likely_fp**: Probable false positive. Pattern match in library code, dead code path, \
or mitigated by other controls.
- **informational**: Not a vulnerability but useful context (e.g., debug flags, \
version info, configuration observations).

## Instructions

1. Use the available tools to read the scan report and examine all findings.
2. For each finding, assess reachability, attacker control, impact, and existing mitigations.
3. Group findings that share a root cause (e.g., all exported component issues, \
all insecure storage issues in the same class).
4. Order priority_order by real-world exploitability, NOT just severity labels. \
A MEDIUM finding behind no authentication is more urgent than a HIGH finding \
in unreachable code.
5. Use find_similar_findings to identify patterns across the codebase.
6. Provide clear, actionable reasoning for each classification.
7. The summary should give the analyst a quick overview of triage results.

## Attack Chain Analysis

Identify multi-step exploitation paths where multiple findings combine into a single
exploit chain. Examples:
- Exported Activity + Deep Link Handler + SQL Injection = remote data exfiltration
- Insecure Storage + Exported Content Provider = cross-app data theft
- Hardcoded API Key + Cleartext Traffic = credential interception
- WebView JS Interface + Missing Certificate Pinning = remote code execution

For each chain, list the finding titles that form the steps (in exploitation order),
describe the end-to-end impact, and assess likelihood (low/medium/high).

Add an "attack_chains" array to your JSON output.

## Critical Requirements

- Call list_findings with limit=100 to get findings. If has_more is true, call again with offset to get remaining.
- If has_more is true in the list_findings response, call list_findings again with offset
  to retrieve remaining findings. Repeat until all findings are retrieved.
- You MUST classify EVERY finding in the report - do not stop early or skip any.
- For CRITICAL and HIGH findings, use read_decompiled_source to examine the actual code.
- Do NOT produce your final JSON until you have examined ALL findings.

## Reasoning Framework

For each finding, apply this 4-step analysis BEFORE assigning a classification:

1. **REACHABILITY**: Is the vulnerable code reachable from an entry point (exported component, \
intent handler, network callback)? If the code is dead or unreachable, classify as likely_fp.

2. **ATTACKER CONTROL**: Does the attacker control the inputs to the vulnerable function? \
Trace data flow from entry point to vulnerability. Intent extras, URI parameters, and \
network responses are attacker-controlled. Hardcoded values and internal state are not.

3. **IMPACT**: What is the worst-case consequence if exploited? Data theft > DoS > information \
disclosure. Consider the app's domain - a banking app SQL injection is CRITICAL, a calculator \
app SQL injection is MEDIUM.

4. **MITIGATIONS**: Are there compensating controls? Permission checks, input validation, \
encryption at rest, certificate pinning. A finding with strong mitigations may be \
informational even if the pattern matches.

Only after completing all 4 steps, assign your classification. Reference the decisive step \
in your reasoning field.

## Confidence Calibration

- confirmed_tp: confidence 0.85-0.95 (reserve 0.95+ for dynamically verified)
- likely_tp: confidence 0.60-0.84
- needs_review: confidence 0.40-0.59
- likely_fp: confidence 0.10-0.39
- informational: confidence 0.05-0.30

NEVER set confidence above 0.95 without dynamic verification evidence.

## Model Compatibility

Wrap your final JSON output in <triage_json>...</triage_json> tags.
If you cannot use XML tags, wrap your JSON in a ```json code block instead."""


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def parse_triage(
    response_text: str,
    task_id: str = "",
    token_usage: Optional[Dict[str, int]] = None,
) -> TriageResult:
    """Extract structured TriageResult from agent response text.

    Uses shared output parser with 3 strategies (XML tags, code blocks,
    bare JSON via raw_decode). Falls back to minimal TriageResult on failure.
    """
    from .output_parser import parse_structured_output

    usage = token_usage or {}
    parse_error = ""

    data = parse_structured_output(
        response_text,
        xml_tag="triage_json",
        expected_fields={"classified_findings", "groups"},
        agent_name="triage",
    )
    if data is not None:
        try:
            # Clamp confidence values to [0.0, 1.0] - LLMs may produce out-of-range
            for cf in data.get("classified_findings", []):
                if isinstance(cf, dict) and "confidence" in cf:
                    cf["confidence"] = max(0.0, min(1.0, float(cf["confidence"])))
            data["task_id"] = task_id
            data["token_usage"] = usage
            return TriageResult(**data)
        except Exception as e:
            logger.warning("triage_model_validation_failed", error=str(e))
            parse_error = str(e)

    # Fallback: wrap raw text
    logger.info("triage_parse_fallback", task_id=task_id)
    summary = response_text
    if parse_error:
        summary = f"Parse error: {parse_error[:200]}. Raw: {response_text[:300]}"
    return TriageResult(
        summary=summary,
        task_id=task_id,
        token_usage=usage,
    )


def save_triage_to_report(result: TriageResult, report_path: str) -> bool:
    """Persist triage data to an existing JSON report.

    Uses atomic write (write to .tmp then rename) to avoid corruption.
    Acquires report_write_lock to prevent concurrent write races.

    Returns:
        True if saved successfully, False otherwise.
    """
    from .report_lock import report_write_lock

    rp = Path(report_path)
    if not rp.exists():
        logger.warning("triage_report_not_found", path=report_path)
        return False

    with report_write_lock:
        try:
            with open(rp, "r") as f:
                report_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("triage_report_read_error", path=report_path, error=str(e))
            return False

        report_data["triage"] = result.model_dump()

        tmp_path = str(rp) + ".tmp"
        try:
            with open(tmp_path, "w") as f:
                json.dump(report_data, f, indent=2, default=str)
            os.rename(tmp_path, str(rp))
            logger.info("triage_saved_to_report", path=report_path)
        except OSError as e:
            logger.error("triage_save_error", path=report_path, error=str(e))
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return False

    # Best-effort: persist triage decisions to vector DB (outside lock)
    _index_triage_to_vector_db(result, report_path)

    return True


def _index_triage_to_vector_db(result: TriageResult, report_path: str) -> None:
    """Best-effort: persist triage classifications to vector DB.

    For each classified finding, updates existing vector metadata with
    triage fields.  If the finding isn't yet indexed, indexes it fresh.
    """
    if os.environ.get("AODS_VECTOR_DB_ENABLED", "0").lower() not in ("1", "true"):
        return

    try:
        from core.vector_db import get_semantic_finding_index

        idx = get_semantic_finding_index()
        if idx is None or not idx.is_available():
            return

        # Read report for scan_context (needed if we must index fresh)
        rp = Path(report_path)
        scan_context: Dict[str, Any] = {}
        if rp.exists():
            try:
                with open(rp, "r") as f:
                    rdata = json.load(f)
                scan_context = {
                    "scan_id": rdata.get("session_id") or rdata.get("scan_id", ""),
                    "owner_user_id": rdata.get("owner_user_id", "system"),
                    "tenant_id": rdata.get("tenant_id", "default"),
                    "visibility": rdata.get("visibility", "private"),
                }
            except Exception:
                pass

        for cf in result.classified_findings:
            finding_id = cf.finding_title  # best stable ID available
            meta_update = {
                "triage_classification": cf.classification,
                "triage_confidence": cf.confidence,
                "triage_reasoning": (cf.reasoning or "")[:500],
                "triage_severity": cf.severity,
            }
            updated = idx.update_finding_metadata(finding_id, meta_update)
            if not updated and scan_context.get("owner_user_id"):
                # Finding not yet in vector DB - index it fresh
                finding_stub = {
                    "id": finding_id,
                    "title": cf.finding_title,
                    "severity": cf.severity,
                }
                finding_stub.update(meta_update)
                idx.index_finding(finding_stub, scan_context)

        logger.debug(
            "triage_vector_indexed",
            count=len(result.classified_findings),
        )
    except Exception as exc:
        logger.warning("triage_vector_index_failed", error=str(exc))


def _has_api_key(config: Any) -> bool:
    """Check whether an LLM API key is available for the configured provider."""
    from .providers import has_api_key

    return has_api_key(
        provider_name=getattr(config, "provider", "anthropic"),
        api_key_env=getattr(config, "api_key_env", "") or None,
    )


def run_triage(
    report_file: str,
    config: Any = None,
    source_dir: Optional[str] = None,
    report_dir: str = "reports",
    force_heuristic: bool = False,
    incremental: bool = True,
) -> TriageResult:
    """Run the triage agent synchronously (CLI entry point).

    When no LLM API key is available (or ``force_heuristic=True``), falls
    back to rule-based heuristic classification automatically.

    Args:
        report_file: Path to the JSON scan report.
        config: AgentConfig instance. If None, loads from default location.
        source_dir: Optional path to decompiled source directory.
        report_dir: Directory containing report files.
        force_heuristic: If True, always use heuristic mode regardless of API key.

    Returns:
        TriageResult with classified findings and groups.
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
            "triage_heuristic_fallback",
            reason="force" if force_heuristic else "no_api_key",
            provider=getattr(config, "provider", "anthropic"),
            api_key_env=getattr(config, "api_key_env", "AUTO"),
        )
        from .triage_heuristic import run_heuristic_triage

        return run_heuristic_triage(report_file, report_dir=report_dir)

    _inject_triage_prompt(config)
    from .prompt_context import inject_scan_context
    inject_scan_context(config, "triage", report_file)
    from .feedback_injector import inject_feedback_context
    inject_feedback_context(config, "triage", report_file)
    from .model_router import apply_model_routing
    apply_model_routing(config, "triage", _count_findings(report_file))

    # Incremental triage: carry forward unchanged findings from previous triage
    carried_forward = []
    incremental_context = ""
    if incremental:
        carried_forward, incremental_context = _compute_incremental(report_file)
        if carried_forward and not incremental_context:
            # All findings unchanged - return previous triage
            logger.info("incremental_triage_no_changes", total=len(carried_forward))
            return _rebuild_from_carried_forward(carried_forward, report_file)

    task_id = create_agent_task(
        agent_type="triage", params={"report_file": report_file}
    )

    user_message = _build_triage_message(report_file, source_dir)
    if incremental_context:
        user_message += "\n\n" + incremental_context

    tool_context = ToolContext(report_dir=report_dir)
    if source_dir:
        tool_context.source_dir = source_dir

    from .output_parser import make_parse_check

    loop = AgentLoop(
        config=config,
        agent_type="triage",
        task_id=task_id,
        tool_context=tool_context,
    )
    result = loop.run(
        user_message,
        parse_check=make_parse_check("triage_json", {"classified_findings", "groups"}),
    )

    triage = parse_triage(
        result.response,
        task_id=task_id,
        token_usage={
            "input_tokens": result.token_usage.input_tokens,
            "output_tokens": result.token_usage.output_tokens,
        },
    )

    # Merge carried-forward classifications from incremental triage
    if carried_forward:
        for cf_dict in carried_forward:
            try:
                rationale = cf_dict.get("rationale", "")
                if rationale and not rationale.startswith("[Carried forward]"):
                    cf_dict["rationale"] = f"[Carried forward] {rationale}"
                elif not rationale:
                    cf_dict["rationale"] = "[Carried forward] Classification from previous scan"
                triage.classified_findings.append(ClassifiedFinding(**cf_dict))
            except Exception:
                pass

    # Ensure every finding is classified (LLMs may drop some)
    triage = _ensure_completeness(triage, report_file)

    save_triage_to_report(triage, report_file)

    update_agent_task(
        task_id,
        status="completed" if result.success else "failed",
        result=triage.summary or result.response,
        error=result.error,
    )

    return triage


def run_triage_background(
    task_id: str,
    config: Any,
    user_message: str,
    tool_context: Any,
    report_file: Optional[str] = None,
) -> None:
    """Run triage agent in a background thread (API entry point).

    Called from the API route's _run_agent_background when agent_type == "triage".
    Falls back to heuristic mode when no API key is available.
    """
    from .state import update_agent_task

    try:
        # Auto-fallback to heuristic mode
        if not _has_api_key(config) and report_file:
            logger.info("triage_background_heuristic_fallback", task_id=task_id)
            from .triage_heuristic import run_heuristic_triage

            triage = run_heuristic_triage(report_file)
            triage.task_id = task_id
            update_agent_task(
                task_id,
                status="completed",
                result=json.dumps(triage.model_dump(), default=str),
            )
            return

        from .loop import AgentLoop
        from .output_parser import make_parse_check as _mk_check

        _inject_triage_prompt(config)

        loop = AgentLoop(
            config=config,
            agent_type="triage",
            task_id=task_id,
            tool_context=tool_context,
        )
        result = loop.run(
            user_message,
            parse_check=_mk_check("triage_json", {"classified_findings", "groups"}),
        )

        triage = parse_triage(
            result.response,
            task_id=task_id,
            token_usage={
                "input_tokens": result.token_usage.input_tokens,
                "output_tokens": result.token_usage.output_tokens,
            },
        )

        # Ensure every finding is classified (LLMs may drop some)
        if report_file:
            triage = _ensure_completeness(triage, report_file)
            save_triage_to_report(triage, report_file)

        update_agent_task(
            task_id,
            status="completed" if result.success else "failed",
            result=json.dumps(triage.model_dump(), default=str),
            error=result.error,
        )
    except ImportError as e:
        # SDK not installed - try heuristic fallback
        if report_file:
            try:
                from .triage_heuristic import run_heuristic_triage

                triage = run_heuristic_triage(report_file)
                triage.task_id = task_id
                update_agent_task(
                    task_id,
                    status="completed",
                    result=json.dumps(triage.model_dump(), default=str),
                )
                return
            except Exception:
                pass
        update_agent_task(
            task_id, status="failed", error=f"Missing dependency: {e}"
        )
    except Exception as e:
        logger.error("triage_background_failed", task_id=task_id, error=str(e))
        update_agent_task(task_id, status="failed", error=str(e))


def _inject_triage_prompt(config: Any) -> None:
    """Ensure the triage agent has a system prompt.

    Uses the config-provided prompt (YAML inline or file) if set,
    otherwise falls back to the code-defined default.
    """
    from .config import AgentSpecificConfig

    if "triage" not in config.agents:
        config.agents["triage"] = AgentSpecificConfig(
            system_prompt=TRIAGE_SYSTEM_PROMPT
        )
    elif not config.agents["triage"].system_prompt:
        # Only set default if user hasn't provided a custom prompt
        # (check system_prompt_file too via get_agent_system_prompt)
        if not config.get_agent_system_prompt("triage"):
            config.agents["triage"].system_prompt = TRIAGE_SYSTEM_PROMPT


def _build_triage_message(
    report_file: str, source_dir: Optional[str] = None
) -> str:
    """Build the initial user message for triage with context hints."""
    # Count findings for inclusion in message
    finding_count = _count_findings(report_file)

    parts = [
        "Triage the scan findings: classify each as TP/FP/needs review, "
        "group related findings by root cause, and prioritize by exploitability.",
        f"The report file is: {report_file}",
    ]
    if finding_count:
        parts.append(
            f"IMPORTANT: The report contains {finding_count} findings. "
            f"You MUST classify ALL {finding_count} findings."
        )
        if finding_count > 30:
            parts.append(
                "NOTE: For findings with identical titles and CWEs in different files, "
                "you may group them under a single classification with a note about "
                "the number of affected locations. Focus your detailed analysis on "
                "unique vulnerability types."
            )
    # Severity breakdown for immediate prioritization
    try:
        rp = Path(report_file)
        if rp.exists():
            with open(rp, "r") as f:
                data = json.load(f)
            findings = data.get("findings", data.get("vulnerabilities", []))
            if findings and isinstance(findings, list):
                sev_counts: Dict[str, int] = {}
                for f in findings:
                    sev = str(f.get("severity", "UNKNOWN")).upper()
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                sev_str = ", ".join(f"{k}: {v}" for k, v in sorted(sev_counts.items()))
                parts.append(f"Severity breakdown: {sev_str}")

                high_critical = sev_counts.get("CRITICAL", 0) + sev_counts.get("HIGH", 0)
                if high_critical > 0:
                    parts.append(
                        f"PRIORITY: Start with the {high_critical} CRITICAL/HIGH findings "
                        f"and use read_decompiled_source on each before classifying."
                    )
    except Exception:
        pass

    if source_dir:
        parts.append(f"Decompiled source code is available at: {source_dir}")

    # Inject historical triage decisions from vector DB
    historical = _get_historical_triage_context(report_file)
    if historical:
        parts.append("")
        parts.append("## Historical Triage Decisions from Past Scans")
        parts.append(historical)
        parts.append(
            "Use these historical triage decisions to inform your classifications. "
            "If a similar finding was previously classified as FP or TP by an analyst, "
            "weigh that context appropriately."
        )

    parts.append(
        "Use the available tools to read findings, examine the report, "
        "inspect source code, and find similar findings. Then produce your "
        "triage in the required <triage_json> format."
    )
    return "\n".join(parts)


def _ensure_completeness(
    result: TriageResult, report_file: str
) -> TriageResult:
    """Ensure every finding in the report has a triage classification.

    LLMs sometimes drop findings, especially with large reports. This
    function identifies any missing findings and auto-classifies them
    using the heuristic fallback, merging them into the result.

    Args:
        result: The LLM-produced triage result.
        report_file: Path to the JSON scan report.

    Returns:
        The same result with any missing findings appended.
    """
    try:
        rp = Path(report_file)
        if not rp.exists():
            return result

        with open(rp, "r") as f:
            data = json.load(f)

        findings = data.get("findings", data.get("vulnerabilities", []))
        if not findings or not isinstance(findings, list):
            return result

        # Build set of already-classified titles
        classified_titles = {cf.finding_title for cf in result.classified_findings}

        # Find missing findings
        missing = [f for f in findings if (f.get("title") or "") not in classified_titles]
        if not missing:
            return result

        logger.info(
            "triage_completeness_fill",
            total=len(findings),
            classified=len(classified_titles),
            missing=len(missing),
        )

        # Auto-classify missing findings using heuristic
        from .triage_heuristic import _classify_finding

        for f in missing:
            classified = _classify_finding(f)
            classified.reasoning = (
                f"Auto-classified by heuristic (LLM missed this finding). "
                f"{classified.reasoning}"
            )
            result.classified_findings.append(classified)

        # Update priority_order to include new findings at the end
        new_titles = {(f.get("title") or "") for f in missing}
        for cf in result.classified_findings:
            if cf.finding_title in new_titles and cf.finding_title not in result.priority_order:
                result.priority_order.append(cf.finding_title)

    except Exception as exc:
        logger.debug("triage_completeness_check_failed", error=str(exc))

    return result


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


def _get_historical_triage_context(report_file: str) -> str:
    """Query vector DB for historical triage decisions on similar findings.

    Looks for past analyst feedback (TP/FP corrections) stored in ChromaDB
    and formats them as context for the triage agent.

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

        # Query HIGH+ severity findings for historical triage decisions
        high_findings = [
            f for f in findings
            if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")
        ][:5]
        if not high_findings:
            high_findings = findings[:3]

        # Also include MEDIUM findings - past analyst feedback on MEDIUM
        # findings is valuable context regardless of severity
        high_titles = {h.get("title", "") for h in high_findings}
        medium_findings = [
            f for f in findings
            if str(f.get("severity", "")).upper() == "MEDIUM"
            and f.get("title", "") not in high_titles
        ][:3]

        query_findings = high_findings + medium_findings

        lines: List[str] = []
        seen_titles: set = set()
        for finding in query_findings:
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
                metadata = match.get("metadata", {})
                classification = metadata.get("triage_classification", "")
                feedback = metadata.get("triage_feedback", "")
                scan_id = match.get("scan_id", metadata.get("scan_id", "unknown"))

                line = (
                    f'- Finding "{title}" is similar to "{match_title}" '
                    f"(scan={scan_id}, similarity={score:.2f}"
                )
                if classification:
                    line += f", prior_classification={classification}"
                if feedback:
                    line += f', analyst_note="{feedback}"'
                line += ")"
                lines.append(line)

        if not lines:
            return ""

        return "\n".join(lines)
    except Exception as exc:
        logger.debug("triage_historical_context_failed", error=str(exc))
        return ""


# ---------------------------------------------------------------------------
# Incremental triage helpers
# ---------------------------------------------------------------------------


def _compute_incremental(report_file: str):
    """Compute incremental triage data from previous triage results.

    Returns:
        (carried_forward, incremental_context):
        - carried_forward: list of classification dicts for unchanged findings
        - incremental_context: user message snippet describing what changed
          (empty string if all unchanged → caller should return early)
    """
    try:
        rp = Path(report_file)
        if not rp.exists():
            return [], ""

        with open(rp, "r") as f:
            report_data = json.load(f)

        previous_triage = report_data.get("triage", {})
        previous_classified = previous_triage.get("classified_findings", [])
        if not previous_classified:
            return [], ""

        findings = report_data.get("findings", report_data.get("vulnerabilities", []))
        if not findings:
            return [], ""

        from .finding_diff import compute_finding_diff, get_carried_forward_classifications

        new_findings, changed_findings, unchanged_findings = compute_finding_diff(
            findings, previous_triage
        )

        carried_forward = get_carried_forward_classifications(
            unchanged_findings, previous_triage
        )

        # If nothing new or changed, signal to return early
        if not new_findings and not changed_findings:
            return carried_forward, ""

        # Build context for LLM
        parts = [
            "## Incremental Triage",
            f"This is a re-scan. {len(unchanged_findings)} findings are unchanged "
            f"and have been pre-classified from the previous triage.",
            f"You only need to triage the {len(new_findings)} new and "
            f"{len(changed_findings)} changed findings.",
        ]
        if new_findings:
            parts.append(f"New findings: {', '.join(f.get('title', '?') for f in new_findings[:10])}")
        if changed_findings:
            parts.append(f"Changed findings: {', '.join(f.get('title', '?') for f in changed_findings[:10])}")

        logger.info(
            "incremental_triage_computed",
            new=len(new_findings),
            changed=len(changed_findings),
            unchanged=len(unchanged_findings),
        )
        return carried_forward, "\n".join(parts)

    except Exception as exc:
        logger.debug("incremental_triage_failed", error=str(exc))
        return [], ""


def _rebuild_from_carried_forward(
    carried_forward: list,
    report_file: str,
) -> TriageResult:
    """Build a TriageResult from carried-forward classifications only.

    Used when all findings are unchanged - no LLM call needed.
    """
    classified = []
    for cf_dict in carried_forward:
        try:
            # Tag carried-forward findings so analysts can distinguish them
            rationale = cf_dict.get("rationale", "")
            if rationale and not rationale.startswith("[Carried forward]"):
                cf_dict["rationale"] = f"[Carried forward] {rationale}"
            elif not rationale:
                cf_dict["rationale"] = "[Carried forward] Classification from previous scan"
            classified.append(ClassifiedFinding(**cf_dict))
        except Exception:
            pass

    result = TriageResult(
        classified_findings=classified,
        summary=f"Incremental triage: all {len(classified)} findings unchanged from previous scan",
        triage_notes={"mode": "incremental", "unchanged_count": str(len(classified))},
        method="heuristic",  # No LLM used
    )

    # Save to report
    save_triage_to_report(result, report_file)
    return result
