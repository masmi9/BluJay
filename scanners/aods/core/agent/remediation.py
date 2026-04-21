"""
core.agent.remediation - Remediation agent for generating code patches (Track 100).

Wraps AgentLoop with a remediation-expert system prompt that produces concrete
code fixes for vulnerability findings, with difficulty estimates and test
suggestions.

Public API:
    RemediationResult - Pydantic model for structured remediation output
    run_remediation() - Synchronous entry point for CLI use
    run_remediation_background() - Background thread entry for API use
    parse_remediation() - Extract structured RemediationResult from agent response
    save_remediation_to_report() - Persist remediation data to JSON report
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

DifficultyLevel = Literal["easy", "moderate", "complex"]


class FindingRemediation(BaseModel):
    """A concrete remediation patch for a single finding."""

    model_config = ConfigDict(extra="forbid")

    finding_title: str = Field(..., description="Title of the finding being remediated")
    vulnerability_type: str = Field("", description="Type of vulnerability (e.g., SQL Injection, Insecure Storage)")
    cwe_id: Optional[str] = Field(None, description="CWE identifier (e.g., CWE-89)")
    current_code: str = Field("", description="The vulnerable code snippet")
    fixed_code: str = Field("", description="The patched code snippet")
    explanation: str = Field("", description="Why the fix works and what it changes")
    difficulty: DifficultyLevel = Field("moderate", description="Implementation difficulty")
    breaking_changes: str = Field("", description="Potential breaking changes or side effects")
    references: List[str] = Field(default_factory=list, description="External references (OWASP, Android docs, etc.)")
    test_suggestion: str = Field("", description="Suggested test to verify the fix")


class RemediationResult(BaseModel):
    """Structured remediation output from the remediation agent."""

    model_config = ConfigDict(extra="forbid")

    remediations: List[FindingRemediation] = Field(default_factory=list)
    summary: str = ""
    total_findings: int = 0
    total_with_patches: int = 0
    overall_effort: str = Field("moderate", description="Overall remediation effort estimate")
    token_usage: Dict[str, int] = Field(default_factory=dict)
    task_id: str = ""
    method: str = Field("llm", description="Execution method: llm, heuristic, heuristic_fallback")


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

REMEDIATION_SYSTEM_PROMPT = """You are a senior Android security engineer specializing in \
vulnerability remediation. Your job is to generate concrete, production-ready code patches \
for security vulnerabilities found in Android applications.

Your audience is a development team that needs specific code changes they can apply directly.

## Output Format

You MUST produce a JSON object wrapped in <remediation_json> tags. The JSON schema is:

```json
{
  "remediations": [
    {
      "finding_title": "Title from the scan report",
      "vulnerability_type": "e.g., SQL Injection, Insecure Storage",
      "cwe_id": "CWE-XXX",
      "current_code": "The vulnerable code snippet",
      "fixed_code": "The patched code with the fix applied",
      "explanation": "Why this fix works and what it changes",
      "difficulty": "easy | moderate | complex",
      "breaking_changes": "Any breaking changes or side effects to watch for",
      "references": ["https://owasp.org/...", "https://developer.android.com/..."],
      "test_suggestion": "How to verify this fix works"
    }
  ],
  "summary": "Overall remediation summary",
  "total_findings": 10,
  "total_with_patches": 8,
  "overall_effort": "easy | moderate | complex"
}
```

## Instructions

1. Use the available tools to read the scan report and examine all findings.
2. For each finding, read the relevant source code to understand the vulnerable code path.
3. Generate a concrete code fix - not just advice, but actual before/after code snippets.
4. Assess difficulty: "easy" (config change, 1-2 lines), "moderate" (method-level refactor), \
"complex" (architectural change, multiple files).
5. Note any breaking changes - API signature changes, behavior differences, dependency additions.
6. Provide specific test suggestions - what to test, what inputs to use, expected outcomes.
7. Include authoritative references (OWASP MASVS, Android developer docs, CWE entries).
8. Focus on HIGH and CRITICAL findings first, then MEDIUM. Skip INFO unless specifically relevant.
9. If you cannot generate a code fix (e.g., finding is too vague), explain why and suggest \
manual investigation steps instead.

## Code Fix Guidelines

- Prefer Android Jetpack Security library (`androidx.security.crypto`) for crypto fixes
- Use `EncryptedSharedPreferences` instead of plain `SharedPreferences` for sensitive data
- Use `Network Security Config` XML for certificate pinning and cleartext traffic control
- For SQL injection, always use parameterized queries (`?` placeholders)
- For exported components, add `android:permission` or `android:exported="false"`
- For WebView, disable JavaScript if not needed, enable safe browsing, restrict file access

## Prioritization Framework

Generate patches in this priority order:

1. **Authentication/Authorization bypass** (CWE-287, CWE-862) - enables all other attacks. \
Fix exported components, missing permission checks, insecure deep link handlers FIRST.

2. **Data exposure** (CWE-312, CWE-319, CWE-532) - cleartext storage, cleartext \
transmission, logging sensitive data. Typically easy fixes with high impact.

3. **Injection flaws** (CWE-89, CWE-78, CWE-79) - SQL injection, command injection, \
XSS in WebViews. Use parameterized queries and input validation.

4. **Cryptographic issues** (CWE-327, CWE-330, CWE-798) - weak algorithms, insecure \
random, hardcoded keys. Migrate to modern APIs (EncryptedSharedPreferences, \
SecureRandom, Android Keystore).

5. **Configuration weaknesses** (CWE-693) - debug enabled, backup allowed. Typically \
one-line config changes.

If triage classified a finding as likely_fp, do NOT generate a patch unless you have \
strong evidence from source code that the finding is real.

## Critical Requirements

- Call list_findings with limit=100 to get ALL findings before generating patches.
- If has_more is true in the list_findings response, call list_findings again with offset
  to retrieve remaining findings. Repeat until all findings are retrieved.
- You MUST generate remediation patches for EVERY CRITICAL and HIGH finding.
- For each finding, use read_decompiled_source to examine the actual vulnerable code.
- Do NOT produce your final JSON until you have examined ALL relevant findings.

## Model Compatibility

Wrap your final JSON output in <remediation_json>...</remediation_json> tags.
If you cannot use XML tags, wrap your JSON in a ```json code block instead."""


# Tools allowed for the remediate agent
REMEDIATION_TOOLS = frozenset({
    "list_findings",
    "get_finding_detail",
    "read_decompiled_source",
    "search_source",
    "get_manifest",
    "get_report_section",
    "find_similar_findings",
})


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def parse_remediation(
    response_text: str,
    task_id: str = "",
    token_usage: Optional[Dict[str, int]] = None,
) -> RemediationResult:
    """Extract structured RemediationResult from agent response text.

    Uses shared output parser with 3 strategies (XML tags, code blocks,
    bare JSON via raw_decode). Falls back to minimal RemediationResult on failure.
    """
    from .output_parser import parse_structured_output

    usage = token_usage or {}
    parse_error = ""

    data = parse_structured_output(
        response_text,
        xml_tag="remediation_json",
        expected_fields={"remediations"},
        agent_name="remediation",
    )
    if data is not None:
        try:
            data["task_id"] = task_id
            data["token_usage"] = usage
            return RemediationResult(**data)
        except Exception as e:
            logger.warning("remediation_model_validation_failed", error=str(e))
            parse_error = str(e)

    # Fallback: wrap raw text
    logger.info("remediation_parse_fallback", task_id=task_id)
    summary = response_text
    if parse_error:
        summary = f"Parse error: {parse_error[:200]}. Raw: {response_text[:300]}"
    return RemediationResult(
        summary=summary,
        task_id=task_id,
        token_usage=usage,
    )


def save_remediation_to_report(result: RemediationResult, report_path: str) -> bool:
    """Persist remediation data to an existing JSON report.

    Uses atomic write (write to .tmp then rename) to avoid corruption.
    Acquires report_write_lock to prevent concurrent write races.

    Returns:
        True if saved successfully, False otherwise.
    """
    from .report_lock import report_write_lock

    rp = Path(report_path)
    if not rp.exists():
        logger.warning("remediation_report_not_found", path=report_path)
        return False

    with report_write_lock:
        try:
            with open(rp, "r") as f:
                report_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("remediation_report_read_error", path=report_path, error=str(e))
            return False

        report_data["remediation"] = result.model_dump()

        tmp_path = str(rp) + ".tmp"
        try:
            with open(tmp_path, "w") as f:
                json.dump(report_data, f, indent=2, default=str)
            os.rename(tmp_path, str(rp))
            logger.info("remediation_saved_to_report", path=report_path)
        except OSError as e:
            logger.error("remediation_save_error", path=report_path, error=str(e))
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return False

    # Best-effort: persist remediation metadata to vector DB (outside lock)
    _index_remediation_to_vector_db(result, report_path)

    return True


def _index_remediation_to_vector_db(result: "RemediationResult", report_path: str) -> None:
    """Best-effort: persist remediation metadata to vector DB.

    For each remediation, updates existing finding metadata with
    difficulty, CWE, and has_code_patch flag.
    """
    if os.environ.get("AODS_VECTOR_DB_ENABLED", "0").lower() not in ("1", "true"):
        return

    try:
        from core.vector_db import get_semantic_finding_index

        idx = get_semantic_finding_index()
        if idx is None or not idx.is_available():
            return

        for rem in result.remediations:
            finding_id = rem.finding_title
            meta_update = {
                "remediation_difficulty": rem.difficulty,
                "remediation_cwe_id": rem.cwe_id or "",
                "has_code_patch": bool(rem.fixed_code),
            }
            idx.update_finding_metadata(finding_id, meta_update)

        logger.debug("remediation_vector_indexed", count=len(result.remediations))
    except Exception as exc:
        logger.warning("remediation_vector_index_failed", error=str(exc))


def _has_api_key(config: Any) -> bool:
    """Check whether an LLM API key is available for the configured provider."""
    from .providers import has_api_key

    return has_api_key(
        provider_name=getattr(config, "provider", "anthropic"),
        api_key_env=getattr(config, "api_key_env", "") or None,
    )


def run_remediation(
    report_file: str,
    config: Any = None,
    source_dir: Optional[str] = None,
    report_dir: str = "reports",
    force_heuristic: bool = False,
) -> RemediationResult:
    """Run the remediation agent synchronously (CLI entry point).

    When no LLM API key is available (or ``force_heuristic=True``), falls
    back to rule-based heuristic remediation automatically.

    Args:
        report_file: Path to the JSON scan report.
        config: AgentConfig instance. If None, loads from default location.
        source_dir: Optional path to decompiled source directory.
        report_dir: Directory containing report files.
        force_heuristic: If True, always use heuristic mode regardless of API key.

    Returns:
        RemediationResult with code patches and difficulty estimates.
    """
    from .config import load_agent_config
    from .loop import AgentLoop
    from .state import create_agent_task, update_agent_task
    from .tools import ToolContext

    if config is None:
        config = load_agent_config()

    # Auto-fallback: use heuristic when no API key is available
    if force_heuristic or not _has_api_key(config):
        logger.info("remediation_heuristic_fallback", reason="force" if force_heuristic else "no_api_key")
        from .remediation_heuristic import run_heuristic_remediation

        return run_heuristic_remediation(report_file, report_dir=report_dir)

    _inject_remediation_prompt(config)
    from .prompt_context import inject_scan_context
    inject_scan_context(config, "remediate", report_file)
    from .feedback_injector import inject_feedback_context
    inject_feedback_context(config, "remediate", report_file)
    from .model_router import apply_model_routing
    apply_model_routing(config, "remediate", _count_findings(report_file))

    task_id = create_agent_task(
        agent_type="remediate", params={"report_file": report_file}
    )

    user_message = _build_remediation_message(report_file, source_dir)

    tool_context = ToolContext(report_dir=report_dir)
    if source_dir:
        tool_context.source_dir = source_dir

    from .output_parser import make_parse_check

    loop = AgentLoop(
        config=config,
        agent_type="remediate",
        task_id=task_id,
        tool_context=tool_context,
    )
    result = loop.run(
        user_message,
        parse_check=make_parse_check("remediation_json", {"remediations"}),
    )

    remediation = parse_remediation(
        result.response,
        task_id=task_id,
        token_usage={
            "input_tokens": result.token_usage.input_tokens,
            "output_tokens": result.token_usage.output_tokens,
        },
    )

    save_remediation_to_report(remediation, report_file)

    update_agent_task(
        task_id,
        status="completed" if result.success else "failed",
        result=remediation.summary or result.response,
        error=result.error,
    )

    return remediation


def run_remediation_background(
    task_id: str,
    config: Any,
    user_message: str,
    tool_context: Any,
    report_file: Optional[str] = None,
) -> None:
    """Run remediation agent in a background thread (API entry point).

    Called from the API route's _run_agent_background when agent_type == "remediate".
    Falls back to heuristic mode when no API key is available.
    """
    from .state import update_agent_task

    try:
        # Auto-fallback to heuristic mode
        if not _has_api_key(config) and report_file:
            logger.info("remediation_background_heuristic_fallback", task_id=task_id)
            from .remediation_heuristic import run_heuristic_remediation

            remediation = run_heuristic_remediation(report_file)
            remediation.task_id = task_id
            update_agent_task(
                task_id,
                status="completed",
                result=json.dumps(remediation.model_dump(), default=str),
            )
            return

        from .loop import AgentLoop
        from .output_parser import make_parse_check as _mk_check

        _inject_remediation_prompt(config)

        loop = AgentLoop(
            config=config,
            agent_type="remediate",
            task_id=task_id,
            tool_context=tool_context,
        )
        result = loop.run(
            user_message,
            parse_check=_mk_check("remediation_json", {"remediations"}),
        )

        remediation = parse_remediation(
            result.response,
            task_id=task_id,
            token_usage={
                "input_tokens": result.token_usage.input_tokens,
                "output_tokens": result.token_usage.output_tokens,
            },
        )

        if report_file:
            save_remediation_to_report(remediation, report_file)

        update_agent_task(
            task_id,
            status="completed" if result.success else "failed",
            result=json.dumps(remediation.model_dump(), default=str),
            error=result.error,
        )
    except ImportError as e:
        # SDK not installed - try heuristic fallback
        if report_file:
            try:
                from .remediation_heuristic import run_heuristic_remediation

                remediation = run_heuristic_remediation(report_file)
                remediation.task_id = task_id
                update_agent_task(
                    task_id,
                    status="completed",
                    result=json.dumps(remediation.model_dump(), default=str),
                )
                return
            except Exception as fallback_err:
                logger.error(
                    "remediation_heuristic_fallback_failed",
                    task_id=task_id,
                    error=str(fallback_err),
                )
        update_agent_task(
            task_id, status="failed", error=f"Missing dependency: {e}"
        )
    except Exception as e:
        logger.error("remediation_background_failed", task_id=task_id, error=str(e))
        update_agent_task(task_id, status="failed", error=str(e))


def _inject_remediation_prompt(config: Any) -> None:
    """Ensure the remediate agent has a system prompt.

    Uses the config-provided prompt (YAML inline or file) if set,
    otherwise falls back to the code-defined default.
    """
    from .config import AgentSpecificConfig

    if "remediate" not in config.agents:
        config.agents["remediate"] = AgentSpecificConfig(
            system_prompt=REMEDIATION_SYSTEM_PROMPT
        )
    elif not config.agents["remediate"].system_prompt:
        if not config.get_agent_system_prompt("remediate"):
            config.agents["remediate"].system_prompt = REMEDIATION_SYSTEM_PROMPT


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


def _build_remediation_message(
    report_file: str, source_dir: Optional[str] = None
) -> str:
    """Build the initial user message for remediation with context hints.

    If the report contains triage results or pipeline context, includes
    guidance to prioritize confirmed true positives and skip likely FPs.
    """
    finding_count = _count_findings(report_file)

    parts = [
        "Generate concrete code patches for the vulnerability findings in this scan report.",
        f"The report file is: {report_file}",
    ]
    if finding_count:
        parts.append(
            f"IMPORTANT: The report contains {finding_count} findings. "
            f"You MUST generate patches for ALL CRITICAL and HIGH findings."
        )
    if source_dir:
        parts.append(f"Decompiled source code is available at: {source_dir}")

    # Inject triage context if available (from pipeline or standalone triage)
    triage_context = _get_triage_context(report_file)
    if triage_context:
        parts.append("")
        parts.append("## Triage Context (from prior triage analysis)")
        parts.append(triage_context)

    # Inject cross-agent collaboration context
    from .collaboration import build_collaboration_context
    collab = build_collaboration_context("remediate", report_file)
    if collab:
        parts.append("")
        parts.append(collab)

    parts.append(
        "Use the available tools to read findings, examine the report, "
        "and inspect source code. For each finding, provide before/after code "
        "snippets with explanations. Produce your output in the required "
        "<remediation_json> format."
    )
    return "\n".join(parts)


def _get_triage_context(report_file: str) -> str:
    """Extract triage context from the report to guide remediation.

    Reads _pipeline_context (from supervisor) or triage section to identify
    confirmed TPs and likely FPs, so remediation can prioritise accordingly.
    """
    try:
        rp = Path(report_file)
        if not rp.exists():
            return ""
        with open(rp, "r") as f:
            data = json.load(f)

        lines: List[str] = []

        # Pipeline context (written by supervisor after triage)
        ctx = data.get("_pipeline_context", {})
        confirmed = ctx.get("confirmed_tp_titles", [])
        likely_fp = ctx.get("likely_fp_titles", [])

        # Fall back to triage section if no pipeline context
        if not confirmed and "triage" in data:
            triage = data["triage"]
            for cf in triage.get("classified_findings", []):
                classification = cf.get("classification", "")
                title = cf.get("finding_title", "")
                if classification in ("confirmed_tp", "likely_tp"):
                    confirmed.append(title)
                elif classification == "likely_fp":
                    likely_fp.append(title)

        if confirmed:
            lines.append(
                f"PRIORITY: These {len(confirmed)} findings were classified as "
                f"true positives by triage. Focus remediation effort on these first:"
            )
            for t in confirmed[:20]:
                lines.append(f"  - {t}")

        if likely_fp:
            lines.append(
                f"\nSKIP: These {len(likely_fp)} findings were classified as "
                f"likely false positives. Do NOT generate patches for these "
                f"unless you have strong evidence they are real:"
            )
            for t in likely_fp[:10]:
                lines.append(f"  - {t}")

        return "\n".join(lines)
    except Exception:
        return ""
