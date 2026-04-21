"""
core.agent.verification - Verification agent for dynamic finding confirmation (Track 92).

Wraps AgentLoop with a Frida-expert system prompt that verifies HIGH+ static
findings via dynamic instrumentation. Produces structured JSON output
(VerificationResult), per-agent tool filtering, and report integration.

When Frida is unavailable, the agent still analyzes findings and produces
verification strategies for manual follow-up.

Public API:
    FindingVerification - Pydantic model for a single finding's verification
    VerificationResult - Pydantic model for aggregate verification results
    run_verification() - Synchronous entry point for CLI use
    run_verification_background() - Background thread entry for API use
    parse_verification() - Extract structured VerificationResult from agent response
    save_verification_to_report() - Persist verification data to JSON report
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


class FindingVerification(BaseModel):
    """Verification result for a single finding."""

    model_config = ConfigDict(extra="forbid")

    finding_title: str = Field(..., description="Title of the verified finding")
    original_confidence: float = Field(0.0, ge=0.0, le=1.0, description="Original confidence score")
    verified_confidence: float = Field(0.0, ge=0.0, le=1.0, description="Post-verification confidence")
    status: str = Field(
        "unverifiable",
        description="Verification status: confirmed, likely, unverifiable, likely_fp",
    )
    evidence: str = Field("", description="Evidence supporting the verification")
    frida_script: str = Field("", description="Frida script used for verification")
    frida_output: str = Field("", description="Output captured from Frida execution")
    reasoning: str = Field("", description="Agent reasoning for the verdict")
    verification_method: str = Field("dynamic", description="Verification method: static|dynamic|both")


class VerificationResult(BaseModel):
    """Aggregate verification results from the verification agent."""

    model_config = ConfigDict(extra="forbid")

    verifications: List[FindingVerification] = Field(default_factory=list)
    summary: str = ""
    total_verified: int = 0
    total_confirmed: int = 0
    total_fp_detected: int = 0
    frida_available: bool = False
    static_verifications: int = Field(0, description="Number of findings verified via static analysis")
    token_usage: Dict[str, int] = Field(default_factory=dict)
    task_id: str = ""
    method: str = Field("llm", description="Execution method: llm, heuristic, heuristic_fallback")


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

VERIFICATION_SYSTEM_PROMPT = """You are an expert Android security researcher specializing in \
dynamic verification of static analysis findings using Frida instrumentation.

Your task is to verify HIGH and CRITICAL static analysis findings by:
1. Examining the finding details and source code context
2. Determining if the vulnerability is real or a false positive
3. When Frida is available, generating and executing instrumentation scripts to confirm
4. Updating finding confidence based on dynamic evidence

## Verification Strategy by Vulnerability Type

**Insecure Storage (SharedPreferences, SQLite, files):**
- Hook SharedPreferences.putString/getString to capture stored data
- Check if sensitive data (tokens, passwords, PII) is stored in plaintext
- Verify file permissions on created files

**Exported Components (Activities, Services, Receivers):**
- Verify component is actually exported in manifest
- Check if intent filters allow external invocation
- Test if sensitive data is accessible via exported components

**Hardcoded Cryptographic Keys:**
- Hook SecretKeySpec constructor to capture key material
- Check if key bytes match known weak patterns (all zeros, test keys)
- Verify cipher algorithm and mode (ECB = weak, CBC/GCM = better)

**SQL Injection:**
- Hook rawQuery/execSQL to capture SQL statements
- Check if user input is concatenated into queries
- Verify parameterized queries vs string concatenation

**Intent Injection:**
- Hook getIntent to capture received intents
- Check if intent data is validated before use
- Verify that exported components validate caller identity

**Generic Method Hooks:**
- Hook target method to observe arguments and return values
- Compare observed behavior with expected secure behavior

## Workflow

1. First, use `check_frida_status` to see if Frida is available
2. Read the scan report findings using available tools
3. For each HIGH/CRITICAL finding:
   a. Read the relevant source code
   b. Analyze the vulnerability context
   c. If Frida is available, generate and execute a verification script
   d. Determine verification status based on evidence
4. Update finding confidence values based on verification results

## Output Format

Produce a JSON object wrapped in <verification_json> tags:

```json
{
  "verifications": [
    {
      "finding_title": "Finding title from report",
      "original_confidence": 0.75,
      "verified_confidence": 0.95,
      "status": "confirmed",
      "evidence": "Dynamic analysis confirmed: SharedPreferences stores auth token in plaintext",
      "frida_script": "Java.perform(function() { ... })",
      "frida_output": "[VERIFY] SharedPreferences.putString: key=auth_token value=abc123",
      "reasoning": "The Frida hook captured plaintext storage of authentication token"
    }
  ],
  "summary": "Verified 5 findings: 3 confirmed, 1 likely FP, 1 unverifiable",
  "total_verified": 5,
  "total_confirmed": 3,
  "total_fp_detected": 1,
  "frida_available": true
}
```

## Status Values
- **confirmed**: Dynamic evidence proves the vulnerability exists
- **likely**: Source code analysis strongly suggests vulnerability but no dynamic proof
- **unverifiable**: Cannot determine with available information
- **likely_fp**: Evidence suggests this is a false positive

## Static Verification (When Frida is Unavailable)

If Frida is not available (check_frida_status returns unavailable), you can still
provide valuable verification using static analysis:

1. **Reachability analysis**: Trace whether the vulnerable code is reachable from
   an exported entry point (Activity, Service, Receiver, ContentProvider).
2. **Input control analysis**: Determine if the inputs to the vulnerable function
   are attacker-controlled (comes from Intent extras, URI parameters, user input).
3. **Mitigation check**: Look for mitigating controls along the code path
   (permission checks, input validation, sanitization).
4. **Dead code detection**: Check if the vulnerable method is actually called
   anywhere in the codebase.

For static-only verification, set verification_method to "static" and provide
your assessment in the reasoning field. Use these confidence mappings:
- Reachable from exported component + attacker-controlled input → confirmed (0.9)
- Reachable but input source unclear → likely (0.7)
- Not clearly reachable or mitigated → unverifiable (keep original confidence)
- Dead code or fully mitigated → likely_fp (0.2)

## Confidence Calibration Rules

Apply these calibration rules when setting verified_confidence:

- **Dynamic confirmation** (Frida hook captured the vulnerable behavior): \
Set verified_confidence to 0.95. Status: confirmed.

- **Dynamic partial** (Frida hook ran but behavior was ambiguous): \
Set verified_confidence to 0.70. Status: likely.

- **Static reachability confirmed** (no Frida, but code path analysis shows the \
vulnerable code IS reachable from an exported entry point with attacker-controlled \
input): Set verified_confidence to 0.85. Status: likely.

- **Static reachability unclear** (code exists but call chain is unclear): \
Keep original_confidence unchanged. Status: unverifiable.

- **Dead code or fully mitigated** (method exists but never called from exported paths): \
Set verified_confidence to 0.15. Status: likely_fp.

- **Library code** (vulnerability is in a third-party library, not app code): \
Set verified_confidence to original_confidence * 0.5. Status: likely_fp.

NEVER set verified_confidence above 0.95 or below 0.05.

## Important Rules
- NEVER execute scripts that modify app data or state
- NEVER use scripts that access the network or filesystem
- Keep scripts read-only: observe and log only
- If Frida is not available, still analyze findings and produce verification \
strategies with status "likely" or "unverifiable"
- Maximum 10 findings per verification session
- Maximum 60 seconds per script execution

## Model Compatibility

Wrap your final JSON output in <verification_json>...</verification_json> tags.
If you cannot use XML tags, wrap your JSON in a ```json code block instead."""


# Tools allowed for the verify agent
VERIFICATION_TOOLS = frozenset({
    "get_finding_detail",
    "read_decompiled_source",
    "search_source",
    "get_manifest",
    "check_frida_status",
    "generate_frida_script",
    "execute_frida_script",
    "update_finding_confidence",
})


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def parse_verification(
    response_text: str, task_id: str = "", token_usage: Optional[Dict[str, int]] = None
) -> VerificationResult:
    """Extract structured VerificationResult from agent response text.

    Uses shared output parser with 3 strategies (XML tags, code blocks,
    bare JSON via raw_decode). Falls back to minimal VerificationResult on failure.
    """
    from .output_parser import parse_structured_output

    usage = token_usage or {}

    data = parse_structured_output(
        response_text,
        xml_tag="verification_json",
        expected_fields={"verifications", "total_verified"},
        agent_name="verification",
    )
    if data is not None:
        try:
            # Clamp confidence values to [0.0, 1.0] - LLMs may produce out-of-range
            for v in data.get("verifications", []):
                if isinstance(v, dict):
                    for conf_key in ("verified_confidence", "original_confidence"):
                        if conf_key in v:
                            v[conf_key] = max(0.0, min(1.0, float(v[conf_key])))
            data["task_id"] = task_id
            data["token_usage"] = usage
            return VerificationResult(**data)
        except Exception as e:
            logger.warning("verification_model_validation_failed", error=str(e))

    # Fallback: wrap raw text
    logger.info("verification_parse_fallback", task_id=task_id)
    return VerificationResult(
        summary=response_text[:500] if response_text else "Verification completed (unstructured output).",
        task_id=task_id,
        token_usage=usage,
    )


def save_verification_to_report(result: VerificationResult, report_path: str) -> bool:
    """Persist verification results to an existing JSON report.

    Adds report["verification"] with aggregate results and updates
    individual finding confidence values in report["vulnerabilities"].

    Uses atomic write (write to .tmp then rename) to avoid corruption.
    Acquires report_write_lock to prevent concurrent write races.
    """
    from .report_lock import report_write_lock

    rp = Path(report_path)
    if not rp.exists():
        logger.warning("verification_report_not_found", path=report_path)
        return False

    with report_write_lock:
        try:
            with open(rp, "r") as f:
                report_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("verification_report_read_error", path=report_path, error=str(e))
            return False

        # Add aggregate verification section
        report_data["verification"] = result.model_dump()

        # Update individual finding confidence values
        findings = report_data.get("vulnerabilities", report_data.get("findings", []))
        verification_map = {v.finding_title: v for v in result.verifications}
        for finding in findings:
            title = finding.get("title", "")
            if title in verification_map:
                v = verification_map[title]
                # Preserve original confidence before overwriting
                if "original_confidence" not in finding:
                    finding["original_confidence"] = finding.get("confidence", 0.0)
                finding["confidence"] = v.verified_confidence
                finding["verification_status"] = v.status
                finding["verification_evidence"] = v.evidence

        tmp_path = str(rp) + ".tmp"
        try:
            with open(tmp_path, "w") as f:
                json.dump(report_data, f, indent=2, default=str)
            os.rename(tmp_path, str(rp))
            logger.info("verification_saved_to_report", path=report_path)
            return True
        except OSError as e:
            logger.error("verification_save_error", path=report_path, error=str(e))
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return False


def run_verification(
    report_file: str,
    config: Any = None,
    source_dir: Optional[str] = None,
    report_dir: str = "reports",
) -> VerificationResult:
    """Run the verification agent synchronously (CLI entry point).

    Args:
        report_file: Path to the JSON scan report.
        config: AgentConfig instance. If None, loads from default location.
        source_dir: Optional path to decompiled source directory.
        report_dir: Directory containing report files.

    Returns:
        VerificationResult with structured verification data.
    """
    from .config import load_agent_config
    from .loop import AgentLoop
    from .state import create_agent_task, update_agent_task
    from .tools import ToolContext

    if config is None:
        config = load_agent_config()

    _inject_verification_prompt(config)
    from .prompt_context import inject_scan_context
    inject_scan_context(config, "verify", report_file)

    task_id = create_agent_task(agent_type="verify", params={"report_file": report_file})

    user_message = _build_verification_message(report_file, source_dir)

    tool_context = ToolContext(report_dir=report_dir)
    if source_dir:
        tool_context.source_dir = source_dir

    from .output_parser import make_parse_check

    loop = AgentLoop(
        config=config,
        agent_type="verify",
        task_id=task_id,
        tool_context=tool_context,
    )
    result = loop.run(
        user_message,
        parse_check=make_parse_check("verification_json", {"verifications", "total_verified"}),
    )

    verification = parse_verification(
        result.response,
        task_id=task_id,
        token_usage={
            "input_tokens": result.token_usage.input_tokens,
            "output_tokens": result.token_usage.output_tokens,
        },
    )

    save_verification_to_report(verification, report_file)

    update_agent_task(
        task_id,
        status="completed" if result.success else "failed",
        result=verification.summary or result.response,
        error=result.error,
    )

    return verification


def run_verification_background(
    task_id: str,
    config: Any,
    user_message: str,
    tool_context: Any,
    report_file: Optional[str] = None,
) -> None:
    """Run verification agent in a background thread (API entry point).

    Called from the API route's _run_agent_background when agent_type == "verify".
    """
    from .loop import AgentLoop
    from .state import update_agent_task

    try:
        from .output_parser import make_parse_check as _mk_check

        _inject_verification_prompt(config)

        loop = AgentLoop(
            config=config,
            agent_type="verify",
            task_id=task_id,
            tool_context=tool_context,
        )
        result = loop.run(
            user_message,
            parse_check=_mk_check("verification_json", {"verifications", "total_verified"}),
        )

        verification = parse_verification(
            result.response,
            task_id=task_id,
            token_usage={
                "input_tokens": result.token_usage.input_tokens,
                "output_tokens": result.token_usage.output_tokens,
            },
        )

        if report_file:
            save_verification_to_report(verification, report_file)

        update_agent_task(
            task_id,
            status="completed" if result.success else "failed",
            result=json.dumps(verification.model_dump(), default=str),
            error=result.error,
        )
    except ImportError as e:
        update_agent_task(task_id, status="failed", error=f"Missing dependency: {e}")
    except Exception as e:
        logger.error("verification_background_failed", task_id=task_id, error=str(e))
        update_agent_task(task_id, status="failed", error=str(e))


def _inject_verification_prompt(config: Any) -> None:
    """Ensure the verify agent has a system prompt.

    Uses the config-provided prompt (YAML inline or file) if set,
    otherwise falls back to the code-defined default.
    """
    from .config import AgentSpecificConfig

    if "verify" not in config.agents:
        config.agents["verify"] = AgentSpecificConfig(system_prompt=VERIFICATION_SYSTEM_PROMPT)
    elif not config.agents["verify"].system_prompt:
        if not config.get_agent_system_prompt("verify"):
            config.agents["verify"].system_prompt = VERIFICATION_SYSTEM_PROMPT


def _build_verification_message(report_file: str, source_dir: Optional[str] = None) -> str:
    """Build the initial user message for verification with context hints."""
    parts = [
        "Verify the HIGH and CRITICAL findings from the scan report using dynamic analysis.",
        f"The report file is: {report_file}",
    ]
    if source_dir:
        parts.append(f"Decompiled source code is available at: {source_dir}")
    parts.append(
        "First check if Frida is available using check_frida_status. "
        "Then examine each HIGH/CRITICAL finding, generate verification "
        "scripts where possible, and produce your results in the "
        "required <verification_json> format."
    )
    return "\n".join(parts)
