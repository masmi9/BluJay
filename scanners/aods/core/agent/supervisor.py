"""
core.agent.supervisor - Pipeline runner for orchestrating agents (Track 96).

Runs multiple agents in sequence (triage -> verify -> remediate -> narrate),
enforcing total token budget and wall-clock time limits.  Supports parallel
execution of independent steps (e.g., triage + verification concurrently)
and cost threshold alerting.

Public API:
    PipelineResult - Pydantic model for pipeline execution results
    run_pipeline() - Synchronous entry point for CLI use
    run_pipeline_background() - Background thread entry for API use
"""

from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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


class PipelineStepConfig(BaseModel):
    """Configuration for a single pipeline step."""

    model_config = ConfigDict(extra="forbid")

    agent_type: str = Field(..., description="Agent type: triage, verify, remediate, narrate")
    enabled: bool = Field(True, description="Whether this step is enabled")
    budget_override: Optional[int] = Field(None, description="Per-step token budget override")
    skip_if: Optional[str] = Field(
        None,
        description=(
            "Condition to skip this step. Supported: "
            "no_high_or_critical, all_informational, no_findings, "
            "triage_all_fp, verification_unavailable"
        ),
    )


class PipelineConfig(BaseModel):
    """Configuration for the full pipeline."""

    model_config = ConfigDict(extra="forbid")

    steps: List[PipelineStepConfig] = Field(default_factory=list)
    total_token_budget: int = Field(200000, description="Total token budget across all steps")
    total_wall_time_seconds: int = Field(900, description="Max wall-clock time in seconds")
    stop_on_failure: bool = Field(False, description="Stop pipeline on first step failure")
    parallel_groups: List[List[str]] = Field(
        default_factory=lambda: [["remediate", "narrate"]],
        description="Groups of agent types that can run concurrently",
    )
    cost_alert_threshold_tokens: int = Field(
        150000,
        description="Emit cost alert when total tokens exceed this threshold",
    )


StepStatus = Literal["completed", "failed", "skipped", "budget_exceeded", "timeout"]


class PipelineStepResult(BaseModel):
    """Result of a single pipeline step."""

    model_config = ConfigDict(extra="forbid")

    agent_type: str
    status: StepStatus
    task_id: str = ""
    token_usage: Dict[str, int] = Field(default_factory=dict)
    elapsed_seconds: float = 0.0
    error: Optional[str] = None
    skip_reason: Optional[str] = Field(None, description="Reason step was skipped (from skip_if condition)")
    method: str = Field("llm", description="Execution method: llm, heuristic, heuristic_fallback")


class PipelineResult(BaseModel):
    """Result of a full pipeline execution."""

    model_config = ConfigDict(extra="forbid")

    steps: List[PipelineStepResult] = Field(default_factory=list)
    total_token_usage: Dict[str, int] = Field(default_factory=dict)
    total_elapsed_seconds: float = 0.0
    status: str = "completed"
    summary: str = ""
    cost_alert_emitted: bool = Field(False, description="Whether cost threshold alert was triggered")


# ---------------------------------------------------------------------------
# Default pipeline
# ---------------------------------------------------------------------------

DEFAULT_PIPELINE = [
    PipelineStepConfig(agent_type="triage"),
    PipelineStepConfig(agent_type="verify", skip_if="no_high_or_critical"),
    PipelineStepConfig(agent_type="remediate", skip_if="triage_all_fp"),
    PipelineStepConfig(agent_type="narrate"),
]


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def _evaluate_skip_condition(condition: str, report_file: str) -> bool:
    """Evaluate whether a pipeline step should be skipped.

    Args:
        condition: Condition name to evaluate.
        report_file: Path to the JSON scan report.

    Returns:
        True if the step should be SKIPPED.
    """
    try:
        from pathlib import Path

        rp = Path(report_file)
        if not rp.exists():
            return False

        with open(rp, "r") as f:
            report = json.load(f)

        if condition == "no_high_or_critical":
            # Skip if triage found no confirmed HIGH/CRITICAL findings
            triage = report.get("triage", {})
            classified = triage.get("classified_findings", [])
            if not classified:
                # No triage data yet - don't skip
                return False
            confirmed_high = [
                f for f in classified
                if f.get("classification") in ("confirmed_tp", "likely_tp")
                and str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")
            ]
            return len(confirmed_high) == 0

        if condition == "all_informational":
            findings = report.get("findings", report.get("vulnerabilities", []))
            if not findings:
                return True
            return all(
                str(f.get("severity", "")).upper() == "INFO"
                for f in findings
            )

        if condition == "no_findings":
            findings = report.get("findings", report.get("vulnerabilities", []))
            return not findings

        if condition == "triage_all_fp":
            triage = report.get("triage", {})
            classified = triage.get("classified_findings", [])
            if not classified:
                return False
            return all(
                f.get("classification") == "likely_fp"
                for f in classified
            )

        if condition == "verification_unavailable":
            try:
                import frida  # noqa: F401
                devices = frida.enumerate_devices()
                usable = [d for d in devices if d.type in ("usb", "remote", "local")]
                return len(usable) == 0
            except Exception:
                return True

        # Unknown condition - don't skip
        return False
    except Exception as exc:
        logger.debug("skip_condition_eval_failed", condition=condition, error=str(exc))
        return False


def _try_heuristic_fallback(
    agent_type: str,
    report_file: str,
    report_dir: str = "reports",
) -> Optional[PipelineStepResult]:
    """Attempt to run the heuristic fallback for a failed agent step.

    Returns a PipelineStepResult on success, None if fallback is unavailable
    or also fails.
    """
    start_time = time.monotonic()
    try:
        if agent_type == "triage":
            from .triage_heuristic import run_heuristic_triage
            result = run_heuristic_triage(report_file, report_dir=report_dir)
            # Save to report
            from .triage import save_triage_to_report
            save_triage_to_report(result, report_file)

        elif agent_type == "narrate":
            from .narration_heuristic import run_heuristic_narration
            result = run_heuristic_narration(report_file, report_dir=report_dir)
            from .narration import save_narrative_to_report
            save_narrative_to_report(result, report_file)

        elif agent_type == "remediate":
            from .remediation_heuristic import run_heuristic_remediation
            result = run_heuristic_remediation(report_file, report_dir=report_dir)
            from .remediation import save_remediation_to_report
            save_remediation_to_report(result, report_file)

        elif agent_type == "orchestrate":
            # Orchestration heuristic needs apk_path, not report_file
            # Can't reliably extract apk_path from report in all cases
            return None

        elif agent_type == "verify":
            # Verification has no heuristic - it already falls back to static
            # analysis within the LLM loop when Frida is unavailable
            return None

        else:
            return None

        elapsed = round(time.monotonic() - start_time, 2)
        logger.info(
            "pipeline_heuristic_fallback_success",
            agent_type=agent_type,
            elapsed=elapsed,
        )
        return PipelineStepResult(
            agent_type=agent_type,
            status="completed",
            token_usage=getattr(result, "token_usage", {}),
            task_id=getattr(result, "task_id", ""),
            elapsed_seconds=elapsed,
            method="heuristic_fallback",
        )
    except Exception as exc:
        logger.warning(
            "pipeline_heuristic_fallback_failed",
            agent_type=agent_type,
            error=str(exc),
        )
        return None


def _run_step(
    agent_type: str,
    report_file: str,
    config: Any,
    source_dir: Optional[str] = None,
    report_dir: str = "reports",
) -> PipelineStepResult:
    """Execute a single pipeline step with error handling and timing."""
    start_time = time.monotonic()
    step_result = PipelineStepResult(agent_type=agent_type, status="failed")

    try:
        if agent_type == "triage":
            from .triage import run_triage

            result = run_triage(
                report_file=report_file,
                config=config,
                source_dir=source_dir,
                report_dir=report_dir,
            )
            step_result.token_usage = result.token_usage
            step_result.task_id = result.task_id
            step_result.status = "completed"

            # Write pipeline context for downstream agents
            _write_pipeline_context(report_file, result)

        elif agent_type == "verify":
            from .verification import run_verification

            result = run_verification(
                report_file=report_file,
                config=config,
                source_dir=source_dir,
                report_dir=report_dir,
            )
            step_result.token_usage = result.token_usage
            step_result.task_id = result.task_id
            step_result.status = "completed"

        elif agent_type == "remediate":
            from .remediation import run_remediation

            result = run_remediation(
                report_file=report_file,
                config=config,
                source_dir=source_dir,
                report_dir=report_dir,
            )
            step_result.token_usage = result.token_usage
            step_result.task_id = result.task_id
            step_result.status = "completed"

        elif agent_type == "narrate":
            from .narration import run_narration

            result = run_narration(
                report_file=report_file,
                config=config,
                source_dir=source_dir,
                report_dir=report_dir,
            )
            step_result.token_usage = result.token_usage
            step_result.task_id = result.task_id
            step_result.status = "completed"

        else:
            step_result.status = "failed"
            step_result.error = f"Unknown agent type: {agent_type}"

    except ImportError as e:
        step_result.status = "failed"
        step_result.error = f"Missing dependency: {e}"
        logger.warning("pipeline_step_import_error", agent_type=agent_type, error=str(e))
    except Exception as e:
        step_result.status = "failed"
        step_result.error = str(e)
        logger.error("pipeline_step_failed", agent_type=agent_type, error=str(e))

    # Automatic heuristic fallback on failure
    if step_result.status == "failed":
        original_error = step_result.error or "unknown"
        fallback = _try_heuristic_fallback(agent_type, report_file, report_dir)
        if fallback is not None:
            logger.warning(
                "pipeline_step_used_heuristic_fallback",
                agent_type=agent_type,
                original_error=original_error,
                elapsed=fallback.elapsed_seconds,
            )
            # Audit event for compliance trail
            try:
                from core.api.auth_helpers import _audit
                _audit(
                    "agent_heuristic_fallback",
                    "system",
                    agent_type,
                    {
                        "original_error": original_error[:200],
                        "agent_type": agent_type,
                        "report_file": report_file,
                    },
                )
            except Exception:
                pass
            return fallback

    step_result.elapsed_seconds = round(time.monotonic() - start_time, 2)
    return step_result


def _write_pipeline_context(report_file: str, triage_result: Any) -> None:
    """Write pipeline context from triage results into the report.

    Extracts confirmed TP finding titles so downstream agents (remediation,
    narration) can prioritize them. Best-effort - never raises.
    Acquires report_write_lock to prevent concurrent write races.
    """
    try:
        from pathlib import Path
        from .report_lock import report_write_lock

        rp = Path(report_file)
        if not rp.exists():
            return

        confirmed_titles = []
        likely_fp_titles = []
        for cf in getattr(triage_result, "classified_findings", []):
            classification = getattr(cf, "classification", "")
            title = getattr(cf, "finding_title", "")
            if classification in ("confirmed_tp", "likely_tp"):
                confirmed_titles.append(title)
            elif classification == "likely_fp":
                likely_fp_titles.append(title)

        with report_write_lock:
            with open(rp, "r") as f:
                report_data = json.load(f)

            report_data["_pipeline_context"] = {
                "confirmed_tp_titles": confirmed_titles,
                "likely_fp_titles": likely_fp_titles,
                "triage_summary": getattr(triage_result, "summary", ""),
            }

            tmp_path = str(rp) + ".tmp"
            with open(tmp_path, "w") as f:
                json.dump(report_data, f, indent=2, default=str)
            os.rename(tmp_path, str(rp))

        logger.debug("pipeline_context_written", confirmed_count=len(confirmed_titles))
    except Exception as exc:
        logger.debug("pipeline_context_write_failed", error=str(exc))


def _get_total_tokens(usage: Dict[str, int]) -> int:
    """Sum input and output tokens from a token_usage dict."""
    return usage.get("input_tokens", 0) + usage.get("output_tokens", 0)


def _check_cost_alert(
    total_input: int,
    total_output: int,
    threshold: int,
    result: PipelineResult,
) -> None:
    """Emit a cost alert if total token usage exceeds the configured threshold."""
    total = total_input + total_output
    if total >= threshold and not result.cost_alert_emitted:
        result.cost_alert_emitted = True
        logger.warning(
            "pipeline_cost_alert",
            total_tokens=total,
            threshold=threshold,
            input_tokens=total_input,
            output_tokens=total_output,
        )
        # Emit audit event if audit system is available
        try:
            from core.api.routes.scans import _audit
            _audit(
                "agent_cost_alert",
                "system",
                "",
                {
                    "total_tokens": total,
                    "threshold": threshold,
                    "input_tokens": total_input,
                    "output_tokens": total_output,
                },
            )
        except Exception:
            pass  # Audit is best-effort


def _run_parallel_group(
    group_steps: List[PipelineStepConfig],
    report_file: str,
    config: Any,
    source_dir: Optional[str],
    report_dir: str,
) -> List[PipelineStepResult]:
    """Run a group of pipeline steps in parallel using ThreadPoolExecutor."""
    results: List[PipelineStepResult] = []

    with ThreadPoolExecutor(max_workers=len(group_steps)) as executor:
        future_to_step = {}
        for step_config in group_steps:
            future = executor.submit(
                _run_step,
                agent_type=step_config.agent_type,
                report_file=report_file,
                config=config,
                source_dir=source_dir,
                report_dir=report_dir,
            )
            future_to_step[future] = step_config

        for future in as_completed(future_to_step):
            step_config = future_to_step[future]
            try:
                step_result = future.result()
            except Exception as e:
                import traceback

                logger.error(
                    "pipeline_parallel_step_exception",
                    agent_type=step_config.agent_type,
                    error=str(e),
                    tb=traceback.format_exc(),
                )
                step_result = PipelineStepResult(
                    agent_type=step_config.agent_type,
                    status="failed",
                    error=str(e),
                )
            results.append(step_result)

    return results


def _emit_observation(
    task_id: Optional[str],
    obs_type: str,
    data: Dict[str, Any],
    progress_callback: Optional[Any] = None,
) -> None:
    """Emit a pipeline observation via SSE (API) and/or progress callback (CLI)."""
    if task_id:
        try:
            from .state import append_observation
            append_observation(task_id, {
                "type": obs_type,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                **data,
            })
        except Exception as exc:
            logger.debug("pipeline_observation_emit_failed", error=str(exc))
    if progress_callback:
        try:
            progress_callback(obs_type, data)
        except Exception:
            pass


def _reconcile_results(report_file: str) -> None:
    """Reconcile verification and triage results after all pipeline steps.

    When verification confirms or denies a finding, update the triage
    classification to be consistent. Best-effort - never raises.
    """
    try:
        from pathlib import Path
        from .report_lock import report_write_lock

        rp = Path(report_file)
        if not rp.exists():
            return

        with report_write_lock:
            with open(rp, "r") as f:
                report_data = json.load(f)

            triage_section = report_data.get("triage")
            verification_section = report_data.get("verification")

            if not triage_section or not verification_section:
                return

            classified_findings = triage_section.get("classified_findings", [])
            verifications = verification_section.get("verifications", [])

            if not classified_findings or not verifications:
                return

            # Build lookup: finding_title -> verification status
            verification_map: Dict[str, str] = {}
            for v in verifications:
                title = v.get("finding_title", "")
                status = v.get("status", "")
                if title and status:
                    verification_map[title] = status

            if not verification_map:
                return

            changed = False
            for cf in classified_findings:
                title = cf.get("finding_title", "")
                classification = cf.get("classification", "")
                v_status = verification_map.get(title)

                if not v_status:
                    continue

                # Verification says likely_fp but triage says confirmed/likely TP
                # -> downgrade triage to needs_review
                if v_status == "likely_fp" and classification in ("confirmed_tp", "likely_tp"):
                    cf["classification"] = "needs_review"
                    changed = True

                # Verification confirms but triage says needs_review or likely_fp
                # -> upgrade triage to confirmed_tp
                elif v_status == "confirmed" and classification in ("needs_review", "likely_fp"):
                    cf["classification"] = "confirmed_tp"
                    changed = True

                # Verification says "likely" and triage says likely_fp
                # -> upgrade to needs_review (conflicting signals)
                elif v_status == "likely" and classification == "likely_fp":
                    cf["classification"] = "needs_review"
                    changed = True

                # Verification uncertain ("likely") but triage says confirmed/likely TP
                # -> downgrade to needs_review (verification couldn't confirm)
                elif v_status == "likely" and classification in ("confirmed_tp", "likely_tp"):
                    cf["classification"] = "needs_review"
                    changed = True

                # Verification says confirmed, triage says informational
                # -> upgrade to confirmed_tp
                elif v_status == "confirmed" and classification == "informational":
                    cf["classification"] = "confirmed_tp"
                    changed = True

                # Verification says likely_fp, triage says needs_review
                # -> downgrade to likely_fp
                elif v_status == "likely_fp" and classification == "needs_review":
                    cf["classification"] = "likely_fp"
                    changed = True

            if not changed:
                return

            triage_section["classified_findings"] = classified_findings
            report_data["triage"] = triage_section

            tmp_path = str(rp) + ".tmp"
            with open(tmp_path, "w") as f:
                json.dump(report_data, f, indent=2, default=str)
            os.rename(tmp_path, str(rp))

        logger.debug("reconcile_results_complete", report=report_file)
    except Exception as exc:
        logger.debug("reconcile_results_failed", error=str(exc))


def _compute_adaptive_budgets(
    pipeline_steps: List[PipelineStepConfig],
    total_token_budget: int,
    report_file: str,
) -> Dict[str, int]:
    """Compute per-step token budgets based on scan characteristics.

    Adjusts weights dynamically:
    - Large scans (50+ findings) -> triage gets more budget
    - Many HIGH/CRITICAL findings -> verify + remediate get more
    - Few findings -> narrate gets proportionally more (synthesis is the value)
    """
    weights: Dict[str, float] = {
        "triage": 0.30,
        "verify": 0.10,
        "remediate": 0.30,
        "narrate": 0.25,
        "orchestrate": 0.05,
    }

    try:
        from pathlib import Path

        rp = Path(report_file)
        if rp.exists():
            with open(rp, "r") as f:
                report = json.load(f)
            findings = report.get("findings", report.get("vulnerabilities", []))
            finding_count = len(findings) if isinstance(findings, list) else 0

            high_critical = sum(
                1
                for f in (findings or [])
                if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")
            )

            if finding_count > 50:
                # Large scan: triage needs more context window
                weights["triage"] = 0.40
                weights["remediate"] = 0.25
                weights["narrate"] = 0.20
            elif finding_count < 10:
                # Small scan: narrate is the main value
                weights["triage"] = 0.20
                weights["narrate"] = 0.35
                weights["remediate"] = 0.25

            if high_critical > 5:
                # Many critical: verify and remediate need more budget
                weights["verify"] = 0.15
                weights["remediate"] = 0.35
                weights["triage"] = max(0.20, weights["triage"] - 0.05)
                weights["narrate"] = max(0.15, weights["narrate"] - 0.05)
            elif high_critical == 0:
                # No critical: shift budget from verify to narrate
                weights["verify"] = 0.05
                weights["narrate"] = weights["narrate"] + 0.05
    except Exception:
        pass  # Use default weights on error

    enabled_steps = [s.agent_type for s in pipeline_steps if s.enabled]
    if not enabled_steps:
        return {}

    active_weights = {s: weights.get(s, 0.20) for s in enabled_steps}
    total_weight = sum(active_weights.values()) or 1.0
    return {s: int(total_token_budget * w / total_weight) for s, w in active_weights.items()}


def run_pipeline(
    report_file: str,
    config: Any = None,
    source_dir: Optional[str] = None,
    report_dir: str = "reports",
    steps: Optional[List[PipelineStepConfig]] = None,
    total_token_budget: int = 200000,
    stop_on_failure: bool = False,
    parallel_groups: Optional[List[List[str]]] = None,
    cost_alert_threshold: Optional[int] = None,
    task_id: Optional[str] = None,
    progress_callback: Optional[Any] = None,
) -> PipelineResult:
    """Run the agent pipeline synchronously (CLI entry point).

    Iterates enabled steps, enforces total token budget, and dispatches
    to the appropriate agent runner for each step.  Steps belonging to a
    ``parallel_groups`` entry run concurrently via ThreadPoolExecutor.

    Args:
        report_file: Path to the JSON scan report.
        config: AgentConfig instance. If None, loads from default location.
        source_dir: Optional path to decompiled source directory.
        report_dir: Directory containing report files.
        steps: Pipeline steps to run. Defaults to DEFAULT_PIPELINE.
        total_token_budget: Total token budget across all steps.
        stop_on_failure: Stop pipeline on first step failure.
        parallel_groups: Groups of agent_types that can run concurrently.
            Default: [["remediate", "narrate"]].
        cost_alert_threshold: Token count threshold for cost alerting.
            Default: 150000 (or AODS_AGENT_COST_ALERT env var).

    Returns:
        PipelineResult with step results and aggregate statistics.
    """
    from .config import load_agent_config

    if config is None:
        config = load_agent_config()

    pipeline_steps = steps or DEFAULT_PIPELINE
    pipeline_start = time.monotonic()

    if parallel_groups is None:
        parallel_groups = [["remediate", "narrate"]]

    if cost_alert_threshold is None:
        cost_alert_threshold = int(os.environ.get("AODS_AGENT_COST_ALERT", "150000"))

    # Build a set of agent types that should run in parallel groups
    parallel_map: Dict[str, int] = {}  # agent_type -> group index
    for gi, group in enumerate(parallel_groups):
        for agent_type in group:
            parallel_map[agent_type] = gi

    # Adaptive budget allocation - adjust weights based on scan characteristics
    step_budgets = _compute_adaptive_budgets(pipeline_steps, total_token_budget, report_file)

    result = PipelineResult()
    total_input = 0
    total_output = 0
    stop_early = False

    # Wall-clock time limit from PipelineConfig defaults
    wall_time_limit = int(os.environ.get("AODS_AGENT_PIPELINE_WALL_TIME", "900"))

    # Process steps, batching parallel groups together
    i = 0
    while i < len(pipeline_steps):
        # Wall-clock timeout check
        elapsed = time.monotonic() - pipeline_start
        if elapsed >= wall_time_limit:
            for remaining in pipeline_steps[i:]:
                if remaining.enabled:
                    result.steps.append(PipelineStepResult(
                        agent_type=remaining.agent_type,
                        status="timeout",
                        error=f"Pipeline wall-clock timeout ({elapsed:.0f}s >= {wall_time_limit}s)",
                    ))
            result.status = "timeout"
            break

        if stop_early:
            for remaining in pipeline_steps[i:]:
                if remaining.enabled:
                    result.steps.append(PipelineStepResult(
                        agent_type=remaining.agent_type,
                        status="skipped",
                        error="Skipped due to previous step failure",
                    ))
            break

        step_config = pipeline_steps[i]

        if not step_config.enabled:
            result.steps.append(PipelineStepResult(
                agent_type=step_config.agent_type,
                status="skipped",
            ))
            i += 1
            continue

        # Evaluate skip_if condition
        if step_config.skip_if:
            if _evaluate_skip_condition(step_config.skip_if, report_file):
                logger.info(
                    "pipeline_step_skipped_by_condition",
                    agent_type=step_config.agent_type,
                    condition=step_config.skip_if,
                )
                _emit_observation(task_id, "pipeline_step_skipped", {
                    "agent_type": step_config.agent_type,
                    "condition": step_config.skip_if,
                    "content": f"Skipped {step_config.agent_type}: {step_config.skip_if}",
                }, progress_callback=progress_callback)
                result.steps.append(PipelineStepResult(
                    agent_type=step_config.agent_type,
                    status="skipped",
                    skip_reason=step_config.skip_if,
                ))
                i += 1
                continue

        # Check token budget
        if total_input + total_output >= total_token_budget:
            result.steps.append(PipelineStepResult(
                agent_type=step_config.agent_type,
                status="budget_exceeded",
                error=f"Token budget exhausted ({total_input + total_output}/{total_token_budget})",
            ))
            i += 1
            continue

        # Check if this step and subsequent steps form a parallel group
        group_idx = parallel_map.get(step_config.agent_type)
        parallel_batch: List[PipelineStepConfig] = []
        if group_idx is not None:
            # Collect consecutive steps in the same parallel group
            for j in range(i, len(pipeline_steps)):
                candidate = pipeline_steps[j]
                if parallel_map.get(candidate.agent_type) == group_idx and candidate.enabled:
                    parallel_batch.append(candidate)
                elif not candidate.enabled:
                    continue  # skip disabled, keep scanning
                else:
                    break

        if len(parallel_batch) >= 2:
            # Run group in parallel
            logger.info(
                "pipeline_parallel_group_start",
                agents=[s.agent_type for s in parallel_batch],
            )
            for ps in parallel_batch:
                _emit_observation(task_id, "pipeline_step_start", {
                    "agent_type": ps.agent_type, "content": f"Starting {ps.agent_type} (parallel)",
                }, progress_callback=progress_callback)
            group_results = _run_parallel_group(
                group_steps=parallel_batch,
                report_file=report_file,
                config=config,
                source_dir=source_dir,
                report_dir=report_dir,
            )
            for sr in group_results:
                result.steps.append(sr)
                total_input += sr.token_usage.get("input_tokens", 0)
                total_output += sr.token_usage.get("output_tokens", 0)
                logger.info(
                    "pipeline_step_complete",
                    agent_type=sr.agent_type,
                    status=sr.status,
                    elapsed=sr.elapsed_seconds,
                    tokens=_get_total_tokens(sr.token_usage),
                    parallel=True,
                )
                _emit_observation(task_id, "pipeline_step_complete", {
                    "agent_type": sr.agent_type,
                    "step_status": sr.status,
                    "elapsed_seconds": sr.elapsed_seconds,
                    "token_usage": sr.token_usage,
                    "method": sr.method,
                    "content": f"{sr.agent_type} {sr.status} in {sr.elapsed_seconds}s",
                }, progress_callback=progress_callback)
                if sr.method == "heuristic_fallback":
                    _emit_observation(task_id, "heuristic_fallback", {
                        "agent_type": sr.agent_type,
                        "content": (
                            f"WARNING: {sr.agent_type} used heuristic fallback - "
                            f"LLM was unavailable. Results may be less detailed."
                        ),
                    }, progress_callback=progress_callback)
                if stop_on_failure and sr.status == "failed":
                    stop_early = True

            # Cost alerting after parallel group
            _check_cost_alert(total_input, total_output, cost_alert_threshold, result)

            # Advance past all steps in the parallel batch
            batch_types = {s.agent_type for s in parallel_batch}
            while i < len(pipeline_steps) and pipeline_steps[i].agent_type in batch_types:
                i += 1
        else:
            # Run single step sequentially
            logger.info("pipeline_step_start", agent_type=step_config.agent_type)
            _emit_observation(task_id, "pipeline_step_start", {
                "agent_type": step_config.agent_type,
                "content": f"Starting {step_config.agent_type}",
            }, progress_callback=progress_callback)

            step_result = _run_step(
                agent_type=step_config.agent_type,
                report_file=report_file,
                config=config,
                source_dir=source_dir,
                report_dir=report_dir,
            )
            result.steps.append(step_result)

            step_tokens = step_result.token_usage.get("input_tokens", 0) + step_result.token_usage.get("output_tokens", 0)
            total_input += step_result.token_usage.get("input_tokens", 0)
            total_output += step_result.token_usage.get("output_tokens", 0)

            # Redistribute underspend to remaining steps
            allocated = step_budgets.get(step_config.agent_type, 0)
            if allocated > 0 and step_tokens < allocated:
                underspend = allocated - step_tokens
                remaining = [s.agent_type for s in pipeline_steps[i + 1:] if s.enabled and s.agent_type in step_budgets]
                if remaining and underspend > 0:
                    bonus = underspend // len(remaining)
                    for r in remaining:
                        step_budgets[r] = step_budgets.get(r, 0) + bonus

            logger.info(
                "pipeline_step_complete",
                agent_type=step_config.agent_type,
                status=step_result.status,
                elapsed=step_result.elapsed_seconds,
                tokens=step_tokens,
            )
            _emit_observation(task_id, "pipeline_step_complete", {
                "agent_type": step_config.agent_type,
                "step_status": step_result.status,
                "elapsed_seconds": step_result.elapsed_seconds,
                "token_usage": step_result.token_usage,
                "method": step_result.method,
                "content": f"{step_config.agent_type} {step_result.status} in {step_result.elapsed_seconds}s",
            }, progress_callback=progress_callback)
            if step_result.method == "heuristic_fallback":
                _emit_observation(task_id, "heuristic_fallback", {
                    "agent_type": step_config.agent_type,
                    "content": (
                        f"WARNING: {step_config.agent_type} used heuristic fallback - "
                        f"LLM was unavailable. Results may be less detailed."
                    ),
                }, progress_callback=progress_callback)

            # Cost alerting after each step
            _check_cost_alert(total_input, total_output, cost_alert_threshold, result)

            if stop_on_failure and step_result.status == "failed":
                stop_early = True

            i += 1

    # Reconcile verification results with triage classifications
    _reconcile_results(report_file)

    result.total_elapsed_seconds = round(time.monotonic() - pipeline_start, 2)
    result.total_token_usage = {
        "input_tokens": total_input,
        "output_tokens": total_output,
    }

    # Determine overall status
    statuses = [s.status for s in result.steps]
    if all(s in ("completed", "skipped") for s in statuses):
        result.status = "completed"
    elif any(s == "failed" for s in statuses):
        result.status = "partial"
    elif all(s == "budget_exceeded" for s in statuses):
        result.status = "budget_exceeded"
    else:
        result.status = "partial"

    # Build summary
    step_summaries = []
    fallback_agents = []
    for s in result.steps:
        label = f"{s.agent_type}: {s.status}"
        if s.method == "heuristic_fallback":
            label += " (heuristic fallback)"
            fallback_agents.append(s.agent_type)
        step_summaries.append(label)
    result.summary = (
        f"Pipeline {result.status} in {result.total_elapsed_seconds}s - "
        + ", ".join(step_summaries)
    )
    if fallback_agents:
        result.summary += (
            f" | WARNING: {', '.join(fallback_agents)} used heuristic fallback "
            f"(LLM unavailable) - results may be less detailed"
        )

    logger.info(
        "pipeline_complete",
        status=result.status,
        elapsed=result.total_elapsed_seconds,
        total_tokens=total_input + total_output,
        steps=len(result.steps),
    )
    return result


def run_pipeline_background(
    task_id: str,
    config: Any,
    report_file: Optional[str] = None,
    steps: Optional[List[PipelineStepConfig]] = None,
    total_token_budget: int = 200000,
    stop_on_failure: bool = False,
) -> None:
    """Run agent pipeline in a background thread (API entry point).

    Called from the API route's _run_agent_background when agent_type == "pipeline".
    """
    from .state import update_agent_task

    try:
        if not report_file:
            update_agent_task(task_id, status="failed", error="report_file is required for pipeline")
            return

        result = run_pipeline(
            report_file=report_file,
            config=config,
            steps=steps,
            total_token_budget=total_token_budget,
            stop_on_failure=stop_on_failure,
            task_id=task_id,
        )

        update_agent_task(
            task_id,
            status="completed" if result.status == "completed" else "failed",
            result=json.dumps(result.model_dump(), default=str),
            error=None if result.status == "completed" else result.summary,
        )
    except ImportError as e:
        update_agent_task(task_id, status="failed", error=f"Missing dependency: {e}")
    except Exception as e:
        logger.error("pipeline_background_failed", task_id=task_id, error=str(e))
        update_agent_task(task_id, status="failed", error=str(e))
