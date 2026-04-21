"""
core.autoresearch.experiment_loop - Core keep/discard optimization loop.

Implements the modify-measure-keep/discard loop:
1. Backup original config
2. Calibration run → session baseline
3. Loop: generate candidate → scan → score → keep/discard
4. Restore best config at end
"""

from __future__ import annotations

import subprocess
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)

from .config import ExperimentConfig, ParameterBounds, get_params_for_tiers
from .grid_search import coordinate_descent, random_neighbor
from .history import ExperimentHistory
from .metrics import CorpusResult, SessionBaseline, ScanResult, compute_aqs
from .parameter_space import (
    REPO_ROOT,
    apply_params,
    extract_current_values,
    revert_to,
    snapshot_current,
)
from .runner import get_corpus, run_corpus
from .safety import (
    create_backup,
    install_signal_handler,
    uninstall_signal_handler,
    validate_params,
)


def _get_git_commit() -> str:
    """Get current git commit hash."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def run_experiment_loop(
    config: ExperimentConfig,
    candidate_generator: Optional[Callable] = None,
) -> Dict[str, Any]:
    """Execute the full experiment loop.

    Args:
        config: Experiment configuration.
        candidate_generator: Optional custom candidate generator for LLM mode.
            Callable that takes (current_best, bounds, history) -> Dict[str,float].

    Returns:
        Summary dict with results.
    """
    run_id = str(uuid.uuid4())[:8]
    run_dir = REPO_ROOT / "data" / "autoresearch" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    bounds = get_params_for_tiers(config.param_tiers)
    apks = get_corpus(subset=config.corpus_subset or None, fast_proxy=config.fast_proxy)

    # Step 1: Backup original config
    backup_path = create_backup()
    original_snapshot = snapshot_current()
    install_signal_handler(original_snapshot)

    history = ExperimentHistory()
    summary: Dict[str, Any] = {
        "run_id": run_id,
        "mode": config.mode,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "apks": [a.name for a in apks],
        "param_count": len(bounds),
        "experiments_run": 0,
        "experiments_accepted": 0,
        "baseline_aqs": 0.0,
        "best_aqs": 0.0,
        "best_params": {},
        "improvement": 0.0,
        "elapsed_seconds": 0.0,
        "backup_path": str(backup_path),
        "aborted": False,
    }

    start_wall = time.monotonic()
    best_aqs = 0.0
    best_params: Dict[str, float] = {}

    try:
        # Step 2: Calibration run
        logger.info("calibration_start", run_id=run_id, apk_count=len(apks))

        if config.dry_run:
            logger.info("dry_run_mode", msg="Skipping calibration scan")
            current_values = extract_current_values(bounds)
            summary["best_params"] = current_values
            summary["dry_run"] = True
            _print_dry_run(bounds, current_values, apks)
            return summary

        calibration_results = run_corpus(
            apks=apks,
            profile=config.scan_profile,
            output_dir=run_dir / "calibration",
            timeout=config.scan_timeout_seconds,
            max_workers=config.parallel_scans,
        )

        baseline = SessionBaseline(
            scan_results=calibration_results,
            git_commit=_get_git_commit(),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        baseline.save(run_dir / "baseline.json")

        baseline_corpus = compute_aqs(calibration_results, baseline)
        baseline_aqs = baseline_corpus.aqs
        summary["baseline_aqs"] = baseline_aqs

        logger.info(
            "calibration_done",
            aqs=round(baseline_aqs, 4),
            detection=round(baseline_corpus.detection_score, 4),
            fp_penalty=round(baseline_corpus.fp_penalty, 4),
            stability=round(baseline_corpus.stability_bonus, 4),
        )

        _print_calibration_summary(calibration_results, baseline_corpus)

        # Step 3: Initialize best
        best_params = extract_current_values(bounds)
        best_aqs = baseline_aqs
        best_snapshot = snapshot_current()

        # Step 4: Experiment loop
        experiment_num = 0
        max_wall = config.max_wall_time_minutes * 60

        if config.mode == "grid":
            candidates = coordinate_descent(best_params, bounds)
        else:
            candidates = None  # random/llm generate per-iteration

        while experiment_num < config.max_experiments:
            # Wall time check
            elapsed = time.monotonic() - start_wall
            if elapsed >= max_wall:
                logger.info("wall_time_exceeded", elapsed=round(elapsed))
                break

            experiment_num += 1

            # Generate candidate
            if config.mode == "grid" and candidates is not None:
                try:
                    candidate = next(candidates)
                except StopIteration:
                    logger.info("grid_search_exhausted")
                    break
            elif config.mode == "llm" and candidate_generator is not None:
                try:
                    candidate = candidate_generator(best_params, bounds, history)
                except Exception as e:
                    logger.error("llm_candidate_failed", error=str(e))
                    continue
            else:
                candidate = random_neighbor(
                    best_params, bounds, n_mutations=config.random_mutations_per_iter
                )

            # Validate
            violations = validate_params(candidate, bounds)
            if violations:
                logger.warning("candidate_invalid", violations=violations)
                continue

            # Apply
            env_overrides = apply_params(candidate, bounds)

            # Scan
            logger.info(
                "experiment_start",
                num=experiment_num,
                max=config.max_experiments,
                changed=_diff_params(best_params, candidate),
            )

            exp_results = run_corpus(
                apks=apks,
                profile=config.scan_profile,
                output_dir=run_dir / f"exp_{experiment_num:03d}",
                timeout=config.scan_timeout_seconds,
                env_overrides=env_overrides,
                max_workers=config.parallel_scans,
            )

            # Score
            corpus_result = compute_aqs(exp_results, baseline)
            exp_aqs = corpus_result.aqs

            # Safety: detection regression check
            if baseline_corpus.detection_score > 0:
                regression_pct = (
                    (baseline_corpus.detection_score - corpus_result.detection_score)
                    / baseline_corpus.detection_score
                    * 100
                )
            else:
                regression_pct = 0.0

            if regression_pct > config.max_regression_pct:
                logger.warning(
                    "detection_regression_abort",
                    regression_pct=round(regression_pct, 1),
                    threshold=config.max_regression_pct,
                )
                revert_to(best_snapshot)
                history.record(
                    run_id=run_id,
                    experiment_num=experiment_num,
                    params=candidate,
                    aqs=exp_aqs,
                    detection_score=corpus_result.detection_score,
                    fp_penalty=corpus_result.fp_penalty,
                    stability_bonus=corpus_result.stability_bonus,
                    accepted=False,
                    reason=f"detection_regression_{regression_pct:.1f}%",
                    per_apk=[r.to_dict() for r in exp_results],
                    elapsed_seconds=time.monotonic() - start_wall,
                    baseline_aqs=baseline_aqs,
                )
                summary["aborted"] = True
                break

            # Keep/discard decision
            accepted = exp_aqs > best_aqs
            reason = ""
            if accepted:
                best_aqs = exp_aqs
                best_params = dict(candidate)
                best_snapshot = snapshot_current()
                reason = f"improved_{best_aqs:.4f}"
                summary["experiments_accepted"] += 1
                logger.info(
                    "experiment_accepted",
                    num=experiment_num,
                    aqs=round(exp_aqs, 4),
                    improvement=round(exp_aqs - baseline_aqs, 4),
                )
            else:
                revert_to(best_snapshot)
                reason = f"no_improvement_{exp_aqs:.4f}_vs_{best_aqs:.4f}"
                logger.info(
                    "experiment_rejected",
                    num=experiment_num,
                    aqs=round(exp_aqs, 4),
                    best=round(best_aqs, 4),
                )

            history.record(
                run_id=run_id,
                experiment_num=experiment_num,
                params=candidate,
                aqs=exp_aqs,
                detection_score=corpus_result.detection_score,
                fp_penalty=corpus_result.fp_penalty,
                stability_bonus=corpus_result.stability_bonus,
                accepted=accepted,
                reason=reason,
                per_apk=[r.to_dict() for r in exp_results],
                elapsed_seconds=time.monotonic() - start_wall,
                baseline_aqs=baseline_aqs,
            )

            summary["experiments_run"] = experiment_num

        # Step 5: Apply best config at end
        if best_aqs > baseline_aqs:
            apply_params(best_params, bounds)
            logger.info("best_config_applied", aqs=round(best_aqs, 4))
        else:
            revert_to(original_snapshot)
            logger.info("no_improvement_found", reverting=True)

    except Exception as e:
        logger.error("experiment_loop_error", error=str(e))
        revert_to(original_snapshot)
        summary["error"] = str(e)

    finally:
        uninstall_signal_handler()
        elapsed = time.monotonic() - start_wall
        summary["elapsed_seconds"] = round(elapsed, 2)
        summary["best_aqs"] = best_aqs
        summary["best_params"] = best_params
        summary["improvement"] = round(best_aqs - summary["baseline_aqs"], 4)
        summary["completed_at"] = datetime.now(timezone.utc).isoformat()

        # Export history
        history.export_json(run_dir / "experiments.json", run_id=run_id)
        history.close()

        # Write summary
        summary_path = run_dir / "summary.json"
        import json
        summary_path.write_text(json.dumps(summary, indent=2, default=str))

        _print_final_summary(summary)

    return summary


def _diff_params(old: Dict[str, float], new: Dict[str, float]) -> Dict[str, str]:
    """Show which parameters changed and by how much."""
    diff = {}
    for k, v in new.items():
        old_v = old.get(k, 0)
        if abs(v - old_v) > 1e-6:
            diff[k] = f"{old_v:.4f}->{v:.4f}"
    return diff


def _print_calibration_summary(results: List[ScanResult], corpus: CorpusResult) -> None:
    """Print calibration results to stdout."""
    print("\n--- Calibration Results ---")
    print(f"AQS: {corpus.aqs:.4f} (detection={corpus.detection_score:.4f}, "
          f"fp_penalty={corpus.fp_penalty:.4f}, stability={corpus.stability_bonus:.4f})")
    print(f"{'APK':<25} {'Type':<12} {'Findings':>8} {'Time':>8}")
    print("-" * 55)
    for r in results:
        status = "OK" if r.success else "FAIL"
        print(f"{r.apk_name:<25} {r.apk_type:<12} {r.total_findings:>8} {r.scan_time_seconds:>7.1f}s [{status}]")
    print()


def _print_dry_run(bounds: List[ParameterBounds], values: Dict[str, float], apks: list) -> None:
    """Print dry run information."""
    print("\n--- Dry Run: Parameter Space ---")
    print(f"{'Parameter':<30} {'Current':>8} {'Min':>8} {'Max':>8} {'Step':>6} {'Tier':>4}")
    print("-" * 68)
    for b in bounds:
        val = values.get(b.name, b.default_value)
        print(f"{b.name:<30} {val:>8.4f} {b.min_value:>8.4f} {b.max_value:>8.4f} {b.step:>6.3f} {b.tier:>4}")
    print(f"\nAPKs: {', '.join(a.name for a in apks)}")
    print()


def _print_final_summary(summary: Dict[str, Any]) -> None:
    """Print final experiment summary."""
    print("\n=== AutoResearch Summary ===")
    print(f"Run ID:       {summary['run_id']}")
    print(f"Mode:         {summary['mode']}")
    print(f"Experiments:  {summary['experiments_run']} run, {summary['experiments_accepted']} accepted")
    print(f"Baseline AQS: {summary['baseline_aqs']:.4f}")
    print(f"Best AQS:     {summary['best_aqs']:.4f}")
    print(f"Improvement:  {summary['improvement']:+.4f}")
    print(f"Elapsed:      {summary['elapsed_seconds']:.0f}s")

    if summary.get("aborted"):
        print("STATUS:       ABORTED (detection regression)")
    elif summary.get("error"):
        print(f"STATUS:       ERROR ({summary['error']})")
    elif summary["improvement"] > 0:
        print("STATUS:       IMPROVED")
    else:
        print("STATUS:       NO IMPROVEMENT")

    if summary.get("best_params"):
        print("\nBest parameters:")
        for k, v in sorted(summary["best_params"].items()):
            print(f"  {k}: {v}")
    print()
