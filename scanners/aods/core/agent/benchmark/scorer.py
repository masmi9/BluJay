"""
core.agent.benchmark.scorer - Score agent output against ground truth.

Computes accuracy, precision, recall, and completeness metrics for
triage, remediation, and narration agent outputs.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from .schema import (
    NarrationBenchmarkCase,
    RemediationBenchmarkCase,
    TriageBenchmarkCase,
)


def score_triage(
    triage_result: Dict[str, Any],
    benchmark: TriageBenchmarkCase,
) -> Dict[str, float]:
    """Score triage output against benchmark ground truth.

    Args:
        triage_result: Triage section from report (with classified_findings).
        benchmark: Expected triage output.

    Returns:
        Dict with metrics:
            classification_accuracy: fraction of findings matching expected class
            tp_recall: of expected TPs, how many were classified as TP
            fp_precision: of findings classified as FP, how many are actually FP
            completeness: fraction of expected findings that got any classification
            findings_scored: number of findings with expected classification
            findings_classified: number of findings the agent classified
    """
    classified = triage_result.get("classified_findings", [])
    agent_map: Dict[str, str] = {}
    for cf in classified:
        title = cf.get("finding_title", "")
        classification = cf.get("classification", "")
        if title and classification:
            agent_map[title] = classification

    # --- Classification accuracy ---
    # Compare against expected_classifications (exact match)
    expected = benchmark.expected_classifications
    correct = 0
    scored = 0
    for title, expected_class in expected.items():
        agent_class = agent_map.get(title)
        if agent_class is not None:
            scored += 1
            if agent_class == expected_class:
                correct += 1
    accuracy = correct / scored if scored > 0 else 0.0

    # --- TP recall ---
    # Of findings expected to be TP, how many did agent classify as TP?
    tp_labels = {"confirmed_tp", "likely_tp"}
    expected_tp = set(benchmark.expected_tp_titles)
    if not expected_tp and expected:
        # Derive from expected_classifications
        expected_tp = {t for t, c in expected.items() if c in tp_labels}
    agent_tp = {t for t, c in agent_map.items() if c in tp_labels}
    tp_hits = expected_tp & agent_tp
    tp_recall = len(tp_hits) / len(expected_tp) if expected_tp else 1.0

    # --- FP precision ---
    # Of findings agent classified as FP, how many are actually FP?
    expected_fp = set(benchmark.expected_fp_titles)
    if not expected_fp and expected:
        expected_fp = {t for t, c in expected.items() if c == "likely_fp"}
    agent_fp = {t for t, c in agent_map.items() if c == "likely_fp"}
    fp_correct = agent_fp & expected_fp
    fp_precision = len(fp_correct) / len(agent_fp) if agent_fp else 1.0

    # --- Completeness ---
    # What fraction of findings in the expected set got classified?
    all_expected_titles = set(expected.keys()) | expected_tp | expected_fp
    if not all_expected_titles:
        all_expected_titles = {cf.get("finding_title", "") for cf in classified}
    classified_expected = all_expected_titles & set(agent_map.keys())
    completeness = len(classified_expected) / len(all_expected_titles) if all_expected_titles else 1.0

    return {
        "classification_accuracy": round(accuracy, 4),
        "tp_recall": round(tp_recall, 4),
        "fp_precision": round(fp_precision, 4),
        "completeness": round(completeness, 4),
        "findings_scored": scored,
        "findings_classified": len(agent_map),
    }


def score_remediation(
    remediation_result: Dict[str, Any],
    benchmark: RemediationBenchmarkCase,
) -> Dict[str, float]:
    """Score remediation output against benchmark.

    Args:
        remediation_result: Remediation section from report.
        benchmark: Expected remediation output.

    Returns:
        Dict with metrics:
            cwe_coverage: fraction of expected CWEs that have patches
            patch_count: number of patches generated
            min_patches_met: 1.0 if patch_count >= expected, else ratio
    """
    remediations = remediation_result.get("remediations", [])
    patched_cwes: Set[str] = set()
    patches_with_code = 0

    for r in remediations:
        cwe = r.get("cwe_id", "")
        if cwe:
            patched_cwes.add(str(cwe))
        if r.get("fixed_code"):
            patches_with_code += 1

    # CWE coverage
    expected_cwes = set(benchmark.expected_cwe_coverage)
    covered = patched_cwes & expected_cwes
    cwe_coverage = len(covered) / len(expected_cwes) if expected_cwes else 1.0

    # Patch count
    min_patches = benchmark.expected_min_patches
    min_patches_met = 1.0
    if min_patches > 0:
        min_patches_met = min(1.0, patches_with_code / min_patches)

    return {
        "cwe_coverage": round(cwe_coverage, 4),
        "patch_count": patches_with_code,
        "min_patches_met": round(min_patches_met, 4),
    }


def score_narration(
    narration_result: Dict[str, Any],
    benchmark: NarrationBenchmarkCase,
) -> Dict[str, float]:
    """Score narration output against benchmark.

    Args:
        narration_result: Agentic analysis section from report.
        benchmark: Expected narration quality criteria.

    Returns:
        Dict with metrics:
            risk_rating_correct: 1.0 if matches expected, 0.0 otherwise
            attack_chains_met: 1.0 if count >= expected, else ratio
            priority_findings_met: 1.0 if count >= expected, else ratio
            has_executive_summary: 1.0 if non-empty, 0.0 otherwise
    """
    risk_rating = narration_result.get("risk_rating", "")
    attack_chains = narration_result.get("attack_chains", [])
    priority_findings = narration_result.get("priority_findings", [])
    executive_summary = narration_result.get("executive_summary", "")

    risk_correct = 1.0 if risk_rating.upper() == benchmark.expected_risk_rating.upper() else 0.0

    min_chains = benchmark.expected_min_attack_chains
    chains_met = 1.0
    if min_chains > 0:
        chains_met = min(1.0, len(attack_chains) / min_chains)

    min_priority = benchmark.expected_min_priority_findings
    priority_met = 1.0
    if min_priority > 0:
        priority_met = min(1.0, len(priority_findings) / min_priority)

    has_summary = 1.0 if executive_summary.strip() else 0.0

    return {
        "risk_rating_correct": risk_correct,
        "attack_chains_met": round(chains_met, 4),
        "priority_findings_met": round(priority_met, 4),
        "has_executive_summary": has_summary,
    }


def compare_runs(
    run_a: Dict[str, Any],
    run_b: Dict[str, Any],
) -> Dict[str, Dict[str, float]]:
    """Compare two benchmark run results and compute deltas.

    Args:
        run_a: First run scores (e.g., baseline).
        run_b: Second run scores (e.g., current).

    Returns:
        Dict of metric → {a: value, b: value, delta: b-a, improved: bool}
    """
    all_metrics = set(run_a.keys()) | set(run_b.keys())
    result = {}
    for metric in sorted(all_metrics):
        val_a = run_a.get(metric, 0.0)
        val_b = run_b.get(metric, 0.0)
        if not isinstance(val_a, (int, float)) or not isinstance(val_b, (int, float)):
            continue
        delta = round(val_b - val_a, 4)
        result[metric] = {
            "baseline": val_a,
            "current": val_b,
            "delta": delta,
            "improved": delta > 0,
        }
    return result
