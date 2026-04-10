"""
core.agent.heuristic_calibration - Calibrate heuristic confidence from LLM comparison.

Compares heuristic triage classifications against LLM triage for the same
findings, then adjusts heuristic confidence to reflect actual agreement rate.

Usage:
    # Run calibration on a scan report (needs LLM API key):
    python -m core.agent.heuristic_calibration --report reports/scan.json

    # Apply calibration to heuristic triage (automatic when data available):
    from core.agent.heuristic_calibration import get_calibrated_confidence
    adjusted = get_calibrated_confidence("CWE-327", 0.8)  # may return 0.72
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)

_CALIBRATION_FILE = Path("artifacts/agent_calibration/heuristic_agreement.json")
_MIN_SAMPLES = 5  # minimum samples per CWE before calibration is applied


def run_calibration(
    report_file: str,
    config: Any = None,
) -> Dict[str, Any]:
    """Run both heuristic and LLM triage on the same report, compare results.

    Args:
        report_file: Path to JSON scan report.
        config: AgentConfig (if None, loads default).

    Returns:
        Comparison dict with per-CWE agreement rates.
    """
    from .triage_heuristic import run_heuristic_triage
    from .triage import run_triage
    from .config import load_agent_config

    if config is None:
        config = load_agent_config()

    # Run heuristic
    logger.info("calibration_heuristic_start", report=report_file)
    heuristic_result = run_heuristic_triage(report_file)
    h_map = {f.finding_title: f for f in heuristic_result.classified_findings}

    # Run LLM
    logger.info("calibration_llm_start", report=report_file)
    llm_result = run_triage(report_file, config=config, force_heuristic=False, incremental=False)
    l_map = {f.finding_title: f for f in llm_result.classified_findings}

    # Compare
    comparisons: List[Dict[str, Any]] = []
    for title, h_finding in h_map.items():
        l_finding = l_map.get(title)
        if not l_finding:
            continue
        agrees = _classifications_agree(h_finding.classification, l_finding.classification)
        comparisons.append({
            "finding_title": title,
            "cwe": getattr(h_finding, "cwe_id", "") or "",
            "heuristic_classification": h_finding.classification,
            "llm_classification": l_finding.classification,
            "agrees": agrees,
            "heuristic_confidence": getattr(h_finding, "confidence", 0.5),
        })

    # Compute per-CWE agreement rates
    by_cwe: Dict[str, List[bool]] = defaultdict(list)
    for c in comparisons:
        cwe = c["cwe"] or "unknown"
        by_cwe[cwe].append(c["agrees"])

    agreement_rates = {}
    for cwe, agreements in by_cwe.items():
        rate = sum(agreements) / len(agreements) if agreements else 0.0
        agreement_rates[cwe] = {
            "samples": len(agreements),
            "agreement_rate": round(rate, 3),
            "agrees": sum(agreements),
            "disagrees": len(agreements) - sum(agreements),
        }

    global_agrees = sum(c["agrees"] for c in comparisons)
    global_total = len(comparisons)

    result = {
        "report_file": report_file,
        "total_findings": global_total,
        "global_agreement_rate": round(global_agrees / max(1, global_total), 3),
        "per_cwe": agreement_rates,
        "comparisons": comparisons,
    }

    # Persist
    _save_calibration(result)
    logger.info(
        "calibration_complete",
        total=global_total,
        agreement=result["global_agreement_rate"],
        cwes=len(agreement_rates),
    )
    return result


def _classifications_agree(heuristic: str, llm: str) -> bool:
    """Check if heuristic and LLM classifications agree at the TP/FP level."""
    tp_classes = {"confirmed_tp", "likely_tp"}
    fp_classes = {"likely_fp", "informational"}
    if heuristic in tp_classes and llm in tp_classes:
        return True
    if heuristic in fp_classes and llm in fp_classes:
        return True
    if heuristic == llm:
        return True
    return False


def _save_calibration(result: Dict[str, Any]) -> None:
    """Persist calibration data, merging with existing."""
    _CALIBRATION_FILE.parent.mkdir(parents=True, exist_ok=True)

    existing = _load_calibration_data()

    # Merge per-CWE data
    for cwe, new_data in result.get("per_cwe", {}).items():
        if cwe not in existing:
            existing[cwe] = {"total_samples": 0, "total_agrees": 0}
        existing[cwe]["total_samples"] += new_data["samples"]
        existing[cwe]["total_agrees"] += new_data["agrees"]
        total = existing[cwe]["total_samples"]
        agrees = existing[cwe]["total_agrees"]
        existing[cwe]["agreement_rate"] = round(agrees / max(1, total), 3)

    _CALIBRATION_FILE.write_text(json.dumps(existing, indent=2))


def _load_calibration_data() -> Dict[str, Any]:
    """Load persisted calibration data."""
    if _CALIBRATION_FILE.exists():
        try:
            return json.loads(_CALIBRATION_FILE.read_text())
        except Exception:
            pass
    return {}


def get_calibrated_confidence(cwe: str, base_confidence: float) -> float:
    """Adjust heuristic confidence based on calibration data.

    If calibration shows the heuristic agrees with LLM 90% of the time for
    this CWE, confidence stays high. If only 50%, confidence is reduced.

    Args:
        cwe: CWE ID (e.g., "CWE-327").
        base_confidence: Original heuristic confidence (0.0-1.0).

    Returns:
        Adjusted confidence.
    """
    data = _load_calibration_data()
    cwe_data = data.get(cwe)
    if not cwe_data or cwe_data.get("total_samples", 0) < _MIN_SAMPLES:
        return base_confidence  # Not enough data to calibrate

    agreement_rate = cwe_data.get("agreement_rate", 1.0)
    # Scale confidence by agreement rate
    # e.g., base=0.8, agreement=0.7 → 0.8 * 0.7 = 0.56... but that's too aggressive
    # Use a softer adjustment: blend base with agreement-weighted base
    adjusted = base_confidence * (0.5 + 0.5 * agreement_rate)
    return round(max(0.1, min(1.0, adjusted)), 3)


def main():
    """CLI entry point for running calibration."""
    import argparse

    parser = argparse.ArgumentParser(description="Run heuristic calibration against LLM")
    parser.add_argument("--report", required=True, help="Path to scan report JSON")
    parser.add_argument("--provider", default=None, help="Override AODS_AGENT_PROVIDER")
    args = parser.parse_args()

    if args.provider:
        os.environ["AODS_AGENT_PROVIDER"] = args.provider

    result = run_calibration(args.report)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
