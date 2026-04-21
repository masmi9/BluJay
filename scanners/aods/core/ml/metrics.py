#!/usr/bin/env python3
"""Simple calibration metrics: ECE and MCE (expected/max calibration error)."""

from __future__ import annotations

from typing import List, Dict, Any
from dataclasses import dataclass


def _bin_index(p: float, num_bins: int) -> int:
    if p <= 0.0:
        return 0
    if p >= 1.0:
        return num_bins - 1
    return min(num_bins - 1, int(p * num_bins))


def expected_calibration_error(probabilities: List[float], labels: List[int], num_bins: int = 15) -> float:
    assert len(probabilities) == len(labels)
    n = len(probabilities)
    if n == 0:
        return 0.0
    bin_sums = [0.0] * num_bins
    bin_counts = [0] * num_bins
    bin_correct = [0] * num_bins
    for p, y in zip(probabilities, labels):
        b = _bin_index(float(p), num_bins)
        bin_sums[b] += float(p)
        bin_counts[b] += 1
        bin_correct[b] += 1 if int(y) == 1 else 0
    ece = 0.0
    for b in range(num_bins):
        if bin_counts[b] == 0:
            continue
        conf = bin_sums[b] / float(bin_counts[b])
        acc = float(bin_correct[b]) / float(bin_counts[b])
        ece += (bin_counts[b] / float(n)) * abs(conf - acc)
    return float(ece)


def max_calibration_error(probabilities: List[float], labels: List[int], num_bins: int = 15) -> float:
    assert len(probabilities) == len(labels)
    bin_sums = [0.0] * num_bins
    bin_counts = [0] * num_bins
    bin_correct = [0] * num_bins
    for p, y in zip(probabilities, labels):
        b = _bin_index(float(p), num_bins)
        bin_sums[b] += float(p)
        bin_counts[b] += 1
        bin_correct[b] += 1 if int(y) == 1 else 0
    mce = 0.0
    for b in range(num_bins):
        if bin_counts[b] == 0:
            continue
        conf = bin_sums[b] / float(bin_counts[b])
        acc = float(bin_correct[b]) / float(bin_counts[b])
        mce = max(mce, abs(conf - acc))
    return float(mce)


@dataclass
class CalibrationMetrics:
    ece: float
    mce: float
    bin_details: List[Dict[str, Any]]


def compute_ece_mce(probabilities: List[float], labels: List[int], num_bins: int = 15) -> CalibrationMetrics:
    """
    Convenience wrapper returning both ECE and MCE along with per-bin details.
    - Keeps behavior stable for empty inputs (both 0.0, no bins)
    - Validates matching lengths
    """
    if len(probabilities) != len(labels):
        raise ValueError("probabilities and labels must have the same length")
    if len(probabilities) == 0:
        return CalibrationMetrics(ece=0.0, mce=0.0, bin_details=[])

    # Build bins once to provide details
    bin_sums = [0.0] * num_bins
    bin_counts = [0] * num_bins
    bin_correct = [0] * num_bins
    for p, y in zip(probabilities, labels):
        b = _bin_index(float(p), num_bins)
        bin_sums[b] += float(p)
        bin_counts[b] += 1
        bin_correct[b] += 1 if int(y) == 1 else 0

    ece_val = 0.0
    mce_val = 0.0
    n = float(len(probabilities))
    details: List[Dict[str, Any]] = []
    for b in range(num_bins):
        if bin_counts[b] == 0:
            continue
        conf = bin_sums[b] / float(bin_counts[b])
        acc = float(bin_correct[b]) / float(bin_counts[b])
        weight = bin_counts[b] / n
        gap = abs(conf - acc)
        ece_val += weight * gap
        mce_val = max(mce_val, gap)
        details.append(
            {
                "bin": b,
                "count": bin_counts[b],
                "avg_confidence": conf,
                "accuracy": acc,
                "weight": weight,
                "gap": gap,
            }
        )

    return CalibrationMetrics(ece=float(ece_val), mce=float(mce_val), bin_details=details)
