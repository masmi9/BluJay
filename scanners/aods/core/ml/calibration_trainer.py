#!/usr/bin/env python3
"""
Lightweight calibrator training utilities for inference-time probability calibration.

Features:
- Train Temperature, Platt, and Isotonic calibrators from (probability, label) data
- Compute ECE/MCE before/after calibration
- Export a single calibrator artifact to models/unified_ml/calibration.json

Dependencies: standard library only (grid search and binning heuristics used)
"""

from __future__ import annotations

import argparse
import json
from math import log, exp
from pathlib import Path
from typing import List, Sequence, Tuple

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

# Local metrics
try:
    from .metrics import compute_ece_mce
except Exception:  # pragma: no cover - fallback if path resolution differs in tests
    from core.ml.metrics import compute_ece_mce  # type: ignore  # noqa: F401


def _clip_prob(p: float) -> float:
    return max(1e-7, min(1.0 - 1e-7, float(p)))


def _logit(p: float) -> float:
    p = _clip_prob(p)
    return log(p / (1.0 - p))


def _sigmoid(z: float) -> float:
    return 1.0 / (1.0 + exp(-z))


def _nll(probs: Sequence[float], labels: Sequence[int]) -> float:
    """Negative log-likelihood for binary labels given probabilities."""
    total = 0.0
    for p, y in zip(probs, labels):
        p = _clip_prob(p)
        if y:
            total += -log(p)
        else:
            total += -log(1.0 - p)
    return total / max(1, len(probs))


def train_temperature(
    probs: Sequence[float], labels: Sequence[int], t_min: float = 0.5, t_max: float = 3.0, t_step: float = 0.05
) -> float:
    """Grid search temperature T minimizing NLL on logits: sigmoid(logit(p)/T)."""
    best_t = 1.0
    best_loss = float("inf")
    for i in range(int((t_max - t_min) / t_step) + 1):
        T = t_min + i * t_step
        adj = [_sigmoid(_logit(p) / max(1e-6, T)) for p in probs]
        loss = _nll(adj, labels)
        if loss < best_loss:
            best_loss, best_t = loss, T
    return best_t


def train_platt(
    probs: Sequence[float],
    labels: Sequence[int],
    a_grid: Tuple[float, float, float] = (0.5, 3.0, 0.1),
    b_grid: Tuple[float, float, float] = (-2.0, 2.0, 0.1),
) -> Tuple[float, float]:
    """Coarse grid search for Platt parameters (a, b) on logit space: sigmoid(a*logit(p)+b)."""
    a_min, a_max, a_step = a_grid
    b_min, b_max, b_step = b_grid
    best = (1.0, 0.0)
    best_loss = float("inf")
    a_steps = int((a_max - a_min) / a_step) + 1
    b_steps = int((b_max - b_min) / b_step) + 1
    logits = [_logit(p) for p in probs]
    for ia in range(a_steps):
        a = a_min + ia * a_step
        for ib in range(b_steps):
            b = b_min + ib * b_step
            adj = [_sigmoid(a * z + b) for z in logits]
            loss = _nll(adj, labels)
            if loss < best_loss:
                best_loss, best = loss, (a, b)
    return best


def train_isotonic_bins(probs: Sequence[float], labels: Sequence[int], bins: int = 10) -> List[Tuple[float, float]]:
    """Construct a monotonic piecewise-linear mapping using bin averages.

    Returns points [(x, y)] with x in [0,1] increasing and y non-decreasing.
    """
    if not probs:
        return [(0.0, 0.0), (1.0, 1.0)]
    paired = sorted((float(p), int(y)) for p, y in zip(probs, labels))
    n = len(paired)
    # Split into contiguous bins of approximately equal size
    points: List[Tuple[float, float]] = []
    for i in range(bins):
        start = int(i * n / bins)
        end = int((i + 1) * n / bins)
        if end <= start:
            continue
        seg = paired[start:end]
        xs = [p for p, _ in seg]
        ys = [y for _, y in seg]
        x_avg = sum(xs) / len(xs)
        y_avg = sum(ys) / len(ys)
        points.append((x_avg, y_avg))
    # Enforce monotonic non-decreasing y
    points.sort(key=lambda t: t[0])
    mono: List[Tuple[float, float]] = []
    last_y = 0.0
    for x, y in points:
        if y < last_y:
            y = last_y
        mono.append((max(0.0, min(1.0, x)), max(0.0, min(1.0, y))))
        last_y = y
    # Ensure endpoints present
    if not mono or mono[0][0] > 0.0:
        mono.insert(0, (0.0, mono[0][1] if mono else 0.0))
    if mono[-1][0] < 1.0:
        mono.append((1.0, mono[-1][1]))
    return mono


def apply_temperature(probs: Sequence[float], T: float) -> List[float]:
    return [_sigmoid(_logit(p) / max(1e-6, float(T))) for p in probs]


def apply_platt(probs: Sequence[float], a: float, b: float) -> List[float]:
    return [_sigmoid(float(a) * _logit(p) + float(b)) for p in probs]


def apply_isotonic(probs: Sequence[float], points: Sequence[Tuple[float, float]]) -> List[float]:
    pts = list(points)
    pts.sort(key=lambda t: t[0])
    out: List[float] = []
    for p in probs:
        p = float(p)
        if p <= pts[0][0]:
            out.append(pts[0][1])
            continue
        if p >= pts[-1][0]:
            out.append(pts[-1][1])
            continue
        placed = False
        for i in range(1, len(pts)):
            x0, y0 = pts[i - 1]
            x1, y1 = pts[i]
            if x0 <= p <= x1:
                if x1 == x0:
                    out.append(y1)
                else:
                    t = (p - x0) / (x1 - x0)
                    out.append(y0 + t * (y1 - y0))
                placed = True
                break
        if not placed:
            out.append(pts[-1][1])
    return out


def export_calibrator(kind: str, params, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "temperature":
        data = {"type": "temperature", "temperature": float(params)}
    elif kind == "platt":
        a, b = params
        data = {"type": "platt", "a": float(a), "b": float(b)}
    elif kind == "isotonic":
        data = {"type": "isotonic", "points": [[float(x), float(y)] for x, y in params]}
    else:
        raise ValueError(f"unknown calibrator kind: {kind}")
    out_path.write_text(json.dumps(data, indent=2))


def _load_dataset(path: Path) -> Tuple[List[float], List[int]]:
    data = json.loads(path.read_text())
    probs = [float(it["p"]) for it in data]
    labels = [int(it["y"]) for it in data]
    return probs, labels


def main() -> int:
    parser = argparse.ArgumentParser(description="Train a probability calibrator from labeled data")
    parser.add_argument("dataset", help="Path to JSON dataset: list of {p: float, y: 0/1}")
    parser.add_argument("--kind", choices=["temperature", "platt", "isotonic"], default="temperature")
    parser.add_argument(
        "--output", default="models/unified_ml/calibration.json", help="Output calibrator artifact path"
    )
    args = parser.parse_args()

    ds_path = Path(args.dataset)
    probs, labels = _load_dataset(ds_path)

    # Before metrics
    from core.ml.metrics import compute_ece_mce as _ece  # import locally to avoid circulars

    before = _ece(probs, labels, num_bins=10)

    if args.kind == "temperature":
        T = train_temperature(probs, labels)
        after_probs = apply_temperature(probs, T)
        export_calibrator("temperature", T, Path(args.output))
    elif args.kind == "platt":
        a, b = train_platt(probs, labels)
        after_probs = apply_platt(probs, a, b)
        export_calibrator("platt", (a, b), Path(args.output))
    else:
        points = train_isotonic_bins(probs, labels)
        after_probs = apply_isotonic(probs, points)
        export_calibrator("isotonic", points, Path(args.output))

    after = _ece(after_probs, labels, num_bins=10)
    logger.info(
        "Calibration training complete",
        kind=args.kind,
        ece_before=before.ece,
        ece_after=after.ece,
        mce_before=before.mce,
        mce_after=after.mce,
        output=str(Path(args.output).resolve()),
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
