#!/usr/bin/env python3
"""
Lightweight calibration loader for inference-time probability calibration.

Capabilities:
- Load temperature scaling parameters from a JSON artifact
- Load Platt scaling parameters from a JSON artifact
- Load isotonic regression mapping from a JSON artifact
- Provide a no-op calibrator when artifacts are absent

Artifact formats (JSON):
Temperature:
{
  "type": "temperature",
  "temperature": 1.5
}

Platt:
{
  "type": "platt",
  "a": 1.0,
  "b": -0.25
}

Isotonic:
{
  "type": "isotonic",
  "points": [[0.0, 0.05], [0.5, 0.5], [1.0, 0.95]]
}
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
import os
from math import log, exp
from pathlib import Path
from typing import Optional, Protocol, List, Tuple

# Singleton cache for calibrators (avoids reloading from disk on every call)
_calibrator_cache: dict = {}
_calibrator_cache_lock = threading.Lock()


class ProbabilityCalibrator(Protocol):
    def calibrate(self, probability: float) -> float:  # pragma: no cover - Protocol
        ...


@dataclass
class NoOpCalibrator:
    """Returns the input probability unchanged."""

    def calibrate(self, probability: float) -> float:
        p = max(0.0, min(1.0, float(probability)))
        return p


@dataclass
class TemperatureCalibrator:
    """Temperature scaling on the logit space: logit(p) / T -> sigmoid()."""

    temperature: float

    def calibrate(self, probability: float) -> float:
        p = max(1e-7, min(1.0 - 1e-7, float(probability)))
        T = max(1e-6, float(self.temperature))
        logit = log(p / (1.0 - p))
        adj = logit / T
        # sigmoid(adj)
        return 1.0 / (1.0 + exp(-adj))


@dataclass
class PlattCalibrator:
    """Platt scaling on logit space: sigmoid(a * logit(p) + b)."""

    a: float
    b: float

    def calibrate(self, probability: float) -> float:
        p = max(1e-7, min(1.0 - 1e-7, float(probability)))
        logit = log(p / (1.0 - p))
        adj = (float(self.a) * logit) + float(self.b)
        return 1.0 / (1.0 + exp(-adj))


@dataclass
class IsotonicCalibrator:
    """
    Isotonic regression via monotonic piecewise-linear mapping.
    `points` must be a list of (x, y) with x strictly increasing in [0,1]
    and y non-decreasing in [0,1].
    """

    points: List[Tuple[float, float]]

    def __post_init__(self) -> None:
        self.points = self._validate_and_prepare(self.points)

    @staticmethod
    def _validate_and_prepare(points_raw: List[Tuple[float, float]]) -> List[Tuple[float, float]]:
        pts = [(max(0.0, min(1.0, float(x))), max(0.0, min(1.0, float(y)))) for x, y in points_raw]
        pts.sort(key=lambda t: t[0])
        if len(pts) < 2:
            return [(0.0, 0.0), (1.0, 1.0)]
        # Ensure strictly increasing x and non-decreasing y
        last_x = -1.0
        last_y = -1.0
        checked: List[Tuple[float, float]] = []
        for x, y in pts:
            if x <= last_x:
                x = last_x + 1e-6
            if y < last_y:
                y = last_y  # enforce monotonic non-decreasing
            checked.append((x, y))
            last_x, last_y = x, y
        return checked

    def calibrate(self, probability: float) -> float:
        p = max(0.0, min(1.0, float(probability)))
        pts = self.points
        if p <= pts[0][0]:
            return pts[0][1]
        if p >= pts[-1][0]:
            return pts[-1][1]
        # Find segment
        for i in range(1, len(pts)):
            x0, y0 = pts[i - 1]
            x1, y1 = pts[i]
            if x0 <= p <= x1:
                if x1 == x0:
                    return y1
                t = (p - x0) / (x1 - x0)
                return y0 + t * (y1 - y0)
        return pts[-1][1]


def load_calibrator(artifact_path: Optional[str] = None, use_cache: bool = True) -> ProbabilityCalibrator:
    """
    Load a probability calibrator from a JSON artifact.

    Resolution order:
    1) artifact_path if provided
    2) default 'models/unified_ml/calibration.json'

    Returns a NoOpCalibrator when the file is missing or invalid.

    Args:
        artifact_path: Explicit path to calibration JSON file
        use_cache: If True (default), returns cached calibrator instance if available
    """
    # Resolve base path from explicit arg or env, then apply optional family override
    base = (
        Path(artifact_path)
        if artifact_path
        else Path(os.getenv("AODS_ML_CALIBRATOR_PATH", "models/unified_ml/calibration.json"))
    )
    family = os.getenv("AODS_ML_CALIBRATION_FAMILY")
    path = base
    if family:
        try:
            if base.name.lower().endswith("calibration.json"):
                fam_path = base.parent / family / "calibration.json"
            else:
                fam_path = base / family / "calibration.json"
            if fam_path.exists():
                path = fam_path
        except Exception:
            # fall back to base path
            path = base

    # Check cache first (keyed by resolved path)
    cache_key = str(path.resolve()) if path.exists() else "__noop__"
    if use_cache:
        with _calibrator_cache_lock:
            if cache_key in _calibrator_cache:
                return _calibrator_cache[cache_key]

    if not path.exists():
        calibrator: ProbabilityCalibrator = NoOpCalibrator()
        if use_cache:
            with _calibrator_cache_lock:
                _calibrator_cache[cache_key] = calibrator
        return calibrator
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        calibrator = NoOpCalibrator()
        if use_cache:
            with _calibrator_cache_lock:
                _calibrator_cache[cache_key] = calibrator
        return calibrator

    # Infer calibrator kind when explicit type missing
    kind = str(data.get("type", "")).strip().lower()
    if not kind:
        if "temperature" in data:
            kind = "temperature"
        elif "a" in data and "b" in data:
            kind = "platt"
        elif "points" in data:
            kind = "isotonic"

    calibrator = NoOpCalibrator()
    try:
        if kind == "temperature":
            T = float(data.get("temperature", 1.0))
            calibrator = TemperatureCalibrator(temperature=T)
        elif kind == "platt":
            a = float(data.get("a", 1.0))
            b = float(data.get("b", 0.0))
            calibrator = PlattCalibrator(a=a, b=b)
        elif kind == "isotonic":
            points = data.get("points", [])
            try:
                pts: List[Tuple[float, float]] = [(float(x), float(y)) for x, y in points]
            except Exception:
                pts = [(0.0, 0.0), (1.0, 1.0)]
            calibrator = IsotonicCalibrator(points=pts)
    except Exception:
        calibrator = NoOpCalibrator()

    # Cache the calibrator for future calls
    if use_cache:
        with _calibrator_cache_lock:
            _calibrator_cache[cache_key] = calibrator

    return calibrator


__all__ = [
    "ProbabilityCalibrator",
    "NoOpCalibrator",
    "TemperatureCalibrator",
    "PlattCalibrator",
    "IsotonicCalibrator",
    "load_calibrator",
]
