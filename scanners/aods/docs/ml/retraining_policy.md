# ML Calibrator Retraining Policy

This document defines when and how to retrain the probability calibrator used to convert raw confidences into calibrated probabilities.

## Triggers
- Validation ECE > 0.08
- Distribution drift (confidence histogram KL > 0.15 or category mix delta > 20%)
- Major rule/profile changes (e.g., new patterns, profile plugin sets)
- Scheduled weekly refresh (Sunday 03:00 UTC)

## Data Requirements
- Overall samples: ≥ 2,000 (p,y) pairs
- Per-category: ≥ 200 (crypto, storage, network/TLS, manifest, webview, injection)
- Profile stratification: collect for `lightning` and `standard`
- Labels: benchmark ground truth (DroidBench/Ghera/MASTG/AndroGoat) + curated benign (F‑Droid) with manual adjudication for edge cases

## Selection
Train temperature, Platt, and isotonic calibrators. Select by lowest validation ECE (10 bins). Prefer isotonic when sample sizes are sufficient; otherwise Platt or temperature.

## Targets
- ECE ≤ 0.05 preferred
- MCE ≤ 0.20

## Implementation Notes
- Use `tools/ml/run_calibration_pipeline.py` to export/train/select.
- Dataset labels can be provided via JSON/JSONL (see `core/ml/dataset_exporter.py`).
- Calibrator artifact path: `models/unified_ml/calibration.json`.
- Gate reports post‑update to ensure unknown fields policy remains green.

See `config/ml/retraining_policy.json` for the current policy parameters.
