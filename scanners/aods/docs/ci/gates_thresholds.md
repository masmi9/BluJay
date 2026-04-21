## CI Gate Thresholds

- Determinism
  - Artifacts/summaries identical; allow ≤1% diff for non-deterministic metadata
  - Tolerance env: `AODS_DETERMINISM_TOLERANCE` (default 1.0)
  - Enforce on small samples: `AODS_ENFORCE_ALWAYS=1`

- Accuracy (ML Baseline)
  - Precision drop ≤2%
  - Recall drop ≤3%
  - False positive rate ≤5%

- Severity
  - Defaults: `AODS_MAX_HIGH=0`, `AODS_MAX_CRITICAL=0`
  - Local convenience: `AODS_VULNERABLE_APP_MODE=1` (or `AODS_TRAINING_MODE=1`) auto-allows up to 1 HIGH when `AODS_MAX_HIGH` not set (CI remains strict)

- Decompilation Completeness
  - Manifest present 100%
  - Resources/assets ≥95% when present
  - Imports linkage heuristic satisfied in optimized/complete

- Integration
  - Roadmap steps mapped to workflows and artifacts present

- Deprecation
  - Zero legacy imports/paths in active code paths
  - Zero direct `subprocess` calls to external tools (jadx/adb/frida)
  - Strict mode: `AODS_DEPRECATION_STRICT=1` enforces failure on any violation

- Dedup Effectiveness
  - Definition: Effectiveness = (duplicates_before - duplicates_after) / duplicates_before
  - Target: ≥90% when duplicates are present
  - Strict mode: `AODS_DEDUP_CHECK_STRICT=1` fails when effectiveness < 0.90

- Execution Path
  - Definition: Exactly one orchestrator path per run; no divergence detected
  - Target: `divergence_detected = false` and `execution_path` present
  - Strict mode: `AODS_EXEC_PATH_STRICT=1` fails when manifest missing or divergence detected
  - No fallback log check tighter with: `AODS_EXEC_PATH_NO_FALLBACK=1`

- External Tools Mode
  - Definition: No dynamic tool usage (ADB/Frida) in static-only hard mode
  - Target: Zero matches of dynamic tool usage in logs when `AODS_STATIC_ONLY_HARD=1`
  - Strict mode: Fails if any dynamic tool usage detected

- UI E2E Skips (Dev)
  - Definition: Maximum allowed skipped Playwright tests in the dev smoke run
  - Target: `skipped <= AODS_E2E_MAX_SKIPS` (default 0)
  - Transitional cushion: CI may set a temporary allowance (e.g., 40) while stabilizing; tighten to 0 when stable

- UI Perf (Frida 10k)
  - Definition: Time to render/cap 10k events to virtualized list
  - Targets:
    - `render_time_ms <= AODS_UI_PERF_MAX_RENDER_MS` (default 12000ms)
    - `jank_p95_ms <= AODS_UI_PERF_MAX_JANK_P95_MS` (default 20ms)
    - `heap_used_mb <= AODS_UI_PERF_MAX_HEAP_MB` (default 400MB)
  - Notes: Captured from Playwright perf test metrics JSON (`artifacts/ui_perf/perf_metrics.json`)

- UI Memoization
  - Definition: Average latency for frequent UI toggle interactions
  - Target: `toggle_avg_ms <= AODS_UI_TOGGLE_MAX_AVG_MS` (default 15ms)
  - Notes: Read from `artifacts/ui_perf/perf_metrics.json`

- ML Calibration Quality
  - Definition: Calibration improves or maintains ECE, MCE stays within max thresholds
  - Targets: `ECE_after <= AODS_ML_MAX_ECE` (default 0.05), `MCE_after <= AODS_ML_MAX_MCE` (default 0.10)
  - Enforcement: `AODS_ML_CALIBRATION_ENFORCE=1` (gate SKIPs if summary missing)

- ML Drift (warn-only by default)
  - Definition: Chi-square test across binned confidences vs. baseline
  - Targets: `chi2 <= AODS_ML_DRIFT_MAX_CHI2` (default 18.3 at 10 bins)
  - Bins: `AODS_ML_DRIFT_BINS` (default 10)

- Flaky Tests
  - Definition: New flaky tests not present in baseline cause failure
  - Inputs: Playwright JSON report, baseline list (optional)

- Determinism Thresholds
  - Definition: Absolute per-key delta across thresholds artifacts must be within tolerance
  - Target: `|Δ| <= AODS_THRESH_TOLERANCE` (default 0.001)
