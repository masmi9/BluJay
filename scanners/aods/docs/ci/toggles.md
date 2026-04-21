## CI Toggles and Thresholds

This document summarizes environment variables used by AODS CI gates.

### Determinism Gate
- `AODS_DETERMINISM_TOLERANCE`: allowable percent diff (default `1.0`).
- `AODS_ENFORCE_ALWAYS`: set `1` to enforce even on small samples.

### Integration Coverage Gate
- `AODS_MIN_FINDINGS`: minimum findings required for enforcement (default `10`).
- `AODS_ENFORCE_ALWAYS`: override minimum and enforce regardless of sample size.

### Calibration Quality Gate
- `AODS_ML_CALIBRATION_ENFORCE`: set `1` to fail CI when ECE/MCE exceed limits.
- `AODS_ML_CALIBRATION_SUMMARY`: path to calibration summary JSON.
- `AODS_ML_MAX_ECE`, `AODS_ML_MAX_MCE`: thresholds (defaults `0.1`, `0.2`).
- AODS_ML_MAX_ECE: Maximum allowed ECE before failing calibration gate (default 0.1)
- AODS_ML_MAX_MCE: Maximum allowed MCE before failing calibration gate (default 0.2)
- AODS_ML_CALIBRATION_STALE_TTL_SEC: Seconds after which calibration summary is considered stale (default 604800)
- `AODS_ML_ECE_DATASET`: optional path to dataset (confidences/labels) to compute true ECE/MCE at gate time.
- `AODS_ML_ECE_BINS`: number of bins for ECE computation (default `10`).
- `AODS_ML_CALIBRATION_FAMILY`: optional model family (e.g., `android`, `ios`) to select family-specific `calibration_summary.json` under the same base folder.
- `AODS_ML_FAMILY_THRESHOLDS_JSON`: JSON map of per-family thresholds, e.g. `{ "android": { "max_ece": 0.05, "max_mce": 0.10 } }`. Falls back to `AODS_ML_MAX_ECE`/`AODS_ML_MAX_MCE` when not provided.
- `AODS_ML_REQUIRE_FAMILY_CALIBRATOR`: when set to `1`, enforce presence of a calibrator artifact for the specified family (tries `<base>/<family>/calibration.json` or `families[family].artifact`).

### ML Drift Gate
- `AODS_ML_DRIFT_BINS`: number of bins for drift chi-square (default `10`).
- `AODS_ML_DRIFT_MAX_CHI2`: chi-square threshold (default `18.3` for 9 dof @95%).

Quick local run:
```bash
bash tools/ci/run_local_gates_quick.sh
# or via make
make local-gates-quick
```

### JADX Flags Policy Gate
- `AODS_ENFORCE_JADX_POLICY`: set `1` to block raw/banned flags.
- AODS_ENFORCE_JADX_POLICY: Enforce decompilation policy resolver in CI (1=on)

### Severity Gate
- `AODS_MAX_HIGH`, `AODS_MAX_CRITICAL`: allowed counts (defaults `0`, `0`).
- `AODS_VULNERABLE_APP_MODE=1` or `AODS_TRAINING_MODE=1`: for local/training runs only, auto-allows up to 1 HIGH when `AODS_MAX_HIGH` is not explicitly set. CI remains strict by default.
- `AODS_TRAINING_MAX_HIGH`, `AODS_TRAINING_MAX_CRITICAL`: optional training-app specific allowances applied only when the run is detected as a training app and hard thresholds (`AODS_MAX_*`) are not set. Defaults: unset (no change). Example: set `AODS_TRAINING_MAX_HIGH=2` to allow up to 2 HIGH on training apps without affecting production scans.
- `AODS_SEVERITY_BLOCK`: set to `0` to make severity non-blocking (warn-only); default unset/`1` blocks when thresholds exceeded. Unified config alternative: `ci.toggles.severity_warn_only=true`.

### MASVS/MASTG Coverage (MSTG)
- `AODS_MSTG_TRACING`: enable MSTG tracer events emission (default `0`)
- `AODS_MSTG_TRACE_FLUSH_MS`: tracer flush interval (default `250`)
- `AODS_MSTG_TRACE_MAX_Q`: tracer queue max size (default `1000`)
- `AODS_MSTG_STRICT`: enable strict coverage gate on main/master only (default `0`)
- `AODS_MSTG_GATE`: enable MSTG coverage gate execution (default `1` warn-only)

### External Dynamic Runner (MPT)
- `AODS_USE_MPT`: opt-in to run MPT orchestrator in CI/local; writes artifacts to `artifacts/dynamic_external/mpt/`

### External Benchmarks (Ostorlab)
- `AODS_USE_OSTORLAB_BENCHMARKS`: opt-in to fetch/build selected Ostorlab apps
- `AODS_RUN_OSTORLAB_BENCHMARKS`: opt-in CI job to scan selected benchmark APKs and publish shadow metrics

### External Tools Mode Gate
- `AODS_STATIC_ONLY_HARD`: set `1` to fail when dynamic tools are invoked in static-only mode.
- `AODS_SCAN_LOG`: specify the log path to scan for dynamic tool invocations.

### Execution Path Gate
- `AODS_EXEC_PATH_STRICT`: set `1` to fail when mixed orchestrator paths are detected.
- `AODS_EXEC_PATH_NO_FALLBACK`: set `1` to treat any canonical→legacy fallback log as a failure.

### Report Presence Gate
- `AODS_REPORT_PRESENCE_STRICT`: set `1` to fail when expected report is missing/unparseable.
- `AODS_RUN_MANIFEST_PATH`: path to `run_manifest.json` (default `artifacts/run_manifest.json`).
- `AODS_EXPECTED_REPORT_PATH`: explicit expected report path (overrides manifest hint).

### E2E Skips Gate
- `AODS_E2E_MAX_SKIPS`: maximum allowed skipped tests in Playwright JSON report (default `50`).

### Evidence Quality Gate
- `AODS_EVID_Q_EXCLUDE_GLOB`: comma-separated glob patterns to exclude (e.g., `calib*.json,*_calibration.json`).

### False-Positive Budget Gate
- `AODS_FP_THRESHOLD`: probability threshold at/above which a finding counts as FP (default `0.8`).
- `AODS_FP_MAX_RATE`: maximum allowed false-positive rate across findings (default `0.2`).



