## Strict Promotion Policy for CI Gates

This document defines how and when WARN-only gates should be promoted to strict (fail-on-violation) mode.

### Goals
- Prevent churn by soaking changes under WARN-only before enforcing
- Use objective evidence (N green runs) to suggest promotion
- Keep toggles transparent in PR summary and UI chips

### Promotion Criteria
- By default, a gate is eligible for promotion after N consecutive or N-of-M recent green runs (PASS), where N defaults to 5.
- Configure the window and threshold in the promotion suggester step parameters (`--window` and `--n-greens`).
- The suggester writes `artifacts/ci_gates/promotion_suggester/summary.json` with recommendations.

### Enabling Strict Mode
- For eligible gates, enable strict via environment toggles or workflow configuration:
  - Accuracy: `AODS_ACCURACY_STRICT=1` or `--strict`
  - ML Version Stamps: `AODS_ML_STAMPS_STRICT=1`
  - Baseline Staleness: `AODS_BASELINE_STALE_STRICT=1`
  - Calibration Staleness (future): `AODS_CALIBRATION_STALE_STRICT=1`
  - MSTG Coverage (warn→strict): `AODS_MSTG_STRICT=1` (main/master only per policy)

### Visibility & Telemetry
- PR summary includes strict toggles under "Strict Toggles" and ML Stamps strict state under the ML Stamps section.
- UI dashboard surfaces chips for Accuracy strict, ML Stamps strict, Baseline/Calibration staleness, and promotion suggestions.

### Rollback
- If a newly strict gate causes unexpected failures, revert the strict env toggle to `0` while investigating root cause.

#### MSTG Coverage Gate - Promotion & Rollback Details
- Eligibility: ≥5 consecutive green runs at or above floors (global and all categories) with no regression ≥5pp vs baseline.
- Enablement: set `AODS_MSTG_STRICT=1` in workflow on main/master only. Keep warn‑only on PR branches.
- Baseline dependency: floors are derived from the latest approved baseline and capped by target floors; promotion requires baseline freshness ≤14 days.
- Rollback: set `AODS_MSTG_STRICT=0` if regressions appear or tracer overhead >5% is observed; open a follow‑up to adjust floors or investigate regressions.

### Notes
- TTLs for staleness gates are configurable via gates.yml with env overrides.
- The suggester is advisory and does not block builds.



