## Local Development Gating Policy

Goal: maximize scanner accuracy while minimizing false positives. All issues must be fixed locally before commit.

Enforcement (default for local dev):
- Severity: warn-only (AODS_SEVERITY_BLOCK=0). Real High/Critical in target apps do not block development.
- False-Positive Budget: enforced. FP rate must be ≤ AODS_FP_MAX_RATE (default 0.05) using FP threshold AODS_FP_THRESHOLD (default 0.80).
- Evidence Quality: runs over curated artifacts (`artifacts/scans_dedup` → `artifacts/scans`) when present; calibration reports excluded by `AODS_EVID_Q_EXCLUDE_GLOB`.

Usage:
- One-off run:
```
AODS_SEVERITY_BLOCK=0 AODS_FP_THRESHOLD=0.8 AODS_FP_MAX_RATE=0.05 \
AODS_EVID_Q_EXCLUDE_GLOB='calib*.json,*calibration*' \
./aods_venv/bin/python ci_quality_gates.py reports/aods_androgoat_true.json
```
- Pre-commit hook:
```
make install-precommit-hook
```

Acceptance criteria before commit:
- FP budget gate: PASS (fp_rate ≤ configured max).
- Evidence quality: PASS or SKIP (when no curated artifacts).
- No legacy ML imports; terminology gate: PASS.
- Dedup effectiveness: PASS (if report available).

Release pipelines:
- Keep severity blocking (AODS_SEVERITY_BLOCK unset/1) and set AODS_MAX_HIGH / AODS_MAX_CRITICAL per policy.
