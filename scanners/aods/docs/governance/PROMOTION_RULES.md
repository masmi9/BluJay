# AODS Gate Promotion Rules

## Overview

This document defines the promotion rules for CI quality gates in AODS.
Since this is a local-only development repository, no CODEOWNERS are required.
Promotion decisions are made by the local development lead.

## Gate Lifecycle

All gates follow this lifecycle:

```
DISABLED → WARN-ONLY → STRICT
```

### 1. DISABLED
- Gate exists but is not executed in CI
- Used during development and testing of new gates

### 2. WARN-ONLY
- Gate executes and reports status but does not block PRs/commits
- Default state for newly deployed gates
- Allows observation period to detect false positives

### 3. STRICT
- Gate executes and blocks on failure
- Only enabled after meeting promotion criteria

## Promotion Criteria

### From DISABLED to WARN-ONLY

Requirements:
- [ ] Gate implementation complete with unit tests
- [ ] Gate produces valid JSON artifact
- [ ] Gate integrated with CI workflow
- [ ] Documentation updated (README, MASTER_EXECUTION_PLAN.md)

### From WARN-ONLY to STRICT

Requirements:
- [ ] ≥5 consecutive green CI runs (no false positives)
- [ ] No regressions reported in observation period
- [ ] Acceptance criteria met (documented in MASTER_EXECUTION_PLAN.md)
- [ ] Rollback procedure documented

## Current Gate Status

| Gate | Status | Last Promotion | Next Review |
|------|--------|----------------|-------------|
| Detection Accuracy | WARN-ONLY | 2026-02-05 | After 5 greens |
| Validation Regression | WARN-ONLY | 2026-02-05 | After 5 greens |
| Taxonomy Freshness | WARN-ONLY | 2026-02-05 | After 5 greens |
| Baseline Staleness | WARN-ONLY | 2026-01-29 | After 5 greens |
| MSTG Coverage | WARN-ONLY | 2026-01-25 | After 5 greens |
| Semgrep MASTG Coverage | WARN-ONLY | 2026-01-29 | After 5 greens |
| Semgrep 10-APK Validation | WARN-ONLY | 2026-02-05 | After 5 greens |

## Rollback Procedure

If a gate causes issues after promotion to STRICT:

1. Immediately revert to WARN-ONLY in CI config
2. Document the failure mode in the gate's tracking issue
3. Fix the gate logic or adjust thresholds
4. Restart the promotion process

## Local-Only Development Notes

For local-only development (no CODEOWNERS):

1. **Pre-commit hooks** enforce `scripts/precommit_local_checks.sh`
2. **Pre-push hooks** run full `LOCAL_GATE_SEQUENCE.sh`
3. **Promotion decisions** are made by the local development lead
4. **Observation period** is based on local test runs, not PR CI
5. **Documentation** is the primary governance mechanism

## Environment Variables

Gates can be controlled via environment variables:

| Variable | Description |
|----------|-------------|
| `AODS_LOCAL_GATES` | Enable local gate execution (0/1) |
| `AODS_TAXONOMY_STRICT` | Enable strict taxonomy freshness (0/1) |
| `AODS_DISABLE_SEMGREP` | Disable Semgrep plugin (0/1) |

## Artifacts

All gates must produce artifacts under `artifacts/ci_gates/<gate_name>/`:

- `summary.json` - Gate execution summary
- `details.json` - Detailed findings (optional)
- `report.md` - Human-readable report (optional)

## Version History

| Date | Change |
|------|--------|
| 2026-02-05 | Initial promotion rules documentation |
