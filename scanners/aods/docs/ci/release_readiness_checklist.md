## Release Readiness Checklist (AODS)

- UI E2E (dev) smoke passes with 0 skips
- UI E2E (prod at /ui) smoke renders `new-scan`
- Playwright reports uploaded (dev, prod, perf)
- UI Perf Gate passes (render, jank p95, heap, DOM nodes)
- UI Memoization Gate passes (toggle_avg_ms)
- A11Y audits run; critical violations blocked or documented
- Flaky Tests Gate passes; no new flakes
- Determinism Gates pass (reports A/B and thresholds A/B)
- Detection Accuracy gate meets min precision/recall (or baseline used)
- ML Calibration Quality Gate passes (ECE/MCE)
- ML Drift Gate evaluated (warn-only if configured)
- Report Presence Gate passes when expected
- Execution Path Gate passes
- Deprecation Gate passes (strict)
- Dedup Effectiveness Gate passes (strict)
- Timeout Policy/Import gates pass
- CI Gates dashboard and PR summary artifacts uploaded
- Roadmap Events Dedup Gate passes; EventIDs updated
- Nightly ML baseline workflow green (most recent run)

Owner sign-off:
- UI Platform: ________
- ML Platform: ________
- Release Eng: ________

