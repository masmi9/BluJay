## Summary

This change hardens CI/CD quality gates, wires baseline generation, stabilizes determinism handling (strict in CI, warn-only locally), enforces static-only gating in Frida UI/API, adds WSL/disk headroom checks to decompilation policy, and provides convenience scripts/targets and documentation.

### Key Changes
- LOCAL_GATE_SEQUENCE.sh: determinism warn-only block stabilized; baseline generation added.
- scripts/check_cache_performance_consolidation.py: exclude `.venv_aods/`; allow adapter bridge imports via marker.
- plugins/performance_analyzer/v2_plugin.py: unified performance tracker; adapter bridge marker.
- core/api/server.py: `/frida/health` fields added; static-only 409 responses; WS/SSE gating.
- FridaConsole.tsx: consumes `/frida/health`; chips for Mode/Determinism/Calibration; static-only disables; friendly policy messages; `secureFetch` enforced; accessibility labels.
- tools/ci/generate_known_good_scan.py: populate minimal known-good report with taxonomy/evidence.
- .github/workflows/quality-gates.yml: baseline suite + strict gates in CI (determinism strict).
- tools/ci/run_local_gates_quick.sh + Makefile: quick local gates target.
- core/decompilation_policy_resolver.py: WSL detection + disk headroom; safer defaults; docs + unit tests.
- docs: ci/toggles.md, ci/gates_catalog.md, api/frida.md, core/decompilation_policy.md, ui/frida_gating_acceptance.md.
- UI tests: unit tests for `secureFetch`; E2E for static-only gating and phases; selectors stabilized.

### Rationale
- Improve local feedback loops while keeping CI strict and deterministic.
- Reduce false positives in consolidation checker.
- Align Frida UI/API with static-only security policy.
- Ensure decompilation behaves safely in WSL/low-disk scenarios.
- Provide clear toggles and fast local gate execution.

### Determinism: Local vs CI
- Local runs: determinism leg set to warn-only via `LOCAL_GATE_SEQUENCE.sh` to avoid blocking on low-sample flakiness.
- CI runs: strict enforcement via `AODS_ENFORCE_ALWAYS=1` and `AODS_DETERMINISM_TOLERANCE=1.0` in workflow.

To toggle determinism strictly locally, export:

```bash
export AODS_ENFORCE_ALWAYS=1
export AODS_DETERMINISM_TOLERANCE=1.0
```

To relax determinism locally, unset or increase tolerance and/or keep warn-only block in the local script.

### Training/Vulnerable App Convenience (keeps CI strict)
- For local/training validation of intentionally vulnerable apps, set one of:
  - `AODS_VULNERABLE_APP_MODE=1` or `AODS_TRAINING_MODE=1`
- Effect: when `AODS_MAX_HIGH` is not explicitly set, the severity gate auto-allows up to 1 HIGH. CI remains strict by default and should not set these env vars.

### How to Run
- Local quick gates:
```bash
bash tools/ci/run_local_gates_quick.sh
```
or
```bash
make local-gates-quick
```

### CI Toggles
See `docs/ci/toggles.md` for:
- AODS_DETERMINISM_TOLERANCE
- AODS_MIN_FINDINGS
- AODS_ENFORCE_ALWAYS
- AODS_ENFORCE_JADX_POLICY
- AODS_ML_CALIBRATION_ENFORCE
- AODS_ML_CALIBRATION_SUMMARY
- AODS_ML_MAX_ECE, AODS_ML_MAX_MCE
- AODS_ML_CALIBRATION_STALE_TTL_SEC
- AODS_MAX_HIGH, AODS_MAX_CRITICAL
- AODS_VULNERABLE_APP_MODE, AODS_TRAINING_MODE

### Acceptance
- CI gate run: PASS locally (see `ci_quality_gates_*.json` and `ci_quality_report_*.txt`).
- UI: static-only gates enforced; determinism/calibration surfaced; unit + E2E cover paths.
- Decompilation: WSL/headroom logic with unit tests; docs updated.

### Next Up (Roadmap Extract)

1) Repo sanitization (scope/milestones/acceptance)
- Scope: stop tracking `artifacts/`, `design/.logs/`, Playwright results; add `.gitignore`; `git rm --cached` noisy files.
- Milestones: (a) add ignores (b) untrack existing noise (c) verify CI unaffected.
- Acceptance: clean `git status`; CI jobs still green.

2) CI hardening (start services, publish Playwright report)
- Scope: bootstrap UI/API in CI for E2E; upload Playwright HTML report as artifact.
- Milestones: (a) add service startup to workflow (b) add report upload step (c) verify no skips, report available.
- Acceptance: E2E shows 0 skips when services start; report downloadable from CI.

3) Frida Console docs (how-to)
- Scope: brief guide covering Reset, Diagnose connectivity, preflight guards, deep-links; screenshots.
- Milestones: (a) write doc (b) capture screenshots (c) link from README/TOC.
- Acceptance: doc renders; steps reproducible; screenshots included.

4) Tests follow-up
- Scope: unit tests for `refreshHealth` and preflight guards; E2E for Diagnose wizard outcomes.
- Milestones: (a) add unit tests (b) add E2E (c) run CI.
- Acceptance: tests pass locally/CI; coverage includes error paths.

5) Performance checks
- Scope: validate virtualized events at 10k lines; confirm memoized lists reduce renders.
- Milestones: (a) synthetic push benchmark (b) CPU/heap capture (c) summarize results.
- Acceptance: < 300 DOM nodes in viewport; CPU/heap within agreed thresholds.

6) A11Y polish
- Scope: axe audit across new chips/popover/wizard; dark-mode contrast verification.
- Milestones: (a) run axe and fix (b) verify dark mode contrast (c) update docs if needed.
- Acceptance: no critical axe violations; contrast ≥ 4.5:1 where applicable.

### PR Summary Additions (MSTG, MPT, Ostorlab)
- MSTG Coverage:
  - Shows global %, per-category bars, top missing tests, baseline date/SHA, and regression warnings when `artifacts/compliance/mstg_coverage/summary.json` exists.
  - Strict eligibility chips shown when applicable (see `promotion_policy.md`).
- External Dynamic (MPT) - shadow:
  - When `AODS_USE_MPT=1` and artifacts exist under `artifacts/dynamic_external/mpt/`, render a non-blocking subsection with short evidence snippets and a link to artifacts.
- External Benchmarks (Ostorlab) - shadow:
  - When enabled and `artifacts/benchmarks/ostorlab/summary.json` exists, display precision/recall/FPR snapshot and link to dataset summary; non-blocking.

### Local demo (shadow sections)
- To generate the new shadow sections locally:
```bash
make shadow-integrations
```
This runs the MPT orchestrator in dry-run, generates an Ostorlab summary (if sample results exist), and writes `artifacts/ci_gates/summary/pr_summary.md` with the new sections.


