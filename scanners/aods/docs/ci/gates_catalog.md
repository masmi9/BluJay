## CI/CD Gates Catalog

> **Note:** Gate scripts are located in `tools/ci/gates/` on the `dev` branch. They are not included in the `main` branch.

See also: CI thresholds and strict-mode envs in `docs/ci/gates_thresholds.md`.

This catalog documents the quality and safety gates executed in CI for AODS, with linked artifacts, acceptance criteria, and troubleshooting notes.

### UI: Playwright E2E (Dev Shell)
- What: Headless smoke of the React UI against localhost API and Vite dev server
- Artifacts: `playwright-report-dev` (HTML report), `playwright-report-dev/report.json` (JSON)
- Acceptance:
  - Test runner completes without infrastructure errors
  - Report is uploaded and contains run details (pass/skip/fail)

### UI: Targeted E2E Gate (Dev, Strict)
- What: Runs only the stabilized, high-signal specs to gate regressions quickly in dev shell.
- Specs:
  - `design/ui/react-app/tests/frida.telemetry.summary.spec.ts`
  - `design/ui/react-app/tests/dashboard.deltas.autorefresh.spec.ts`
- Command (CI step): starts API (8088) + Vite (5088), then executes the two specs with `--workers=1`.
- Artifacts: `playwright-report-targeted` (HTML report)
- Acceptance:
  - Both specs pass with zero skips
  - Report is uploaded
  - Intended to be strict and fast; unrelated suites may fail elsewhere without blocking this gate

### UI: Playwright E2E (Prod Shell at /ui)
- What: Smoke test against the FastAPI-served production build under `/ui`
- Artifacts: `playwright-report-prod` (HTML report)
- Acceptance:
  - `/ui/new-scan` renders
  - Report is uploaded

### UI: Jest Unit Coverage Gate (strict)
- **What**: Run React unit tests with coverage and enforce strict minimum thresholds.
- **Command**: `COVERAGE_ONLY=1 jest --coverage --runInBand` (V8 coverage provider)
- **Artifacts**: `design/ui/react-app/coverage/` (HTML and JSON coverage outputs)
- **Thresholds (global)**: branches ≥ 55%, functions ≥ 60%, lines ≥ 80%, statements ≥ 80%
- **Acceptance**:
  - Jest completes and global coverage thresholds are met
  - Coverage artifact is uploaded

### UI: Deep-linking E2E (Artifacts view links)
- What: Verify “view” links from CI Gates dashboard deep‑link to `Artifacts` and auto‑open preview.
- Test: `design/ui/react-app/tests/gates.view-deeplink.spec.ts`
- Artifacts: `playwright-report-deeplink` (HTML report)
- Acceptance:
  - Navigating via a "view" link opens the target artifact preview
  - Type filter/pagination do not block preview (page forces a preview panel)

### UI: CI Toggles E2E (Prod UI)
- What: Verify `ToolsStatus` CI toggles persist via backend and survive reload.
- Toggles: `failOnCritical`, `failOnHigh`, `dedupStrict` (`/api/ci/toggles`)
- Test: `design/ui/react-app/tests/ci.toggles.prod.spec.ts`
- Artifacts: `playwright-report-ci-toggles` (HTML report)
- Acceptance:
  - Toggling switches updates server and state persists after reload
  - Aggregator honors unified config toggles when env vars are unset (local runs)

### UI: Frida Screenshots (Documentation)
- What: Best-effort capture of Frida Console screenshots for docs
- Artifacts: `frida-ui-screenshots` → `docs/ui/images/*.png`
- Acceptance:
  - Artifact contains the 6 expected screenshots (header, diagnose, reset, static-only, deep-link raw, virtualization)

### UI: A11Y Audit (Informational)
- What: A11Y checks for ARIA labels/roles and an `axe-core` audit (CSP may block external script; non-blocking)
- Acceptance:
  - Key chips/controls expose labels (e.g., `execution-mode`, `sse-status`)
  - No critical A11Y regressions logged in CI output

### Security: Bandit (Python)
- What: Static analysis for Python (high severity enforced)
- Acceptance:
  - No high-severity Bandit findings

### Security: Safety (Python)
- What: Dependency vulnerability scan (warning-only for now)
- Acceptance:
  - Job completes; findings are logged but do not fail build unless configured

### Plugin Interface Contract Gate (Reporting)
- Purpose: Validate that findings contain required evidence/location fields for downstream reporting and triage.
- Inputs:
  - Preferred: `artifacts/reports/report_v1_1.json`
  - Fallback: first `artifacts/scans/*aods*.json`
- Implementation: `tools/ci/gates/plugin_interface_contract_gate.py`
- Artifacts: `artifacts/ci_gates/plugin_contract/summary.json` (status, total_findings, issues)
- Enforcement: WARN-only initially (promotion after ≥5 greens)
- PR Summary: Shows status, total findings, and issues count

### Evidence Coverage Trend (Reporting)
- Purpose: Track coverage of `location.file`, `location.line`, and `evidence.snippet` across findings, with breakdown by plugin.
- Inputs: v1.1 report if present; otherwise latest scan report
- Implementation: `tools/ci/gates/evidence_coverage_trend.py`
- Artifacts: `artifacts/ci_gates/evidence_trends/summary.json` (global and per-plugin percentages)
- PR Summary: Shows global file/line/snippet coverage and lowest snippet coverage plugins

### Evidence Coverage Floor Gate (Advisory)
- Purpose: Compare current coverage against configurable floors to surface regressions.
- Inputs: `artifacts/ci_gates/evidence_trends/summary.json`
- Implementation: `tools/ci/gates/evidence_coverage_floor_gate.py`
- Artifacts: `artifacts/ci_gates/evidence_trends/floor_gate.json`
- Toggles:
  - `AODS_EVID_FILE_FLOOR`, `AODS_EVID_LINE_FLOOR`, `AODS_EVID_SNIPPET_FLOOR` (0.0–1.0; defaults 0.0)
  - `AODS_EVIDENCE_COVERAGE_STRICT=1` to fail when below floors; else WARN-only
- PR Summary: Shows floors, current coverage, and any violations

### Security: npm audit (UI)
- What: Production dependency audit (high severity enforced)
- Acceptance:
  - No high-severity vulnerabilities reported

### Quality Gates Aggregator
- What: Aggregates calibrated quality gates and fails build if thresholds are exceeded
- Artifacts:
  - `ci_quality_gates_*.json`
  - `ci_quality_report_*.txt`
- Acceptance:
  - Gate script exits 0 with `AODS_ENFORCE_ALWAYS=1`, `AODS_MAX_HIGH=0`, `AODS_MAX_CRITICAL=0`

### AST/Role-Aware Architecture Checks (H3)
- Fast vs Full modes:
  - Fast (PR): regex-only scan and/or changed-files limiting (`--no-ast` + changed-files); budget ≤ 60s
  - Full (nightly): AST-enabled full repository scan; budget ≤ 10 min
- Role Map:
  - Generated via `tools/ci/generate_roles_config_from_dup.py` into `tools/ci/config/component_roles.json`
  - Sources canonical facades/adapters from duplication system
- Acceptance:
  - Zero false positives for FACADE/ADAPTER files (role-aware skip)
  - Full finds >= fast findings (AST is a superset)

### ML Detection Accuracy Gate (Conditional)
- What: Runs when dataset exists; enforces precision/recall thresholds
- Artifacts:
  - `artifacts/ci_gates/detection_accuracy/summary.json` (includes dataset_vintage: `dataset_mtime`, `dataset_size_bytes`)
  - Derived thresholds (when PR metrics exist)
- Acceptance:
  - Precision ≥ 0.90, Recall ≥ 0.85 (unless warn-only)
 - Optional FPR ceiling: FPR ≤ 0.05 when available
 - Inputs:
   - `--dataset <path>` combined labeled dataset (list of {p, y, category, plugin_source})
   - `--thresholds <path>` base thresholds JSON; prefers nightly in `artifacts/ml_baselines/**/thresholds.json`
   - `--benign-dataset <path>` optional benign-only dataset to compute FPR accurately
   - `--max-fpr <float>` maximum allowed FPR (default 0.05); applied when FPR present
 - Outputs:
   - Summary includes `metrics.fpr` and `fpr_source` (overall|benign), `min_precision`, `min_recall`, `max_fpr`

### Reporting: SysReptor JSON (Conditional)
- What: Converts the latest scan JSON into SysReptor format if a report is present
- Artifacts: `artifacts/reports/sysreptor_report.json`
- Acceptance:
  - JSON artifact is produced when input report exists

### External Benchmarks (Ostorlab) - Shadow Metrics
- Purpose: Run selected vulnerable apps (opt-in) to produce evaluation metrics.
- Inputs/Env: `AODS_RUN_OSTORLAB_BENCHMARKS=1` and dataset manifest under `artifacts/ml_datasets/ostorlab/index.json`.
- Artifacts: `artifacts/benchmarks/ostorlab/summary.json` plus APK builds under `artifacts/benchmarks/ostorlab/apks/`.
- PR Summary: Adds an "External Benchmarks (Ostorlab)" section with precision/recall/FPR snapshot; non-blocking.
- Acceptance:
  - When enabled and artifacts exist: PR summary includes shadow metrics; job completes.
  - When disabled or missing: job SKIP; no effect on other gates.

### Artifacts Policy
- All HTML reports and images are uploaded as GitHub Actions artifacts for traceability
- Large artifacts are pruned; only the latest run’s reports are uploaded to keep storage lean
- Locations:
  - UI reports: `design/ui/react-app/playwright-report-*`
  - Screenshots: `docs/ui/images`
  - Quality/accuracy/reports: `artifacts/**`

### Operational Notes
- CI orchestrates service startup (API on 8088; Vite on 5088) and waits on readiness via `curl`
- Playwright is pinned to Chromium and executes with `--workers=1` for determinism in smoke jobs
- CSP may prevent `axe-core` injection; A11Y audit remains informational and non-blocking

### Local Warn-only Posture (Cross-links)
- For local development runs, the following gates default to WARN-only unless explicitly set strict via env:
  - Deprecation Gate: `AODS_DEPRECATION_STRICT=1` to fail on violations.
  - External Tools Mode Gate: enable hard static-only with `AODS_STATIC_ONLY_HARD=1` (denies ADB/Frida usage; local runs recommended WARN-only unless training).
  - MSTG Coverage Gate: `AODS_MSTG_STRICT=1` to enforce floors; otherwise WARN-only when below floors.
  - Accuracy Gate: force strict with `AODS_ACCURACY_STRICT=1` or aggregator `AODS_ENFORCE_ALWAYS=1`.
- For a local consolidated run, see `LOCAL_GATE_SEQUENCE.sh`; JSON artifacts are written under `artifacts/ci_gates/**`.

### CI Gates Deltas API (UI integration)
- What: Lightweight API to expose WARN/FAIL deltas between successive dashboard polls
- Endpoint: `/gates/deltas`
- Response: `{ totals: { PASS,WARN,FAIL }, previous: {…}, delta: { WARN?, FAIL? } }`
- Notes:
  - In-memory only (per-process); resets on API restart
  - UI Dashboard and CI Gates Dashboard consume this to show transient +WARN/+FAIL chips since last refresh
  - UI behavior: Dashboard exposes an "Auto deltas" toggle (persisted) and a manual Refresh button. When auto is off, deltas chips are hidden until Refresh.
  - Tests:
    - E2E (dev shell): `design/ui/react-app/tests/dashboard.deltas.spec.ts` and `tests/gatesdashboard.deltas.spec.ts`
    - E2E (dev shell, auto-refresh): `design/ui/react-app/tests/dashboard.deltas.autorefresh.spec.ts`
    - E2E (prod shell): `design/ui/react-app/tests/dashboard.deltas.prod.spec.ts`

### Tool Metadata (External Tools & Optional Dependencies)
- /tools/status: now includes `last_checked` (ISO), `install_hint` (when missing), `executable_path`, `default_timeout`, `max_retries`.
- /optional-deps/status: now includes `version`, `min_version`, `supported`, `last_checked`.
- UI: `ToolsStatus.tsx` renders path/timeout/retries/hints and last-checked; auto-refresh toggle persisted.
- Acceptance:
  - Tool status page clearly indicates READY/NOT READY with remediation hints when missing.
  - Metadata (path, timeout, retries, last-checked) visible.

### Future Gates (Proposed)
- UI performance micro-bench (virtualized events 10k) under a separate job with relaxed timeouts
- Memoization regression checks for device/process lists

This catalog lists the CI/CD quality gates used by AODS, their purpose, inputs, and ownership.

- Determinism Gate
  - Purpose: Ensure repeated runs produce stable artifacts/summaries.
  - Inputs: Pair of reports or summaries.
  - Owner: Architecture (Quality) - see `docs/ci/gates_runbooks.md`

- Accuracy Gate (ML Baseline)
  - Purpose: Prevent regressions vs. baseline precision/recall and FP rate.
  - Inputs: Baseline `summary.json` and current `summary.json`.
  - Artifacts: `artifacts/ci_gates/detection_accuracy/summary.json`, optional `artifacts/ml_thresholds_derived.json`, `artifacts/ml_datasets/metrics/thresholds_summary.json`.
  - Owner: AI/ML - see `docs/ci/gates_runbooks.md`

- Deprecation Gate
  - Purpose: Block legacy imports/paths and direct external tool calls.
  - Inputs: Repository scan (+ optional `AODS_SCAN_LOG` heuristics).
  - Checks:
    - Legacy ML imports
    - `core.plugin_manager` and `parallel_scan_manager` usages in active paths
    - BasePlugin v1 imports/subclassing outside allowlists
    - Direct `subprocess` calls to `jadx`/`adb`/`frida` (should use UnifiedToolExecutor)
  - Strict toggle: `AODS_DEPRECATION_STRICT=1` fails CI on violations (default WARN in local runs)
  - Owner: Architecture (Migration) - see `docs/ci/gates_runbooks.md`

- Plugin Audit Gate
  - Purpose: Enforce migration to `BasePluginV2` and basic conformance.
  - Inputs: `artifacts/plugin_audit/<run>/summary.json` from `tools/ci/check_baseplugin_v2_compliance.py`.
  - Checks: v2 modules discovered, v2 class conformance (metadata present), zero issues.
  - Strict toggle: `AODS_PLUGIN_AUDIT_STRICT=1` fails when issues>0 or v2_compatible < v2_modules.
  - Shadow check: RegistryV3 parity check runs non-strict to report any cached vs live discovery diffs.
  - Owner: Plugins - see `docs/plugins/base_plugin_v2.md`

- Discovery Log Gate
  - Purpose: Ensure only one authoritative plugin discovery completion summary per run (avoid duplicated discovery work/logs).
  - Inputs: Scan log (`AODS_SCAN_LOG` or `scan_results/scan_log`).
  - Implementation: `tools/ci/gates/discovery_log_gate.py`.
  - Strict toggle: `AODS_DISCOVERY_LOG_STRICT=1`; threshold via `AODS_DISCOVERY_MAX_SUMMARIES` (default `1`).
  - Owner: Plugins / Architecture

- Integration Gate
  - Purpose: Ensure roadmap → workflow → artifacts consistency.
  - Inputs: Workflow/job runs + artifacts
  - Owner: Release Engineering - see `docs/ci/gates_runbooks.md`

- Report Presence Gate
  - Purpose: Ensure that when findings>0 or a report is expected, the AODS report exists and is structurally sound.
  - Inputs: `--manifest artifacts/run_manifest.json` (hint for expected report), `--report <path>`
  - Implementation: `tools/ci/gates/report_presence_gate.py`
  - Strict toggle: `AODS_REPORT_PRESENCE_STRICT=1` fails when the expected report is missing or unparseable
  - Owner: Release Engineering

- Decompilation Completeness Gate
- Non‑redaction Policy Gate
  - Purpose: Enforce that stored JSON artifacts (reports, SSE/WS event dumps, exports) do not contain redaction markers; masking belongs to UI only.
  - Inputs: `artifacts/**/*.json`, `scan_results/**/*.json` (configurable via `--glob`)
  - Implementation: `tools/ci/gates/non_redaction_gate.py`.
  - Strict toggle: always strict in CI; writes `artifacts/ci_gates/non_redaction/summary.json`.
  - Owner: Release Engineering

  - Purpose: Validate policy outputs (manifest/resources/imports) heuristically.
  - Inputs: AODS report JSON.
  - Owner: Static Analysis - see `docs/ci/gates_runbooks.md`

- Execution Path Gate
  - Purpose: Ensure single orchestrator path per run; detect mixed-path divergence.
  - Inputs: `artifacts/run_manifest.json` written by execution path guard.
  - Implementation: `tools/ci/gates/execution_path_gate.py`.
  - Strict toggle: `AODS_EXEC_PATH_STRICT=1` fails on missing manifest or divergence.
  - Owner: Architecture (Quality)

- External Tools Mode Gate
  - Purpose: Enforce static-only runs by denying dynamic tools (ADB/Frida) when hard mode is enabled.
  - Inputs: Scan log (`AODS_SCAN_LOG` or `scan_results/scan_log`).
  - Implementation: `tools/ci/gates/external_tools_mode_gate.py`.
  - Strict toggle: `AODS_STATIC_ONLY_HARD=1` fails when dynamic tool usage is detected.
  - Owner: Static/Dynamic Orchestration

- Calibration Quality Gate
  - Purpose: Enforce model calibration quality thresholds (ECE/MCE) and signal staleness.
  - Inputs: `AODS_ML_CALIBRATION_ENFORCE`, `AODS_ML_CALIBRATION_SUMMARY`, `AODS_ML_MAX_ECE`, `AODS_ML_MAX_MCE`, `AODS_ML_CALIBRATION_STALE_TTL_SEC`.
  - Checks: Parses calibration summary JSON; compares ECE/MCE to thresholds; skips on insufficient findings upstream; marks status `stale` when the summary file mtime exceeds TTL.
  - Owner: ML Platform
  - Optional: Compute true ECE/MCE from dataset via `AODS_ML_ECE_DATASET` using 10-bin ECE (bins configurable via `AODS_ML_ECE_BINS`).
  - Dashboard: An HTML summary can be generated and uploaded from `tools/ml/generate_ml_dashboard.py` (artifact at `artifacts/ml_datasets/metrics/dashboard.html`).


- Dedup Effectiveness Gate
  - Purpose: Ensure duplicate findings are consolidated effectively by the canonical aggregator.
  - Inputs: Latest AODS report JSON (falls back to synthetic if none found).
  - Implementation: `tools/ci/check_dedup_effectiveness.py` (wired into `plugin-audit` job non-strict).
  - Strict toggle: `AODS_DEDUP_CHECK_STRICT=1` fails CI if effectiveness < 0.90.
  - Owner: Architecture (Quality) - see `core/execution/shared/` aggregator and normalizer.

- E2E Skips Gate
  - Purpose: Prevent silent erosion of UI coverage by enforcing a maximum number of skipped Playwright tests.
  - Inputs: Playwright JSON report (`design/ui/react-app/playwright-report-*/report.json`).
  - Implementation: `tools/ci/gates/e2e_skips_gate.py`.
  - Threshold: `AODS_E2E_MAX_SKIPS` (default `0`); CI may set a temporary cushion while stabilizing.
  - Owner: UI Platform

- Roadmap Events Dedup Gate
  - Purpose: Prevent duplication of roadmap implementation events in the tracking document.
  - Inputs: `roadmap/Upgrade/UPGRADE_ROADMAP_TRACKING.md` (section: "Roadmap Event Ledger (deduplicated)")
  - Implementation: `tools/ci/gates/roadmap_events_dedup_gate.py`
  - Rule: All `EventID` entries (`EVT-YYYY-MM-DD-XXX`) must be unique; gate fails on duplicates.
  - Owner: Release Engineering

- UI Perf Gate (Frida 10k)
  - Purpose: Enforce performance budget for virtualized live events rendering.
  - Inputs: `artifacts/ui_perf/perf_metrics.json` produced by Playwright perf test.
  - Implementation: `tools/ci/gates/ui_perf_gate.py`.
  - Threshold: `AODS_UI_PERF_MAX_RENDER_MS` (default 12000ms).
  - Owner: UI Platform

Notes:
- Performance gates are opt-in in CI via `AODS_RUN_PERF=1`.

- UI Memoization Gate
  - Purpose: Ensure frequent UI toggles are memoized and cheap.
  - Inputs: `artifacts/ui_perf/perf_metrics.json` (`toggle_avg_ms`).
  - Implementation: `tools/ci/gates/ui_memoization_gate.py`.
  - Threshold: `AODS_UI_TOGGLE_MAX_AVG_MS` (default 15ms).
  - Owner: UI Platform

- ML Drift Gate
- Report Quality Gate (composite)
  - Purpose: Validate overall report quality without churn by composing existing checks.
  - Inputs: AODS report JSON (v1.0 required; optional v1.1 dual‑export when enabled).
  - Implementation: `tools/ci/gates/report_quality_gate.py` delegates to:
    - Schema validation (v1.1 optional), Evidence Completeness (extended with quality score), Non‑redaction, size/time checks.
  - Config: thresholds in `tools/ci/gates/config/gates.yml` (size_mb, max_time_sec, evidence_quality_min).
  - Transition: runs WARN‑only initially; moves to strict after stability window.

### Reporting: v1.1 Dual-Export Acceptance
- Purpose: Ensure presence and minimal shape of v1.1 wrapper alongside v1.0.
- Implementation: `tools/ci/gates/report_v11_acceptance_gate.py` (warn-only initially).
- Inputs: `artifacts/reports/report_v1_1.json` generated by `tools/reporting/export_report_v1_1.py`.
- Acceptance: `schema_version=1.1`, `metadata` keys present, embedded `report` object exists.

### Frida: Injection Policy (Safety-Strict)
### Frida Telemetry Summary
- Purpose: Provide a compact summary of recent Frida injection telemetry for PRs.
- Implementation: `tools/ci/gates/summarize_frida_telemetry.py` (best-effort; non-blocking).
- Inputs: `artifacts/frida/telemetry/events.jsonl`.
- Output: `artifacts/frida/telemetry/summary.json` consumed by PR summary.
- Retention: Telemetry file rotates by size (`AODS_FRIDA_TELEMETRY_MAX_MB`, default 5MB) and purges old rotated files by count (`AODS_FRIDA_TELEMETRY_MAX_ROTATED`, default 5) and age (`AODS_FRIDA_TELEMETRY_MAX_AGE_DAYS`, default 30 days).
### ML Version Stamps Gate
- Purpose: Ensure accuracy summary includes model/dataset/calibration stamps for traceability.
- Implementation: `tools/ci/gates/ml_version_stamps_gate.py` (warn-only).
- Inputs: `artifacts/ci_gates/detection_accuracy/summary.json`.
- Checks: `model_version/hash/id`, `dataset_vintage` (mtime/size/name), optional calibration stamp.

### Baseline Staleness Gate
- Purpose: Detect stale nightly baseline thresholds.
- Implementation: `tools/ci/gates/baseline_staleness_gate.py` (warn-only).
- Inputs: `artifacts/ml_baselines/**/thresholds.json`.
- Threshold: `--ttl-days` (default 14 days). Env override: `AODS_BASELINE_TTL_DAYS`.

### Accuracy Strict Mode
### Calibration Staleness Gate
- Purpose: Ensure calibration summary is updated within TTL.
- Implementation: `tools/ci/gates/calibration_staleness_gate.py` (warn-only).
- Inputs: `models/unified_ml/calibration_summary.json` (configurable via `AODS_ML_CALIBRATION_SUMMARY`).
- Threshold: `--ttl-days` (default 14 days). Env override: `AODS_CALIBRATION_TTL_DAYS`.

### Strict Promotion Suggester (Advisory)
- Purpose: Recommend enabling strict mode for gates that have been green for N runs.
- Implementation: `tools/ci/gates/promotion_suggester_gate.py` (warn-only, advisory).
- Inputs: Latest `ci_quality_gates_*.json`.
- Output: `artifacts/ci_gates/promotion_suggester/summary.json` with suggested gates.

See also: [Promotion Policy](promotion_policy.md)
- Purpose: Force accuracy gate to fail below thresholds regardless of `--warn-only`.
- Toggle: `AODS_ACCURACY_STRICT=1` or `--strict`.
- Purpose: Enforce allowed modes and require safety guard; safety violations hard-fail even in warn-only mode.
- Implementation: `tools/ci/gates/frida_injection_policy_gate.py` with `AODS_FRIDA_SAFETY_STRICT=1`.
- Inputs: `scan_results/scan_log` for observed modes and `safety_guard=` markers.
- Acceptance: No `safety_guard=disabled`; disallowed modes reported as WARN unless configured strict.

### MSTG Coverage Gate (warn-only → strict)
- Purpose: Enforce MASVS/MASTG coverage floors and detect regressions.
- Implementation: `tools/ci/gates/mstg_coverage_gate.py` (warn-only initially; strict via `AODS_MSTG_STRICT=1`).
- Inputs:
  - Rollup summary: `artifacts/compliance/mstg_coverage/summary.json` (executed/defined/manually-required counts; by-category percentages).
  - Baseline: `artifacts/compliance/mstg_coverage/baselines/<date>/summary.json` (for initial floors and regression comparisons).
- Floors:
  - Pilot: per-category/global floors = `baseline_pct - 0.05` (min caps and target caps apply per roadmap §0.4), warn-only.
  - Strict: eligible after ≥5 green runs meeting floors with no ≥5pp regressions; main/master only.
- PR Summary: Global %, per-category bars, top missing 10 tests, baseline date/SHA, and regression warnings.
- Acceptance:
  - SKIP when summary absent; WARN when below floors or regression detected; PASS when ≥ floors.
  - With `AODS_MSTG_STRICT=1` on main/master: FAIL on below-floor or regression conditions.

### Semgrep MASTG Coverage Gate (warn-only)
- Purpose: Ensure Semgrep findings are tagged with valid MSTG IDs and surface basic coverage signal.
- Implementation: `tools/ci/gates/semgrep_mastg_coverage_gate.py` (warn-only; strict via `--strict` or policy).
- Inputs:
  - Semgrep wrapper summary: `artifacts/ci_gates/semgrep/summary.json`
- Outputs:
  - `artifacts/ci_gates/semgrep/coverage_gate.json` with `status`, `mastg_ids_count`, and extracted IDs
- PR Summary: “Semgrep MASTG” section shows coverage_gate status and MSTG IDs count; also renders rules pin info when present.
- Notes:
  - Regex extraction supports `metadata.mstg_id`, message, and `check_id`.
  - Gate WARNs when no MSTG IDs detected or when Semgrep reports errors.

### MSTG Dynamic Mapping (Tracer Integration)
- Purpose: Map dynamic hook names to MSTG IDs for tracer events without inflating coverage by default.
- Config: `compliance/masvs_mstg/dynamic_map.json` (overridable via `AODS_MSTG_DYNAMIC_MAP`).
- Runtime: `core/compliance/mstg_dynamic_map.resolve_mstg_id(hook_name, payload)` prefers `payload['mstg_id']` when present.
- PR Summary: Shows a small sample and total entries when the map exists.
- Notes:
  - Tracer emits MANUAL status by default for dynamic hook events.
  - Keep mappings conservative and audited; avoid broad defaults.

### External Dynamic (MPT) - Informational (Shadow)
- Purpose: Surface artifacts and evidence from the optional Mobile Pentest Toolkit (MPT) runner when present.
- Artifacts: `artifacts/dynamic_external/mpt/` (logs, screenshots, `PROVENANCE.json`, normalized evidence JSON)
- Inputs: Enabled when `AODS_USE_MPT=1` and orchestrator produces artifacts for a sample APK.
- PR Summary: Adds an "External Dynamic (MPT)" section with short evidence snippets and a link to artifacts; non‑blocking.
- Acceptance:
  - When artifacts exist: PR summary includes MPT subsection; job completes.
  - When disabled or missing: job SKIP; no effect on other gates.

### Evidence Quality Gate
- What: Enforce minimum evidence quality across findings and limit duplicated evidence locations.
- Script: `tools/ci/gates/evidence_quality_gate.py`
- Inputs:
  - `--reports-dir` (default `artifacts/scans`)
  - Thresholds (env overrides):
    - `AODS_EVID_Q_MIN_AVG` (default 0.85)
    - `AODS_EVID_Q_MAX_DUPE` (default 0.20)
    - `AODS_EVID_Q_MIN_FP` (default 0.90)
    - `AODS_EVID_Q_MIN_LN` (default 0.80)
    - `AODS_EVID_Q_MIN_CS` (default 0.85)
    - `AODS_EVID_Q_MIN_TAX` (default 0.70)
- Acceptance:
  - PASS when average quality ≥ min, duplication ≤ max, and field ratios meet minima
  - FAIL otherwise; SKIP when no reports

### Governance Validators
- Pattern Registry Validator
  - Purpose: Validate `patterns/registry.yaml` required fields and uniqueness.
  - Implementation: `tools/ci/gates/pattern_registry_validator.py`
  - Acceptance: Gate passes with no errors; warnings permitted.
- RACI + Deprecation Validator
  - Purpose: Enforce governance policy (`governance.raci`) and deprecation lifecycle for registry entries.
  - Implementation: `tools/ci/gates/raci_deprecation_validator.py`
  - Config: `AODS_GOV_REQUIRE_RACI` (default 1 in CI), `AODS_GOV_MAX_LAST_REVIEWED_DAYS` (default 365)
  - Acceptance: No errors; with `--strict`, warnings also fail.

- ML Drift Gate
  - Purpose: Detect significant drift in confidence score distribution vs. baseline.
  - Inputs: Baseline/current confidence JSONs with `confidences` arrays.
  - Implementation: `tools/ci/gates/ml_drift_gate.py` using chi-square over `AODS_ML_DRIFT_BINS` (default 10); SKIP for small samples.
  - Threshold: `AODS_ML_DRIFT_MAX_CHI2` (default 18.3 ~ χ²(9) 95th percentile).
  - Artifacts: `artifacts/ci_gates/ml_drift/summary.json`.
  - PR Summary: Displays status, chi², and sample sizes.
  - Owner: ML Platform

- Flaky Tests Gate
  - Purpose: Prevent merging when new flaky tests appear; quarantine tracked flakes only.
  - Inputs: Playwright JSON report (`design/ui/react-app/playwright-report-dev/report.json`), optional baseline `tools/ci/gates/config/flaky_baseline.json`.
  - Implementation: `tools/ci/gates/flaky_tests_gate.py` (heuristics on mixed outcomes across runs).
  - Owner: UI Platform

- Cache Adoption Gate
  - Purpose: Detect local dict caches and encourage use of the unified cache manager.
  - Inputs: Source tree (Python files)
  - Implementation: `tools/ci/gates/cache_adoption_gate.py` (heuristic grep over assignments like `cache = {}` / `self._cache = {}`)
  - Strict toggle: `AODS_CACHE_ADOPTION_STRICT=1` fails on violations; default WARN in CI
  - Owner: Architecture (Performance)

- Determinism Thresholds Gate
  - Purpose: Ensure ML thresholds artifacts remain stable across runs.
  - Inputs: Two thresholds JSON files under `artifacts/ml_thresholds*.json`.
  - Implementation: `tools/ci/gates/determinism_thresholds_gate.py` with absolute per-key tolerance.
  - Owner: ML Platform

- Toggle Precedence and Local-run Flow
  - Precedence:
    - Explicit environment variables override unified configuration for CI gates (e.g., `AODS_MAX_HIGH`, `AODS_MAX_CRITICAL`, `AODS_ACCURACY_STRICT`).
    - When env vars are not set, UI-managed unified configuration toggles are honored (e.g., `/api/ci/toggles`: `failOnCritical`, `failOnHigh`, `dedupStrict`).
  - Local runs:
    - Use `python tools/ci/run_quality_gates_local.py` to execute gates locally; by default, env unset → unified config applies (matching UI toggles).
    - Dev UI (Vite): `UI_URL=http://127.0.0.1:5088`, API at `http://127.0.0.1:8088`; Prod UI served at `/ui` by FastAPI.
    - Recommended policy: set env vars only for temporary overrides; persist long-lived policy in unified config via the UI.

- ML Calibration Quality Gate
  - Purpose: Ensure calibration improves or maintains calibration error and stays within budgets.
  - Inputs: `models/unified_ml/calibration_summary.json` (and optional dataset for recompute).
  - Implementation: `tools/ci/gates/calibration_quality_gate.py`.
  - Thresholds: `AODS_ML_MAX_ECE` (default 0.05), `AODS_ML_MAX_MCE` (default 0.10); enforcement via `AODS_ML_CALIBRATION_ENFORCE=1`.
  - Family-aware options:
    - `AODS_ML_CALIBRATION_FAMILY`: prefer family-specific `calibration_summary.json` and thresholds
    - `AODS_ML_FAMILY_THRESHOLDS_JSON`: JSON map per-family (e.g. `{ "android": { "max_ece": 0.05, "max_mce": 0.10 } }`)
    - `AODS_ML_REQUIRE_FAMILY_CALIBRATOR`: require family calibrator artifact (e.g. `models/unified_ml/<family>/calibration.json`)
  - Owner: ML Platform

- Timeout Policy Gate
  - Purpose: Enforce an overall runtime ceiling and prohibit unexpected timeouts.
  - Inputs: Runtime metrics JSON (optional), scan log (optional).
  - Implementation: `tools/ci/gates/timeout_policy_gate.py`.
  - Strict toggle: `AODS_TIMEOUT_POLICY_STRICT=1` fails when inputs missing; thresholds via `AODS_MAX_TOTAL_RUNTIME_SEC` (default 1800) and `AODS_MAX_TIMEOUTS` (default 0).
  - Owner: Release Engineering

### Execution Stability Gate
- Purpose: Surface execution reliability (success-rate SLOs, timeouts, retries) and detect regressions.
- Inputs:
  - Structured runtime metrics (if present): `artifacts/ci_gates/runtime_metrics.json`
  - Log fallback: `scan_results/scan_log`
- Implementation: `tools/ci/gates/execution_stability_gate.py`
- Artifacts: `artifacts/ci_gates/execution_stability/summary.json` (success rate, timeout/error counts)
- Toggles:
  - `AODS_EXEC_STABILITY_MIN_SUCCESS` (default `0.99`)
  - `AODS_EXEC_STABILITY_STRICT=1` to fail when below SLO
  - Retry knobs (execution layer): `AODS_EXEC_RETRY_ATTEMPTS`, `AODS_EXEC_RETRY_MIN_SUCCESS`, `AODS_EXEC_RETRY_BACKOFF_MS`
- PR Summary: Adds “Execution Stability” section with success rate and counts
- Owner: Architecture (Reliability)

### Device Matrix Smoke (Infrastructure)
- Purpose: Surface Android tooling availability and connected devices (best-effort, non-blocking).
- Inputs: `adb devices -l`, `sdkmanager --list`, `avdmanager list avd`
- Implementation: `tools/ci/device_matrix_smoke.py`
- Artifacts: `artifacts/device_matrix/provisioning.json` (tooling availability, device_count, ready flag)
- Owner: Dynamic Analysis

### Device Readiness Gate
- Purpose: Enforce minimum ready devices when dynamic analysis is expected; advisory by default.
- Inputs: `artifacts/device_matrix/provisioning.json`
- Implementation: `tools/ci/gates/device_readiness_gate.py`
- Artifacts: `artifacts/ci_gates/device_readiness/summary.json`
- Toggles:
  - `AODS_DEVICE_MIN_READY` (default 0)
  - `AODS_DEVICE_STRICT=1` to fail when below minimum
- PR Summary: Shows readiness status and ready/total/min counts

### Dependency Validation Gate
- Purpose: Validate presence (and basic versions) of key dynamic analysis tools.
- Tools checked: `adb`, `aapt`, `frida`, `objection`, `flutter`, plus opportunistic `sdkmanager`, `avdmanager`
- Implementation: `tools/ci/gates/dependency_validation_gate.py`
- Artifacts: `artifacts/ci_gates/dependency_validation/summary.json`
- Toggles:
  - `AODS_DEP_VALIDATION_REQUIRED` (comma-separated list, e.g., `adb,aapt,frida`)
  - `AODS_DEP_VALIDATION_STRICT=1` to fail when any required tool is missing
- PR Summary: Shows status, required/missing lists, and a quick presence snapshot

### Execution SLO Gate (Track 7)
- Purpose: Validate plugin execution success rates against Service Level Objectives.
- Inputs: `artifacts/ci_gates/execution_slo/slo_summary.json` (from ExecutionSLOMonitor)
- Implementation: `tools/ci/gates/execution_slo_gate.py`
- Artifacts: `artifacts/ci_gates/execution_slo/gate_result.json`
- Checks:
  - Success rate vs target/warning/critical thresholds
  - Timeout budget not exceeded
  - Identifies plugins below SLO for targeted remediation
- Toggles:
  - `AODS_SLO_TARGET` (default 99.0) - Target success rate %
  - `AODS_SLO_WARNING` (default 97.0) - Warning threshold %
  - `AODS_SLO_CRITICAL` (default 95.0) - Critical threshold %
  - `AODS_SLO_TIMEOUT_BUDGET` (default 5.0) - Max timeout rate %
  - `AODS_SLO_STRICT=1` to fail on warnings (not just failures)
- PR Summary: Shows SLO status, success rate, and plugins below threshold
- Owner: Architecture (Reliability)

### Emulator Provisioning Gate (Track 7)
- Purpose: Validate Android emulator provisioning status and smoke test results.
- Inputs: `artifacts/device_matrix/provisioning.json` (from EmulatorProvisioningManager)
- Implementation: `tools/ci/gates/emulator_provisioning_gate.py`
- Artifacts: `artifacts/ci_gates/emulator_provisioning/gate_result.json`
- Checks:
  - Provisioning success
  - API level within configured range
  - Emulator state (running)
  - Smoke test pass rate (adb_shell, package_manager, activity_manager, frida_push, root_access)
- Toggles:
  - `AODS_EMU_MIN_API` (default 29) - Minimum API level
  - `AODS_EMU_MAX_API` (default 34) - Maximum API level
  - `AODS_EMU_SMOKE_PASS_RATE` (default 0.8) - Minimum smoke test pass rate
  - `AODS_EMU_REQUIRE_ROOT=1` to require root access smoke test
  - `AODS_EMU_STRICT=1` to fail on warnings
- PR Summary: Shows provisioning status, API level, and smoke test results
- Owner: Dynamic Analysis

### Unified Configuration Enforcement Gate
- Purpose: Flag ad-hoc environment/config reads and encourage unified configuration usage.
- Inputs: Source tree scan; allowlist of directories for legacy hotspots.
- Implementation: `tools/ci/gates/config_enforcement_gate.py`
- Artifacts: `artifacts/ci_gates/config_enforcement/summary.json` (status, total_violations, files_with_violations, violations list)
- Toggles:
  - `AODS_CONFIG_ENFORCE_STRICT=1` to fail when violations present
- PR Summary: Counts and top offenders with remediation hints

### Python Dependencies Gate
- Purpose: Consolidated Python dependencies management - inventory, vulnerability scanning, and SBOM generation.
- Implementation: `tools/ci/gates/python_deps_gate.py`
- Artifacts (all in `artifacts/python_sbom/`):
  - `python-deps.inventory.json` (pip inventory)
  - `python-deps-scan.json` (scan report summary)
  - `python-deps.cdx.json` (CycloneDX SBOM)
- Toggles:
  - `AODS_PYDEPS_STRICT=1` to fail when vulnerabilities detected
- PR Summary: Shows status and vulnerability counts by severity

### Determinism & Baselines: Toggles and Thresholds

- Determinism
  - Strict by default in CI. Tolerance percent via `AODS_DETERMINISM_TOLERANCE` (default `1.0`).
  - Local warn-only suggested for exploratory runs (handled in `LOCAL_GATE_SEQUENCE.sh` secondary leg).
  - Force enforcement even on small samples with `AODS_ENFORCE_ALWAYS=1`.

- Integration Coverage Minimum
  - Minimum findings before enforcement: `AODS_MIN_FINDINGS` (default `10`).
  - Rationale: avoid noisy decisions on tiny samples; logged as SKIP when below threshold.

- Baselines
  - Local scaffolding: `tools/ci/run_baseline_suite.py` to generate `artifacts/ml_baselines/<date>/summary.json`.
  - CI wiring: run baseline suite as a pre-step; accuracy/detection gates use latest baseline by default.

- Severity (Training Mode convenience)
  - Default CI policy: `AODS_MAX_HIGH=0`, `AODS_MAX_CRITICAL=0`.
  - Local/training convenience toggles: set `AODS_VULNERABLE_APP_MODE=1` or `AODS_TRAINING_MODE=1` to auto-allow up to 1 HIGH only when `AODS_MAX_HIGH` is not explicitly set. This prevents friction when validating intentionally vulnerable apps; CI remains strict by default.

### Artifacts Policy
- See `docs/ci/artifacts_policy.md` for what we upload in CI and why.

- A11Y Gate (optional)
  - Purpose: Verify required labels/roles are present in the UI.
  - Inputs: `artifacts/ui_a11y/a11y_summary.json` generated by Playwright smoke.
  - Implementation: `tools/ci/gates/a11y_gate.py`.
  - Strict toggle: `AODS_A11Y_STRICT=1` to fail build when required labels missing. Configure labels with `AODS_A11Y_REQUIRED_LABELS`.
  - Owner: UI Platform

### Planned Gates (Roadmap)

- (none currently)


