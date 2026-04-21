## Gates Runbooks, Owners, and SLAs

- Determinism Gate
  - Owner: Architecture (Quality)
  - SLA: Investigate within 24h; fix within 72h unless waived
  - Runbook: Re-run impacted jobs; compare cache keys and summaries; inspect nondeterministic sources (timestamps, ordering).

- Accuracy Gate (ML)
  - Owner: AI/ML
  - SLA: Investigate within 24h; mitigation plan within 48h
  - Runbook: Compare current vs baseline; inspect dataset drift; check model/calibrator versions; rollback or adjust thresholds if justified.

- Deprecation Gate
  - Owner: Architecture (Migration)
  - SLA: Same-day fix or suppression PR with justification
  - Runbook: Locate offending imports/paths; migrate to canonical modules; update allowlist only for transitional exceptions.

- Integration Gate
  - Owner: Release Engineering
  - SLA: 48h
  - Runbook: Ensure docs/scripts exist; verify artifacts directory structure; update workflow steps when docs change.

- Decompilation Completeness Gate
  - Owner: Static Analysis
  - SLA: 72h
  - Runbook: Check policy mode; confirm manifest/resources/imports presence; re-run with elevated flags or adjusted mode; document constraints.

- Dedup Effectiveness Gate
  - Owner: Architecture (Quality)
  - SLA: Investigate within 24h; mitigation within 72h or convert to non-strict temporarily with justification
  - Runbook:
    1. Run `python tools/ci/check_dedup_effectiveness.py` locally with the latest report. If none exists, generate a synthetic run.
    2. Inspect `duplicates_before/after` and effectiveness. Confirm `AODS_DEDUP_AGGREGATE=1` during scans.
    3. If below target, review normalizer/aggregator grouping keys, precedence, and evidence mapping.
    4. Add targeted precedence for underperforming plugins or improve normalization of titles/categories.
    5. Re-run and, once stable, enable `AODS_DEDUP_CHECK_STRICT=1` in CI.

- Execution Path Gate
  - Owner: Architecture (Quality)
  - SLA: Investigate within 24h; fix within 72h
  - Runbook:
    1. Check `artifacts/run_manifest.json` (or `AODS_RUN_MANIFEST_PATH` override). Ensure `execution_path` present and `divergence_detected=false`.
    2. If manifest missing, ensure orchestrator entry records via `ExecutionPathGuard` and that `APKContext` creation occurs on run.
    3. Scan logs (`--log` or `AODS_SCAN_LOG`) for mixed-path phrases. Remove or adapt legacy fallback triggers.
    4. Freeze path early in the chosen orchestrator (`canonical` or `enhanced`) and validate elsewhere.
    5. Re-run gate. Enable strict mode (`AODS_EXEC_PATH_STRICT=1`) once stable.

- External Tools Mode Gate
  - Owner: Static/Dynamic Orchestration
  - SLA: Investigate within 24h; fix within 72h
  - Runbook:
    1. Verify environment set for the job: `AODS_STATIC_ONLY_HARD=1` on static-only workflows.
    2. Run `python tools/ci/gates/external_tools_mode_gate.py` (set `AODS_SCAN_LOG` to scan log path).
    3. If FAIL, locate sources invoking ADB/Frida in static-only paths. Migrate to policy-aware calls or guard behind mode checks.
    4. Confirm `UnifiedToolExecutor` pre-check denies ADB/Frida under hard mode.
    5. Re-run gate; keep strict on static-only jobs.

- Skip-if-report-exists (New)
  - Owner: Release Engineering
  - Runbook:
    1. Use `--skip-if-report-exists --output <path>` to avoid rerunning scans when a report already exists.
    2. CI uses this flag in self-test and dedup baseline; see tools/ci/smoke_skip_if_report_exists.py.
    3. For local runs, set `AODS_SKIP_IF_REPORT_EXISTS=1` to enforce env-based early-exit.

- Dry Run (New)
  - Owner: Release Engineering
  - Runbook:
    1. Use `--dry-run` to print planned actions (apk, profile, mode, output) without executing a scan.

- Resource-Safe & WSL (Updated)
  - Owner: Architecture (Performance)
  - Runbook:
    1. Set `AODS_RESOURCE_SAFE=1` to force lightning profile and sequential mode.
    2. On WSL, resource-safe defaults disable ML and shrink cache tiers automatically.
    3. Override cache tiers via env: `AODS_CACHE_MEMORY_MB`, `AODS_CACHE_SSD_GB`, `AODS_CACHE_DISK_GB`.


