# AODS Feature Flag & Environment Variable Registry

**Created:** 2026-01-26
**Last updated:** 2026-03-11
**Scope:** All `AODS_*` environment variables across the codebase

---

## Overview

AODS uses environment variables as feature flags and configuration knobs. This registry documents every `AODS_*` variable with its purpose, default, and lifecycle status.

**Convention:** All project-specific variables use the `AODS_` prefix.

---

## Quick Reference: Most Important Variables

| Variable | Default | Category | Impact |
|----------|---------|----------|--------|
| `AODS_ADMIN_PASSWORD` | *(random if not set)* | Auth | Admin login credential |
| `AODS_AUTH_DISABLED` | `0` | Auth | Disables all authentication |
| `AODS_ENFORCE_TIMEOUTS` | `0` | Execution | Process-based timeout enforcement |
| `AODS_PARALLEL_WORKERS` | `1` | Execution | Parallel plugin worker count |
| `AODS_PLUGIN_DELAY` | `0.5` | Execution | Seconds between plugin executions |
| `AODS_BATCH_DELAY` | `0.5` | Execution | Seconds between plugin batches |
| `AODS_SCAN_FOCUSED` | `0` | Execution | Skip resource throttling |
| `AODS_DISABLE_ML` | `0` | ML | Disables all ML features |
| `AODS_STATIC_ONLY` | `0` | Analysis | Static-only mode (soft) |
| `AODS_ENTERPRISE_ENABLE` | `0` | Features | Enterprise RBAC/multi-tenant |

---

## 1. Authentication & Authorization

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_ADMIN_PASSWORD` | *(random if not set)* | string | Password for the `admin` user. Hashed with PBKDF2-SHA256 on startup. If not set, a random password is generated via `secrets.token_urlsafe(16)` and logged at startup. |
| `AODS_ANALYST_PASSWORD` | *(none)* | string | Password for the `analyst` user. Optional role. |
| `AODS_VIEWER_PASSWORD` | *(none)* | string | Password for the `viewer` user. Optional role. |
| `AODS_JWT_SECRET` | *(auto-generated)* | string | JWT signing secret. Auto-generated per server start if not set. |
| `AODS_JWT_EXPIRY_HOURS` | `24` | int | JWT token expiry in hours. |
| `AODS_AUTH_DISABLED` | `0` | bool | Set to `1` to bypass all authentication. **Dev/testing only.** |
| `AODS_WS_DEV_NOAUTH` | `0` | bool | Disables auth for WebSocket endpoints. **Dev only.** |
| `AODS_WS_ORIGIN_ALLOW_ALL` | `0` | bool | Allows all origins for WebSocket connections. |
| `AODS_ENTERPRISE_ENABLE` | `0` | bool | Enables enterprise features (RBAC, multi-tenant). |

**Files:** `core/api/server.py`, `core/api/auth_helpers.py`, `core/enterprise/rbac_manager.py`

---

## 2. UI & Server Configuration

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_UI_ORIGIN` | `http://127.0.0.1:5088` | URL | Primary UI origin for CORS allowlist. |
| `AODS_UI_ORIGIN_ALT` | `http://127.0.0.1:8088` | URL | Alternate UI origin for CORS. |
| `AODS_FRIDA_FORWARD_PORT` | `27042` | int | Port for Frida device forwarding. |
| `AODS_FRIDA_MODE` | `standard` | string | Frida execution mode. |

**Files:** `core/api/server.py`

---

## 3. Scan Execution & Timeouts

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_PARALLEL_WORKERS` | `1` | int | Number of parallel plugin workers. |
| `AODS_ENFORCE_TIMEOUTS` | `0` | bool | Use `multiprocessing.Process` for killable timeouts. |
| `AODS_PLUGIN_DELAY` | `0.5` | float | Seconds to sleep between plugin executions. |
| `AODS_BATCH_DELAY` | `0.5` | float | Seconds to sleep between plugin batches. |
| `AODS_SCAN_FOCUSED` | `0` | bool | Skip resource throttling (for testing/CI). |
| `AODS_PLUGIN_TIMEOUT_MAX_S` | `3600` | int | Maximum plugin timeout in seconds. |
| `AODS_EA_MIN_TIMEOUT_S` | `900` | int | Minimum timeout for extended analysis plugins. |
| `AODS_STATIC_PLUGIN_TIMEOUT_S` | `180` | int | Timeout for static analysis plugins. |
| `AODS_PROGRESS_HEARTBEAT_S` | `15` | int | Progress heartbeat interval. |
| `AODS_TOTAL_TIMEOUT_MAX_S` | `7200` | int | Maximum total scan timeout. |
| `AODS_MAX_MEMORY_MB` | `1536` | int | Maximum memory for plugin execution. |
| `AODS_MAX_EXTERNAL_PROCS` | *(auto)* | int | Maximum external tool processes. |
| `AODS_TOOL_EXECUTOR_THREADS` | *(auto)* | int | Thread count for tool executor. |
| `AODS_NO_THREADS` | `0` | bool | Disables all threading. |
| `AODS_SINGLE_RUN_LOCK` | `0` | bool | Prevents concurrent scans. |
| `AODS_SINGLE_RUN_LOCK_SKIP` | `1` | bool | Skips single-run lock check. |
| `AODS_EXEC_RETRY_ATTEMPTS` | `0` | int | Plugin execution retry attempts. |
| `AODS_EXEC_RETRY_BACKOFF_MS` | `250` | int | Retry backoff in milliseconds. |
| `AODS_EXEC_RETRY_MIN_SUCCESS` | `0.99` | float | Min success rate before retries stop. |

**Files:** `core/plugins/unified_manager.py`, `dyna.py`, `core/cli/execution_parallel.py`, `core/cli/execution_setup.py`

---

## 4. Analysis Mode Configuration

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_STATIC_ONLY` | `0` | bool | Enables static-only mode (soft enforcement). |
| `AODS_STATIC_ONLY_HARD` | `0` | bool | Hard-blocks all dynamic analysis. |
| `AODS_DISABLE_FRIDA` | *(none)* | bool | Disables Frida framework entirely. |
| `AODS_DISABLE_DROZER` | `1` | bool | Disables Drozer dynamic analysis. |
| `AODS_ENABLE_DROZER` | `0` | bool | Enables Drozer (overrides disable). |
| `AODS_FAST_MODE` | *(set to 1)* | bool | Enables fast scan profile. |
| `AODS_MAX_FILES` | `200` | int | Maximum files to process in fast mode. |
| `AODS_BATCH_SIZE` | `25` | int | Batch size for file processing. |
| `AODS_RESOURCE_CONSTRAINED` | `0` | bool | Enables resource-constrained mode. |
| `AODS_MINIMAL_MODE` | `0` | bool | Enables minimal resource mode. |
| `AODS_RESOURCE_SAFE` | `0` | bool | Enables resource-safe mode. Forces lightning profile (12 plugins) and disables ML unless `AODS_DISABLE_ML=0` is explicitly set. |
| `AODS_PLUGIN_MULTIPROCESS` | `auto` | string | Plugin execution mode: `1`=multiprocess (hard killable timeouts), `0`=threading, `auto`=enable for lightning profile. |
| `AODS_PERFORMANCE_MODE` | `1` | bool | Enables performance optimizations. |
| `AODS_MANIFEST_ONLY` | `0` | bool | Analyzes only AndroidManifest.xml. |
| `AODS_NON_INTERACTIVE` | `0` | bool | Non-interactive mode (no prompts). |
| `AODS_SKIP_IF_REPORT_EXISTS` | `0` | bool | Skips scan if report already exists. |

**Files:** `core/external/unified_tool_executor.py`, `core/api/server.py`, `core/cli/execution_setup.py`, `dyna.py`

---

## 5. ML & Model Configuration

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_DISABLE_ML` | `0` | bool | Disables all ML features. |
| `AODS_ML_CALIBRATION_ENABLE` | `1` | bool | Enables ML confidence calibration. |
| `AODS_ML_CALIBRATION_ENFORCE` | `0` | bool | Enforces calibration quality gate. |
| `AODS_ML_CALIBRATOR_PATH` | `models/unified_ml/calibration.json` | path | Path to ML calibrator model. |
| `AODS_ML_CALIBRATION_SUMMARY` | `models/unified_ml/calibration_summary.json` | path | Path to calibration summary. |
| `AODS_ML_CALIBRATION_STALE_TTL_SEC` | `604800` (7 days) | int | Stale calibration TTL in seconds. |
| `AODS_ML_MAX_ECE` | `0.1` | float | Maximum expected calibration error. |
| `AODS_ML_MAX_MCE` | `0.2` | float | Maximum calibration error. |
| `AODS_ML_THRESHOLD_AUTO` | `1` | bool | Auto-adjusts ML thresholds. |
| `AODS_ML_THRESHOLD_VENDOR` | `0.10` | float | ML threshold for vendor libraries. |
| `AODS_ML_THRESHOLD_MIXED` | `0.12` | float | ML threshold for mixed code. |
| `AODS_ML_THROTTLED_MODE` | `1` | bool | Throttled ML processing. |
| `AODS_ML_FP_THRESHOLD` | `0.15` | float | ML false-positive filtering threshold. |
| `AODS_ML_ENABLE_CALIBRATION` | `1` | bool | Enables ML probability calibration. |
| `AODS_ML_CACHE` | `1` | bool | Enables ML model caching. |
| `AODS_ML_FAMILY` | *(none)* | string | ML model family identifier. |
| `AODS_ML_THRESHOLDS_PATH` | *(none)* | path | Path to ML thresholds file. |
| `AODS_ML_FAMILIES` | `android` | string | ML model families (comma-separated). |
| `AODS_CURATION_USE_LABELS` | `1` | bool | Uses curation labels for ML. |
| `AODS_THREAT_MODEL_DIR` | *(none)* | path | Directory for threat models. |

**Files:** `core/api/server.py`, `core/ml/unified_pipeline.py`, `core/ml/*.py`, `dyna.py`

---

## 6. Frida Dynamic Analysis

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_FRIDA_TIMEOUT` | *(none)* | int | Frida execution timeout. |
| `AODS_FRIDA_SHADOW_MODE` | `0` | bool | Enables shadow mode testing. |
| `AODS_FRIDA_TELEMETRY` | `1` | bool | Enables Frida telemetry logging. |
| `AODS_FRIDA_TELEMETRY_PATH` | *(auto)* | path | Telemetry events file path. |
| `AODS_FRIDA_TELEMETRY_MAX_MB` | `5` | int | Max telemetry file size (MB). |
| `AODS_FRIDA_TELEMETRY_MAX_ROTATED` | `5` | int | Max rotated telemetry files. |
| `AODS_FRIDA_TELEMETRY_MAX_AGE_DAYS` | `30` | int | Max telemetry file age (days). |
| `AODS_FRIDA_TELEMETRY_SAMPLE_RATE` | `1.0` | float | Telemetry sampling rate (0-1). |
| `AODS_FRIDA_TELEMETRY_ALLOWLIST` | *(none)* | path | Path to telemetry allowlist file. |
| `AODS_FRIDA_TELEMETRY_ALLOW_KEYS` | *(none)* | string | Comma-separated allowed telemetry keys. |
| `AODS_FRIDA_CANARY_PERCENT` | `0` | int | Canary testing percentage. |
| `AODS_FRIDA_PLANNER_SEED` | *(none)* | int | Seed for reproducible test planning. |
| `AODS_FRIDA_ANALYZER_ENABLE` | `0` | bool | Enables Frida analyzer endpoint. |
| `AODS_AI_FRIDA_ENABLE` | `0` | bool | Enables AI-assisted Frida. |
| `AODS_AI_FRIDA_ML_ENABLE` | `0` | bool | Enables ML for AI Frida. |
| `AODS_AI_FRIDA_MODEL_PATH` | *(none)* | path | Path to AI Frida model. |
| `AODS_AI_FRIDA_MAX` | `2` | int | Max AI Frida suggestions. |
| `AODS_AI_FRIDA_MIN_SCORE` | `0.6` | float | Min score for AI Frida suggestions. |

**Files:** `plugins/frida_dynamic_analysis/*.py`, `core/frida/*.py`, `core/frida_framework/*.py`

---

## 7. Static Analysis Configuration

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_STATIC_MAX_FILE_SIZE` | *(none)* | int | Max file size for static analysis (bytes). |
| `AODS_VULN_PATTERNS_CONFIG` | *(none)* | path | Path to vulnerability patterns config. |
| `AODS_STATIC_INCLUDE_GLOBS` | *(none)* | string | Glob patterns to include in analysis. |
| `AODS_SCAN_PROFILE` | `standard` | string | Scan profile selection: `lightning` (12 plugins), `fast` (18), `standard` (40), `deep` (48). |
| `AODS_APP_PROFILE` | `production` | string | Application profile (`production` or `vulnerable`). Affects ML thresholds. |
| `AODS_VULN_PATTERNS_FILE` | *(none)* | path | Path to vulnerability patterns file. |

**Files:** `plugins/enhanced_static_analysis/static_analyzer.py`, `plugins/jadx_static_analysis/__init__.py`

---

## 8. APK & Package Filtering

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_FILTER_SUPPORT_LIBS` | `0` | bool | Filters out Android support libraries. |
| `AODS_INCLUDE_PACKAGES` | *(none)* | string | Comma-separated packages to include. |
| `AODS_EXCLUDE_PACKAGES` | *(none)* | string | Comma-separated packages to exclude. |
| `AODS_FILE_SAMPLE_RATE` | `1` | float | File sampling rate (0.0-1.0). |
| `AODS_FILE_MAX` | `0` | int | Max files to analyze (0 = unlimited). |
| `AODS_STRICT_APK_VALIDATION` | *(none)* | bool | Strict APK format validation. |
| `AODS_CURRENT_APK` | *(set at runtime)* | path | Current APK being scanned. |
| `AODS_APK_PATH` | *(none)* | path | APK file path (fallback). |

**Files:** `core/apk_ctx.py`, `core/graceful_shutdown_manager.py`

---

## 9. Output & Reporting

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_OUTPUT_PATH` | *(none)* | path | Path for output report. |
| `AODS_OUTPUT_FORMAT` | `json` | string | Output format (json, html, pdf). |
| `AODS_REPORT_GLOB` | `reports/*aods*.json` | glob | Glob pattern for report files. |
| `AODS_REPORT_FILTER_BY_THRESHOLDS` | `0` | bool | Filters findings by ML thresholds. |
| `AODS_REPORT_STRICT_LOCATIONS` | `0` | bool | Strict location inference in reports. |
| `AODS_REFERENCE_ONLY` | `0` | bool | Generates reference-only report. |
| `AODS_EXPECTED_REPORT_PATH` | *(none)* | path | Expected report path for CI validation. |
| `AODS_ENCRYPTION_PROVIDER` | `noop` | string | Report encryption provider. |
| `AODS_ENCRYPTION_KEY_B64` | *(none)* | string | Base64-encoded encryption key. |
| `AODS_TENANT_ID` | `default` | string | Tenant identifier for reports. |
| `AODS_MAPPING_SOURCES_PATH` | `configs/security_framework_mappings.yml` | path | Security framework mappings file. |

**Files:** `core/reporting/*.py`, `core/graceful_shutdown_manager.py`

---

## 10. False Positive Filtering

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_FILTER_ML_FORCE` | `0` | bool | Forces ML-based filtering. |
| `AODS_FILTER_USE_CANONICAL_FP` | `1` | bool | Uses canonical FP filter. |
| `AODS_SECURITY_USE_CANONICAL_FP` | `1` | bool | Uses canonical FP in security analysis. |
| `AODS_AUTO_INIT_FP_REDUCER` | `true` | bool | Auto-initializes FP reducer singleton. |
| `AODS_DISABLE_RUNTIME_FP_FILTER` | *(none)* | bool | Disables runtime FP filter. |
| `AODS_DISABLE_THREAT_ANALYSIS` | `0` | bool | Disables threat analysis phase. |
| `AODS_DISABLE_THREAT_INTEL_AUTOPATCH` | *(none)* | bool | Disables threat intel autopatch. |

**Files:** `core/fp_reducer.py` (canonical 3-stage pipeline: `NoiseSourceDampener` → `OptimizedMLFalsePositiveReducer` → heuristic rules)

---

## 11. Decompilation

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_DECOMP_OUT` | `/tmp/jadx_decompiled` | path | Decompilation output directory. |
| `AODS_DECOMPILATION_MODE` | *(none)* | string | Decompilation strategy mode. |
| `AODS_PROFILE` | `production` | string | JADX profile selection. |

**Files:** `core/decompilation_policy_resolver.py`, `core/shared_infrastructure/jadx_unified_helper.py`

---

## 12. Caching & Performance

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_CACHE_MEMORY_MB` | *(none)* | int | Memory cache size in MB. |
| `AODS_CACHE_SSD_GB` | *(none)* | float | SSD cache size in GB. |
| `AODS_CACHE_DISK_GB` | *(none)* | float | Disk cache size in GB. |
| `AODS_DISABLE_SQLITE_CACHE` | `0` | bool | Disables SQLite result cache. |
| `AODS_PLUGIN_REGISTRY_TTL_S` | `86400` | int | Plugin registry cache TTL (seconds). |
| `AODS_PLUGIN_REGISTRY_V3` | `0` | bool | Uses plugin registry V3. |
| `AODS_PLUGIN_REGISTRY_V3_SHADOW` | `1` | bool | Shadow verification for V3. |
| `AODS_PATTERN_CACHE_MAX` | `1000` | int | Max entries in pattern cache. |

**Files:** `core/shared_infrastructure/performance/caching_consolidation.py`, `core/plugins/unified_manager.py`

---

## 13. Deduplication

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_DEDUP_AGGREGATE` | `0` | bool | Aggregates dedup results. |
| `AODS_DEDUP_OVERRIDES` | `{}` | JSON | Override dedup config per plugin. |
| `AODS_DEDUP_SIMILARITY` | *(none)* | float | Dedup similarity threshold. |
| `AODS_DEDUP_CHECK_STRICT` | `0` | bool | Strict dedup CI validation. |
| `AODS_DEDUP_PERF_STRICT` | `0` | bool | Strict dedup performance checks. |
| `AODS_DEDUP_PERF_MAX_MS` | `750.0` | float | Max dedup latency (ms). |

**Files:** `core/unified_deduplication_framework/`, `core/reporting/unified_reporting_manager.py`

---

## 14. A/B Testing & Gradual Rollout

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_WEBVIEW_HARDENING_AUTO` | `1` | bool | Auto webview hardening. |
| `AODS_WEBVIEW_HARDENING_FORCE` | `0` | bool | Forces webview hardening. |
| `AODS_WEBVIEW_HARDENING_AB_PCT` | `0.25` | float | A/B test percentage for webview. |
| `AODS_PATTERN_CONTEXT_AB_PCT` | `1` | float | A/B test percentage for pattern context. |
| `AODS_PATTERN_CONTEXT_FORCE` | `0` | bool | Forces pattern context. |

**Files:** `core/enhanced_vulnerability_reporting_engine.py`

---

## 15. CI Quality Gates (Strict Mode Flags)

All CI gate strict flags default to `0` (warn-only). Set to `1` to make failures block the pipeline.

| Variable | Default | Description |
|----------|---------|-------------|
| `AODS_SEVERITY_BLOCK` | `1` | Block on severity violations |
| `AODS_MASVS_STRICT` | `1` | Strict MASVS validation |
| `AODS_ACCURACY_STRICT` | `0` | Strict accuracy validation |
| `AODS_DEVICE_STRICT` | `0` | Strict device readiness |
| `AODS_TIMEOUT_POLICY_STRICT` | `0` | Strict timeout policy |
| `AODS_DEPRECATED_MODULES_STRICT` | `1` | Strict deprecated modules |
| `AODS_EXEC_STABILITY_STRICT` | `0` | Strict execution stability |
| `AODS_BASELINE_STALE_STRICT` | `0` | Strict baseline staleness |
| `AODS_CACHE_ADOPTION_STRICT` | `0` | Strict cache adoption |
| `AODS_DEPRECATION_STRICT` | `0` | Strict deprecation |
| `AODS_REPORT_PRESENCE_STRICT` | `0` | Strict report presence |
| `AODS_A11Y_STRICT` | `0` | Strict accessibility |
| `AODS_DEP_VALIDATION_STRICT` | `0` | Strict dependency validation |
| `AODS_REGISTRY_V3_SHADOW_STRICT` | `0` | Strict registry V3 shadow |

**Files:** `tools/ci/gates/*.py`

---

## 16. CI Quality Gate Thresholds

| Variable | Default | Description |
|----------|---------|-------------|
| `AODS_ACCURACY_MIN_PRECISION` | `0.90` | Min precision for accuracy gate |
| `AODS_ACCURACY_MIN_RECALL` | `0.85` | Min recall for accuracy gate |
| `AODS_FP_THRESHOLD` | *(config)* | FP threshold |
| `AODS_FP_MAX_RATE` | *(config)* | Max FP rate |
| `AODS_MAX_F1_DELTA` | `0.02` | Max F1 score delta between runs |
| `AODS_MAX_PRECISION_DELTA` | `0.02` | Max precision delta |
| `AODS_MAX_RECALL_DELTA` | `0.02` | Max recall delta |
| `AODS_MAX_TOTAL_RUNTIME_SEC` | `1800` | Max total scan runtime (sec) |
| `AODS_MAX_TIMEOUTS` | `0` | Max allowed timeouts |
| `AODS_E2E_MAX_SKIPS` | `0` | Max allowed E2E test skips |
| `AODS_EVID_MIN_CODE` | `0.90` | Min code evidence score |
| `AODS_EVID_MIN_LINE` | `0.85` | Min line evidence score |
| `AODS_EVID_MIN_PATH` | `0.90` | Min path evidence score |
| `AODS_EVID_MIN_TAX` | `0.95` | Min taxonomy evidence score |
| `AODS_EVIDENCE_MIN_ALL` | `0.85` | Min overall evidence score |
| `AODS_EVIDENCE_MIN_FIELD` | `0.90` | Min per-field evidence score |
| `AODS_EVIDENCE_MIN_QUALITY` | `0.85` | Min evidence quality score |

**Files:** `tools/ci/gates/*.py`

---

## 17. Monitoring & Compliance

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_MONITORING_CONFIG` | `config/monitoring.yaml` | path | Monitoring configuration path. |
| `AODS_MSTG_TRACING` | `0` | bool | Enables MSTG compliance tracing. |
| `AODS_MSTG_EVENTS` | `artifacts/compliance/mstg_coverage/events.jsonl` | path | MSTG events output path. |
| `AODS_MSTG_DYNAMIC_MAP` | *(none)* | path | MSTG dynamic mappings path. |
| `AODS_MSTG_BASELINES_DIR` | `artifacts/compliance/mstg_coverage/baselines` | path | MSTG baselines directory. |
| `AODS_ENABLE_GDPR` | *(none)* | bool | Enables GDPR compliance mode. |
| `AODS_GDPR` | `auto` | string | GDPR handling mode. |

**Files:** `core/compliance/*.py`, `core/shared_infrastructure/monitoring/*.py`

---

## 18. Environment & Debug

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_ENVIRONMENT` | `production` | string | Environment identifier. |
| `AODS_DEBUG` | `false` | bool | Enables debug output. |
| `AODS_TEMP_DIR` | `/tmp/aods` | path | Temporary directory. |
| `AODS_DI_DEBUG` | `0` | bool | Dependency injection debug. |
| `AODS_DEBUG_ML_SINGLETON` | *(none)* | bool | Debug ML singleton lifecycle. |
| `AODS_DEBUG_PLUGIN_DISCOVERY` | *(none)* | bool | Debug plugin discovery. |
| `AODS_FALLBACK_WARN` | `0` | bool | Fallback logger warning level. |
| `AODS_TESTING_MODE` | *(none)* | bool | Testing mode flag. |
| `AODS_TEST_MODE` | `1` | bool | Sets performance test mode. |

**Files:** `core/unified_config.py`, `dyna.py`

---

## 19. Agent System

Controls the optional LLM-powered agent subsystem. All agents are disabled by default (`AODS_AGENT_ENABLED=0`) and can be fully omitted at runtime without architectural changes.

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_AGENT_ENABLED` | `0` | bool | Enables the agent system (all agent types). |
| `AODS_AGENT_PROVIDER` | `anthropic` | string | LLM provider: `anthropic`, `openai`, or `ollama` (Ollama uses the OpenAI-compatible API). |
| `AODS_AGENT_API_KEY_ENV` | *(none)* | string | Name of the env var holding the LLM API key (e.g., `ANTHROPIC_API_KEY`). |
| `AODS_AGENT_BASE_URL` | *(none)* | URL | Custom base URL for LLM API (for Ollama or proxies). |
| `AODS_AGENT_MODEL` | *(provider default)* | string | Model name override (provider-specific). |
| `AODS_AGENT_MAX_ITERATIONS` | `10` | int | Maximum agent loop iterations per task. |
| `AODS_AGENT_COST_LIMIT` | *(none)* | float | Token budget / cost cap for the agent pipeline supervisor. |
| `AODS_AGENT_TASK_DB` | `data/agent_tasks.db` | path | SQLite database path for agent task persistence. |

**Notes:**
- Triage and remediation agents automatically fall back to heuristic mode when no API key is available.
- Provider can also be set via `provider:` in `config/agent_config.yaml`.
- CLI flags: `--agent-narrate`, `--agent-verify`, `--agent-orchestrate`, `--agent-triage`, `--agent-remediate`, `--agent-pipeline`.

**Files:** `core/agent/`, `config/agent_config.yaml`, `core/api/routes/agent.py`, `core/agent/state.py`

---

## 20. Vector Database

Controls the optional ChromaDB-backed semantic similarity index. Disabled by default (`AODS_VECTOR_DB_ENABLED=0`).

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_VECTOR_DB_ENABLED` | `0` | bool | Enables ChromaDB vector index for semantic finding search. |
| `AODS_VECTOR_DB_PATH` | `data/vector_index/` | path | ChromaDB storage directory. |
| `AODS_EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | string | Sentence-transformer model name for embeddings. |
| `AODS_DISABLE_EMBEDDINGS` | `0` | bool | Disables embedding generation entirely (no vector indexing). |
| `AODS_VECTOR_CACHE_SIZE` | `10000` | int | Maximum number of entries in the embedding cache. |
| `AODS_VECTOR_SNIPPET_MAX` | `500` | int | Maximum code snippet characters used for embedding. |

**Notes:**
- ChromaDB uses SQLite internally and is **not safe for multi-worker deployments**. Always use single-process uvicorn (`--workers 1`) when enabled.
- API endpoints (require `AODS_VECTOR_DB_ENABLED=1`): `POST /api/vector/findings/similar`, `GET /api/vector/index/status`, `POST /api/vector/index/rebuild`.

**Files:** `core/vector_db/`, `core/api/routes/` (vector_search route)

---

## 21. Structured Logging

Controls log output format and verbosity via `structlog`. All modules use a graceful import pattern that falls back to stdlib `logging` if `structlog` is unavailable.

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `AODS_LOG_FORMAT` | `auto` | string | Log format: `json` (production), `console` (dev), `auto` (detects TTY - console if interactive, JSON otherwise). |
| `AODS_LOG_LEVEL` | `INFO` | string | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR`. |
| `AODS_LOG_INCLUDE_TIMESTAMP` | `1` | bool | Includes ISO 8601 timestamp in each log entry. |

**Files:** `core/logging_config.py`

---

## Lifecycle States

| State | Meaning | Action Required |
|-------|---------|-----------------|
| **Active** | In use, fully supported | None |
| **Experimental** | May change without notice | Monitor for changes |
| **Deprecated** | Will be removed | Migrate to replacement |
| **Internal** | For development/debugging only | Do not use in production |

---

## Common Configurations

### CI Pipeline (Strict)
```bash
export AODS_SEVERITY_BLOCK=1
export AODS_MASVS_STRICT=1
export AODS_ACCURACY_STRICT=1
export AODS_SCAN_FOCUSED=1
export AODS_PLUGIN_DELAY=0
export AODS_BATCH_DELAY=0
```

### Development (Permissive)
```bash
export AODS_AUTH_DISABLED=1
export AODS_DEBUG=true
export AODS_DI_DEBUG=1
export AODS_ENVIRONMENT=development
```

### Static-Only Scan
```bash
export AODS_STATIC_ONLY=1
export AODS_DISABLE_FRIDA=1
export AODS_DISABLE_DROZER=1
```

### Resource-Constrained Environment
```bash
export AODS_RESOURCE_CONSTRAINED=1
export AODS_MAX_MEMORY_MB=512
export AODS_MAX_FILES=100
export AODS_BATCH_SIZE=10
export AODS_PARALLEL_WORKERS=1
```

### Fast Scan Mode
```bash
export AODS_FAST_MODE=1
export AODS_MAX_FILES=200
export AODS_BATCH_SIZE=25
export AODS_PLUGIN_DELAY=0
export AODS_BATCH_DELAY=0
```

---

**Total variables cataloged:** 220+
**Last updated:** 2026-03-11
