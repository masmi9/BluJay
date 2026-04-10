# AODS System Architecture Overview

## High-Level Architecture

```
dyna.py (thin entry point, ~200 lines) --> core/cli/ (17 modules)
    |
    +-- [1] Startup: MITRE integrity check -> venv enforcement -> ML env setup
    +-- [2] APKContext creation (core/apk_ctx.py)
    +-- [3] Plugin discovery via ScanProfileManager (selects plugin subset)
    +-- [4] Plugin execution (66 v2 analyzers, parallel with semaphore)
    +-- [5] ML post-processing: confidence calibration -> FP reduction -> explainability
    +-- [6] Agent analysis (optional): triage -> verify -> remediate -> narrate
    +-- [7] Multi-format report generation (JSON, HTML, CSV, TXT)
```

## Core Subsystems

### Plugin System (`plugins/`, `core/plugins/`)

- **66 v2 security analyzers** loaded by scan profile
- Primary interface: `BasePluginV2` with `PluginFinding` dataclass (17 fields)
- Canonical import: `from core.plugins import PluginManager, create_plugin_manager`
- Plugin manager: `core/plugins/unified_manager.py`
- Timeout protection per plugin; global process semaphore caps concurrency
- Multiprocess mode available for hard timeout enforcement (lightning profile default)

### Scan Profiles

| Profile | Plugins | Time | Use Case |
|---------|---------|------|----------|
| `lightning` | 12 | ~30s | CI/CD gates, quick triage |
| `fast` | 18 | ~2-3min | Development, pre-commit |
| `standard` | 43 | ~5-8min | Security review, audit |
| `deep` | 48+ (all) | ~15+min | Penetration testing |

### Analysis Context (`core/apk_ctx.py`)

- `APKContext` is the central context object holding APK paths, analysis state, and device info
- Thread-safe with `_cache_lock`; each analysis gets a unique `analysis_id`
- Created in `dyna.py` (CLI) and `core/api/server.py` (API)

### External Tool Execution (`core/external/unified_tool_executor.py`)

- Single abstraction for ADB, JADX, Frida, AAPT, Python subprocesses
- Global semaphore (`AODS_MAX_EXTERNAL_PROCS`), per-tool timeouts with process tree cleanup
- Resource monitoring (memory limits, peak tracking), retry with exponential backoff
- JADX timeout: 240s for standard profile (Track 108-110 hardening)

### ML Pipeline (`core/ai_ml/`, `core/ml/`)

```
Feature Extraction -> Model Selection -> Prediction -> Calibration
                                                          |
                                     FP Reduction <- Confidence Score
                                                          |
                                  Explainability -> Final Output
```

- Models stored in `models/` (sklearn ensembles: RF, GB, MLP)
- Confidence calibration via isotonic/Platt/temperature scaling
- Explainability via `ExplainabilityFacade` (SHAP/LIME, confidence, rule-based)
- ML drift gate enforcement: `tools/ci/gates/ml_drift_gate.py` compares confidence distributions via chi-square test (`AODS_ML_DRIFT_MAX_CHI2`, default 18.3)
- Can be fully disabled with `AODS_DISABLE_ML=1`

### FP Reduction (`core/fp_reducer.py`)

Canonical 3-stage pipeline (Track 112):
1. **NoiseSourceDampener** - filters noisy plugin sources
2. **OptimizedMLFalsePositiveReducer** - trained 8-classifier ensemble
3. **Heuristic rules** - pattern-based final filtering

Single call site in `execution_parallel.py`.

### API Layer (`core/api/server.py`)

- FastAPI with 9 route modules in `core/api/routes/`:
  - `scans.py` - scan start, progress, cancel, results
  - `frida.py` - Frida console and dynamic analysis
  - `ml.py` - ML model management and metrics
  - `dev.py` - development utilities and feature flags
  - `admin.py` - user management, RBAC administration
  - `vector_search.py` - ChromaDB semantic search (conditional)
  - `agent.py` - AI agent tasks and pipeline (conditional)

- SSE streaming: `/scans/{id}/progress/stream`, `/scans/{id}/logs/stream`, `/batch/{id}/status/stream`
  - Accept auth via `Authorization: Bearer` header OR `?token=` query param
  - Heartbeat comments every ~30s for TCP keepalive
- WebSocket: `/api/frida/ws` for real-time Frida console
- RBAC: 5 roles (admin, analyst, viewer, auditor, api_user) via `core/enterprise/rbac_manager.py`
- Auth: Opaque bearer tokens with PBKDF2-SHA256 password hashing, 24h expiry

### Agent System (`core/agent/`, optional)

Disabled by default (`AODS_AGENT_ENABLED=0`). LLM-agnostic via providers (Anthropic, OpenAI, Ollama).

**6 specialized agents:**
1. **Triage** (`triage.py`) - finding classification (Critical Path, Quick Wins, etc.)
2. **Verification** (`verification.py`) - dynamic confirmation via Frida
3. **Remediation** (`remediation.py`) - CWE-specific code patch generation
4. **Narration** (`narration.py`) - structured Narrative output (risk ratings, attack chains)
5. **Orchestration** (`orchestration.py`) - pre-scan intelligent plugin selection
6. **Pipeline** (`supervisor.py`) - sequential: triage -> verify -> remediate -> narrate

**Key features:**
- Per-agent tool filtering via `_AGENT_TOOL_ALLOWLIST`
- Heuristic fallback: triage/remediation work without LLM API key
- Vector DB integration: agent tools use `get_semantic_finding_index()` singleton
- Observability: shared `output_parser.py`, token metrics, pipeline step SSE observations
- Task persistence: SQLite database at `data/agent_tasks.db` (`core/agent/state.py`) survives server restarts
- Config: `config/agent_config.yaml`
- API routes: `core/api/routes/agent.py`
- Triage feedback export: `GET /api/agent/triage/feedback/export` (admin, analyst)

### EVRE (Enhanced Vulnerability Reporting Engine)

- `core/evre/` - 13 files (10 mixins + `__init__.py`, `_dataclasses.py`, `_dynamic_package_filter.py`)
- Composes `EnhancedVulnerabilityReportingEngine` from 10 mixins (~5K lines)
- `core/enhanced_vulnerability_reporting_engine.py` is a 13-line re-export shim

### Report Pipeline

Two stages:
1. **`UnifiedReportingManager._apply_vulnerability_first_processing()`** - hot path during scan (dedup, confidence, noise filtering)
2. **`serialize_final_report()`** in `final_report_serializer.py` - runs after report is saved

### Vector Search (`core/vector_db/`)

- ChromaDB-based semantic similarity search
- Single-worker uvicorn only (SQLite backend)
- Enabled via `AODS_VECTOR_DB_ENABLED=1`
- Agent tools write-back to vector DB for triage/remediation context

### React Frontend (`design/ui/react-app/`)

- React 18 + TypeScript + Vite + Material-UI
- 33 pages including Dashboard, NewScan, Results, ResultDetail, FridaConsole, BatchConsole, Config, AuditLog, ToolsStatus, VectorSearch, AgentDashboard, ScanCompare, RBACAdmin, FeedbackAnalytics, AutoResearch, IoCDashboard, MalwareFamilies, and ML pages
- SSE reconnection via `useSseStream` hook (exponential backoff, 500ms base, 10s max)
- Auth context with `RequireRoles` component for route protection
- E2E tests: 113 Playwright spec files; Jest unit tests: 50 test suites

### CLI Architecture (`core/cli/`)

- `dyna.py` (~200 lines) delegates to 17 modules in `core/cli/`
- Key modules: `scanner.py` (AODSScanner), `execution.py` (orchestrator), `arg_parser.py`, `feature_flags.py`, `finding_processing.py`
- Decomposed sub-modules: `scanner_static.py`, `scanner_analysis.py`, `scanner_report.py`, `scanner_dynamic.py`, `execution_setup.py`, `execution_parallel.py`, `execution_standard.py`

## Data Flow

```
APK Input
    |
[APKContext Creation] <- core/apk_ctx.py
    |
[Plugin Discovery] <- ScanProfileManager (profile selection)
    |
[Parallel Execution] <- execution_parallel.py (semaphore-controlled)
    |
[FP Reduction] <- core/fp_reducer.py (3-stage: dampener -> ML -> heuristics)
    |
[ML Enhancement] <- confidence calibration, explainability
    |
[Agent Analysis] <- optional: triage, verify, remediate, narrate
    |
[Report Generation] <- UnifiedReportingManager (hot path)
    |
JSON/HTML/CSV/TXT Reports
```

## Configuration Precedence

Environment variables > YAML (`config/vulnerability_patterns.yaml`) > JSON configs > defaults

Key configuration files:
- `config/vulnerability_patterns.yaml` - 100+ patterns with regex/CWE/severity
- `config/ml_config.json` - ML pipeline configuration
- `config/agent_config.yaml` - Agent system configuration
- `config/ui-config.json` - React UI API discovery

## Security Architecture

- **RBAC**: 5 roles with ownership-based access control
- **Auth**: Opaque bearer tokens, PBKDF2-SHA256 password hashing
- **SSE Auth**: Token query param support for browser EventSource
- **Plugin Isolation**: Timeout protection, process semaphore, resource limits
- **Frida Script Safety**: `script_safety.py` validates scripts before execution
- **Path Traversal Prevention**: Input validation on file paths
- **PII Filtering**: Sensitive data stripped from API responses

## Deployment

- **Development**: API on port 8088, UI on port 5088
- **Docker**: `docker compose --profile dev up -d api-ui`
- **Production**: Docker with security hardening (read-only FS, non-root, capabilities dropped)
- **CI/CD**: Quality gate scripts in `tools/ci/gates/` (dev branch only)

> **Port defaults:** The API server defaults to port **8088** and the UI to port **5088** (configurable via `API_PORT` and `UI_PORT` env vars). Legacy documentation may reference port 8081.

## Key File Locations

| Purpose | Location |
|---------|----------|
| Entry point | `dyna.py` -> `core/cli/` |
| Analysis context | `core/apk_ctx.py` |
| Plugin base class | `core/plugins/base_plugin_v2.py` |
| Plugin manager | `core/plugins/unified_manager.py` |
| FP reducer | `core/fp_reducer.py` |
| API server | `core/api/server.py` |
| API routes | `core/api/routes/` (9 modules) |
| Auth helpers | `core/api/auth_helpers.py` |
| RBAC manager | `core/enterprise/rbac_manager.py` |
| Agent system | `core/agent/` (6 agents + providers + tools) |
| EVRE | `core/evre/` (13 mixin modules) |
| ML pipeline | `core/ai_ml/`, `core/ml/` |
| Vector DB | `core/vector_db/` |
| React frontend | `design/ui/react-app/` |
| E2E tests | `design/ui/react-app/tests/` (dev branch only) |
| Semgrep rules | `compliance/semgrep_rules/` (dev branch only) |
| Quality gates | `tools/ci/gates/` (dev branch only) |
