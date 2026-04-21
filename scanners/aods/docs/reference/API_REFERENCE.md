# AODS API Reference

## Overview

AODS provides a FastAPI-based REST API server at `core/api/server.py` with 9 route modules. The API uses opaque bearer token authentication with RBAC (5 roles).

### Starting the API Server

```bash
source aods_venv/bin/activate
AODS_ADMIN_PASSWORD=admin uvicorn core.api.server:app --host 127.0.0.1 --port 8088 --workers 1
```

> **Important:** Use `--workers 1` when ChromaDB is enabled (SQLite backend).

---

## Authentication

### Login

```bash
curl -X POST http://127.0.0.1:8088/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'
```

**Response:**
```json
{
  "token": "abc123...",
  "user": "admin",
  "roles": ["admin", "analyst", "viewer"]
}
```

### Using the Token

```bash
# Header-based (standard)
curl http://127.0.0.1:8088/api/scans/results \
  -H "Authorization: Bearer abc123..."

# Query param (SSE streams - browsers can't set headers on EventSource)
curl -N "http://127.0.0.1:8088/api/scans/SESSION_ID/progress/stream?token=abc123..."
```

### Current User

```bash
curl http://127.0.0.1:8088/api/auth/me \
  -H "Authorization: Bearer TOKEN"
```

### Roles

| Role | Description |
|------|-------------|
| `admin` | Full access to all resources and operations |
| `analyst` | Start scans, view results, Frida console, vector search |
| `viewer` | Read-only access to results and dashboards |
| `auditor` | Audit log access only |
| `api_user` | Programmatic API access (read scans, cannot start/cancel) |

---

## REST API Endpoints

### Health & Status

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | None | Basic health check |
| GET | `/api/health/ml` | viewer+ | ML subsystems health |
| GET | `/api/health/plugins` | viewer+ | Plugin discovery health |
| GET | `/api/health/scan` | viewer+ | Scan infrastructure health |
| GET | `/api/info` | None | API version and server time |
| GET | `/api/tools/status` | viewer+ | External tools status (ADB, Frida, JADX) |
| GET | `/api/optional-deps/status` | Any | Optional dependency availability |

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/login` | None | Authenticate and receive token |
| GET | `/api/auth/me` | Any | Get current user info and roles |
| POST | `/api/auth/logout` | Any | Invalidate token |

### Scan Management

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/scans/start` | admin, analyst | Start scan with options |
| GET | `/api/scans/start-quick` | admin, analyst | Quick-start scan via query params |
| POST | `/api/scans/upload_apk` | admin, analyst | Upload APK file |
| POST | `/api/scans/{id}/confirm-package` | admin, analyst | Confirm auto-detected package |
| POST | `/api/scans/{id}/retry-detection` | admin, analyst | Retry package detection |
| GET | `/api/scans/{id}/progress` | Any | Get scan progress |
| GET | `/api/scans/{id}/progress/stream` | Owner | SSE stream of scan progress |
| GET | `/api/scans/{id}/logs/stream` | Owner | SSE stream of scan logs |
| GET | `/api/scans/{id}/details` | Owner | Get session details |
| GET | `/api/scans/active` | Any | List active scans (owner-filtered) |
| GET | `/api/scans/recent` | Any | List recent scans (paginated) |
| GET | `/api/scans/results` | Any | List scan results |
| GET | `/api/scans/result/{id}` | Any | Get full scan result JSON |
| POST | `/api/scans/{id}/cancel` | Owner | Cancel running scan |

### Batch Processing

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/batch/start` | admin | Start batch scan job |
| GET | `/api/batch/{id}/status` | admin | Get batch job status |
| GET | `/api/batch/{id}/status/stream` | admin | SSE stream of batch status |
| POST | `/api/batch/{id}/cancel` | admin | Cancel batch job |

### Reports

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/reports/list` | Any | List available reports |
| GET | `/api/reports/read` | Any | Read report file content |
| GET | `/api/reports/download` | Any | Download report file |

### Frida Dynamic Analysis

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/frida/health` | admin, analyst | Frida health status |
| GET | `/api/frida/devices` | admin, analyst | List Frida devices |
| GET | `/api/frida/devices/{id}/processes` | admin, analyst | List device processes |
| POST | `/api/frida/attach` | admin, analyst | Attach to process |
| POST | `/api/frida/detach` | admin, analyst | Detach session |
| GET | `/api/frida/session/{pkg}/status` | admin, analyst | Session status |
| POST | `/api/frida/session/{pkg}/scripts` | **admin only** | Upload script |
| DELETE | `/api/frida/session/{pkg}/scripts/{name}` | **admin only** | Unload script |
| POST | `/api/frida/session/{id}/rpc` | **admin only** | Execute RPC call |
| POST | `/api/frida/session/{pkg}/run-targeted` | **admin only** | Run targeted analysis |
| GET | `/api/frida/session/{pkg}/events/stream` | admin, analyst | SSE event stream |
| POST | `/api/frida/corellium/connect` | admin | Connect Corellium device |
| POST | `/api/frida/corellium/ensure` | admin | Ensure ADB + Frida ready |
| GET | `/api/frida/telemetry/recent` | **admin only** | Recent telemetry events |
| GET | `/api/frida/telemetry/summary` | **admin only** | Telemetry summary |
| POST | `/api/frida/ws-token` | admin, analyst | Issue WebSocket token |
| WS | `/api/frida/ws` | token | WebSocket Frida console |

### ML & Explainability

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/ml/training/status` | admin, analyst | ML training job status |
| POST | `/api/ml/training/run_calibration` | admin, analyst | Trigger calibration run |
| GET | `/api/ml/calibration/summary` | admin, analyst | Calibration summary |
| GET | `/api/ml/thresholds` | admin, analyst | Current confidence thresholds |
| GET | `/api/ml/metrics/pr` | admin, analyst | Precision/recall metrics |
| GET | `/api/ml/metrics/fp_breakdown` | admin, analyst | FP breakdown by plugin |
| POST | `/api/ml/metrics/eval_thresholds` | admin, analyst | Evaluate thresholds |
| GET | `/api/ml/analytics/summary` | admin, analyst | Learning analytics summary |
| GET | `/api/ml/metrics/detection_accuracy/summary` | admin, analyst | Detection accuracy gate summary |
| GET | `/api/explain/status` | admin, analyst | Explainability subsystem status |
| POST | `/api/explain/finding` | admin, analyst | Explain finding (SHAP/LIME/rule-based) |

### Vector Search (requires `AODS_VECTOR_DB_ENABLED=1`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/vector/findings/similar` | admin, analyst | Find similar findings |
| GET | `/api/vector/index/status` | admin, analyst | Vector index status |
| POST | `/api/vector/index/rebuild` | admin | Rebuild vector index |
| DELETE | `/api/vector/index/scan/{scan_id}` | admin | Delete all vector entries for a scan |

### Agent System (requires `AODS_AGENT_ENABLED=1`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/agent/tasks` | admin, analyst | Create agent task (generic) |
| GET | `/api/agent/tasks` | admin, analyst | List agent tasks (analysts see own tasks only) |
| GET | `/api/agent/tasks/{id}` | admin, analyst | Get agent task result |
| POST | `/api/agent/tasks/{id}/cancel` | admin, analyst | Cancel a running agent task |
| GET | `/api/agent/tasks/{id}/stream` | admin, analyst | SSE observation stream for a task |
| GET | `/api/agent/tasks/{id}/transcript` | admin, analyst | Get agent execution transcript |
| POST | `/api/agent/triage` | admin, analyst | Run triage agent |
| POST | `/api/agent/narrate` | admin, analyst | Run narration agent |
| POST | `/api/agent/verify` | admin, analyst | Run verification agent |
| POST | `/api/agent/orchestrate` | admin, analyst | Run orchestration agent |
| POST | `/api/agent/remediate` | admin, analyst | Run remediation agent |
| POST | `/api/agent/pipeline` | admin, analyst | Run full agent pipeline |
| GET | `/api/agent/stats` | admin, analyst | Agent usage statistics and token metrics |
| GET | `/api/agent/config` | admin | Get agent configuration |
| POST | `/api/agent/config` | admin | Update agent configuration at runtime |
| POST | `/api/agent/triage/feedback` | admin, analyst | Submit triage feedback |
| GET | `/api/agent/triage/feedback/history` | admin, analyst | Get feedback history |
| GET | `/api/agent/triage/feedback/export` | admin, analyst | Export triage feedback (JSON) |

### Admin & User Management

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/admin/users` | admin | List all users |
| GET | `/api/admin/roles` | admin | List available roles |
| PUT | `/api/admin/users/{username}/role` | admin | Update user role |

### Audit & Compliance

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/audit/events` | admin, auditor | List audit events (paginated) |
| GET | `/api/audit/export` | admin | Export raw audit log |
| POST | `/api/audit/event` | admin, analyst | Log audit event |

### Artifacts & CI Gates

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/artifacts/list` | admin, analyst | List artifacts |
| GET | `/api/artifacts/read` | admin, analyst | Read artifact file |
| GET | `/api/artifacts/download` | admin, analyst | Download artifact |
| GET | `/api/gates/summary` | admin, analyst | CI gates summary |
| GET | `/api/gates/deltas` | admin, analyst | Gates delta vs last check |
| GET | `/api/jobs/history` | Any | Aggregated job history |

### Configuration & Dev

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/config` | Any | Runtime UI configuration |
| GET | `/api/schemas/{name}` | Any | Retrieve JSON schema |
| GET | `/api/mappings/sources` | Any | Security framework mappings |
| GET | `/api/dev/servers/status` | admin | Dev server status |
| POST | `/api/dev/servers/start` | admin | Start dev servers |
| POST | `/api/dev/servers/stop` | admin | Stop dev servers |
| POST | `/api/dev/servers/restart` | admin | Restart dev servers |
| POST | `/api/dev/servers/stop_all` | admin | Stop all dev servers and clear PID files |
| POST | `/api/dev/servers/start_clean` | admin | Stop then start all dev servers |
| GET | `/api/ci/toggles` | viewer+ | Get CI gate toggles |
| PATCH | `/api/ci/toggles` | admin | Update CI gate toggles |
| GET | `/api/decomp/policy` | analyst+ | Get decompilation policy |
| PATCH | `/api/decomp/policy` | admin | Update decompilation policy |

---

## Python API

### CLI Entry Point

AODS is primarily a CLI tool. The entry point is `dyna.py`, which delegates to `core/cli/scanner.py`:

```bash
python dyna.py --apk app.apk --mode deep --formats json html
```

### Plugin Development

All plugins extend `BasePluginV2`:

```python
from core.plugins.base_plugin_v2 import BasePluginV2, PluginCapability, PluginResult, PluginStatus

class MyPlugin(BasePluginV2):
    def get_metadata(self):
        return PluginMetadata(
            name="my_plugin",
            version="1.0.0",
            capabilities=[PluginCapability.STATIC_ANALYSIS],
            dependencies=["jadx"]
        )

    def execute(self, apk_ctx):
        findings = []
        # ... analysis logic using apk_ctx ...
        return PluginResult(
            status=PluginStatus.SUCCESS,
            findings=findings,
            metadata={"execution_time": elapsed}
        )
```

**Key types:**
- `PluginCapability` - static, dynamic, network, crypto, manifest, compliance
- `PluginStatus` - SUCCESS, FAILURE, TIMEOUT, SKIPPED, PARTIAL_SUCCESS
- `PluginFinding` - title, severity, confidence, evidence, CWE, MASVS mapping (17 fields)
- `PluginResult` - wrapper with status, findings list, and metadata
- `APKContext` (`core/apk_ctx.py`) - runtime context with APK path, workspace, sources, manifest

### Explainability Facade

```python
from core.ml.explainability_facade import ExplainabilityFacade, UnifiedExplanation

facade = ExplainabilityFacade()

# Explain a finding
explanation = facade.explain_finding(finding_dict)
# Returns UnifiedExplanation with method, summary, factors

# Check available methods
status = facade.get_status()
# Returns: {rule_based, confidence_based, shap, lime, available_methods}
```

### EVRE (Report Engine)

```python
from core.enhanced_vulnerability_reporting_engine import EnhancedVulnerabilityReportingEngine

# The EVRE is composed from 10 mixins in core/evre/
# It handles evidence enrichment, deduplication, and normalization
engine = EnhancedVulnerabilityReportingEngine()
report = engine.generate_enhanced_report(vulnerabilities, app_context, scan_metadata)
```

---

## SSE Streaming

AODS provides three SSE stream endpoints for real-time updates:

### Scan Progress Stream

```javascript
// Browser: use token query param (can't set headers on EventSource)
const evtSource = new EventSource(
  `/api/scans/${sessionId}/progress/stream?token=${token}`
);
evtSource.onmessage = (e) => {
  const data = JSON.parse(e.data);
  console.log(`${data.pct}% - ${data.stage}: ${data.message}`);
};
// Listen for clean close
evtSource.addEventListener('end', () => evtSource.close());
```

### Scan Logs Stream

```javascript
const evtSource = new EventSource(
  `/api/scans/${sessionId}/logs/stream?token=${token}`
);
```

### Batch Status Stream

```javascript
const evtSource = new EventSource(
  `/api/batch/${jobId}/status/stream?token=${token}`
);
```

### SSE Reconnection

The frontend `useSseStream` hook handles reconnection with exponential backoff (500ms base, 10s max). Backend sends heartbeat comments (`": heartbeat\n\n"`) every ~30s to keep TCP alive.

---

## Data Structures

### Vulnerability Finding (JSON Report)

```json
{
  "title": "Insecure SharedPreferences Storage",
  "severity": "HIGH",
  "confidence": 0.92,
  "description": "Sensitive data stored in unencrypted SharedPreferences...",
  "file_path": "com/example/app/utils/PrefsHelper.java",
  "line_number": 42,
  "code_snippet": "getSharedPreferences(\"user_data\", MODE_PRIVATE)",
  "cwe_id": "CWE-312",
  "masvs": "MASVS-STORAGE-1",
  "recommendation": "Use EncryptedSharedPreferences from AndroidX Security library",
  "evidence": { "code_snippet": "...", "description": "..." },
  "classification": { "severity": "HIGH", "category": "Data Storage" },
  "plugin_source": "insecure_data_storage",
  "references": ["https://owasp.org/..."]
}
```

### Scan Result Metadata

```json
{
  "scan_id": "abc123",
  "apk_name": "app.apk",
  "package_name": "com.example.app",
  "scan_profile": "standard",
  "scan_mode": "deep",
  "duration_seconds": 423,
  "timestamp": "2026-03-09T14:30:22Z",
  "plugins_summary": { "total": 33, "executed": 33, "skipped": 0 }
}
```

### UnifiedExplanation (Explainability)

```python
@dataclass
class UnifiedExplanation:
    finding_id: str
    summary: str
    method: str              # "shap", "lime", "heuristic", "rule-based", "confidence"
    confidence: float
    contributing_factors: List[Dict[str, Any]]
    risk_factors: List[str]
    mitigating_factors: List[str]
    metadata: Dict[str, Any]
```

---

## Environment Variables

See [USER_GUIDE.md Section 7](../USER_GUIDE.md#7-environment-variables) for the complete environment variable reference.

Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AODS_ADMIN_PASSWORD` | random | Admin user password |
| `AODS_DISABLE_ML` | `0` | Disable ML features |
| `AODS_VECTOR_DB_ENABLED` | `0` | Enable ChromaDB |
| `AODS_AGENT_ENABLED` | `0` | Enable agent system |
| `AODS_AGENT_PROVIDER` | `anthropic` | LLM provider |
| `AODS_LOG_FORMAT` | `auto` | Log format (json/console/auto) |
| `AODS_LOG_LEVEL` | `INFO` | Log level |

---

## HTTP Status Codes

| Code | Meaning |
|------|---------|
| `200 OK` | Successful request |
| `400 Bad Request` | Invalid parameters |
| `401 Unauthorized` | Missing or expired token |
| `403 Forbidden` | Insufficient permissions or ownership violation |
| `404 Not Found` | Resource not found |
| `500 Internal Server Error` | Server error |
