# BluJay — Roadmap

## Phase 1 — Complete ✓

All original AppSec toolkit features are shipped and in production:
Screenshot Capture · CVE Correlation · JS/WebView Analysis · TLS Audit · JWT Attack Testing · Diff/Change Detection · Risk Graph & Scoring · API Fuzzing · Credential Brute Force · iOS/IPA Support · Multi-APK Campaign · MCP Server (query tools)

---

## Phase 2 — Autonomous Pipeline Completion

This phase closes the remaining gaps in the autonomous AppSec architecture. Items are ordered by impact-to-effort ratio.

---

### 1 — MCP Resources (read-only)

**Status:** Not started  
**Effort:** Low  
**What's missing:** `mcp_server.py` exposes tools but no MCP Resources. Resources let Claude pull structured context passively (e.g., attach `report://42` to a prompt automatically).

**Resources to add:**

| URI | What it returns |
|-----|----------------|
| `analysis://{analysis_id}` | Analysis detail as structured text |
| `findings://{analysis_id}` | Findings as a markdown severity table |
| `report://{analysis_id}` | Full pentest report in markdown (score, findings, CVEs, permissions, recommendations) |
| `pipeline://{run_id}` | Live pipeline run status and results |

**Files to change:** `backend/mcp_server.py` — add `@mcp.resource()` decorated functions using the existing `_rows` / `_one` helpers and the `_get()` HTTP helper.

**Acceptance criteria:**
- [ ] `report://42` attached to a Claude prompt returns a complete markdown security report
- [ ] `pipeline://{run_id}` returns current node, status, and finding count
- [ ] Resources listed in `mcp.list_resources()` response

---

### 2 — GitHub Actions Workflow

**Status:** Not started  
**Effort:** Low  
**What's missing:** No `.github/workflows/` directory. Layer 0 shows GitHub Push as an external trigger but there's no Actions YAML to actually fire the webhook or upload SARIF.

**Files to create:**

| File | What it does |
|------|-------------|
| `.github/workflows/blujay-scan.yml` | On push to any branch: runs `cli.py scan --apk` on any APK in the build artifacts, uploads SARIF to GitHub Code Scanning, optionally POSTs a webhook to n8n `github-push-scan.json` |
| `.github/workflows/blujay-pr-gate.yml` | On PR: fails the check if `cli.py scan --fail-on high` exits non-zero — blocks merge on critical/high findings |

**Acceptance criteria:**
- [ ] Push to a branch with an APK artifact triggers a BluJay scan
- [ ] SARIF appears in the Security tab of the repo
- [ ] PR with high-severity findings shows a failed check

---

### 3 — Locust Integration (Layer 4)

**Status:** Not started  
**Effort:** Medium  
**What's missing:** Layer 4 calls out Locust for complex stateful scenarios that k6 can't model — multi-user OAuth flows, session chaining, WebSocket load, JWT rotation under load. Only k6 is implemented.

**Files to create:**

| File | What it does |
|------|-------------|
| `backend/data/locust_scripts/oauth_flow.py` | Locust `HttpUser` — full OAuth2 authorization code + token refresh cycle under load |
| `backend/data/locust_scripts/session_chain.py` | Locust `HttpUser` — multi-step stateful API sequence (login → action → logout) |
| `backend/data/locust_scripts/ws_load.py` | Locust `FastHttpUser` — WebSocket connection load with concurrent message bursts |
| `backend/data/locust_scripts/jwt_rotation.py` | Locust `HttpUser` — JWT fetch → use → expire → refresh loop at concurrency |
| `backend/core/locust_runner.py` | `run_locust(job_id, script, target_url, users, spawn_rate, duration, queue)` — spawns `locust --headless` as subprocess, streams CSV stats to asyncio queue |

**Files to modify:**

| File | Change |
|------|--------|
| `backend/api/perf.py` | Add `POST /perf/locust/run` endpoint accepting `script` (oauth_flow \| session_chain \| ws_load \| jwt_rotation), `users`, `spawn_rate`, `duration` |
| `backend/api/router.py` | Already registered — no change needed |

**Acceptance criteria:**
- [ ] `POST /perf/locust/run` with `script=oauth_flow` spawns Locust and streams stats via WebSocket
- [ ] Stats include RPS, failure rate, p50/p95 response time per second
- [ ] Job reaches `completed` status and stores summary metrics
- [ ] `GET /perf/{job_id}` returns Locust job results in the same schema as k6 jobs

---

### 4 — PDF Report Export

**Status:** Not started  
**Effort:** Medium  
**What's missing:** Layer 5 shows email delivery of PDF reports. The report module generates HTML and SARIF but no PDF. No PDF library is in requirements.

**Approach:** WeasyPrint renders the existing HTML report template to PDF — no new template needed.

**Files to modify:**

| File | Change |
|------|--------|
| `backend/requirements.txt` | Add `weasyprint>=62.0` |
| `backend/api/report.py` | Add `GET /report/{analysis_id}/pdf` — renders the existing HTML report through WeasyPrint, returns `application/pdf` with `Content-Disposition: attachment` |
| `backend/core/report_generator.py` (or equivalent) | Add `generate_pdf(analysis_id, db) -> bytes` wrapper |

**n8n:** Update `cron-nightly-scan.json` and the Slack output workflow to attach the PDF as a file upload rather than inline text.

**Acceptance criteria:**
- [ ] `GET /report/{id}/pdf` returns a valid PDF that opens in a browser
- [ ] PDF contains: executive summary, findings table sorted by severity, CVE matches, dangerous permissions, recommendations
- [ ] File size is reasonable (< 2MB for a typical scan)
- [ ] n8n email node can attach the PDF binary response

---

### 5 — Jira / Linear Ticket Creation

**Status:** Not started  
**Effort:** Medium  
**What's missing:** Jira and Linear are listed as Layer 5 output sinks but no n8n workflow node creates tickets. Slack notifications exist but findings don't auto-flow to a tracker.

**Approach:** Add a new n8n workflow (or extend `k6-perf-trigger.json`) with a Jira/Linear node that fires when a finding severity is `high` or `critical`.

**Files to create:**

| File | What it does |
|------|-------------|
| `workflows/finding-to-jira.json` | n8n workflow: BluJay finding webhook → severity gate (high/critical only) → Jira `Create Issue` node with title, description, CVSS, repro steps, OWASP ref, MASVS control |
| `workflows/finding-to-linear.json` | Same pattern but Linear `Create Issue` node — for teams using Linear instead of Jira |

**Jira issue fields to populate:**

| Field | Source |
|-------|--------|
| Summary | `{severity.upper()} [{finding_type}] {endpoint}` |
| Description | Finding evidence + payload + repro steps |
| Priority | Mapped from CVSS: critical→Highest, high→High, medium→Medium |
| Labels | `blujay`, `appsec`, OWASP category |
| Custom field | CVE ID if present |

**Acceptance criteria:**
- [ ] Confirming a critical finding in the pipeline automatically creates a Jira issue
- [ ] Issue contains enough detail to reproduce without opening BluJay
- [ ] Duplicate suppression: don't create a second ticket if the same `(rule_id, endpoint)` pair already has an open issue (check via Jira search node)
- [ ] Linear workflow works equivalently

---

### 6 — PagerDuty Alerting

**Status:** Not started  
**Effort:** Low  
**What's missing:** PagerDuty is listed in the n8n Layer 1 output nodes but no workflow fires a PagerDuty event. Critical findings in off-hours would page nobody.

**Files to create:**

| File | What it does |
|------|-------------|
| `workflows/critical-to-pagerduty.json` | n8n workflow: BluJay finding webhook → severity gate (`critical` only) → PagerDuty `Create Event` node (severity=critical, summary, component, source=BluJay, custom_details with endpoint + payload + CVSS) |

**Acceptance criteria:**
- [ ] Critical finding triggers a PagerDuty incident within 60 seconds
- [ ] Incident title includes target, finding type, and endpoint
- [ ] Resolving the finding in BluJay (future: via `/pipeline/{run_id}/resolve`) triggers `POST /services/{id}/integrations` to auto-resolve the incident

---

### 7 — LangGraph Persistent Checkpointing

**Status:** Not started  
**Effort:** Medium  
**What's missing:** The pipeline uses `MemorySaver` — an in-process checkpointer that loses all state on restart. A server restart while a pipeline is `awaiting_review` means the run is unrecoverable.

**Approach:** Replace `MemorySaver` with `SqliteSaver` (LangGraph built-in, no new dependency) backed by the same SQLite DB BluJay already uses.

**Files to modify:**

| File | Change |
|------|--------|
| `backend/agents/graph.py` | Replace `MemorySaver()` with `SqliteSaver.from_conn_string(str(settings.db_path))` |
| `backend/api/pipeline.py` | Update `_runs` in-memory store to hydrate from checkpoint on startup; add `GET /pipeline/runs` to reconstruct run list from checkpoint metadata |

**Acceptance criteria:**
- [ ] Restart the backend while a pipeline is `awaiting_review` — run state is preserved
- [ ] `GET /pipeline/runs` still returns the paused run after restart
- [ ] Resuming a gate approval after restart works correctly
- [ ] No regression in normal pipeline execution

---

### 8 — Pipeline Frontend UI

**Status:** Not started  
**Effort:** High  
**What's missing:** The LangGraph pipeline (`/pipeline`) and k6 perf tester (`/perf`) have complete backends with WebSocket streaming but no frontend pages. Users can only interact via the API or Claude/MCP.

**Files to create:**

| File | What it does |
|------|-------------|
| `frontend/src/pages/PipelinePage.tsx` | Start run form (target URL, scan type), live node progress timeline (recon → exploit → gate → poc → report), gate approval panel with finding summary and Approve/Deny buttons, completed run report viewer |
| `frontend/src/pages/PerfPage.tsx` | Finding type selector, target URL input, VU/duration config, live metric charts (p95 latency, RPS, error rate) via WebSocket, completed job metric summary |
| `frontend/src/api/pipeline.ts` | API client: `startRun`, `getRun`, `resumeRun`, `listRuns`, `connectPipelineWS` |
| `frontend/src/api/perf.ts` | API client: `startPerfJob`, `getJob`, `listJobs`, `connectPerfWS` |
| `frontend/src/types/pipeline.ts` | `PipelineRun`, `GatePayload`, `NodeEvent` TypeScript interfaces |
| `frontend/src/types/perf.ts` | `PerfJob`, `PerfMetric` TypeScript interfaces |

**Files to modify:**

| File | Change |
|------|--------|
| `frontend/src/App.tsx` | Add routes `/pipeline` and `/perf` |
| Sidebar | Add Pipeline and Performance entries |

**Acceptance criteria:**
- [ ] Can start a pipeline run from the UI and watch nodes progress in real time
- [ ] Gate review panel appears when pipeline reaches `awaiting_review`; Approve/Deny calls `/resume`
- [ ] Completed report is rendered inline (SARIF findings table + HTML summary)
- [ ] Perf page shows live metric charts during a k6 run via WebSocket

---

## Backlog

These are valid future improvements but not blocking the autonomous pipeline story:

- **Google Drive trigger** — Wire the Drive API watch in n8n (`google-drive-watch.json`) to detect new APK/IPA uploads and auto-trigger analysis. Blocked on Google OAuth setup per deployment.
- **n8n workflow auto-activation script** — Extend `scripts/import_n8n_workflows.sh` to activate all 5 workflows via the n8n API after import, so a fresh setup doesn't require manual clicking.
- **API authentication** — Add an API key / Bearer token layer to BluJay's REST API for deployments where n8n or MCP clients call over a network rather than localhost. Currently relies on network isolation.
- **Multi-target pipeline** — Allow a single pipeline run to sweep multiple target URLs in parallel (currently 1:1). Useful for campaign-mode autonomous testing.
- **OWASP finding → pipeline loop** — When AODS/IODS dynamic scan completes and finds high/critical issues, auto-trigger a `start_pipeline` run against the same target for deeper web-layer exploitation.
- **Strix ↔ LangGraph unified state** — Strix currently runs in a separate Docker sandbox. Pipe Strix findings back into the LangGraph `AgentState` so the Report node can incorporate them alongside the web scanner findings in a single unified report.
