# AppAnalysis — Feature Roadmap

This document tracks the 12 planned features for AppAnalysis. Each feature section lists every file to create, every existing file to modify, new dependencies to install, and acceptance criteria. Work through them in order — earlier features produce data that later ones consume.

---

## Dependency Overview

```
Screenshot Capture       → no dependencies
CVE Correlation          → no dependencies (uses existing analysis output)
JS / WebView Analysis    → no dependencies (uses existing decompile output)
TLS Audit                → no dependencies (uses existing proxy flow data)
JWT Attack Testing       → no dependencies (uses existing proxy flow data)
Diff / Change Detection  → no dependencies (uses existing findings/flows)
Risk Graph & Scoring     → depends on: CVE Correlation, JS/WebView Analysis
API Fuzzing              → depends on: existing proxy flows + static findings
Credential Brute Force   → depends on: existing proxy flows
iOS / IPA Support        → independent (parallel pipeline)
Multi-APK Campaign       → depends on: CVE Correlation (for shared CVE detection)
MCP Server               → depends on: all features above being implemented
```

---

## Global Setup (do once before starting)

### Install new Python dependencies
```bash
cd backend
pip install Pillow>=10.3.0 PyJWT>=2.8.0 pycryptodome>=3.20.0 mcp>=1.0.0
```
Then add these lines to `backend/requirements.txt`:
```
Pillow>=10.3.0
PyJWT>=2.8.0
pycryptodome>=3.20.0
mcp>=1.0.0
```

### Install new frontend dependencies
```bash
cd frontend
npm install recharts d3 @types/d3
```

### Create new directories
```
backend/wordlists/          — wordlist files for JWT and brute force
backend/frida_scripts/      — already exists; will add iOS scripts here
```

Create `backend/wordlists/top_passwords.txt` with the top 500 common passwords (rockyou-style).
Create `backend/wordlists/jwt_secrets.txt` with ~1000 common JWT secrets (`secret`, `password`, `changeme`, etc.).

---

## Feature 1 — Screenshot Capture

**Purpose:** Capture device screenshots during dynamic analysis sessions via ADB and display them in the UI linked to the session timeline.

### New files to create

| File | What it does |
|------|-------------|
| `backend/core/screenshot_manager.py` | `capture_screenshot(serial) -> bytes` runs `adb exec-out screencap -p`; `save_screenshot(session_id, data, label, workspace_dir) -> Path` writes PNG and generates base64 thumbnail using Pillow |
| `backend/models/screenshot.py` | `Screenshot` ORM model: `id`, `session_id` (FK), `captured_at`, `label`, `file_path`, `thumbnail_b64` |
| `backend/schemas/screenshot.py` | `ScreenshotOut`, `CaptureRequest(serial, session_id, label)` |
| `backend/api/screenshot.py` | `POST /screenshots/capture`, `GET /screenshots?session_id=`, `GET /screenshots/{id}/image` (FileResponse), `DELETE /screenshots/{id}` |
| `frontend/src/types/screenshot.ts` | TypeScript interfaces for `Screenshot`, `CaptureRequest` |
| `frontend/src/api/screenshot.ts` | API client wrappers |
| `frontend/src/components/dynamic/ScreenshotGallery.tsx` | Thumbnail grid with Radix Dialog for full-size view, capture button, label input |

### Existing files to modify

| File | Change |
|------|--------|
| `backend/main.py` | Add `import models.screenshot  # noqa: F401` |
| `backend/api/router.py` | Import and register `screenshot_router` at prefix `/screenshots` |
| `backend/config.py` | Add `screenshots_dir` property pointing to `workspace_dir / "screenshots"`; extend `ensure_dirs()` to create it |
| `backend/api/adb.py` | Add `GET /devices/{serial}/screenshot` convenience endpoint streaming PNG bytes |
| `frontend/src/pages/DynamicAnalysis.tsx` | Add "Screenshots" tab using `ScreenshotGallery` component |

### Implementation notes
- Use `adb exec-out screencap -p` not `adb shell screencap -p` — `exec-out` avoids CR/LF corruption on Windows.
- Thumbnail: resize to 100px wide, encode as JPEG quality 70, base64 encode, store in `thumbnail_b64` so gallery loads without serving static files.
- Filename format: `{timestamp}_{label}.png` using `%Y%m%d_%H%M%S_%f`.

### Acceptance criteria
- [X] Clicking "Capture Screenshot" on the Dynamic Analysis page saves a screenshot and shows it in the gallery.
- [X] Screenshots are persisted across page reloads (stored in DB + disk).
- [X] Thumbnails load without full image download.
- [X] PNG download works via the image endpoint.

---

## Feature 2 — CVE Correlation

**Purpose:** Detect libraries and SDKs in the decompiled APK and cross-reference them against the OSV.dev vulnerability database to surface known CVEs.

### New files to create

| File | What it does |
|------|-------------|
| `backend/core/cve_correlator.py` | `extract_libraries(jadx_path, decompile_path) -> list[dict]` — parses `build.gradle` for Maven deps, clusters Java imports by known package prefixes, checks `strings.xml`; `query_osv(package, version, ecosystem) -> list[dict]` — async POST to `https://api.osv.dev/v1/query`; `run_cve_scan(analysis_id, db_factory)` — orchestrates extraction + querying + persistence |
| `backend/models/cve.py` | `DetectedLibrary` model: `id`, `analysis_id` (FK), `name`, `version`, `ecosystem`, `source`; `CveMatch` model: `id`, `analysis_id` (FK), `library_id` (FK), `osv_id`, `cve_id`, `severity`, `cvss_score`, `summary`, `fixed_version`, `published`, `fetched_at` |
| `backend/schemas/cve.py` | `DetectedLibraryOut`, `CveMatchOut`, `CveScanResponse(libraries, cve_matches, total_critical, total_high)` |
| `backend/api/cve.py` | `POST /cve/scan/{analysis_id}`, `GET /cve/{analysis_id}/libraries`, `GET /cve/{analysis_id}/matches?severity=`, `GET /cve/{analysis_id}/summary` |
| `frontend/src/types/cve.ts` | TypeScript interfaces |
| `frontend/src/api/cve.ts` | API client wrappers |
| `frontend/src/pages/CvePage.tsx` | Table of detected libraries with expandable CVE rows; severity badges; CVSS score bars; links to OSV advisories |

### Existing files to modify

| File | Change |
|------|--------|
| `backend/main.py` | Add `import models.cve  # noqa: F401` |
| `backend/api/router.py` | Register `cve_router` at `/cve` |
| `backend/core/apk_analyzer.py` | At the end of `run_analysis`, after findings are saved, add `asyncio.create_task(run_cve_scan(analysis_id, AsyncSessionLocal))` |
| `frontend/src/App.tsx` | Add `<Route path="/cve/:id" element={<CvePage />} />` |
| `frontend/src/components/layout/Sidebar.tsx` | Add CVE entry with `ShieldAlert` icon |
| `frontend/src/pages/StaticAnalysis.tsx` | Add "CVE" tab linking to the CVE page for the current analysis |

### Implementation notes
- OSV API: `POST https://api.osv.dev/v1/query` with `{"package": {"name": pkg, "ecosystem": "Maven"}, "version": version}`. No auth required.
- Use `asyncio.Semaphore(10)` to cap concurrent OSV requests.
- Cache results: skip re-fetching CVEs where `fetched_at < 24h` ago.
- CVSS severity mapping: parse `database_specific.severity` or `severity[].score` from OSV response.
- Library extraction: (a) `implementation 'group:artifact:version'` in `build.gradle`, (b) known namespace clusters (`com.squareup`, `com.google`, `io.realm`, `org.apache`, `okhttp3`, etc.), (c) version strings in `res/raw/`.

### Acceptance criteria
- [X] Running a scan auto-triggers CVE correlation after static analysis completes.
- [X] CVE page shows detected libraries grouped by ecosystem.
- [X] Each library expands to show matched CVEs with severity, CVSS score, and OSV link.
- [X] Critical/High CVE count appears on the Static Analysis overview.

---

## Feature 3 — JS / WebView Analysis

**Purpose:** Extract JavaScript from APK assets and WebView `loadUrl`/`loadData` call sites, then scan for secrets, dangerous APIs, postMessage handlers, and exposed JS bridges.

### New files to create

| File | What it does |
|------|-------------|
| `backend/core/webview_analyzer.py` | `extract_webview_js(decompile_path, jadx_path) -> list[dict]` — finds JS in `assets/`, `res/raw/`, `.html` files, and inline `loadUrl("javascript:` strings in Java; `scan_js_content(filename, content) -> list[dict]` — regex rules for secrets, `eval(`, `innerHTML =`, `postMessage`, mixed content `http://`, `addJavascriptInterface` calls |
| `backend/api/webview.py` | `POST /webview/scan/{analysis_id}`, `GET /webview/{analysis_id}/files`, `GET /webview/{analysis_id}/files/{index}/content` |
| `backend/schemas/webview.py` | `WebViewFile(source, path, size_bytes)`, `WebViewScanResult(files_found, findings_count, findings)` |
| `frontend/src/types/webview.ts` | TypeScript interfaces |
| `frontend/src/api/webview.ts` | API client wrappers |
| `frontend/src/pages/WebViewPage.tsx` | File tree (left), Monaco editor (right), findings panel (bottom) |

### Existing files to modify

| File | Change |
|------|--------|
| `backend/api/router.py` | Register `webview_router` at `/webview` |
| `frontend/src/App.tsx` | Add `<Route path="/webview/:id" element={<WebViewPage />} />` |
| `frontend/src/components/layout/Sidebar.tsx` | Add entry with `Code2` icon |
| `frontend/src/pages/StaticAnalysis.tsx` | Add "WebView JS" tab with link to full WebView page |

### Implementation notes
- `addJavascriptInterface` extraction is high value: scan JADX output to find the interface class name and exposed methods — these define the bridge API surface.
- Persist findings as `StaticFinding` rows with `category="webview_js"` so they appear in the existing findings table.
- Monaco editor is already a dependency — no new packages needed.
- Also scan `.html` files in `assets/` for inline `<script>` blocks.

### Acceptance criteria
- [X] JS files extracted from APK assets appear in the file tree.
- [X] Inline JavaScript from `loadUrl`/`loadData` calls is extracted and displayed.
- [X] Findings (secrets, eval, postMessage) are flagged with severity and line numbers.
- [X] `addJavascriptInterface` bridges are listed with their exposed method signatures.

---

## Feature 4 — TLS Audit

**Purpose:** Audit TLS configuration of backend hosts discovered during dynamic analysis — protocol support, weak ciphers, certificate validity, and HSTS.

### New files to create

| File | What it does |
|------|-------------|
| `backend/core/tls_auditor.py` | `audit_host(host, port=443) -> dict` — uses Python `ssl` stdlib to probe protocol versions (TLS 1.0/1.1/1.2/1.3), detect weak ciphers (RC4, DES, 3DES, NULL, EXPORT), parse cert with `cryptography.x509`, check HSTS header; `extract_hosts_from_session(session_id, db) -> list[tuple]` — queries `ProxyFlow.host` for unique HTTPS hosts |
| `backend/models/tls_audit.py` | `TlsAudit` model: `id`, `host`, `port`, `session_id` (FK nullable), `analysis_id` (FK nullable), `status`, `cert_subject`, `cert_issuer`, `cert_expiry`, `cert_self_signed`, `tls10_enabled`, `tls11_enabled`, `tls12_enabled`, `tls13_enabled`, `hsts_present`, `weak_ciphers` (JSON), `findings_json` (JSON), `error` |
| `backend/schemas/tls_audit.py` | `TlsAuditOut`, `TlsAuditRequest(hosts, session_id, analysis_id)` |
| `backend/api/tls_audit.py` | `POST /tls/audit` — accepts host list or `session_id` to auto-extract; `GET /tls/audits?session_id=&analysis_id=`; `GET /tls/audits/{id}` |
| `frontend/src/types/tls.ts` | TypeScript interfaces |
| `frontend/src/api/tls.ts` | API client wrappers |
| `frontend/src/pages/TlsAuditPage.tsx` | Host list input, per-host accordion with protocol version badges, cert details card, weak cipher list, findings |

### Existing files to modify

| File | Change |
|------|--------|
| `backend/main.py` | Add `import models.tls_audit  # noqa: F401` |
| `backend/api/router.py` | Register `tls_router` at `/tls` |
| `frontend/src/App.tsx` | Add `<Route path="/tls" element={<TlsAuditPage />} />` |
| `frontend/src/components/layout/Sidebar.tsx` | Add entry with `Lock` icon |

### Implementation notes
- Use `ssl.SSLContext` with `check_hostname = False` and `verify_mode = ssl.CERT_NONE` for audit. Parse cert via `cryptography.x509` (already in requirements).
- To detect TLS 1.0/1.1: create SSLContext with `maximum_version = ssl.TLSVersion.TLSv1` and attempt connect.
- Run each host audit in `loop.run_in_executor(None, ...)` since `ssl` is synchronous.
- Cap concurrency at 5 hosts simultaneously with `asyncio.gather`.

### Acceptance criteria
- [ ] Auditing a session automatically finds all HTTPS hosts from proxy flows.
- [ ] Protocol support (TLS 1.0/1.1/1.2/1.3) shown per host.
- [ ] Certificate expiry, issuer, and self-signed status shown.
- [ ] Weak ciphers flagged with severity.
- [ ] HSTS absence flagged as a finding.

---

## Feature 5 — JWT Attack Testing

**Purpose:** Decode JWTs captured in proxy traffic and test them for common vulnerabilities: weak HMAC secrets, `alg:none` forgery, RS256→HS256 confusion, `kid` injection, and role escalation.

### New files to create

| File | What it does |
|------|-------------|
| `backend/core/jwt_attacker.py` | `decode_jwt(token) -> dict`; `brute_force_hmac(token, wordlist_path, progress_queue) -> dict` — iterates wordlist in executor; `forge_alg_none(token) -> str`; `rs256_to_hs256(token, public_key_pem) -> str`; `test_kid_injection(token, payloads) -> list[str]`; `escalate_roles(token, role_fields, escalation_values) -> list[str]` |
| `backend/models/jwt_test.py` | `JwtTest` model: `id`, `created_at`, `session_id` (FK nullable), `analysis_id` (FK nullable), `raw_token`, `decoded_header` (JSON), `decoded_payload` (JSON), `alg_none_token`, `hmac_secret_found`, `rs256_hs256_token`, `kid_injection_payloads` (JSON), `role_escalation_tokens` (JSON), `notes` |
| `backend/schemas/jwt_test.py` | `JwtTestCreate(token, session_id, wordlist)`, `JwtTestOut`, `JwtBruteForceResult(found, secret, tested_count)` |
| `backend/api/jwt_test.py` | `POST /jwt/decode`; `POST /jwt/brute-force` (background task with WS progress); `POST /jwt/forge`; `GET /jwt/tests`; `GET /jwt/from-flows?session_id=` — regex-scans proxy flows for `eyJ...` tokens |
| `backend/wordlists/jwt_secrets.txt` | ~1000 common JWT secrets (create this file) |
| `frontend/src/types/jwt.ts` | TypeScript interfaces |
| `frontend/src/api/jwt.ts` | API client wrappers |
| `frontend/src/pages/JwtPage.tsx` | Token input, decoded header/payload display (Monaco JSON), attack buttons, results table, brute-force progress bar |

### Existing files to modify

| File | Change |
|------|--------|
| `backend/main.py` | Add `import models.jwt_test  # noqa: F401` |
| `backend/api/router.py` | Register `jwt_router` at `/jwt` |
| `backend/api/ws.py` | Add `@ws_router.websocket("/jwt/{test_id}")` for brute-force progress |
| `frontend/src/App.tsx` | Add `<Route path="/jwt" element={<JwtPage />} />` |
| `frontend/src/components/layout/Sidebar.tsx` | Add entry with `Key` icon |

### Implementation notes
- JWT scan from flows: regex `eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*` across `request_headers` and `response_body` fields of `ProxyFlow`.
- `alg:none` forge: base64url-encode modified header (`{"alg":"none","typ":"JWT"}`), keep original payload, append empty signature (trailing `.`).
- HMAC brute force: `concurrent.futures.ThreadPoolExecutor(max_workers=4)`, emit progress every 10,000 attempts to the asyncio queue.

### Acceptance criteria
- [ ] "Scan Flows" button finds JWTs in captured proxy traffic automatically.
- [ ] Header and payload decoded and displayed as formatted JSON.
- [ ] `alg:none` forged token generated in one click.
- [ ] Brute-force shows live progress and reveals secret if found.
- [ ] Role escalation variants generated for common fields (`role`, `admin`, `is_admin`).

---

## Feature 6 — Diff / Change Detection

**Purpose:** Compare two analyses of the same app (different versions) and surface what changed: permissions, findings, components, network hosts.

### New files to create

| File | What it does |
|------|-------------|
| `backend/core/diff_engine.py` | `diff_analyses(analysis_id_a, analysis_id_b, db) -> dict` — computes: new/removed permissions (set diff), new/removed/changed findings (keyed on `rule_id+file_path+line_number`), new/removed exported components, new/removed proxy hosts, new/removed Frida event types, metadata changes (version name, SDK levels) |
| `backend/models/diff.py` | `AnalysisDiff` model: `id`, `created_at`, `analysis_id_a` (FK), `analysis_id_b` (FK), `label`, `status`, `result_json` (Text) |
| `backend/schemas/diff.py` | `DiffRequest(analysis_id_a, analysis_id_b, label)`, `DiffResult(new_permissions, removed_permissions, new_findings, removed_findings, changed_findings, new_components, removed_components, new_hosts, removed_hosts, metadata_changes)`, `AnalysisDiffOut` |
| `backend/api/diff.py` | `POST /diff`, `GET /diff/{id}`, `GET /diff` (paginated list) |
| `frontend/src/types/diff.ts` | TypeScript interfaces |
| `frontend/src/api/diff.ts` | API client wrappers |
| `frontend/src/pages/DiffPage.tsx` | Two analysis selectors (dropdowns), side-by-side diff view with colored badges (green=new, red=removed, yellow=changed), expandable sections per category |

### Existing files to modify

| File | Change |
|------|--------|
| `backend/main.py` | Add `import models.diff  # noqa: F401` |
| `backend/api/router.py` | Register `diff_router` at `/diff` |
| `frontend/src/App.tsx` | Add `<Route path="/diff" element={<DiffPage />} />` and `<Route path="/diff/:id" element={<DiffPage />} />` |
| `frontend/src/components/layout/Sidebar.tsx` | Add entry with `GitCompare` icon |
| `frontend/src/pages/StaticAnalysis.tsx` | Add "Compare with..." button that navigates to the diff selector pre-populated with the current analysis |

### Implementation notes
- Finding key: composite `(rule_id, file_path, line_number)`. Same key in both = compare severity for change detection.
- Host query: `SELECT DISTINCT host FROM proxy_flows WHERE session_id IN (SELECT id FROM dynamic_sessions WHERE analysis_id = ?)`.
- Diff result is stored as JSON in `result_json` — re-fetching is always cheap.

### Acceptance criteria
- [ ] Can select any two analyses from dropdowns and run a diff.
- [ ] New permissions appear in green, removed in red.
- [ ] Finding changes show severity before/after.
- [ ] New backend hosts discovered in the newer version are highlighted.
- [ ] Diff persists and is viewable from a list.

---

## Feature 7 — Risk Graph & Scoring Visualization

**Purpose:** Compute a 0–100 risk score per analysis and render a force-directed graph connecting findings, components, permissions, network hosts, libraries, and CVEs.

**Depends on:** CVE Correlation (Feature 2) being implemented for full scoring.

### New files to create

| File | What it does |
|------|-------------|
| `backend/core/risk_scorer.py` | `SEVERITY_WEIGHTS = {"critical":10,"high":7,"medium":4,"low":1,"info":0}`; `compute_risk_score(analysis_id, db) -> dict` — weighted sum normalized to 0–100, grade A–F; `build_graph(analysis_id, db) -> dict` — node types: `analysis`, `finding`, `component`, `permission`, `host`, `library`, `cve`; edges connect related nodes |
| `backend/api/risk.py` | `GET /risk/{analysis_id}/score`, `GET /risk/{analysis_id}/graph` |
| `backend/schemas/risk.py` | `RiskScore(score, grade, breakdown, finding_count_by_severity)`, `GraphNode(id, type, label, severity)`, `GraphEdge(source, target, relation)`, `RiskGraph(nodes, edges)` |
| `frontend/src/types/risk.ts` | TypeScript interfaces |
| `frontend/src/api/risk.ts` | API client wrappers |
| `frontend/src/components/analysis/RiskScoreCard.tsx` | SVG score gauge, grade badge, severity breakdown bar chart (Recharts) |
| `frontend/src/components/analysis/RiskGraph.tsx` | D3 force-directed graph: nodes colored by type, edges labeled, zoom/pan support |
| `frontend/src/pages/RiskPage.tsx` | Combines `RiskScoreCard` + `RiskGraph` |

### Existing files to modify

| File | Change |
|------|--------|
| `backend/api/router.py` | Register `risk_router` at `/risk` |
| `frontend/src/App.tsx` | Add `<Route path="/risk/:id" element={<RiskPage />} />` |
| `frontend/src/components/layout/Sidebar.tsx` | Add entry with `BarChart2` icon |
| `frontend/src/pages/StaticAnalysis.tsx` | Add mini `RiskScoreCard` widget in the Overview tab linking to the full Risk page |
| `frontend/package.json` | Add `"recharts": "^2.12.0"`, `"d3": "^7.9.0"`, `"@types/d3": "^7.4.3"` (also run `npm install`) |

### Implementation notes
- Grade thresholds: A ≤ 20, B ≤ 40, C ≤ 60, D ≤ 80, F > 80 (score out of 100).
- D3 force graph: `d3-force` simulation with `forceLink`, `forceManyBody`, `forceCenter`. Color scheme: findings = severity-colored, components = blue, permissions = purple, hosts = teal, CVEs = dark red.
- Only emit graph nodes/edges for data that actually exists — don't render empty node types.

### Acceptance criteria
- [ ] Risk score and grade shown on the Static Analysis overview tab.
- [ ] Full risk page shows score gauge with breakdown by category (secrets, permissions, CVEs, etc.).
- [ ] Force-directed graph renders with all connected node types.
- [ ] Graph nodes are clickable and link to the relevant finding or component.
- [ ] Zooming and panning work in the graph.

---

## Feature 8 — API Fuzzing

**Purpose:** Fuzz REST/GraphQL/WebSocket endpoints extracted from proxy traffic or static analysis for IDOR, verb tampering, mass assignment, auth bypass, parameter pollution, and rate-limit gaps.

### New files to create

| File | What it does |
|------|-------------|
| `backend/core/api_fuzzer.py` | `EndpointSpec` dataclass; `extract_endpoints_from_flows(session_id, db) -> list[EndpointSpec]`; `extract_endpoints_from_static(analysis_id, db) -> list[EndpointSpec]` — scans JADX output for Retrofit `@GET/@POST` annotations; attack functions: `fuzz_idor`, `fuzz_verb_tampering`, `fuzz_mass_assignment`, `fuzz_param_pollution`, `fuzz_auth_bypass_headers`, `fuzz_rate_limit`; `run_fuzz_job(job_id, specs, attacks, db_factory, progress_queue)` |
| `backend/models/fuzzing.py` | `FuzzJob` model: `id`, `created_at`, `session_id` (FK nullable), `analysis_id` (FK nullable), `status`, `attacks` (JSON), `endpoint_count`, `result_summary` (JSON), `error`; `FuzzResult` model: `id`, `job_id` (FK), `attack_type`, `method`, `url`, `request_headers` (JSON), `request_body`, `response_status`, `response_body`, `duration_ms`, `is_interesting`, `notes` |
| `backend/schemas/fuzzing.py` | `FuzzJobCreate(session_id, analysis_id, attacks, endpoint_filter)`, `FuzzJobOut`, `FuzzResultOut`, `FuzzJobDetail` |
| `backend/api/fuzzing.py` | `POST /fuzzing/jobs`, `GET /fuzzing/jobs`, `GET /fuzzing/jobs/{id}`, `DELETE /fuzzing/jobs/{id}` |
| `frontend/src/types/fuzzing.ts` | TypeScript interfaces |
| `frontend/src/api/fuzzing.ts` | API client wrappers |
| `frontend/src/pages/FuzzingPage.tsx` | Job creator (endpoint selector, attack type checkboxes), jobs list, results table with response diff viewer |

### Existing files to modify

| File | Change |
|------|--------|
| `backend/main.py` | Add `import models.fuzzing  # noqa: F401` |
| `backend/api/router.py` | Register `fuzzing_router` at `/fuzzing` |
| `backend/api/ws.py` | Add `@ws_router.websocket("/fuzzing/{job_id}")` for real-time progress |
| `frontend/src/App.tsx` | Add `<Route path="/fuzzing" element={<FuzzingPage />} />` |
| `frontend/src/components/layout/Sidebar.tsx` | Add entry with `Crosshair` icon |

### Implementation notes
- "Interesting" response heuristic: flag when status differs from baseline by ≥ 100 (e.g., got 200 where baseline was 403), or status is 5xx, or body contains `SQL`, `syntax error`, `exception`, `stack trace`, `ORA-`.
- Rate limit detection: if 50 rapid requests produce zero 429 responses, flag "no rate limiting."
- GraphQL: detect via `content-type: application/graphql` or path `/graphql` — add introspection query fuzzing.
- Cap concurrency at `asyncio.Semaphore(10)`.

### Acceptance criteria
- [ ] Endpoints auto-populated from proxy session flows.
- [ ] User can select which attack types to run.
- [ ] "Interesting" results flagged in results table with explanation.
- [ ] Real-time progress shown via WebSocket.
- [ ] GraphQL introspection attempted if GraphQL endpoint detected.

---

## Feature 9 — Credential Brute Forcing

**Purpose:** Detect login endpoints from proxy traffic and brute-force them against common credentials with configurable concurrency and rate limiting.

### New files to create

| File | What it does |
|------|-------------|
| `backend/core/brute_forcer.py` | `detect_login_endpoint(flows) -> list[dict]` — heuristics: POST to paths containing `login`, `auth`, `signin`, `token`; body contains `username`, `password`, `email`; response contains `token` or `Set-Cookie`; `BruteForceJob` orchestrator: parses auth type (HTTP Basic vs form), generates credential pairs, sends requests with `httpx.AsyncClient`, detects success (200/302 + session token), emits progress events |
| `backend/models/brute_force.py` | `BruteForceJob` model: `id`, `target_url`, `auth_type`, `username_field`, `password_field`, `wordlist_path`, `username`, `concurrency`, `rate_limit_rps`, `status`, `attempts_made`, `credentials_found` (JSON), `error`; `BruteForceAttempt` model: `id`, `job_id` (FK), `username`, `password`, `status_code`, `success`, `timestamp` |
| `backend/schemas/brute_force.py` | `BruteForceJobCreate`, `BruteForceJobOut`, `BruteForceCredential` |
| `backend/api/brute_force.py` | `POST /brute-force/detect` (auto-detect from session), `POST /brute-force/jobs`, `POST /brute-force/jobs/{id}/pause`, `POST /brute-force/jobs/{id}/resume`, `GET /brute-force/jobs/{id}`, `GET /brute-force/jobs/{id}/attempts` (paginated) |
| `backend/wordlists/top_passwords.txt` | Top 500 common passwords (create this file manually) |
| `frontend/src/types/brute_force.ts` | TypeScript interfaces |
| `frontend/src/api/brute_force.ts` | API client wrappers |
| `frontend/src/pages/BruteForcePage.tsx` | Endpoint detector panel, job config form (wordlist path, concurrency slider, RPS limit), live progress bar via WebSocket, found credentials table |

### Existing files to modify

| File | Change |
|------|--------|
| `backend/main.py` | Add `import models.brute_force  # noqa: F401` |
| `backend/api/router.py` | Register `brute_force_router` at `/brute-force` |
| `backend/api/ws.py` | Add `@ws_router.websocket("/brute-force/{job_id}")` |
| `backend/config.py` | Add `wordlists_dir: Path = Path(__file__).parent / "wordlists"` |
| `frontend/src/App.tsx` | Add `<Route path="/brute-force" element={<BruteForcePage />} />` |
| `frontend/src/components/layout/Sidebar.tsx` | Add entry with `KeyRound` icon |

### Implementation notes
- Rate limiting: `asyncio.sleep(1 / rate_limit_rps)` between batches. Update `attempts_made` in DB every 100 attempts.
- HTTP Basic auth: `base64(username:password)` in `Authorization: Basic` header.
- Success detection: response status 200/302 AND body/headers contain `token`, `access_token`, or `Set-Cookie` with a session value AND body does NOT contain `invalid`, `incorrect`, `failed`, `unauthorized`.
- Pause: set `status = "paused"` and check it in the run loop before each batch.

### Acceptance criteria
- [ ] "Detect Endpoints" scans proxy flows and proposes likely login endpoints.
- [ ] User can configure wordlist, concurrency, and rate limit before starting.
- [ ] Job can be paused and resumed.
- [ ] Found credentials appear immediately in the UI.
- [ ] Attempts are logged and paginated.

---

## Feature 10 — iOS / IPA Support

**Purpose:** Add a parallel analysis pipeline for iOS IPA files covering Info.plist, ATS config, entitlements, binary strings, and iOS-specific Frida hooks.

### New files to create

| File | What it does |
|------|-------------|
| `backend/core/ipa_analyzer.py` | `run_ipa_analysis(analysis_id, ipa_path, progress_queue, db_factory)`: (1) unzip IPA with `zipfile`, (2) parse `Info.plist` with `plistlib`, (3) extract entitlements from binary or codesign, (4) binary strings scan via regex `[\x20-\x7e]{4,}` over raw binary, (5) ATS config analysis from `NSAppTransportSecurity` dict, (6) persist `StaticFinding` rows tagged `platform="ios"` |
| `backend/frida_scripts/ios_ssl_pinning_bypass.js` | Frida script hooking `SecTrustEvaluate` and `SSLHandshake` on iOS |
| `backend/frida_scripts/ios_jailbreak_bypass.js` | Frida script hooking `NSFileManager fileExistsAtPath:` for common jailbreak paths |
| `backend/schemas/ipa.py` | `IpaSummary(bundle_id, min_ios_version, ats_config)`, `EntitlementInfo(key, value, risk_level)` |
| `backend/api/ipa.py` | `POST /ipa` (upload IPA), `GET /ipa/{analysis_id}/plist`, `GET /ipa/{analysis_id}/entitlements`, `GET /ipa/{analysis_id}/ats`, `GET /ipa/{analysis_id}/strings` |
| `frontend/src/types/ipa.ts` | TypeScript interfaces |
| `frontend/src/api/ipa.ts` | API client wrappers |
| `frontend/src/pages/IpaPage.tsx` | IPA upload widget, ATS config display, entitlements table with risk badges, binary strings tab |

### Existing files to modify

| File | Change |
|------|--------|
| `backend/models/analysis.py` | Add columns to `Analysis`: `platform: Mapped[str] = mapped_column(default="android")`, `bundle_id: Mapped[str \| None]`, `min_ios_version: Mapped[str \| None]`, `ats_config_json: Mapped[str \| None]` |
| `backend/api/router.py` | Register `ipa_router` at `/ipa` |
| `backend/core/frida_manager.py` | Extend `BUILTIN_SCRIPTS` with iOS script entries; modify `attach()` to accept `platform` param and load from platform-specific script set |
| `frontend/src/App.tsx` | Add `<Route path="/ipa" element={<IpaPage />} />` |
| `frontend/src/components/layout/Sidebar.tsx` | Add entry with `Tablet` icon |
| `frontend/src/pages/Dashboard.tsx` | Add IPA upload area alongside the existing APK upload |

### Alembic migration required
Add migration for new columns on `Analysis`: `platform`, `bundle_id`, `min_ios_version`, `ats_config_json`.

### Implementation notes
- IPA is a ZIP file — use Python's `zipfile` stdlib to extract. The main app bundle is in `Payload/*.app/`.
- `plistlib` handles both binary and XML plist formats natively (Python 3.4+).
- Entitlements risk: `com.apple.private.security.no-sandbox` = critical; `com.apple.developer.icloud-services` = medium; `aps-environment: development` = low info.
- ATS finding: `NSAllowsArbitraryLoads: true` = high severity finding.
- iOS Frida requires frida-server on a jailbroken device. Add a UI note about this requirement.

### Acceptance criteria
- [ ] IPA file uploads and analysis completes without errors.
- [ ] Info.plist values (bundle ID, min iOS version, permissions) displayed.
- [ ] ATS configuration parsed with flagged insecure exceptions.
- [ ] Entitlements listed with risk level per key.
- [ ] Binary strings scanned for secrets and URLs.
- [ ] iOS Frida scripts available in the Frida page when an iOS session is active.

---

## Feature 11 — Multi-APK Campaign

**Purpose:** Group multiple analyses into a named campaign and cross-correlate shared secrets, backend hosts, SDK versions, vulnerable components, and CVEs across all member APKs.

**Depends on:** CVE Correlation (Feature 2) for shared CVE detection.

### New files to create

| File | What it does |
|------|-------------|
| `backend/models/campaign.py` | `Campaign` model: `id`, `created_at`, `name`, `description`, `status` (`active`/`archived`), `correlation_json` (Text); `CampaignMember` model: `id`, `campaign_id` (FK), `analysis_id` (FK), `added_at`, `label` |
| `backend/core/campaign_correlator.py` | `correlate_campaign(campaign_id, db) -> dict` — loads all member analyses, cross-correlates: shared secrets (same `rule_id` + `evidence` match in ≥ 2 APKs), shared hosts (SQL GROUP BY host HAVING COUNT DISTINCT analysis_id > 1), shared SDK versions, shared vulnerable components, shared CVE IDs |
| `backend/schemas/campaign.py` | `CampaignCreate(name, description)`, `CampaignOut`, `CampaignDetail(campaign, members, correlation)`, `CampaignCorrelation(shared_secrets, shared_hosts, shared_sdks, shared_findings, shared_cves)` |
| `backend/api/campaign.py` | `POST /campaigns`, `GET /campaigns`, `GET /campaigns/{id}`, `POST /campaigns/{id}/members`, `DELETE /campaigns/{id}/members/{analysis_id}`, `POST /campaigns/{id}/correlate`, `GET /campaigns/{id}/correlation` |
| `frontend/src/types/campaign.ts` | TypeScript interfaces |
| `frontend/src/api/campaign.ts` | API client wrappers |
| `frontend/src/pages/CampaignPage.tsx` | Campaign list, campaign detail: member APK grid, correlation results grouped by category with occurrence counts, "Correlate" button |

### Existing files to modify

| File | Change |
|------|--------|
| `backend/main.py` | Add `import models.campaign  # noqa: F401` |
| `backend/api/router.py` | Register `campaign_router` at `/campaigns` |
| `frontend/src/App.tsx` | Add `<Route path="/campaigns" element={<CampaignPage />} />` and `<Route path="/campaigns/:id" element={<CampaignPage />} />` |
| `frontend/src/components/layout/Sidebar.tsx` | Add entry with `Layers` icon |
| `frontend/src/pages/Dashboard.tsx` | Add "Add to Campaign" action on each analysis row |

### Implementation notes
- Correlation is computed as a background task and cached in `correlation_json`. The GET endpoint returns the cached result.
- Shared host SQL: `SELECT host, COUNT(DISTINCT ds.analysis_id) as cnt FROM proxy_flows pf JOIN dynamic_sessions ds ON pf.session_id = ds.id WHERE ds.analysis_id IN (...) GROUP BY host HAVING cnt > 1`.
- Shared secrets: join `StaticFinding` on `rule_id` + extracted match value across analyses.

### Acceptance criteria
- [ ] Can create a named campaign and add any existing analyses as members.
- [ ] "Correlate" button runs cross-APK analysis.
- [ ] Shared secrets (same hardcoded key appearing in multiple APKs) are listed.
- [ ] Shared backend hosts shown with count of APKs that contact them.
- [ ] Shared CVEs and vulnerable SDK versions listed.

---

## Feature 12 — MCP Server

**Purpose:** Expose AppAnalysis as an MCP (Model Context Protocol) server so AI assistants like Claude Code can trigger analyses, query findings, run Frida scripts, and retrieve reports programmatically.

**Depends on:** All other features above being implemented.

### New files to create

| File | What it does |
|------|-------------|
| `backend/mcp_server.py` | Standalone MCP entry point; mounts JSON-RPC 2.0 transport via FastAPI sub-application; registers all tools and resources listed below |
| `backend/core/mcp_tools.py` | MCP tool handler functions (thin wrappers over DB queries): `list_analyses`, `get_analysis`, `upload_apk`, `get_findings`, `run_frida_script`, `get_proxy_flows`, `get_cve_matches`, `run_tls_audit`, `get_campaign_correlation`, `query_finding_search`; `generate_report(analysis_id, db) -> str` — markdown security report with executive summary, findings table, CVE table, permissions audit, recommendations |
| `backend/schemas/mcp.py` | `McpRequest(jsonrpc, method, params, id)`, `McpResponse(jsonrpc, result, error, id)`, `McpTool(name, description, input_schema)` |

### MCP Tools exposed

| Tool | Description |
|------|-------------|
| `list_analyses` | List all analyses with package name, version, platform, finding counts |
| `get_analysis(analysis_id)` | Full analysis detail + findings |
| `upload_apk(file_path)` | Trigger analysis from local file path, return analysis_id |
| `get_findings(analysis_id, severity_filter)` | Filtered findings list |
| `run_frida_script(session_id, script_name)` | Load a built-in Frida script |
| `get_proxy_flows(session_id, limit)` | Captured proxy flows |
| `get_cve_matches(analysis_id)` | CVE correlation results |
| `run_tls_audit(hosts)` | Initiate TLS audit for a list of hosts |
| `get_campaign_correlation(campaign_id)` | Cross-APK correlation results |
| `query_finding_search(analysis_id, query)` | Text search over findings |

### MCP Resources exposed

| Resource URI | Description |
|------|-------------|
| `analysis://{analysis_id}` | Analysis detail as plain text |
| `findings://{analysis_id}` | Findings as a markdown table |
| `report://{analysis_id}` | Full formatted security report in markdown |

### Existing files to modify

| File | Change |
|------|--------|
| `backend/main.py` | Mount MCP server at `/mcp`: `app.mount("/mcp", mcp_app)` |
| `backend/config.py` | Add `mcp_enabled: bool = True`, `mcp_auth_token: str \| None = None` |

### Implementation notes
- MCP uses JSON-RPC 2.0 over HTTP POST (`POST /mcp/messages`) for single requests and SSE for streaming (`GET /mcp/sse`).
- Tool schemas use JSON Schema Draft 7 — define `input_schema` as a Python dict per tool.
- Authentication: check `Authorization: Bearer {mcp_auth_token}` on each request if `mcp_auth_token` is configured.
- MCP tool handlers query the DB directly (not via HTTP) to avoid circular calls.
- Do not expose destructive operations (delete analysis, raw shell execution) by default. Add an `allow_mutations` config flag if needed.
- The `generate_report` resource produces: executive summary (score + grade), findings table sorted by severity, CVE matches table, dangerous permissions list, exported components list, recommendations.

### Acceptance criteria
- [ ] Claude Code can connect to AppAnalysis via MCP and list analyses.
- [ ] `get_findings` returns correctly filtered results.
- [ ] `generate_report` produces a readable markdown security report.
- [ ] Authentication blocks unauthenticated requests when `mcp_auth_token` is set.
- [ ] `upload_apk` triggers a full analysis and returns the analysis ID.

---

## Alembic Migrations Checklist

Run `alembic revision --autogenerate -m "<description>"` and `alembic upgrade head` after each group of model changes:

- [X] After Feature 1: `screenshots` table
- [X] After Feature 2: `detected_libraries`, `cve_matches` tables
- [X] After Feature 4: `tls_audits` table
- [X] After Feature 5: `jwt_tests` table
- [X] After Feature 6: `analysis_diffs` table
- [X] After Feature 8: `fuzz_jobs`, `fuzz_results` tables
- [X] After Feature 9: `brute_force_jobs`, `brute_force_attempts` tables
- [X] After Feature 10: `platform`, `bundle_id`, `min_ios_version`, `ats_config_json` columns on `analyses`
- [X] After Feature 11: `campaigns`, `campaign_members` tables

Feature 3 (WebView), Feature 7 (Risk), and Feature 12 (MCP) require no new DB tables — they operate on existing data.

---

## Sidebar Navigation Final State

After all features are implemented, `Sidebar.tsx` should have these entries (in addition to existing ones):

```
Existing:        Dashboard, Static Analysis, Dynamic Analysis, Proxy, Frida, Agent Console, OWASP Scan, Testing Lab, Settings
New (top-level): TLS Audit (Lock), JWT Testing (Key), API Fuzzer (Crosshair), Brute Force (KeyRound), iOS / IPA (Tablet), Campaigns (Layers), Diff (GitCompare)
Via Analysis:    CVE (ShieldAlert), WebView JS (Code2), Risk (BarChart2)  ← accessed from tabs inside Static Analysis
```

---

## Completion Checklist

- [x] Feature 1 — Screenshot Capture
- [x] Feature 2 — CVE Correlation
- [x] Feature 3 — JS / WebView Analysis
- [x] Feature 4 — TLS Audit
- [x] Feature 5 — JWT Attack Testing
- [x] Feature 6 — Diff / Change Detection
- [x] Feature 7 — Risk Graph & Scoring
- [x] Feature 8 — API Fuzzing
- [x] Feature 9 — Credential Brute Forcing
- [x] Feature 10 — iOS / IPA Support
- [x] Feature 11 — Multi-APK Campaign
- [x] Feature 12 — MCP Server
