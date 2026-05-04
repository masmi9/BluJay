```
██████╗ ██╗     ██╗   ██╗     ██╗ █████╗ ██╗   ██╗
██╔══██╗██║     ██║   ██║     ██║██╔══██╗╚██╗ ██╔╝
██████╔╝██║     ██║   ██║     ██║███████║ ╚████╔╝ 
██╔══██╗██║     ██║   ██║██   ██║██╔══██║  ╚██╔╝  
██████╔╝███████╗╚██████╔╝╚██████╔╝██║  ██║   ██║   
╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
```

A mobile application security analysis platform for Android and iOS. BluJay combines static analysis, dynamic instrumentation, traffic interception, active/passive scanning, race condition testing, OWASP MASVS compliance scanning, autonomous backend pentesting, APK repackaging, passive recon, WebSocket/GraphQL testing, PCI DSS testing, and local AI-powered triage into a single unified interface.

## Navigation

The sidebar is organized into consolidated modules:

| Tab | Contains |
|-----|---------|
| **Proxy** | Traffic capture, Repeater (Enhanced/Raw), Race Conditions |
| **API + Scanner** | Scanner, API Testing, Brute Force, WebSocket, GraphQL, Recon, Repackage, Strix Pentest |
| **Frida** | Dynamic instrumentation |
| **OWASP Scanner** | MASVS compliance scanning |
| **Agent Console** | AI-assisted Android analysis |
| **Decode** | TLS Audit, JWT Testing, AI Triage |
| **Diff / Change Detection** | APK/IPA version comparison |
| **Testing Checklist** | OWASP MASVS (iOS & Android) + WSTG progress tracker |
| **Settings** | Tool paths, proxy port, log level |

## Features

### Mobile Analysis
- **Static Analysis** — Decompile APKs (apktool + jadx) and IPAs, extract secrets, permissions, components, and binary strings
- **OWASP Scanner** — Full AODS (Android) and IODS (iOS) dynamic scans with MASVS compliance reporting
- **Proxy / Traffic Capture** — mitmproxy integration with a custom addon for intercepting, persisting, and replaying HTTP/S traffic from Android and iOS devices
- **Frida** — Dynamic instrumentation: attach to running apps, run scripts, hook methods in real time
- **iOS IPA Dump** — Pull decrypted IPAs from jailbroken devices using Frida + SSH/SFTP (three-phase: Frida locates the bundle and writes the decrypted segment patch to `/tmp` on-device, SFTP downloads the full `.app` bundle, host applies the patch and packages a valid IPA)
- **iOS Syslog** — Live syslog streaming from connected iOS devices via libimobiledevice

### Testing Checklist
Track progress across OWASP MASVS and WSTG test cases within a single engagement:

- **Mobile tab (iOS / Android toggle)** — Full OWASP MASVS v2.0 test case list organized by control group (STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE). Switch between iOS and Android checklists; progress is stored separately per platform.
- **Web tab** — OWASP WSTG v4.2 test cases organized by section (INFO, CONFIG, AUTHN, AUTHZ, SESS, INPUT, ERR, CRYPT, BUSLOGIC, CLIENT, API).
- Status cycle: `Not Started → In Progress → Pass → Fail` (click to cycle, per test case)
- Per-category progress bars and an overall summary bar across all test cases
- Persisted in browser localStorage per platform (`blujay_checklist_v1_mobile_ios`, `blujay_checklist_v1_mobile_android`, `blujay_checklist_v1_web`)

### Network & API
- **Scanner (Passive)** — Runs automatically on every proxied flow. Checks for missing security headers, insecure cookies, reflected input, sensitive data exposure, info disclosure, and CORS misconfigurations
- **Scanner (Active)** — Sends crafted payloads against target URLs or proxy flows to detect reflected XSS, SQL injection (error-based), open redirect, path traversal, and SSRF. URLs without query parameters are automatically seeded with common parameter names
- **Race Conditions** — HTTP/2 single-packet attack engine built into the Repeater. Switch to the Race Conditions sub-tab, set a thread count (1–50), and fire all requests simultaneously. Anomalous responses (different status or body size) are highlighted red — the key indicator of a race condition window
- **TLS Audit** — Validate certificate pinning and TLS configuration
- **JWT Testing** — Decode, forge, and test JWT tokens from intercepted traffic
- **API Testing** — Active API security test suite for IDOR sweeps, auth stripping, token replay, and cross-user authorization checks
- **Brute Force** — Credential stuffing and rate-limit testing against login endpoints
- **WebSocket Testing** — Connect to WS/WSS endpoints, probe with injection payloads, detect unauthenticated access, XSS reflection, prototype pollution, and JSON-RPC exposure. Auth-strip test included.
- **GraphQL Testing** — Introspection detection, batching abuse, alias overload (DoS), field suggestion leakage, injection, and unauthenticated mutation detection.
- **Recon** — Passive subdomain enumeration via certificate transparency (crt.sh) + DNS resolution + cloud storage bucket discovery (S3, GCS, Azure Blob). Derives bucket name candidates from APK package name. Feed results directly into Strix.
- **Strix Pentest Agent** — Autonomous AI-driven pentesting of backend targets (APIs, servers) discovered during mobile analysis. Runs multi-agent recon → exploit → PoC validation in a Docker sandbox. Findings are proof-of-concept validated before being reported.

### PCI DSS Testing
Interactive PCI DSS compliance test flow from the **PCI Testing** tab:

- Structured test cases mapped to PCI DSS requirements
- Live result tracking with pass/fail/pending states
- Streaming output for long-running checks

### APK Repackage + Resign
Decode, patch, recompile, and re-sign an APK in one click from the **Repackage** tab:

| Patch | What it does |
|-------|-------------|
| **SSL Pinning Bypass** | Injects `network_security_config.xml` to trust all CAs including user-installed mitmproxy cert |
| **Root Detection Bypass** | Stubs common root-check smali methods (`isRooted`, `checkRoot`, `detectRoot`, etc.) to always return false |
| **Force Debuggable** | Sets `android:debuggable="true"` in `AndroidManifest.xml` for dynamic attach |
| **Enable ADB Backup** | Sets `android:allowBackup="true"` for `adb backup` data extraction |

The patched APK is re-signed with a generated debug keystore (`blujay-debug.keystore`) and available for immediate download.

### Static Analysis Improvements
- **iOS Risk Scoring** — Calibrated risk scorer (denominator 1000) prevents score inflation on large commercial binaries
- **iOS Finding Enrichment** — All iOS findings carry `impact`, `attack_path`, and `evidence` fields. Rule IDs cover ATS misconfigurations, binary secrets, entitlement abuse, insecure frameworks, and sensitive permissions
- **Binary String Deduplication** — Scanner deduplicates findings per pattern (max 3 examples each) so a single binary with hundreds of weak-crypto references doesn't skew the risk score
- **Deep Secrets Scanner** — 55+ patterns covering AWS, GCP, Azure, GitHub, GitLab, Stripe, Square, PayPal, Twilio, SendGrid, Mailgun, Slack, Auth0, Okta, Shopify, HubSpot, Docker Hub, npm, and more

### AI & Reporting
- **AI Triage** — Local AI-powered vulnerability analysis using metatron-qwen (fine-tuned Qwen via Ollama). No cloud, no API keys. Accepts output from any scan module and returns severity classification, OWASP MASVS mapping, and remediation steps. Includes consolidated session reports that correlate findings across all modules and identify attack chains.
- **Agent Console** — AI-assisted Android agent for manifest analysis, permission auditing, exported component enumeration, and IPC analysis
- **Risk Scoring** — Unified risk score across all findings for a session
- **HTML Report Export** — Self-contained HTML report (inline CSS, dark theme) covering static findings, OWASP results, and network scanner findings. Download from any completed analysis.
- **SARIF Export** — SARIF 2.1.0 output compatible with GitHub Code Scanning, GitLab SAST, and any CI/CD pipeline that supports the standard. Export button on every analysis page.

### CI/CD Headless Mode
Run BluJay scans without the frontend from any pipeline:

```bash
# Install requests (only external dep for the CLI)
pip install requests

# Scan and export SARIF (for GitHub Actions / GitLab CI)
python backend/cli.py scan --apk app.apk --format sarif --output results.sarif

# Fail the build if any high/critical findings are present
python backend/cli.py scan --apk app.apk --fail-on high
```

Add to **GitHub Actions**:
```yaml
- name: BluJay scan
  run: python backend/cli.py scan --apk app/build/outputs/apk/release/app.apk --format sarif --output blujay.sarif --fail-on high
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: blujay.sarif
```

### Device Management
- **Dashboard** — Android (ADB) and iOS (libimobiledevice) device management, one-click Pull & Analyze
- **WebView Inspector** — Detect and audit WebView configurations in running apps
- **Screenshot Capture** — Capture device screenshots during dynamic sessions

## How API Testing Works

The API Testing module is designed around the idea that the proxy is doing the reconnaissance — you don't need to manually enter URLs.

```
Proxy Session (traffic capture)
        │
        ▼
Build from Proxy Flows  →  Extracts auth tokens, resource IDs, URL patterns
        │
        ▼
Suggested Tests  →  IDOR Sweep, Auth Strip, Token Replay, Cross-User Auth
        │
        ▼
Run Test  →  WebSocket streams live results back to the UI
        │
        ▼
Export vulnerable findings  →  Saved to Static Findings (same as OWASP results)
```

### Test Types

| Type | What it does |
|------|-------------|
| **IDOR Sweep** | Takes an endpoint with a resource ID in the URL/params, replays with 25 foreign IDs, flags responses that return data |
| **Auth Strip** | Sends the request three ways: with original auth, without any auth header, and with a mangled token. Flags if no-auth or mangled returns data |
| **Token Replay** | Captures a valid token, pauses and waits for you to log out of the app, then replays the token — detects missing server-side session invalidation |
| **Cross-User Auth** | With two or more captured auth contexts, swaps Account B's token on Account A's resource — detects BOLA (Broken Object Level Authorization) |

### Dynamic Activation

Navigate to `/api-testing?session=N` to link the module to an active proxy session. The left panel shows a green "Session #N active" indicator. When you click **Build from Proxy Flows**, the backend:

1. Scans all captured proxy flows for that session
2. Extracts auth headers (`Authorization`, `X-Auth-Token`, session cookies, etc.)
3. Normalizes URL patterns (digits → `{id}`)
4. Extracts ID-bearing parameters (Snowflake IDs, `user_id`, `object_id`, etc.)
5. Returns suggested tests with pre-filled URLs and headers

### Fuzzer Tab

The **Fuzzer** tab inside API Testing is the full API fuzzer — enter a session ID or analysis ID, select attack types, and start a fuzz job. Results stream live and are stored alongside your test suite history.

## How Strix and AI Triage Work Together

```
Static Analysis / Proxy Session
        │
        ▼
Extract backend URL (hardcoded in APK strings, captured in proxy traffic)
        │
        ▼
Strix Pentest Agent  ──►  Autonomous exploit agents in Docker sandbox
        │                  Recon → exploit → PoC validation
        ▼
AI Triage → Analyze      Paste Strix findings for severity + remediation
AI Triage → Session Report  Consolidate all module findings into one report
```

The **auto-triage** option on the Strix page feeds findings directly into metatron-qwen after a scan completes — no manual copy-paste required.

## Monorepo Structure

```
BluJay/
├── backend/
│   ├── api/              # FastAPI routers — one file per feature module (35 total)
│   │   ├── analysis.py, proxy.py, frida.py, owasp.py
│   │   ├── strix.py, ollama.py, scanner.py, api_testing.py
│   │   ├── repackage.py, recon.py, race.py, brute_force.py
│   │   ├── ws_test.py, graphql_test.py, tls_audit.py, jwt_test.py
│   │   ├── ios_devices.py, adb.py, pci.py, report.py, ...
│   │   └── router.py     # registers all routers
│   ├── core/             # Business logic and tool wrappers (52 modules)
│   │   ├── proxy_manager.py, proxy_addon.py
│   │   ├── apk_analyzer.py, ipa_analyzer.py
│   │   ├── frida_manager.py, frida_dump.py
│   │   ├── passive_scanner.py, active_scanner.py, secret_scanner.py
│   │   ├── repackage_engine.py, recon_engine.py, race_engine.py
│   │   ├── api_fuzzer.py, api_test_engine.py
│   │   ├── pci_*.py      # PCI DSS testing modules
│   │   ├── jadx_wrapper.py, apktool_wrapper.py
│   │   ├── tool_detector.py, ios_device_manager.py
│   │   └── risk_scorer.py, finding_enricher.py, ...
│   ├── models/           # SQLAlchemy ORM models
│   ├── schemas/          # Pydantic request/response schemas
│   ├── migrations/       # Alembic database migrations
│   ├── frida_scripts/    # Bundled Frida instrumentation scripts
│   ├── wordlists/        # Security testing wordlists
│   ├── config.py         # Pydantic-settings configuration
│   ├── requirements.txt
│   └── run.py            # Uvicorn entry point
├── frontend/
│   ├── src/
│   │   ├── pages/        # One page component per feature (30 total)
│   │   │   ├── Dashboard.tsx, StaticAnalysis.tsx, DynamicAnalysis.tsx
│   │   │   ├── ProxyPage.tsx, ScannerPage.tsx, ApiScannerPage.tsx
│   │   │   ├── StrixPage.tsx, AiTriagePage.tsx, AgentConsole.tsx
│   │   │   ├── RepackagePage.tsx, ReconPage.tsx, RiskPage.tsx
│   │   │   ├── WsTestPage.tsx, GraphqlPage.tsx, PciTestPage.tsx
│   │   │   ├── ChecklistPage.tsx   # MASVS + WSTG progress tracker
│   │   │   └── Settings.tsx, ...
│   │   ├── components/   # Shared UI components
│   │   │   ├── layout/   # Sidebar, TopBar, StatusBar
│   │   │   ├── common/   # Badge, CodeBlock, SplitPane
│   │   │   └── analysis/ # RiskScoreCard, RiskGraph
│   │   ├── api/          # Axios API client wrappers
│   │   ├── hooks/        # Custom React hooks
│   │   ├── store/        # Zustand state management
│   │   └── types/        # TypeScript interfaces
│   └── package.json
├── scanners/
│   ├── aods/             # Android OWASP Dynamic Scanner (dyna.py + venv)
│   └── iods/             # iOS OWASP Dynamic Scanner (ios_scan.py + venv)
├── scripts/
│   ├── setup_windows.ps1 # Downloads apktool, jadx, platform-tools (Windows)
│   └── setup_linux.sh    # Same for Linux/macOS/WSL
├── tools/                # apktool.jar, jadx/, platform-tools/ — not committed
└── docker/               # Strix sandbox configuration
```

## Prerequisites

| Tool | Purpose |
|------|---------|
| Python 3.11+ | Backend + scanners |
| Node.js 18+ | Frontend |
| Java 11+ | apktool / jadx |
| ADB (platform-tools) | Android device management |
| libimobiledevice | iOS device management |
| Frida | Dynamic instrumentation |
| mitmproxy | Traffic interception |
| Docker | Required by Strix sandbox |
| Strix CLI | Autonomous pentest agent |
| Ollama + metatron-qwen | Local AI triage (no API key needed) |

## Quick Start

### Tools

```bash
# Windows
powershell -ExecutionPolicy Bypass -File scripts/setup_windows.ps1

# Linux / macOS / WSL
bash scripts/setup_linux.sh
```

This downloads `apktool.jar`, `jadx`, and Android `platform-tools` into `tools/`.

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
# or: source venv/bin/activate  # Linux/macOS/WSL
pip install -r requirements.txt
python run.py          # development (hot-reload on by default)
python run.py --no-reload  # stable — use this when running the proxy
```

> **Note:** Use `--no-reload` when using the proxy. Hot-reload wipes the `ProxyManager` state and orphans any running `mitmdump` process, which prevents new proxy sessions from starting until the orphan is killed.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Scanners

Each scanner has its own virtualenv to avoid dependency conflicts:

```bash
# AODS (Android)
cd scanners/aods
python -m venv aods_venv
aods_venv\Scripts\activate
pip install -r requirements/base.txt

# IODS (iOS)
cd scanners/iods
python -m venv iods_venv
iods_venv\Scripts\activate
pip install -r requirements/base.txt
```

### Strix

```bash
# Install (Linux/WSL)
curl -sSL https://strix.ai/install | bash
source ~/.bashrc

# Configure LLM (add to ~/.bashrc for persistence)
export LLM_API_KEY=your-api-key
export STRIX_LLM=anthropic/claude-sonnet-4-6   # or openai/gpt-4o

# To use local Ollama instead (no API key)
export LLM_API_KEY=ollama
export LLM_API_BASE=http://localhost:11434
export STRIX_LLM=ollama/metatron-qwen
```

> **Windows users:** Strix installs into WSL. The backend detects it automatically via a WSL wrapper. If `strix` is not found, add it to your WSL PATH and ensure the WSL distribution is running.

### AI Triage (Ollama + metatron-qwen)

```bash
# Install Ollama: https://ollama.com
# Then build and run the metatron-qwen model:
git clone https://github.com/sooryathejas/METATRON
cd METATRON
ollama create metatron-qwen -f Modelfile
ollama run metatron-qwen
```

## Proxy Setup

### Verifying the proxy is running

After clicking **Start** on the Proxy page, confirm the `mitmdump` process launched successfully:

```
GET http://localhost:8000/api/v1/proxy/status/0
```

Expected response when running correctly:
```json
{ "running": true, "pid": 12345, "port": 8080 }
```

If you get `{ "running": false, "pid": null }`:

| Cause | Fix |
|-------|-----|
| **Proxy was never started** | Click **Start** on the Proxy page first |
| **Hot-reload wiped the session** | Restart with `python run.py --no-reload`, then click Start |
| **Orphaned `mitmdump` holding port 8080** | Run `taskkill /F /IM mitmdump.exe`, then restart the backend and click Start |
| **`mitmdump` not found** | Ensure `mitmproxy` is installed in the same venv as the backend: `pip install mitmproxy` |

### Android traffic capture

The proxy uses `adb reverse` to tunnel traffic through the USB connection — this bypasses Windows Firewall and avoids network topology issues entirely.

1. Start the backend with `--no-reload`
2. Click **Start** on the Proxy page — verify status returns `running: true`
3. Click **Configure Device** — this automatically runs `adb reverse tcp:8080 tcp:8080` and sets the device proxy to `127.0.0.1:8080`
4. Install the CA cert on the device:
   - The cert is pushed to `/sdcard/Download/mitmproxy-ca-cert.pem` automatically
   - **Android 11+:** Settings → Security → Encryption & credentials → Install a certificate → CA certificate → select the `.pem` from Downloads
   - Confirm it appears under Settings → Security → Trusted credentials → User tab
5. Test with `http://neverssl.com` in the device browser — the request should appear in the flow table immediately

> **HTTPS in modern apps (Android 7+):** Apps targeting API 24+ reject user-installed CA certs by default due to Network Security Config. Use the **Frida** page to attach to the target app and load the **SSL Pinning Bypass** script to force the app to trust the mitmproxy cert.

To manually set up the ADB reverse tunnel without clicking Configure Device:
```bash
adb reverse tcp:8080 tcp:8080
adb shell settings put global http_proxy 127.0.0.1:8080

# To clear when done:
adb shell settings put global http_proxy :0
adb reverse --remove tcp:8080
```

### iOS traffic capture

1. Connect iPhone via USB
2. Start the proxy, then click **iOS Setup** in the toolbar (visible when an iOS device is detected)
3. Start the cert server → scan the QR code with the iPhone camera
4. Install the cert: Settings → General → VPN & Device Management → install
5. Enable full trust: Settings → General → About → Certificate Trust Settings → toggle mitmproxy on
6. Set the Wi-Fi proxy manually on the iPhone: Settings → Wi-Fi → [network] → Configure Proxy → Manual → enter your PC's LAN IP and port 8080
7. For apps with SSL pinning: attach Frida and load the **iOS SSL Pinning Bypass** script

## Configuration

Copy `backend/.env` and adjust paths as needed. Tool path defaults in `config.py` resolve automatically relative to the repo root — only set them explicitly if your tools are installed elsewhere:

```env
# Server
HOST=127.0.0.1
PORT=8000

# Workspace
WORKSPACE_DIR=~/.blujay

# Tool paths — omit these to use the defaults (tools/ dir relative to repo root)
# APKTOOL_JAR=/custom/path/apktool.jar
# JADX_PATH=/custom/path/jadx
# ADB_PATH=/custom/path/adb

# Proxy
PROXY_HOST=0.0.0.0
PROXY_PORT=8089

# Scanner paths
AODS_PATH=scanners/aods/dyna.py
AODS_VENV_PYTHON=scanners/aods/aods_venv/Scripts/python.exe
IODS_PATH=scanners/iods/ios_scan.py
IODS_VENV_PYTHON=scanners/iods/iods_venv/Scripts/python.exe

# Logging: DEBUG | INFO | WARNING | ERROR
LOG_LEVEL=INFO
```

> **Important:** Do not set `APKTOOL_JAR`, `JADX_PATH`, or `ADB_PATH` to relative paths. Pydantic-settings resolves them relative to the working directory at server startup (`backend/`), not the repo root. The defaults in `config.py` use `Path(__file__).parent.parent` and resolve correctly without any override.

## API

The backend exposes a REST API at `http://localhost:8000/api/v1`. Interactive docs available at `http://localhost:8000/docs`.

Key endpoint groups:

| Prefix | Description |
|--------|-------------|
| `/analyses` | Static analysis (APK/IPA upload + device pull) |
| `/sessions` | Dynamic analysis sessions |
| `/proxy` | Proxy flows, replay, repeater |
| `/frida` | Dynamic instrumentation |
| `/owasp` | OWASP MASVS scanner |
| `/strix` | Autonomous pentest scans |
| `/ollama` | AI triage (metatron-qwen) |
| `/cve` | CVE correlation |
| `/api-testing` | API test suites, tests, results, fuzzing |
| `/fuzzing` | Standalone API fuzzing jobs |
| `/tls` | TLS audit |
| `/jwt` | JWT testing |
| `/brute-force` | Brute force jobs |
| `/ios-devices` | iOS device management + pull-and-analyze |
| `/devices` | Android (ADB) device management |
| `/pci` | PCI DSS compliance testing |
| `/scanner` | Passive + active web scanner |
| `/recon` | Passive subdomain and cloud bucket enumeration |
| `/repackage` | APK decode, patch, and resign |
| `/race` | HTTP/2 race condition testing |
| `/ws-test` | WebSocket security testing |
| `/graphql-test` | GraphQL security testing |

## Workspace

Runtime data (database, decompiled output, uploaded APKs/IPAs, mitmproxy certs, Strix run output) is stored in `~/.blujay/` and is never committed.

## License

Private — all rights reserved.
