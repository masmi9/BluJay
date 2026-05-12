```
██████╗ ██╗     ██╗   ██╗     ██╗ █████╗ ██╗   ██╗
██╔══██╗██║     ██║   ██║     ██║██╔══██╗╚██╗ ██╔╝
██████╔╝██║     ██║   ██║     ██║███████║ ╚████╔╝ 
██╔══██╗██║     ██║   ██║██   ██║██╔══██║  ╚██╔╝  
██████╔╝███████╗╚██████╔╝╚██████╔╝██║  ██║   ██║   
╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
```

A mobile and web application security platform for intermediate–senior AppSec engineers. BluJay combines static analysis, dynamic instrumentation, traffic interception, a standalone Burp-style repeater, auth/session testing, vulnerability intelligence, cloud security testing, protocol testing, race condition testing, OWASP MASVS compliance scanning, autonomous backend pentesting, APK repackaging, passive recon, WebSocket/GraphQL testing, PCI DSS testing, CTF automation, and local AI-powered triage into a single unified interface.

## Navigation

| Tab | Contains |
|-----|---------|
| **Proxy** | Traffic capture, Send to Repeater |
| **Repeater** | Standalone request editor (Enhanced/Raw), Race Conditions, Diff mode, Match & Replace, History |
| **API + Scanner** | Scanner, API Testing, Brute Force, WebSocket, GraphQL, Recon, Repackage, Strix Pentest |
| **CTF Mode** | Automated recon pipeline (nmap → scope → Strix), persistent scan history |
| **Auth & Session Tester** | JWT decode/forge/verify, OAuth/OIDC audit, session cookie analysis, SAML decode |
| **Vulnerability Intelligence** | CVE search (NVD), version-match scanning, Nuclei scanner, ExploitDB |
| **Cloud Tester** | IMDS probing, SSRF payloads, bucket enumeration, credential scanning/validation |
| **Protocol Tester** | TLS/SSL analysis, subdomain enumeration (crt.sh + DNS), LDAP, gRPC |
| **AI Triage** | Multi-source findings triage via Ollama (metatron-qwen), session reports |
| **Frida** | Dynamic instrumentation |
| **OWASP Scanner** | MASVS compliance scanning |
| **PCI DSS Scanner** | Interactive PCI DSS compliance test flow |
| **Agent Console** | AI-assisted Android analysis |
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

### Repeater
Standalone Burp-style request editor at `/repeater`:

- **Form mode** — Method selector, URL bar, headers editor, body editor with content-type picker, follow-redirects / verify-SSL / timeout options
- **Raw mode** — Edit the full HTTP request as text (Burp-style); syncs bidirectionally with form mode
- **Raw view tab** — Read-only render of the outgoing HTTP request for copy-paste
- **Match & Replace rules** — Regex find/replace applied to `url`, `headers`, `body`, or `all` before each send
- **Response viewer** — Status, elapsed time, size, redirect count, body/headers tabs, copy button
- **Diff mode** — Pin any response as baseline; click Diff to see line-by-line delta against the next response
- **Race Conditions** — Switch to the Race Conditions tab, set a thread count (1–50), fire all requests simultaneously. Anomalous responses (different status or body size) are highlighted — the key indicator of a race condition window
- **History sidebar** — All sent requests are saved automatically; reload any entry to continue editing
- **Send to Repeater** — Click the button in Proxy's flow detail panel to pre-populate Repeater with a captured flow (method, URL, headers, body passed via sessionStorage)

### Auth & Session Tester
Full authentication and session security testing at `/auth-tester`:

**JWT tab**
- Decode any JWT (header, payload, signature validation)
- Detect vulnerabilities: weak `alg`, missing `exp`, `kid` SQLi/path-traversal, `jku`/`x5u` presence
- Forge attacks: `alg:none` (strip signature), RS256→HS256 key confusion, `kid` SQL injection, `kid` path traversal, custom claim editing
- Verify JWT against a provided public key or HMAC secret

**OAuth/OIDC tab**
- Audit OAuth 2.0 flows for: state CSRF, PKCE enforcement, implicit flow usage, redirect_uri whitelist, nonce replay, token leakage in referrer

**Session & Cookie tab**
- Analyze `Set-Cookie` headers for `HttpOnly`, `Secure`, `SameSite` flags, `__Host-`/`__Secure-` prefix compliance
- Shannon entropy scoring on session token values to detect predictable IDs

**SAML tab**
- Decode and inspect SAML assertions (base64 + zlib inflate)
- Detect unsigned assertions, wrapping attack vectors

### Vulnerability Intelligence
CVE and exploit research at `/vuln-intel`:

**CVE Search tab**
- Keyword search against NVD API v2 with severity, score, CWE, CPE, and CVSS metrics displayed
- Version-match mode: specify product + version, checks all known CPEs — returns CVEs affecting that exact release
- 24-hour MD5-keyed cache; respects NVD rate limits (0.7s between requests); `NVD_API_KEY` env var for 50 req/30s tier

**Nuclei Scanner tab**
- Launch Nuclei scans against a target URL with configurable template tags, severity filter, and rate limit
- Results parsed from JSONL output and streamed to the UI (background task with poll endpoint)
- Cross-platform binary detection (Windows/Mac/Linux + common install paths)

**ExploitDB tab**
- Search ExploitDB via `searchsploit --json` with automatic web API fallback
- Results show exploit ID, title, type, platform, and link to exploit-db.com

### Cloud Tester
Cloud security testing at `/cloud-tester`:

**IMDS / SSRF tab**
- Probe AWS, GCP, Azure, and DigitalOcean IMDS endpoints directly or via SSRF callback URL
- 6 SSRF payload variants per provider: direct IP, octal encoding (`0177.0.0.01`), nip.io DNS rebind, IPv6, percent-encoded, short URL
- Credential fields extracted and redacted in results (shows first 4 + last 4 chars)

**Bucket Audit tab**
- Unauthenticated enumeration of S3 (ListObjects), GCS (list), and Azure Blob Storage containers
- Tests for public read and anonymous write access
- Specify provider, bucket name, and region

**Credential Scanner tab**
- Scan arbitrary text (APK strings, config files, env dumps) for 6 credential pattern families: AWS Access Key, AWS Secret, GCP Service Account JSON, Azure Connection String, Azure SAS Token, generic API key patterns
- Validate AWS credentials live against STS `GetCallerIdentity` (requires boto3)
- All found secrets redacted in display output

### Protocol Tester
Low-level protocol security testing at `/protocol-tester`:

**TLS/SSL tab**
- Probe supported TLS versions: SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3
- Parse certificate: subject, issuer, SANs, validity window, self-signed detection
- Classify known vulnerabilities: BEAST (CBC + TLS ≤1.0), POODLE (SSLv3), LOGJAM (TLS 1.0/1.1), DROWN (SSLv2/SSLv3)

**Subdomains tab**
- crt.sh certificate transparency lookup + async DNS A/AAAA resolution (50 concurrent)
- Brute-force DNS check against 80 common subdomain prefixes
- Deduplicated results with IP addresses and active/inactive status

**LDAP tab**
- Anonymous bind → rootDSE probe (server info, supported controls, naming contexts)
- User enumeration via `(objectClass=person)` search
- Password policy extraction
- Authenticated bind with custom DN/password

**gRPC tab**
- Server reflection (lists available services + methods + proto descriptor)
- Send unary requests with JSON payload to any reflected method
- Fuzz suite: 15 payloads covering empty string, null byte, oversized string (8192 chars), SQL injection, NoSQL, path traversal, SSTI (`{{7*7}}`), format string, unicode BiDi, oversized int, negative int, float overflow, null JSON, array, nested object

### CTF Mode
Automated recon pipeline at `/ctf`:

- Start a scan with just a target hostname/IP — BluJay runs nmap → scope analysis → Strix pentest agent in sequence
- **Persistent scan history** backed by `backend/data/ctf_scans.json` (survives server restarts)
- Scan rows show: open ports, Strix finding count, current phase, time ago, and delete button
- Clear-all button (blocked while any scan is running)
- Unity C2 integration and MobileMorphAgent capabilities for post-exploitation simulation

### Testing Checklist
Track progress across OWASP MASVS and WSTG test cases within a single engagement:

- **Mobile tab (iOS / Android toggle)** — Full OWASP MASVS v2.0 test case list organized by control group (STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE). Switch between iOS and Android checklists; progress is stored separately per platform.
- **Web tab** — OWASP WSTG v4.2 test cases organized by section (INFO, CONFIG, AUTHN, AUTHZ, SESS, INPUT, ERR, CRYPT, BUSLOGIC, CLIENT, API).
- Status cycle: `Not Started → In Progress → Pass → Fail` (click to cycle, per test case)
- Per-category progress bars and an overall summary bar across all test cases
- Persisted in browser localStorage per platform

### Network & API
- **Scanner (Passive)** — Runs automatically on every proxied flow. Checks for missing security headers, insecure cookies, reflected input, sensitive data exposure, info disclosure, and CORS misconfigurations
- **Scanner (Active)** — Sends crafted payloads against target URLs or proxy flows to detect reflected XSS, SQL injection (error-based), open redirect, path traversal, and SSRF
- **API Testing** — Active API security test suite for IDOR sweeps, auth stripping, token replay, and cross-user authorization checks
- **Brute Force** — Credential stuffing and rate-limit testing against login endpoints
- **WebSocket Testing** — Connect to WS/WSS endpoints, probe with injection payloads, detect unauthenticated access, XSS reflection, prototype pollution, and JSON-RPC exposure
- **GraphQL Testing** — Introspection detection, batching abuse, alias overload (DoS), field suggestion leakage, injection, and unauthenticated mutation detection
- **Recon** — Passive subdomain enumeration via certificate transparency (crt.sh) + DNS resolution + cloud storage bucket discovery (S3, GCS, Azure Blob)
- **Strix Pentest Agent** — Autonomous AI-driven pentesting of backend targets. Runs multi-agent recon → exploit → PoC validation in a Docker sandbox

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
- **iOS Finding Enrichment** — All iOS findings carry `impact`, `attack_path`, and `evidence` fields
- **Binary String Deduplication** — Scanner deduplicates findings per pattern (max 3 examples each)
- **Deep Secrets Scanner** — 55+ patterns covering AWS, GCP, Azure, GitHub, GitLab, Stripe, Square, PayPal, Twilio, SendGrid, Mailgun, Slack, Auth0, Okta, Shopify, HubSpot, Docker Hub, npm, and more

### AI & Reporting
- **AI Triage** — Local AI-powered vulnerability analysis using metatron-qwen (fine-tuned Qwen via Ollama). No cloud, no API keys. Accepts output from any scan module and returns severity classification, OWASP MASVS mapping, and remediation steps. Includes consolidated session reports that correlate findings across all modules and identify attack chains.
- **Agent Console** — AI-assisted Android agent for manifest analysis, permission auditing, exported component enumeration, and IPC analysis
- **Risk Scoring** — Unified risk score across all findings for a session
- **HTML Report Export** — Self-contained HTML report (inline CSS, dark theme) covering static findings, OWASP results, and network scanner findings
- **SARIF Export** — SARIF 2.1.0 output compatible with GitHub Code Scanning, GitLab SAST, and any CI/CD pipeline that supports the standard

### CI/CD Headless Mode
Run BluJay scans without the frontend from any pipeline:

```bash
pip install requests
python backend/cli.py scan --apk app.apk --format sarif --output results.sarif
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

## How the AppSec Workflow Fits Together

```
Mobile App  ──►  Static Analysis → secrets, perms, components, risk score
     │
     ▼
Proxy (traffic capture)
     │
     ├──► Send to Repeater  →  edit, replay, diff, race
     │
     ├──► Send to Scanner   →  active XSS/SQLi/SSRF/redirect checks
     │
     └──► API Testing        →  IDOR, auth strip, token replay, cross-user auth
     │
     ▼
Auth & Session Tester  →  JWT forge/verify, OAuth audit, cookie flags, SAML
     │
     ▼
Protocol Tester        →  TLS version probing, subdomain enum, LDAP, gRPC fuzz
     │
     ▼
Cloud Tester           →  IMDS probe, SSRF payloads, bucket ACL, cred scan
     │
     ▼
Vuln Intelligence      →  CVE/NVD match, Nuclei scan, ExploitDB lookup
     │
     ▼
Strix Pentest Agent    →  autonomous exploit validation in Docker sandbox
     │
     ▼
AI Triage              →  severity, OWASP mapping, remediation, session report
```

## Monorepo Structure

```
BluJay/
├── backend/
│   ├── api/              # FastAPI routers — one file per feature module (40 total)
│   │   ├── analysis.py, proxy.py, frida.py, owasp.py
│   │   ├── strix.py, ollama.py, scanner.py, api_testing.py
│   │   ├── repackage.py, recon.py, race.py, brute_force.py
│   │   ├── ws_test.py, graphql_test.py, pci.py, report.py
│   │   ├── repeater.py       # Standalone Burp-style HTTP repeater + history
│   │   ├── auth_tester.py    # JWT, OAuth/OIDC, session/cookie, SAML
│   │   ├── vuln_intel.py     # CVE/NVD, Nuclei, ExploitDB
│   │   ├── cloud_tester.py   # IMDS, SSRF, bucket, credential scan/validate
│   │   ├── protocol_tester.py # TLS, subdomain enum, LDAP, gRPC
│   │   └── router.py         # registers all routers
│   ├── core/             # Business logic and tool wrappers
│   ├── models/           # SQLAlchemy ORM models
│   ├── schemas/          # Pydantic request/response schemas
│   ├── migrations/       # Alembic database migrations
│   ├── frida_scripts/    # Bundled Frida instrumentation scripts
│   ├── wordlists/        # Security testing wordlists
│   ├── data/             # Runtime JSON persistence (CTF scans, repeater history, vuln cache)
│   ├── config.py
│   ├── requirements.txt
│   └── run.py
├── frontend/
│   ├── src/
│   │   ├── pages/        # One page component per feature (35 total)
│   │   │   ├── Dashboard.tsx, StaticAnalysis.tsx, DynamicAnalysis.tsx
│   │   │   ├── ProxyPage.tsx, ScannerPage.tsx, ApiScannerPage.tsx
│   │   │   ├── RepeaterPage.tsx      # Standalone repeater + race + diff + history
│   │   │   ├── AuthTesterPage.tsx    # JWT, OAuth, session/cookie, SAML
│   │   │   ├── VulnIntelPage.tsx     # CVE, Nuclei, ExploitDB
│   │   │   ├── CloudTesterPage.tsx   # IMDS, SSRF, buckets, credentials
│   │   │   ├── ProtocolTesterPage.tsx # TLS, subdomains, LDAP, gRPC
│   │   │   ├── CTFPage.tsx           # CTF auto-recon with persistent history
│   │   │   ├── AiTriagePage.tsx      # Standalone AI triage (Ollama)
│   │   │   ├── StrixPage.tsx, AgentConsole.tsx
│   │   │   ├── RepackagePage.tsx, ReconPage.tsx, RiskPage.tsx
│   │   │   ├── WsTestPage.tsx, GraphqlPage.tsx, PciTestPage.tsx
│   │   │   ├── ChecklistPage.tsx
│   │   │   └── Settings.tsx, ...
│   │   ├── api/          # Axios API client wrappers
│   │   │   ├── repeater.ts, authTester.ts, vulnIntel.ts
│   │   │   ├── cloudTester.ts, protocolTester.ts
│   │   │   └── proxy.ts, scanner.ts, strix.ts, ollama.ts, ...
│   │   ├── components/   # Shared UI components
│   │   ├── hooks/        # Custom React hooks
│   │   ├── store/        # Zustand state management
│   │   └── types/        # TypeScript interfaces
│   └── package.json
├── scanners/
│   ├── aods/             # Android OWASP Dynamic Scanner
│   └── iods/             # iOS OWASP Dynamic Scanner
├── scripts/
│   ├── setup_windows.ps1
│   └── setup_linux.sh
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
| Nuclei | Template-based vulnerability scanner (optional) |
| ldap3 | LDAP testing (`pip install ldap3`, optional) |
| grpcio | gRPC testing (`pip install grpcio grpcio-reflection`, optional) |
| boto3 | AWS credential validation (`pip install boto3`, optional) |

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

> **Note:** Use `--no-reload` when using the proxy. Hot-reload wipes the `ProxyManager` state and orphans any running `mitmdump` process.

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
cd scanners/aods && python -m venv aods_venv && aods_venv\Scripts\activate && pip install -r requirements/base.txt

# IODS (iOS)
cd scanners/iods && python -m venv iods_venv && iods_venv\Scripts\activate && pip install -r requirements/base.txt
```

### Strix

**Linux / WSL terminal:**
```bash
curl -sSL https://strix.ai/install | bash
source ~/.bashrc

export LLM_API_KEY=your-api-key
export STRIX_LLM=anthropic/claude-sonnet-4-6   # or openai/gpt-4o

# Local Ollama (no API key)
export LLM_API_KEY=ollama
export LLM_API_BASE=http://localhost:11434
export STRIX_LLM=ollama/metatron-qwen
```

**Windows (PowerShell) — Strix runs inside WSL, BluJay bridges automatically:**
```powershell
wsl bash -c "curl -sSL https://strix.ai/install | bash && source ~/.bashrc"
wsl bash -c "echo 'export LLM_API_KEY=ollama' >> ~/.bashrc"
wsl bash -c "echo 'export LLM_API_BASE=http://localhost:11434' >> ~/.bashrc"
wsl bash -c "echo 'export STRIX_LLM=ollama/metatron-qwen' >> ~/.bashrc"
wsl strix --version
```

### AI Triage (Ollama + metatron-qwen)

```bash
# Install Ollama: https://ollama.com
git clone https://github.com/sooryathejas/METATRON
cd METATRON
ollama create metatron-qwen -f Modelfile
ollama run metatron-qwen
```

> Ollama listens on `http://localhost:11434` — the BluJay backend connects to the same URL on both Windows and Linux.

## Proxy Setup

### Android traffic capture

1. Start the backend with `--no-reload`
2. Click **Start** on the Proxy page
3. Click **Configure Device** — runs `adb reverse tcp:8080 tcp:8080` and sets device proxy to `127.0.0.1:8080`
4. Install the CA cert on the device (pushed automatically to `/sdcard/Download/mitmproxy-ca-cert.pem`)
   - Android 11+: Settings → Security → Encryption & credentials → Install a certificate → CA certificate
5. Test with `http://neverssl.com` — the request should appear in the flow table immediately

> **HTTPS in modern apps (API 24+):** Use the **Frida** page to attach and load the **SSL Pinning Bypass** script.

### iOS traffic capture

1. Connect iPhone via USB, start the proxy, click **iOS Setup** in the toolbar
2. Start the cert server → scan the QR code with iPhone camera
3. Install the cert: Settings → General → VPN & Device Management → install
4. Enable full trust: Settings → General → About → Certificate Trust Settings
5. Set the Wi-Fi proxy on the iPhone to your PC's LAN IP and port 8080
6. For apps with SSL pinning: attach Frida and load the **iOS SSL Pinning Bypass** script

## Configuration

```env
# Server
HOST=127.0.0.1
PORT=8000

# Workspace
WORKSPACE_DIR=~/.blujay

# Tool paths — omit to use auto-resolved defaults (tools/ dir relative to repo root)
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

# Optional — increases NVD API rate limit from 6 req/30s to 50 req/30s
# NVD_API_KEY=your-nvd-api-key

# Logging: DEBUG | INFO | WARNING | ERROR
LOG_LEVEL=INFO
```

## API

The backend exposes a REST API at `http://localhost:8000/api/v1`. Interactive docs at `http://localhost:8000/docs`.

| Prefix | Description |
|--------|-------------|
| `/analyses` | Static analysis (APK/IPA upload + device pull) |
| `/sessions` | Dynamic analysis sessions |
| `/proxy` | Proxy flows, replay |
| `/repeater` | Standalone HTTP repeater + history |
| `/auth` | JWT, OAuth/OIDC, session/cookie, SAML |
| `/vuln` | CVE/NVD search, Nuclei, ExploitDB |
| `/cloud` | IMDS, SSRF, bucket, credential testing |
| `/protocol` | TLS, subdomain enum, LDAP, gRPC |
| `/frida` | Dynamic instrumentation |
| `/owasp` | OWASP MASVS scanner |
| `/strix` | Autonomous pentest scans |
| `/ollama` | AI triage (metatron-qwen) |
| `/cve` | CVE correlation |
| `/api-testing` | API test suites, tests, results, fuzzing |
| `/fuzzing` | Standalone API fuzzing jobs |
| `/brute-force` | Brute force jobs |
| `/ios-devices` | iOS device management |
| `/devices` | Android (ADB) device management |
| `/pci` | PCI DSS compliance testing |
| `/scanner` | Passive + active web scanner |
| `/recon` | Passive subdomain and cloud bucket enumeration |
| `/repackage` | APK decode, patch, and resign |
| `/race` | HTTP/2 race condition testing |
| `/ws-test` | WebSocket security testing |
| `/graphql-test` | GraphQL security testing |
| `/ctf` | CTF auto-recon scan management |

## Workspace

Runtime data (database, decompiled output, uploaded APKs/IPAs, mitmproxy certs, Strix run output) is stored in `~/.blujay/`. The `backend/data/` directory holds lightweight JSON persistence (CTF scans, repeater history, NVD cache) and is not committed.

## License

Private — all rights reserved.
