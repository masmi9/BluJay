```
██████╗ ██╗     ██╗   ██╗     ██╗ █████╗ ██╗   ██╗
██╔══██╗██║     ██║   ██║     ██║██╔══██╗╚██╗ ██╔╝
██████╔╝██║     ██║   ██║     ██║███████║ ╚████╔╝ 
██╔══██╗██║     ██║   ██║██   ██║██╔══██║  ╚██╔╝  
██████╔╝███████╗╚██████╔╝╚██████╔╝██║  ██║   ██║   
╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
```

BluJay is an autonomous AppSec platform for intermediate–senior security engineers. It combines a full mobile and web security toolkit with an AI-driven agent pipeline that runs reconnaissance, exploitation, human review, proof-of-concept validation, and reporting on any target — triggered automatically from your development workflow or on demand.

## What It Does

**Automated pipeline** — Point BluJay at a target and it autonomously runs a full pentest lifecycle. A human review gate pauses the pipeline before any exploit confirmation so your team stays in control. When approved, the pipeline completes PoC validation and produces a structured report.

**Workflow integration** — Scans can be triggered by code pushes, file uploads, scheduled sweeps, Slack commands, or inbound webhooks from any external system. Results are routed to Slack, ticketing systems, email, and your CI/CD pipeline.

**AI triage** — Findings are classified, mapped to OWASP MASVS/WSTG, scored, and triaged by a local AI model with no cloud dependency. High-confidence findings can also be escalated to a cloud reasoning model for deeper exploit analysis.

**MCP integration** — BluJay exposes a Model Context Protocol server so AI assistants can query findings, trigger scans, and manage pipeline runs directly from chat — no UI required.

**Performance correlation** — When a security finding is confirmed, finding-type-matched performance tests fire automatically to assess rate-limit gaps, race condition windows, and DoS viability under realistic load.

## Features

### Mobile Analysis
- **Static Analysis** — Decompile APKs and IPAs, extract secrets, permissions, components, and binary strings with 55+ credential patterns and YARA-based detection
- **Dynamic Analysis** — Full OWASP MASVS dynamic scanning (Android and iOS) with real-time instrumentation, SSL pinning bypass, and ML-assisted finding classification
- **Proxy / Traffic Capture** — Intercept, inspect, persist, and replay HTTP/S traffic from Android and iOS devices
- **iOS IPA Dump** — Pull decrypted IPAs from jailbroken devices using a three-phase Frida + SFTP pipeline
- **APK Repackage + Resign** — Decode, patch (SSL pinning bypass, root detection bypass, force debuggable, enable backup), recompile, and re-sign in one click

### Repeater
Standalone Burp-style request editor:

- Form and raw editing modes with bidirectional sync
- Match & Replace rules (regex, applied to URL / headers / body before each send)
- Diff mode — pin a baseline response and compare line-by-line against subsequent responses
- Race Conditions tab — fire up to 50 concurrent requests and highlight anomalous responses
- Persistent history — all sent requests saved automatically
- Send to Repeater from the Proxy flow table

### Auth & Session Tester
- **JWT** — Decode, detect vulnerabilities (weak algorithm, missing expiry, injection vectors), forge attacks (alg:none, RS256→HS256 confusion, kid injection, role escalation), verify against a key or secret
- **OAuth/OIDC** — Audit flows for state CSRF, PKCE enforcement, implicit flow, redirect_uri whitelist, nonce replay, token leakage in referrer
- **Session & Cookie** — Flag missing security flags, entropy-score session tokens for predictability
- **SAML** — Decode and inspect assertions, detect unsigned assertions and wrapping vectors

### Vulnerability Intelligence
- **CVE Search** — NVD API v2 with version-match mode, 24-hour cache, severity/CVSS/CWE display
- **Nuclei Scanner** — Template-based scanning with tag/severity filtering, real-time streamed results
- **ExploitDB** — Searchsploit with web API fallback

### Cloud Tester
- **IMDS / SSRF** — Probe AWS, GCP, Azure, DigitalOcean metadata endpoints directly or via SSRF callback with 6 encoding variants per provider
- **Bucket Audit** — Unauthenticated S3, GCS, and Azure Blob public read/write enumeration
- **Credential Scanner** — Pattern-match and live-validate cloud credentials found in APK strings or config files

### Protocol Tester
- **TLS/SSL** — Protocol version probing, cipher analysis, certificate parsing, BEAST/POODLE/LOGJAM/DROWN classification
- **Subdomain Enumeration** — Certificate transparency + async DNS resolution + brute-force prefix sweep
- **LDAP** — Anonymous bind, rootDSE probe, user enumeration, policy extraction, authenticated bind
- **gRPC** — Server reflection, unary request execution, 15-payload fuzz suite

### Network & API
- **Passive Scanner** — Runs on every proxied flow: security headers, insecure cookies, reflected input, CORS, info disclosure
- **Active Scanner** — Crafted payload attacks for XSS, SQLi, SSRF, open redirect, and path traversal
- **API Testing** — IDOR sweeps, auth stripping, token replay, cross-user authorization checks
- **Brute Force** — Credential stuffing and rate-limit testing against login endpoints
- **WebSocket Testing** — Injection payloads, unauthenticated access detection, prototype pollution, JSON-RPC probing
- **GraphQL Testing** — Introspection detection, batching abuse, alias DoS, field suggestion leakage, unauthenticated mutations
- **Race Condition Testing** — Concurrent HTTP/2 replay with timing analysis and state mutation detection
- **Recon** — Certificate transparency + DNS + cloud bucket discovery

### Compliance & Reporting
- **OWASP Scanner** — Full MASVS dynamic compliance scan (Android + iOS)
- **PCI DSS Testing** — Structured test cases mapped to PCI DSS requirements with live pass/fail tracking
- **Testing Checklist** — OWASP MASVS v2.0 (iOS + Android) and WSTG v4.2 progress tracker with per-category bars
- **HTML Report Export** — Self-contained dark-theme report covering static findings, OWASP results, and scanner findings
- **SARIF Export** — SARIF 2.1.0 output compatible with GitHub Code Scanning, GitLab SAST, and standard CI/CD pipelines

### AI & Automation
- **AI Triage** — Local AI-powered triage (no cloud, no API key required). Classifies severity, maps to OWASP MASVS, generates remediation guidance, and produces session-level reports correlating findings across all modules
- **Autonomous Pentest Pipeline** — Multi-stage AI agent pipeline with a human-in-the-loop review gate. Triggered automatically or on demand; produces a structured report with CVSS-scored, confirmed findings
- **Agent Console** — AI-assisted Android analysis: manifest audit, permission enumeration, exported component analysis, IPC surface mapping
- **CTF Mode** — Automated recon pipeline for CTF targets with persistent scan history

### CI/CD Headless Mode

```bash
python backend/cli.py scan --apk app.apk --format sarif --output results.sarif
python backend/cli.py scan --apk app.apk --fail-on high
```

## Prerequisites

| Tool | Purpose |
|------|---------|
| Python 3.12+ | Backend + scanners |
| Node.js 18+ | Frontend |
| Java 11+ | APK decompilation |
| ADB | Android device management |
| libimobiledevice | iOS device management |
| Frida | Dynamic instrumentation |
| mitmproxy | Traffic interception |
| Docker | Sandbox and load testing containers |
| Ollama | Local AI model hosting (no API key needed) |
| Nuclei | Template-based scanning (optional) |

## Quick Start

### Tools

```bash
# macOS / Linux / WSL
bash scripts/setup_linux.sh

# Windows
powershell -ExecutionPolicy Bypass -File scripts/setup_windows.ps1
```

Downloads `apktool`, `jadx`, and Android `platform-tools` into `tools/`.

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate         # Windows
pip install -r requirements.txt
python run.py
```

Use `python run.py --no-reload` when running the proxy — hot-reload will orphan the proxy process.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### AI Triage (local model)

```bash
# Install Ollama: https://ollama.com
git clone https://github.com/sooryathejas/METATRON
cd METATRON && ollama create metatron-qwen -f Modelfile
```

## Proxy Setup

### Android

1. Start the backend with `--no-reload`
2. Click **Start** on the Proxy page
3. Click **Configure Device** — configures ADB reverse proxy and sets the device proxy automatically
4. Install the CA cert pushed to `/sdcard/Download/` (Settings → Security → Install certificate → CA certificate)
5. For apps with SSL pinning, attach Frida and load the **SSL Pinning Bypass** script

### iOS

1. Connect iPhone via USB, start the proxy, click **iOS Setup**
2. Start the cert server → scan the QR code with the iPhone camera
3. Install and trust the cert (Settings → General → About → Certificate Trust Settings)
4. Set the device Wi-Fi proxy to your machine's LAN IP
5. For apps with SSL pinning, attach Frida and load the **iOS SSL Pinning Bypass** script

## Configuration

```env
# Server
HOST=127.0.0.1
PORT=8000
WORKSPACE_DIR=~/.blujay

# Proxy
PROXY_HOST=0.0.0.0
PROXY_PORT=8089

# Scanner paths (auto-resolved from tools/ if omitted)
AODS_PATH=scanners/aods/dyna.py
IODS_PATH=scanners/iods/ios_scan.py

# AI pipeline — omit to run fully on the local model
ANTHROPIC_API_KEY=sk-ant-...

# NVD API — increases rate limit from 6 to 50 req/30s (optional)
NVD_API_KEY=...

# Logging
LOG_LEVEL=INFO
```

## Workspace

Runtime data (database, decompiled output, uploaded files, certificates, scan output) is stored in `~/.blujay/`. Not committed.

## License

Private — all rights reserved.
