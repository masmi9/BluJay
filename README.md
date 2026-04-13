# BluJay

A mobile application security analysis platform for Android and iOS. BluJay combines static analysis, dynamic instrumentation, traffic interception, OWASP MASVS compliance scanning, autonomous backend pentesting, and local AI-powered triage into a single unified interface.

## Features

### Mobile Analysis
- **Static Analysis** — Decompile APKs (apktool + jadx) and IPAs, extract secrets, permissions, components, and binary strings
- **OWASP Scanner** — Full AODS (Android) and IODS (iOS) dynamic scans with MASVS compliance reporting
- **Proxy / Traffic Capture** — mitmproxy integration with a custom addon for intercepting, persisting, and replaying HTTP/S traffic from Android and iOS devices
- **Frida** — Dynamic instrumentation: attach to running apps, run scripts, hook methods in real time
- **iOS Syslog** — Live syslog streaming from connected iOS devices via libimobiledevice

### Network & API
- **TLS Audit** — Validate certificate pinning and TLS configuration
- **JWT Testing** — Decode, forge, and test JWT tokens from intercepted traffic
- **API Fuzzing** — Fuzz discovered API endpoints for IDOR, auth bypass, verb tampering, and rate-limit issues
- **Brute Force** — Credential stuffing and rate-limit testing against login endpoints
- **Strix Pentest Agent** — Autonomous AI-driven pentesting of backend targets (APIs, servers) discovered during mobile analysis. Runs multi-agent recon → exploit → PoC validation in a Docker sandbox. Findings are proof-of-concept validated before being reported.

### AI & Reporting
- **AI Triage** — Local AI-powered vulnerability analysis using metatron-qwen (fine-tuned Qwen via Ollama). No cloud, no API keys. Accepts output from any scan module and returns severity classification, OWASP MASVS mapping, and remediation steps. Includes consolidated session reports that correlate findings across all modules and identify attack chains.
- **Agent Console** — AI-assisted Android agent for manifest analysis, permission auditing, exported component enumeration, and IPC analysis
- **Risk Scoring** — Unified risk score across all findings for a session

### Device Management
- **Dashboard** — Android (ADB) and iOS (libimobiledevice) device management, one-click Pull & Analyze
- **WebView Inspector** — Detect and audit WebView configurations in running apps
- **Screenshot Capture** — Capture device screenshots during dynamic sessions

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
│   ├── api/              # FastAPI routers (one per feature module)
│   │   ├── strix.py      # Strix autonomous pentest integration
│   │   └── ollama.py     # metatron-qwen AI triage integration
│   ├── core/
│   │   ├── proxy_addon.py  # mitmproxy addon script (runs as subprocess)
│   │   └── proxy_manager.py
│   └── models/           # SQLAlchemy ORM models
├── frontend/
│   ├── src/
│   │   ├── pages/        # One page component per feature
│   │   │   ├── StrixPage.tsx
│   │   │   └── AiTriagePage.tsx
│   │   ├── api/          # Axios API clients
│   │   └── types/        # TypeScript interfaces
├── scanners/
│   ├── aods/             # Android OWASP Dynamic Scanner (dyna.py)
│   └── iods/             # iOS OWASP Dynamic Scanner (ios_scan.py)
├── tools/                # apktool.jar, jadx, platform-tools (not committed)
└── .gitignore
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

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
# or: source venv/bin/activate  # Linux/macOS/WSL
pip install -r requirements.txt
python main.py --reload
```

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

> **Windows users:** Strix installs into WSL. If your BluJay backend runs in Windows Python, create a wrapper so `strix` is visible on the Windows PATH:
> ```powershell
> New-Item -Path "$env:USERPROFILE\AppData\Local\Microsoft\WindowsApps\strix.cmd" -Force -Value "@echo off`nwsl strix %*"
> ```

### AI Triage (Ollama + metatron-qwen)

```bash
# Install Ollama: https://ollama.com
# Then build and run the metatron-qwen model:
git clone https://github.com/sooryathejas/METATRON
cd METATRON
ollama create metatron-qwen -f Modelfile
ollama run metatron-qwen
```

## Configuration

Copy `.env.example` to `backend/.env` and adjust paths as needed. Key settings:

```env
AODS_PATH=scanners/aods/dyna.py
AODS_VENV_PYTHON=scanners/aods/aods_venv/Scripts/python.exe
IODS_PATH=scanners/iods/ios_scan.py
IODS_VENV_PYTHON=scanners/iods/iods_venv/Scripts/python.exe
APKTOOL_JAR=tools/apktool.jar
```

## API

The backend exposes a REST API at `http://localhost:8000/api/v1`. Interactive docs available at `http://localhost:8000/docs`.

Key endpoint groups:

| Prefix | Description |
|--------|-------------|
| `/analyses` | Static analysis (APK/IPA) |
| `/sessions` | Dynamic analysis sessions |
| `/proxy` | Proxy flows, replay, repeater |
| `/frida` | Dynamic instrumentation |
| `/owasp` | OWASP MASVS scanner |
| `/strix` | Autonomous pentest scans |
| `/ollama` | AI triage (metatron-qwen) |
| `/cve` | CVE correlation |
| `/fuzzing` | API fuzzing jobs |
| `/tls` | TLS audit |
| `/jwt` | JWT testing |
| `/brute-force` | Brute force jobs |

## Workspace

Runtime data (database, decompiled output, uploaded APKs/IPAs, mitmproxy certs, Strix run output) is stored in `~/.blujay/` and `~/strix_runs/` and is never committed.

## License

Private — all rights reserved.
