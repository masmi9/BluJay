# BluJay

A mobile application security analysis platform for Android and iOS. BluJay combines static analysis, dynamic instrumentation, traffic interception, and OWASP MASVS compliance scanning into a single unified interface.

## Features

- **Static Analysis** — Decompile APKs (apktool + jadx) and IPAs, extract secrets, permissions, components, and binary strings
- **OWASP Scanner** — Full AODS (Android) and IODS (iOS) dynamic scans with MASVS compliance reporting
- **Proxy / Traffic Capture** — mitmproxy integration for intercepting and replaying HTTP/S traffic from Android and iOS devices
- **Frida** — Dynamic instrumentation: attach to running apps, run scripts, hook methods in real time
- **TLS Audit** — Validate certificate pinning and TLS configuration
- **JWT Testing** — Decode, forge, and test JWT tokens
- **API Fuzzing** — Fuzz discovered API endpoints for injection and logic bugs
- **Brute Force** — Credential stuffing and rate-limit testing
- **Agent Console** — AI-powered triage and remediation suggestions
- **Dashboard** — Device management for Android (ADB) and iOS (libimobiledevice), one-click Pull & Analyze

## Monorepo Structure

```
BluJay/
├── backend/          # FastAPI + SQLAlchemy async (Python)
├── frontend/         # React + TypeScript + Tailwind (Vite)
├── scanners/
│   ├── aods/         # Android OWASP Dynamic Scanner (dyna.py)
│   └── iods/         # iOS OWASP Dynamic Scanner (ios_scan.py)
├── tools/            # apktool.jar, jadx, platform-tools (not committed)
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

## Quick Start

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
python run.py --reload
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

## Configuration

Copy `.env.example` to `backend/.env` and adjust paths as needed. Key settings:

```env
AODS_PATH=scanners/aods/dyna.py
AODS_VENV_PYTHON=scanners/aods/aods_venv/Scripts/python.exe
IODS_PATH=scanners/iods/ios_scan.py
IODS_VENV_PYTHON=scanners/iods/iods_venv/Scripts/python.exe
APKTOOL_JAR=tools/apktool.jar
```

## Workspace

Runtime data (database, decompiled output, uploaded APKs/IPAs, mitmproxy certs) is stored in `~/.blujay/` and is never committed.

## License

Private — all rights reserved.
