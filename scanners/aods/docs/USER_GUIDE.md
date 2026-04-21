# AODS User Guide

Automated OWASP Dynamic Scan Framework - Android application security analysis.

---

## Table of Contents

1. [Introduction & Overview](#1-introduction--overview)
2. [Installation & Setup](#2-installation--setup)
3. [Quick Start](#3-quick-start)
4. [Command-Line Reference](#4-command-line-reference)
5. [Scan Profiles](#5-scan-profiles)
6. [Output Formats & Reports](#6-output-formats--reports)
7. [Environment Variables](#7-environment-variables)
8. [API Server & Web UI](#8-api-server--web-ui)
9. [Plugin System](#9-plugin-system)
10. [ML Pipeline](#10-ml-pipeline)
11. [Dynamic Analysis with Frida](#11-dynamic-analysis-with-frida)
12. [Vector Search (ChromaDB)](#12-vector-search-chromadb)
13. [Batch Processing & CI/CD](#13-batch-processing--cicd)
14. [Agent System (AI-Powered Analysis)](#14-agent-system-ai-powered-analysis)
15. [Advanced Features](#15-advanced-features)
16. [Deployment](#16-deployment)
17. [Troubleshooting](#17-troubleshooting)

---

## 1. Introduction & Overview

### What is AODS?

AODS (Automated OWASP Dynamic Scan) is an automated Android application security analysis framework. It combines static analysis, dynamic analysis, and machine learning to detect vulnerabilities in Android APK files. AODS produces actionable security reports with evidence-backed findings, confidence scores, and remediation guidance.

### Key Capabilities

- **Static Analysis** - decompiles APKs with JADX and analyzes source code, manifests, and resources
- **Dynamic Analysis** - runtime testing with Frida instrumentation and ADB device interaction
- **Machine Learning** - false positive reduction, confidence scoring, malware detection, and explainability
- **66 security plugins** - organized into categories covering OWASP MASVS controls
- **4 Scan Profiles** - lightning (~30s), fast (2-3 min), standard (5-8 min), deep (15+ min)
- **AI Agent System** - 6 specialized agents (triage, verification, remediation, narration, orchestration, pipeline) with LLM-agnostic provider support (Anthropic, OpenAI, Ollama)
- **Web UI** - React dashboard with 33 pages for scan management, reports, ML, agents, and administration
- **REST API** - FastAPI with RBAC, SSE streaming, and WebSocket Frida console
- **Batch Processing** - parallel analysis of multiple APKs with CI/CD integration
- **Compliance** - NIST, MASVS, OWASP, and ISO 27001 mapping

### Architecture

```
                         +-----------------+
                         |   Web UI (React)|
                         |   33 pages      |
                         +--------+--------+
                                  |
                         +--------v--------+
                         | FastAPI Server   |
                         | 9 route modules  |
                         | RBAC + SSE + WS  |
                         +--------+--------+
                                  |
       +------------+------------+------------+------------+
       |            |            |            |            |
  +----v----+ +-----v-----+ +---v-----+ +---v-----+ +----v----+
  | Static  | | Dynamic   | | ML      | | Agent   | | Vector  |
  | Analysis| | Analysis  | | Pipeline| | System  | | Search  |
  | JADX    | | Frida     | | FP red. | | 6 agents| | ChromaDB|
  | 66 plugs| | ADB + WS  | | Explain | | LLM-agn | |         |
  +----+----+ +-----+-----+ +---+-----+ +---+-----+ +----+----+
       |            |            |            |            |
       +------------+------------+------------+------------+
                                  |
                         +--------v--------+
                         | Report Engine    |
                         | JSON/HTML/CSV/TXT|
                         | Evidence + Dedup |
                         +-----------------+
```

---

## 2. Installation & Setup

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.10+ | 3.11 |
| RAM | 4 GB | 8 GB |
| Disk | 2 GB free | 5 GB free |
| OS | Linux, WSL2, macOS | Kali Linux, Ubuntu 22.04 |
| Node.js | 18+ | 20.x (for React UI) |

### Step-by-Step Installation

**1. Clone the repository:**

```bash
git clone <repo-url> AODS
cd AODS
```

**2. Set up Git LFS (required for ML models):**

```bash
git lfs install
git lfs pull
```

The `models/` directory contains pre-trained ML models (`.pkl` files and metadata `.json` files). Without Git LFS these will be pointer files and ML features will not work.

**3. Create the Python virtual environment:**

The virtual environment **must** be named `aods_venv`. Other names will cause import errors in tests and CI scripts.

```bash
python3 -m venv aods_venv
source aods_venv/bin/activate
```

**4. Install dependencies:**

```bash
pip install -r requirements/base.txt       # Core dependencies
pip install -r requirements/analysis.txt   # Analysis tools (JADX helpers, Frida bindings)
pip install -r requirements/dev.txt        # Development/testing (pytest, playwright, flake8)
```

Or install all at once:

```bash
pip install -r requirements/base.txt -r requirements/analysis.txt -r requirements/dev.txt
```

**5. Install required tools:**

| Tool | Purpose | Installation |
|------|---------|-------------|
| **JADX** | APK decompilation (bundled/PATH) | `apt install jadx` or download from GitHub |
| **ADB** (optional) | Device communication | `apt install android-tools-adb` |
| **Frida** (optional) | Runtime instrumentation | `pip install frida-tools frida` |

**6. Verify installation:**

```bash
# Verify Python environment
source aods_venv/bin/activate
python -c "import structlog; print('structlog OK')"

# Verify JADX
jadx --version

# Verify tool availability
python -c "from core.external.unified_tool_executor import get_global_executor, ToolType; e = get_global_executor(); print(e.get_tool_info(ToolType.JADX))"

# Dry-run a scan
python dyna.py --apk /path/to/app.apk --dry-run
```

---

## 3. Quick Start

### Your First Scan

```bash
source aods_venv/bin/activate
python dyna.py --apk app.apk --mode safe
```

This runs a lightning-profile scan with automatic package name detection. The output is a JSON report in the `reports/` directory.

### Deeper Analysis

```bash
python dyna.py --apk app.apk --mode deep --formats json html
```

This runs all plugins with the deep profile (~15 minutes) and generates both JSON and HTML reports.

### Understanding the Output

When a scan completes, AODS prints a summary:

```
Scan complete: 15 findings (1 CRITICAL, 6 HIGH, 3 MEDIUM, 5 INFO)
Report saved to: reports/aods_com.example.app_20260219_143022.json
```

### Reading a JSON Report

The JSON report contains these top-level sections:

```json
{
  "metadata": {
    "scan_id": "abc123",
    "apk_name": "app.apk",
    "package_name": "com.example.app",
    "scan_profile": "deep",
    "scan_mode": "deep",
    "duration_seconds": 423,
    "timestamp": "2026-02-19T14:30:22Z",
    "plugins_summary": { "total": 48, "executed": 48, "skipped": 0 }
  },
  "summary": {
    "total_findings": 15,
    "critical": 1,
    "high": 6,
    "medium": 3,
    "low": 0,
    "info": 5
  },
  "findings": [
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
      "evidence": {
        "code_snippet": "...",
        "description": "..."
      },
      "classification": {
        "severity": "HIGH",
        "category": "Data Storage"
      },
      "plugin_source": "insecure_data_storage"
    }
  ]
}
```

### Opening an HTML Report

```bash
python dyna.py --apk app.apk --formats html
# Open the generated HTML file in a browser
xdg-open reports/aods_com.example.app_*.html
```

The HTML report includes interactive sorting, severity filtering, expandable finding details, and summary charts.

---

## 4. Command-Line Reference

### Primary Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--apk PATH` | string | - | Path to APK file to analyze |
| `--pkg NAME` | string | auto-detected | Package name (auto-detected if omitted) |
| `--mode {safe,deep,agent}` | choice | `safe` | Scan mode: `safe` (basic), `deep` (thorough), `agent` (AI-orchestrated) |
| `--profile {lightning,fast,standard,deep}` | choice | auto | Scan profile (auto-selected from mode if omitted) |
| `--output PATH` | string | auto | Output file path for results |
| `--config PATH` | string | - | Path to custom YAML configuration file |

### Analysis Control

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--static-only` | flag | false | Run only static analysis |
| `--dynamic-only` | flag | false | Run only dynamic analysis |
| `--disable-static-analysis` | flag | false | Disable static analysis |
| `--disable-dynamic-analysis` | flag | false | Disable dynamic analysis |
| `--parallel` | flag | false | Enable parallel plugin execution |
| `--parallel-scan` | flag | true | Parallel static + dynamic scans (default) |
| `--sequential` | flag | false | Run scans sequentially in single process |
| `--max-workers N` | int | auto | Maximum worker processes |
| `--testing-mode` | flag | false | Use lightning profile for fast dev iteration |
| `--optimized` | flag | false | Enable advanced optimized execution |
| `--canonical` | flag | false | Use canonical modular architecture |

### Output & Reporting

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--formats {txt,json,csv,html,all}` | list | `json` | Report formats to generate |
| `--skip-if-report-exists` | flag | false | Skip scanning if output file exists |
| `--dry-run` | flag | false | Print planned actions and exit |
| `--verbose` / `-v` | flag | false | Enable verbose logging |
| `--benchmark` | flag | false | Enable benchmarking mode |
| `--dashboard` | flag | false | Launch interactive executive dashboard |
| `--executive-dashboard` | flag | false | Generate executive dashboard report |
| `--no-executive-dashboard` | flag | false | Disable executive dashboard generation |
| `--executive-dashboard-out DIR` | string | auto | Output directory for executive dashboard |

### ML & Confidence

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--disable-ml` | flag | false | Disable all ML components |
| `--disable-enhancements` | flag | false | Disable vulnerability enhancements and smart filtering |
| `--enable-malware-scan` | flag | false | Enable ML-based APK malware detection |
| `--ml-confidence FLOAT` | float | - | ML model confidence threshold (0.0-1.0) |
| `--ml-models-path PATH` | string | `models/` | Path to custom ML models directory |
| `--ml-fp-threshold FLOAT` | float | - | Override ML false-positive threshold (0.0-1.0) |
| `--force-ml-filtering` | flag | false | Force ML FP filtering for vulnerable/training apps |
| `--app-profile {production,vulnerable,qa_vulnerable}` | choice | - | App profile for ML defaults |
| `--vulnerable-app-mode` | flag | false | Relaxed detection for testing/training apps |

### Batch Processing & CI/CD

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--batch-targets PATH` | string | - | Path to file listing targets (one per line) |
| `--batch-config PATH` | string | - | Path to YAML batch configuration |
| `--batch-parallel` | flag | false | Enable parallel batch processing |
| `--batch-max-concurrent N` | int | 4 | Max concurrent batch analyses |
| `--batch-timeout MIN` | int | 60 | Timeout per target in minutes |
| `--batch-output-dir DIR` | string | `batch_results/` | Output directory for batch results |
| `--ci-mode` | flag | false | CI/CD mode with machine-readable output |
| `--fail-on-critical` | flag | false | Exit with error if critical findings |
| `--fail-on-high` | flag | false | Exit with error if high findings |

### Detection Patterns

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--disable-android14-webview-patterns` | flag | false | Disable Android 14 WebView patterns |
| `--disable-android14-network-patterns` | flag | false | Disable Android 14 network patterns |
| `--enable-android14-audit-patterns` | flag | false | Enable Android 14 data access auditing |
| `--enable-crypto-rng-patterns` | flag | false | Enable RNG-related crypto rules |
| `--enable-crypto-policy-patterns` | flag | false | Enable policy-oriented crypto rules |
| `--enable-gdpr-policy-patterns` | flag | false | Enable GDPR/data policy patterns |
| `--http-mode {strict,internal,auto}` | choice | - | HTTP detection mode |
| `--enable-job-constraints-patterns` | flag | false | Enable WorkManager/JobScheduler patterns |

### Package Detection

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--auto-pkg` | flag | true | Enable automatic package name detection |
| `--no-auto-pkg` | flag | false | Disable auto-detection, require manual entry |
| `--confirm-pkg` | flag | false | Always confirm auto-detected package names |
| `--pkg-confidence-threshold FLOAT` | float | 0.8 | Minimum confidence for auto-detection |

### Cross-Platform & Compliance

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--cross-platform` | flag | false | Enable cross-platform analysis |
| `--frameworks {flutter,react_native,xamarin,pwa,all}` | list | `all` | Specific frameworks to analyze |
| `--compliance {nist,masvs,owasp,iso27001}` | choice | - | Compliance framework analysis |
| `--environment {development,staging,production}` | choice | - | Deployment environment config |
| `--security-profile {basic,enhanced,enterprise}` | choice | `basic` | Security profile for analysis |
| `--enterprise-optimization` | flag | false | Enterprise performance optimization |

### Deduplication

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--dedup-strategy {basic,intelligent,aggressive,conservative}` | choice | `aggressive` | Deduplication strategy |
| `--dedup-threshold FLOAT` | float | 0.85 | Similarity threshold for dedup (0.0-1.0) |
| `--preserve-evidence` | flag | true | Preserve evidence from merged duplicates |
| `--disable-deduplication` | flag | false | Disable deduplication entirely |

### Progressive & QA

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--progressive-analysis` | flag | false | Enable progressive analysis for large APKs |
| `--sample-rate FLOAT` | float | 0.3 | Sample rate for progressive analysis (0.1-1.0) |
| `--qa-mode` | flag | false | Enable quality assurance benchmarking |
| `--enable-metrics` | flag | false | Enable Prometheus metrics collection |
| `--metrics-port PORT` | int | 9090 | Port for metrics endpoint |

### Objection Integration

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--with-objection` | flag | false | Enable Objection integration |
| `--objection-mode {recon,verify,training,dev}` | choice | - | Objection integration mode |
| `--objection-timeout SEC` | int | 300 | Timeout for Objection operations |
| `--export-objection-commands` | flag | false | Export commands for manual execution |

### Agent Intelligence (optional)

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--agent` | flag | false | Enable AI agent analysis (requires `AODS_AGENT_ENABLED=1`) |
| `--agent-narrate` | flag | false | Run narration agent to summarize findings |
| `--agent-verify` | flag | false | Run verification agent to confirm findings |
| `--agent-orchestrate` | flag | false | Run orchestration agent for optimal plugin selection |
| `--agent-triage` | flag | false | Run triage agent to classify and prioritize findings |
| `--agent-remediate` | flag | false | Run remediation agent to generate code patches |
| `--agent-pipeline` | flag | false | Run full pipeline (triage → verify → remediate → narrate) |
| `--agent-model MODEL` | string | - | Override LLM model for agent tasks |

### Feedback

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--feedback-server` | flag | false | Start web-based ML feedback interface |
| `--feedback-port PORT` | int | 5000 | Port for feedback server |

---

## 5. Scan Profiles

AODS provides four scan profiles that control which plugins run and how long scans take. Profiles are subsets: Lightning ⊆ Fast ⊆ Standard ⊆ Deep.

### Profile Comparison

| Feature | Lightning | Fast | Standard | Deep |
|---------|-----------|------|----------|------|
| **Estimated Time** | ~30 seconds | 2-3 minutes | 5-8 minutes | 15+ minutes |
| **Plugin Count** | 12 | 18 | 43 | All (~48+) |
| **JADX Decompilation** | Yes (60s timeout) | Yes | Yes | Yes |
| **Manifest Analysis** | Yes | Yes | Yes | Yes |
| **Crypto Analysis** | Yes | Yes | Yes | Yes |
| **Data Storage** | Yes | Yes | Yes | Yes |
| **Network Security** | Yes | Yes | Yes | Yes |
| **Injection Testing** | Yes | Yes | Yes | Yes |
| **Privacy Analysis** | - | Privacy leak | Full MASVS-PRIVACY | Full |
| **Anti-Tampering** | - | - | Yes | Yes |
| **Dynamic (Frida)** | - | - | Yes | Yes |
| **Compliance** | - | - | Semgrep MASTG | All |
| **Malware Detection** | - | - | - | Optional |
| **Use Case** | CI/CD gates, quick triage | Development, pre-commit | Security review, audit | Penetration testing |

### Selecting a Profile

Profiles can be selected explicitly or auto-selected from the scan mode:

```bash
# Explicit profile selection
python dyna.py --apk app.apk --profile standard

# Auto-selection from mode
python dyna.py --apk app.apk --mode safe     # → lightning (or fast if --vulnerable-app-mode)
python dyna.py --apk app.apk --mode deep     # → deep
```

**Auto-selection logic:**

| Mode | Vulnerable App Mode | Selected Profile |
|------|-------------------|------------------|
| `safe` | No | Lightning |
| `safe` | Yes | Fast |
| `deep` | No/Yes | Deep |
| `agent` | No/Yes | Deep (with all agents enabled) |

### Profile Details

**Lightning** (12 plugins) - detection-first fast analysis:
- `insecure_data_storage`, `cryptography_tests`, `enhanced_data_storage_analyzer`
- `authentication_security_analysis`, `enhanced_manifest_analysis`
- `jadx_static_analysis`, `enhanced_static_analysis`
- `apk_signing_certificate_analyzer`, `network_cleartext_traffic`
- `injection_vulnerabilities`, `webview_security_analysis`
- `advanced_ssl_tls_analyzer`

**Fast** (18 plugins) - adds common vulnerability checks:
- All Lightning plugins plus:
- `improper_platform_usage`, `traversal_vulnerabilities`
- `privacy_leak_detection`, `component_exploitation_plugin`
- `attack_surface_analysis`, `enhanced_network_security_analysis`

**Standard** (43 plugins) - full analysis:
- All Fast plugins plus:
- `code_quality_injection_analysis`, `privacy_controls_analysis`
- `anti_tampering_analysis`, `frida_dynamic_analysis`
- `token_replay_analysis`, `external_service_analysis`
- `runtime_decryption_analysis`, `semgrep_mastg_analyzer`
- Privacy: `privacy_analyzer`, `consent_analyzer`, `data_minimization_analyzer`, `tracking_analyzer`
- Resilience: `dynamic_code_analyzer`, `emulator_detection_analyzer`

**Deep** (48+ plugins) - all available plugins except examples.

---

## 6. Output Formats & Reports

### Supported Formats

| Format | Extension | Description |
|--------|-----------|-------------|
| JSON | `.json` | Structured report with full finding details (default) |
| HTML | `.html` | Interactive browser report with charts and filtering |
| CSV | `.csv` | Tabular format for spreadsheet import |
| TXT | `.txt` | Plain text summary |

```bash
# Single format
python dyna.py --apk app.apk --formats json

# Multiple formats
python dyna.py --apk app.apk --formats json html csv

# All formats
python dyna.py --apk app.apk --formats all
```

### JSON Report Structure

```json
{
  "metadata": {
    "scan_id": "string",
    "apk_name": "string",
    "package_name": "string",
    "scan_profile": "lightning|fast|standard|deep",
    "scan_mode": "safe|deep",
    "duration_seconds": 0,
    "timestamp": "ISO 8601",
    "plugins_summary": {
      "total": 0,
      "executed": 0,
      "skipped": 0,
      "failed": 0
    }
  },
  "summary": {
    "total_findings": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "findings": [
    {
      "title": "string",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "confidence": 0.0,
      "description": "string",
      "file_path": "string",
      "line_number": 0,
      "code_snippet": "string",
      "cwe_id": "CWE-NNN",
      "masvs": "MASVS-CATEGORY-N",
      "recommendation": "string",
      "evidence": { "code_snippet": "", "description": "" },
      "classification": { "severity": "", "category": "" },
      "plugin_source": "string",
      "references": ["url"]
    }
  ]
}
```

### HTML Report Features

- Interactive severity filter buttons (Critical, High, Medium, Low, Info)
- Sortable findings table (by severity, confidence, title)
- Expandable finding details with code snippets
- Summary charts showing severity distribution
- MASVS compliance coverage indicator
- One-click export to PDF (via browser print)

### Output Path Control

```bash
# Custom output path
python dyna.py --apk app.apk --output reports/my_scan.json

# Skip if report already exists (useful for batch/CI)
python dyna.py --apk app.apk --output reports/cached.json --skip-if-report-exists
```

Default output path: `reports/aods_<package_name>_<timestamp>.json`

---

## 7. Environment Variables

### Essential

| Variable | Default | Description |
|----------|---------|-------------|
| `AODS_DISABLE_ML` | `0` | Disable ML features (`1` to disable) |
| `AODS_STATIC_ONLY` | `0` | Static analysis only - no device needed |
| `AODS_STATIC_ONLY_HARD` | `0` | Force static-only - suppresses all dynamic probes |
| `AODS_CANONICAL` | `0` | Use canonical modular execution paths |
| `AODS_REFERENCE_ONLY` | `0` | Emit reference-only reports (smaller artifacts) |
| `PYTHONPATH` | - | Set to repo root if running from a subdirectory |

### Security & RBAC

| Variable | Default | Description |
|----------|---------|-------------|
| `AODS_ADMIN_PASSWORD` | random | Admin user password (random if unset - logged to console) |
| `AODS_ANALYST_PASSWORD` | - | Analyst user password (user not created if unset) |
| `AODS_VIEWER_PASSWORD` | - | Viewer user password (user not created if unset) |
| `AODS_AUTH_DISABLED` | `0` | Disable authentication entirely (dev mode only) |

> **Warning:** If `AODS_ADMIN_PASSWORD` is not set, a random password is generated and logged to the console on startup. Set it explicitly for production use.

### Resources & Performance

| Variable | Default | Description |
|----------|---------|-------------|
| `AODS_MAX_WORKERS` | auto | Maximum parallel worker processes |
| `AODS_JADX_THREADS` | auto | JADX decompilation thread count |
| `AODS_JADX_MEM_MB` | `512` | JADX heap memory in MB |
| `AODS_ORCHESTRATOR_TIMEOUT_SEC` | `1200` | Overall scan timeout in seconds |
| `AODS_DECOMPILATION_MODE` | `FULL` | Decompilation mode (`FULL` or `MINIMAL`) |

### Plugin Execution

| Variable | Default | Description |
|----------|---------|-------------|
| `AODS_ALLOW_VULNERABLE_APP_HEURISTICS` | `0` | Enable name-pattern heuristics for vulnerable app detection |
| `AODS_DEDUP_AGGREGATE` | `0` | Enable deduplication aggregation |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `AODS_LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `AODS_LOG_FORMAT` | `auto` | Log format: `json` (production), `console` (dev), `auto` (detect TTY) |

### ML Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AODS_DISABLE_ML` | `0` | Disable ML integration (`1`, `true`, or `yes`) |

### Frida / Dynamic Analysis

| Variable | Default | Description |
|----------|---------|-------------|
| `AODS_AI_FRIDA_ENABLE` | `0` | Enable rule-based Frida suggestions |
| `AODS_AI_FRIDA_ML_ENABLE` | `0` | Enable ML-based Frida suggestions |
| `AODS_AI_FRIDA_MIN_SCORE` | `0.6` | Minimum score for ML suggestions |

### Vector Database

| Variable | Default | Description |
|----------|---------|-------------|
| `AODS_VECTOR_DB_ENABLED` | `0` | Enable ChromaDB vector search |
| `AODS_VECTOR_DB_PATH` | `data/vector_index/` | ChromaDB persistence directory |

### Docker / Deployment

| Variable | Default | Description |
|----------|---------|-------------|
| `AODS_WEB_BASE` | `/ui` | UI base path |
| `AODS_API_BASE` | `/api` | API base path |
| `AODS_TITLE` | `AODS` | Application title |
| `ADB_SERVER_SOCKET` | `tcp:host.docker.internal:5037` | ADB server socket (Docker) |

### Resource-Constrained Recipe (WSL / CI)

For WSL2 or CI environments with limited resources:

```bash
export AODS_STATIC_ONLY_HARD=1
export AODS_MAX_WORKERS=1
export AODS_DECOMPILATION_MODE=MINIMAL
export AODS_JADX_THREADS=1
export AODS_JADX_MEM_MB=256
export AODS_ORCHESTRATOR_TIMEOUT_SEC=1800
export AODS_DISABLE_ML=1

python dyna.py --apk app.apk --static-only --profile lightning \
  --sequential --disable-ml --disable-enhancements \
  --sample-rate 0.2 --formats json
```

---

## 8. API Server & Web UI

### Starting the Server

**Manual startup:**

```bash
source aods_venv/bin/activate
uvicorn core.api.server:app --host 0.0.0.0 --port 8088 --workers 1
```

> **Important:** ChromaDB requires `--workers 1` (single-worker mode). Using multiple workers causes database lock errors.

**With environment variables:**

```bash
AODS_ADMIN_PASSWORD=mysecretpass \
AODS_VIEWER_PASSWORD=viewerpass \
uvicorn core.api.server:app --host 0.0.0.0 --port 8088 --workers 1
```

**Using Docker Compose:**

```bash
docker compose --profile dev up -d api-ui
# API available at http://localhost:8088/api
# UI available at http://localhost:8088/ui
```

### Authentication

AODS uses opaque bearer token authentication with PBKDF2-SHA256 password hashing. Tokens are stored server-side with a 24-hour expiry.

**Login flow:**

```bash
# 1. Authenticate
curl -X POST http://localhost:8088/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "mysecretpass"}'

# Response: {"token": "abc123...", "user": "admin", "roles": ["admin", "analyst", "viewer"]}

# 2. Use token in subsequent requests (Authorization header)
curl http://localhost:8088/api/scans/results \
  -H "Authorization: Bearer abc123..."

# 3. For SSE streams, use token query param (browsers can't set headers on EventSource)
curl -N "http://localhost:8088/api/scans/SESSION_ID/progress/stream?token=abc123..."

# 4. Check current user
curl http://localhost:8088/api/auth/me \
  -H "Authorization: Bearer abc123..."
```

**Role hierarchy:**

| Role | Capabilities |
|------|-------------|
| `admin` | Full access - scans, ML, config, audit, batch, user management |
| `analyst` | Start scans, view results, Frida console, vector search, gates |
| `viewer` | View results, reports, tools status, policies |
| `auditor` | View audit log, reports |
| `api_user` | API-only access for integrations |

**Password configuration:**

Set passwords via environment variables before starting the server:

```bash
export AODS_ADMIN_PASSWORD=strongpassword
export AODS_ANALYST_PASSWORD=analystpass    # optional
export AODS_VIEWER_PASSWORD=viewerpass      # optional
```

If `AODS_ADMIN_PASSWORD` is not set, a random 22-character password is generated and logged to the console.

### API Endpoint Reference

#### Health & Status (7 endpoints)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | None | Basic health check |
| GET | `/api/health/ml` | None | ML subsystems health |
| GET | `/api/health/plugins` | None | Plugin discovery health |
| GET | `/api/health/scan` | None | Scan infrastructure health (JADX, sessions) |
| GET | `/api/info` | None | API version and server time |
| GET | `/api/tools/status` | Any | External tools status (ADB, Frida, JADX) |
| GET | `/api/optional-deps/status` | Any | Optional dependency availability |

#### Authentication (3 endpoints)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/login` | None | Authenticate and receive JWT token |
| GET | `/api/auth/me` | Any | Get current user info and roles |
| POST | `/api/auth/logout` | Any | Invalidate token |

#### Scan Management (14 endpoints)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/scans/start` | admin, analyst | Start scan with options |
| GET | `/api/scans/start-quick` | admin, analyst | Quick-start scan via query params |
| POST | `/api/scans/upload_apk` | admin, analyst | Upload APK file |
| POST | `/api/scans/{id}/confirm-package` | admin, analyst | Confirm auto-detected package |
| POST | `/api/scans/{id}/retry-detection` | admin, analyst | Retry package detection |
| GET | `/api/scans/{id}/progress` | Any | Get scan progress |
| GET | `/api/scans/{id}/progress/stream` | Any | SSE stream of scan progress |
| GET | `/api/scans/{id}/logs/stream` | Any | SSE stream of scan logs |
| GET | `/api/scans/{id}/details` | Any | Get session details |
| GET | `/api/scans/active` | Any | List active scans |
| GET | `/api/scans/recent` | Any | List recent scans (paginated) |
| GET | `/api/scans/results` | Any | List scan results |
| GET | `/api/scans/result/{id}` | Any | Get full scan result JSON |
| POST | `/api/scans/{id}/cancel` | admin, analyst | Cancel running scan |

#### Batch Processing (4 endpoints)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/batch/start` | admin | Start batch scan job |
| GET | `/api/batch/{id}/status` | admin | Get batch job status |
| GET | `/api/batch/{id}/status/stream` | admin | SSE stream of batch status |
| POST | `/api/batch/{id}/cancel` | admin | Cancel batch job |

#### Reports (4 endpoints)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/reports/list` | Any | List available reports |
| GET | `/api/reports/read` | Any | Read report file content |
| GET | `/api/reports/download` | Any | Download report file |
| POST | `/api/reports/generate` | admin, analyst | Generate report from scan results |

#### Frida Dynamic Analysis (18 endpoints)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/frida/health` | admin, analyst | Frida health status |
| GET | `/api/frida/devices` | admin, analyst | List Frida devices |
| GET | `/api/frida/devices/{id}/processes` | admin, analyst | List device processes |
| POST | `/api/frida/attach` | admin, analyst | Attach to process |
| POST | `/api/frida/detach` | admin, analyst | Detach session |
| GET | `/api/frida/session/{pkg}/status` | admin, analyst | Session status |
| POST | `/api/frida/session/{session_id}/baseline` | admin, analyst | Baseline facts |
| POST | `/api/frida/session/{pkg}/scripts` | admin, analyst | Upload script |
| DELETE | `/api/frida/session/{pkg}/scripts/{name}` | admin, analyst | Unload script |
| POST | `/api/frida/session/{id}/rpc` | admin, analyst | Execute RPC call |
| POST | `/api/frida/session/{pkg}/run-targeted` | admin, analyst | Run targeted analysis |
| GET | `/api/frida/session/{pkg}/events/stream` | admin, analyst | SSE event stream |
| POST | `/api/frida/corellium/connect` | admin | Connect Corellium device |
| POST | `/api/frida/corellium/ensure` | admin | Ensure ADB + Frida ready |
| GET | `/api/frida/telemetry/recent` | admin | Recent telemetry events |
| GET | `/api/frida/telemetry/summary` | admin | Telemetry summary |
| POST | `/api/frida/ws-token` | admin, analyst | Issue WebSocket token |
| WS | `/api/frida/ws` | token | WebSocket Frida console |

#### ML & Explainability (9 endpoints)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/ml/training/status` | admin | ML training job status |
| POST | `/api/ml/training/run_calibration` | admin | Trigger calibration run |
| GET | `/api/ml/calibration/summary` | admin | Calibration summary |
| GET | `/api/ml/thresholds` | admin | Current confidence thresholds |
| GET | `/api/ml/metrics/pr` | admin | Precision/recall metrics |
| GET | `/api/ml/metrics/fp_breakdown` | admin | FP breakdown by plugin |
| POST | `/api/ml/metrics/eval_thresholds` | admin | Evaluate thresholds |
| GET | `/api/explain/status` | admin | Explainability status |
| POST | `/api/explain/finding` | admin | Explain finding (SHAP/LIME) |

#### Vector Search (3 endpoints)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/vector/findings/similar` | admin, analyst | Find similar findings |
| GET | `/api/vector/index/status` | admin, analyst | Vector index status |
| POST | `/api/vector/index/rebuild` | admin | Rebuild vector index |

#### Audit & Compliance (3 endpoints)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/audit/events` | admin, auditor | List audit events (paginated) |
| GET | `/api/audit/export` | admin | Export raw audit log |
| POST | `/api/audit/event` | admin, analyst | Log audit event |

#### Artifacts & CI Gates (6 endpoints)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/artifacts/list` | admin, analyst | List artifacts in subdirectory |
| GET | `/api/artifacts/read` | admin, analyst | Read artifact file |
| GET | `/api/artifacts/download` | admin, analyst | Download artifact |
| GET | `/api/gates/summary` | admin, analyst | CI gates summary |
| GET | `/api/gates/deltas` | admin, analyst | Gates delta vs last check |
| GET | `/api/jobs/history` | Any | Aggregated job history |

#### Curation (4 endpoints)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/curation/import` | admin | Import external results |
| GET | `/api/curation/tasks` | admin | Get curation tasks |
| POST | `/api/curation/review` | admin | Record review decision |
| GET | `/api/curation/summary` | admin | Curation summary |

#### Agent System (8 endpoints, requires `AODS_AGENT_ENABLED=1`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/agent/tasks` | admin, analyst | Create agent task |
| GET | `/api/agent/tasks/{id}` | admin, analyst | Get agent task result |
| GET | `/api/agent/tasks/{id}/transcript` | admin, analyst | Get agent transcript |
| POST | `/api/agent/pipeline` | admin, analyst | Run full agent pipeline |
| GET | `/api/agent/stats` | admin, analyst | Agent usage statistics |
| GET | `/api/agent/config` | admin | Get agent configuration |
| POST | `/api/agent/triage/feedback` | admin, analyst | Submit triage feedback |
| GET | `/api/agent/triage/feedback/history` | admin, analyst | Feedback history |

#### Admin & User Management (3 endpoints)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/admin/users` | admin | List all users |
| GET | `/api/admin/roles` | admin | List available roles |
| PUT | `/api/admin/users/{username}/role` | admin | Update user role |

#### Admin & Dev (8 endpoints)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/config` | Any | Runtime UI configuration |
| GET | `/api/schemas/{name}` | Any | Retrieve JSON schema |
| GET | `/api/mappings/sources` | Any | Security framework mappings |
| GET | `/api/dev/servers/status` | admin | Dev server status |
| POST | `/api/dev/servers/start` | admin | Start dev servers |
| POST | `/api/dev/servers/stop` | admin | Stop dev servers |
| GET | `/api/ci/toggles` | admin | List CI/feature toggles |
| PATCH | `/api/ci/toggles` | admin | Update CI/feature toggles |

### SSE Streaming

AODS uses Server-Sent Events (SSE) for real-time updates. Three SSE streams are available:

**Scan progress:**

```javascript
const token = 'YOUR_JWT_TOKEN';
const evtSource = new EventSource(
  `/api/scans/${sessionId}/progress/stream?token=${token}`
);
evtSource.onmessage = (e) => {
  const data = JSON.parse(e.data);
  console.log(`${data.pct}% - ${data.stage}: ${data.message}`);
};
```

> **Note:** `EventSource` does not support custom headers in browsers. Pass the JWT via the `?token=` query parameter instead of an `Authorization` header.

**Scan logs:**

```javascript
const evtSource = new EventSource(`/api/scans/${sessionId}/logs/stream?token=${token}`);
```

**Batch status:**

```javascript
const evtSource = new EventSource(`/api/batch/${jobId}/status/stream?token=${token}`);
```

### Web UI Pages

The React web UI is available at `http://localhost:8088/ui` and provides 33 pages:

**General (all roles):**

| Page | Path | Description |
|------|------|-------------|
| Dashboard | `/` | Overview with scan stats and activity |
| Scan Results | `/runs` | List of all scan results |
| Result Detail | `/runs/:id` | Detailed findings view for a scan |
| Recent Jobs | `/jobs` | Aggregated job history |
| Tools Status | `/tools` | ADB, JADX, Frida availability |
| Artifacts | `/artifacts` | Browse scan artifacts and reports |
| Reports | `/reports` | Report browser and download |
| Policies | `/policies` | Security policies reference |
| Playbooks | `/playbooks` | Response playbooks |

**Analyst (admin + analyst):**

| Page | Path | Description |
|------|------|-------------|
| New Scan | `/new-scan` | Start a new scan with options |
| Vector Search | `/vector-search` | Semantic similarity search |
| CI Gates | `/gates` | Quality gate dashboard |
| Frida Console | `/frida` | Interactive Frida instrumentation |
| Scan Compare | `/compare` | Side-by-side scan comparison |

**Admin only:**

| Page | Path | Description |
|------|------|-------------|
| ML Overview | `/ml` | ML pipeline status and models |
| ML Training | `/ml/training` | Training job management |
| ML Thresholds | `/ml/thresholds` | Confidence threshold tuning |
| ML PR Metrics | `/ml/metrics` | Precision/recall charts |
| ML FP Breakdown | `/ml/fp-breakdown` | False positive analysis |
| Mapping Sources | `/mappings/sources` | Security framework sources |
| Dataset Explorer | `/datasets` | ML dataset browser |
| Executive Dashboard | `/exec` | Executive summary view |
| Batch Console | `/batch` | Batch scan management |
| Audit Log | `/audit` | Audit trail (also auditor role) |
| Config | `/config` | Runtime configuration |
| Curation | `/curation` | Finding curation workflow |
| Agent Dashboard | `/agent` | AI agent status, pipeline runs, token metrics |
| RBAC Admin | `/rbac-admin` | User role management |
| Feedback Analytics | `/feedback` | ML triage feedback analysis and trends |

**Keyboard shortcuts:**
- `gg` - navigate to Gates dashboard
- `gr` - navigate to Results list

---

## 9. Plugin System

### How Plugins Work

All AODS plugins extend `BasePluginV2` and follow a standard interface:

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
        # Analyze the APK
        findings = []
        # ... analysis logic ...
        return PluginResult(
            status=PluginStatus.SUCCESS,
            findings=findings,
            metadata={"execution_time": elapsed}
        )
```

**Key types:**

- `PluginCapability` - declares what a plugin does (static, dynamic, network, crypto, manifest, compliance, etc.)
- `PluginStatus` - execution result (SUCCESS, FAILURE, TIMEOUT, SKIPPED, PARTIAL_SUCCESS)
- `PluginFinding` - a single vulnerability finding with title, severity, confidence, evidence, CWE, MASVS mapping
- `PluginResult` - wrapper containing status, list of findings, and metadata
- `APKContext` - runtime context providing APK path, workspace, sources, manifest data

### Plugin Categories

#### Manifest & Platform (5 plugins)

| Plugin | Description | MASVS |
|--------|-------------|-------|
| `enhanced_manifest_analysis` | AndroidManifest.xml analysis - debuggable, backup, cleartext, exports | PLATFORM-1/2, STORAGE-1 |
| `apk_signing_certificate_analyzer` | APK signing certificate validation and tampering detection | CRYPTO-1/2 |
| `attack_surface_analysis` | Exposed components, intent receivers, entry points | - |
| `component_exploitation_plugin` | Exploitation testing for exported activities/services/receivers | - |
| `improper_platform_usage` | Android API usage pattern violations | - |

#### Data Storage & Privacy (9 plugins)

| Plugin | Description | MASVS |
|--------|-------------|-------|
| `insecure_data_storage` | Unencrypted sensitive data, weak storage patterns | - |
| `enhanced_data_storage_modular` | SharedPrefs, files, databases, external storage | - |
| `privacy_leak_detection` | Sensitive data exposure paths | - |
| `privacy_controls_analysis` | Location, microphone, camera permission analysis | - |
| `privacy_analyzer` | Hardcoded PII, clipboard, logging, unencrypted storage | PRIVACY-1 |
| `consent_analyzer` | Missing consent mechanisms and privacy policies | PRIVACY-3 |
| `data_minimization_analyzer` | Excessive data collection, retention issues | PRIVACY-2 |
| `tracking_analyzer` | Tracking SDKs, advertising ID misuse, fingerprinting | PRIVACY-4 |
| `network_pii_traffic_analyzer` | PII in network traffic | PRIVACY-1, NETWORK-1 |

#### Cryptography & Network (7 plugins)

| Plugin | Description | MASVS |
|--------|-------------|-------|
| `cryptography_tests` | Encryption implementations, key management, algorithm strength | - |
| `advanced_ssl_tls_analyzer` | SSL/TLS certificates, pinning, protocols, ciphers | - |
| `network_cleartext_traffic` | HTTP cleartext, insecure network configs | NETWORK-1/2 |
| `enhanced_network_security_analysis` | Network security config, cert pinning, TLS versions | - |
| `enhanced_encoding_cloud_analysis` | Cloud service security, encoding analysis | CRYPTO-1 |
| `enhanced_firebase_integration_analyzer` | Firebase API misconfig, auth bypass | - |
| `network_communication_tests` | Dynamic SSL/TLS testing, MitM susceptibility | NETWORK-1/2 |

#### Code Quality & Injection (4 plugins)

| Plugin | Description | MASVS |
|--------|-------------|-------|
| `advanced_vulnerability_detection` | Pattern-based detection with parallel processing | - |
| `code_quality_injection_analysis` | SQL injection, expression language injection | - |
| `injection_vulnerabilities` | SQL injection via Drozer and content provider analysis | CODE-8 |
| `traversal_vulnerabilities` | Path/directory traversal in file operations | - |

#### Dynamic & Behavioral (6 plugins)

| Plugin | Description | MASVS |
|--------|-------------|-------|
| `frida_dynamic_analysis` | Frida runtime hooking, memory inspection, traffic interception | - |
| `advanced_dynamic_analysis_modules` | Intent fuzzing, network traffic, WebView testing | PLATFORM-1/2/3 |
| `alternative_dynamic_analysis` | Baseline dynamic analysis without Frida | - |
| `intent_fuzzing_analysis` | Intent filter vulnerabilities | - |
| `mitmproxy_network_analysis` | Protocol analysis with MITMProxy | - |
| `objection_integration` | Interactive runtime testing | - |

#### Anti-Tampering & Resilience (5 plugins)

| Plugin | Description | MASVS |
|--------|-------------|-------|
| `anti_tampering_analysis` | Root detection, debugger detection, obfuscation, RASP | - |
| `authentication_security_analysis` | Auth bypass, biometrics, credentials, sessions | - |
| `biometric_security_analysis` | Fingerprint bypass, biometric weaknesses | - |
| `emulator_detection_analyzer` | Emulator checks and RE resistance | RESILIENCE-2 |
| `dynamic_code_analyzer` | Dynamic code loading, reflection, dex loading | CODE-4 |

#### Compliance & Standards (4 plugins)

| Plugin | Description | MASVS |
|--------|-------------|-------|
| `mastg_integration` | MASTG compliance validation | - |
| `nist_compliance_reporting` | NIST framework compliance assessment | - |
| `semgrep_mastg_analyzer` | Semgrep rule-based MASTG analysis | - |
| `jadx_static_analysis` | JADX source code vulnerability patterns | CRYPTO-1, STORAGE-1 |

#### Specialized (6 plugins)

| Plugin | Description | MASVS |
|--------|-------------|-------|
| `enhanced_static_analysis` | Static code pattern analysis | CODE-2, STORAGE-1 |
| `webview_security_analysis` | WebView XSS, JS bridge, file access | - |
| `mobile_serialization_security` | Unsafe deserialization, object injection | - |
| `external_service_analysis` | OAuth flows, third-party API security | - |
| `token_replay_analysis` | Token replay attacks, auth token handling | - |
| `runtime_decryption_analysis` | Obfuscation bypass, runtime decryption | - |

### MASVS Coverage Summary

| MASVS Category | Plugins |
|---------------|---------|
| MASVS-PLATFORM | 6 plugins |
| MASVS-STORAGE | 7 plugins |
| MASVS-CRYPTO | 9 plugins |
| MASVS-NETWORK | 7 plugins |
| MASVS-PRIVACY | 5 plugins |
| MASVS-CODE | 5 plugins |
| MASVS-RESILIENCE | 2 plugins |
| MASVS-AUTH | 1 plugin |

---

## 10. ML Pipeline

### Architecture Overview

```
APK → Feature Extraction → Model Selection → Prediction
                                                  ↓
                            Calibration ← Confidence Score
                                                  ↓
                         FP Reduction → Explainability → Output
```

### Pipeline Stages

1. **Feature Extraction** - `core/ml/apk_feature_extractor.py` extracts structural features from APK files (permissions, API calls, string patterns, component counts)

2. **Model Selection** - based on finding type, the pipeline routes to the appropriate model (vulnerability detection, malware classification, or false positive reduction)

3. **Prediction** - models in `models/` produce raw predictions:
   - `vulnerability_detection/` - ensemble of RF, MLP, and GB classifiers
   - `malware_classification/` - hybrid malware classifier
   - `false_positive_reduction/` - FP reducer model

4. **Calibration** - `core/ml/calibration_loader.py` applies isotonic, Platt, or temperature calibration to convert raw scores into calibrated probabilities

5. **Confidence Scoring** - `core/confidence_scorer.py` combines ML predictions with evidence-based assessment

6. **FP Reduction** - `core/fp_reducer.py` provides a canonical 3-stage pipeline: noise source dampening → ML 8-classifier ensemble → heuristic rules

7. **Explainability** - `core/ml/explainability_facade.py` provides unified explainability via `ExplainabilityFacade` with fallback (SHAP → LIME → rule-based → confidence-based)

### Model Types

| Model | Location | Purpose |
|-------|----------|---------|
| Vulnerability Ensemble | `models/vulnerability_detection/` | Multi-model vulnerability detection (RF + MLP + GB) |
| FP Reducer | `models/unified_ml/false_positive/` | Optimized 8-classifier FP ensemble |
| Calibration | `models/calibration/` | Score calibration (isotonic, Platt, temperature) |
| Malware Classifier | `models/malware_classification/` | ML-based malware detection |
| Malware Enhanced | `models/malware_detection_enhanced/` | Enhanced malware classifier |
| Malware Hybrid | `models/malware_detection_hybrid/` | Hybrid approach malware detection |
| Malware Proactive | `models/malware_detection_proactive/` | Proactive malware detection |
| Explainability | `models/vulnerability_detection/explainability_model.pkl` | SHAP/LIME feature explanations |
| CWE-Specific | `models/vulnerability_detection_enhanced/cwe_*.pkl` | Per-CWE specialized models |
| Unified ML | `models/unified_ml/` | Unified calibration config |

### Confidence Scoring System

AODS uses a multi-factor confidence scoring system (`core/confidence_scorer.py`):

**Evidence Assessment:**
- Structural evidence - code snippets, file paths, line numbers
- NLP evidence - description quality, keyword density
- Pattern strength - match against known vulnerability signatures

**Business Domain Detection** (`core/app_type_detector.py`):

AODS detects the business domain of the app being analyzed and adjusts confidence scores accordingly. A crypto vulnerability in a banking app gets a higher confidence boost than the same finding in a game.

| Domain | Description | Security Sensitivity |
|--------|-------------|---------------------|
| Banking | Financial services, payments | Very High |
| Healthcare | Medical, health, fitness | Very High |
| Government | Government services, civic | Very High |
| E-Commerce | Shopping, retail | High |
| Enterprise | Business, productivity | High |
| Social Media | Social networks, messaging | High |
| Education | Learning, training | Medium |
| Travel | Navigation, transportation | Medium |
| News/Media | News, content | Medium |
| Utility | Tools, system apps | Medium |
| Gaming | Games, entertainment | Low |
| Unknown | Cannot determine | Medium |

**Confidence Levels:**

| Level | Score Range | Meaning |
|-------|-----------|---------|
| HIGH | >90% | Clear vulnerability patterns with strong evidence |
| MEDIUM | 70-90% | Probable issues requiring investigation |
| LOW | 50-70% | Uncertain findings needing manual review |
| VERY LOW | <50% | Likely false positives |

### Disabling ML

```bash
# Via environment variable
AODS_DISABLE_ML=1 python dyna.py --apk app.apk

# Via CLI flag
python dyna.py --apk app.apk --disable-ml

# Disable enhancements (ML + smart filtering + recommendations)
python dyna.py --apk app.apk --disable-enhancements
```

---

## 11. Dynamic Analysis with Frida

### Prerequisites

- **Frida server** running on target device/emulator
- **ADB** connected to the device
- **frida-tools** installed: `pip install frida-tools frida`

### WebSocket Console

The Frida console is available at `/frida` in the web UI. It provides:

- Device selection and process listing
- One-click attach/detach to running processes
- Script editor with syntax highlighting
- Real-time event log with SSE streaming
- RPC call interface
- Session baseline (environment, anti-debug detection)

### API-Based Frida Interaction

**1. List devices:**

```bash
curl http://localhost:8088/api/frida/devices \
  -H "Authorization: Bearer TOKEN"
```

**2. Attach to a process:**

```bash
curl -X POST http://localhost:8088/api/frida/attach \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"packageName": "com.example.app", "deviceId": "emulator-5554"}'
```

**3. Upload a custom script:**

```bash
curl -X POST http://localhost:8088/api/frida/session/com.example.app/scripts \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "inline",
    "name": "hook_crypto",
    "content": "Interceptor.attach(Module.findExportByName(\"libcrypto.so\", \"EVP_EncryptInit_ex\"), { onEnter: function(args) { console.log(\"encrypt called\"); } });"
  }'
```

**4. Execute an RPC call:**

```bash
curl -X POST http://localhost:8088/api/frida/session/SESSION_ID/rpc \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"method": "getClassList", "args": []}'
```

**5. Stream events (SSE):**

```bash
curl -N http://localhost:8088/api/frida/session/com.example.app/events/stream \
  -H "Authorization: Bearer TOKEN"
```

### Corellium Integration

For cloud-based device testing with Corellium:

```bash
curl -X POST http://localhost:8088/api/frida/corellium/ensure \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"host": "device.corellium.com", "port": 5001}'
```

This handles ADB connection, Frida server port forwarding, and readiness verification with retries.

---

## 12. Vector Search (ChromaDB)

### Overview

AODS includes a ChromaDB-based vector search system for semantic similarity search across findings. This allows you to find findings similar to a known vulnerability pattern.

### Enabling

```bash
export AODS_VECTOR_DB_ENABLED=1
export AODS_VECTOR_DB_PATH=data/vector_index/   # optional, default path
```

### Usage

**Find similar findings via API:**

```bash
curl -X POST http://localhost:8088/api/vector/findings/similar \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "hardcoded API key in source code",
    "limit": 10
  }'
```

**Check index status:**

```bash
curl http://localhost:8088/api/vector/index/status \
  -H "Authorization: Bearer TOKEN"
```

**Rebuild index (admin only):**

```bash
curl -X POST http://localhost:8088/api/vector/index/rebuild \
  -H "Authorization: Bearer TOKEN"
```

### Web UI

The Vector Search page is available at `/vector-search` in the web UI (admin and analyst roles). It provides a search box with results showing similarity scores and finding details.

### Constraints

- **Single-worker uvicorn only** - ChromaDB uses SQLite internally, which does not support concurrent write access from multiple processes. Always start the server with `--workers 1`.
- The embedding model runs locally (no external API calls).

---

## 13. Batch Processing & CI/CD

### Batch Target File

Create a text file with one APK path per line:

```text
# batch_targets.txt
/path/to/app1.apk
/path/to/app2.apk
/path/to/app3.apk
```

### Running a Batch Scan

```bash
# Sequential batch
python dyna.py --batch-targets batch_targets.txt

# Parallel batch
python dyna.py --batch-targets batch_targets.txt --batch-parallel --batch-max-concurrent 4

# With custom output directory
python dyna.py --batch-targets batch_targets.txt --batch-output-dir results/batch_2026/
```

### Batch YAML Configuration

```yaml
# batch_config.yaml
targets:
  - path: /path/to/app1.apk
    profile: standard
  - path: /path/to/app2.apk
    profile: deep
concurrency: 4
timeout_minutes: 60
output_dir: results/batch/
```

```bash
python dyna.py --batch-config batch_config.yaml
```

### API-Based Batch Processing

```bash
# Start a batch job
curl -X POST http://localhost:8088/api/batch/start \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "apkList": "/path/to/targets.txt",
    "profile": "lightning",
    "concurrency": 4,
    "outDir": "artifacts/scans/batch"
  }'

# Monitor status via SSE
curl -N http://localhost:8088/api/batch/JOB_ID/status/stream \
  -H "Authorization: Bearer TOKEN"
```

### CI/CD Integration

#### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed successfully |
| 1 | Critical vulnerabilities found (with `--fail-on-critical`) |
| 2 | High vulnerabilities found (with `--fail-on-high`) |

#### GitHub Actions Example

```yaml
name: AODS Security Scan
on:
  pull_request:
    paths: ['app/**']

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          lfs: true

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install AODS
        run: |
          python -m venv aods_venv
          source aods_venv/bin/activate
          pip install -r requirements/base.txt -r requirements/analysis.txt

      - name: Run Security Scan
        env:
          AODS_STATIC_ONLY_HARD: '1'
          AODS_DISABLE_ML: '1'
        run: |
          source aods_venv/bin/activate
          python dyna.py --apk app/build/outputs/apk/release/app-release.apk \
            --profile lightning \
            --ci-mode \
            --fail-on-critical \
            --formats json \
            --output artifacts/security-report.json

      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: artifacts/security-report.json
```

#### GitLab CI Example

```yaml
security-scan:
  stage: test
  image: python:3.11-slim
  variables:
    AODS_STATIC_ONLY_HARD: '1'
    AODS_DISABLE_ML: '1'
  script:
    - python -m venv aods_venv
    - source aods_venv/bin/activate
    - pip install -r requirements/base.txt -r requirements/analysis.txt
    - python dyna.py --apk $APK_PATH
        --profile lightning
        --ci-mode
        --fail-on-critical
        --formats json
        --output artifacts/security-report.json
  artifacts:
    paths:
      - artifacts/security-report.json
    when: always
```

#### Docker-Based CI

```bash
# Run tests in CI container
make test-ci

# Run E2E tests
make test-e2e
```

### Make Targets for Quality Gates

| Target | Description |
|--------|-------------|
| `make baseline-suite` | Run baseline scan suite |
| `make local-gates` | Run integration quality gates |
| `make local-gates-quick` | Quick quality gate check |
| `make dev-gates` | Development quality gates |
| `make release-gates` | Strict release quality gates |
| `make dedup-smoke` | Deduplication smoke test |
| `make dedup-effectiveness` | Check deduplication effectiveness |
| `make androgoat-dedup` | Full AndroGoat dedup pipeline |
| `make androgoat-dedup-wsl` | WSL-safe AndroGoat dedup run |
| `make androgoat-dedup-wsl-ultra` | Ultra-conservative WSL run |
| `make precommit` | Run pre-commit checks |

---

## 14. Agent System (AI-Powered Analysis)

### Overview

AODS includes an optional AI agent system that provides intelligent post-scan analysis. Agents are disabled by default and require `AODS_AGENT_ENABLED=1` to activate. The agent system is fully optional - AODS works without it.

### Agent Types

| Agent | Purpose | CLI Flag | When It Runs |
|-------|---------|----------|-------------|
| **Triage** | Classifies findings into groups (Critical Path, Quick Wins, etc.) | `--agent-triage` | Post-scan |
| **Verification** | Confirms HIGH+ findings via Frida instrumentation | `--agent-verify` | Post-scan |
| **Remediation** | Generates CWE-specific code patches | `--agent-remediate` | Post-scan |
| **Narration** | Produces structured narrative with risk ratings and attack chains | `--agent-narrate` | Post-scan |
| **Orchestration** | Selects optimal plugins based on APK manifest analysis | `--agent-orchestrate` | Pre-scan |
| **Pipeline** | Runs all agents sequentially: triage → verify → remediate → narrate | `--agent-pipeline` | Post-scan |

### Quick Start

```bash
# Enable the agent system
export AODS_AGENT_ENABLED=1

# Configure an LLM provider (Anthropic, OpenAI, or Ollama)
export AODS_AGENT_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...

# Run a scan with agent triage
python dyna.py --apk app.apk --mode deep --agent-triage

# Run the full agent pipeline
python dyna.py --apk app.apk --mode deep --agent-pipeline

# Or use agent mode (equivalent to --mode deep with all agents)
python dyna.py --apk app.apk --mode agent
```

### Heuristic Fallback

Triage and remediation agents automatically fall back to heuristic mode when no LLM API key is available:

```bash
# Works without any API key - uses heuristic triage/remediation
AODS_AGENT_ENABLED=1 python dyna.py --apk app.apk --agent-triage --agent-remediate
```

The heuristic triage classifies findings by severity, CWE, and exploitability patterns. Heuristic remediation provides CWE-specific code templates for the top 10 vulnerability categories.

### LLM Provider Configuration

| Provider | Env Vars | Notes |
|----------|----------|-------|
| Anthropic | `AODS_AGENT_PROVIDER=anthropic`, `ANTHROPIC_API_KEY` | Default provider |
| OpenAI | `AODS_AGENT_PROVIDER=openai`, `OPENAI_API_KEY` | GPT-4 recommended |
| Ollama | `AODS_AGENT_PROVIDER=ollama`, `AODS_AGENT_BASE_URL=http://localhost:11434` | Local models, OpenAI-compatible API |

Override the model: `AODS_AGENT_MODEL=claude-sonnet-4-6` or `--agent-model claude-sonnet-4-6`

### API Endpoints

```bash
# Run a triage agent task
curl -X POST http://localhost:8088/api/agent/tasks \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type": "triage", "scan_id": "SESSION_ID"}'

# Get agent task result
curl http://localhost:8088/api/agent/tasks/TASK_ID \
  -H "Authorization: Bearer TOKEN"

# Run the full pipeline
curl -X POST http://localhost:8088/api/agent/pipeline \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "SESSION_ID"}'

# Get agent usage stats (token metrics, trends)
curl http://localhost:8088/api/agent/stats \
  -H "Authorization: Bearer TOKEN"

# Submit triage feedback
curl -X POST http://localhost:8088/api/agent/triage/feedback \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"finding_id": "...", "feedback": "true_positive"}'
```

### Web UI

The Agent Dashboard is available at `/agent` (admin role) and provides:

- Pipeline run status and history
- Token usage metrics and cost tracking
- Agent trends panel with historical data
- Pipeline step progress visualization

Agent results also appear as tabs in the Result Detail page: Triage, Remediation, AI Analysis (narration), Verification, and Orchestration Strategy.

### Configuration

Agent configuration is stored in `config/agent_config.yaml`:

```yaml
provider: anthropic          # or openai, ollama
max_iterations: 10           # Max agent loop iterations
cost_limit: null             # Token budget / cost cap
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AODS_AGENT_ENABLED` | `0` | Enable agent system |
| `AODS_AGENT_PROVIDER` | `anthropic` | LLM provider: `anthropic`, `openai`, `ollama` |
| `AODS_AGENT_API_KEY_ENV` | - | Env var name holding the API key |
| `AODS_AGENT_BASE_URL` | - | Custom base URL (for Ollama or proxies) |
| `AODS_AGENT_MODEL` | - | Model override |
| `AODS_AGENT_MAX_ITERATIONS` | `10` | Max agent loop iterations |
| `AODS_AGENT_COST_LIMIT` | - | Token budget / cost cap for pipeline |

---

## 15. Advanced Features

### Vulnerable App Mode

For deliberately vulnerable training apps (DIVA, InsecureBankv2, AndroGoat, etc.), use vulnerable app mode to disable aggressive filtering:

```bash
python dyna.py --apk DIVA.apk --vulnerable-app-mode

# With name-pattern heuristics (auto-detection)
AODS_ALLOW_VULNERABLE_APP_HEURISTICS=1 python dyna.py --apk DIVA.apk
```

This relaxes ML filtering and confidence thresholds so intentional vulnerabilities are not filtered out.

### Malware Detection

Enable ML-based malware classification:

```bash
python dyna.py --apk suspicious.apk --enable-malware-scan
```

This analyzes structural APK features (permissions, API calls, component patterns) to detect malware without relying on AV signatures.

### Progressive Analysis

For very large APKs (100MB+), enable progressive analysis to sample a subset of source files:

```bash
python dyna.py --apk large_app.apk --progressive-analysis --sample-rate 0.3
```

The `--sample-rate` controls what fraction of files to analyze (0.1 = 10%, 1.0 = 100%).

### Compliance Frameworks

```bash
# NIST Cybersecurity Framework
python dyna.py --apk app.apk --compliance nist

# OWASP MASVS
python dyna.py --apk app.apk --compliance masvs

# ISO 27001
python dyna.py --apk app.apk --compliance iso27001

# OWASP Top 10 Mobile
python dyna.py --apk app.apk --compliance owasp
```

### Cross-Platform Analysis

Analyze cross-platform frameworks within Android APKs:

```bash
# All frameworks
python dyna.py --apk app.apk --cross-platform

# Specific frameworks
python dyna.py --apk app.apk --cross-platform --frameworks flutter react_native
```

Supported: Flutter, React Native, Xamarin, PWA.

### Custom Configuration

Create a custom YAML configuration file to override default settings:

```bash
python dyna.py --apk app.apk --config config/my_config.yaml
```

Pattern files in `config/`:
- `vulnerability_patterns.yaml` - vulnerability detection patterns
- `framework_vulnerability_patterns.yaml` - framework-specific patterns
- `kotlin_vulnerability_patterns.yaml` - Kotlin-specific patterns
- `vulnerable_app_heuristics.yaml` - vulnerable app detection heuristics
- `masvs_config.json` - MASVS control configuration

### Deduplication Strategies

| Strategy | Description |
|----------|-------------|
| `aggressive` | Maximum dedup - merges similar findings aggressively (default) |
| `intelligent` | Context-aware dedup with evidence preservation |
| `conservative` | Minimal dedup - preserves more distinct findings |
| `basic` | Simple title + CWE dedup |

```bash
python dyna.py --apk app.apk --dedup-strategy conservative --dedup-threshold 0.9
```

---

## 16. Deployment

### Development Setup

**Manual:**

```bash
source aods_venv/bin/activate

# Start API server
AODS_ADMIN_PASSWORD=admin uvicorn core.api.server:app --host 0.0.0.0 --port 8088 --workers 1 &

# Start UI dev server (optional, for hot reload)
cd design/ui/react-app && npm run dev &
```

### Docker Compose

AODS provides three Docker Compose profiles:

**Development:**

```bash
# Build and start
make up-dev

# Or manually
docker compose --profile dev up -d api-ui

# View logs
make logs

# Stop
make down
```

**Production (security-hardened):**

```bash
# Initialize secrets
make secrets-init
# Edit secrets/aods_admin_password with a strong password

# Start
make up-prod
```

Production hardening includes:
- Read-only filesystem with tmpfs
- `no-new-privileges` security option
- All capabilities dropped
- Resource limits (2 CPU, 4 GB RAM)
- Non-root user (UID 10001)
- Docker secrets for passwords

**CI Testing:**

```bash
# Run pytest in container
make test-ci

# Run Playwright E2E in container
make test-e2e
```

### Service Architecture

| Service | Port | Profile | Description |
|---------|------|---------|-------------|
| `api-ui` | 8088 | dev | API server + React UI |
| `api-ui-prod` | 8088 | prod | Hardened API + UI |
| `worker` | - | dev | Scan execution worker |
| `ci-runner` | - | ci | Test execution |
| `playwright` | - | e2e | E2E browser tests |

### Named Volumes

| Volume | Lifecycle | Description |
|--------|-----------|-------------|
| `aods_artifacts` | Persistent | Scan artifacts and reports |
| `aods_reports` | Persistent | Generated reports |
| `aods_logs` | Persistent | Application logs |
| `aods_cache` | Ephemeral | Build and dependency cache |

### Environment Variable Recipes

**Minimal static-only:**

```bash
AODS_STATIC_ONLY_HARD=1 AODS_DISABLE_ML=1 AODS_ADMIN_PASSWORD=admin
```

**Full-featured with ML:**

```bash
AODS_ADMIN_PASSWORD=strongpass AODS_ANALYST_PASSWORD=analystpass
```

**CI pipeline:**

```bash
AODS_STATIC_ONLY_HARD=1 AODS_DISABLE_ML=1 AODS_MAX_WORKERS=1 AODS_JADX_THREADS=1
```

---

## 17. Troubleshooting

### Common Errors

**Virtual environment name error:**

```
ModuleNotFoundError: No module named 'structlog'
```

The venv must be named `aods_venv`. Other names like `.venv` or `venv` will fail because CI scripts and some imports reference the specific path.

```bash
# Fix: recreate with correct name
python3 -m venv aods_venv
source aods_venv/bin/activate
pip install -r requirements/base.txt
```

**JADX timeout:**

```
JADX decompilation timed out after 240 seconds
```

JADX has a 240-second timeout for the standard profile (configurable). It may time out on large APKs. Increase the timeout or use minimal decompilation:

```bash
AODS_JADX_THREADS=1 AODS_JADX_MEM_MB=1024 python dyna.py --apk large.apk
```

JADX returns exit code 1 on warnings but still produces valid output. The scan continues if the output directory exists.

**Out of memory (OOM):**

```
Killed
```

Reduce resource usage:

```bash
AODS_MAX_WORKERS=1 AODS_JADX_THREADS=1 AODS_JADX_MEM_MB=256 \
python dyna.py --apk app.apk --profile lightning --sequential --disable-ml
```

**ML models not found:**

```
ML integration unavailable
```

Ensure Git LFS is installed and models are pulled:

```bash
git lfs install
git lfs pull
ls models/vulnerability_detection/  # Should contain .pkl files, not pointer files
```

Or disable ML: `AODS_DISABLE_ML=1`

**ChromaDB lock error:**

```
sqlite3.OperationalError: database is locked
```

ChromaDB requires single-worker mode. Restart uvicorn with `--workers 1`:

```bash
uvicorn core.api.server:app --workers 1
```

**Frida not available:**

```
frida_tool_not_found
```

Install Frida tools and ensure Frida server is running on the target device:

```bash
pip install frida-tools frida
# On the device/emulator:
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
```

Or run in static-only mode: `AODS_STATIC_ONLY_HARD=1`

**ADB device not found:**

```
error: no devices/emulators found
```

Check ADB connection:

```bash
adb devices
# For Docker: ensure ADB_SERVER_SOCKET is set correctly
```

**Import errors after dependency changes:**

```
ImportError: cannot import name 'X' from 'core.Y'
```

Reinstall dependencies and verify the venv:

```bash
source aods_venv/bin/activate
pip install -r requirements/base.txt -r requirements/analysis.txt
```

### Debug Mode

Enable verbose logging for detailed diagnostics:

```bash
python dyna.py --apk app.apk --verbose
```

Or set the log level via environment variable:

```bash
AODS_LOG_LEVEL=DEBUG python dyna.py --apk app.apk
```

### Performance Tips

1. **Use the right profile** - lightning for CI, standard for most use cases, deep only when needed
2. **Static-only mode** - skip dynamic analysis if no device is available: `--static-only` or `AODS_STATIC_ONLY_HARD=1`
3. **Disable ML** - `--disable-ml` saves model loading time when confidence scores are not needed
4. **Limit workers** - `--max-workers 1` for resource-constrained environments
5. **Sequential execution** - `--sequential` avoids process spawning overhead for small APKs
6. **Progressive analysis** - `--progressive-analysis --sample-rate 0.2` for APKs with 10,000+ source files
7. **Skip existing reports** - `--skip-if-report-exists` avoids redundant scans in batch mode

### Getting Help

- Run `python dyna.py --help` for CLI usage
- Check API docs at `http://localhost:8088/docs` (Swagger UI)
- Review `docs/` directory for architecture and reference documentation
- File issues at the project repository
