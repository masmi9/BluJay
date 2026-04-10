# AODS - Automated OWASP Dynamic Scan Framework

[![Version](https://img.shields.io/badge/version-4.2.0-blue.svg)](https://github.com/ondefend/aods)
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()
[![Quality](https://img.shields.io/badge/quality-97--98%25-brightgreen.svg)](DOCS_INDEX.md)
[![AI/ML](https://img.shields.io/badge/AI%2FML-enhanced-purple.svg)](core/ai_ml/)

**Android security testing platform with vulnerability detection, analysis, and threat intelligence integration.**

## Project Status

> **Documentation**: See [DOCS_INDEX.md](DOCS_INDEX.md) for documentation navigation
> **Track Progress**: Roadmap and validated status documents are available on the `dev` branch under `roadmap/`

- **ML Pipeline**: Operational with 10 model directories (pre-trained ensembles)
- **Plugin Migration**: 100% on BasePluginV2 (66 plugin dirs)
- **Agent System**: 6 AI agents with LLM-agnostic provider support
- **Core Systems**: 160+ engineering tracks completed
- **Tests**: Python unit tests, Jest suites, and Playwright E2E specs are available on the `dev` branch

## Key Features

### Security Analysis
- **Static Analysis**: AndroidManifest.xml, source code, and binary analysis
- **Dynamic Analysis**: Runtime behavior monitoring with Frida integration
- **WebView Security**: WebView vulnerability detection
- **Network Analysis**: SSL/TLS, cleartext traffic, and certificate validation
- **Cryptographic Analysis**: Encryption strength and implementation review

### AI/ML Pipeline
- **ML Detection Pipeline**: Confidence calibration, FP reduction (3-stage pipeline)
- **Threat Intelligence**: CVE correlation and MITRE ATT&CK mapping
- **Explainability**: SHAP/LIME explanations for ML decisions
- **AutoResearch**: Automated parameter tuning for detection vs FP tradeoff
- **Malware Detection**: 48 malware family signatures with deobfuscation engine

### AI Agent System (optional)
- **Triage Agent**: Automated finding classification (Critical Path, Quick Wins, etc.)
- **Verification Agent**: Dynamic confirmation of findings via Frida instrumentation
- **Remediation Agent**: CWE-specific code patch generation with heuristic fallback
- **Narration Agent**: Post-scan natural-language analysis with risk ratings and attack chains
- **Orchestration Agent**: Pre-scan plugin selection based on APK analysis
- **Pipeline Supervisor**: Sequential orchestration (triage → verify → remediate → narrate)
- **LLM-Agnostic**: Supports Anthropic, OpenAI, and Ollama providers
- **Graceful Degradation**: Triage and remediation auto-fall back to heuristic mode when no API key

### Enterprise Features
- **Batch Processing**: Automated analysis of multiple APKs
- **CI/CD Integration**: Pipeline integration with quality gate scripts (available on the `dev` branch)
- **RBAC**: Role-based access control (admin, analyst, viewer, auditor, api_user)
- **Multi-format Reporting**: JSON, HTML, CSV, TXT output
- **React Dashboard**: 33-page React 18 + TypeScript + MUI frontend
- **Real-time Streaming**: SSE progress streams with reconnection support

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+ (for React UI)
- Android SDK (for APK analysis)
- Optional: Frida (for dynamic analysis)
- Note: Drozer is deprecated and disabled by default. Frida is the primary dynamic engine.

### Installation
```bash
# Clone repository
git clone https://github.com/ondefend/aods.git
cd aods

# Set up Python virtual environment (MUST be named aods_venv)
python3 -m venv aods_venv
source aods_venv/bin/activate

# Install dependencies
pip install -r requirements/base.txt        # Core dependencies
pip install -r requirements/analysis.txt    # Full analysis (includes ML)
pip install -r requirements/dev.txt         # Development (testing + code quality)

# Set up React UI
cd design/ui/react-app && npm ci && cd -
```

### Basic Usage

#### Single APK Analysis
```bash
# Quick analysis (recommended)
python dyna.py --apk app.apk --mode safe

# full analysis with AI/ML
python dyna.py --apk app.apk --mode deep

# Generate multiple report formats
python dyna.py --apk app.apk --formats json html csv
```

#### Enterprise Batch Processing
```bash
# Batch analysis with auto-detection
python dyna.py --batch-targets targets.txt --batch-parallel

# CI/CD pipeline integration
python dyna.py --batch-targets targets.txt --ci-mode --fail-on-critical
```

#### Targeted Analysis
```bash
# Static analysis only
python dyna.py --apk app.apk --static-only

# Dynamic analysis with Frida
python dyna.py --apk app.apk --dynamic-only

# WebView security focus
python dyna.py --apk app.apk --mode deep --profile deep
```

### UI/API Quickstart

```bash
# 1) Start the API server (FastAPI)
source aods_venv/bin/activate
python -m pip install -r requirements/docker.txt  # provides fastapi/uvicorn
python -m uvicorn core.api.server:app --host 127.0.0.1 --port 8088 --no-access-log

# 2) Configure UI to point at the API
sed -i 's#"apiBaseUrl".*#"apiBaseUrl": "http://127.0.0.1:8088/api",#' config/ui-config.json

# 3) Open the static mockups
#   - design/ui/index.html (gallery)
#   - design/ui/mockup_ui.html (interactive readiness)

# 4) Run the React app (optional; requires Node 18+)
cd design/ui/react-app
npm ci || npm install
npm run dev  # opens http://localhost:5088
```

Key paths:
- API server: `core/api/server.py` + route modules in `core/api/routes/`
- API endpoints: health, auth, scans, batch, reports, gates, ML, Frida, vector search, agent, dev/admin
- UI config: `config/ui-config.json` (`apiBaseUrl`, `webBasePath`, `workspaceRoot`)
- React app: `design/ui/react-app/` (33 pages, shared components, custom hooks)

## Analysis Profiles

| Profile | Plugins | Speed | Use Case |
|---------|---------|-------|----------|
| `lightning` | 12 | ~60s | Quick CI/CD checks |
| `fast` | 18 | ~2-3min | Regular testing |
| `standard` | 41 | ~5-8min | Production scans |
| `deep` | 48 | ~15+min | Security audits |

## Advanced Configuration

### Scan Modes
- **`safe`**: Static analysis only, no device interaction
- **`deep`**: Static + dynamic analysis with ML filtering

### CLI Options
```bash
# Disable ML (faster, pattern-only detection)
python dyna.py --apk app.apk --disable-ml

# Vulnerable app mode (relaxed thresholds for test apps)
python dyna.py --apk app.apk --vulnerable-app-mode

# Parallel plugin execution
python dyna.py --apk app.apk --parallel --profile fast

# Agent-assisted analysis (requires LLM API key)
python dyna.py --apk app.apk --mode agent --profile deep
```

#### ML False-Positive Threshold (env > YAML > default)

The ML FP filtering threshold is resolved in this order:
- Environment: `AODS_ML_FP_THRESHOLD` (or `AODS_ML_FALSE_POSITIVE_THRESHOLD`)
- YAML: `ml_filtering_control.production_app_ml_filtering_threshold` or `vulnerable_app_ml_filtering_threshold`
  - The selection is based on `AODS_APP_PROFILE` (`production` vs `vulnerable`/`qa_vulnerable`)
- Default: `0.15`

Examples:
```bash
# Force threshold to 0.12 regardless of YAML profile
export AODS_ML_FP_THRESHOLD=0.12

# Use YAML vulnerable threshold path
export AODS_APP_PROFILE=vulnerable

# CLI equivalents (persist into YAML for the run; env still wins)
python dyna.py --app-profile vulnerable --ml-fp-threshold 0.12 --apk app.apk --mode deep
```

### Environment Variables

| Variable | Default | Purpose |
|---------|---------|---------|
| `AODS_ALLOW_VULNERABLE_APP_HEURISTICS` | `0` | Enable name-pattern heuristics from `config/vulnerable_app_heuristics.yaml` for training apps. |
| `AODS_AI_FRIDA_ENABLE` | `0` | Enable rule-based Frida dynamic analysis suggestions. |
| `AODS_AI_FRIDA_ML_ENABLE` | `0` | Enable ML-based Frida suggestions (requires model artifacts). |
| `AODS_AI_FRIDA_MIN_SCORE` | `0.6` | Minimum score threshold for ML suggestions. |
| `AODS_REFERENCE_ONLY` | `0` | Emit reference-only reports to reduce artifact size in CI. |
| `AODS_CANONICAL` | `0` | Use canonical modular execution paths. |
| `AODS_ENABLE_DROZER` | `0` | Removed. Legacy env is ignored; Drozer is disabled in AODS. |
| `AODS_MAX_EXTERNAL_PROCS` | `2` | Global cap on concurrent external processes (ADB/JADX/Frida). Use `1` on constrained hosts. |
| `AODS_TOOL_EXECUTOR_THREADS` | `4` | Internal monitor thread-pool size used by the unified tool executor. Use `1-2` on constrained hosts. |
| `AODS_DEDUP_SIMILARITY` | `0.80` | Override deduplication similarity threshold (0.0–1.0). |

#### Crypto pattern toggles (YAML)

In `config/vulnerability_patterns.yaml` under `android_14_pattern_control`:

- `enable_crypto_rng_patterns` (default: false)
  - Gates RNG-related rules like `crypto_math_random_001` and `crypto_random_001`.
  - Turn on when auditing randomness issues in application code. Leave off to avoid noise in non-crypto contexts.
- `enable_crypto_policy_patterns` (default: false)
  - Gates policy-oriented rules like `crypto_keygen_001` (DSA/DH keygen heuristics).
  - Enable when enforcing org policy on key algorithms/params; keep off by default to reduce policy FPs.

These toggles can also be changed at runtime via `dyna.py` overrides or by editing the YAML. No code edits required.

CLI usage:

```bash
# Enable RNG-related crypto rules (Math.random/SHA1PRNG/constant seeds)
python dyna.py --enable-crypto-rng-patterns --apk app.apk --mode deep

# Enable policy crypto rules (DSA/DH keygen heuristics)
python dyna.py --enable-crypto-policy-patterns --apk app.apk --mode deep
```

#### Pattern Context Validation (SSRF/GDPR)

| Variable | Default | Purpose |
|---------|---------|---------|
| `AODS_PATTERN_CONTEXT_AB_PCT` | `1` | Percentage of findings to apply SSRF/GDPR context validation to (A/B gating). |
| `AODS_PATTERN_CONTEXT_FORCE` | `0` | Force-enable context validation for all SSRF/GDPR findings regardless of A/B bucket. |

Examples:
```bash
# 50% A/B rollout
export AODS_PATTERN_CONTEXT_AB_PCT=0.5

# Force-enable everywhere (e.g., CI hardening)
export AODS_PATTERN_CONTEXT_FORCE=1
```

#### Conditional WebView Hardening

| Variable | Default | Purpose |
|---------|---------|---------|
| `AODS_WEBVIEW_HARDENING_AUTO` | `1` | Auto-enable WebView hardening when signals are detected. |
| `AODS_WEBVIEW_HARDENING_AB_PCT` | `0.25` | A/B ramp percentage for auto-enablement. |
| `AODS_WEBVIEW_HARDENING_FORCE` | `0` | Force-enable WebView hardening (ignores auto/AB). |

Signals include: `android.webkit.WebView`, `WebSettings.setJavaScriptEnabled(...)`, `addJavascriptInterface(...)`, `evaluateJavascript(...)`, `setWebViewClient(...)`, `setWebChromeClient(...)`, `webview.loadUrl|loadData(...)`.

Examples:
```bash
# Increase ramp to 75%
export AODS_WEBVIEW_HARDENING_AB_PCT=0.75

# Force on for targeted runs
export AODS_WEBVIEW_HARDENING_FORCE=1
```

#### Network hardening (cleartext and hostname verification)

In `config/vulnerability_patterns.yaml` under `android_14_pattern_control`:

- `enable_network_hardening_patterns` (default: true)
  - Gates cleartext HTTP/WS rules (e.g., `network_http_002`, `network_http_003`, `network_ws_001`) and HostnameVerifier trust-all lambdas.
  - Set to `false` to disable these network hardening checks.

Many network and WebView hardening rules can be toggled without code edits via these YAML flags.

#### HTTP modes and allowlists

In `config/vulnerability_patterns.yaml` under `android_14_pattern_control`:

- `enable_http_strict` (default: true)
  - Flags all non-allowlisted HTTP (localhost/emulator exceptions only).
- `enable_http_rfc1918_allowed` (default: false)
  - Flags only public HTTP; RFC1918/internal HTTP is allowed.
- `enable_dev_lan_http_allowlist` (default: false)
  - Dev-LAN variant: allows RFC1918 ranges for development workflows.

Runtime override (preferred in CI/dev):

```bash
# Strict everywhere (production)
export AODS_HTTP_MODE=strict

# Internal/dev mode (allow RFC1918; flag public HTTP)
export AODS_HTTP_MODE=internal
```

Note: `strict_http_allowlist` is deprecated and disabled by default; use `enable_http_strict` or `AODS_HTTP_MODE` instead.

#### Job constraints (WorkManager/JobScheduler)

In `config/vulnerability_patterns.yaml` under `android_14_pattern_control`:

- `enable_job_constraints_patterns` (default: false)
  - Flags WorkManager/JobScheduler usage without constraints.

Runtime control (AUTO by app profile):

```bash
# Explicit enable/disable
export AODS_ENABLE_JOB_CONSTRAINTS=1   # or 0

# AUTO mode (default): enable for production-like profiles
export AODS_JOB_CONSTRAINTS=auto
export AODS_APP_PROFILE=production     # enables by default in AUTO
```

#### GDPR/data policy patterns

These are gated by `enable_gdpr_policy_patterns` (default: false) under `android_14_pattern_control` in `config/vulnerability_patterns.yaml`.

Enable at runtime via CLI or env:

```bash
# CLI override (persists into YAML for the run)
python dyna.py --enable-gdpr-policy-patterns --apk app.apk

# or set in YAML directly (persists)
# android_14_pattern_control:
#   enable_gdpr_policy_patterns: true
```

#### Resource-constrained recommendations (WSL/CI)

On memory/CPU-limited environments (e.g., WSL, small CI runners), use conservative values to avoid hangs or OS instability:

```bash
export AODS_RESOURCE_SAFE=1
export AODS_MAX_EXTERNAL_PROCS=1
export AODS_TOOL_EXECUTOR_THREADS=1
export AODS_PARALLEL_WORKERS=1
```

## Performance Metrics

### Key Metrics
- **Flake8**: 0 violations
- **TypeScript**: 0 errors (`tsc --noEmit`)
- **Plugin Coverage**: 66 v2 analyzers across 4 scan profiles

## Architecture

### Core Components
- **`dyna.py`**: Thin entry point (~200 lines) delegating to `core/cli/` (17 modules)
- **`core/`**: Core analysis engines, ML pipeline, API server, EVRE reporting
- **`core/api/`**: FastAPI server with 9 route modules (scans, frida, ml, dev, admin, vector_search, agent, autoresearch, malware)
- **`core/agent/`**: 6 AI agents with LLM providers (Anthropic, OpenAI, Ollama)
- **`core/evre/`**: Enhanced Vulnerability Reporting Engine (13 mixin modules)
- **`core/ai_ml/`** + **`core/ml/`**: ML pipeline with explainability facade
- **`plugins/`**: 66 v2 security analyzers + semgrep rule files
- **`design/ui/react-app/`**: React 18 + TypeScript + Vite + MUI (33 pages)
- **`config/`**: Configuration, vulnerability patterns, ML config, agent config

### Key Subsystems
- **Plugin System**: 66 BasePluginV2 analyzers with profile-based selection
- **Agent System**: 6 AI agents (triage, verification, remediation, narration, orchestration, pipeline) with heuristic fallback
- **EVRE**: Enhanced Vulnerability Reporting Engine (evidence enrichment, dedup, normalization)
- **ML Pipeline**: Feature extraction, confidence calibration, FP reduction, explainability (SHAP/LIME)
- **FP Reduction**: Canonical 3-stage pipeline (noise dampening → ML classifier → heuristic rules)
- **Vector Search**: ChromaDB-based semantic similarity search for findings
- **RBAC**: Role-based access control with ownership enforcement
- **SSE Streaming**: Real-time scan progress, logs, and batch status streams

## Report Formats

### Available Formats
- **JSON**: Machine-readable results for automation
- **HTML**: Web-based reports
- **CSV**: Spreadsheet-compatible vulnerability data
- **TXT**: Human-readable text summaries

### Report Contents
- Executive summary with risk assessment
- Detailed vulnerability findings with evidence
- ML confidence scores and explanations
- Remediation recommendations
- Compliance mapping (OWASP MASTG, NIST)

## Vulnerability Detection

### Detection Categories
- **Injection Flaws**: SQL, command, LDAP injection
- **Authentication Issues**: Weak authentication, session management
- **Authorization Problems**: Access control, privilege escalation
- **Cryptographic Failures**: Weak encryption, key management
- **Network Security**: SSL/TLS, cleartext communication
- **WebView Vulnerabilities**: XSS, JavaScript bridge security
- **Platform Misuse**: Android-specific security issues

### Additional Capabilities
- **IoC Extraction**: IP, domain, URL, hash, and crypto wallet detection with cross-APK correlation
- **Semgrep Rules**: 113 custom MASTG rules for static pattern matching
- **MITRE ATT&CK**: Technique mapping and threat intelligence enrichment
- **FP Reduction**: 3-stage pipeline (noise dampening, ML classifier, heuristic rules)

## Contributing

### Development Setup
```bash
# Install development dependencies
pip install -r requirements/dev.txt

# Code quality checks
flake8 core/ plugins/

# Tests are available on the dev branch
# git checkout dev && python -m pytest tests/
```

### Architecture Guidelines
- Follow modular design principles
- Maintain backward compatibility
- Implement error handling
- Add unit tests for new functionality

## Documentation

- **[Documentation Index](DOCS_INDEX.md)**: Central navigation for all docs
- **[User Guide](docs/USER_GUIDE.md)**: Usage guide (16 sections)
- **[RBAC Guide](docs/security/RBAC_GUIDE.md)**: Role-based access control details
- Roadmap, project status, and developer onboarding guide (`CLAUDE.md`) are available on the `dev` branch

## Support

### Getting Help
- **Issues**: [GitHub Issues](https://github.com/ondefend/aods/issues)
- **Documentation**: Check `docs/` directory and [DOCS_INDEX.md](DOCS_INDEX.md)
- **Developer Guide**: See `CLAUDE.md` on the `dev` branch for architecture and onboarding

### Common Issues
- **Frida not found**: Install Frida for dynamic analysis
- **APK not found**: Ensure APK path is correct
- **Permission errors**: Run with appropriate permissions

## License

This project is licensed under the MIT License.

## Acknowledgments

- OWASP Mobile Security Testing Guide (MASTG)
- Android Security Research Community
- Open source security testing tools
- Academic research in mobile security

---

**AODS: Android vulnerability detection and analysis.**

## Environment Toggles

- AODS_HTTP_MODE: `strict` or `internal` to switch HTTP rules mode.
- AODS_ENABLE_JOB_CONSTRAINTS: `1/0` to force enable/disable WorkManager/JobScheduler constraints.
- AODS_JOB_CONSTRAINTS: `auto|on|off` (auto respects AODS_APP_PROFILE).
- AODS_APP_PROFILE: `production|prod|qa|staging|dev` used by auto gating.
- AODS_MASVS_STRICT: `1` to fail MASVS gate on contradictions (local/CI optional).
- AODS_LOCAL_GATES: `1` to run local MASVS strict during pre-commit/pytest integration test.
- WebView hardening: AODS_WEBVIEW_HARDENING_AUTO (`1`), AODS_WEBVIEW_HARDENING_FORCE (`0/1`), AODS_WEBVIEW_HARDENING_AB_PCT (`0..1`).
- ML pipeline (Phase 3.6):
  - AODS_ML_ENABLE_CALIBRATION: `1/0` enable probability calibration (no-op if calibrator missing).
  - AODS_ML_CALIBRATOR_PATH: path to calibrator JSON (e.g., `{ "temperature": 1.3 }`).
- AODS_ML_CALIBRATION_FAMILY: optional family key (e.g., `android`, `ios`); when set, the runtime tries `<calibrator_path>/FAMILY/calibration.json` or `<base>/models/unified_ml/FAMILY/calibration.json` before falling back to the base calibrator.

### ML Calibrator

Calibrator artifact: `models/unified_ml/calibration.json`

The calibration pipeline trains and selects the best calibrator (Platt or Isotonic) based on validation ECE. The training pipeline and associated tooling are available on the `dev` branch under `tools/ml/`.

### Additional ML/Reporting Environment Variables

- AODS_ML_ENABLE_BATCH: `1/0` enables batch API usage (serial wrapper currently).
- AODS_ML_ENABLE_CACHE: `1/0` toggles classifier result caching.
- AODS_TENANT_ID: tenant label for report/artifact partitioning (default `default`).
- AODS_ENCRYPTION_PROVIDER: `noop|fernet|auto` encryption-at-rest provider for exported reports (default `noop`).
- AODS_ENCRYPTION_KEY_B64: base64-URL-safe key for `fernet`; if omitted, an ephemeral key is generated at runtime.

CI quality gates, baseline collection, deduplication evaluation, and related tooling are available on the `dev` branch under `tools/ci/`.

## ML Thresholds and Reporting

- Thresholds are derived from PR metrics and stored in `artifacts/ml_thresholds.json` (and `.yml`).
- Reports annotate findings with their applied threshold for transparency.
- Optional filtering: set environment variable `AODS_REPORT_FILTER_BY_THRESHOLDS=1` to hide findings below the per-plugin/category/default threshold. High/Critical are always preserved.
- UI: The React page `design/ui/react-app/src/pages/MLThresholds.tsx` includes a client-side preview tool to see which findings would pass the current thresholds without changing backend behavior.

## Configuration Overrides (Static Analyzer)
- `AODS_VULN_PATTERNS_CONFIG`: Optional env var with colon-separated YAML paths to load before defaults. Example:
  - Linux/macOS: `export AODS_VULN_PATTERNS_CONFIG="/path/one.yaml:/path/two.yaml"`
- YAML keys supported:
  - `file_filters.exclude_paths`: array of path-prefix strings to skip from scanning
  - `framework_exclusions`: array of regex/substring patterns for library/framework paths
- `AODS_STATIC_INCLUDE_GLOBS`: Optional colon-separated globs to include-only. When set, only files matching these globs are analyzed (others are skipped). Example:
  - `export AODS_STATIC_INCLUDE_GLOBS="*.java:src/company/app/*"`
- `AODS_STATIC_MAX_FILE_SIZE`: Optional integer (bytes) to override the per-file size analysis limit (default 10MB). Example:
  - `export AODS_STATIC_MAX_FILE_SIZE=1048576`  # 1MB

## Scan Profiles and Plugin Selection

AODS includes four scan profiles. Each profile selects a specific set of plugins and excludes deprecated or slow modules.

- Lightning: Fast, static-focused. Includes coordinated `jadx_static_analysis` + `enhanced_static_analysis`, critical analyzers, and TLS analyzer; excludes heavy/unstable modules (e.g., `advanced_pattern_integration`, `privacy_analyzer`, `network_pii_traffic_analyzer`).
- Fast: Adds common vulnerability analyzers (traversal, privacy leak, component exploitation, attack surface, enhanced network) while preserving cycle-safe static coordination.
- Standard: Full security coverage (41 plugins); includes dynamic capabilities (e.g., Frida). Excludes deprecated `network_pii_traffic_analyzer`. TLS analyzer enabled.
- Deep: All available plugins (no exclusions).

Profile validation tests and CI quality gates are available on the `dev` branch.
