# IODS – iOS OWASP Dynamic Scan Framework

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)]()
[![Platform](https://img.shields.io/badge/platform-iOS-lightgrey.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

**iOS security testing platform with vulnerability detection, analysis, and ML-powered false-positive reduction.**

IODS is the iOS equivalent of AODS, sharing the same architecture: plugin system, EVRE reporting engine, ML pipeline, FastAPI backend, and CLI interface — adapted for IPA files.

---

## Key Features

### Security Analysis
- **Binary Hardening**: PIE, ASLR, Stack Canary, ARC, symbol stripping (otool/nm)
- **App Transport Security**: NSAllowsArbitraryLoads, exception domains, TLS version checks
- **Keychain Security**: Insecure accessibility attributes (kSecAttrAccessibleAlways)
- **Entitlements**: get-task-allow, private entitlements, dangerous capabilities
- **Cryptography**: Weak algorithms (DES, MD5, RC4), ECB mode, hardcoded keys
- **Network Security**: SSL bypass patterns, cleartext HTTP, AFNetworking/Alamofire config
- **Data Storage**: NSUserDefaults, SQLite without encryption, NSFileProtectionNone
- **WebView**: UIWebView usage, JS bridge exposure, file:// access
- **Privacy**: NSUsageDescription keys, background location, permission combinations
- **Secrets**: API keys, AWS credentials, JWT tokens, high-entropy strings

### ML Pipeline
- **3-Stage FP Reduction**: Confidence adjustment → ML classifier → Heuristic rules
- **App Profile Thresholds**: Different thresholds for production vs. test apps
- **XGBoost Classifier**: Train on your own findings for custom FP reduction

### Enterprise Features
- **20 Security Plugins** across 4 scan profiles
- **Batch Processing**: Analyze multiple IPAs from a targets file
- **CI/CD Integration**: `--ci-mode --fail-on-critical` for pipeline gates
- **FastAPI Backend**: REST API for integration with dashboards/CI systems
- **RBAC**: admin, analyst, viewer, auditor, api_user roles
- **Multi-format Reports**: JSON, HTML, CSV, TXT

---

## Quick Start

### Prerequisites
- Python 3.10+
- Optional (for full analysis): `otool`, `nm`, `strings`, `class-dump`/`jtool2`, `codesign`
- Optional (for dynamic): Frida + jailbroken iOS device

### Installation

```bash
git clone https://github.com/yourorg/iods.git
cd iods

# Create virtual environment (MUST be named iods_venv)
python3 -m venv iods_venv
source iods_venv/bin/activate

# Install dependencies
pip install -r requirements/base.txt       # Core only
pip install -r requirements/analysis.txt   # + ML
pip install -r requirements/dev.txt        # + testing
```

### Basic Usage

```bash
# Static analysis (no device needed)
python ios_scan.py --ipa MyApp.ipa --mode safe

# Full analysis with ML false-positive reduction
python ios_scan.py --ipa MyApp.ipa --mode safe --profile deep

# Generate multiple report formats
python ios_scan.py --ipa MyApp.ipa --formats json html csv txt

# Dynamic analysis (jailbroken device + Frida)
python ios_scan.py --ipa MyApp.ipa --mode deep --profile deep

# Batch processing
python ios_scan.py --batch-targets targets.txt

# CI/CD mode
python ios_scan.py --ipa MyApp.ipa --ci-mode --fail-on-critical
```

### API Server

```bash
# Start API server
python -m uvicorn core.api.server:app --host 127.0.0.1 --port 8089

# Start a scan via API
curl -X POST http://127.0.0.1:8089/api/scans/start \
  -H "Content-Type: application/json" \
  -d '{"ipa_path": "/path/to/MyApp.ipa", "options": {"profile": "standard", "mode": "safe"}}'
```

---

## Scan Profiles

| Profile | Plugins | Use Case |
|---------|---------|----------|
| `lightning` | 8 | Fast CI checks |
| `fast` | 12 | Regular testing |
| `standard` | 16 | Production scans (default) |
| `deep` | 20 | Full security audit |

---

## iOS Tools Used

| Android (AODS) | iOS (IODS) |
|----------------|------------|
| JADX | class-dump / jtool2 |
| APKTool | unzip + plutil |
| ADB | ideviceinfo / ideviceinstaller |
| aapt | codesign + plutil |
| apksigner | codesign -dv |
| Frida (Android) | Frida (iOS, jailbroken) |

---

## Environment Variables

| Variable | Default | Purpose |
|---------|---------|---------|
| `IODS_DISABLE_ML` | `0` | Disable ML pipeline |
| `IODS_RESOURCE_SAFE` | `0` | Conservative resource usage (WSL/CI) |
| `IODS_STATIC_ONLY` | `0` | Skip dynamic analysis |
| `IODS_APP_PROFILE` | `production` | `production\|vulnerable` |
| `IODS_ML_FP_THRESHOLD` | `0.15` | Override ML FP threshold |
| `IODS_MAX_EXTERNAL_PROCS` | `2` | Cap on concurrent tool processes |
| `IODS_TOOL_EXECUTOR_THREADS` | `4` | Thread pool size |
| `IODS_PARALLEL_WORKERS` | `2` | Plugin parallel workers |

---

## Architecture

```
ios_scan.py              → Entry point (thin, ~100 lines)
core/
  ipa/
    ipa_context.py       → IPAContext (session object)
    ipa_extractor.py     → IPA extraction + tool invocation
    ipa_analyzer.py      → Analysis coordination
  plugins/
    base_plugin_ios.py   → BasePluginIOS (abstract base)
    ios_plugin_manager.py → Discovery, selection, execution
  cli/
    arg_parser.py        → CLI arguments
    execution.py         → run_main() orchestrator
    execution_standard.py → Sequential scan pipeline
    output_manager.py    → Rich console output
  evre/                  → Enhanced Vulnerability Reporting Engine (9 mixins)
  ml/                    → 3-stage ML FP reduction pipeline
  api/                   → FastAPI REST server + RBAC
plugins/                 → 20 iOS security analyzer plugins
config/                  → YAML/JSON configuration files
```

---

## Plugins

| Plugin | Checks |
|--------|--------|
| `binary_security_analyzer` | PIE, ASLR, Stack Canary, ARC, symbols |
| `ats_analyzer` | NSAllowsArbitraryLoads, exception domains, TLS versions |
| `keychain_analyzer` | kSecAttrAccessibleAlways, access groups |
| `entitlements_analyzer` | get-task-allow, private entitlements |
| `code_signing_analyzer` | Signing cert, debug provisioning profile |
| `cryptography_analyzer` | DES, MD5, ECB mode, hardcoded keys |
| `data_storage_analyzer` | NSUserDefaults, SQLite, NSFileProtectionNone |
| `network_security_analyzer` | SSL bypass, cleartext HTTP |
| `webview_analyzer` | UIWebView, JS bridge, file:// access |
| `url_scheme_analyzer` | Custom URL schemes, Universal Links |
| `privacy_analyzer` | NSUsageDescription keys, permissions |
| `logging_analyzer` | NSLog with sensitive data |
| `clipboard_analyzer` | UIPasteboard misuse |
| `jailbreak_detection_analyzer` | Missing jailbreak detection |
| `anti_debugging_analyzer` | PT_DENY_ATTACH, sysctl checks |
| `hardcoded_secrets_analyzer` | API keys, tokens, entropy analysis |
| `swift_objc_patterns_analyzer` | sprintf, strcpy, format strings |
| `third_party_library_analyzer` | Vulnerable SDK versions |
| `cert_pinning_analyzer` | Certificate pinning implementation |
| `dynamic_analysis_modules` | Frida: keychain, network, crypto hooks |

---

## MASVS Coverage

IODS maps findings to OWASP MASVS v2 controls:
- MASVS-STORAGE-1/2/3
- MASVS-CRYPTO-1
- MASVS-NETWORK-1/2
- MASVS-PLATFORM-1/2/3
- MASVS-CODE-4
- MASVS-RESILIENCE-1/2/3/4
- MASVS-PRIVACY-1
- MASVS-SUPPLY-CHAIN-1

---

## License

MIT License
