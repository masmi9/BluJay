# AODS Quick Start Guide
## Get Started in 5 Minutes

### Quick Installation

```bash
# 1. Clone and setup
git clone https://github.com/ondefend/aods.git
cd aods
python3 -m venv aods_venv
source aods_venv/bin/activate
pip install -r requirements/base.txt

# 2. Set up Git LFS (required for ML models)
git lfs install && git lfs pull

# 3. Run your first scan
python dyna.py --apk /path/to/your/app.apk --mode safe --formats json html

# 4. View results
ls reports/
```

### Basic Usage

#### Quick Security Scan (lightning profile, ~30 seconds)
```bash
python dyna.py --apk myapp.apk --mode safe
```

#### Full Scan with ML Enhancement
```bash
python dyna.py --apk myapp.apk --mode deep --formats json html
```

#### Static Analysis Only (no device needed)
```bash
python dyna.py --apk myapp.apk --static-only --formats json
```

#### With AI Agent Analysis (optional, requires LLM API key)
```bash
AODS_AGENT_ENABLED=1 AODS_AGENT_PROVIDER=anthropic \
python dyna.py --apk myapp.apk --mode deep --agent-pipeline
```

### Understanding Results

#### JSON Reports
- Programmatic access via `reports/aods_<package>_<timestamp>.json`
- Structured findings with severity, confidence, CWE, MASVS mapping
- Integrate with other security tools or build custom reporting

#### HTML Reports
```bash
python dyna.py --apk app.apk --formats html
xdg-open reports/aods_*.html
```
- Interactive severity filtering and sorting
- Expandable finding details with code snippets
- Summary charts showing severity distribution

### Key Features

- **66 Security Plugins**: Vulnerability detection across OWASP MASVS categories
- **4 Scan Profiles**: Lightning (~30s), Fast (2-3min), Standard (5-8min), Deep (15+min)
- **ML-Enhanced Confidence**: False positive reduction with confidence scoring and explainability
- **AI Agent System**: 6 specialized agents for triage, verification, orchestration, remediation, and narration
- **33-Page Web UI**: React 18 + TypeScript + MUI dashboard
- **RBAC**: 5 roles (admin, analyst, viewer, auditor, api_user) with ownership enforcement
- **Real-time Streaming**: SSE progress streams with reconnection support
- **Evidence Collection**: Automated code snippets, line numbers, and file paths
- **Compliance Mapping**: OWASP MASVS, NIST, CWE, ISO 27001/27002

### Common Commands

```bash
# Help and version
python dyna.py --help

# Specific output directory
python dyna.py --apk app.apk --output reports/my_scan.json --formats json html

# Verbose output for debugging
python dyna.py --apk app.apk --verbose --formats json html

# Disable ML for faster scans
python dyna.py --apk app.apk --disable-ml --profile lightning

# Vulnerable app mode (for DIVA, InsecureBankv2, etc.)
python dyna.py --apk DIVA.apk --vulnerable-app-mode
```

### Start the Web UI

```bash
# Start API + UI manually
source aods_venv/bin/activate
AODS_ADMIN_PASSWORD=admin uvicorn core.api.server:app --host 127.0.0.1 --port 8088 --workers 1 &
cd design/ui/react-app && npm ci && npm run dev &

# Login at http://localhost:5088 with admin/admin
```

### Next Steps

1. **Read the User Guide**: [docs/USER_GUIDE.md](../USER_GUIDE.md) (17 sections)
2. **RBAC Guide**: [docs/security/RBAC_GUIDE.md](../security/RBAC_GUIDE.md) for access control details
3. **Agent System**: Set `AODS_AGENT_ENABLED=1` and configure an LLM provider
4. **CI/CD Integration**: Use `--ci-mode --fail-on-critical` in pipelines
5. **Customize Configuration**: Edit `config/vulnerability_patterns.yaml`

### UI E2E Modes

```bash
cd design/ui/react-app

# Stubbed E2E tests (mock data, no API needed)
npm run test:e2e:stubbed

# Production build tests (starts mock server)
npm run test:e2e:prod

# Jest unit tests
npm test
```

### Versions and Environment

- Python: 3.10+ (recommended 3.11)
- Node.js: 18+ (recommended 20.x)
- Virtual environment: must be named `aods_venv`
- OS: Linux/WSL2/macOS

---

For more details, see the [User Guide](../USER_GUIDE.md).
