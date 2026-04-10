# AODS Documentation Index

**Last Updated**: 2026-03-10

---

## Tracking & Roadmap

Roadmap and tracking documents are maintained on the `dev` branch in the `roadmap/` directory.

---

## User Guides

| Document | Purpose |
|----------|---------|
| [USER_GUIDE.md](docs/USER_GUIDE.md) | user guide (17 sections) |
| [QUICK_START_GUIDE.md](docs/reference/QUICK_START_GUIDE.md) | 5-minute getting started |
| [RBAC_GUIDE.md](docs/security/RBAC_GUIDE.md) | Role-based access control guide |
| [Frida Console HowTo](docs/ui/Frida_Console_HowTo.md) | Frida console usage |
| [Local E2E Runs](docs/ui/Local_E2E_Runs.md) | Running E2E tests locally |

---

## Reference Documents

**Location**: `docs/reference/`

| Document | Purpose |
|----------|---------|
| [API_REFERENCE.md](docs/reference/API_REFERENCE.md) | REST API documentation |
| [SYSTEM_ARCHITECTURE.md](docs/reference/SYSTEM_ARCHITECTURE.md) | Architecture overview |
| [MITRE_INTEGRATION_GUIDE.md](docs/reference/MITRE_INTEGRATION_GUIDE.md) | MITRE integration |
| [QUICK_REFERENCE.md](docs/reference/QUICK_REFERENCE.md) | Quick reference card |

---

## Security & Operations

| Document | Purpose |
|----------|---------|
| [RBAC_GUIDE.md](docs/security/RBAC_GUIDE.md) | RBAC roles, permissions, auth flow |
| [OWASP_ADHERENCE.md](docs/SECURITY/OWASP_ADHERENCE.md) | OWASP compliance documentation |
| [FEATURE_FLAG_REGISTRY.md](docs/operations/FEATURE_FLAG_REGISTRY.md) | Feature flags reference |
| [SLOS_AND_SLIS.md](docs/operations/SLOS_AND_SLIS.md) | Service level objectives |
| [DOCKER_TROUBLESHOOTING.md](docs/operations/DOCKER_TROUBLESHOOTING.md) | Docker troubleshooting |
| [ROLLBACK_PROCEDURES.md](docs/operations/ROLLBACK_PROCEDURES.md) | Rollback procedures |

---

## Development Guides

| Document | Purpose |
|----------|---------|
| [README.md](README.md) | Project overview |
| [PLUGIN_DEVELOPMENT.md](docs/development/PLUGIN_DEVELOPMENT.md) | Plugin development guide |
| [base_plugin_v2.md](docs/plugins/base_plugin_v2.md) | BasePluginV2 reference |
| [CI_TESTING_GUIDE.md](docs/ci/CI_TESTING_GUIDE.md) | CI testing guide |

---

## CI & Quality Gates

| Document | Purpose |
|----------|---------|
| [gates_catalog.md](docs/ci/gates_catalog.md) | Quality gates catalog |
| [gates_runbooks.md](docs/ci/gates_runbooks.md) | Gates runbooks |
| [gates_thresholds.md](docs/ci/gates_thresholds.md) | Gates thresholds |

---

## Directory Structure

```
docs/
├── tracking/           <- Migration and pattern fix tracking
│   ├── PLUGIN_MIGRATION_PLAN.md
│   ├── VULNERABILITY_PATTERNS_FIXES.md
│   └── README.md
│
├── reference/          <- REFERENCE: Consult as needed
│   ├── API_REFERENCE.md
│   ├── SYSTEM_ARCHITECTURE.md
│   ├── MITRE_INTEGRATION_GUIDE.md
│   ├── QUICK_REFERENCE.md
│   └── QUICK_START_GUIDE.md
│
├── security/           <- Security docs
│   └── RBAC_GUIDE.md
│
├── ui/                 <- UI documentation
│   ├── Frida_Console_HowTo.md
│   └── Local_E2E_Runs.md
│
├── operations/         <- Operations docs
│   ├── FEATURE_FLAG_REGISTRY.md
│   ├── SLOS_AND_SLIS.md
│   ├── DOCKER_TROUBLESHOOTING.md
│   └── ROLLBACK_PROCEDURES.md
│
├── ci/                 <- CI documentation
│   ├── gates_catalog.md
│   ├── gates_runbooks.md
│   ├── gates_thresholds.md
│   └── ...
│
└── development/        <- Plugin and developer guides
    └── PLUGIN_DEVELOPMENT.md
```

---

## Quick Commands

```bash
# Activate venv (IMPORTANT: must use aods_venv, not .venv)
source aods_venv/bin/activate

# Run Python tests
pytest tests/unit/ -v

# Run React E2E tests
cd design/ui/react-app && npm run test:e2e:stubbed

# Run React unit tests
cd design/ui/react-app && npm test

# Start API + UI
./scripts/start_services.sh --install

# Train ML models
python scripts/train_models.py --all

# Start with agent system enabled
AODS_AGENT_ENABLED=1 AODS_AGENT_PROVIDER=anthropic \
  uvicorn core.api.server:app --host 0.0.0.0 --port 8088 --workers 1
```
