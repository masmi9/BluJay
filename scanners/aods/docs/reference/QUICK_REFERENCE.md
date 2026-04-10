# AODS Quick Reference

## Quick Commands

### APK Analysis
```bash
python dyna.py --apk app.apk --mode safe                         # Quick analysis
python dyna.py --apk app.apk --mode deep --profile standard      # Full analysis
python dyna.py --apk app.apk --mode agent --profile deep         # Agent-assisted (LLM)
python dyna.py --apk app.apk --static-only --formats json html   # Static only
python dyna.py --apk app.apk --agent-triage --agent-remediate    # With specific agents
python dyna.py --apk app.apk --agent-pipeline                    # Full agent pipeline
```

### Services
```bash
python -m uvicorn core.api.server:app --host 127.0.0.1 --port 8088 --no-access-log
cd design/ui/react-app && npm run dev
./scripts/start_services.sh --install   # Auto-start both
```

### Testing
```bash
pytest tests/unit/ -v                                  # Python unit tests
PYTHONPATH=. pytest -q tests/api --maxfail=1           # API integration tests
make baseline-suite                                    # ML baseline & smoke tests
make precommit                                         # Pre-commit checks

cd design/ui/react-app
npm run test                                           # Jest unit tests
npm run test:e2e                                       # Playwright E2E (all)
npm run test:e2e:stubbed                               # E2E with mocked data
npm run test:e2e:prod                                  # Production build + mock server
```

### Linting
```bash
flake8 core/ plugins/ --max-line-length=120
black core/ plugins/ --line-length=120 --check
cd design/ui/react-app && npx tsc --noEmit
```

---

## Scan Profiles

| Profile | Plugins | Workers | Timeout | Use Case |
|---------|---------|---------|---------|----------|
| `lightning` | 12 | 2 | 30s | Quick CI checks (~30s); multiprocess mode on by default |
| `fast` | 18 | auto | 60s | Regular testing (~2-3 min) |
| `standard` | 43 | auto | 240s | Production scans (~5-8 min) |
| `deep` | 48 | auto | 300s | Security audits (~15+ min) |

Set profile: `--profile standard` or `AODS_SCAN_PROFILE=standard`

---

## Key Environment Variables

### Auth / RBAC
| Variable | Default | Notes |
|----------|---------|-------|
| `AODS_ADMIN_PASSWORD` | *random* | Set explicitly for dev/E2E |
| `AODS_ANALYST_PASSWORD` | *random* | Set explicitly for dev/E2E |
| `AODS_VIEWER_PASSWORD` | *random* | Set explicitly for dev/E2E |
| `AODS_JWT_SECRET` | *generated* | Auto-generated if unset |
| `AODS_JWT_EXPIRY_HOURS` | `24` | Token lifetime |

### Scan Config
| Variable | Default | Notes |
|----------|---------|-------|
| `AODS_SCAN_PROFILE` | `standard` | lightning / fast / standard / deep |
| `AODS_DISABLE_ML` | `0` | Set `1` to skip all ML processing |
| `AODS_ML_FP_THRESHOLD` | `0.15` | FP filtering threshold |
| `AODS_ML_ENABLE_CALIBRATION` | `1` | Probability calibration |
| `AODS_APP_PROFILE` | - | `production` or `vulnerable` |
| `AODS_PLUGIN_MULTIPROCESS` | `auto` | `1`=hard-kill processes, `0`=threading |

### Resource Tuning
| Variable | Default | Notes |
|----------|---------|-------|
| `AODS_MAX_EXTERNAL_PROCS` | `2` | Concurrent external tool cap |
| `AODS_TOOL_EXECUTOR_THREADS` | `4` | Executor thread pool |
| `AODS_RESOURCE_SAFE` | `0` | `1` forces lightning profile + disables ML |

### Agent System
| Variable | Default | Notes |
|----------|---------|-------|
| `AODS_AGENT_ENABLED` | `0` | Enable all agent types |
| `AODS_AGENT_PROVIDER` | `anthropic` | `anthropic` / `openai` / `ollama` |
| `AODS_AGENT_API_KEY_ENV` | - | Env var name holding the API key |
| `AODS_AGENT_MODEL` | - | Provider-specific model override |
| `AODS_AGENT_MAX_ITERATIONS` | `10` | Agent loop iteration cap |
| `AODS_AGENT_COST_LIMIT` | - | Token budget for pipeline |

### Vector DB (ChromaDB)
| Variable | Default | Notes |
|----------|---------|-------|
| `AODS_VECTOR_DB_ENABLED` | `0` | Enable ChromaDB; use `--workers 1` only |
| `AODS_VECTOR_DB_PATH` | `data/vector_index/` | Storage path |
| `AODS_EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | Sentence-transformer model |

### Logging
| Variable | Default | Notes |
|----------|---------|-------|
| `AODS_LOG_FORMAT` | `auto` | `json` / `console` / `auto` (TTY detect) |
| `AODS_LOG_LEVEL` | `INFO` | DEBUG / INFO / WARNING / ERROR |

---

## Architecture at a Glance

```
dyna.py (~200 lines, shim)
  └─> core/cli/ (17 modules, ~9.5K lines)
        ├─ startup.py      MITRE check, venv, ML env
        ├─ execution.py    orchestrates plugin runs
        ├─ scanner.py      AODSScanner class
        └─ ...arg_parser, feature_flags, finding_processing, utilities, ...

  Plugin execution: 66 v2 analyzers (plugins/), semaphore-gated, timeout-protected
  ML post-processing: calibration -> CanonicalFPReducer -> explainability
  Reports: JSON, HTML, CSV, TXT (UnifiedReportingManager hot path)

API:   core/api/server.py + core/api/routes/ (9 route modules)
UI:    design/ui/react-app/ - React 18 + TypeScript + Vite + MUI - 33 pages
Agent: core/agent/ - 6 agents + supervisor (optional, AODS_AGENT_ENABLED=0)
VecDB: core/vector_db/ - ChromaDB, single-worker only
```

---

## API Endpoints Quick List

### Auth
| Method | Path | Min Role |
|--------|------|----------|
| POST | `/auth/login` | - |
| GET | `/auth/me` | any |

### Scans
| Method | Path | Min Role |
|--------|------|----------|
| POST | `/api/scans` | analyst |
| GET | `/api/scans/{id}/progress` | viewer |
| GET | `/api/scans/{id}/results` | viewer |
| GET | `/api/scans/{id}/progress/stream` | viewer (SSE) |
| GET | `/api/scans/{id}/logs/stream` | viewer (SSE) |
| GET | `/api/batch/{id}/status/stream` | viewer (SSE) |

### ML / Explainability
| Method | Path | Min Role |
|--------|------|----------|
| GET | `/api/explain/status` | viewer |
| POST | `/api/explain/finding` | analyst |
| GET | `/api/ml/analytics/summary` | viewer |
| POST | `/api/ml/training/run_calibration` | admin |

### Agent
| Method | Path | Min Role |
|--------|------|----------|
| POST | `/api/agent/triage` | analyst |
| POST | `/api/agent/remediate` | analyst |
| POST | `/api/agent/narrate` | analyst |
| POST | `/api/agent/verify` | analyst |
| POST | `/api/agent/orchestrate` | analyst |
| POST | `/api/agent/pipeline` | analyst |
| POST | `/api/agent/triage/feedback` | analyst |
| GET | `/api/agent/triage/feedback/history` | viewer |
| GET | `/api/agent/stats` | viewer |

### Vector Search
| Method | Path | Min Role |
|--------|------|----------|
| POST | `/api/vector/findings/similar` | viewer |
| GET | `/api/vector/index/status` | viewer |
| POST | `/api/vector/index/rebuild` | admin |
| DELETE | `/api/vector/index/scan/{id}` | admin |

### Admin
| Method | Path | Min Role |
|--------|------|----------|
| GET | `/admin/users` | admin |
| GET | `/admin/roles` | admin |
| PUT | `/admin/users/{username}/role` | admin |

### Frida / WebSocket
| Method | Path | Min Role |
|--------|------|----------|
| GET | `/api/frida/ws-token` | analyst |
| WS | `/api/frida/ws` | analyst |

### Health
| Method | Path | Min Role |
|--------|------|----------|
| GET | `/api/health` | - |
| GET | `/api/health/ml` | viewer |
| GET | `/api/health/plugins` | viewer |
| GET | `/api/health/scan` | viewer |
| GET | `/api/tools/status` | viewer |
| GET | `/api/audit/events` | auditor |

---

## Common Configuration Recipes

### CI / Automated Pipeline
```bash
export AODS_SCAN_PROFILE=lightning
export AODS_RESOURCE_SAFE=1
export AODS_LOG_FORMAT=json
python dyna.py --apk build/app.apk --formats json --static-only
```

### Development (local)
```bash
export AODS_ADMIN_PASSWORD=admin AODS_ANALYST_PASSWORD=analyst AODS_VIEWER_PASSWORD=viewer
export AODS_LOG_FORMAT=console AODS_LOG_LEVEL=DEBUG
python -m uvicorn core.api.server:app --host 127.0.0.1 --port 8088 --no-access-log
```

### Static Analysis Only
```bash
python dyna.py --apk app.apk --static-only --formats json html --profile standard
```

### Resource-Constrained (WSL / low-memory)
```bash
export AODS_RESOURCE_SAFE=1          # Forces lightning profile, disables ML
export AODS_MAX_EXTERNAL_PROCS=1
export AODS_TOOL_EXECUTOR_THREADS=1
export AODS_MAX_WORKERS=1
```

### Agent Pipeline (with LLM)
```bash
export AODS_AGENT_ENABLED=1
export AODS_AGENT_PROVIDER=anthropic
export ANTHROPIC_API_KEY=<key>
export AODS_AGENT_API_KEY_ENV=ANTHROPIC_API_KEY
python dyna.py --apk app.apk --mode agent --profile deep
```

---

## Key File Locations

**Backend Core**
| Purpose | Location |
|---------|----------|
| Main entry point | `dyna.py` (shim) -> `core/cli/` (17 modules) |
| Analysis context | `core/apk_ctx.py` |
| Scan profiles | `core/scan_profiles.py` |
| Structured logging | `core/logging_config.py` |
| Vulnerability patterns | `config/vulnerability_patterns.yaml` |

**Plugins & Reporting**
| Purpose | Location |
|---------|----------|
| Plugin base class | `core/plugins/base_plugin_v2.py` |
| Plugin manager (canonical import) | `core/plugins/__init__.py` |
| Deduplication framework | `core/unified_deduplication_framework/` |
| Reporting manager (hot path) | `core/reporting/unified_reporting_manager.py` |
| Final report serializer | `core/reporting/final_report_serializer.py` |
| EVRE (vulnerability reporting) | `core/evre/` (13 mixins); shim at `core/enhanced_vulnerability_reporting_engine.py` |
| FP reducer (CLI path) | `core/fp_reducer.py` (CanonicalFPReducer) |

**API Layer**
| Purpose | Location |
|---------|----------|
| API server | `core/api/server.py` |
| Route modules | `core/api/routes/` (scans, frida, ml, dev, vector_search, agent, admin) |
| Shared state | `core/api/shared_state.py` |
| Auth helpers | `core/api/auth_helpers.py` |
| RBAC manager | `core/enterprise/rbac_manager.py` |
| Request logging middleware | `core/api/middleware/request_logging.py` |

**Agent System**
| Purpose | Location |
|---------|----------|
| Agent modules | `core/agent/` (narration, verification, orchestration, triage, remediation, supervisor) |
| LLM providers | `core/agent/providers/` (Anthropic, OpenAI, Ollama) |
| Heuristic fallbacks | `core/agent/triage_heuristic.py`, `core/agent/remediation_heuristic.py` |
| Agent config | `config/agent_config.yaml` |
| Agent API routes | `core/api/routes/agent.py` |

**ML & Vector DB**
| Purpose | Location |
|---------|----------|
| ML config | `config/ml_config.json` |
| ML pipeline (API path) | `core/unified_ml_pipeline.py` |
| Explainability facade | `core/ml/explainability_facade.py` |
| Vector DB | `core/vector_db/` |
| Trained models | `models/` (vulnerability_detection/, false_positive/, calibration/, ...) |

**React Frontend**
| Purpose | Location |
|---------|----------|
| App entry | `design/ui/react-app/src/main.tsx` |
| API client | `design/ui/react-app/src/services/api.ts` |
| SSE reconnection hook | `design/ui/react-app/src/hooks/useSseStream.ts` |
| Auth context / RequireRoles | `design/ui/react-app/src/context/AuthContext.tsx` |
| E2E tests | `design/ui/react-app/tests/` |
| E2E auth helper | `design/ui/react-app/tests/helpers/auth.ts` |
| E2E mock server | `design/ui/react-app/scripts/preview_mock.cjs` |

**CI & Quality** (dev branch only)
| Purpose | Location |
|---------|----------|
| Semgrep MASVS/CWE rules | `compliance/semgrep_rules/` |
| Quality gate scripts | `tools/ci/gates/` |
| CI workflows | `.github/workflows/` |
