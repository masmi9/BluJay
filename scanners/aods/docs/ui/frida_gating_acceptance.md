## Frida Gating - Acceptance Criteria

This checklist verifies backend and UI behavior for static-only enforcement and health exposure.

### Backend (FastAPI)
- /frida/health returns:
  - executionMode ("static"|"dynamic"|"unknown") and dynamicAllowed (bool)
  - determinism: { status: "ok"|"fail"|"unknown", updatedAt?: iso8601 }
  - calibration: { status: "ok"|"fail"|"stale"|"missing"|"unknown", ece_after?: number|null, mce_after?: number|null, updatedAt?: iso8601|null }
  - lastProbeTs (iso8601)
  - Honors env: AODS_ML_MAX_ECE, AODS_ML_MAX_MCE, AODS_ML_CALIBRATION_SUMMARY, AODS_ML_CALIBRATION_STALE_TTL_SEC
- Static-only hard mode (AODS_STATIC_ONLY_HARD=1):
  - POST /frida/ws-token → HTTP 409
  - POST /frida/attach → HTTP 409
  - POST /frida/corellium/connect → HTTP 409
  - POST /frida/corellium/ensure → HTTP 409
  - WebSocket /frida/ws closes immediately (policy)
- Tests:
  - Unit: tests/unit/api/test_frida_health_and_gating.py

### UI (Frida Console)
- Chips in header reflect:
  - Mode chip shows Static or Dynamic
  - Determinism and Calibration status chips (color-coded)
- Static-only UI gating:
  - Connect WS, Ensure (ADB+Frida), Corellium Connect, Attach to package are disabled
  - Read-only actions (Refresh health, Devices list, Processes list) remain enabled
  - Friendly error messaging on policy blocks (HTTP 409)
- Calls to /frida/* go through secureFetch
- SSE/WS do not initialize in static-only
- A11Y basics: labels on interactive controls; no horizontal overflow at 1280px
- Tests:
  - Playwright: design/ui/react-app/tests/frida.static_only.spec.ts
  - Playwright: design/ui/react-app/tests/frida.static_only_readonly.spec.ts
  - Playwright (broader flows): design/ui/react-app/tests/frida.phases.spec.ts
  - Unit: design/ui/react-app/src/pages/__tests__/fridaConsole.secureFetch.test.tsx

### Docs/Toggles
- API doc: docs/api/frida.md documents /frida/health schema and static-only behavior
- CI Toggles: docs/ci/toggles.md includes AODS_ML_CALIBRATION_STALE_TTL_SEC
- Gates catalog: docs/ci/gates_catalog.md includes Calibration Quality Gate and staleness note

### How to Validate Quickly (local)
1) Unit tests (backend): `pytest -q tests/unit/api/test_frida_health_and_gating.py`
2) UI unit test: from design/ui/react-app, `npm test -- --testPathPattern=fridaConsole.secureFetch.test.tsx`
3) E2E tests: from design/ui/react-app, `UI_URL=http://127.0.0.1:5088 npx playwright test -g "static-only"`





