## Frida API

### GET /frida/health
- Roles: `admin`, `analyst`
- Query params:
  - `forwardPort` (int, default 27042): Local forwarded port to probe
- Response JSON (keys may be absent when unknown):
  - `portOpen` (bool)
  - `pid` (int|null)
  - `clientVersion` (string|null)
  - `serverVersion` (string|null)
  - `binding` (string|null)
  - `executionMode` ("static"|"dynamic"|"unknown")
  - `dynamicAllowed` (bool)
  - `determinism`: { `status`: "ok"|"fail"|"unknown", `updatedAt`: iso8601|null }
  - `calibration`: { `status`: "ok"|"fail"|"stale"|"missing"|"unknown", `ece_after`: number|null, `mce_after`: number|null, `updatedAt`: iso8601|null }
  - `lastProbeTs` (iso8601)

Notes:
- Calibration thresholds are controlled via env: `AODS_ML_MAX_ECE` (default 0.1), `AODS_ML_MAX_MCE` (default 0.2).
- Staleness uses `AODS_ML_CALIBRATION_STALE_TTL_SEC` (default 604800 seconds).

### Static-only policy
When `AODS_STATIC_ONLY_HARD=1`:
- POST `/frida/ws-token` → 409 (denied in static-only hard mode)
- POST `/frida/attach` → 409
- POST `/frida/corellium/connect` → 409
- POST `/frida/corellium/ensure` → 409
- WebSocket `/frida/ws` closes immediately (policy)
- UI disables dynamic controls and prevents WS/SSE connections

Read-only endpoints remain available:
- GET `/frida/health`
- GET `/frida/devices`
- GET `/frida/devices/{device_id}/processes`



