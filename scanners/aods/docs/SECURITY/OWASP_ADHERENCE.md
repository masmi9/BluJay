# AODS Secure Coding and OWASP Adherence

This document codifies mandatory security standards for AODS. All contributions MUST comply.

Principles
- Input validation and early rejection; explicit content-type checks
- Least privilege and RBAC enforcement on every sensitive endpoint
- No secrets/tokens in URLs (including WebSocket query strings)
- Short-lived, single-use tokens for privileged channels (e.g., WS)
- CSRF protection on state-changing HTTP endpoints (API/UI integration)
- Rate limiting for brute-force/hot paths (WS handshakes, auth)
- Secure defaults (deny by default, explicit allow)
- audit logging with context, no sensitive data exposure
- PII redaction in logs and streaming channels

Implementation Standards
- WebSocket auth
  - Tokens minted via POST by admin only; 5-minute expiry; single-use
  - Passed via Sec-WebSocket-Protocol subprotocol: "aods-frida, token.<value>"
  - Optional Origin allowlist; per-IP handshake rate limiting
- SSE
  - Authorization via token (header or pre-signed param); no PII in messages
- HTTP
  - Strict RBAC checks; mode gating (read_only/standard/advanced)
  - Validate request schemas; reject on malformed payloads
  - Do not return stack traces to clients; log detailed errors server-side

Testing and CI
- Unit tests MUST cover:
  - RBAC and mode gates (deny in read_only, advanced-only actions)
  - WS token single-use and Origin checks
- Severity gating: fail build when high/critical exceed configured limits (AODS_MAX_HIGH, AODS_MAX_CRITICAL)
- E2E tests MUST cover:
  - Auth flows, sign-out clears state, RBAC links visibility
  - SSE/WS smoke without secrets in URLs
  - CSRF headers present on login and state-changing requests
  - PII policy: WS echoes are redacted; scan outputs remain unredacted (forensics)
- CI Security Scans (warn-only by default, can enforce):
  - Python: Bandit (severity high) and Safety
  - UI: npm audit (production, high severity)

Acceptance Criteria (per feature)
- All new endpoints: RBAC, mode checks, input validation, error handling
- No URL tokens; short-lived credentials for real-time channels
- Logs redact PII; structured audit entries are generated
- Unit/E2E tests implemented and passing locally and in CI

Change Management
- Security review is part of PR; CI runs security scans
- Any deviation requires an explicit risk acceptance and follow-up issue



