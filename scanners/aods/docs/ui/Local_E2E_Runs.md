## UI Local E2E Runs (Dev and Prod Shell)

This guide documents how to run the React UI Playwright E2E tests locally in both dev shell (Vite dev server) and prod shell. You can run prod-shell tests either via the Vite preview at `/ui` or (recommended) via the API-served UI at `/ui` for zero‑skip assertions.

### Why this matters
- **Developer loop speed**: Single-command runs start the right server, wait until ready, and execute deterministic specs. This reduces friction and catches regressions early.
- **Parity with CI**: The prod-shell run verifies the production build and base path (`/ui`) behavior that the dev server does not exercise, preventing routing and asset path regressions.
- **Policy verification**: CI toggles (e.g., `failOnHigh`, `dedupStrict`) persist and are honored when explicit env vars are not set, matching the unified config model.

### Prerequisites
- From `design/ui/react-app`:
  - Install deps: `npm ci`
  - Install browsers: `npx playwright install` (add `--with-deps` if system libs are missing)
- Python venv is not required for UI-only E2E, but if you also start the API locally, activate `aods_venv` first.

### Scripts
All scripts live under `design/ui/react-app/package.json` → `scripts`.

- `e2e:dev-local`
  - Starts Vite dev server on `http://127.0.0.1:5088`, waits for readiness, runs all Playwright specs with `UI_URL=http://127.0.0.1:5088` and `--workers=1` for determinism.
  - Use when iterating quickly or validating mocked/stubbed flows.

- `e2e:prod-local:dashboard`
  - Builds the UI and serves it at `http://127.0.0.1:8088/ui` (Vite preview), then runs the targeted dashboard prod spec against `UI_URL=http://127.0.0.1:8088/ui`.
  - Use to verify production build paths/base and dashboard deltas behavior under prod shell.

- `e2e:prod-local:ci-toggles`
  - Builds and serves at `/ui` like above, then executes the CI Toggles spec to ensure toggles persist and survive reload.
  - Use to validate CI policy toggles via the `ToolsStatus` page without a live backend (API calls are stubbed in the test).

- `test:e2e:prod:api`
  - Runs the full prod-shell suite against the API-served UI at `/ui`, avoiding the preview server. Requires services started and a production build available for the API to serve.
  - Zero‑skip flow when the API is running: `./scripts/start_services.sh start && cd design/ui/react-app && npm run build -- --base /ui && npm run test:e2e:prod:api`

### Usage
Run from the repo root or from `design/ui/react-app`:

```bash
cd design/ui/react-app
npm run e2e:dev-local
npm run e2e:prod-local:dashboard
npm run e2e:prod-local:ci-toggles
# Full prod suite (API-served UI, zero skips)
npm run test:e2e:prod:api
```

Override the target URL (rarely needed) by setting `UI_URL`:

```bash
UI_URL=http://127.0.0.1:5088 npx playwright test --workers=1
```

### Reports
- The default reporter is `line`. To generate an HTML report on demand:

```bash
UI_URL=http://127.0.0.1:8088/ui npx playwright test --reporter=html --output=playwright-report-local --workers=1
```

### Mapping to CI Quality Gates
- Dev shell smoke and targeted specs correspond to the CI gates in `docs/ci/gates_catalog.md`:
  - UI: Playwright E2E (Dev Shell)
  - UI: Targeted E2E Gate (Dev, Strict)
  - UI: Playwright E2E (Prod Shell at /ui)
  - UI: CI Toggles E2E (Prod UI)

Running these locally gives you early signal on the same surfaces CI enforces, reducing back-and-forth during reviews.

### Troubleshooting
- Port busy errors: Ensure `5088` (dev) or `8088` (preview) are free; kill previous preview with `pkill -f vite` if necessary.
- `UI not reachable`: Tests skip when the server is down. Confirm the readiness check URL matches the script (`http://127.0.0.1:5088` or `/ui`).
- `404` on `/api/*`: Local E2E specs stub backend endpoints; if you run custom specs that need a live API, start it separately and point tests via `UI_URL`.
- Headless stability: Specs run with `--workers=1` to avoid flakiness. Keep it that way for smoke and gate parity.

### Related
- CI gates catalog: see `docs/ci/gates_catalog.md` (sections for Dev/Prod UI E2E and CI Toggles).





