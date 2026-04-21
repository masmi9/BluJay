# AODS CI Testing Guide

This guide covers running tests locally and understanding the CI workflow for AODS.

## Test Categories

AODS has several categories of tests:

| Category | Location | Framework | Purpose |
|----------|----------|-----------|---------|
| API Tests | `tests/api/` | pytest | Backend API endpoint testing |
| Unit Tests | `tests/unit/` | pytest | Core module unit tests |
| E2E Tests | `design/ui/react-app/tests/` | Playwright | End-to-end UI testing |
| UI Unit Tests | `design/ui/react-app/src/**/__tests__/` | Jest | React component tests |
| Accessibility | via npm scripts | axe-core | A11y compliance |

## Running Tests Locally

### Prerequisites

```bash
# Activate the Python virtual environment
source aods_venv/bin/activate

# Install Node.js dependencies (for UI tests)
cd design/ui/react-app && npm install
```

### API Tests (pytest)

```bash
# Run all API tests
cd /path/to/aods
source aods_venv/bin/activate
PYTHONPATH=. pytest tests/api -v

# Run a specific test file
PYTHONPATH=. pytest tests/api/test_rbac_matrix.py -v

# Run a specific test
PYTHONPATH=. pytest tests/api/test_api.py::test_health_ok -v

# Run with coverage
PYTHONPATH=. pytest tests/api --cov=core --cov-report=html

# Run with fail-fast
PYTHONPATH=. pytest tests/api --maxfail=1
```

### Unit Tests (pytest)

```bash
# Run all unit tests
PYTHONPATH=. pytest tests/unit -v

# Run specific module tests
PYTHONPATH=. pytest tests/unit/core/test_logging_config.py -v

# Run with keyword filter
PYTHONPATH=. pytest tests/unit -k "ml" -v
```

### E2E Tests (Playwright)

```bash
cd design/ui/react-app

# Install Playwright browsers (first time only)
npx playwright install --with-deps

# Run all E2E tests
npm run test:e2e

# Run specific test file
npx playwright test tests/dashboard.spec.ts

# Run in headed mode (see browser)
npx playwright test --headed

# Run with HTML report
npm run test:e2e:report

# Run production E2E tests (requires built UI)
npm run test:e2e:prod
```

### UI Unit Tests (Jest)

```bash
cd design/ui/react-app

# Run all Jest tests
npm test

# Run with coverage
npm run coverage

# Run in watch mode
npm test -- --watch
```

### Accessibility Tests

```bash
cd design/ui/react-app

# Run axe-core accessibility audit
# Requires UI_PROD_URL environment variable
UI_PROD_URL=http://127.0.0.1:8088/ui npm run test:a11y

# Run Lighthouse audit
UI_PROD_URL=http://127.0.0.1:8088/ui npm run test:lighthouse
```

## Test Configuration

### Environment Variables for Tests

| Variable | Purpose | Example |
|----------|---------|---------|
| `AODS_ADMIN_PASSWORD` | Admin test password | `test_admin_123` |
| `AODS_ANALYST_PASSWORD` | Analyst test password | `test_analyst_123` |
| `AODS_VIEWER_PASSWORD` | Viewer test password | `test_viewer_123` |
| `PYTHONPATH` | Python module path | `.` |
| `UI_PROD_URL` | URL for E2E/a11y tests | `http://127.0.0.1:8088/ui` |

### pytest Configuration

The `tests/conftest.py` file:
- Sets up test credentials before imports
- Manages `sys.path` to prevent module shadowing
- Provides shared fixtures

### Playwright Configuration

The `design/ui/react-app/playwright.config.ts` file:
- Configures browser options
- Sets base URL for tests
- Defines test timeouts

## CI Workflow

### GitHub Actions

The CI workflow runs on push/PR and includes:

1. **Lint Check** - flake8 and black for Python, tsc for TypeScript
2. **API Tests** - pytest with coverage
3. **Unit Tests** - pytest for core modules
4. **E2E Tests** - Playwright with Chromium
5. **Build Verification** - Vite build for UI

### Local CI Simulation

To run a full CI check locally:

```bash
# Run all checks (recommended before PR)
make precommit

# Or manually:
# 1. Lint
flake8 core/ plugins/ --max-line-length=120
cd design/ui/react-app && npx tsc --noEmit

# 2. API tests
PYTHONPATH=. pytest tests/api -v

# 3. Unit tests
PYTHONPATH=. pytest tests/unit -v

# 4. Build UI
cd design/ui/react-app && npm run build
```

## Test Files Overview

### API Tests (`tests/api/`)

| File | Purpose |
|------|---------|
| `test_api.py` | Core API endpoint tests |
| `test_rbac_matrix.py` | RBAC permission tests (roles, resource ownership) |
| `test_ml_endpoints.py` | ML/explainability endpoint tests |
| `test_recent_scans.py` | Recent scans endpoint tests |
| `test_artifacts_boundaries.py` | Artifact security tests (path traversal, boundaries) |
| `test_package_confirmation.py` | Package confirmation flow tests |
| `test_request_logging.py` | Request logging middleware tests |

### E2E Tests (`design/ui/react-app/tests/`)

| File | Purpose |
|------|---------|
| `dashboard.spec.ts` | Dashboard page tests |
| `results.spec.ts` | Results page tests |
| `newscan.spec.ts` | New scan flow tests |
| `gates.spec.ts` | CI gates page tests |
| `login.spec.ts` | Authentication tests |

## Debugging Failed Tests

### API Test Failures

```bash
# Run with verbose output
PYTHONPATH=. pytest tests/api -v -s

# Run with debugging
PYTHONPATH=. pytest tests/api --pdb

# Check for import issues
python -c "import core.api.server"
```

### E2E Test Failures

```bash
# Run with trace
npx playwright test --trace on

# View trace after failure
npx playwright show-trace trace.zip

# Run in debug mode
PWDEBUG=1 npx playwright test

# Take screenshots on failure (default in config)
npx playwright test --screenshot on
```

### Common Issues

**"Module not found" errors:**
```bash
# Ensure PYTHONPATH is set
export PYTHONPATH=.
```

**"Port already in use" errors:**
```bash
# Kill processes on common ports
lsof -ti:8088 | xargs kill -9
lsof -ti:5088 | xargs kill -9
```

**"Browser not found" (Playwright):**
```bash
npx playwright install chromium --with-deps
```

**Test database conflicts:**
```bash
# Tests use in-memory state; restart services between runs
./scripts/start_services.sh --restart
```

## Writing New Tests

### API Test Template

```python
"""Description of test module."""
from __future__ import annotations
import os

# Set credentials before importing server
os.environ['AODS_ADMIN_PASSWORD'] = 'test_password'

import pytest
from fastapi.testclient import TestClient
import core.api.server as srv

client = TestClient(srv.app)


def test_example():
    """Test description."""
    r = client.get('/api/endpoint')
    assert r.status_code == 200
```

### E2E Test Template

```typescript
import { test, expect } from '@playwright/test';

test.describe('Feature Name', () => {
  test.beforeEach(async ({ page }) => {
    // Setup: login, navigate, etc.
    await page.goto('/');
  });

  test('should do something', async ({ page }) => {
    await expect(page.locator('h1')).toBeVisible();
  });
});
```

## Test Coverage

### Viewing Coverage Reports

```bash
# Generate HTML coverage report
PYTHONPATH=. pytest tests/api --cov=core --cov-report=html

# Open report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

### Coverage Targets

| Module | Target | Current |
|--------|--------|---------|
| `core/api/server.py` | 80% | -- |
| `core/logging_config.py` | 90% | -- |
| `core/enterprise/rbac_manager.py` | 85% | -- |

## Related Documentation

- [RBAC Guide](../security/RBAC_GUIDE.md)
- [API Reference](../api/API_REFERENCE.md)
- [Contributing Guide](../../CONTRIBUTING.md)
