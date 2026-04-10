# AODS Rollback Procedures

**Created:** 2026-01-26
**Scope:** Track 8 - professional Scanner Foundation

---

## Overview

This document provides step-by-step rollback procedures for each major Track 8 feature. All features were introduced as backward-compatible changes with environment variable toggles where applicable.

**General rollback approach:** `git revert <commit>` for any individual feature.

---

## 1. Authentication Hardening (PBKDF2 Password Hashing)

**Commit:** `4d05d7b`
**Files:** `core/api/server.py`

### What Changed
- Replaced placeholder `password == "admin"` with PBKDF2-SHA256 hashing
- Password set via `AODS_ADMIN_PASSWORD` environment variable
- Login endpoint validates against hashed credential

### How to Verify Working
```bash
# Should return 200 with token
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<AODS_ADMIN_PASSWORD value>"}'
```

### How to Revert
```bash
git revert 4d05d7b --no-edit
```

### Risk if Reverted
- Authentication returns to placeholder mode (any password accepted)
- **HIGH RISK** - only revert if auth is completely broken and blocking all access

### Verification After Rollback
```bash
# Login with any password should work again (insecure)
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"anything"}'
```

---

## 2. SSE Endpoint Authentication

**Commit:** `93a1cae`
**Files:** `core/api/server.py`

### What Changed
- All 3 SSE streaming endpoints now require valid JWT token
- Token accepted via `Authorization: Bearer <token>` header or `?token=` query param

### How to Verify Working
```bash
# Without token - should return 401
curl http://localhost:8000/api/stream/scan-progress

# With token - should return SSE stream
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/stream/scan-progress
```

### How to Revert
```bash
git revert 93a1cae --no-edit
```

### Risk if Reverted
- SSE endpoints become unauthenticated (information exposure)
- **MEDIUM RISK** - acceptable temporarily if SSE auth breaks the UI

### Verification After Rollback
```bash
# SSE endpoint should work without auth
curl http://localhost:8000/api/stream/scan-progress
```

---

## 3. RBAC SafeExpressionEvaluator (eval() Replacement)

**Commit:** `5ae9588`
**Files:** `core/enterprise/rbac_manager.py`

### What Changed
- Replaced `eval()` in `PolicyEvaluator` with AST-based `SafeExpressionEvaluator`
- Only allows: literals, comparisons, boolean ops, allowlisted function calls
- Blocks: imports, attribute access, lambdas, comprehensions

### How to Verify Working
```bash
cd /home/kali/PROJECTS/AODS/AODS-feature-ui-rbac-sse-e2e-20260119-061413
source aods_venv/bin/activate
pytest tests/unit/core/enterprise/test_rbac_manager.py -v -k "SafeExpression"
```

### How to Revert
```bash
git revert 5ae9588 --no-edit
```

### Risk if Reverted
- Returns to `eval()` which allows arbitrary code execution in policy expressions
- **HIGH RISK** - only revert if RBAC policies are completely broken

### Verification After Rollback
```bash
pytest tests/unit/core/enterprise/test_rbac_manager.py -v -k "PolicyEvaluator"
```

---

## 4. Parallel Plugin Execution Re-enablement

**Commit:** `0330aa9`
**Files:** `dyna.py`, `core/plugins/unified_manager.py`

### What Changed
- Removed `if False and` dead code gate in `dyna.py`
- Removed forced `batch_size = 1` override in `unified_manager.py`
- Reduced sleep delays: 5.0s → 0.5s (configurable), 3.0s → 0.5s (configurable)
- Fixed `parallel_engine` None reference crash

### How to Verify Working
```bash
# Run scan, should complete in ~60s (not 5+ minutes)
python dyna.py --apk apks/vulnerable_apps/AndroGoat.apk --static-only --testing-mode --formats json
```

### Quick Disable (Without Revert)
```bash
# Force sequential execution with old delays
export AODS_PLUGIN_DELAY=5.0
export AODS_BATCH_DELAY=3.0
```

### How to Revert
```bash
git revert 0330aa9 --no-edit
```

### Risk if Reverted
- Returns to forced sequential execution with 5s delays
- **LOW RISK** - only affects scan speed, not correctness

### Verification After Rollback
```bash
# Scan should still complete (slower)
python dyna.py --apk apks/vulnerable_apps/AndroGoat.apk --static-only --testing-mode --formats json
```

---

## 5. Process-Based Plugin Timeout Enforcement

**Commit:** `b1fce94`
**Files:** `core/plugins/unified_manager.py`

### What Changed
- Added `_execute_plugin_in_process()` method using `multiprocessing.Process`
- Processes can be `terminate()`/`kill()` on timeout (unlike threads)
- Activated via `AODS_ENFORCE_TIMEOUTS=1` environment variable
- Default remains thread-based

### How to Verify Working
```bash
# Enable process-based timeouts
export AODS_ENFORCE_TIMEOUTS=1
python dyna.py --apk apks/vulnerable_apps/AndroGoat.apk --static-only --testing-mode --formats json
```

### Quick Disable (Without Revert)
```bash
# Just don't set the env var (default is thread-based)
unset AODS_ENFORCE_TIMEOUTS
```

### How to Revert
```bash
git revert b1fce94 --no-edit
```

### Risk if Reverted
- Removes process-based timeout option; threads may hang on timeout
- **LOW RISK** - feature is opt-in via env var

### Verification After Rollback
```bash
# Scan should still work (thread-based timeouts only)
python dyna.py --apk apks/vulnerable_apps/AndroGoat.apk --static-only --testing-mode --formats json
```

---

## 6. Health Check Endpoints

**Commit:** `b0e28c2`
**Files:** `core/api/server.py`

### What Changed
- Added `/api/health/ml` - ML models, calibration, FP reducer status
- Added `/api/health/plugins` - plugin discovery count, v2 count
- Added `/api/health/scan` - JADX availability, sessions, reports directory

### How to Verify Working
```bash
curl http://localhost:8000/api/health/ml | python3 -m json.tool
curl http://localhost:8000/api/health/plugins | python3 -m json.tool
curl http://localhost:8000/api/health/scan | python3 -m json.tool
```

### How to Revert
```bash
git revert b0e28c2 --no-edit
```

### Risk if Reverted
- Removes monitoring endpoints; no impact on core functionality
- **VERY LOW RISK** - informational endpoints only

### Verification After Rollback
```bash
# These should now return 404
curl -o /dev/null -w "%{http_code}" http://localhost:8000/api/health/ml
# Existing health endpoint should still work
curl http://localhost:8000/api/health
```

---

## 7. E2E Scan Pipeline Tests

**Commit:** `2dddaec`
**Files:** `tests/e2e/test_scan_pipeline.py`, `tests/e2e/__init__.py`

### What Changed
- Added 12 E2E tests covering CLI scan, API scan, report format, plugin discovery

### How to Verify Working
```bash
pytest tests/e2e/ -m e2e -v
```

### How to Revert
```bash
git revert 2dddaec --no-edit
```

### Risk if Reverted
- Removes test coverage only; no production impact
- **NO RISK** - test files only

---

## 8. Decompilation Path Fix

**Commit:** `71d83a7`
**Files:** `core/apk_ctx.py`, `core/jadx_decompilation_manager.py`

### What Changed
- JADX output directory now propagated to APKContext
- Ensures `AndroidManifest.xml` is accessible to all plugins

### How to Verify Working
```bash
# Scan should not show "AndroidManifest.xml not found" in output
python dyna.py --apk apks/vulnerable_apps/AndroGoat.apk --static-only --testing-mode --formats json 2>&1 | grep -i "manifest.*not found"
# No output = working correctly
```

### How to Revert
```bash
git revert 71d83a7 --no-edit
```

### Risk if Reverted
- Plugins cannot find AndroidManifest.xml; most static analysis fails
- **CRITICAL RISK** - do not revert unless replaced with alternative fix

---

## 9. Static-Only Flag Enforcement

**Commit:** `acb2f46`
**Files:** `core/external/policy.py`, `dyna.py`

### What Changed
- `--static-only` flag now enforced at policy layer
- Blocks Frida/ADB invocations in static-only mode

### How to Verify Working
```bash
# Run with --static-only, verify no ADB/Frida in output
python dyna.py --apk apks/vulnerable_apps/AndroGoat.apk --static-only --testing-mode --formats json 2>&1 | grep -iE "frida|adb"
# No output = working correctly
```

### How to Revert
```bash
git revert acb2f46 --no-edit
```

### Risk if Reverted
- `--static-only` flag becomes advisory (Frida/ADB may still be invoked)
- **MEDIUM RISK** - functional regression for CI environments without devices

---

## Emergency: Full Track 8 Rollback

To revert all Track 8 changes to the pre-Track-8 state:

```bash
# Find the last commit before Track 8 changes
git log --oneline | grep -A1 "ci: add GitHub workflows"
# Reset to that commit (DESTRUCTIVE - creates new commits)
git revert --no-edit b0e28c2..HEAD

# Or reset branch entirely (DESTRUCTIVE - loses history)
# git reset --hard 3969450
```

**Revert order (safest to most risky):**
1. Health check endpoints (`b0e28c2`) - no risk
2. Process timeouts (`b1fce94`) - no risk (opt-in)
3. E2E tests (`2dddaec`) - no risk (tests only)
4. Parallel execution (`0330aa9`) - low risk
5. RBAC evaluator (`5ae9588`) - high risk (security)
6. SSE auth (`93a1cae`) - medium risk (security)
7. Auth hardening (`4d05d7b`) - high risk (security)
8. Static-only enforcement (`acb2f46`) - medium risk
9. Decompilation path (`71d83a7`) - critical risk

---

## Environment Variable Quick Reference

| Variable | Default | Purpose | Safe to Remove |
|----------|---------|---------|----------------|
| `AODS_ADMIN_PASSWORD` | (required) | Admin login password | No |
| `AODS_ENFORCE_TIMEOUTS` | `0` (off) | Process-based timeouts | Yes |
| `AODS_PLUGIN_DELAY` | `0.5` | Delay between plugins (seconds) | Yes |
| `AODS_BATCH_DELAY` | `0.5` | Delay between batches (seconds) | Yes |
| `AODS_SCAN_FOCUSED` | `0` (off) | Skip resource throttling | Yes |
| `AODS_PARALLEL_WORKERS` | auto | Max parallel plugin workers | Yes |
