# Session Handoff - 2026-01-29

## Session Summary

Completed full integration and validation of Semgrep MASTG Analyzer plugin into AODS.

## What Was Accomplished

### Semgrep MASTG Plugin Integration (Track 2) ✅ COMPLETE

Created a new AODS plugin that runs Semgrep with OWASP MASTG security rules on JADX-decompiled Android sources.

**Key Implementation Details:**

1. **MSTG→MASVS Mapping**
   - `MSTGToMASVSMapper` class loads mapping from `compliance/masvs_mstg/taxonomy.yaml`
   - MSTG IDs (test identifiers) stored in `evidence["mstg_tests"]`
   - MASVS controls (security requirements) set in `masvs_control` field
   - Fallback mapping for standard categories (AUTH, CRYPTO, NETWORK, STORAGE, etc.)

2. **Graceful Degradation**
   - Plugin SKIPs cleanly when semgrep CLI not installed
   - Plugin SKIPs when rules directory missing (offline-safe)
   - Plugin SKIPs when no JADX sources available

3. **Configuration**
   - `compliance/masvs_mstg/versions.yaml` pins Semgrep CLI version and rules commit
   - Rules repo: `mindedsecurity/semgrep-rules-android-security`

### Track 2 Validation ✅ COMPLETE

**Validation Results (AndroGoat APK):**

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Findings | N/A | 256 | ✅ |
| MSTG IDs Covered | N/A | 21 | ✅ |
| MASVS Controls | N/A | 6 | ✅ |
| Execution Time | ≤ 90s | ~73s | ✅ |
| Pipeline Integration | Works | Works | ✅ |

**MSTG Test Coverage:**
- MSTG-AUTH-8
- MSTG-CODE-2, MSTG-CODE-4, MSTG-CODE-8
- MSTG-CRYPTO-4
- MSTG-NETWORK-1, MSTG-NETWORK-4
- MSTG-PLATFORM-1, MSTG-PLATFORM-2, MSTG-PLATFORM-4, MSTG-PLATFORM-5, MSTG-PLATFORM-6
- MSTG-STORAGE-1, MSTG-STORAGE-2, MSTG-STORAGE-3, MSTG-STORAGE-5, MSTG-STORAGE-6, MSTG-STORAGE-7, MSTG-STORAGE-8, MSTG-STORAGE-9, MSTG-STORAGE-11

**MASVS Controls Covered:**
- MASVS-AUTH-1
- MASVS-CODE-1
- MASVS-CRYPTO-1
- MASVS-NETWORK-1
- MASVS-PLATFORM-1
- MASVS-STORAGE-1

## Files Created

| File | Description |
|------|-------------|
| `plugins/semgrep_mastg_analyzer/__init__.py` | Plugin entry point with PLUGIN_METADATA |
| `plugins/semgrep_mastg_analyzer/v2_plugin.py` | Main implementation (~750 lines) |
| `compliance/masvs_mstg/versions.yaml` | Semgrep rules version pinning |
| `tests/unit/plugins/test_semgrep_mastg_analyzer.py` | 40 unit tests |
| `external/semgrep-rules-android-security/` | Cloned rules repo |

## Files Modified

| File | Change |
|------|--------|
| `requirements/analysis.txt` | Added `semgrep>=1.90.0` |
| `core/scan_profiles.py` | Added plugin to STANDARD profile |
| `core/enhanced_scan_orchestrator.py` | Added to static plugins list |
| `docs/tracking/TASK_CHECKLIST.md` | Added Track 2 Semgrep section |
| `docs/tracking/MASTER_EXECUTION_PLAN.md` | Updated Track 2 status |

## Bug Fixes Applied

1. **`--no-git-ignore` flag**: Semgrep by default skips files not tracked by git. Added `--no-git-ignore` to scan all decompiled files.

2. **Source path discovery**: Added support for additional APKContext attribute names (`jadx_sources_path`, `decompiled_dir`) and workspace directory patterns.

3. **Path sanitization**: Improved to produce clean relative paths in findings.

4. **Plugin discovery**: Added `PLUGIN_METADATA` and `run_plugin()` to `__init__.py` for legacy discovery compatibility.

## Git Status

```
Branch: main
Latest commits:
  b43aab3 feat(semgrep): add optional SARIF output for CI integration
  df2c399 refactor(orchestrator): use profile-based plugin selection
  580680a feat(semgrep): add runtime version validation for CLI and rules
  a577cf5 feat(semgrep): vendor MASTG rules for offline operation
  c9876bd feat(semgrep): add AODS_DISABLE_SEMGREP environment variable toggle
  ae46346 feat(plugins): add Semgrep MASTG analyzer plugin
Status: Pushed to origin/main
```

## Verification Commands

```bash
# Run Semgrep plugin unit tests
pytest tests/unit/plugins/test_semgrep_mastg_analyzer.py -v

# Test plugin standalone
python -c "
from plugins.semgrep_mastg_analyzer.v2_plugin import SemgrepMastgAnalyzerV2
class MockCtx:
    apk_path = 'workspace/AndroGoat.apk'
plugin = SemgrepMastgAnalyzerV2()
result = plugin.execute(MockCtx())
print(f'Findings: {len(result.findings) if result.findings else 0}')
"

# Test in full pipeline
python dyna.py --apk apks/vulnerable_apps/AndroGoat.apk --mode safe --profile standard --static-only
```

## Test Results

All 40 unit tests pass:
- MSTG→MASVS mapping (8 tests)
- Plugin metadata (6 tests)
- MSTG ID extraction (6 tests)
- CWE extraction (4 tests)
- Severity mapping (3 tests)
- Graceful skip behavior (2 tests)
- Finding conversion (2 tests)
- Path sanitization (2 tests)
- Vulnerability type inference (4 tests)
- OWASP category mapping (3 tests)

## Architecture Review Improvements (Session 2)

Based on architecture review feedback, implemented 5 additional improvements:

### 1. Opt-in Toggle ✅
- Added `AODS_DISABLE_SEMGREP=1` env var to disable plugin
- Checked in `can_execute()` method

### 2. Vendor Rules ✅
- Vendored 53 rules to `compliance/semgrep_rules/mastg/`
- 528K total, organized by MASTG category (arch, auth, code, crypto, network, platform, resilience, storage)
- Created `scripts/update_semgrep_rules.sh` for maintainers
- Plugin checks vendored path first, falls back to external clone

### 3. Version Validation ✅
- Runtime check against `compliance/masvs_mstg/versions.yaml`
- Logs warnings on CLI version mismatch or commit SHA mismatch
- Non-blocking (scan continues with warning)

### 4. Fix Orchestrator ✅
- Replaced hardcoded plugin list in `core/enhanced_scan_orchestrator.py`
- Now uses `scan_profile_manager.get_plugins_for_profile()`
- Single source of truth for plugin selection

### 5. SARIF Output ✅
- Added `AODS_SEMGREP_EMIT_SARIF=1` env var
- Generates SARIF 2.1.0 format to `reports/semgrep_mastg_<timestamp>.sarif`
- Compatible with GitHub Security, GitLab SAST, and other CI systems

### New Unit Tests
- 14 new tests added (54 total)
- TestGracefulSkip: env var disable tests
- TestVersionValidation: 8 tests for version checking
- TestSARIFOutput: 4 tests for SARIF functionality

## Pending/Future Work

### Track 2 Remaining Items

1. **Custom Rules & Advanced** (not started)
   - Android 14 specific rules
   - Profile filtering per scan profile

2. **Rollout** (not started)
   - Enable by default after validation
   - Promote gate after ≥5 green CI runs

3. **Multi-APK Validation** (partial)
   - AndroGoat: ✅ Complete
   - DIVA: ⚠️ APK file is placeholder, not valid

## Key Classes/Functions

### `MSTGToMASVSMapper` (v2_plugin.py)
- `map_to_masvs(mstg_id)` - Maps single MSTG ID to MASVS control
- `map_multiple(mstg_ids)` - Maps list, returns (primary, all_controls)

### `SemgrepMastgAnalyzerV2` (v2_plugin.py)
- `execute(context)` - Main entry point, returns PluginResult
- `_extract_mstg_ids(result)` - Extracts MSTG IDs from Semgrep finding
- `_convert_findings(semgrep_output, context)` - Converts to PluginFinding objects
- `_sanitize_path(path, context)` - Removes absolute paths from findings
- `_get_sources_path(apk_ctx)` - Locates JADX decompiled sources

## Environment Notes

- Python 3.13.9
- Semgrep 1.149.0
- pytest 9.0.2
- Working directory: `/home/kali/PROJECTS/AODS/AODS-feature-ui-rbac-sse-e2e-20260119-061413`
- Virtual environments: `.venv/` and `aods_venv/` (symlinked semgrep)

## Quick Start for Next Session

```bash
cd /home/kali/PROJECTS/AODS/AODS-feature-ui-rbac-sse-e2e-20260119-061413
source aods_venv/bin/activate

# Verify tests still pass
pytest tests/unit/plugins/test_semgrep_mastg_analyzer.py -v

# Check git status
git status
git log --oneline -5
```
