# Semgrep MASTG Plugin - Architecture Review

## Overview

This document captures the architectural review of the Semgrep MASTG Analyzer plugin integration into AODS, identifying what works well, gaps to address, and the improvement roadmap.

## Current Implementation Summary

**Plugin:** `plugins/semgrep_mastg_analyzer/`
**Added:** 2026-01-29
**Status:** Functional prototype, validation complete

### What It Does

1. Runs Semgrep with OWASP MASTG security rules on JADX-decompiled Android sources
2. Extracts MSTG test IDs from rule metadata
3. Maps MSTG IDs to MASVS controls via taxonomy.yaml
4. Converts findings to canonical `PluginFinding` format
5. Participates in AODS deduplication and reporting pipeline

### Validation Results

| Metric | Value |
|--------|-------|
| Test APK | AndroGoat |
| Findings | 256 |
| MSTG IDs Covered | 21 |
| MASVS Controls | 6 |
| Execution Time | ~73 seconds |
| Profile | STANDARD/DEEP only |

## Architecture Review

### What Works Well

| Aspect | Implementation | Assessment |
|--------|----------------|------------|
| Pipeline reuse | Uses existing JADX decompilation output | ✅ Good |
| Unified output | Full PluginFinding conversion | ✅ Good |
| Profile gating | STANDARD/DEEP only, not LIGHTNING/FAST | ✅ Good |
| Taxonomy extraction | MSTG/MASVS/CWE from rule metadata | ✅ Good |
| Graceful degradation | SKIPs cleanly when CLI/rules missing | ✅ Good |
| Deduplication | Participates in unified dedup pipeline | ✅ Good |

### Identified Gaps

#### 1. No Explicit Opt-In Toggle (Medium Priority)

**Issue:** Plugin is only gated by scan profile. No way to disable in STANDARD/DEEP without changing profile.

**Risk:** Users who want STANDARD profile features but not Semgrep overhead have no recourse.

**Solution:** Add `AODS_DISABLE_SEMGREP` environment variable.

#### 2. Rules Not Vendored (High Priority for Production)

**Issue:** Rules cloned from GitHub (`mindedsecurity/semgrep-rules-android-security`) to `external/` directory at setup time. Not committed to repo.

**Risk:**
- Fails in offline/air-gapped environments
- Version drift if upstream changes
- Setup complexity for new installs

**Solution:** Vendor rules under `compliance/semgrep_rules/` or create versioned release artifact.

#### 3. No Runtime Version Validation (Medium Priority)

**Issue:** `versions.yaml` pins Semgrep CLI and rules versions, but no runtime validation.

**Risk:**
- Silent behavior changes with version drift
- Difficult to debug inconsistent results

**Solution:** Add `_validate_versions()` check in `can_execute()`, log warnings on mismatch.

#### 4. Hardcoded Orchestrator Plugin List (Medium Priority)

**Issue:** `enhanced_scan_orchestrator.py` lines 1134-1143 have hardcoded `static_plugins` list that bypasses `scan_profiles.py`.

**Risk:**
- Two parallel plugin selection mechanisms
- Profile changes don't automatically apply
- Maintenance burden

**Solution:** Refactor orchestrator to use `ScanProfileManager.get_plugins_for_profile()`.

#### 5. No SARIF Output (Low Priority)

**Issue:** Only produces PluginFinding output, no SARIF for CI tool integration.

**Risk:**
- Can't integrate with GitHub/GitLab security dashboards
- No parity with CI-only Semgrep usage

**Solution:** Add optional `--emit-sarif` capability.

## Improvement Roadmap

### Phase 1: Hardening (Required for Production)

| Task | Priority | Effort |
|------|----------|--------|
| Add AODS_DISABLE_SEMGREP toggle | Medium | Small |
| Vendor rules for offline operation | High | Medium |
| Add runtime version validation | Medium | Small |

### Phase 2: Architecture Cleanup

| Task | Priority | Effort |
|------|----------|--------|
| Fix orchestrator plugin selection | Medium | Medium |
| Remove hardcoded plugin lists | Medium | Small |

### Phase 3: Enhancements

| Task | Priority | Effort |
|------|----------|--------|
| Add SARIF output option | Low | Small |
| Profile-specific rule filtering | Low | Medium |
| Android 14 specific rules | Low | Medium |

## Configuration Reference

### Current Configuration

```yaml
# compliance/masvs_mstg/versions.yaml
semgrep_rules:
  repository: "mindedsecurity/semgrep-rules-android-security"
  pinned_commit: "ea8f288a90dea9476c814a4d5c43e0e9089abba2"

semgrep_cli:
  minimum_version: "1.90.0"
```

### Environment Variables (Current + Proposed)

| Variable | Default | Description |
|----------|---------|-------------|
| `AODS_SEMGREP_RULES_DIR` | - | Override rules directory path |
| `AODS_DISABLE_SEMGREP` | `0` | **PROPOSED:** Disable plugin regardless of profile |

### Profile Integration

```python
# core/scan_profiles.py - Current state
profiles[ScanProfile.STANDARD].plugins = {
    # ... other plugins ...
    "semgrep_mastg_analyzer"  # Added for STANDARD
}

profiles[ScanProfile.DEEP].plugins = set()  # All plugins including semgrep
```

## Key Files

| File | Purpose |
|------|---------|
| `plugins/semgrep_mastg_analyzer/__init__.py` | Plugin entry point, PLUGIN_METADATA |
| `plugins/semgrep_mastg_analyzer/v2_plugin.py` | Main implementation (~750 lines) |
| `compliance/masvs_mstg/versions.yaml` | Version pinning |
| `compliance/masvs_mstg/taxonomy.yaml` | MSTG→MASVS mapping |
| `core/scan_profiles.py` | Profile-based plugin selection |
| `core/enhanced_scan_orchestrator.py` | Runtime plugin execution (has hardcoded list issue) |
| `external/semgrep-rules-android-security/` | Cloned rules (not committed) |

## Decision Record

### Why BasePluginV2 Integration?

**Considered Alternatives:**
1. CI-only gate (no runtime integration)
2. Separate CLI tool invoked post-scan
3. BasePluginV2 plugin (chosen)

**Rationale for Plugin Approach:**
- Findings participate in unified dedup/reporting
- Profile-aware execution
- MSTG coverage tracked per-scan
- Consistent with AODS plugin architecture

**Trade-offs Accepted:**
- ~73s overhead in STANDARD/DEEP scans
- Dependency on Semgrep CLI + rules
- Increased finding volume requiring dedup tuning

### Why STANDARD/DEEP Only?

**Rationale:**
- LIGHTNING target: 30-60s → 73s Semgrep alone exceeds budget
- FAST target: 2-3 min → 73s is significant but could fit
- STANDARD target: 5-8 min → 73s is acceptable overhead
- DEEP target: 15+ min → 73s is negligible

**Decision:** Start with STANDARD/DEEP, evaluate FAST after optimization.

## References

- [OWASP MASTG](https://mas.owasp.org/MASTG/)
- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [Semgrep Rules Repo](https://github.com/mindedsecurity/semgrep-rules-android-security)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
