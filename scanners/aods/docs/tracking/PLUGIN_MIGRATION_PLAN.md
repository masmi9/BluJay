# AODS Plugin Consolidation Plan

**Created:** 2026-01-25
**Status:** Active
**Owner:** @assistant

---

## Executive Summary

AODS has 68 plugin packages with multiple competing architectures. This plan consolidates all plugins onto the modern **BasePluginV2** standard to improve maintainability, performance, and security.

**Current State:** (Updated: 2026-02-07, Track 26)
- **66/66 plugin directories** (100%) have `v2_plugin.py` with BasePluginV2 subclass
- 9 legacy `_standardized.py` files deprecated (Track 9.3, 2026-01-28)
- 7 standalone root-level `.py` files deprecated with `DeprecationWarning` (Track 26.2, 2026-02-07)
- Single unified plugin manager (`core/plugins/unified_manager.py`)

**Target State:** ✅ **ACHIEVED** (2026-02-07)
- 100% plugins on BasePluginV2
- Single unified plugin manager
- Consistent metadata and capabilities
- Legacy adapters retained for backward compatibility only

---

## Current Architecture Analysis

### Plugin Distribution

| Category | Count | Pattern | Status |
|----------|-------|---------|--------|
| BasePluginV2 | **66** | `plugins/*/v2_plugin.py` | ✅ **100% adopted** |
| Legacy BasePlugin | ~~9~~ 0 | `plugins/*_standardized.py` | ✅ Deprecated (Track 9.3) |
| Root-level legacy | 7 | `plugins/*.py` | ✅ Deprecated with warnings (Track 26.2) |
| ML/Custom | 0 | `plugins/ml_*/` | ✅ `ml_vulnerability_scanner` now has v2_plugin.py (Track 26.1) |
| **Total dirs** | **66** | | **100% migrated** |

### Plugin Management Layers

| Layer | File | Lines | Status |
|-------|------|-------|--------|
| BasePlugin (v1) | `core/plugins/base_plugin.py` | 218 | Deprecated |
| **BasePluginV2** | `core/plugins/base_plugin_v2.py` | 600+ | **Active standard** |
| PluginRegistryV2 | `core/plugins/plugin_registry_v2.py` | 600+ | Active |
| PluginRegistryV3 | `core/plugins/registry_v3.py` | 140 | Experimental |
| UnifiedManager | `core/plugins/unified_manager.py` | 3000+ | Production |
| LegacyAdapter | `core/plugins/legacy_plugin_manager_adapter.py` | 54 | Compatibility |

---

## Migration Phases

### Phase 1: Audit & Categorize (Week 1)
**Goal:** Complete inventory of all plugins and their migration status

- [ ] Generate full plugin inventory with metadata completeness scores
- [ ] Identify plugins with missing capabilities/dependencies
- [ ] Document plugins with external tool requirements
- [ ] Create per-plugin migration checklist

**Deliverables:**
- `artifacts/plugin_audit/inventory.json`
- `artifacts/plugin_audit/migration_status.csv`

### Phase 2: Migrate Legacy Root Files (Weeks 2-3)
**Goal:** Convert 11 root-level `.py` files to package structure

**Files to migrate:**
```
plugins/advanced_dynamic_analysis.py
plugins/advanced_ml_analyzer.py
plugins/advanced_pattern_integration.py
plugins/component_analyzer.py
plugins/dynamic_analysis_enhancement_plugin.py
plugins/enhanced_data_storage_analyzer.py
plugins/enhanced_detection_plugin.py
plugins/enhanced_firebase_integration_analyzer.py
plugins/performance_analyzer.py
plugins/threat_intelligence_plugin.py
plugins/zero_day_detector.py
```

**Migration steps per plugin:**
1. Create package directory: `plugins/<name>/`
2. Create `__init__.py` with exports
3. Create `v2_plugin.py` inheriting from `BasePluginV2`
4. Migrate logic from legacy file
5. Add complete `PluginMetadata`
6. Add unit test in `tests/unit/plugins/`
7. Mark legacy file as deprecated (add `# DEPRECATED: Use plugins/<name>/v2_plugin.py`)

**Acceptance criteria:**
- [ ] All 11 files converted to packages
- [ ] Each has working `v2_plugin.py`
- [ ] Unit tests pass for each
- [ ] Legacy files marked deprecated

### Phase 3: Complete BasePlugin→BasePluginV2 Migration (Weeks 3-4)
**Goal:** Convert 9 `_standardized.py` plugins to `v2_plugin.py`

**Files to migrate:**
```
plugins/advanced_dynamic_analysis_standardized.py
plugins/advanced_ml_analyzer_standardized.py
plugins/component_analyzer_standardized.py
plugins/enhanced_data_storage_analyzer_standardized.py
plugins/enhanced_detection_plugin_standardized.py
plugins/enhanced_firebase_integration_analyzer_standardized.py
plugins/performance_analyzer_standardized.py
plugins/threat_intelligence_plugin_standardized.py
plugins/zero_day_detector_standardized.py
```

**Migration steps:**
1. Identify corresponding `v2_plugin.py` (if exists)
2. If v2 exists: merge any unique functionality
3. If v2 missing: create new `v2_plugin.py`
4. Verify all capabilities are preserved
5. Mark `_standardized.py` as deprecated

### Phase 4: Metadata Standardization (Week 5)
**Goal:** Ensure all 68 plugins have complete metadata

**Required metadata fields:**
```python
PluginMetadata(
    name="plugin_name",
    version="1.0.0",
    description="Clear description",
    author="AODS Team",
    capabilities=[PluginCapability.X, ...],  # Required
    priority=PluginPriority.NORMAL,
    timeout_seconds=300,
    dependencies=[],  # Or actual dependencies
    supported_platforms=["android"],
    tags=["category", "type"],
    categories=["security", "analysis"],
    decompilation_requirements=["jadx"],  # Or []
    security_level="standard",
    data_access_required=["filesystem"],
)
```

**Audit checklist per plugin:**
- [ ] `capabilities` populated (not empty)
- [ ] `dependencies` documented (if any)
- [ ] `decompilation_requirements` accurate
- [ ] `security_level` appropriate
- [ ] `data_access_required` accurate

### Phase 5: Deprecate Legacy Infrastructure (Week 6)
**Goal:** Remove legacy code paths

**Tasks:**
- [ ] Add deprecation warnings to `BasePlugin` class
- [ ] Add deprecation warnings to `LegacyPluginAdapter`
- [ ] Update `UnifiedPluginManager` to log legacy usage
- [ ] Create migration guide for external plugin developers
- [ ] Set removal date for legacy support (e.g., v3.0)

### Phase 6: Optimize Plugin Discovery (Week 7)
**Goal:** Improve startup time and reliability

**Tasks:**
- [ ] Evaluate PluginRegistryV3 performance
- [ ] Consider making v3 the default (if faster)
- [ ] Add plugin discovery caching
- [ ] Implement lazy loading for non-critical plugins
- [ ] Add health checks for plugin initialization

---

## Migration Priority Matrix

| Plugin | Current State | Priority | Complexity | Notes |
|--------|--------------|----------|------------|-------|
| threat_intelligence_plugin.py | Root legacy | HIGH | Medium | Active use |
| zero_day_detector.py | Root legacy | HIGH | Medium | Security critical |
| frida_enhanced_plugin.py | Root legacy | HIGH | High | Dynamic analysis |
| malware_similarity_analyzer.py | Root legacy | MEDIUM | Medium | ML-based |
| behavioral_analysis_plugin.py | Root legacy | MEDIUM | Medium | Dynamic |
| *_standardized.py (9 files) | Legacy base | MEDIUM | Low | Already structured |
| Other root files (15) | Root legacy | LOW | Low | Less active |

---

## Success Metrics

### Phase Completion Criteria

| Phase | Metric | Target |
|-------|--------|--------|
| Phase 1 | Audit complete | 100% plugins inventoried |
| Phase 2 | Root migrations | 11/11 converted |
| Phase 3 | BasePlugin migrations | 9/9 converted |
| Phase 4 | Metadata completeness | 100% fields populated |
| Phase 5 | Legacy warnings | All legacy paths warn |
| Phase 6 | Discovery time | <2s startup |

### Overall Success Criteria

- [ ] 100% plugins on BasePluginV2
- [ ] 0 legacy adapter invocations in production
- [ ] All plugins have complete metadata
- [ ] Plugin discovery <2 seconds
- [ ] No regression in plugin functionality
- [ ] Unit test coverage >80% for migrated plugins

---

## Risk Mitigation

### Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Breaking existing plugins | HIGH | Feature flags, gradual rollout |
| Performance regression | MEDIUM | Benchmark before/after |
| Missing functionality in migration | HIGH | test coverage |
| External plugin breakage | MEDIUM | Migration guide, deprecation period |

### Rollback Plan

Each phase can be rolled back independently:
1. Legacy files remain functional until explicitly removed
2. `LegacyPluginAdapter` continues to work
3. Feature flag `AODS_USE_LEGACY_PLUGINS=1` forces legacy paths
4. Git tags mark each phase completion for easy revert

---

## Implementation Notes

### Creating a v2_plugin.py from Legacy

```python
# Template for migration
from typing import Any
from core.plugins.base_plugin_v2 import (
    BasePluginV2, PluginMetadata, PluginResult, PluginFinding,
    PluginCapability, PluginStatus, PluginPriority
)

class MyPluginV2(BasePluginV2):
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my_plugin",
            version="2.0.0",
            description="Migrated from legacy my_plugin.py",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
        )

    def execute(self, apk_ctx) -> PluginResult:
        # Migrate logic from legacy file
        findings = []
        # ... analysis logic ...
        return PluginResult(
            status=PluginStatus.SUCCESS,
            findings=findings,
            metadata={"migrated_from": "legacy"}
        )

def create_plugin() -> MyPluginV2:
    return MyPluginV2()
```

### Marking Legacy Files Deprecated

```python
# Add to top of legacy file
import warnings
warnings.warn(
    "This module is deprecated. Use plugins/my_plugin/v2_plugin.py instead.",
    DeprecationWarning,
    stacklevel=2
)
```

---

## Timeline Summary

| Week | Phase | Deliverable |
|------|-------|-------------|
| 1 | Audit | Plugin inventory & status |
| 2-3 | Root migration | 21 plugins converted |
| 3-4 | BasePlugin migration | 9 plugins converted |
| 5 | Metadata | 100% metadata complete |
| 6 | Deprecation | Legacy warnings active |
| 7 | Optimization | Discovery optimized |

**Total Duration:** 7 weeks
**Target Completion:** Phase 8.3 milestone

---

## Appendix: Plugin Inventory

### Already on BasePluginV2 (65 plugins)

<details>
<summary>Click to expand full list</summary>

```
plugins/anti_tampering_analysis/v2_plugin.py
plugins/attack_surface_analysis/v2_plugin.py
plugins/authentication_analysis/v2_plugin.py
plugins/backup_analysis/v2_plugin.py
plugins/biometric_analysis/v2_plugin.py
plugins/certificate_transparency/v2_plugin.py
plugins/clipboard_security/v2_plugin.py
plugins/code_injection_analyzer/v2_plugin.py
plugins/component_exploitation_plugin/v2_plugin.py
plugins/crypto_implementation_analysis/v2_plugin.py
plugins/cryptography_tests/v2_plugin.py
plugins/custom_permission_analysis/v2_plugin.py
plugins/data_flow_analysis/v2_plugin.py
plugins/data_validation_plugin/v2_plugin.py
plugins/deep_link_security/v2_plugin.py
plugins/enhanced_manifest_analysis/v2_plugin.py
plugins/enhanced_static_analysis/v2_plugin.py
plugins/external_service_analysis/v2_plugin.py
plugins/file_permission_analysis/v2_plugin.py
plugins/flutter_security/v2_plugin.py
plugins/hardcoded_secrets_scanner/v2_plugin.py
plugins/icc_analysis/v2_plugin.py
plugins/injection_vulnerabilities/v2_plugin.py
plugins/input_validation_analysis/v2_plugin.py
plugins/insecure_data_storage/v2_plugin.py
plugins/intent_redirection_analysis/v2_plugin.py
plugins/jadx_static_analysis/v2_plugin.py
plugins/javascript_interface_analysis/v2_plugin.py
plugins/jwt_analysis/v2_plugin.py
plugins/key_management/v2_plugin.py
plugins/kotlin_security/v2_plugin.py
plugins/logging_security/v2_plugin.py
plugins/malware_detection/v2_plugin.py
plugins/memory_corruption_analysis/v2_plugin.py
plugins/mitmproxy_network_analysis/v2_plugin.py
plugins/native_binary_analysis/v2_plugin.py
plugins/network_pii_traffic_analyzer/v2_plugin.py
plugins/network_security_analysis/v2_plugin.py
plugins/oauth_security/v2_plugin.py
plugins/patch_analysis/v2_plugin.py
plugins/pending_intent_analysis/v2_plugin.py
plugins/permission_analysis/v2_plugin.py
plugins/privacy_controls_analysis/v2_plugin.py
plugins/provider_security_analysis/v2_plugin.py
plugins/random_number_analysis/v2_plugin.py
plugins/react_native_security/v2_plugin.py
plugins/reverse_engineering_analysis/v2_plugin.py
plugins/root_detection_analysis/v2_plugin.py
plugins/runtime_decryption_analysis/v2_plugin.py
plugins/security_header_analysis/v2_plugin.py
plugins/session_management/v2_plugin.py
plugins/shared_preferences_analysis/v2_plugin.py
plugins/sql_injection_scanner/v2_plugin.py
plugins/ssl_pinning_analysis/v2_plugin.py
plugins/storage_analysis/v2_plugin.py
plugins/tapjacking_analysis/v2_plugin.py
plugins/third_party_libs/v2_plugin.py
plugins/threat_intelligence_plugin/v2_plugin.py
plugins/tls_analysis/v2_plugin.py
plugins/url_scheme_analysis/v2_plugin.py
plugins/webview_analysis/v2_plugin.py
plugins/webview_configuration_analyzer/v2_plugin.py
plugins/xamarin_security/v2_plugin.py
plugins/xml_external_entity_analysis/v2_plugin.py
plugins/xss_vulnerability_analysis/v2_plugin.py
```

</details>

### Need Migration (20 files)

**Root-level legacy (11):**
- See Phase 2 list above

**BasePlugin standardized (9):**
- See Phase 3 list above

**Note:** Each legacy root file often has a corresponding `_standardized.py` version,
representing a partial migration that was never completed.

---

**Last Updated:** 2026-01-25
**Next Review:** After Phase 1 completion
