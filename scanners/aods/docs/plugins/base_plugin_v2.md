# BasePluginV2 Interface - Developer Guide

This document defines the standardized plugin interface used by AODS (BasePluginV2), required metadata, and migration guidance. It also clarifies decompilation requirements integration and best practices for reliability and performance.

## Interface Overview
A v2 plugin implements two methods:
- `get_metadata() -> PluginMetadata`
- `execute(apk_ctx) -> PluginResult`

All v2 plugins should be importable as `plugins.<plugin_name>.v2_plugin` and export a `create_plugin()` factory and a `*V2` class.

## Key Types (summary)
- `PluginMetadata` (fields subset):
  - `name: str`
  - `version: str`
  - `capabilities: List[PluginCapability]`
  - `dependencies: List[str|PluginDependency]`
  - `priority: PluginPriority` (execution order hint)
  - `timeout_seconds: int`
  - `supported_platforms: List[str]`
  - `tags, categories: List[str]`
  - `decompilation_requirements: List[str]` - one or more of `"res" | "assets" | "imports" | "debug"`

- `PluginResult` (fields subset):
  - `status: PluginStatus`
  - `findings: List[PluginFinding]`
  - `execution_time, start_time, end_time`
  - `metadata, performance_metrics`
  - `error_message, warning_messages`

- `PluginFinding` (fields subset):
  - `finding_id, title, description, severity, confidence`
  - `file_path, line_number, code_snippet`
  - `vulnerability_type, cwe_id, owasp_category, masvs_control`
  - `evidence, remediation, references`

## Decompilation Requirements
Plugins can elevate decompilation policy via `PluginMetadata.decompilation_requirements`:
- `"res"`: requires resources (e.g., XML, strings)
- `"assets"`: requires assets
- `"imports"`: requires import stubs (cross-file linking)
- `"debug"`: requires debug info

The plugin manager aggregates requirements across all active plugins and passes them to the decompilation policy resolver. The resolver enforces multi‑DEX assertions and policy defaults. See `core/decompilation_policy_resolver.py`.

Recommended defaults by plugin type:
- Static/code analyzers: `["imports"]`
- Manifest/network security analyzers: `["res"]`
- Storage/privacy analyzers: `["res", "imports"]`

## Error Handling & Performance
- Use precise exception handling (no broad bare except) and set `PluginStatus` appropriately.
- Respect `timeout_seconds` in metadata; long-running steps should be cooperatively cancellable.
- Prefer shared facilities (unified cache, performance tracker) instead of bespoke implementations.
- Avoid heavy imports at module import time; lazy-load if needed.

## Migration Notes (Legacy → v2)
- Export a v2 module `plugins/<name>/v2_plugin.py` with `create_plugin()` returning a `*V2` instance.
- Map any legacy outputs into `PluginFinding` and return via `PluginResult`.
- Ensure the root `plugins/<name>/__init__.py` provides a `Plugin` adapter for compatibility during transition if required.
- Declare `decompilation_requirements` where the plugin depends on resources/imports.

## Examples
Minimal structure (illustrative):
```python
# plugins/example/v2_plugin.py
from core.plugins.base_plugin_v2 import BasePluginV2, PluginMetadata, PluginResult, PluginCapability, PluginStatus

class ExampleV2(BasePluginV2):
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="example",
            version="1.0.0",
            capabilities=[PluginCapability.VULNERABILITY_DETECTION],
            timeout_seconds=120,
            decompilation_requirements=["imports"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        findings = []  # produce PluginFinding objects as needed
        return PluginResult(status=PluginStatus.SUCCESS, findings=findings)

def create_plugin() -> ExampleV2:
    return ExampleV2()
```

## References
- `core/plugins/base_plugin_v2.py`
- `core/plugins/__init__.py` (canonical import, aggregation logic)
- `core/decompilation_policy_resolver.py` (policy & assertions)
- `core/shared_infrastructure/jadx_unified_helper.py` (policy-aware fallback)










