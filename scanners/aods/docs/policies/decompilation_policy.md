# Decompilation Policy (JADX) - Modes, Overrides, and Elevation

This document specifies how AODS resolves JADX flags deterministically based on mode, environment, and plugin needs. Implementation lives in `core/decompilation_policy_resolver.py`; callers include `core/jadx_decompilation_manager.py`.

## Modes
- complete: Maximum fidelity; keeps resources/imports; allows debug info.
- optimized: Balanced defaults; imports kept; debug info disabled.
- minimal: Fastest; may skip resources/imports; optional `--classes-only`.

Default mode is derived from profile and can be overridden via `AODS_DECOMPILATION_MODE`.

## Environment Overrides (boolean)
- `AODS_DECOMP_INCLUDE_RES`
- `AODS_DECOMP_INCLUDE_IMPORTS`
- `AODS_DECOMP_INCLUDE_DEBUG`
- `AODS_DECOMP_ALLOW_CLASSES_ONLY` (only honored in minimal mode)

Values considered true: 1, true, yes, on.

## Plugin Elevation
Plugins declare `PluginMetadata.decompilation_requirements: [res|assets|imports|debug]`.
- Any required component removes its disabling flag.
- If mode is minimal and a plugin requires `res` or `imports`, mode elevates to optimized.
- Assets are treated as part of resources in JADX semantics.

Aggregated requirements are computed by `PluginManager.aggregate_decompilation_requirements` and passed into the resolver.

## Multi‑DEX Assertions
For multi‑DEX APKs in `optimized` or `complete` mode:
- `--classes-only` is disallowed.
- `--no-imports` is removed to retain imports for correctness.

Multi‑DEX detection scans `.dex` entries inside the APK.

## Disk Headroom Check
Resolver annotates `disk_ok` using a headroom threshold (default 2GB). Errors in checking are permissive.

## Flags Versioning
`AODS_DECOMP_FLAGS_VERSION` controls surfaced `flags_version` to aid cache keys and determinism testing.

## Acceptance Criteria
- Deterministic flag resolution per input tuple (apk_path, profile, plugin_requirements, env).
- Elevation occurs whenever required by active plugins.
- Multi‑DEX assertions enforced in optimized/complete.
- Manifest always processed implicitly by downstream components.
- Safe defaults on WSL/low headroom via manager-level policies (threads/JVM), not resolver.

## References
- Policy resolver: `core/decompilation_policy_resolver.py`
- Manager integration: `core/jadx_decompilation_manager.py`
- Plugin metadata: `core/plugins/base_plugin_v2.py`
- Aggregation: `core/plugin_manager.py`

## Declared plugin requirements (initial)
- `plugins/jadx_static_analysis`: ["imports", "res"]
- `plugins/enhanced_static_analysis`: ["imports", "res"]
- `plugins/webview_security_analysis`: ["imports", "res"]
- `plugins/enhanced_manifest_analysis`: ["res"]
- `plugins/cryptography_tests`: ["imports"]
- `plugins/network_communication_tests`: ["res"]
- `plugins/enhanced_network_security_analysis`: ["res"]
- `plugins/insecure_data_storage`: ["res", "imports"]
- `plugins/privacy_leak_detection`: ["res", "imports"]
