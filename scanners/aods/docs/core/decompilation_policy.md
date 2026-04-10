## Decompilation Policy Resolver

This component determines safe, environment-aware settings for JADX decompilation.

### Environment Detection
- WSL: Detected via `/proc/version` containing `microsoft` or `wsl`.
  - Defaults under WSL: `memory_limit_mb=1024`, `max_threads=1`.
  - Non-WSL defaults: `memory_limit_mb=2048`, `max_threads=floor((CPU count)/2)` with a minimum of 2.

### Disk Headroom and Fallback
- Headroom check: requires free space of at least:
  - 1 GiB on WSL
  - 2 GiB otherwise
- Preferred root: `preferred_output_root` if provided, else `AODS_DECOMP_OUT`, else `/tmp/jadx_decompiled`.
- If preferred root lacks headroom:
  - Falls back to `./artifacts/jadx_decompiled/` (created if missing) when it has headroom.
  - If no location has sufficient headroom, the resolver scales down resources (`memory_limit_mb` ≤ 1024, `max_threads=1`) to reduce temp usage.

### Mode Resolution
- Source of truth:
  - `AODS_DECOMPILATION_MODE` env: `minimal|min`, `optimized|opt`, `complete|full`.
  - Otherwise by profile: `production` → `optimized`, others → `minimal`.
- Minimal may be elevated to `optimized` when plugin requirements include `imports` or `resources`.

### Flags
- Minimal: `--no-res --no-imports --no-debug-info`
- Optimized: `--no-debug-info` (+ `--no-imports` if `AODS_DECOMP_INCLUDE_IMPORTS` is disabled)
- Complete: no forced negative flags
- Deobfuscation: Adds `--deobf` unless profile is `lightning` or `fast`.
- Threads: Adds `-j <max_threads>`; caller maps to jadx `-j`.

### Key Environment Variables
- `AODS_DECOMP_OUT`: Preferred output root
- `AODS_DECOMPILATION_MODE`: `minimal|min|optimized|opt|complete|full`
- `AODS_DECOMP_INCLUDE_IMPORTS`: `1` (default) to include imports; `0` to exclude

### Return Object
`DecompilationPolicy` includes:
- `output_dir` (per-APK directory)
- `max_threads`, `memory_limit_mb`
- `flags` (safe, minimal set)
- `mode` (`minimal|optimized|complete`)
- `reason` (`wsl` or `standard`)

### Tests
- See `tests/unit/core/test_decompilation_policy_resolver.py` for WSL defaults, headroom fallback/scale-down, and mode resolution.





