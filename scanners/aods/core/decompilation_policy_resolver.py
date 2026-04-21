#!/usr/bin/env python3
"""
Decompilation policy resolver
Determines safe, environment-aware settings for JADX decompilation.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Iterable, Set
from enum import Enum


class DecompilationMode(Enum):
    MINIMAL = "minimal"
    OPTIMIZED = "optimized"
    COMPLETE = "complete"


@dataclass
class DecompilationPolicy:
    output_dir: str
    max_threads: int
    memory_limit_mb: int
    flags: List[str]
    mode: DecompilationMode
    reason: Optional[str] = None
    flags_version: str = "1.0"
    disk_ok: bool = True


def _is_wsl() -> bool:
    try:
        with open("/proc/version", "r", encoding="utf-8") as f:
            v = f.read().lower()
            return ("microsoft" in v) or ("wsl" in v)
    except Exception:
        return False


def _has_disk_headroom(path: Path, min_free_mb: int) -> bool:
    try:
        usage = shutil.disk_usage(str(path))
        return usage.free >= (min_free_mb * 1024 * 1024)
    except Exception:
        return True  # be permissive if unknown


def _normalize_requirements(reqs: Optional[Iterable[str]]) -> Set[str]:
    norm: Set[str] = set()
    if not reqs:
        return norm
    try:
        for r in reqs:
            if r is None:
                continue
            norm.add(str(r).strip().lower())
    except TypeError:
        # Single string
        norm.add(str(reqs).strip().lower())
    return norm


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _resolve_mode(profile: str, plugin_requirements: Set[str]) -> DecompilationMode:
    raw = (os.getenv("AODS_DECOMPILATION_MODE") or "").strip().lower()
    if raw in {"minimal", "min"}:
        mode = DecompilationMode.MINIMAL
    elif raw in {"complete", "full"}:
        mode = DecompilationMode.COMPLETE
    elif raw in {"optimized", "opt"}:
        mode = DecompilationMode.OPTIMIZED
    else:
        # Default by profile
        mode = DecompilationMode.OPTIMIZED if profile == "production" else DecompilationMode.MINIMAL

    # Elevate from minimal if a plugin requires features (e.g., imports, resources, assets)
    if mode == DecompilationMode.MINIMAL and (
        "imports" in plugin_requirements
        or "resources" in plugin_requirements
        or "res" in plugin_requirements
        or "assets" in plugin_requirements
    ):
        mode = DecompilationMode.OPTIMIZED
    return mode


def get_decompilation_policy(
    apk_path: str,
    profile: str = "production",
    plugin_requirements: Optional[Iterable[str]] = None,
    preferred_output_root: Optional[str] = None,
) -> DecompilationPolicy:
    requirements = _normalize_requirements(plugin_requirements)

    # Defaults
    is_wsl = _is_wsl()
    default_mem_mb = 1024 if is_wsl else 2048
    default_threads = 1 if is_wsl else max(2, (os.cpu_count() or 4) // 2)
    _default_out = os.path.join(tempfile.gettempdir(), "jadx_decompiled")
    output_root = Path(preferred_output_root or os.getenv("AODS_DECOMP_OUT", _default_out))

    # Use app package hint for folder name if available
    apk_name = Path(apk_path).stem
    out_dir = output_root / apk_name
    out_dir.mkdir(parents=True, exist_ok=True)

    # Disk headroom checks
    # Baseline: require 2GB free; WSL: require 1GB free
    min_free_mb = 1024 if is_wsl else 2048
    if not _has_disk_headroom(output_root, min_free_mb):
        # Try fallback root under current workspace
        workspace_root = Path(".").resolve() / "artifacts" / "jadx_decompiled"
        workspace_root.mkdir(parents=True, exist_ok=True)
        if _has_disk_headroom(workspace_root, min_free_mb):
            out_dir = workspace_root / apk_name
            out_dir.mkdir(parents=True, exist_ok=True)
        else:
            # Last resort: scale down memory/threads to reduce temp usage
            default_mem_mb = min(default_mem_mb, 768 if is_wsl else 1024)
            default_threads = 1

    # Determine mode (env + profile + plugin requirements)
    mode = _resolve_mode(profile, requirements)

    # Safe flags – avoid raw/banned ones here; keep minimal set
    flags: List[str] = []

    if mode == DecompilationMode.MINIMAL:
        # Highly constrained output to be fast and lightweight
        flags.extend(["--no-res", "--no-imports", "--no-debug-info"])  # negative flags OK in minimal
    elif mode == DecompilationMode.OPTIMIZED:
        # Balanced: keep structures but drop debug info; allow env override to drop imports
        flags.extend(["--no-debug-info"])  # allowed by tests
        if not _env_bool("AODS_DECOMP_INCLUDE_IMPORTS", True):
            flags.append("--no-imports")
    else:  # COMPLETE
        # No forced negative flags; retain as much info as possible
        pass

    # Enable deobfuscation for non-lightning profiles
    if profile not in ("lightning", "fast"):
        flags.extend(["--deobf"])  # safe general deobf

    # NOTE: Thread count is NOT added to flags here because:
    # 1. The adaptive decision engine in jadx_decompilation_manager.py already handles thread count
    # 2. JADX fails with "Can only specify option --threads-count once" if duplicated
    # The default_threads value is still returned in the policy for reference by other components

    # Compute flags_version fingerprint for cache keying
    flags_hash_input = mode.value + "|" + "|".join(sorted(flags))
    flags_version = hashlib.md5(flags_hash_input.encode()).hexdigest()[:8]

    # Disk headroom status (already computed above at line 111)
    disk_ok = _has_disk_headroom(output_root, min_free_mb)

    # Return policy
    return DecompilationPolicy(
        output_dir=str(out_dir),
        max_threads=default_threads,
        memory_limit_mb=default_mem_mb,
        flags=flags,
        mode=mode,
        reason=("wsl" if is_wsl else "standard"),
        flags_version=flags_version,
        disk_ok=disk_ok,
    )


class DecompilationPolicyResolver:
    """Resolver facade to support test-facing API."""

    def resolve_policy(
        self,
        apk_path: str,
        profile: str = "production",
        plugin_requirements: Optional[Iterable[str]] = None,
        preferred_output_root: Optional[str] = None,
    ) -> DecompilationPolicy:
        return get_decompilation_policy(
            apk_path=apk_path,
            profile=profile,
            plugin_requirements=plugin_requirements,
            preferred_output_root=preferred_output_root,
        )
