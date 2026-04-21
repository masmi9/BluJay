"""
core.native_decompiler.analysis_budget - Budget-controlled native binary analysis.

Manages the resource budget for Ghidra decompilation: which binaries to
analyze, how many, and for how long. Prevents unbounded scan time by
selecting the most valuable .so files within a time/count budget.

Default behavior (opt-in only):
- AODS_NATIVE_DEEP=0 (default): skip Ghidra decompilation entirely
- AODS_NATIVE_DEEP=1: analyze up to max_binaries with per-binary timeout
- AODS_NATIVE_DEEP=all: analyze all .so files (WARNING: can take hours)

Selection strategy:
- Skip tiny stubs (< 50KB) - too small to contain meaningful code
- Skip well-known SDK libraries (libflutter.so, libreactnative.so, etc.)
- Prioritize by: file size (larger = more code) × name interest score
- Name interest: crypto/ssl/auth/security in name → higher priority
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)


@dataclass
class NativeAnalysisConfig:
    """Configuration for native binary analysis budget."""
    enabled: bool = False
    max_binaries: int = 5
    per_binary_timeout: int = 180  # seconds
    max_total_time: int = 600  # seconds (10 min total budget)
    min_binary_size_kb: int = 50  # skip stubs smaller than this
    skip_sdk_libraries: bool = True

    @classmethod
    def from_env(cls) -> "NativeAnalysisConfig":
        """Load config from environment variables."""
        mode = os.environ.get("AODS_NATIVE_DEEP", "0").lower()

        if mode in ("0", "false", "no", ""):
            return cls(enabled=False)

        config = cls(enabled=True)

        if mode == "all":
            config.max_binaries = 999
            config.max_total_time = 3600  # 1 hour cap even for "all"

        max_b = os.environ.get("AODS_NATIVE_MAX_BINARIES")
        if max_b:
            try:
                config.max_binaries = max(1, min(100, int(max_b)))
            except ValueError:
                pass

        timeout = os.environ.get("AODS_NATIVE_TIMEOUT")
        if timeout:
            try:
                config.per_binary_timeout = max(30, min(600, int(timeout)))
            except ValueError:
                pass

        total = os.environ.get("AODS_NATIVE_TOTAL_TIME")
        if total:
            try:
                config.max_total_time = max(60, min(7200, int(total)))
            except ValueError:
                pass

        return config


# SDK libraries that are not worth decompiling (massive, well-known, no vulns)
_SDK_SKIP_PATTERNS = [
    re.compile(r"libflutter\.so", re.IGNORECASE),
    re.compile(r"libreactnative", re.IGNORECASE),
    re.compile(r"libhermes", re.IGNORECASE),
    re.compile(r"libv8\.so", re.IGNORECASE),
    re.compile(r"libchrome\.so", re.IGNORECASE),
    re.compile(r"libwebviewchromium", re.IGNORECASE),
    re.compile(r"libmonodroid", re.IGNORECASE),
    re.compile(r"libxamarin", re.IGNORECASE),
    re.compile(r"libunity\.so", re.IGNORECASE),
    re.compile(r"libUE4\.so", re.IGNORECASE),
    re.compile(r"libgdx\.so", re.IGNORECASE),
]

# Names that suggest security-relevant code (higher analysis priority)
_INTEREST_KEYWORDS = [
    "crypto", "ssl", "tls", "auth", "security", "cipher", "encrypt",
    "decrypt", "sign", "verify", "token", "secret", "key", "cert",
    "native", "jni", "bridge", "hook", "inject", "obfusc",
]


def _is_sdk_library(name: str) -> bool:
    """Check if a .so file is a well-known SDK library."""
    return any(p.search(name) for p in _SDK_SKIP_PATTERNS)


def _interest_score(name: str) -> float:
    """Score a binary name by security relevance (0.0-1.0)."""
    name_lower = name.lower()
    matches = sum(1 for kw in _INTEREST_KEYWORDS if kw in name_lower)
    return min(1.0, matches * 0.3)


def select_binaries(
    binary_paths: List[Path],
    config: NativeAnalysisConfig,
) -> List[Path]:
    """Select the most valuable binaries for analysis within budget.

    Args:
        binary_paths: All .so files found in the APK.
        config: Analysis budget configuration.

    Returns:
        Ordered list of binaries to analyze (most valuable first).
    """
    candidates = []

    for bp in binary_paths:
        name = bp.name
        try:
            size_kb = bp.stat().st_size / 1024
        except OSError:
            continue

        # Skip tiny stubs
        if size_kb < config.min_binary_size_kb:
            continue

        # Skip SDK libraries
        if config.skip_sdk_libraries and _is_sdk_library(name):
            logger.debug("native_skip_sdk", binary=name, size_kb=round(size_kb))
            continue

        # Score = size_weight * (1 + interest_bonus)
        # Larger files have more code; interesting names get a boost
        size_weight = min(size_kb / 1000, 10.0)  # Cap at 10MB weight
        interest = _interest_score(name)
        score = size_weight * (1.0 + interest)

        candidates.append((score, size_kb, bp))

    # Sort by score descending, take top max_binaries
    candidates.sort(key=lambda x: x[0], reverse=True)
    selected = [bp for _, _, bp in candidates[:config.max_binaries]]

    if selected:
        logger.info(
            "native_binaries_selected",
            total_found=len(binary_paths),
            candidates=len(candidates),
            selected=len(selected),
            names=[p.name for p in selected],
        )

    return selected


def estimate_analysis_time(
    binaries: List[Path],
    config: NativeAnalysisConfig,
) -> Dict[str, Any]:
    """Estimate total analysis time for user display.

    Returns:
        Dict with estimated_minutes, binary_count, total_size_mb,
        and per_binary estimates.
    """
    total_size = sum(bp.stat().st_size for bp in binaries if bp.exists())
    total_size_mb = round(total_size / (1024 * 1024), 1)

    # Rough estimate: ~1 min per MB of binary, capped at per_binary_timeout
    per_binary = []
    total_est_seconds = 0
    for bp in binaries:
        size_mb = bp.stat().st_size / (1024 * 1024) if bp.exists() else 0
        est_seconds = min(size_mb * 60, config.per_binary_timeout)
        total_est_seconds += est_seconds
        per_binary.append({
            "name": bp.name,
            "size_mb": round(size_mb, 1),
            "est_seconds": round(est_seconds),
        })

    # Cap at max_total_time
    total_est_seconds = min(total_est_seconds, config.max_total_time)

    return {
        "binary_count": len(binaries),
        "total_size_mb": total_size_mb,
        "estimated_minutes": round(total_est_seconds / 60, 1),
        "estimated_seconds": round(total_est_seconds),
        "per_binary": per_binary,
        "budget": {
            "max_binaries": config.max_binaries,
            "per_binary_timeout": config.per_binary_timeout,
            "max_total_time": config.max_total_time,
        },
    }
