#!/usr/bin/env python3
from __future__ import annotations

import os
from typing import Dict, Any


def is_shadow_mode_enabled() -> bool:
    return os.environ.get("AODS_FRIDA_SHADOW_MODE", "0") == "1"


def choose_injection_mode(features: Dict[str, Any]) -> str:
    """
    Skeleton ML planner: returns a mode hint using heuristics only in shadow mode.
    This function must not change behavior; callers should log only.
    """
    pkg = str(features.get("package", ""))
    # simple heuristic placeholder
    if "bank" in pkg.lower():
        return "attach"
    return "spawn"
