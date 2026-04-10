from __future__ import annotations

"""
Dynamic MSTG ID resolution for runtime hooks.

Loads a mapping from hook_name -> MSTG_ID from:
- Env var AODS_MSTG_DYNAMIC_MAP (JSON file path), else
- compliance/masvs_mstg/dynamic_map.json if present

If payload already contains an 'mstg_id', prefer that.
"""
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

_CACHED_MAP: Optional[Dict[str, str]] = None


def _load_map() -> Dict[str, str]:
    global _CACHED_MAP
    if _CACHED_MAP is not None:
        return _CACHED_MAP
    # Env override
    env_path = os.getenv("AODS_MSTG_DYNAMIC_MAP")
    candidates = []
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path("compliance/masvs_mstg/dynamic_map.json"))
    for c in candidates:
        try:
            if c.exists():
                data = json.loads(c.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict):
                    # normalize keys/values to strings
                    _CACHED_MAP = {str(k): str(v) for k, v in data.items()}
                    return _CACHED_MAP
        except Exception:
            continue
    _CACHED_MAP = {}
    return _CACHED_MAP


def resolve_mstg_id(hook_name: str, payload: Dict[str, Any] | None = None) -> Optional[str]:
    if isinstance(payload, dict):
        mid = payload.get("mstg_id")
        if isinstance(mid, str) and mid.strip():
            return mid.strip()
    m = _load_map()
    val = m.get(hook_name)
    return val.strip() if isinstance(val, str) and val.strip() else None
