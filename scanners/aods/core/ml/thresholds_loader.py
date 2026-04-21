#!/usr/bin/env python3
"""
Optional loader for per-category/per-plugin decision thresholds.

Search order (first found wins):
- Env AODS_ML_THRESHOLDS_PATH (json or yaml)
- artifacts/ml_thresholds.json
- artifacts/ml_thresholds.yml

Schema:
{
  "default": 0.5,
  "categories": { "webview": 0.7, ... },
  "plugins": { "network_cleartext_traffic": 0.8, ... }
}
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional
import json
import os


def _safe_read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _load_yaml(text: str) -> Dict[str, Any]:
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text) or {}
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _load_json(text: str) -> Dict[str, Any]:
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def load_thresholds(path: Optional[str] = None) -> Dict[str, Any]:
    env_p = os.getenv("AODS_ML_THRESHOLDS_PATH")
    family = os.getenv("AODS_ML_FAMILY")
    candidates = [path, env_p]
    # Prefer family-specific thresholds if a family is specified
    if family:
        candidates.extend(
            [
                str(Path(f"artifacts/ml_thresholds/{family}.json")),
                str(Path(f"artifacts/ml_thresholds/{family}.yml")),
                str(Path(f"artifacts/ml_thresholds_{family}.json")),
                str(Path(f"artifacts/ml_thresholds_{family}.yml")),
            ]
        )
    # Generic fallbacks
    candidates.extend(
        [
            str(Path("artifacts/ml_thresholds.json")),
            str(Path("artifacts/ml_thresholds.yml")),
        ]
    )
    for cand in candidates:
        if not cand:
            continue
        p = Path(cand)
        if not p.exists() or not p.is_file():
            continue
        text = _safe_read_text(p)
        if p.suffix.lower() in (".yml", ".yaml"):
            data = _load_yaml(text)
        else:
            data = _load_json(text)
        if data:
            # Normalize structure
            out: Dict[str, Any] = {
                "default": float(data.get("default", 0.5)),
                "categories": {},
                "plugins": {},
            }
            cats = data.get("categories") or {}
            if isinstance(cats, dict):
                out["categories"] = {str(k): float(v) for k, v in cats.items() if _is_num(v)}
            plugs = data.get("plugins") or {}
            if isinstance(plugs, dict):
                out["plugins"] = {str(k): float(v) for k, v in plugs.items() if _is_num(v)}
            return out
    return {}


def _is_num(v: Any) -> bool:
    try:
        float(v)
        return True
    except Exception:
        return False


__all__ = ["load_thresholds"]
