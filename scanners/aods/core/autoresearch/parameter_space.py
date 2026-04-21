"""
core.autoresearch.parameter_space - Parameter read/write/snapshot.

Handles reading and writing tunable parameters to:
- artifacts/ml_thresholds.json (JSON dot-paths)
- config/vulnerability_patterns.yaml (yaml: prefixed paths)
- Environment variables (env: prefixed paths)

Never touches .py files. All config changes via JSON/YAML + env vars.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)

from .config import ParameterBounds

REPO_ROOT = Path(__file__).parent.parent.parent
THRESHOLDS_PATH = REPO_ROOT / "artifacts" / "ml_thresholds.json"
VULN_PATTERNS_PATH = REPO_ROOT / "config" / "vulnerability_patterns.yaml"


def _get_nested(data: dict, dotpath: str) -> Any:
    """Retrieve a value from a nested dict using dot-separated path.

    Supports integer indices for lists (e.g. 'dampening.range.0').
    """
    keys = dotpath.split(".")
    current = data
    for key in keys:
        if isinstance(current, list):
            try:
                current = current[int(key)]
            except (ValueError, IndexError):
                return None
        elif isinstance(current, dict):
            current = current.get(key)
            if current is None:
                return None
        else:
            return None
    return current


def _set_nested(data: dict, dotpath: str, value: Any) -> None:
    """Set a value in a nested dict using dot-separated path.

    Creates intermediate dicts as needed. Supports list indices.
    """
    keys = dotpath.split(".")
    current = data
    for i, key in enumerate(keys[:-1]):
        next_key = keys[i + 1]
        if isinstance(current, list):
            idx = int(key)
            while len(current) <= idx:
                current.append({})
            current = current[idx]
        elif isinstance(current, dict):
            if key not in current:
                # Create list if next key is numeric, else dict
                try:
                    int(next_key)
                    current[key] = []
                except ValueError:
                    current[key] = {}
            current = current[key]

    last_key = keys[-1]
    if isinstance(current, list):
        idx = int(last_key)
        while len(current) <= idx:
            current.append(None)
        current[idx] = value
    elif isinstance(current, dict):
        current[last_key] = value


def _read_json(path: Path) -> dict:
    """Read and parse a JSON file, returning empty dict on failure."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _write_json_atomic(path: Path, data: dict) -> None:
    """Atomic write: .tmp + rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.rename(path)


def _read_yaml(path: Path) -> dict:
    """Read and parse a YAML file."""
    if yaml is None:
        return {}
    try:
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except (OSError, Exception):
        return {}


def _write_yaml_atomic(path: Path, data: dict) -> None:
    """Atomic write YAML."""
    if yaml is None:
        logger.warning("yaml_not_available", msg="Cannot write YAML without PyYAML")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8")
    tmp.rename(path)


def snapshot_current() -> Dict[str, Any]:
    """Capture current state of all config files as a restorable snapshot."""
    snapshot: Dict[str, Any] = {}

    if THRESHOLDS_PATH.exists():
        snapshot["ml_thresholds"] = _read_json(THRESHOLDS_PATH)

    if VULN_PATTERNS_PATH.exists():
        snapshot["vulnerability_patterns"] = _read_yaml(VULN_PATTERNS_PATH)

    # Capture relevant env vars
    env_vars = {}
    for key in ("AODS_ML_FP_THRESHOLD",):
        val = os.environ.get(key)
        if val is not None:
            env_vars[key] = val
    snapshot["env_vars"] = env_vars

    return snapshot


def revert_to(snapshot: Dict[str, Any]) -> None:
    """Restore config files from a snapshot."""
    if "ml_thresholds" in snapshot:
        _write_json_atomic(THRESHOLDS_PATH, snapshot["ml_thresholds"])

    if "vulnerability_patterns" in snapshot:
        _write_yaml_atomic(VULN_PATTERNS_PATH, snapshot["vulnerability_patterns"])

    # Restore env vars
    for key, val in snapshot.get("env_vars", {}).items():
        os.environ[key] = val

    logger.info("config_reverted", files=list(snapshot.keys()))


def extract_current_values(bounds: List[ParameterBounds]) -> Dict[str, float]:
    """Read current values for all parameters in the bounds list."""
    thresholds = _read_json(THRESHOLDS_PATH) if THRESHOLDS_PATH.exists() else {}
    vuln_patterns = _read_yaml(VULN_PATTERNS_PATH) if VULN_PATTERNS_PATH.exists() else {}

    values: Dict[str, float] = {}
    for param in bounds:
        val = _resolve_param_value(param, thresholds, vuln_patterns)
        values[param.name] = val if val is not None else param.default_value

    return values


def _resolve_param_value(
    param: ParameterBounds,
    thresholds: dict,
    vuln_patterns: dict,
) -> Optional[float]:
    """Resolve a parameter's current value from its path."""
    path = param.json_path

    if path.startswith("env:"):
        env_var = path[4:]
        val = os.environ.get(env_var)
        return float(val) if val is not None else None

    if path.startswith("yaml:"):
        yaml_path = path[5:]
        raw = _get_nested(vuln_patterns, yaml_path)
        return float(raw) if raw is not None else None

    # Default: ml_thresholds.json dot-path
    raw = _get_nested(thresholds, path)
    return float(raw) if raw is not None else None


def apply_params(params: Dict[str, float], bounds: Optional[List[ParameterBounds]] = None) -> Dict[str, str]:
    """Apply parameter values to config files and env vars.

    Args:
        params: Dict mapping parameter name -> value.
        bounds: Parameter definitions (needed to resolve paths).
                If None, uses all tiers.

    Returns:
        Dict of env var overrides to pass to scan subprocess.
    """
    if bounds is None:
        from .config import TIER_1_PARAMS, TIER_2_PARAMS, TIER_3_PARAMS
        bounds = TIER_1_PARAMS + TIER_2_PARAMS + TIER_3_PARAMS

    bounds_by_name = {b.name: b for b in bounds}

    thresholds = _read_json(THRESHOLDS_PATH) if THRESHOLDS_PATH.exists() else {}
    vuln_patterns = _read_yaml(VULN_PATTERNS_PATH) if VULN_PATTERNS_PATH.exists() else {}

    json_dirty = False
    yaml_dirty = False
    env_overrides: Dict[str, str] = {}

    for name, value in params.items():
        bound = bounds_by_name.get(name)
        if bound is None:
            logger.warning("unknown_param", name=name)
            continue

        path = bound.json_path

        if path.startswith("env:"):
            env_var = path[4:]
            os.environ[env_var] = str(value)
            env_overrides[env_var] = str(value)

        elif path.startswith("yaml:"):
            yaml_path = path[5:]
            _set_nested(vuln_patterns, yaml_path, value)
            yaml_dirty = True

        else:
            _set_nested(thresholds, path, value)
            json_dirty = True

    if json_dirty:
        _write_json_atomic(THRESHOLDS_PATH, thresholds)

    if yaml_dirty:
        _write_yaml_atomic(VULN_PATTERNS_PATH, vuln_patterns)

    logger.info("params_applied", count=len(params), env_overrides=list(env_overrides.keys()))
    return env_overrides
