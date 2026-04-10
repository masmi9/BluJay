"""
IODS Execution Setup – initializes the execution context from parsed args.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from core.logging_config import get_logger
from core.cli.output_manager import OutputManager

logger = get_logger(__name__)

_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "ios_vulnerability_patterns.yaml"
_ML_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "ios_ml_config.json"


@dataclass
class ExecutionContext:
    args: Any
    output_mgr: OutputManager
    config_data: Dict[str, Any] = field(default_factory=dict)
    ml_config: Dict[str, Any] = field(default_factory=dict)
    ml_enabled: bool = True
    static_only: bool = False
    dynamic_enabled: bool = False
    parallel: bool = True
    app_profile: str = "production"
    ml_fp_threshold: float = 0.15


def initialize_execution(args) -> ExecutionContext:
    """Build and validate the execution context."""
    output_mgr = OutputManager(verbose=getattr(args, "verbose", False), quiet=getattr(args, "quiet", False))

    # Apply env overrides
    if os.environ.get("IODS_DISABLE_ML", "0") == "1" or getattr(args, "disable_ml", False):
        os.environ["IODS_DISABLE_ML"] = "1"

    if getattr(args, "static_only", False):
        os.environ["IODS_STATIC_ONLY"] = "1"

    # Load config
    config_data = _load_yaml_config(_CONFIG_PATH)
    ml_config = _load_json_config(_ML_CONFIG_PATH)

    # ML threshold: env > CLI > config > default
    threshold = float(os.environ.get("IODS_ML_FP_THRESHOLD", "0"))
    if not threshold:
        threshold = getattr(args, "ml_fp_threshold", None) or 0.0
    if not threshold:
        app_profile = getattr(args, "app_profile", "production")
        ml_ctrl = config_data.get("ml_filtering_control", {})
        if app_profile == "production":
            threshold = float(ml_ctrl.get("production_app_ml_filtering_threshold", 0.05))
        else:
            threshold = float(ml_ctrl.get("vulnerable_app_ml_filtering_threshold", 0.15))
    if not threshold:
        threshold = 0.15

    ml_enabled = os.environ.get("IODS_DISABLE_ML", "0") != "1" and not getattr(args, "disable_ml", False)

    return ExecutionContext(
        args=args,
        output_mgr=output_mgr,
        config_data=config_data,
        ml_config=ml_config,
        ml_enabled=ml_enabled,
        static_only=getattr(args, "static_only", False) or args.mode == "safe",
        dynamic_enabled=not getattr(args, "static_only", False) and args.mode == "deep",
        parallel=not getattr(args, "sequential", False),
        app_profile=getattr(args, "app_profile", "production"),
        ml_fp_threshold=threshold,
    )


def _load_yaml_config(path: Path) -> Dict[str, Any]:
    if not path.exists():
        logger.warning("Config file not found", path=str(path))
        return {}
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning("Failed to load YAML config", path=str(path), error=str(e))
        return {}


def _load_json_config(path: Path) -> Dict[str, Any]:
    import json
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        logger.warning("Failed to load JSON config", path=str(path), error=str(e))
        return {}
