"""
AutoResearch API routes - read-only experiment history and config.

Exposes experiment history from SQLite and parameter space configuration.
All endpoints are admin-only (autoresearch modifies production configs).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Header, Query

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)

from core.api.auth_helpers import _require_roles

router = APIRouter(tags=["autoresearch"])

REPO_ROOT = Path(__file__).parent.parent.parent.parent
THRESHOLDS_PATH = REPO_ROOT / "artifacts" / "ml_thresholds.json"


@router.get("/autoresearch/experiments/recent")
def get_recent_experiments(
    n: int = Query(20, ge=1, le=200),
    run_id: Optional[str] = Query(None, max_length=128),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Get the most recent N experiments."""
    _require_roles(authorization, ["admin"])
    history = _get_history()
    if history is None:
        return {"experiments": [], "total": 0}
    experiments = history.get_recent(n=n, run_id=run_id)
    return {"experiments": experiments, "total": len(experiments)}


@router.get("/autoresearch/experiments/best")
def get_best_experiments(
    n: int = Query(5, ge=1, le=100),
    run_id: Optional[str] = Query(None, max_length=128),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Get the top N experiments by AQS score."""
    _require_roles(authorization, ["admin"])
    history = _get_history()
    if history is None:
        return {"experiments": [], "total": 0}
    experiments = history.get_best(n=n, run_id=run_id)
    return {"experiments": experiments, "total": len(experiments)}


@router.get("/autoresearch/experiments/accepted")
def get_accepted_experiments(
    run_id: Optional[str] = Query(None, max_length=128),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Get all accepted (improvement-producing) experiments."""
    _require_roles(authorization, ["admin"])
    history = _get_history()
    if history is None:
        return {"experiments": [], "total": 0}
    experiments = history.get_accepted(run_id=run_id)
    return {"experiments": experiments, "total": len(experiments)}


@router.get("/autoresearch/config")
def get_autoresearch_config(
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Get AutoResearch parameter space and configuration."""
    _require_roles(authorization, ["admin"])
    from core.autoresearch.config import (
        TIER_1_PARAMS,
        TIER_2_PARAMS,
        TIER_3_PARAMS,
        ExperimentConfig,
    )

    defaults = ExperimentConfig()
    tiers = {
        "tier_1": [p.model_dump() for p in TIER_1_PARAMS],
        "tier_2": [p.model_dump() for p in TIER_2_PARAMS],
        "tier_3": [p.model_dump() for p in TIER_3_PARAMS],
    }
    return {
        "defaults": defaults.model_dump(),
        "parameter_space": tiers,
        "total_params": sum(len(v) for v in tiers.values()),
        "aqs_formula": "0.6 * detection - 0.3 * fp_penalty + 0.1 * stability",
    }


@router.get("/autoresearch/current-thresholds")
def get_current_thresholds(
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Get current ml_thresholds.json contents."""
    _require_roles(authorization, ["admin"])
    if not THRESHOLDS_PATH.exists():
        return {"thresholds": {}, "exists": False}
    try:
        data = json.loads(THRESHOLDS_PATH.read_text(encoding="utf-8"))
        return {"thresholds": data, "exists": True}
    except (json.JSONDecodeError, OSError):
        return {"thresholds": {}, "exists": False}


def _get_history():
    """Lazy-load ExperimentHistory to avoid SQLite init at import time."""
    try:
        from core.autoresearch.history import ExperimentHistory
        return ExperimentHistory()
    except Exception as e:
        logger.debug("autoresearch_history_unavailable", err=str(e))
        return None
