"""
AODS API ML & Explainability Routes
====================================

ML training, calibration, thresholds, metrics, and explainability endpoints.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Header, HTTPException

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from core.api.shared_state import (
    REPO_ROOT,
    _ML_STATUS_LOCK,
    _ML_STATUS,
    check_expensive_op_rate,
)
from core.api.auth_helpers import _require_roles, _audit, _now_iso

router = APIRouter(tags=["ml"])


@router.get("/explain/status")
def explain_status(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """Return explainability subsystem status and available methods."""
    _require_roles(authorization, ["admin", "analyst"])
    try:
        from core.ml.explainability_facade import ExplainabilityFacade

        facade = ExplainabilityFacade()
        return facade.get_status()
    except HTTPException:
        raise
    except Exception:
        return {"available_methods": ["rule-based"]}


@router.post("/explain/finding")
def explain_finding(body: Dict[str, Any], authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """Generate an explanation for a vulnerability finding.

    Accepts a finding dictionary and returns a unified explanation
    using the best available method (SHAP/LIME > confidence > rule-based).
    """
    user_info = _require_roles(authorization, ["admin", "analyst"])
    try:
        from core.ml.explainability_facade import ExplainabilityFacade

        facade = ExplainabilityFacade()
        explanation = facade.explain_finding(body)
        method = explanation.method if hasattr(explanation, "method") else "unknown"
        _audit("explain_finding", user_info.get("user", "unknown"), details={"method": method})
        return explanation.to_dict()
    except Exception:
        raise HTTPException(status_code=500, detail="Explanation failed")


# ------------------------ ML Training & Calibration ------------------------ #


def _ml_set_status(**kwargs: Any) -> None:
    with _ML_STATUS_LOCK:
        _ML_STATUS.update(kwargs)


@router.get("/ml/training/status")
def ml_training_status(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst"])  # Analysts allowed
    with _ML_STATUS_LOCK:
        return dict(_ML_STATUS)


def _run_calibration_stub(requested_by: str = "unknown") -> None:
    """Fallback stub calibration when venv or training script is unavailable."""
    try:
        _ml_set_status(running=True, phase="calibrating", startedAt=_now_iso())
        time.sleep(0.2)
        try:
            out_dir = REPO_ROOT / "artifacts" / "ml_baselines"
            out_dir.mkdir(parents=True, exist_ok=True)
            summary_path = out_dir / "summary.json"
            payload = {
                "status": "OK", "updatedAt": _now_iso(),
                "notes": "stub calibration run (venv/script unavailable)",
            }
            with summary_path.open("w", encoding="utf-8") as f:
                f.write(json.dumps(payload, indent=2))
            _ml_set_status(summary=str(summary_path.relative_to(REPO_ROOT)))
        except Exception:
            pass
    finally:
        _ml_set_status(running=False, lastRun=_now_iso(), phase=None)
        _audit("ml_calibration_complete", requested_by)


def _run_calibration_job(requested_by: str = "unknown") -> None:
    venv_python = REPO_ROOT / "aods_venv" / "bin" / "python"
    train_script = REPO_ROOT / "scripts" / "train_models.py"

    # Fallback to stub if venv or script is missing
    if not venv_python.is_file() or not train_script.is_file():
        logger.warning(
            "ml_calibration_fallback_to_stub",
            venv_exists=venv_python.is_file(),
            script_exists=train_script.is_file(),
        )
        return _run_calibration_stub(requested_by)

    try:
        _ml_set_status(running=True, phase="initializing", startedAt=_now_iso())
        _audit("ml_calibration_start_real", requested_by)

        env = os.environ.copy()
        env["PYTHONPATH"] = str(REPO_ROOT)

        _ml_set_status(phase="calibrating")
        logger.info("ml_calibration_subprocess_start", script=str(train_script))

        result = subprocess.run(
            [str(venv_python), str(train_script), "--calibration"],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.stdout:
            logger.info("ml_calibration_stdout", output=result.stdout[-2000:])
        if result.stderr:
            logger.warning("ml_calibration_stderr", output=result.stderr[-2000:])

        if result.returncode != 0:
            error_msg = (result.stderr or result.stdout or "unknown error")[-500:]
            logger.error(
                "ml_calibration_failed",
                returncode=result.returncode,
                error=error_msg,
            )
            _ml_set_status(
                phase="failed",
                error=f"calibration exited with code {result.returncode}: {error_msg}",
            )
            return

        # Success - try to locate and record the real summary
        _ml_set_status(phase="complete", error=None)
        summary_candidates = [
            REPO_ROOT / "artifacts" / "ml_datasets" / "training_summary.json",
            REPO_ROOT / "models" / "unified_ml" / "calibration_summary.json",
            REPO_ROOT / "models" / "calibration" / "calibration_summary.json",
        ]
        for sp in summary_candidates:
            if sp.is_file():
                try:
                    _ml_set_status(summary=str(sp.relative_to(REPO_ROOT)))
                    logger.info("ml_calibration_summary_found", path=str(sp))
                except Exception:
                    _ml_set_status(summary=str(sp))
                break

    except subprocess.TimeoutExpired:
        logger.error("ml_calibration_timeout", timeout_seconds=300)
        _ml_set_status(phase="failed", error="calibration timed out after 300 seconds")
    except Exception as exc:
        logger.error("ml_calibration_exception", error_type=type(exc).__name__)
        _ml_set_status(phase="failed", error="calibration process failed")
    finally:
        with _ML_STATUS_LOCK:
            _ML_STATUS.update({"running": False, "lastRun": _now_iso()})
            if _ML_STATUS.get("phase") != "failed":
                _ML_STATUS["phase"] = None
        _audit("ml_calibration_complete", requested_by)


@router.post("/ml/training/run_calibration")
def ml_training_run_calibration(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    info = _require_roles(authorization, ["admin", "analyst"])  # Analysts allowed
    if os.getenv("AODS_ML_CALIBRATION_ENABLE", "1") != "1":
        raise HTTPException(status_code=503, detail="ML calibration disabled")
    user = info.get("user", "unknown")
    check_expensive_op_rate("ml_calibration", user)
    with _ML_STATUS_LOCK:
        if _ML_STATUS.get("running"):
            return {"status": "already_running", "startedAt": _ML_STATUS.get("startedAt")}
        # Mark as running BEFORE releasing the lock to prevent concurrent starts
        _ML_STATUS["running"] = True
        _ML_STATUS["startedAt"] = _now_iso()
    t = threading.Thread(target=_run_calibration_job, args=(user,), daemon=True)
    t.start()
    _audit("ml_calibration_start", info.get("user", "api"))
    return {"status": "started"}


@router.get("/ml/calibration/summary")
def get_calibration_summary(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """Return latest calibration training summary JSON if present."""
    _require_roles(authorization, ["admin", "analyst"])
    p = REPO_ROOT / "artifacts" / "ml_datasets" / "training_summary.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="calibration summary not found")
    try:
        return json.loads(p.read_text(errors="replace"))
    except Exception:
        raise HTTPException(status_code=500, detail="failed to read calibration summary")


@router.get("/ml/thresholds")
def get_ml_thresholds(
    path: Optional[str] = None, authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Return current ML thresholds (from artifacts or a provided path)."""
    _require_roles(authorization, ["admin", "analyst"])
    try:
        if path:
            p = Path(path).resolve()
            if not str(p).startswith(str(REPO_ROOT.resolve())):
                raise HTTPException(status_code=403, detail="path outside repository")
            if not p.exists():
                raise HTTPException(status_code=404, detail="thresholds file not found")
            txt = p.read_text(errors="replace")
            try:
                return json.loads(txt)
            except Exception:
                # try yaml
                try:
                    import yaml  # type: ignore

                    return yaml.safe_load(txt) or {}
                except Exception:
                    raise HTTPException(status_code=500, detail="failed to parse thresholds")
        # default locations
        from core.ml.thresholds_loader import load_thresholds

        data = load_thresholds()
        if not data:
            raise HTTPException(status_code=404, detail="thresholds not configured")
        return data
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="failed to load thresholds")


@router.get("/ml/metrics/pr")
def get_pr_metrics(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """Return global/per-category/per-plugin PR metrics if present."""
    _require_roles(authorization, ["admin", "analyst"])
    p = REPO_ROOT / "artifacts" / "ml_datasets" / "metrics" / "pr_metrics.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="pr metrics not found")
    try:
        return json.loads(p.read_text(errors="replace"))
    except Exception:
        raise HTTPException(status_code=500, detail="failed to read pr metrics")


@router.get("/ml/metrics/fp_breakdown")
def get_fp_breakdown(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """Return simple FP counts by plugin and category from the labeled dataset if present."""
    _require_roles(authorization, ["admin", "analyst"])
    ds = REPO_ROOT / "artifacts" / "ml_datasets" / "dataset_combined_fdroid1k_vuln_androgoat_v4.json"
    if not ds.exists():
        raise HTTPException(status_code=404, detail="labeled dataset not found")
    try:
        raw = json.loads(ds.read_text(errors="replace"))
        if not isinstance(raw, list):
            raise HTTPException(status_code=500, detail="dataset format invalid (expected list)")
        fp_by_plugin: Dict[str, int] = {}
        fp_by_category: Dict[str, int] = {}
        for it in raw:
            try:
                y = 1 if int(it.get("y", 0)) == 1 else 0
            except Exception:
                y = 0
            if y == 0:
                plg = str(it.get("plugin_source", ""))
                cat = str(it.get("category", ""))
                fp_by_plugin[plg] = fp_by_plugin.get(plg, 0) + 1
                fp_by_category[cat] = fp_by_category.get(cat, 0) + 1
        return {"dataset": str(ds), "fp_by_plugin": fp_by_plugin, "fp_by_category": fp_by_category}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="failed to read dataset")


@router.post("/ml/metrics/eval_thresholds")
def eval_thresholds(payload: Dict[str, Any], authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """Evaluate precision/recall given a thresholds mapping on the labeled dataset.

    Body schema:
    {
      "thresholds": {"default": float, "categories": {...}, "plugins": {...}},
      "dataset": "optional/path/to/dataset.json"
    }
    """
    _require_roles(authorization, ["admin", "analyst"])
    try:
        ds_path = payload.get("dataset")
        if not ds_path:
            ds_path = str(REPO_ROOT / "artifacts" / "ml_datasets" / "dataset_combined_fdroid1k_vuln_androgoat_v4.json")
        p = Path(ds_path).resolve()
        if not str(p).startswith(str(REPO_ROOT.resolve())):
            raise HTTPException(status_code=403, detail="dataset path outside repository")
        if not p.exists():
            raise HTTPException(status_code=404, detail="dataset not found")
        try:
            data = json.loads(p.read_text(errors="replace"))
            if not isinstance(data, list):
                data = []
        except Exception:
            raise HTTPException(status_code=500, detail="failed to read dataset")
        th = payload.get("thresholds") or {}
        # Reuse gate's evaluator
        try:
            from tools.ci.gates.detection_accuracy_evaluator import evaluate as eval_fn  # type: ignore
        except Exception:
            raise HTTPException(status_code=500, detail="evaluator import failed")
        metrics = eval_fn(data, th if isinstance(th, dict) else {})
        return {"dataset": ds_path, "metrics": metrics}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="evaluation failed")


@router.get("/ml/analytics/summary")
def get_ml_analytics_summary(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """Return learning analytics summary from the most recent scan report."""
    _require_roles(authorization, ["admin", "analyst"])
    reports_dir = REPO_ROOT / "reports"
    if not reports_dir.exists():
        raise HTTPException(status_code=404, detail="reports directory not found")
    try:
        candidates = sorted(reports_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for rp in candidates[:10]:
            try:
                data = json.loads(rp.read_text(errors="replace"))
                summary = data.get("learning_analytics_summary")
                if summary and isinstance(summary, dict):
                    return {"source": rp.name, "summary": summary}
            except Exception:
                continue
        # No report had the field - try generating a fresh summary
        try:
            from core.shared_infrastructure.learning_analytics_dashboard import (
                LearningAnalyticsDashboard,
                generate_executive_summary_for_dashboard,
                AnalyticsTimeframe,
            )
            dashboard = LearningAnalyticsDashboard()
            summary = generate_executive_summary_for_dashboard(dashboard, AnalyticsTimeframe.LAST_MONTH)
            if summary:
                return {"source": "generated", "summary": summary}
        except Exception:
            pass
        raise HTTPException(status_code=404, detail="no learning analytics summary available")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="failed to read analytics summary")


@router.get("/ml/metrics/detection_accuracy/summary")
def get_detection_accuracy_summary(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """Return the latest detection accuracy gate summary if present."""
    _require_roles(authorization, ["admin", "analyst"])
    base = REPO_ROOT / "artifacts" / "ci_gates" / "detection_accuracy"
    if not base.exists():
        raise HTTPException(status_code=404, detail="detection accuracy artifacts missing")
    try:
        main = base / "summary.json"
        if main.exists():
            return json.loads(main.read_text(errors="replace"))
        candidates = sorted(base.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for p in candidates:
            try:
                return json.loads(p.read_text(errors="replace"))
            except Exception:
                continue
        raise HTTPException(status_code=404, detail="no summary found")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="failed to read detection accuracy summary")
