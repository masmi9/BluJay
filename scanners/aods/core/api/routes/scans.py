"""
AODS API Scan & Batch Routes
=============================

Scan management (start, progress, cancel, results), batch processing,
SSE streaming, and package confirmation endpoints.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Header, HTTPException, Query, UploadFile, File
from fastapi.responses import StreamingResponse

try:
    from core.logging_config import get_logger, bind_user_context

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

    def bind_user_context(**kw):
        return None  # type: ignore


from core.enterprise.rbac_manager import (
    ResourceType as RBACResourceType,
    Permission as RBACPermission,
)
from core.api.shared_state import (
    REPO_ROOT,
    DYNA_PATH,
    REPORTS_DIR,
    BATCH_JOBS_DIR,
    UPLOADS_DIR,
    AUDIT_LOG,
    _SESSIONS_LOCK,
    _SESSIONS,
    _BATCH_LOCK,
    _BATCH_JOBS,
    _get_cached_or_compute,
    _invalidate_file_cache,
    PACKAGE_CONFIDENCE_THRESHOLD,
    PACKAGE_CONFIRMATION_TIMEOUT,
    _CONFIRMATION_CLEANUP_INTERVAL,
    MAX_ACTIVE_SCANS_PER_USER,
    MAX_ACTIVE_SCANS_GLOBAL,
    COMPLETED_SESSION_TTL,
    COMPLETED_BATCH_TTL,
    MAX_BATCH_JOBS,
    SSE_IDLE_TIMEOUT,
    check_expensive_op_rate,
)
from core.api.auth_helpers import (
    _require_roles,
    _enforce_access,
    _can_access_resource,
    _audit,
    _now_iso,
    _redact_pii,
)

# Pydantic models and helpers imported from server (available since route modules
# are loaded inside build_app() after server.py's class definitions are executed)
from core.api.server import (
    StartScanRequest,
    PackageDetectionInfo,
    StartScanResponse,
    ScanProgressResponse,
    ScanResultSummary,
    ScanResultItem,
    StartBatchRequest,
    StartBatchResponse,
    AuditEvent,
    ConfirmPackageRequest,
    _validate_apk_file,
)

router = APIRouter(tags=["scans"])

_ACTIVE_SCAN_STATUSES = {"queued", "running", "awaiting_confirmation"}


def _check_scan_concurrency(owner: str) -> None:
    """Enforce per-user and global scan concurrency limits. Raises 429 if exceeded."""
    with _SESSIONS_LOCK:
        user_active = 0
        global_active = 0
        for sess in _SESSIONS.values():
            if sess.get("status") in _ACTIVE_SCAN_STATUSES:
                global_active += 1
                if sess.get("owner") == owner:
                    user_active += 1
    if user_active >= MAX_ACTIVE_SCANS_PER_USER:
        raise HTTPException(
            status_code=429,
            detail=f"too many active scans (limit {MAX_ACTIVE_SCANS_PER_USER} per user)",
        )
    if global_active >= MAX_ACTIVE_SCANS_GLOBAL:
        raise HTTPException(
            status_code=429,
            detail="server scan capacity reached, try again later",
        )


def _safe_bool_env(name: str, default: str = "0") -> str:
    val = os.getenv(name, default)
    return "1" if str(val).strip() in {"1", "true", "True", "yes"} else "0"


def _start_scan_subprocess(session_id: str, apk_path: Path) -> None:
    started = _now_iso()
    with _SESSIONS_LOCK:
        _SESSIONS[session_id].update({"status": "running", "startedAt": started})

    # Prefer running scans with the repo's virtual environment interpreter when available
    def _choose_python_executable() -> str:
        try:
            ve = os.environ.get("VIRTUAL_ENV")
            if ve:
                cand = Path(ve) / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
                if cand.exists():
                    return str(cand)
            cand2 = REPO_ROOT / "aods_venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            if cand2.exists():
                return str(cand2)
        except Exception:
            pass
        return sys.executable

    python_exec = _choose_python_executable()
    cmd = [python_exec, str(DYNA_PATH), "--apk", str(apk_path)]

    # Add confirmed package name if available (from package confirmation flow)
    with _SESSIONS_LOCK:
        confirmed_pkg = _SESSIONS.get(session_id, {}).get("confirmedPackage")
    if confirmed_pkg:
        cmd.extend(["--pkg", confirmed_pkg])

    # Respect resource-constrained defaults when applicable
    env = os.environ.copy()
    env.setdefault("AODS_RESOURCE_CONSTRAINED", _safe_bool_env("AODS_RESOURCE_CONSTRAINED", "0"))
    # API-initiated scans run non-interactively (auto-accept package names)
    env.setdefault("AODS_NON_INTERACTIVE", "1")
    # Apply per-request options via resolver and record effective options

    def _resolve_scan_env(base_env: Dict[str, str], session_id: str) -> Tuple[Dict[str, str], Dict[str, Any]]:
        resolved_env = dict(base_env)
        effective: Dict[str, Any] = {"applied": {}, "ignored": {}}
        with _SESSIONS_LOCK:
            s = dict(_SESSIONS.get(session_id) or {})
        # Legacy single flag (threshold filtering)
        if bool(s.get("enableThresholdFiltering")):
            resolved_env["AODS_REPORT_FILTER_BY_THRESHOLDS"] = "1"
            effective["applied"]["enableThresholdFiltering"] = True
        raw = s.get("scanOptions") or {}
        # Booleans

        def _apply_bool(opt_key: str, env_key: str):
            v = raw.get(opt_key, None)
            if v is None:
                return
            try:
                v_bool = bool(v)
            except Exception:
                effective["ignored"][opt_key] = "invalid bool"
                return
            if v_bool:
                resolved_env[env_key] = "1"
                effective["applied"][opt_key] = True
            else:
                resolved_env.pop(env_key, None)
                effective["applied"][opt_key] = False

        _apply_bool("staticOnly", "AODS_STATIC_ONLY_HARD")
        _apply_bool("resourceConstrained", "AODS_RESOURCE_CONSTRAINED")
        # Frida mode (role enforcement omitted here; UI/role gates elsewhere; keep conservative in API)
        fm = raw.get("fridaMode")
        if fm:
            fm_l = str(fm).lower()
            if fm_l in ("standard", "read_only", "advanced"):
                if resolved_env.get("AODS_STATIC_ONLY_HARD") == "1":
                    effective["ignored"]["fridaMode"] = "staticOnly active"
                else:
                    resolved_env["AODS_FRIDA_MODE"] = fm_l
                    effective["applied"]["fridaMode"] = fm_l
            else:
                effective["ignored"]["fridaMode"] = "invalid value"
        # maxWorkers (clamp conservatively if resource constrained)
        mw = raw.get("maxWorkers")
        if mw is not None:
            try:
                mw_i = max(1, min(64, int(mw)))
                if resolved_env.get("AODS_RESOURCE_CONSTRAINED") == "1":
                    if mw_i > 2:
                        mw_i = 2
                        effective.setdefault("reasons", {})["maxWorkers"] = "clamped under resourceConstrained"
                resolved_env["AODS_MAX_WORKERS"] = str(mw_i)
                effective["applied"]["maxWorkers"] = mw_i
            except Exception:
                effective["ignored"]["maxWorkers"] = "invalid int"
        # timeoutsProfile pass-through
        tp = raw.get("timeoutsProfile")
        if tp:
            tp_l = str(tp).lower()
            if tp_l in ("default", "slow", "fast"):
                resolved_env["AODS_TIMEOUTS_PROFILE"] = tp_l
                effective["applied"]["timeoutsProfile"] = tp_l
            else:
                effective["ignored"]["timeoutsProfile"] = "invalid value"
        # plugins include/exclude future support (record + env CSV)
        inc = raw.get("pluginsInclude")
        exc = raw.get("pluginsExclude")
        if isinstance(inc, list) and inc:
            try:
                resolved_env["AODS_PLUGINS_INCLUDE"] = ",".join([str(x) for x in inc if x])
                effective["applied"]["pluginsInclude"] = inc
            except Exception:
                effective["ignored"]["pluginsInclude"] = "invalid list"
        if isinstance(exc, list) and exc:
            try:
                resolved_env["AODS_PLUGINS_EXCLUDE"] = ",".join([str(x) for x in exc if x])
                effective["applied"]["pluginsExclude"] = exc
            except Exception:
                effective["ignored"]["pluginsExclude"] = "invalid list"
        return resolved_env, effective

    # Resolve and persist effective options
    try:
        env, effective = _resolve_scan_env(env, session_id)
        with _SESSIONS_LOCK:
            if session_id in _SESSIONS:
                _SESSIONS[session_id]["effectiveOptions"] = effective
    except Exception:
        effective = {"applied": {}, "ignored": {}}

    try:
        # Ensure repo root is on PYTHONPATH so dynamic plugin imports (e.g., plugins.*) resolve
        try:
            repo_root_str = str(REPO_ROOT)
            existing_pp = env.get("PYTHONPATH", "") if isinstance(env, dict) else ""
            parts = [p for p in existing_pp.split(":") if p]
            if repo_root_str not in parts:
                parts.insert(0, repo_root_str)
            env["PYTHONPATH"] = ":".join(parts)
        except Exception:
            pass

        # If using a specific venv interpreter, surface it in PATH and VIRTUAL_ENV for subprocesses
        try:
            if python_exec and os.path.isabs(python_exec):
                py_path = Path(python_exec)
                # Derive venv root from python path (…/bin/python or …/Scripts/python.exe)
                venv_root = (
                    py_path.parent.parent if py_path.name.lower().startswith("python") else py_path.parent.parent
                )
                if venv_root.exists():
                    env["VIRTUAL_ENV"] = str(venv_root)
                    bin_dir = venv_root / ("Scripts" if os.name == "nt" else "bin")
                    env["PATH"] = f"{str(bin_dir)}:{env.get('PATH', '')}"
        except Exception:
            pass

        # Apply cli options derived from scanOptions (mode/profile/formats)
        try:
            with _SESSIONS_LOCK:
                sess_for_cli = dict(_SESSIONS.get(session_id) or {})
            raw_cli = (
                (sess_for_cli.get("scanOptions") or {}) if isinstance(sess_for_cli.get("scanOptions"), dict) else {}
            )
            # mode
            mode = str(raw_cli.get("mode") or "").lower().strip()
            if mode in ("safe", "deep"):
                cmd.extend(["--mode", mode])
                try:
                    effective.setdefault("applied", {})["mode"] = mode
                except Exception:
                    pass
            elif mode:
                try:
                    effective.setdefault("ignored", {})["mode"] = "invalid value"
                except Exception:
                    pass
            # profile
            prof = str(raw_cli.get("profile") or "").lower().strip()
            if prof in ("lightning", "fast", "standard", "deep"):
                cmd.extend(["--profile", prof])
                try:
                    effective.setdefault("applied", {})["profile"] = prof
                except Exception:
                    pass
            elif prof:
                try:
                    effective.setdefault("ignored", {})["profile"] = "invalid value"
                except Exception:
                    pass
            # formats
            fmts = raw_cli.get("formats")
            if isinstance(fmts, list) and fmts:
                allowed = {"txt", "json", "csv", "html", "all"}
                vals = [str(x).lower().strip() for x in fmts if str(x).lower().strip() in allowed]
                if vals:
                    if "all" in vals:
                        vals = ["txt", "json", "csv", "html"]
                    cmd.append("--formats")
                    cmd.extend(vals)
                    try:
                        effective.setdefault("applied", {})["formats"] = vals
                    except Exception:
                        pass
                else:
                    try:
                        effective.setdefault("ignored", {})["formats"] = "invalid list"
                    except Exception:
                        pass
            else:
                # Default formats
                cmd.extend(["--formats", "json", "html"])
            # CI flags

            def _apply_flag_bool(key: str, cli: str):
                try:
                    v = raw_cli.get(key)
                    if v is None:
                        return
                    if bool(v):
                        cmd.append(cli)
                        effective.setdefault("applied", {})[key] = True
                    else:
                        effective.setdefault("applied", {})[key] = False
                except Exception:
                    effective.setdefault("ignored", {})[key] = "invalid bool"

            _apply_flag_bool("ciMode", "--ci-mode")
            _apply_flag_bool("failOnCritical", "--fail-on-critical")
            _apply_flag_bool("failOnHigh", "--fail-on-high")
            # frameworks
            fws = raw_cli.get("frameworks")
            if isinstance(fws, list) and fws:
                allowed_fw = {"flutter", "react_native", "xamarin", "pwa", "all"}
                vals_fw = [str(x).lower().strip() for x in fws if str(x).lower().strip() in allowed_fw]
                if "all" in vals_fw:
                    # Enforce full selection when 'all' is requested
                    vals_fw = ["flutter", "react_native", "xamarin", "pwa", "all"]
                if vals_fw:
                    cmd.append("--frameworks")
                    cmd.extend(vals_fw)
                    effective.setdefault("applied", {})["frameworks"] = vals_fw
                else:
                    effective.setdefault("ignored", {})["frameworks"] = "invalid list"
            # compliance (single)
            comp = str(raw_cli.get("compliance") or "").lower().strip()
            if comp == "all":
                # CLI does not support 'all' directly; default to OWASP for now
                cmd.extend(["--compliance", "owasp"])
                eff = effective.setdefault("applied", {})
                eff["complianceRequested"] = "all"
                eff["compliance"] = "owasp"
            elif comp in {"nist", "masvs", "owasp", "iso27001"}:
                cmd.extend(["--compliance", comp])
                effective.setdefault("applied", {})["compliance"] = comp
            elif comp:
                effective.setdefault("ignored", {})["compliance"] = "invalid value"
            # static-only
            if bool(raw_cli.get("staticOnly")):
                cmd.append("--static-only")
                effective.setdefault("applied", {})["staticOnly"] = True
            # max-workers (consider resource constrained)
            try:
                mw = raw_cli.get("maxWorkers")
                rc = bool(raw_cli.get("resourceConstrained"))
                if rc:
                    effective.setdefault("applied", {})["resourceConstrained"] = True
                if mw is not None or rc:
                    val = int(mw) if mw is not None else None
                    if val is not None and (val < 1 or val > 64):
                        effective.setdefault("ignored", {})["maxWorkers"] = "out of range"
                        val = None
                    # If resource constrained, clamp to 2
                    if rc:
                        val = 2 if (val is None or val > 2) else val
                    if val is not None:
                        cmd.extend(["--max-workers", str(val)])
                        effective.setdefault("applied", {})["maxWorkers"] = val
            except Exception:
                effective.setdefault("ignored", {})["maxWorkers"] = "invalid int"
            # ML config
            try:
                mc = raw_cli.get("mlConfidence")
                if mc is not None:
                    val = float(mc)
                    if 0.0 <= val <= 1.0:
                        cmd.extend(["--ml-confidence", str(val)])
                        effective.setdefault("applied", {})["mlConfidence"] = val
                    else:
                        effective.setdefault("ignored", {})["mlConfidence"] = "out of range"
            except Exception:
                effective.setdefault("ignored", {})["mlConfidence"] = "invalid float"
            mp = raw_cli.get("mlModelsPath")
            if isinstance(mp, str) and mp.strip():
                mp_resolved = Path(mp.strip()).resolve()
                try:
                    mp_resolved.relative_to(REPO_ROOT.resolve())
                    cmd.extend(["--ml-models-path", str(mp_resolved)])
                    effective.setdefault("applied", {})["mlModelsPath"] = str(mp_resolved)
                except ValueError:
                    effective.setdefault("ignored", {})["mlModelsPath"] = "path outside repository"
            # Dedup
            ds = str(raw_cli.get("dedupStrategy") or "").lower().strip()
            if ds in {"basic", "intelligent", "aggressive", "conservative"}:
                cmd.extend(["--dedup-strategy", ds])
                effective.setdefault("applied", {})["dedupStrategy"] = ds
            elif ds:
                effective.setdefault("ignored", {})["dedupStrategy"] = "invalid value"
            try:
                dt = raw_cli.get("dedupThreshold")
                if dt is not None:
                    val = float(dt)
                    if 0.0 <= val <= 1.0:
                        cmd.extend(["--dedup-threshold", str(val)])
                        effective.setdefault("applied", {})["dedupThreshold"] = val
                    else:
                        effective.setdefault("ignored", {})["dedupThreshold"] = "out of range"
            except Exception:
                effective.setdefault("ignored", {})["dedupThreshold"] = "invalid float"
            # Progressive analysis
            if bool(raw_cli.get("progressiveAnalysis")):
                cmd.append("--progressive-analysis")
                effective.setdefault("applied", {})["progressiveAnalysis"] = True
                try:
                    sr = raw_cli.get("sampleRate")
                    if sr is not None:
                        sval = float(sr)
                        if 0.1 <= sval <= 1.0:
                            cmd.extend(["--sample-rate", str(sval)])
                            effective.setdefault("applied", {})["sampleRate"] = sval
                        else:
                            effective.setdefault("ignored", {})["sampleRate"] = "out of range"
                except Exception:
                    effective.setdefault("ignored", {})["sampleRate"] = "invalid float"
            # Agent flags - set AODS_AGENT_ENABLED=1 in subprocess when UI requests agents
            agent_enabled = raw_cli.get("agentEnabled")
            if agent_enabled:
                env["AODS_AGENT_ENABLED"] = "1"
                allowed_steps = {"narrate", "verify", "triage", "remediate", "orchestrate", "pipeline"}
                agent_steps = raw_cli.get("agentSteps") or []
                if isinstance(agent_steps, list) and agent_steps:
                    valid_steps = [s for s in agent_steps if str(s).lower() in allowed_steps]
                    if "pipeline" in valid_steps:
                        cmd.append("--agent-pipeline")
                        effective.setdefault("applied", {})["agentSteps"] = ["pipeline"]
                    else:
                        for step in valid_steps:
                            cmd.append(f"--agent-{step}")
                        effective.setdefault("applied", {})["agentSteps"] = valid_steps
                else:
                    # No specific steps = enable all agents
                    cmd.append("--agent")
                    effective.setdefault("applied", {})["agentEnabled"] = True
        except Exception:
            # Fallback to default formats if any error
            try:
                if "--formats" not in cmd:
                    cmd.extend(["--formats", "json", "html"])
            except Exception:
                pass

        # Force unbuffered child output for real-time streaming
        env.setdefault("PYTHONUNBUFFERED", "1")
        proc = subprocess.Popen(
            cmd,
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            start_new_session=True,
        )

        with _SESSIONS_LOCK:
            _SESSIONS[session_id]["process"] = proc
            if not isinstance(_SESSIONS[session_id].get("logLines"), deque):
                _SESSIONS[session_id]["logLines"] = deque(maxlen=1000)
            try:
                _SESSIONS[session_id]["logLines"].append(f"interpreter: {python_exec}")
            except Exception:
                pass

        def _reader(stream, label: str):
            try:
                for line in iter(stream.readline, ""):
                    ln = line.rstrip("\n")
                    with _SESSIONS_LOCK:
                        s = _SESSIONS.get(session_id)
                        if not s:
                            break
                        lg = s.get("logLines")
                        if isinstance(lg, deque):
                            lg.append(("[stderr] " + ln) if label == "stderr" else ln)
                        # Detect agent progress from CLI output (CLIProgressReporter writes to stderr)
                        if label == "stderr":
                            ln_lower = ln.lower().strip()
                            # Agent step markers from CLIProgressReporter
                            if ": starting..." in ln_lower:
                                agent = ln.split("]")[-1].split(":")[0].strip() if "]" in ln else ""
                                s["agentStage"] = f"agent:{agent}:starting"
                                s["agentMessage"] = f"Running {agent} agent..."
                            elif ": completed" in ln_lower or ": success" in ln_lower:
                                agent = ln.split("]")[-1].split(":")[0].strip() if "]" in ln else ""
                                s["agentStage"] = f"agent:{agent}:complete"
                                s["agentMessage"] = f"{agent} agent complete"
                            elif "heuristic fallback" in ln_lower:
                                s["agentMessage"] = "Agent using heuristic fallback"
                            elif "agent pipeline" in ln_lower and "running" in ln_lower:
                                s["agentStage"] = "agents_running"
                                s["agentMessage"] = "Running agent pipeline..."
                            elif "agent pipeline complete" in ln_lower:
                                s["agentStage"] = "agents_complete"
            except Exception:
                pass
            finally:
                try:
                    stream.close()
                except Exception:
                    pass

        t_out = threading.Thread(target=_reader, args=(proc.stdout, "stdout"), daemon=True)
        t_err = threading.Thread(target=_reader, args=(proc.stderr, "stderr"), daemon=True)
        t_out.start()
        t_err.start()
        rc = proc.wait()
        try:
            t_out.join(timeout=1.0)
            t_err.join(timeout=1.0)
        except Exception:
            pass
        # Respect explicit cancellation
        with _SESSIONS_LOCK:
            cancel_req = bool((_SESSIONS.get(session_id) or {}).get("cancelRequested"))
        status = "completed" if (rc == 0 and not cancel_req) else ("cancelled" if cancel_req else "failed")
        finished = _now_iso()
        with _SESSIONS_LOCK:
            _SESSIONS[session_id].update(
                {
                    "status": status,
                    "returnCode": rc,
                    "finishedAt": finished,
                }
            )
        # Invalidate file cache when scan completes (new report may exist)
        _invalidate_file_cache("discover_results")
        try:
            with _SESSIONS_LOCK:
                _owner = (_SESSIONS.get(session_id) or {}).get("owner", "unknown")
            _audit(f"scan_{status}", _owner, session_id, {"returnCode": rc})
        except Exception:
            pass
    except Exception as e:
        finished = _now_iso()
        with _SESSIONS_LOCK:
            _SESSIONS[session_id].update(
                {
                    "status": "failed",
                    "error": type(e).__name__,
                    "finishedAt": finished,
                }
            )
        logger.error("scan_subprocess_failed", session_id=session_id, error_type=type(e).__name__)
        _invalidate_file_cache("discover_results")
        try:
            with _SESSIONS_LOCK:
                _owner = (_SESSIONS.get(session_id) or {}).get("owner", "unknown")
            _audit("scan_failed", _owner, session_id, {"error": type(e).__name__})
        except Exception:
            pass


def _coarse_progress(session_id: str) -> ScanProgressResponse:
    """
    Return coarse progress estimate for a scan session.

    Currently uses time-based estimation since richer telemetry (phase completion
    events from dyna.py) is not yet wired. Typical scan durations by profile:
    - lightning: ~30s, fast: ~2-3min, standard: ~5-8min, deep: ~15+min

    To implement richer telemetry:
    1. dyna.py would emit phase events (e.g., "plugin_started", "plugin_completed")
    2. Store phase progress in _SESSIONS[session_id]["phases"]
    3. Calculate pct from completed_phases / total_phases
    """
    with _SESSIONS_LOCK:
        s = _SESSIONS.get(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    status = s.get("status", "unknown")
    pct = 0.0
    stage = "running"
    if status == "running":
        # Time-based estimate: assume ~5 minute average scan (standard profile)
        # Progress ramps from 5% to 95% over expected duration
        started_at = s.get("startedAt")
        if started_at:
            try:
                from datetime import datetime

                start_time = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
                now = datetime.now(start_time.tzinfo) if start_time.tzinfo else datetime.now()
                elapsed_seconds = (now - start_time).total_seconds()
                # Estimate: ramp from 5% to 90% over 5 minutes (300s), cap at 95%
                expected_duration = 300.0
                pct = min(5.0 + (elapsed_seconds / expected_duration) * 85.0, 95.0)
            except Exception:
                pct = 10.0  # fallback if time parsing fails
        else:
            pct = 10.0  # fallback if no start time
    elif status == "completed":
        pct = 100.0
        stage = "completed"
    elif status == "failed":
        pct = 100.0
        stage = "failed"
    else:
        stage = status
    # Include agent progress info if available
    agent_msg = s.get("agentMessage")
    agent_stage = s.get("agentStage", "")
    message = s.get("error")

    # If scan plugins are done but agents are still running, show agent stage
    if status == "running" and agent_stage:
        if pct > 90:
            stage = agent_stage
            message = agent_msg

    return ScanProgressResponse(
        id=session_id,
        pct=pct,
        stage=stage,
        message=message or agent_msg,
        startedAt=s.get("startedAt"),
        finishedAt=s.get("finishedAt"),
    )


def _find_result_file(result_id: str) -> Optional[Path]:
    """Find a scan result JSON file by its stem ID across all search locations."""
    for search_dir in [REPORTS_DIR, REPO_ROOT, REPO_ROOT / "artifacts" / "reports"]:
        if not search_dir.exists():
            continue
        p = search_dir / f"{result_id}.json"
        if p.exists():
            return p
    return None


def _summarize_result(json_obj: Dict[str, Any]) -> ScanResultSummary:
    # Best-effort summary extraction across possible shapes
    summary = ScanResultSummary()
    try:
        # 1) Direct summary block
        if "summary" in json_obj and isinstance(json_obj["summary"], dict):
            s = json_obj["summary"]
            try:
                # Some reports use total_findings at root
                summary.findings = int(s.get("findings", s.get("total_findings", summary.findings)))
            except Exception:
                pass
            sev = s.get("severity", {})
            if isinstance(sev, dict) and sev:
                try:
                    summary.critical = int(sev.get("critical", summary.critical))
                except Exception:
                    pass
                try:
                    summary.high = int(sev.get("high", summary.high))
                except Exception:
                    pass
                try:
                    summary.medium = int(sev.get("medium", summary.medium))
                except Exception:
                    pass
                try:
                    summary.low = int(sev.get("low", summary.low))
                except Exception:
                    pass
                try:
                    summary.info = int(sev.get("info", sev.get("informational", summary.info)))
                except Exception:
                    pass
                return summary
            # No severity in summary - fall through to tally from vulnerabilities array

        # Helper to tally a list of finding-like objects
        def _norm_sev(v: Any) -> str:
            s = str(v or "").lower()
            if "crit" in s:
                return "critical"
            if "high" in s:
                return "high"
            if "med" in s:
                return "medium"
            if "low" in s:
                return "low"
            if "info" in s:
                return "info"
            return ""

        def _tally(arr: List[Dict[str, Any]]):
            c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for it in arr:
                sev = _norm_sev(
                    (it or {}).get("severity")
                    or (it or {}).get("Severity")
                    or (it or {}).get("risk")
                    or (it or {}).get("Risk")
                )
                if sev in c:
                    c[sev] += 1
            summary.critical = c["critical"]
            summary.high = c["high"]
            summary.medium = c["medium"]
            summary.low = c["low"]
            summary.info = c["info"]
            summary.findings = c["critical"] + c["high"] + c["medium"] + c["low"] + c["info"]

        # 2) Processed findings under context
        processed = None
        try:
            processed = json_obj.get("context", {}).get("processed_findings")
        except Exception:
            processed = None
        if isinstance(processed, list) and processed:
            _tally(processed)
            return summary

        # 3) Sections[*].findings aggregated
        try:
            secs = json_obj.get("sections")
            if isinstance(secs, list):
                allf: List[Dict[str, Any]] = []
                for s in secs:
                    fl = (s or {}).get("findings")
                    if isinstance(fl, list) and fl:
                        allf.extend(fl)
                if allf:
                    _tally(allf)
                    return summary
        except Exception:
            pass

        # 4) Statistics severity breakdown
        try:
            stats = json_obj.get("statistics") or {}
            cand = stats if isinstance(stats, dict) else {}
            for k in ["severity", "severity_counts", "severity_breakdown", "by_severity"]:
                if isinstance(cand.get(k), dict):
                    d = cand[k]
                    summary.critical = int(d.get("critical", summary.critical))
                    summary.high = int(d.get("high", summary.high))
                    summary.medium = int(d.get("medium", summary.medium))
                    summary.low = int(d.get("low", summary.low))
                    summary.info = int(d.get("info", d.get("informational", summary.info)))
                    summary.findings = summary.critical + summary.high + summary.medium + summary.low + summary.info
                    return summary
        except Exception:
            pass

        # 5) Root findings array
        if isinstance(json_obj.get("findings"), list):
            arr = json_obj["findings"]
            _tally(arr)
    except Exception:
        pass
    return summary


def _discover_result_files_uncached() -> List[Tuple[Path, float]]:
    """Discover result files and return with mtime (uncached)."""
    candidates: List[Path] = []
    try:
        candidates.extend(list(REPO_ROOT.glob("*_security_report_*.json")))
    except Exception:
        pass
    try:
        candidates.extend(list(REPO_ROOT.glob("aods_parallel_*.json")))
    except Exception:
        pass
    try:
        if REPORTS_DIR.exists():
            candidates.extend(list(REPORTS_DIR.glob("*.json")))
    except Exception:
        pass
    try:
        ar = REPO_ROOT / "artifacts" / "reports"
        if ar.exists():
            candidates.extend(list(ar.glob("*.json")))
    except Exception:
        pass
    # De-duplicate
    uniq: Dict[str, Path] = {}
    for p in candidates:
        try:
            uniq[str(p.resolve())] = p
        except Exception:
            uniq[str(p)] = p
    # Get mtime for each file once
    files_with_mtime: List[Tuple[Path, float]] = []
    for p in uniq.values():
        try:
            mtime = p.stat().st_mtime if p.exists() else 0.0
            files_with_mtime.append((p, mtime))
        except Exception:
            files_with_mtime.append((p, 0.0))
    # Sort by mtime descending
    files_with_mtime.sort(key=lambda x: x[1], reverse=True)
    return files_with_mtime


def _discover_results(limit: int = 100) -> List[ScanResultItem]:
    """Discover scan results with caching for file listing."""
    # Use cached file listing (TTL-based)
    files_with_mtime = _get_cached_or_compute("discover_results_files", _discover_result_files_uncached)
    items: List[ScanResultItem] = []
    # Filter non-scan files before processing
    _NON_SCAN_PREFIXES = ("scan_validation_", "validation_report_", "claims_report",
                          "comparison_latest", "dampener_audit", "fp_reducer_retrain",
                          "calibrator_retrain", "retrain_comparison", "ci_run_")
    for p, mtime in files_with_mtime:
        if len(items) >= limit:
            break
        # Skip known non-scan-result files
        if any(p.name.startswith(pfx) for pfx in _NON_SCAN_PREFIXES):
            continue
        started = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        profile = None
        apk_name = None
        finished = started
        summary = ScanResultSummary()
        try:
            data = json.loads(p.read_text(errors="replace"))
            # Skip files that look like validation/gate reports, not scan results
            if "coverage_validation" in data or "gate_failures" in data or "claims_count" in data:
                continue
            profile = data.get("profile") or data.get("analysis_profile")
            summary = _summarize_result(data)
            # Extract APK name from apk_info or metadata
            apk_info = data.get("apk_info") or {}
            metadata = data.get("metadata") or {}
            custom_meta = metadata.get("custom_metadata") or {}
            apk_name = apk_info.get("package_name") or apk_info.get("app_name") or metadata.get("package_name")
            # Fallback: target_application (full path) - take basename, strip .apk
            if not apk_name:
                target_app = metadata.get("target_application") or ""
                if target_app:
                    base = target_app.rsplit("/", 1)[-1]
                    apk_name = base.replace(".apk", "") if base else None
            # Fallback: apk_path
            if not apk_name and metadata.get("apk_path"):
                base = metadata["apk_path"].rsplit("/", 1)[-1]
                apk_name = base.replace(".apk", "") if base else None
            # Profile fallback: custom_metadata.scan_profile
            if not profile:
                profile = custom_meta.get("scan_profile")
            # Timestamps: prefer report-embedded dates over file mtime
            generated_at = data.get("generated_at") or metadata.get("generated_at")
            if generated_at:
                started = str(generated_at)
            analysis_duration = metadata.get("analysis_duration")
            if analysis_duration and generated_at:
                try:
                    dur_secs = float(analysis_duration)
                    from datetime import datetime as _dt

                    gen_dt = _dt.fromisoformat(str(generated_at).replace("Z", "+00:00"))
                    start_dt = gen_dt - __import__("datetime").timedelta(seconds=dur_secs)
                    started = start_dt.isoformat().replace("+00:00", "Z")
                    finished = str(generated_at)
                except Exception:
                    finished = started
            elif generated_at:
                finished = started
        except Exception:
            pass
        try:
            rel_path = str(p.relative_to(REPO_ROOT))
        except Exception:
            rel_path = str(p)
        items.append(
            ScanResultItem(
                id=p.stem,
                startedAt=started,
                finishedAt=finished,
                profile=profile,
                apkName=apk_name or None,
                summary=summary,
                path=rel_path,
            )
        )
    return items


def _start_batch_subprocess(job_id: str, req: StartBatchRequest) -> None:
    BATCH_JOBS_DIR.mkdir(parents=True, exist_ok=True)
    with _BATCH_LOCK:
        _BATCH_JOBS[job_id].update({"status": "running", "startedAt": _now_iso()})
    cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "batch_scan.py"),
    ]
    # Validate manifest and apkList paths stay under REPO_ROOT
    for label, val in [("manifest", req.manifest), ("apkList", req.apkList)]:
        if val:
            p = Path(val).resolve() if os.path.isabs(val) else (REPO_ROOT / val).resolve()
            try:
                p.relative_to(REPO_ROOT.resolve())
            except ValueError:
                with _BATCH_LOCK:
                    _BATCH_JOBS[job_id].update({
                        "status": "failed",
                        "error": f"{label} path traversal not allowed",
                        "finishedAt": _now_iso(),
                    })
                return
    if req.manifest:
        m = req.manifest
        manifest_resolved = Path(m).resolve() if os.path.isabs(m) else (REPO_ROOT / m).resolve()
        cmd += ["--manifest", str(manifest_resolved)]
    if req.apkList:
        a = req.apkList
        apklist_resolved = Path(a).resolve() if os.path.isabs(a) else (REPO_ROOT / a).resolve()
        cmd += ["--apk-list", str(apklist_resolved)]
    # Validate outDir stays under REPO_ROOT to prevent path traversal
    out_resolved = Path(req.outDir).resolve() if os.path.isabs(req.outDir) else (REPO_ROOT / req.outDir).resolve()
    try:
        out_resolved.relative_to(REPO_ROOT.resolve())
    except ValueError:
        with _BATCH_LOCK:
            _BATCH_JOBS[job_id].update({
                "status": "failed", "error": "outDir path traversal not allowed",
                "finishedAt": _now_iso(),
            })
        return
    # Validate profile against allowed values before subprocess call
    _ALLOWED_PROFILES = {"lightning", "fast", "standard", "deep"}
    batch_profile = req.profile.lower().strip() if req.profile else "lightning"
    if batch_profile not in _ALLOWED_PROFILES:
        with _BATCH_LOCK:
            _BATCH_JOBS[job_id].update({
                "status": "failed", "error": "invalid scan profile",
                "finishedAt": _now_iso(),
            })
        return
    cmd += ["--profile", batch_profile, "--concurrency", str(req.concurrency), "--out-dir", str(out_resolved)]
    os.environ.copy()
    try:
        proc = subprocess.Popen(cmd, cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        with _BATCH_LOCK:
            _BATCH_JOBS[job_id]["pid"] = proc.pid
        stdout, stderr = proc.communicate()
        rc = proc.returncode
        with _BATCH_LOCK:
            _BATCH_JOBS[job_id].update(
                {
                    "status": "completed" if rc == 0 else "failed",
                    "returnCode": rc,
                    "stdout": stdout[-4000:] if stdout else "",
                    "stderr": stderr[-4000:] if stderr else "",
                    "finishedAt": _now_iso(),
                }
            )
    except Exception as e:
        with _BATCH_LOCK:
            _BATCH_JOBS[job_id].update(
                {
                    "status": "failed",
                    "error": type(e).__name__,
                    "finishedAt": _now_iso(),
                }
            )


@router.post("/scans/upload_apk")
def upload_apk(file: UploadFile = File(...), authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """Accept an APK upload and store it under artifacts/scans/uploads.

    Returns the absolute path so the UI can auto-fill the APK Path.
    """
    _enforce_access(authorization, RBACResourceType.APK_ANALYSIS, RBACPermission.EXECUTE)
    MAX_UPLOAD_BYTES = 500 * 1024 * 1024  # 500 MB
    dest: Optional[Path] = None
    try:
        if not file.filename or not file.filename.lower().endswith(".apk"):
            raise HTTPException(status_code=400, detail="file must be an .apk")
        # Validate ZIP/APK magic bytes (PK\x03\x04)
        header = file.file.read(4)
        file.file.seek(0)
        if header[:2] != b"PK":
            raise HTTPException(status_code=400, detail="file is not a valid APK (bad magic bytes)")
        UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", file.filename)
        # timestamp + UUID prefix to avoid collisions
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        uid = uuid.uuid4().hex[:8]
        dest = UPLOADS_DIR / f"{ts}_{uid}_{safe_name}"
        total = 0
        with dest.open("wb") as out:
            while True:
                chunk = file.file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413, detail="file too large (max 500 MB)"
                    )
                out.write(chunk)
        return {"path": str(dest.resolve())}
    except HTTPException:
        # Clean up partial file on validation/size error
        if dest and dest.exists():
            try:
                dest.unlink()
            except OSError:
                pass
        raise
    except Exception:
        if dest and dest.exists():
            try:
                dest.unlink()
            except OSError:
                pass
        raise HTTPException(status_code=500, detail="upload failed")


@router.post("/scans/start", response_model=StartScanResponse, openapi_extra={"security": [{"bearerAuth": []}]})
def start_scan(req: StartScanRequest, authorization: Optional[str] = Header(default=None)) -> StartScanResponse:
    user_info = _enforce_access(authorization, RBACResourceType.APK_ANALYSIS, RBACPermission.EXECUTE)
    owner = user_info.get("user", "unknown")

    # Enforce scan concurrency limits before allocating resources
    _check_scan_concurrency(owner)

    apk_path = Path(req.apkPath)
    if not apk_path.exists():
        raise HTTPException(status_code=400, detail="apkPath does not exist")

    # Validate APK file is actually a valid Android package
    is_valid, validation_error = _validate_apk_file(apk_path)
    if not is_valid:
        raise HTTPException(status_code=400, detail="invalid APK file")

    if not DYNA_PATH.exists():
        raise HTTPException(status_code=500, detail="dyna.py not found")

    started_at = _now_iso()
    session_id = uuid.uuid4().hex
    scan_options = req.scanOptions.model_dump() if req.scanOptions else {}

    # Check for explicit package name in request - if provided, bypass detection
    explicit_package = req.packageName
    if explicit_package:
        # User provided package name explicitly - no confirmation needed
        with _SESSIONS_LOCK:
            _SESSIONS[session_id] = {
                "status": "queued",
                "apkPath": str(apk_path),
                "enableThresholdFiltering": bool(req.enableThresholdFiltering or False),
                "scanOptions": scan_options,
                "logLines": deque(maxlen=1000),
                "confirmedPackage": explicit_package,
                "packageDetection": None,
                "createdAt": time.time(),
                "owner": owner,
            }
            _SESSIONS[session_id]["logLines"].append(f"queued scan for {apk_path} (package: {explicit_package})")
        t = threading.Thread(target=_start_scan_subprocess, args=(session_id, apk_path), daemon=True)
        t.start()
        _audit("scan_start", owner, session_id, {"apk": str(apk_path), "package": explicit_package})
        return StartScanResponse(sessionId=session_id, status="queued", startedAt=started_at)

    # Perform package detection before spawning subprocess
    detection_info = None
    needs_confirmation = False
    warning_msg = None

    try:
        from core.utils.package_name_extractor import PackageNameExtractor

        extractor = PackageNameExtractor(timeout=30)
        result = extractor.extract_package_name(str(apk_path))

        if result.success and result.package_name:
            # Check if confidence is high enough to proceed automatically
            reliable_methods = {"aapt_badging", "aapt_xmltree", "manifest_parsing"}
            is_reliable = result.method in reliable_methods
            is_confident = result.confidence >= PACKAGE_CONFIDENCE_THRESHOLD

            detection_info = PackageDetectionInfo(
                packageName=result.package_name,
                confidence=result.confidence,
                method=result.method,
                appName=result.app_name,
                versionName=result.version_name,
                needsConfirmation=not (is_reliable and is_confident),
            )

            # Check if we should auto-confirm (CI mode or explicit autoConfirmPackage flag)
            ci_mode = scan_options.get("ciMode", False)
            auto_confirm = scan_options.get("autoConfirmPackage", False)

            if not (is_reliable and is_confident):
                if ci_mode or auto_confirm:
                    # Auto-accept with warning
                    logger.warning(
                        "package_detection_auto_accepted",
                        session_id=session_id,
                        package_name=result.package_name,
                        confidence=result.confidence,
                        method=result.method,
                    )
                    detection_info.needsConfirmation = False
                else:
                    # Need user confirmation
                    needs_confirmation = True
        else:
            # Detection failed - generate a placeholder and require confirmation
            clean_name = re.sub(r"[^a-zA-Z0-9]", "", apk_path.stem.lower())[:20]
            fallback_pkg = f"com.unknown.{clean_name}" if clean_name else f"com.unknown.app_{session_id[:8]}"
            detection_info = PackageDetectionInfo(
                packageName=fallback_pkg,
                confidence=0.1,
                method="fallback",
                appName=None,
                versionName=None,
                needsConfirmation=True,
            )
            # Check CI mode
            ci_mode = scan_options.get("ciMode", False)
            auto_confirm = scan_options.get("autoConfirmPackage", False)
            if ci_mode or auto_confirm:
                logger.warning(
                    "package_detection_fallback",
                    session_id=session_id,
                    fallback_package=fallback_pkg,
                )
                detection_info.needsConfirmation = False
            else:
                needs_confirmation = True
    except Exception as e:
        logger.warning(
            "package_detection_error",
            session_id=session_id,
            error=str(e),
            error_type=type(e).__name__,
        )
        # Detection threw an exception - generate a fallback and require confirmation
        clean_name = re.sub(r"[^a-zA-Z0-9]", "", apk_path.stem.lower())[:20]
        fallback_pkg = f"com.unknown.{clean_name}" if clean_name else f"com.unknown.app_{session_id[:8]}"
        detection_info = PackageDetectionInfo(
            packageName=fallback_pkg,
            confidence=0.1,
            method="fallback",
            appName=None,
            versionName=None,
            needsConfirmation=True,
        )
        # Check CI mode
        ci_mode = scan_options.get("ciMode", False)
        auto_confirm = scan_options.get("autoConfirmPackage", False)
        if ci_mode or auto_confirm:
            logger.warning(
                "package_detection_fallback_after_error",
                session_id=session_id,
                fallback_package=fallback_pkg,
                error=str(e),
            )
            detection_info.needsConfirmation = False
        else:
            needs_confirmation = True

    # Create session
    with _SESSIONS_LOCK:
        _SESSIONS[session_id] = {
            "status": "awaiting_confirmation" if needs_confirmation else "queued",
            "apkPath": str(apk_path),
            "enableThresholdFiltering": bool(req.enableThresholdFiltering or False),
            "scanOptions": scan_options,
            "logLines": deque(maxlen=1000),
            "packageDetection": detection_info.model_dump() if detection_info else None,
            "confirmedPackage": (
                None if needs_confirmation else (detection_info.packageName if detection_info else None)
            ),
            "createdAt": time.time(),
            "owner": owner,
        }
        if needs_confirmation:
            _SESSIONS[session_id]["logLines"].append(f"awaiting package confirmation for {apk_path}")
        else:
            _SESSIONS[session_id]["logLines"].append(f"queued scan for {apk_path}")

    if needs_confirmation:
        # Return early - user must call /confirm-package to proceed
        return StartScanResponse(
            sessionId=session_id,
            status="awaiting_confirmation",
            startedAt=started_at,
            packageDetection=detection_info,
            warning=None,
        )

    # Start the scan subprocess immediately
    t = threading.Thread(target=_start_scan_subprocess, args=(session_id, apk_path), daemon=True)
    t.start()
    pkg = detection_info.packageName if detection_info else "unknown"
    _audit("scan_start", owner, session_id, {"apk": str(apk_path), "package": pkg})
    return StartScanResponse(
        sessionId=session_id,
        status="queued",
        startedAt=started_at,
        packageDetection=detection_info,
        warning=warning_msg,
    )


@router.post("/scans/{session_id}/confirm-package", openapi_extra={"security": [{"bearerAuth": []}]})
def confirm_package(
    session_id: str, req: ConfirmPackageRequest, authorization: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    """
    Confirm package name for a scan that is awaiting confirmation.

    This endpoint is called after /scans/start returns status="awaiting_confirmation".
    The user can confirm the detected package name or provide an override.
    """
    _enforce_access(authorization, RBACResourceType.APK_ANALYSIS, RBACPermission.EXECUTE)

    with _SESSIONS_LOCK:
        session = _SESSIONS.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        if session.get("status") != "awaiting_confirmation":
            raise HTTPException(
                status_code=409,
                detail="session is not awaiting confirmation",
            )

        # Check for timeout
        created_at = session.get("createdAt", 0)
        if time.time() - created_at > PACKAGE_CONFIRMATION_TIMEOUT:
            session["status"] = "cancelled"
            session["cancelReason"] = "Package confirmation timeout"
            raise HTTPException(status_code=410, detail="Package confirmation timeout expired")

        # Update session with confirmed package and start the scan
        session["confirmedPackage"] = req.packageName
        session["status"] = "queued"
        apk_path = Path(session.get("apkPath", ""))

        try:
            session["logLines"].append(f"package confirmed: {req.packageName}")
        except Exception:
            pass

    if not apk_path.exists():
        with _SESSIONS_LOCK:
            _SESSIONS[session_id]["status"] = "failed"
        raise HTTPException(status_code=400, detail="APK file no longer exists")

    # Start the scan subprocess
    t = threading.Thread(target=_start_scan_subprocess, args=(session_id, apk_path), daemon=True)
    t.start()

    _audit("confirm_package", "api_user", session_id, {"packageName": req.packageName})

    return {
        "sessionId": session_id,
        "status": "queued",
        "packageName": req.packageName,
    }


@router.post("/scans/{session_id}/retry-detection", openapi_extra={"security": [{"bearerAuth": []}]})
def retry_package_detection(session_id: str, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """
    Retry package detection for a scan that is awaiting confirmation.

    This endpoint allows users to retry the package detection process,
    which may succeed if AAPT or other tools become available.
    """
    _enforce_access(authorization, RBACResourceType.APK_ANALYSIS, RBACPermission.EXECUTE)

    with _SESSIONS_LOCK:
        session = _SESSIONS.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        if session.get("status") != "awaiting_confirmation":
            raise HTTPException(
                status_code=409,
                detail="session is not awaiting confirmation",
            )

        apk_path = Path(session.get("apkPath", ""))

    if not apk_path.exists():
        raise HTTPException(status_code=400, detail="APK file no longer exists")

    # Capture old confidence before any updates (session is a reference to the dict in _SESSIONS)
    old_confidence = session.get("packageDetection", {}).get("confidence", 0)

    # Retry package detection
    try:
        from core.utils.package_name_extractor import PackageNameExtractor

        extractor = PackageNameExtractor(timeout=30)
        result = extractor.extract_package_name(str(apk_path))

        if result.success and result.package_name:
            reliable_methods = {"aapt_badging", "aapt_xmltree", "manifest_parsing"}
            is_reliable = result.method in reliable_methods
            is_confident = result.confidence >= PACKAGE_CONFIDENCE_THRESHOLD

            detection_info = PackageDetectionInfo(
                packageName=result.package_name,
                confidence=result.confidence,
                method=result.method,
                appName=result.app_name,
                versionName=result.version_name,
                needsConfirmation=not (is_reliable and is_confident),
            )

            # Update session with new detection
            with _SESSIONS_LOCK:
                _SESSIONS[session_id]["packageDetection"] = detection_info.model_dump()
                try:
                    _SESSIONS[session_id]["logLines"].append(
                        f"retry detection: {result.package_name} ({result.confidence:.0%} via {result.method})"
                    )
                except Exception:
                    pass

            return {
                "sessionId": session_id,
                "status": "awaiting_confirmation",
                "packageDetection": detection_info.model_dump(),
                "improved": result.confidence > old_confidence,
            }
        else:
            return {
                "sessionId": session_id,
                "status": "awaiting_confirmation",
                "packageDetection": session.get("packageDetection"),
                "improved": False,
                "error": result.error or "Detection failed",
            }
    except Exception as e:
        logger.warning(
            "retry_detection_error",
            session_id=session_id,
            error=str(e),
            error_type=type(e).__name__,
        )
        return {
            "sessionId": session_id,
            "status": "awaiting_confirmation",
            "packageDetection": session.get("packageDetection"),
            "improved": False,
            "error": "package detection failed",
        }


@router.get(
    "/scans/start-quick",
    response_model=StartScanResponse,
    summary="Start Scan (Quick)",
    openapi_extra={"security": [{"bearerAuth": []}]},
)
def start_scan_quick(
    apkPath: str = Query(..., description="Absolute path to APK file", examples=["/path/to/app.apk"]),
    authorization: Optional[str] = Header(default=None),
) -> StartScanResponse:
    user_info = _enforce_access(authorization, RBACResourceType.APK_ANALYSIS, RBACPermission.EXECUTE)
    owner = user_info.get("user", "unknown")
    apk_path = Path(apkPath)
    if not apk_path.exists():
        raise HTTPException(status_code=400, detail="apkPath does not exist")

    # Validate APK file is actually a valid Android package
    is_valid, validation_error = _validate_apk_file(apk_path)
    if not is_valid:
        raise HTTPException(status_code=400, detail="invalid APK file")

    if not DYNA_PATH.exists():
        raise HTTPException(status_code=500, detail="dyna.py not found")

    session_id = uuid.uuid4().hex
    with _SESSIONS_LOCK:
        _SESSIONS[session_id] = {
            "status": "queued",
            "apkPath": str(apk_path),
            "logLines": deque(maxlen=1000),
            "owner": owner,
            "createdAt": time.time(),
        }
        try:
            _SESSIONS[session_id]["logLines"].append(f"queued scan for {apk_path}")
        except Exception:
            pass

    t = threading.Thread(target=_start_scan_subprocess, args=(session_id, apk_path), daemon=True)
    t.start()
    return StartScanResponse(sessionId=session_id, status="queued", startedAt=_now_iso())


@router.get("/scans/{session_id}/progress", response_model=ScanProgressResponse)
def scan_progress(session_id: str, authorization: Optional[str] = Header(default=None)) -> ScanProgressResponse:
    user_info = _enforce_access(authorization, RBACResourceType.APK_ANALYSIS, RBACPermission.READ)
    with _SESSIONS_LOCK:
        s = _SESSIONS.get(session_id)
    if s and not _can_access_resource(user_info, s.get("owner")):
        raise HTTPException(status_code=403, detail="access denied: you can only view your own scans")
    return _coarse_progress(session_id)


@router.get("/scans/{session_id}/progress/stream")
def scan_progress_stream(
    session_id: str,
    authorization: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
):
    """Stream scan progress updates via SSE. Requires authentication.

    Non-admin users can only stream progress for their own scans.
    """
    # Allow either Authorization header or token query for EventSource compatibility
    if token and not authorization:
        authorization = f"Bearer {token}"
    user_info = _enforce_access(authorization, RBACResourceType.APK_ANALYSIS, RBACPermission.READ)

    # Check ownership before allowing stream connection
    with _SESSIONS_LOCK:
        s = _SESSIONS.get(session_id)
    if s and not _can_access_resource(user_info, s.get("owner")):
        raise HTTPException(status_code=403, detail="access denied: you can only view your own scans")

    def event_stream():
        last = None
        heartbeat_counter = 0
        started = time.time()
        while True:
            try:
                # Enforce idle timeout to prevent resource exhaustion
                if time.time() - started > SSE_IDLE_TIMEOUT:
                    yield f"event: end\ndata: {json.dumps({'reason': 'idle_timeout'})}\n\n"
                    break
                with _SESSIONS_LOCK:
                    s = _SESSIONS.get(session_id)
                if not s:
                    yield f"event: end\ndata: {json.dumps({'error': 'not found'})}\n\n"
                    break
                resp = _coarse_progress(session_id)
                payload = resp.model_dump()
                cur = (payload.get("pct"), payload.get("stage"))
                if cur != last:
                    # Apply PII redaction to progress payloads
                    yield f"data: {json.dumps(_redact_pii(payload))}\n\n"
                    last = cur
                    heartbeat_counter = 0
                    started = time.time()  # reset on activity
                if payload.get("stage") in ("completed", "failed", "cancelled"):
                    yield f"event: end\ndata: {json.dumps(_redact_pii({'status': payload.get('stage')}))}\n\n"
                    break
                heartbeat_counter += 1
                if heartbeat_counter >= 30:  # ~30s at 1s interval
                    yield ": heartbeat\n\n"
                    heartbeat_counter = 0
                time.sleep(1.0)
            except Exception as e:
                logger.error("sse_progress_error", error_type=type(e).__name__)
                yield f"event: end\ndata: {json.dumps({'error': 'stream error'})}\n\n"
                break

    resp = StreamingResponse(event_stream(), media_type="text/event-stream")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return resp


@router.get("/scans/{session_id}/logs/stream")
def scan_logs_stream(
    session_id: str,
    authorization: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
):
    """Stream scan log output via SSE. Requires authentication.

    Non-admin users can only stream logs for their own scans.
    """
    # Allow either Authorization header or token query for EventSource compatibility
    if token and not authorization:
        authorization = f"Bearer {token}"
    user_info = _enforce_access(authorization, RBACResourceType.APK_ANALYSIS, RBACPermission.READ)

    # Check ownership before allowing stream connection
    with _SESSIONS_LOCK:
        s = _SESSIONS.get(session_id)
    if s and not _can_access_resource(user_info, s.get("owner")):
        raise HTTPException(status_code=403, detail="access denied: you can only view your own scans")

    def event_stream():
        idx = 0
        heartbeat_counter = 0
        started = time.time()
        while True:
            try:
                if time.time() - started > SSE_IDLE_TIMEOUT:
                    yield f"event: end\ndata: {json.dumps({'reason': 'idle_timeout'})}\n\n"
                    break
                with _SESSIONS_LOCK:
                    s = _SESSIONS.get(session_id)
                    if not s:
                        yield f"event: end\ndata: {json.dumps({'error': 'not found'})}\n\n"
                        break
                    lg = s.get("logLines")
                    lines = list(lg) if isinstance(lg, deque) else []
                    status = str(s.get("status", "running")).lower()
                if idx < len(lines):
                    for i in range(idx, len(lines)):
                        yield f"data: {json.dumps({'line': lines[i]})}\n\n"
                    idx = len(lines)
                    heartbeat_counter = 0
                    started = time.time()
                if status in ("completed", "failed", "cancelled") and idx >= len(lines):
                    yield f"event: end\ndata: {json.dumps({'status': status})}\n\n"
                    break
                heartbeat_counter += 1
                if heartbeat_counter >= 60:  # ~30s at 0.5s interval
                    yield ": heartbeat\n\n"
                    heartbeat_counter = 0
                time.sleep(0.5)
            except Exception as e:
                logger.error("sse_logs_error", error_type=type(e).__name__)
                yield f"event: end\ndata: {json.dumps({'error': 'stream error'})}\n\n"
                break

    resp = StreamingResponse(event_stream(), media_type="text/event-stream")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return resp


@router.get("/scans/{session_id}/details")
def scan_details(session_id: str, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    user_info = _require_roles(authorization, ["admin", "analyst", "viewer"])
    with _SESSIONS_LOCK:
        s = _SESSIONS.get(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    # Check ownership (admins see all, others see only their own)
    if not _can_access_resource(user_info, s.get("owner")):
        raise HTTPException(status_code=403, detail="access denied: you do not own this scan")
    # Return a safe projection
    return {
        "id": session_id,
        "status": s.get("status"),
        "startedAt": s.get("startedAt"),
        "finishedAt": s.get("finishedAt"),
        "effectiveOptions": s.get("effectiveOptions") or {"applied": {}, "ignored": {}},
        "owner": s.get("owner"),
    }


@router.get("/scans/results", response_model=List[ScanResultItem])
def scan_results(limit: int = 100, authorization: Optional[str] = Header(default=None)) -> List[ScanResultItem]:
    """List scan results. Requires authentication."""
    _require_roles(authorization, ["admin", "analyst", "viewer", "api_user"])
    return _discover_results(limit=limit)


@router.get("/scans/result/{result_id}")
def scan_result_detail(result_id: str, authorization: Optional[str] = Header(default=None)) -> Any:
    """Get scan result detail. Requires authentication."""
    _require_roles(authorization, ["admin", "analyst", "viewer", "api_user"])
    # Return the JSON object for the report whose stem matches result_id
    candidate = _find_result_file(result_id)
    if not candidate:
        raise HTTPException(status_code=404, detail="result not found")
    try:
        return json.loads(candidate.read_text(errors="replace"))
    except Exception:
        raise HTTPException(status_code=500, detail="failed to read result")


@router.get("/scans/result/{result_id}/attack-surface")
def scan_result_attack_surface(
    result_id: str, authorization: Optional[str] = Header(default=None)
) -> Any:
    """Build and return the attack-surface graph for a scan result."""
    _require_roles(authorization, ["admin", "analyst", "viewer", "api_user"])

    candidate = _find_result_file(result_id)
    if not candidate:
        raise HTTPException(status_code=404, detail="result not found")

    try:
        report = json.loads(candidate.read_text(errors="replace"))
    except Exception:
        raise HTTPException(status_code=500, detail="failed to read result")

    findings = report.get("findings") or report.get("vulnerabilities") or []
    attack_chains = None
    agentic = report.get("agentic_analysis")
    if isinstance(agentic, dict):
        attack_chains = agentic.get("attack_chains")

    # Try to locate the decoded manifest
    manifest_path = _find_manifest_for_report(report, candidate)

    # Fall back to persisted manifest data if manifest file is unavailable
    metadata = report.get("metadata") or {}
    manifest_data = metadata.get("manifest_data") or report.get("manifest_data")

    from core.analysis.attack_surface import build_attack_surface_graph

    graph = build_attack_surface_graph(
        manifest_path=manifest_path,
        findings=findings,
        attack_chains=attack_chains,
        manifest_data=manifest_data,
    )
    return graph.to_dict()


def _find_manifest_for_report(
    report: Dict[str, Any], report_path: Path
) -> Optional[Path]:
    """Best-effort locate AndroidManifest.xml for a completed scan."""
    metadata = report.get("metadata") or {}

    # 1. Workspace directory stored in metadata
    workspace = metadata.get("workspace") or metadata.get("workspace_dir")
    if workspace:
        mp = Path(workspace) / "AndroidManifest.xml"
        if mp.exists():
            return mp

    # 2. APK path - extract manifest from APK
    apk_path = metadata.get("apk_path") or metadata.get("apk")
    if apk_path:
        apk_p = Path(apk_path)
        if apk_p.exists():
            from core.manifest_parsing_utils import extract_manifest_from_apk

            import tempfile

            tmp = Path(tempfile.mkdtemp(prefix="aods_asf_"))
            result = extract_manifest_from_apk(str(apk_p), tmp)
            if result:
                return result

    # 3. Adjacent manifest in report directory
    for search_dir in [report_path.parent, REPO_ROOT / "reports"]:
        if search_dir.exists():
            for mp in search_dir.glob("**/AndroidManifest.xml"):
                return mp

    return None


@router.get("/scans/result/{result_id}/iocs")
def scan_result_iocs(
    result_id: str,
    format: str = Query("json", pattern="^(json|stix)$"),
    authorization: Optional[str] = Header(default=None),
) -> Any:
    """Extract IoCs from a scan result.

    Returns structured IoC list extracted from:
    - Static findings (MALWARE_IOC_EXTRACTED, MALWARE_CROSS_APK_IOC, etc.)
    - Dynamic Frida events (network_communication, file_access, filesystem_ioc,
      malware_behavior) stored in shared state

    Query params:
        format: "json" (default) or "stix" for STIX 2.1 bundle output
    """
    _require_roles(authorization, ["admin", "analyst", "viewer", "api_user"])

    # Load the scan result JSON
    candidate = _find_result_file(result_id)
    if not candidate:
        raise HTTPException(status_code=404, detail="result not found")

    try:
        report = json.loads(candidate.read_text(errors="replace"))
    except Exception:
        raise HTTPException(status_code=500, detail="failed to read result")

    # --- Extract IoCs from static findings ---
    from core.dynamic_ioc_collector import collect_iocs_from_frida_events

    static_iocs: List[Dict[str, Any]] = []
    findings = report.get("findings") or report.get("vulnerabilities") or []
    for f in findings:
        title = (f.get("title") or "").upper()
        evidence = f.get("evidence") or {}

        # IoC extraction findings from malware_detection plugin
        if "IOC" in title or "MALWARE" in title:
            iocs_in_evidence = evidence.get("iocs") or evidence.get("extracted_iocs") or []
            if isinstance(iocs_in_evidence, list):
                for ioc_item in iocs_in_evidence:
                    if isinstance(ioc_item, dict) and ioc_item.get("value"):
                        static_iocs.append({
                            "type": ioc_item.get("type", "unknown"),
                            "value": ioc_item["value"],
                            "source": "static",
                            "severity": f.get("severity", "medium"),
                            "confidence": f.get("confidence", 0.5),
                            "context": {
                                "finding_title": f.get("title", ""),
                                "finding_id": f.get("finding_id", ""),
                                "file_path": f.get("file_path", ""),
                            },
                        })

            # Also check for direct IoC fields in evidence
            for key in ("c2_ip", "c2_url", "domain", "ip", "url", "wallet"):
                val = evidence.get(key)
                if val and isinstance(val, str):
                    ioc_type = "url" if "url" in key else (
                        "ip_address" if "ip" in key else (
                            "domain" if "domain" in key else "unknown"
                        )
                    )
                    static_iocs.append({
                        "type": ioc_type,
                        "value": val,
                        "source": "static",
                        "severity": f.get("severity", "medium"),
                        "confidence": f.get("confidence", 0.5),
                        "context": {"finding_title": f.get("title", "")},
                    })

    # --- Extract IoCs from Frida runtime events ---
    from core.api.shared_state import _FRIDA_EVENTS_LOCK, _FRIDA_EVENTS

    dynamic_iocs: List[Dict[str, Any]] = []
    # Look for events keyed by any package associated with this scan
    apk_name = (report.get("metadata") or {}).get("apk_name", "")
    pkg = (report.get("metadata") or {}).get("package_name", "")
    frida_events: List[Dict[str, Any]] = []
    with _FRIDA_EVENTS_LOCK:
        for key in (result_id, pkg, apk_name):
            if key and key in _FRIDA_EVENTS:
                frida_events.extend(_FRIDA_EVENTS[key])

    if frida_events:
        dynamic_iocs = collect_iocs_from_frida_events(frida_events)

    # --- Merge and deduplicate ---
    all_iocs = static_iocs + dynamic_iocs
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for ioc in all_iocs:
        key = f"{ioc.get('type')}:{ioc.get('value')}"
        if key not in seen:
            seen.add(key)
            deduped.append(ioc)

    # --- STIX format ---
    if format == "stix":
        from core.stix_exporter import export_iocs_to_stix

        families = []
        mitre_techniques = []
        # Try to extract family/MITRE info from report
        for f in findings:
            ev = f.get("evidence") or {}
            fam = ev.get("family_name") or ev.get("malware_family")
            if fam and fam not in families:
                families.append(fam)
            for tech in (ev.get("mitre_techniques") or []):
                if tech not in mitre_techniques:
                    mitre_techniques.append(tech)

        return export_iocs_to_stix(
            deduped,
            scan_id=result_id,
            apk_name=apk_name,
            families=families or None,
            mitre_techniques=mitre_techniques or None,
        )

    return {
        "scan_id": result_id,
        "apk_name": apk_name,
        "iocs": deduped,
        "total": len(deduped),
        "static_count": len(static_iocs),
        "dynamic_count": len(dynamic_iocs),
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/scans/result/{result_id}/chunk")
def scan_result_chunk(
    result_id: str,
    offset: int = Query(0, ge=0, le=500_000_000),
    numBytes: int = Query(131072, ge=1, le=10_000_000),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Get scan result chunk. Requires authentication."""
    _require_roles(authorization, ["admin", "analyst", "viewer", "api_user"])
    candidate = _find_result_file(result_id)
    if not candidate:
        raise HTTPException(status_code=404, detail="result not found")
    size = candidate.stat().st_size
    next_off = min(size, offset + numBytes)
    try:
        with candidate.open("rb") as f:
            f.seek(offset)
            chunk = f.read(numBytes)
        text = chunk.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=500, detail="failed to read chunk")
    return {
        "id": result_id,
        "size": size,
        "offset": offset,
        "nextOffset": next_off,
        "eof": next_off >= size,
        "content": text,
    }


@router.get("/scans/active")
def list_active_scans(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """List currently active scans (queued or running). Admin/analyst only.

    Admins see all active scans, analysts see only their own.
    """
    user_info = _require_roles(authorization, ["admin", "analyst"])
    with _SESSIONS_LOCK:
        items: List[Dict[str, Any]] = []
        for sid, sess in _SESSIONS.items():
            # Check ownership (admins see all, analysts see only their own)
            if not _can_access_resource(user_info, sess.get("owner")):
                continue
            status = str(sess.get("status", "unknown")).lower()
            if status in {"queued", "running"}:
                items.append(
                    {
                        "id": sid,
                        "status": status,
                        "startedAt": sess.get("startedAt"),
                        "owner": sess.get("owner"),
                    }
                )
    try:
        items.sort(key=lambda x: (x.get("startedAt") or ""), reverse=True)
    except Exception:
        pass
    return {"items": items}


@router.get("/scans/recent")
def list_recent_scans(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
    status: Optional[str] = Query(default=None, description="Filter by status: running,completed,failed,cancelled,all"),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """List recent scans with status, timing, and summary.

    Aggregates from in-memory sessions and persisted report files.
    Non-admin users only see their own scans.

    Args:
        limit: Maximum number of items to return (1-100, default 20)
        offset: Number of items to skip (for pagination)
        status: Filter by status (running, completed, failed, cancelled, all)

    Returns:
        { items: [...], total: int, hasMore: bool }
    """
    user_info = _require_roles(authorization, ["admin", "analyst", "viewer"])

    items: List[Dict[str, Any]] = []

    # Collect from in-memory sessions
    with _SESSIONS_LOCK:
        for sid, sess in _SESSIONS.items():
            # Check ownership (admins see all, others see only their own)
            if not _can_access_resource(user_info, sess.get("owner")):
                continue

            sess_status = str(sess.get("status", "unknown")).lower()
            # Apply status filter
            if status and status != "all" and sess_status != status.lower():
                continue

            apk_path = sess.get("apkPath", "")
            apk_name = Path(apk_path).name if apk_path else "unknown"

            # Calculate duration if available
            duration_ms = None
            started = sess.get("startedAt")
            finished = sess.get("finishedAt")
            if started and finished:
                try:
                    from datetime import datetime

                    _fmt = "%Y-%m-%dT%H:%M:%S.%fZ" if "." in started else "%Y-%m-%dT%H:%M:%SZ"  # noqa: F841
                    start_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
                    end_dt = datetime.fromisoformat(finished.replace("Z", "+00:00"))
                    duration_ms = int((end_dt - start_dt).total_seconds() * 1000)
                except Exception:
                    pass

            items.append(
                {
                    "id": sid,
                    "source": "session",
                    "apkName": apk_name,
                    "apkPath": apk_path,
                    "status": sess_status,
                    "profile": (
                        sess.get("scanOptions", {}).get("profile")
                        if isinstance(sess.get("scanOptions"), dict)
                        else None
                    ),
                    "mode": (
                        sess.get("scanOptions", {}).get("mode") if isinstance(sess.get("scanOptions"), dict) else None
                    ),
                    "startedAt": started,
                    "finishedAt": finished,
                    "durationMs": duration_ms,
                    "findingsCount": None,  # Not available from session
                    "createdAt": sess.get("createdAt"),
                    "owner": sess.get("owner"),
                }
            )

    # Collect from persisted reports (artifacts/scans/ and reports/)
    scan_dirs = [REPO_ROOT / "artifacts" / "scans", REPO_ROOT / "reports"]
    for scan_dir in scan_dirs:
        if not scan_dir.exists():
            continue
        try:
            for report_path in scan_dir.rglob("*.json"):
                # Skip non-report files
                if report_path.name.startswith(".") or "summary" in report_path.name.lower():
                    continue

                try:
                    # Check if this report is already in items (by ID)
                    report_id = report_path.stem
                    if any(it.get("id") == report_id for it in items):
                        continue

                    # Quick parse for metadata (don't load full file)
                    stat = report_path.stat()
                    mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)

                    # Only include completed status if filtering
                    if status and status != "all" and status.lower() != "completed":
                        continue

                    # Try to extract summary info from file
                    findings_count = None
                    apk_name = report_path.stem
                    profile = None
                    mode = None
                    started_at = None
                    finished_at = mtime.isoformat().replace("+00:00", "Z")
                    duration_ms = None

                    # Read first 4KB to extract metadata
                    try:
                        with open(report_path, "r", encoding="utf-8", errors="replace") as f:
                            head = f.read(4096)
                            if '"apk_info"' in head or '"package_name"' in head or '"vulnerabilities"' in head:
                                # This looks like a scan report
                                try:
                                    data = json.loads(report_path.read_text(errors="replace"))
                                    apk_info = data.get("apk_info", {})
                                    apk_name = (
                                        apk_info.get("app_name")
                                        or apk_info.get("package_name")
                                        or data.get("package_name")
                                        or report_path.stem
                                    )
                                    findings_count = len(
                                        data.get("vulnerabilities", []) or data.get("findings", []) or []
                                    )
                                    profile = data.get("profile")
                                    mode = data.get("mode") or data.get("scan_mode")
                                    started_at = data.get("started_at") or data.get("timestamp")
                                    finished_at = data.get("finished_at") or finished_at
                                    duration_ms = data.get("duration_ms") or data.get("scan_duration_ms")
                                except Exception:
                                    pass
                    except Exception:
                        pass

                    items.append(
                        {
                            "id": report_id,
                            "source": "report",
                            "apkName": apk_name,
                            "apkPath": None,
                            "status": "completed",
                            "profile": profile,
                            "mode": mode,
                            "startedAt": started_at,
                            "finishedAt": finished_at,
                            "durationMs": duration_ms,
                            "findingsCount": findings_count,
                            "reportPath": str(report_path.relative_to(REPO_ROOT)),
                            "createdAt": stat.st_mtime,
                        }
                    )
                except Exception:
                    continue
        except Exception:
            continue

    # Sort by createdAt/startedAt descending (most recent first)
    def sort_key(item: Dict[str, Any]) -> float:
        ts = item.get("createdAt") or 0
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            except Exception:
                ts = 0
        return float(ts)

    items.sort(key=sort_key, reverse=True)

    # Apply pagination
    total = len(items)
    paginated = items[offset : offset + limit]

    return {
        "items": paginated,
        "total": total,
        "hasMore": offset + limit < total,
        "limit": limit,
        "offset": offset,
    }


@router.post("/batch/start", response_model=StartBatchResponse, openapi_extra={"security": [{"bearerAuth": []}]})
def start_batch(req: StartBatchRequest, authorization: Optional[str] = Header(default=None)) -> StartBatchResponse:
    user_info = _enforce_access(authorization, RBACResourceType.APK_ANALYSIS, RBACPermission.EXECUTE)
    check_expensive_op_rate("batch_start", user_info.get("user", "unknown"))
    if not req.manifest and not req.apkList:
        raise HTTPException(status_code=400, detail="manifest or apkList is required")
    job_id = uuid.uuid4().hex
    with _BATCH_LOCK:
        _BATCH_JOBS[job_id] = {
            "status": "queued",
            "request": req.model_dump(),
            "owner": user_info.get("user", "unknown"),
        }
    t = threading.Thread(target=_start_batch_subprocess, args=(job_id, req), daemon=True)
    t.start()
    return StartBatchResponse(jobId=job_id, pid=None, status="queued")


@router.get("/batch/{job_id}/status")
def batch_status(job_id: str, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    user_info = _enforce_access(authorization, RBACResourceType.APK_ANALYSIS, RBACPermission.READ)
    with _BATCH_LOCK:
        j = _BATCH_JOBS.get(job_id)
    if not j:
        raise HTTPException(status_code=404, detail="job not found")
    if not _can_access_resource(user_info, j.get("owner")):
        raise HTTPException(status_code=403, detail="access denied: you can only view your own batch jobs")
    return j


@router.get("/batch/{job_id}/status/stream")
def batch_status_stream(
    job_id: str,
    authorization: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
):
    """Stream batch job status updates via SSE. Requires authentication."""
    # Allow either Authorization header or token query for EventSource compatibility
    if token and not authorization:
        authorization = f"Bearer {token}"
    user_info = _enforce_access(authorization, RBACResourceType.APK_ANALYSIS, RBACPermission.READ)

    # Check ownership before allowing stream connection
    with _BATCH_LOCK:
        j = _BATCH_JOBS.get(job_id)
    if j and not _can_access_resource(user_info, j.get("owner")):
        raise HTTPException(status_code=403, detail="access denied: you can only view your own batch jobs")

    def event_stream():
        last = None
        heartbeat_counter = 0
        started = time.time()
        while True:
            try:
                if time.time() - started > SSE_IDLE_TIMEOUT:
                    yield f"event: end\ndata: {json.dumps({'reason': 'idle_timeout'})}\n\n"
                    break
                with _BATCH_LOCK:
                    j = _BATCH_JOBS.get(job_id)
                if not j:
                    yield f"event: end\ndata: {json.dumps({'error': 'not found'})}\n\n"
                    break
                status = j.get("status")
                if status != last:
                    # Apply PII redaction to status payloads
                    yield f"data: {json.dumps(_redact_pii({'status': status}))}\n\n"
                    last = status
                    heartbeat_counter = 0
                    started = time.time()
                if status in ("completed", "failed", "cancelled"):
                    yield f"event: end\ndata: {json.dumps(_redact_pii({'status': status}))}\n\n"
                    break
                heartbeat_counter += 1
                if heartbeat_counter >= 20:  # ~30s at 1.5s interval
                    yield ": heartbeat\n\n"
                    heartbeat_counter = 0
                time.sleep(1.5)
            except Exception as e:
                logger.error("sse_batch_error", error_type=type(e).__name__)
                yield f"event: end\ndata: {json.dumps({'error': 'stream error'})}\n\n"
                break

    resp = StreamingResponse(event_stream(), media_type="text/event-stream")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return resp


@router.post("/audit/event")
def append_audit_event(evt: AuditEvent, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin"])
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(evt.model_dump()) + "\n")
        return {"status": "ok"}
    except Exception:
        raise HTTPException(status_code=500, detail="failed to append audit event")


@router.post("/scans/{session_id}/cancel")
def cancel_scan(session_id: str, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    user_info = _enforce_access(authorization, RBACResourceType.APK_ANALYSIS, RBACPermission.EXECUTE)
    with _SESSIONS_LOCK:
        s = _SESSIONS.get(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    # Check ownership (admins can cancel any, others only their own)
    if not _can_access_resource(user_info, s.get("owner")):
        raise HTTPException(status_code=403, detail="access denied: you can only cancel your own scans")
    proc = s.get("process")
    cancelled = False
    try:
        # Mark cancel intent
        with _SESSIONS_LOCK:
            try:
                _SESSIONS[session_id]["cancelRequested"] = True
            except Exception:
                pass
        if proc and hasattr(proc, "poll") and proc.poll() is None:
            try:
                # Terminate the whole process group
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except Exception:
                    proc.terminate()
            except Exception:
                pass
            # brief wait
            for _ in range(5):
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
            if proc.poll() is None:
                try:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except Exception:
                        proc.kill()
                except Exception:
                    pass
            cancelled = True
    finally:
        with _SESSIONS_LOCK:
            s = _SESSIONS.get(session_id) or {}
            s.update(
                {
                    "status": "cancelled" if cancelled else s.get("status", "failed"),
                    "finishedAt": _now_iso(),
                }
            )
            _SESSIONS[session_id] = s
    _audit("scan_cancel", user_info.get("user", "unknown"), session_id, {"cancelled": cancelled})
    return {"status": _SESSIONS[session_id].get("status")}


@router.post("/batch/{job_id}/cancel")
def cancel_batch(job_id: str, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _enforce_access(authorization, RBACResourceType.APK_ANALYSIS, RBACPermission.EXECUTE)
    with _BATCH_LOCK:
        j = _BATCH_JOBS.get(job_id)
    if not j:
        raise HTTPException(status_code=404, detail="job not found")
    pid = j.get("pid")
    cancelled = False
    if isinstance(pid, int) and pid > 0:
        try:
            os.kill(pid, 15)  # SIGTERM
            time.sleep(0.2)
            # if still alive, SIGKILL
            try:
                os.kill(pid, 0)
                os.kill(pid, 9)
            except Exception:
                pass
            cancelled = True
        except Exception:
            pass
    with _BATCH_LOCK:
        j = _BATCH_JOBS.get(job_id) or {}
        j.update(
            {
                "status": "cancelled" if cancelled else j.get("status", "failed"),
                "finishedAt": _now_iso(),
            }
        )
        _BATCH_JOBS[job_id] = j
    return {"status": _BATCH_JOBS[job_id].get("status")}


def _cleanup_expired_confirmation_sessions() -> None:
    """
    Background thread that periodically:
    1. Cancels sessions in 'awaiting_confirmation' that exceeded timeout.
    2. Removes expired auth tokens from _TOKENS to prevent memory leak.
    3. Removes completed/failed/cancelled sessions older than COMPLETED_SESSION_TTL.
    4. Removes finished batch jobs older than COMPLETED_BATCH_TTL.
    """
    from core.api.shared_state import _TOKENS, _TOKENS_LOCK

    while True:
        try:
            time.sleep(_CONFIRMATION_CLEANUP_INTERVAL)
            now = time.time()
            expired_sessions = []

            with _SESSIONS_LOCK:
                for sid, session in list(_SESSIONS.items()):
                    if session.get("status") == "awaiting_confirmation":
                        created_at = session.get("createdAt", 0)
                        if now - created_at > PACKAGE_CONFIRMATION_TIMEOUT:
                            expired_sessions.append(sid)

                # Cancel expired sessions
                for sid in expired_sessions:
                    if sid in _SESSIONS:
                        _SESSIONS[sid]["status"] = "cancelled"
                        _SESSIONS[sid]["cancelReason"] = "Package confirmation timeout"
                        try:
                            _SESSIONS[sid]["logLines"].append(
                                f"Session cancelled: package confirmation timeout after {PACKAGE_CONFIRMATION_TIMEOUT}s"
                            )
                        except Exception:
                            pass

                # Evict old completed/failed/cancelled sessions
                stale_sessions = []
                for sid, session in list(_SESSIONS.items()):
                    if session.get("status") in ("completed", "failed", "cancelled"):
                        created_at = session.get("createdAt", 0)
                        if now - created_at > COMPLETED_SESSION_TTL:
                            stale_sessions.append(sid)
                for sid in stale_sessions:
                    _SESSIONS.pop(sid, None)

            if expired_sessions:
                logger.info(
                    "sessions_cleaned_up",
                    count=len(expired_sessions),
                    session_ids=expired_sessions,
                )
            if stale_sessions:
                logger.debug("stale_sessions_evicted", count=len(stale_sessions))

            # Purge expired auth tokens (tokens accumulate indefinitely
            # because _get_user_info only removes them on access)
            expired_tokens = []
            with _TOKENS_LOCK:
                for tok, info in list(_TOKENS.items()):
                    if info.get("exp", 0) < now:
                        expired_tokens.append(tok)
                for tok in expired_tokens:
                    _TOKENS.pop(tok, None)
            if expired_tokens:
                logger.debug("expired_tokens_cleaned", count=len(expired_tokens))

            # Evict old batch jobs and enforce cap
            with _BATCH_LOCK:
                stale_batches = []
                for jid, job in list(_BATCH_JOBS.items()):
                    if job.get("status") in ("completed", "failed", "cancelled"):
                        created_at = job.get("createdAt", 0)
                        if isinstance(created_at, str):
                            created_at = 0  # ISO string - treat as old
                        if now - created_at > COMPLETED_BATCH_TTL:
                            stale_batches.append(jid)
                for jid in stale_batches:
                    _BATCH_JOBS.pop(jid, None)
                # Hard cap: if still too many, remove oldest completed first
                if len(_BATCH_JOBS) > MAX_BATCH_JOBS:
                    completed_jobs = sorted(
                        [(jid, j.get("createdAt", 0)) for jid, j in _BATCH_JOBS.items()
                         if j.get("status") in ("completed", "failed", "cancelled")],
                        key=lambda x: x[1],
                    )
                    excess = len(_BATCH_JOBS) - MAX_BATCH_JOBS
                    for jid, _ in completed_jobs[:excess]:
                        _BATCH_JOBS.pop(jid, None)
            if stale_batches:
                logger.debug("stale_batches_evicted", count=len(stale_batches))

        except Exception as e:
            logger.debug(
                "confirmation_cleanup_error",
                error=str(e),
                error_type=type(e).__name__,
            )
