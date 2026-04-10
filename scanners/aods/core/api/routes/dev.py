"""
AODS API Dev Routes
===================

Development server controls, CI toggles, and decompilation policy endpoints.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

try:
    from core.shared_infrastructure.configuration.unified_facade import (
        get_configuration_value as _get_cfg,
        set_configuration_value as _set_cfg,
    )
except Exception:
    _get_cfg = None  # type: ignore
    _set_cfg = None  # type: ignore

from core.api.shared_state import (
    REPO_ROOT,
    AUDIT_LOG,
    _API_PID_FILES,
    _UI_PID_FILES,
    _DEVCTL,
)
from core.api.auth_helpers import _require_roles, _now_iso

router = APIRouter(tags=["dev"])

# -------------------- Dev Server Controls (admin) --------------------


class _DevTargets(BaseModel):
    targets: Optional[List[str]] = Field(default=None, max_length=10)  # ["api", "ui"]


def _pid_alive(pid: Optional[int]) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _read_pid(p: Path) -> Optional[int]:
    try:
        txt = p.read_text().strip()
        return int(txt) if txt else None
    except Exception:
        return None


def _port_listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except Exception:
        return False


def _dev_status_payload() -> Dict[str, Any]:
    def _read_first(paths: List[Path]) -> Optional[int]:
        for p in paths:
            pid = _read_pid(p)
            if pid:
                return pid
        return None

    api_pid = _read_first(_API_PID_FILES)
    ui_pid = _read_first(_UI_PID_FILES)
    # Collect network info

    def _collect_net_info() -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "ips": [],
            "listeners": [],
            "api": {"host": "127.0.0.1", "port": 8088, "url": "http://127.0.0.1:8088/api"},
            "ui": {"host": "127.0.0.1", "port": 5088, "url": "http://127.0.0.1:5088"},
        }
        # Try hostname -I for IPv4 addresses
        try:
            cp = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=1.0)
            if cp.returncode == 0:
                ips = [p for p in (cp.stdout or "").strip().split() if p]
                # Always include loopback
                if "127.0.0.1" not in ips:
                    ips.append("127.0.0.1")
                info["ips"] = ips
        except Exception:
            info["ips"] = ["127.0.0.1"]
        # Try ss -ltn to list listeners
        try:
            cp2 = subprocess.run(["ss", "-ltn"], capture_output=True, text=True, timeout=1.0)
            if cp2.returncode == 0:
                lines = (cp2.stdout or "").splitlines()
                for ln in lines[1:]:
                    try:
                        parts = [p for p in ln.split() if p]
                        if len(parts) < 5:
                            continue
                        local = parts[3]  # e.g., 127.0.0.1:8088 or [::]:5088
                        # Normalize and split host/port
                        host = local
                        port = None
                        if local.startswith("["):
                            # IPv6
                            if "]:" in local:
                                host, port = local.rsplit(":", 1)
                        else:
                            if ":" in local:
                                host, port = local.rsplit(":", 1)
                        info["listeners"].append(
                            {"local": local, "host": host, "port": (int(port) if (port and port.isdigit()) else port)}
                        )
                    except Exception:
                        continue
        except Exception:
            pass
        return info

    net = _collect_net_info()
    # Discover all matching processes for API/UI

    def _read_cmdline(pid: int) -> Optional[str]:
        try:
            p = Path(f"/proc/{pid}/cmdline")
            if p.exists():
                raw = p.read_bytes()
                if raw:
                    return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except Exception:
            pass
        # Fallback to ps
        try:
            cp = subprocess.run(["ps", "-p", str(pid), "-o", "args="], capture_output=True, text=True, timeout=1.0)
            if cp.returncode == 0:
                return (cp.stdout or "").strip()
        except Exception:
            pass
        return None

    def _pids_listening_on(port: int) -> List[int]:
        pids: List[int] = []
        try:
            cp = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, timeout=1.0)
            if cp.returncode != 0:
                return pids
            for ln in (cp.stdout or "").splitlines()[1:]:
                if f":{port} " in ln or ln.rstrip().endswith(f":{port}"):
                    # users:("proc",pid=1234,fd=...)
                    for m in re.finditer(r"pid=(\d+)", ln):
                        try:
                            pid = int(m.group(1))
                            if pid not in pids:
                                pids.append(pid)
                        except Exception:
                            continue
        except Exception:
            pass
        return pids

    def _list_instances(
        terms_list: List[List[str]], regex_list: Optional[List[str]] = None, listen_port: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        # First try pgrep with regex patterns for robustness
        try:
            for rgx in regex_list or []:
                try:
                    cp0 = subprocess.run(["pgrep", "-a", "-f", rgx], capture_output=True, text=True, timeout=1.0)
                    if cp0.returncode == 0 and cp0.stdout:
                        for ln in (cp0.stdout or "").splitlines():
                            try:
                                pid_str, cmd = ln.strip().split(None, 1)
                                pid = int(pid_str)
                                out.append({"pid": pid, "cmd": cmd[:200]})
                            except Exception:
                                continue
                except Exception:
                    continue
        except Exception:
            pass
        # Fallback to ps scan if pgrep yielded nothing
        if not out:
            try:
                cp = subprocess.run(["ps", "-eo", "pid,comm,args"], capture_output=True, text=True, timeout=1.5)
                if cp.returncode != 0:
                    return out
                lines = (cp.stdout or "").splitlines()
                for ln in lines[1:]:
                    try:
                        parts = ln.strip().split(None, 2)
                        if len(parts) < 3:
                            continue
                        pid_str, comm, args = parts[0], parts[1], parts[2]
                        pid = int(pid_str)
                        s = f"{comm} {args}".lower()
                        for terms in terms_list:
                            if all(t in s for t in terms):
                                out.append({"pid": pid, "cmd": args[:200]})
                                break
                    except Exception:
                        continue
            except Exception:
                pass
        # de-dup by pid
        seen = set()
        uniq: List[Dict[str, Any]] = []
        for it in out:
            if it["pid"] in seen:
                continue
            seen.add(it["pid"])
            uniq.append(it)
        # Merge listeners on the port (if provided)
        if listen_port is not None:
            for pid in _pids_listening_on(listen_port):
                if pid not in seen:
                    uniq.append({"pid": pid, "cmd": _read_cmdline(pid) or ""})
                    seen.add(pid)
        return uniq

    api_instances = _list_instances(
        [["uvicorn", "core.api.server:app"], ["python", "uvicorn", "core.api.server:app"]],
        regex_list=[r"uvicorn.*core\.api\.server:app", r"python.*-m\s+uvicorn.*core\.api\.server:app"],
        listen_port=8088,
    )
    ui_instances = _list_instances(
        [["vite"], ["node", "vite"], ["npm", "run", "dev"]],
        regex_list=[r"node.*vite", r"vite(\s|$)", r"npm.*run.*dev"],
        listen_port=5088,
    )
    ports = {"api": _port_listening(8088), "ui": _port_listening(5088)}
    api_running = bool(ports["api"]) or _pid_alive(api_pid)
    ui_running = bool(ports["ui"]) or _pid_alive(ui_pid)
    payload = {
        "api": {"pid": api_pid, "running": api_running},
        "ui": {"pid": ui_pid, "running": ui_running},
        "ports": ports,
        "devctl": str(_DEVCTL),
        "network": net,
        "apiInstances": api_instances,
        "uiInstances": ui_instances,
    }
    # If instance lists are empty but PID files exist, include them as instances
    try:
        if not payload["apiInstances"] and api_pid:
            payload["apiInstances"] = [{"pid": api_pid, "cmd": _read_cmdline(api_pid) or ""}]
    except Exception:
        pass
    try:
        if not payload["uiInstances"] and ui_pid:
            payload["uiInstances"] = [{"pid": ui_pid, "cmd": _read_cmdline(ui_pid) or ""}]
    except Exception:
        pass
    return payload


@router.get("/dev/servers/status")
def dev_servers_status(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin"])
    return _dev_status_payload()


def _run_devctl(args: List[str]) -> Tuple[int, str, str]:
    try:
        if not _DEVCTL.exists():
            return 127, "", f"devctl not found at {_DEVCTL}"
        proc = subprocess.Popen(
            [str(_DEVCTL)] + args, cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        try:
            out, err = proc.communicate(timeout=6)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
            out, err = "", "timeout"
        return int(proc.returncode or 0), (out or ""), (err or "")
    except Exception as e:
        return 1, "", type(e).__name__


def _normalize_targets(body: Optional[_DevTargets]) -> List[str]:
    t = body.targets if body and isinstance(body.targets, list) else ["api", "ui"]  # type: ignore[attr-defined]
    vals: List[str] = []
    for x in t:
        v = str(x or "").lower().strip()
        if v in ("api", "ui") and v not in vals:
            vals.append(v)
    return vals or ["api", "ui"]


def _run_service_manager(action: str, targets: List[str]) -> None:
    svc = REPO_ROOT / "scripts" / "start_services.sh"
    used_service = False
    # If API is involved and start_services.sh exists, prefer it to keep PID files in sync
    if "api" in targets and svc.exists():
        try:
            subprocess.run([str(svc), action], cwd=str(REPO_ROOT), check=False, timeout=20)
            used_service = True
        except Exception:
            pass
    # For UI or when start_services is unavailable, use devctl per-target
    if not used_service:
        for t in targets:
            try:
                _ = _run_devctl([f"{t}-{action}"])
            except Exception:
                continue


@router.post("/dev/servers/start")
def dev_servers_start(body: _DevTargets, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin"])  # admin-only
    targets = _normalize_targets(body)
    _run_service_manager("start", targets)
    return _dev_status_payload()


@router.post("/dev/servers/stop")
def dev_servers_stop(body: _DevTargets, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin"])  # admin-only
    targets = _normalize_targets(body)
    _run_service_manager("stop", targets)
    return _dev_status_payload()


@router.post("/dev/servers/restart")
def dev_servers_restart(body: _DevTargets, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin"])  # admin-only
    targets = _normalize_targets(body)
    _run_service_manager("restart", targets)
    return _dev_status_payload()


@router.post("/dev/servers/stop_all")
def dev_servers_stop_all(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin"])  # admin-only
    # Best-effort: stop via devctl and clear known PID files
    try:
        _ = _run_devctl(["stop"])  # stop both
    except Exception:
        pass
    # Remove PID files if present
    try:
        for p in [
            REPO_ROOT / "artifacts" / "pids" / "api.pid",
            REPO_ROOT / "artifacts" / "pids" / "ui.pid",
            REPO_ROOT / ".logs" / "dev" / "api.pid",
            REPO_ROOT / ".logs" / "dev" / "ui.pid",
        ]:
            try:
                p.unlink(missing_ok=True)  # type: ignore[arg-type]
            except Exception:
                pass
    except Exception:
        pass
    return _dev_status_payload()


@router.post("/dev/servers/start_clean")
def dev_servers_start_clean(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin"])  # admin-only
    try:
        _ = _run_devctl(["stop"])  # stop both
    except Exception:
        pass
    try:
        _ = _run_devctl(["start"])  # start both
    except Exception:
        pass
    return _dev_status_payload()


# -------------------- CI Toggles (Critical Gate Toggles) --------------------


class _CIToggles(BaseModel):
    """CI toggle update request with schema validation."""
    model_config = ConfigDict(extra="forbid")
    failOnCritical: Optional[bool] = None
    failOnHigh: Optional[bool] = None
    dedupStrict: Optional[bool] = None


def _cfg_get_bool(key: str, default: bool = False) -> bool:
    if not _get_cfg:
        return default
    try:
        v = _get_cfg(key, default)
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return bool(v)
        if isinstance(v, str):
            return v.strip().lower() in {"1", "true", "yes", "on"}
    except Exception:
        return default
    return default


def _cfg_set(key: str, value: Any) -> None:
    if not _set_cfg:
        return
    try:
        _set_cfg(key, value, precedence="runtime")  # type: ignore[arg-type]
    except Exception:
        pass


@router.get("/ci/toggles")
def get_ci_toggles(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    now = _now_iso()
    toggles = {
        "failOnCritical": _cfg_get_bool("ci.toggles.fail_on_critical", False),
        "failOnHigh": _cfg_get_bool("ci.toggles.fail_on_high", False),
        "dedupStrict": _cfg_get_bool("ci.toggles.dedup_strict", False),
        "last_updated": _get_cfg("ci.toggles.last_updated", None) if _get_cfg else None,
    }
    if not toggles["last_updated"]:
        toggles["last_updated"] = now
        _cfg_set("ci.toggles.last_updated", toggles["last_updated"])
    return toggles


@router.patch("/ci/toggles")
def update_ci_toggles(update: _CIToggles, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin"])
    if update.failOnCritical is not None:
        _cfg_set("ci.toggles.fail_on_critical", bool(update.failOnCritical))
    if update.failOnHigh is not None:
        _cfg_set("ci.toggles.fail_on_high", bool(update.failOnHigh))
    if update.dedupStrict is not None:
        _cfg_set("ci.toggles.dedup_strict", bool(update.dedupStrict))
    now = _now_iso()
    _cfg_set("ci.toggles.last_updated", now)
    out = get_ci_toggles()
    out["last_updated"] = now
    # Audit trail for toggle changes
    try:
        from core.api.auth_helpers import _audit
        user_info = _require_roles(authorization, ["admin"])
        username = user_info.get("user", "unknown") if isinstance(user_info, dict) else "admin"
        _audit("toggle_change", username, "ci_toggles", {
            "changes": update.model_dump(exclude_none=True),
            "new_state": {k: v for k, v in out.items() if k != "last_updated"},
        })
    except Exception:
        pass
    return out


@router.get("/ci/metrics")
def get_ci_metrics(
    authorization: Optional[str] = Header(default=None),
    history: int = Query(0, ge=0, le=50, description="Include last N historical runs"),
) -> Dict[str, Any]:
    """Return latest CI quality gate metrics and optional history.

    Reads the consolidated summary from the last gate run.
    Requires analyst role or higher.
    """
    _require_roles(authorization, ["admin", "analyst"])

    result: Dict[str, Any] = {"status": "ok"}

    # Latest summary
    summary_path = Path("artifacts/ci_gates/consolidated_summary.json")
    if summary_path.exists():
        try:
            result["latest"] = json.loads(summary_path.read_text())
        except Exception:
            result["latest"] = None
    else:
        result["latest"] = None

    # Historical runs
    if history > 0:
        history_path = Path("artifacts/ci_gates/ci_run_history.jsonl")
        runs: list = []
        if history_path.exists():
            try:
                lines = history_path.read_text().strip().split("\n")
                for line in lines[-history:]:
                    if line.strip():
                        runs.append(json.loads(line))
            except Exception:
                pass
        result["history"] = runs

    return result


@router.get("/decomp/policy")
def decomp_policy(
    apkPath: str = Query(..., description="Absolute path to APK file", examples=["/path/to/app.apk"]),
    profile: str = Query("production", description="Profile name: production|staging|dev"),
    requirements: Optional[str] = Query(
        None, description="Comma-separated plugin requirements e.g. 'imports,resources'"
    ),
    preferredOutputRoot: Optional[str] = Query(
        None, description="Optional preferred output root for decompiled sources"
    ),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst"])
    try:
        from core.decompilation_policy_resolver import DecompilationPolicyResolver

        reqs = None
        if requirements:
            reqs = [s.strip() for s in requirements.split(",") if s and s.strip()]
        resolver = DecompilationPolicyResolver()
        pol = resolver.resolve_policy(
            apk_path=apkPath,
            profile=profile,
            plugin_requirements=reqs,
            preferred_output_root=preferredOutputRoot,
        )
        return {
            "outputDir": pol.output_dir,
            "maxThreads": pol.max_threads,
            "memoryLimitMb": pol.memory_limit_mb,
            "flags": pol.flags,
            "mode": pol.mode.value,
            "reason": pol.reason,
        }
    except Exception:
        # Fallback: try unified config snapshot if resolver fails
        try:
            if _get_cfg:  # type: ignore
                mode = _get_cfg("decomp.policy.mode", None)
                max_threads = _get_cfg("decomp.policy.max_threads", None)
                memory_mb = _get_cfg("decomp.policy.memory_mb", None)
                flags = _get_cfg("decomp.policy.flags", None)
                out_dir = _get_cfg("decomp.policy.output_dir", None)
                if any(v is not None for v in (mode, max_threads, memory_mb, flags, out_dir)):
                    return {
                        "outputDir": out_dir,
                        "maxThreads": max_threads,
                        "memoryLimitMb": memory_mb,
                        "flags": flags or [],
                        "mode": mode or "optimized",
                        "reason": "served-from-config",
                    }
        except Exception:
            pass
        raise HTTPException(status_code=400, detail="failed to resolve decompilation policy")


class DecompPolicyUpdate(BaseModel):
    preset: Optional[str] = Field(default=None, max_length=32, description="optimized|balanced|full")
    mode: Optional[str] = Field(default=None, max_length=32, description="optimized|full|custom")
    max_threads: Optional[int] = Field(default=None, ge=1, le=32)
    memory_mb: Optional[int] = Field(default=None, ge=256, le=65536)
    flags: Optional[List[str]] = Field(default=None, max_length=50)


@router.patch("/decomp/policy")
def patch_decomp_policy(
    req: DecompPolicyUpdate,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Persist admin-approved decompilation policy overrides to unified config.

    Safety caps enforced via validation: max_threads<=32, memory_mb<=65536, flags allowlist.
    """
    _require_roles(authorization, ["admin"])  # type: ignore

    # Preset templates
    preset_defaults: Dict[str, Dict[str, Any]] = {
        "optimized": {"mode": "optimized", "max_threads": 4, "memory_mb": 2048, "flags": ["--no-debug-info"]},
        "balanced": {"mode": "optimized", "max_threads": 8, "memory_mb": 4096, "flags": ["--no-debug-info", "--deobf"]},
        "full": {
            "mode": "full",
            "max_threads": 8,
            "memory_mb": 8192,
            "flags": ["--no-debug-info", "--deobf", "--no-replace-consts"],
        },
    }

    effective: Dict[str, Any] = {}
    if req.preset:
        p = (req.preset or "").strip().lower()
        if p not in preset_defaults:
            raise HTTPException(status_code=400, detail="invalid preset")
        effective.update(preset_defaults[p])
    if req.mode:
        m = (req.mode or "").strip().lower()
        if m not in {"optimized", "full", "custom"}:
            raise HTTPException(status_code=400, detail="invalid mode")
        effective["mode"] = m
    if req.max_threads is not None:
        effective["max_threads"] = int(req.max_threads)
    if req.memory_mb is not None:
        effective["memory_mb"] = int(req.memory_mb)
    if req.flags is not None:
        allowlist = {"--no-debug-info", "--deobf", "--no-replace-consts", "--fs-case-sensitive"}
        invalid = [f for f in req.flags if f not in allowlist]
        if invalid:
            raise HTTPException(status_code=400, detail="invalid flags")
        effective["flags"] = list(req.flags)

    try:
        if not _set_cfg:  # type: ignore
            raise RuntimeError("unified configuration not available")
        if "mode" in effective:
            _set_cfg("decomp.policy.mode", effective["mode"])  # type: ignore
        if "max_threads" in effective:
            _set_cfg("decomp.policy.max_threads", effective["max_threads"])  # type: ignore
        if "memory_mb" in effective:
            _set_cfg("decomp.policy.memory_mb", effective["memory_mb"])  # type: ignore
        if "flags" in effective:
            _set_cfg("decomp.policy.flags", effective["flags"])  # type: ignore
        # Track audit
        try:
            with open(AUDIT_LOG, "a", encoding="utf-8") as af:
                af.write(
                    json.dumps(
                        {"ts": _now_iso(), "actor": "admin", "action": "decomp_policy.update", "effective": effective}
                    )
                    + "\n"
                )
        except Exception:
            pass
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="failed to persist policy")

    return {"updated": True, "effective": effective}
