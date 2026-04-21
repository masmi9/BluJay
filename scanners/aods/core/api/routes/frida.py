"""
AODS API Frida Routes
=====================

Frida device management, session control, scripting, WebSocket console,
Corellium integration, and telemetry endpoints.
"""

from __future__ import annotations

import json
import os
import secrets
import time
import uuid
import threading
import concurrent.futures as _futures
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel, Field

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from core.frida.telemetry import read_recent as _frida_read_recent, get_events_path as _frida_events_path
from core.api.shared_state import (
    REPO_ROOT,
    _FRIDA_EVENTS_LOCK,
    _FRIDA_EVENTS,
    _FRIDA_HEALTH_CACHE_LOCK,
    _FRIDA_HEALTH_CACHE,
    _FRIDA_PROCS_CACHE_LOCK,
    _FRIDA_PROCS_CACHE,
    _FRIDA_LOCK,
    _FRIDA_SESSIONS,
    _FRIDA_WS_TOKENS_LOCK,
    _FRIDA_WS_TOKENS,
    _WS_RATE_LIMIT,
    _WS_ALLOWED_ORIGINS,
)
from core.api.auth_helpers import (
    _require_roles,
    _audit,
    _now_iso,
    _redact_pii,
)

# Pydantic models imported from server
from core.api.server import FridaUploadRequest, FridaTargetedRunRequest

router = APIRouter(tags=["frida"])


_FRIDA_PLACEHOLDER_APK: Optional[Path] = None


def _get_frida_placeholder_apk() -> Path:
    """Return path to a placeholder APK for Frida runtime attachment.

    Frida routes attach to running processes by package name and don't need a
    real APK, but APKContext requires a valid path.  We create a temp file
    with a unique name on first call (avoids predictable /tmp paths).
    """
    global _FRIDA_PLACEHOLDER_APK
    if _FRIDA_PLACEHOLDER_APK is not None and _FRIDA_PLACEHOLDER_APK.exists():
        return _FRIDA_PLACEHOLDER_APK
    import tempfile
    try:
        fd = tempfile.NamedTemporaryFile(
            prefix="aods_frida_", suffix=".apk", delete=False
        )
        fd.close()
        _FRIDA_PLACEHOLDER_APK = Path(fd.name)
    except Exception:
        # Fallback: use a hashed name so it's not trivially guessable
        import hashlib
        import os
        tag = hashlib.sha256(os.urandom(16)).hexdigest()[:12]
        ph = Path(tempfile.gettempdir()) / f"aods_frida_{tag}.apk"
        ph.touch()
        _FRIDA_PLACEHOLDER_APK = ph
    return _FRIDA_PLACEHOLDER_APK


def _frida_list_devices() -> List[Dict[str, Any]]:
    try:
        import frida  # type: ignore

        out: List[Dict[str, Any]] = []
        # Best-effort: ensure remote device is registered if local forward is active
        try:
            import socket

            s = socket.socket()
            s.settimeout(0.3)
            s.connect(("127.0.0.1", int(os.getenv("AODS_FRIDA_FORWARD_PORT", "27042"))))
            s.close()
            try:
                dm = frida.get_device_manager()
                dm.add_remote_device(f"127.0.0.1:{int(os.getenv('AODS_FRIDA_FORWARD_PORT', '27042'))}")
            except Exception:
                pass
        except Exception:
            pass
        for d in frida.enumerate_devices():
            out.append(
                {
                    "id": d.id,
                    "name": getattr(d, "name", d.id),
                    "type": getattr(d, "type", "usb"),
                    "online": True,
                    "platform": "android",
                    "arch": "arm64",
                }
            )
        return out
    except Exception:
        return []


def _frida_list_processes(device_id: str) -> List[Dict[str, Any]]:
    # Serve from short-lived cache when fresh to keep UI responsive
    now = time.time()
    with _FRIDA_PROCS_CACHE_LOCK:
        entry = _FRIDA_PROCS_CACHE.get(device_id)
        if entry and (now - float(entry.get("ts", 0))) < 5.0:
            items = entry.get("items") or []
            if isinstance(items, list):
                return list(items)
    # Slow path with guarded timeouts
    try:
        import frida  # type: ignore

        dev = None
        try:
            dev = frida.get_device(device_id)
        except Exception:
            dev = None
        if dev is None:
            try:
                dm = frida.get_device_manager()
                for d in dm.enumerate_devices():
                    if d.id == device_id:
                        dev = d
                        break
            except Exception:
                dev = None
        if dev is None:
            # As a last resort, attach to locally forwarded frida-server
            try:
                port = int(os.getenv("AODS_FRIDA_FORWARD_PORT", "27042"))
                dm = frida.get_device_manager()
                dev = dm.add_remote_device(f"127.0.0.1:{port}")
            except Exception:
                dev = None
        if dev is None:
            return []
        # Enumerate with a timeout to avoid hanging forever

        def _enum() -> List[Dict[str, Any]]:
            procs = dev.enumerate_processes()
            return [{"pid": p.pid, "name": p.name} for p in procs]

        try:
            with _futures.ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(_enum)
                items = fut.result(timeout=4.0)
        except Exception:
            items = []
        # Update cache
        with _FRIDA_PROCS_CACHE_LOCK:
            _FRIDA_PROCS_CACHE[device_id] = {"ts": time.time(), "items": list(items)}
        return items
    except Exception:
        return []


class AttachRequest(BaseModel):
    deviceId: str = Field(..., max_length=256)
    pid: int
    packageName: Optional[str] = Field(default=None, max_length=256)


def _frida_mode(mode_header: Optional[str]) -> str:
    m = (mode_header or os.getenv("AODS_FRIDA_MODE", "standard")).strip().lower()
    if m == "read_only":
        return "read_only"
    if m == "advanced":
        return "advanced"
    return "standard"


class AttachResponse(BaseModel):
    sessionId: str
    status: str


class FridaBaselineResponse(BaseModel):
    facts: Dict[str, Any]


class FridaRPCRequest(BaseModel):
    function: str = Field(..., max_length=256)
    args: Optional[Dict[str, Any]] = None


class FridaRPCResponse(BaseModel):
    id: str
    fn: str
    status: str
    result: Optional[Any] = None
    error: Optional[str] = None


class SaveCustomScriptRequest(BaseModel):
    name: str = Field(..., max_length=256)
    content: str = Field(..., max_length=50_000)
    description: Optional[str] = Field(default=None, max_length=1000)


class CorelliumConnectRequest(BaseModel):
    ip: str = Field(..., max_length=256, description="Corellium device IP (without port)")
    port: int = Field(5555, ge=1, le=65535, description="ADB port (default 5555)")
    manageFrida: bool = Field(True, description="Auto-install/start frida-server on device")
    forwardPort: int = Field(27042, ge=1, le=65535, description="Port to forward for frida-server (default 27042)")


class FridaEnsureRequest(BaseModel):
    ip: str = Field(..., max_length=256, description="Corellium device IP (without port)")
    port: int = Field(5555, ge=1, le=65535)
    forwardPort: int = Field(27042, ge=1, le=65535)
    retries: int = Field(3, ge=1, le=10)
    manageFrida: bool = Field(True)


def _push_frida_event(package: str, event: Dict[str, Any]) -> None:
    try:
        with _FRIDA_EVENTS_LOCK:
            buf = _FRIDA_EVENTS.setdefault(package, [])
            buf.append(event)
            # cap to last 500
            if len(buf) > 500:
                del buf[: len(buf) - 500]
    except Exception:
        pass


def _probe_frida_health(forward_port: int = 27042, timeout_sec: float = 1.5) -> Dict[str, Any]:
    """Probe frida-server health via adb + local TCP connect. Short timeouts and best-effort.
    Returns a small dict for UI display. This runs with small timeouts and is cached by the API endpoint.
    """
    info: Dict[str, Any] = {
        "portOpen": False,
        "pid": None,
        "clientVersion": None,
        "serverVersion": None,
        "binding": f"127.0.0.1:{forward_port}",
        "errors": [],
    }
    # Client version
    try:
        import frida  # type: ignore

        info["clientVersion"] = getattr(frida, "__version__", None)
    except Exception as e:
        info["errors"].append(f"client_version:{e}")
    # PID via adb
    try:
        from core.external.unified_tool_executor import execute_adb_command

        # Try pidof frida-server; ignore failures
        res = execute_adb_command(["shell", "pidof", "frida-server"], timeout=timeout_sec)
        if res.status.name == "SUCCESS":
            pid = (res.stdout or "").strip().splitlines()[0] if res.stdout else None
            info["pid"] = int(pid) if pid and pid.isdigit() else pid or None
    except Exception as e:
        info["errors"].append(f"pid:{e}")
    # Port check
    try:
        import socket

        s = socket.socket()
        s.settimeout(timeout_sec)
        s.connect(("127.0.0.1", int(forward_port)))
        info["portOpen"] = True
        s.close()
    except Exception as e:
        info["errors"].append(f"port:{e}")
    # Server version (best-effort): use frida API remote device enumerate to trigger handshake quickly
    if info["portOpen"]:
        try:
            import frida  # type: ignore

            dm = frida.get_device_manager()
            d = dm.add_remote_device(f"127.0.0.1:{forward_port}")
            # No official server version API; leave None or derive from banner if available later
            _ = d.id  # access to confirm
        except Exception as e:
            info["errors"].append(f"server:{e}")
        # Try to read server version via adb invoking the binary with -v (common convention)
        try:
            from core.external.unified_tool_executor import execute_adb_command

            candidates = [
                ["shell", "sh", "-c", "/data/local/tmp/frida-server -v 2>/dev/null | head -n1"],
                ["shell", "sh", "-c", "frida-server -v 2>/dev/null | head -n1"],
            ]
            for cmd in candidates:
                res = execute_adb_command(cmd, timeout=timeout_sec)
                if res.status.name == "SUCCESS":
                    line = (res.stdout or "").strip().splitlines()[0] if res.stdout else ""
                    if line:
                        # Extract version-like token e.g., "frida-server 16.3.5" -> 16.3.5
                        import re

                        m = re.search(r"(?:frida[- ]server|frida)\s+([0-9]+(?:\.[0-9]+){1,3})", line, re.IGNORECASE)
                        if m:
                            info["serverVersion"] = m.group(1)
                            break
        except Exception as e:
            info["errors"].append(f"server_version:{e}")
    return info


@router.get("/frida/health")
def frida_health(authorization: Optional[str] = Header(default=None), forwardPort: int = 27042) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst"])  # admin or analyst can view health
    now = time.time()
    with _FRIDA_HEALTH_CACHE_LOCK:
        cache = _FRIDA_HEALTH_CACHE
        if cache["payload"] and (now - cache["ts"] < 3.0):
            return cache["payload"]
    payload = _probe_frida_health(forward_port=forwardPort, timeout_sec=1.5)
    # If port is open but no devices, nudge frida to register remote
    try:
        if payload.get("portOpen"):
            import frida  # type: ignore

            dm = frida.get_device_manager()
            dm.add_remote_device(f"127.0.0.1:{forwardPort}")
    except Exception:
        pass
    # Guard: if port is open but availability is effectively false, try to start frida-server quickly and re-probe once
    try:
        need_try = bool(payload.get("portOpen")) and (not payload.get("pid"))
        if need_try:
            ok, msg = _try_start_frida_server_quick(timeout_sec=1.2)
            if ok:
                # small delay then re-probe
                time.sleep(0.4)
                payload = _probe_frida_health(forward_port=forwardPort, timeout_sec=1.2)
                payload.setdefault("guard", {})["autoStart"] = msg
            else:
                payload.setdefault("guard", {})["autoStart"] = msg
    except Exception as e:
        try:
            payload.setdefault("guard", {})["error"] = type(e).__name__
        except Exception:
            pass
    # Execution mode and gating summary
    try:
        static_only = os.getenv("AODS_STATIC_ONLY_HARD", "0") == "1"
        payload["executionMode"] = "static" if static_only else "dynamic"
        payload["dynamicAllowed"] = not static_only
    except Exception:
        payload["executionMode"] = "unknown"
        payload["dynamicAllowed"] = False

    # Determinism status (best-effort from artifacts if present)
    try:
        det_status = "unknown"
        det_updated_at = None
        try:
            base = Path("artifacts/ci_gates/determinism")
            candidates: List[Path] = []
            if base.exists():
                for p in base.rglob("summary.json"):
                    try:
                        candidates.append(p)
                    except Exception:
                        continue
            if candidates:
                latest = max(candidates, key=lambda p: p.stat().st_mtime)
                with latest.open("r", encoding="utf-8") as f:
                    j = json.load(f)
                status_val = str(j.get("status") or j.get("result") or "").lower()
                if status_val in {"pass", "ok", "success"}:
                    det_status = "ok"
                elif status_val in {"fail", "error"}:
                    det_status = "fail"
                det_updated_at = _now_iso()
        except Exception:
            pass
        payload["determinism"] = {"status": det_status, "updatedAt": det_updated_at}
    except Exception:
        payload["determinism"] = {"status": "unknown"}

    # Calibration status (ECE/MCE thresholds + staleness)
    try:
        summary_path = os.getenv("AODS_ML_CALIBRATION_SUMMARY", "models/unified_ml/calibration_summary.json")
        max_ece = float(os.getenv("AODS_ML_MAX_ECE", "0.1"))
        max_mce = float(os.getenv("AODS_ML_MAX_MCE", "0.2"))
        stale_ttl = int(os.getenv("AODS_ML_CALIBRATION_STALE_TTL_SEC", str(7 * 24 * 3600)))
        status = "missing"
        ece_after = None
        mce_after = None
        updated_at = None
        try:
            sp = Path(summary_path)
            if sp.exists():
                with sp.open("r", encoding="utf-8") as f:
                    sj = json.load(f)
                # tolerate field name variants
                ece_after = (
                    float(sj.get("ece_after") or sj.get("eceAfter") or sj.get("ece")) if sj is not None else None
                )
                mce_after = (
                    float(sj.get("mce_after") or sj.get("mceAfter") or sj.get("mce")) if sj is not None else None
                )
                updated_at = sj.get("updated_at") or sj.get("updatedAt") or _now_iso()
                # compute staleness
                stale = False
                try:
                    # very tolerant: parse ISO or treat missing as now
                    pass
                    # using file mtime as fallback
                    mtime = sp.stat().st_mtime
                    stale = (time.time() - mtime) > stale_ttl
                except Exception:
                    stale = False
                # compute status
                if ece_after is not None and mce_after is not None:
                    within = (ece_after <= max_ece) and (mce_after <= max_mce)
                    if within and not stale:
                        status = "ok"
                    elif within and stale:
                        status = "stale"
                    else:
                        status = "fail"
                else:
                    status = "unknown"
        except Exception:
            status = "unknown"
        payload["calibration"] = {
            "status": status,
            "ece_after": ece_after,
            "mce_after": mce_after,
            "updatedAt": updated_at,
        }
    except Exception:
        payload["calibration"] = {"status": "unknown"}

    payload["lastProbeTs"] = _now_iso()
    with _FRIDA_HEALTH_CACHE_LOCK:
        _FRIDA_HEALTH_CACHE.update({"ts": now, "payload": payload})
    return payload


def _try_start_frida_server_quick(timeout_sec: float = 2.0) -> Tuple[bool, str]:
    """Best-effort attempt to start frida-server on the device quickly.
    - Returns (ok, message)
    - Uses small timeouts and avoids blocking the request path.
    """
    try:
        from core.external.unified_tool_executor import execute_adb_command

        # If already running, short-circuit
        res = execute_adb_command(["shell", "pidof", "frida-server"], timeout=timeout_sec)
        if res.status.name == "SUCCESS" and (res.stdout or "").strip():
            return True, "already running"
        # Try regular shell start (no su) with background
        _ = execute_adb_command(
            ["shell", "sh", "-c", "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"], timeout=timeout_sec
        )
        time.sleep(0.25)
        res2 = execute_adb_command(["shell", "pidof", "frida-server"], timeout=timeout_sec)
        if res2.status.name == "SUCCESS" and (res2.stdout or "").strip():
            return True, "started"
        # Try su -c variant if available
        _ = execute_adb_command(
            ["shell", "su", "-c", "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"], timeout=timeout_sec
        )
        time.sleep(0.25)
        res3 = execute_adb_command(["shell", "pidof", "frida-server"], timeout=timeout_sec)
        if res3.status.name == "SUCCESS" and (res3.stdout or "").strip():
            return True, "started (su)"
        return False, "not running"
    except Exception as e:
        return False, f"error: {e}"


@router.post("/frida/session/{package}/scripts")
def frida_upload_script(
    package: str,
    req: FridaUploadRequest,
    authorization: Optional[str] = Header(default=None),
    x_frida_mode: Optional[str] = Header(default=None),
    x_frida_device: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    # Admin only; deny if static-only hard gate is set
    info = _require_roles(authorization, ["admin"])  # raises on fail
    if os.getenv("AODS_STATIC_ONLY_HARD", "0") == "1":
        raise HTTPException(status_code=409, detail="external tools denied in static-only hard mode")
    if _frida_mode(x_frida_mode) == "read_only":
        raise HTTPException(status_code=403, detail="read-only mode: script upload disabled")
    try:
        from core.apk_ctx import APKContext

        # Runtime Frida attachment by package name doesn't require an actual APK file.
        # However, APKContext constructor validates that apk_path exists.
        # We create a minimal placeholder to satisfy this validation when doing
        # live attachment to running processes (package name is set below).
        # The actual APK analysis (if needed) happens separately via scan endpoints.
        ctx = APKContext(apk_path_str=str(_get_frida_placeholder_apk()))
        ctx.package_name = package
        # Analyzer may be unavailable on some hosts; don't hard-fail here, we can still use RuntimeHookEngine path
        try:
            analyzer = ctx.get_frida_analyzer()
        except Exception:
            analyzer = None
        ok = False
        # Prefer RuntimeHookEngine + CustomFridaScriptManager integration
        from plugins.frida_dynamic_analysis.runtime_hooks.hook_engine import RuntimeHookEngine

        # Resolve device: header X-Frida-Device, else prefer usb/remote/tcp, else None
        device_obj = None
        try:
            import frida  # type: ignore

            devices = list(frida.enumerate_devices())
            if x_frida_device:
                for d in devices:
                    if d.id == x_frida_device:
                        device_obj = d
                        break
            if device_obj is None:
                preferred = {"usb", "remote", "tcp"}
                for d in devices:
                    if getattr(d, "type", None) in preferred:
                        device_obj = d
                        break
            if device_obj is None and devices:
                device_obj = devices[0]
        except Exception:
            device_obj = None
        # Best-effort: register remote device if forward exists, to stabilize enumeration
        try:
            import frida as _f  # type: ignore

            _f.get_device_manager().add_remote_device(f"127.0.0.1:{int(os.getenv('AODS_FRIDA_FORWARD_PORT', '27042'))}")
        except Exception:
            pass

        engine = RuntimeHookEngine(device_obj, package)
        if req.mode == "inline" and req.content:
            # Execute immediately and stream events to SSE buffer
            def _runner():
                try:
                    res = engine.execute_hook_script(req.content or "", req.name or "custom")
                    # Emit loaded event regardless
                    try:
                        _push_frida_event(
                            package,
                            {
                                "ts": _now_iso(),
                                "script": req.name,
                                "msg": {
                                    "type": "send",
                                    "payload": {
                                        "type": "custom_script_loaded",
                                        "name": req.name,
                                        "status": res.status.value if hasattr(res, "status") else "ok",
                                    },
                                },
                            },
                        )
                    except Exception:
                        pass
                    # Stream runtime events collected by engine to SSE buffer for a short window
                    seen = 0
                    end_time = time.time() + 120
                    while time.time() < end_time:
                        try:
                            buf = list(getattr(engine, "runtime_events", []) or [])
                            if seen < len(buf):
                                for ev in buf[seen:]:
                                    try:
                                        _push_frida_event(package, {"ts": _now_iso(), "script": req.name, "msg": ev})
                                    except Exception:
                                        continue
                                seen = len(buf)
                            time.sleep(1.0)
                        except Exception:
                            break
                except Exception:
                    try:
                        _push_frida_event(
                            package,
                            {
                                "ts": _now_iso(),
                                "script": req.name,
                                "msg": {"type": "error", "payload": {"type": "custom_script_error", "name": req.name}},
                            },
                        )
                    except Exception:
                        pass

            t = threading.Thread(target=_runner, daemon=True)
            t.start()
            ok = True
        elif req.mode == "file" and req.path:
            resolved = Path(req.path).resolve()
            if not str(resolved).startswith(str(REPO_ROOT.resolve())):
                raise HTTPException(status_code=403, detail="script path outside repository")
            ok = engine.add_custom_script_from_file(str(resolved))
        elif req.mode == "url" and req.url:
            # SSRF prevention: only allow https:// URLs
            if not req.url.startswith("https://"):
                raise HTTPException(status_code=400, detail="only https:// URLs allowed")
            # Block internal/private IPs in URL
            from urllib.parse import urlparse
            _host = urlparse(req.url).hostname or ""
            _blocked = ("127.", "10.", "192.168.", "172.16.", "172.17.",
                        "172.18.", "172.19.", "172.20.", "172.21.",
                        "172.22.", "172.23.", "172.24.", "172.25.",
                        "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.", "169.254.", "0.", "::1",
                        "localhost", "[::1]",
                        # IPv6 private/link-local ranges
                        "fc", "fd", "fe80:", "ff0")
            if any(_host.startswith(b) or _host == b for b in _blocked):
                raise HTTPException(status_code=400, detail="internal URLs not allowed")
            ok = engine.add_custom_script_from_url(req.name, req.url)
        else:
            raise HTTPException(status_code=400, detail="invalid mode or payload")
        if not ok:
            # If we have an analyzer and a script manager available, provide a clearer message
            if analyzer is None:
                raise HTTPException(status_code=503, detail="Frida not available or script engine failed")
            raise HTTPException(status_code=500, detail="failed to load script")
        _audit("frida_load", info.get("user", "api"), package, {"name": req.name, "mode": req.mode})
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("frida_script_load_failed", error=type(e).__name__)
        raise HTTPException(status_code=500, detail="script operation failed")


@router.delete("/frida/session/{package}/scripts/{name}")
def frida_unload_script(package: str, name: str, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    info = _require_roles(authorization, ["admin"])  # raises on fail
    if os.getenv("AODS_STATIC_ONLY_HARD", "0") == "1":
        raise HTTPException(status_code=409, detail="external tools denied in static-only hard mode")
    try:
        from core.apk_ctx import APKContext

        ctx = APKContext(apk_path_str=str(_get_frida_placeholder_apk()))
        ctx.package_name = package
        try:
            analyzer = ctx.get_frida_analyzer()
        except Exception:
            analyzer = None
        ok = False
        if getattr(analyzer, "script_manager", None):
            try:
                ok = bool(analyzer.script_manager.unload_script(name))
            except Exception:
                ok = False
        # If analyzer path failed, attempt a best-effort runtime engine unload (no-op for now)
        if not ok:
            raise HTTPException(status_code=404, detail="script not found")
        _audit("frida_unload", info.get("user", "api"), package, {"name": name})
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("frida_script_unload_failed", error=type(e).__name__)
        raise HTTPException(status_code=500, detail="script operation failed")


@router.get("/frida/session/{package}/status")
def frida_status(package: str, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst"])  # admin or analyst
    # Prefer a lightweight availability check that doesn't require an APKContext
    try:
        from core.frida_framework.frida_connection import FridaConnection  # type: ignore

        fc = FridaConnection()
        ok, msg = fc.check_frida_availability()
        if not ok:
            # Guard: if local forward port is open, attempt a quick frida-server auto-start, then re-probe once
            try:
                import socket

                forward_port = int(os.getenv("AODS_FRIDA_FORWARD_PORT", "27042"))
                s = socket.socket()
                s.settimeout(0.8)
                try:
                    s.connect(("127.0.0.1", forward_port))
                    port_open = True
                except Exception:
                    port_open = False
                try:
                    s.close()
                except Exception:
                    pass
                if port_open:
                    try:
                        from core.external.unified_tool_executor import execute_adb_command

                        # Skip start if already running
                        pid_res = execute_adb_command(["shell", "pidof", "frida-server"], timeout=2.0)
                        already = pid_res.status.name == "SUCCESS" and bool((pid_res.stdout or "").strip())
                        if not already:
                            res1 = execute_adb_command(
                                ["shell", "su", "-c", "/data/local/tmp/frida-server >/dev/null 2>&1 &"], timeout=2.0
                            )
                            if res1.status.name != "SUCCESS":
                                _ = execute_adb_command(
                                    ["shell", "sh", "-c", "/data/local/tmp/frida-server >/dev/null 2>&1 &"], timeout=2.0
                                )
                        # brief wait and remote registration
                        try:
                            time.sleep(0.8)
                        except Exception:
                            pass
                        try:
                            import frida as _f  # type: ignore

                            try:
                                _f.get_device_manager().add_remote_device(f"127.0.0.1:{forward_port}")
                            except Exception:
                                pass
                        except Exception:
                            pass
                        ok2, msg2 = fc.check_frida_availability()
                        if ok2:
                            return {
                                "available": True,
                                "message": msg2,
                                "devices": [getattr(fc.get_device(), "id", None)],
                            }
                        return {"available": False, "message": msg2 or msg}
                    except Exception:
                        return {"available": False, "message": msg}
                return {"available": False, "message": msg}
            except Exception:
                return {"available": False, "message": msg}
    except Exception:
        # Fall back to the legacy APKContext-based detector
        try:
            from core.apk_ctx import APKContext

            ctx = APKContext(apk_path_str=str(_get_frida_placeholder_apk()))
            ctx.package_name = package
            analyzer = ctx.get_frida_analyzer()
            if not analyzer:
                return {"available": False}
            info = analyzer.get_connection_status()
            scripts = list(getattr(analyzer.script_manager, "scripts", {}).keys())
            return {"available": True, "status": info, "scripts": scripts}
        except Exception:
            return {"available": False}
    # If available, attempt to return basic status via frida_connection when possible
    try:
        # Enumerate device list for UI context (best-effort)
        import frida  # type: ignore

        devices = [
            {"id": d.id, "name": getattr(d, "name", d.id), "type": getattr(d, "type", "usb")}
            for d in frida.enumerate_devices()
        ]
    except Exception:
        devices = []
    return {"available": True, "devices": devices}


@router.post("/frida/session/{package}/run-targeted")
def frida_run_targeted(
    package: str,
    body: FridaTargetedRunRequest,
    authorization: Optional[str] = Header(default=None),
    x_frida_mode: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    info = _require_roles(authorization, ["admin"])  # raises on fail
    if os.getenv("AODS_STATIC_ONLY_HARD", "0") == "1":
        raise HTTPException(status_code=409, detail="external tools denied in static-only hard mode")
    mode = _frida_mode(x_frida_mode)
    if mode == "read_only":
        raise HTTPException(status_code=403, detail="read-only mode: targeted run disabled")
    if mode != "advanced":
        # Only allow targeted runs in advanced mode
        raise HTTPException(status_code=403, detail="standard mode: targeted run requires advanced mode")
    try:
        # Prefer enhanced runtime engine if analyzer is unavailable
        try:
            from core.apk_ctx import APKContext

            ctx = APKContext(apk_path_str=str(_get_frida_placeholder_apk()))
            ctx.package_name = package
            analyzer = ctx.get_frida_analyzer()
        except Exception:
            analyzer = None
        if analyzer:
            res = analyzer.run_targeted_analysis(body.types, duration=body.durationSec)
            _audit("frida_run", info.get("user", "api"), package, {"types": body.types, "duration": body.durationSec})
            return {"ok": True, "result": res}
        else:
            # Fallback: indicate unavailability with informative detail
            raise HTTPException(status_code=503, detail="Frida not available or analyzer missing")
    except HTTPException:
        raise
    except Exception as e:
        logger.error("frida_baseline_failed", error=type(e).__name__)
        raise HTTPException(status_code=500, detail="baseline operation failed")


@router.get("/frida/session/{package}/events/stream")
def frida_events_stream(
    package: str,
    authorization: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
):
    # Allow either Authorization header or token query for EventSource compatibility
    if token and not authorization:
        authorization = f"Bearer {token}"
    _require_roles(authorization, ["admin", "analyst"])  # admin or analyst
    if os.getenv("AODS_STATIC_ONLY_HARD", "0") == "1":
        raise HTTPException(status_code=409, detail="events stream denied in static-only hard mode")

    def event_stream():
        last_idx = 0
        heartbeat_counter = 0
        while True:
            try:
                with _FRIDA_EVENTS_LOCK:
                    buf = list(_FRIDA_EVENTS.get(package, []))
                if last_idx < len(buf):
                    for ev in buf[last_idx:]:
                        try:
                            # Apply PII redaction to streaming events
                            yield f"data: {json.dumps(_redact_pii(ev))}\n\n"
                        except Exception:
                            continue
                    last_idx = len(buf)
                    heartbeat_counter = 0
                else:
                    heartbeat_counter += 1
                    if heartbeat_counter >= 30:  # ~30s at 1s interval
                        yield ": heartbeat\n\n"
                        heartbeat_counter = 0
                time.sleep(1.0)
            except Exception as e:
                logger.error("sse_frida_error", error_type=type(e).__name__)
                yield f"event: end\ndata: {json.dumps({'error': 'stream error'})}\n\n"
                break

    resp = StreamingResponse(event_stream(), media_type="text/event-stream")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return resp


@router.get("/frida/devices")
def frida_devices(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst"])  # admin or analyst
    return {"items": _frida_list_devices()}


@router.get("/frida/telemetry/recent")
def frida_telemetry_recent(
    limit: int = Query(default=100, ge=1, le=1000),
    mode: Optional[str] = Query(default=None, description="Filter by mode (attach|spawn|auto)"),
    since: Optional[str] = Query(default=None, description="ISO timestamp lower bound (inclusive)"),
    until: Optional[str] = Query(default=None, description="ISO timestamp upper bound (inclusive)"),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Return recent Frida injection telemetry events (admin-only)."""
    _require_roles(authorization, ["admin"])  # admin only
    try:
        # helper to parse ISO timestamps that may include 'Z'
        def _parse_iso(ts: Optional[str]) -> Optional[float]:
            if not ts:
                return None
            try:
                s = str(ts).replace("Z", "+00:00")
                return datetime.fromisoformat(s).timestamp()
            except Exception:
                return None

        items = _frida_read_recent(limit)
        # apply filters
        want_mode = (mode or "").strip().lower() or None
        ts_lo = _parse_iso(since)
        ts_hi = _parse_iso(until)

        def _keep(it: Dict[str, Any]) -> bool:
            try:
                if want_mode and str(it.get("mode") or "").lower() != want_mode:
                    return False
                if ts_lo is not None or ts_hi is not None:
                    t = _parse_iso(str(it.get("timestamp") or ""))
                    if t is None:
                        return False
                    if ts_lo is not None and t < ts_lo:
                        return False
                    if ts_hi is not None and t > ts_hi:
                        return False
                return True
            except Exception:
                return False

        if want_mode or (ts_lo is not None) or (ts_hi is not None):
            items = [it for it in items if _keep(it)]
        return {"items": items, "count": len(items)}
    except Exception:
        raise HTTPException(status_code=500, detail="telemetry error")


@router.get("/frida/telemetry/summary")
def frida_telemetry_summary(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """Return a compact telemetry summary (admin-only)."""
    _require_roles(authorization, ["admin"])  # admin only
    try:
        items = _frida_read_recent(10000)  # bound memory (read_recent already caps)
        total = len(items)
        success = sum(1 for it in items if bool((it or {}).get("success")))
        failures = total - success
        by_mode: Dict[str, int] = {}
        for it in items:
            try:
                m = str((it or {}).get("mode") or "unknown").lower()
                by_mode[m] = by_mode.get(m, 0) + 1
            except Exception:
                continue
        return {"total": total, "success": success, "failures": failures, "by_mode": by_mode}
    except Exception:
        raise HTTPException(status_code=500, detail="telemetry error")


@router.get("/frida/telemetry/download")
def frida_telemetry_download(authorization: Optional[str] = Header(default=None)) -> FileResponse:
    """Download the raw telemetry JSONL file (admin-only)."""
    _require_roles(authorization, ["admin"])  # admin only
    try:
        p = _frida_events_path().resolve()
        if not p.exists():
            raise HTTPException(status_code=404, detail="telemetry file not found")
        return FileResponse(str(p), filename=p.name, media_type="application/jsonl")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="telemetry download error")


@router.post("/frida/corellium/connect")
def frida_corellium_connect(
    req: CorelliumConnectRequest, authorization: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    """Connect to a Corellium device via ADB, optionally start frida-server, and set up port forwarding."""
    _require_roles(authorization, ["admin", "analyst"])  # admin or analyst
    if os.getenv("AODS_STATIC_ONLY_HARD", "0") == "1":
        raise HTTPException(status_code=409, detail="external tools denied in static-only hard mode")
    device = f"{req.ip}:{req.port}"
    # adb connect (with pre-disconnect; honor provided port strictly)
    try:
        from core.external.unified_tool_executor import execute_adb_command

        try:
            # Best-effort to clear stale connections
            execute_adb_command(["disconnect", device], timeout=4)
        except Exception:
            pass
        # Primary attempt (bounded)
        res = execute_adb_command(["connect", device], timeout=12)
        if res.status.name != "SUCCESS":
            return {"ok": False, "step": "adb_connect", "stderr": res.stderr, "status": res.status.name}
    except Exception as e:
        return {"ok": False, "step": "adb_connect", "error": type(e).__name__}

    # forward frida port
    try:
        from core.external.unified_tool_executor import execute_adb_command

        res = execute_adb_command(
            ["-s", device, "forward", f"tcp:{req.forwardPort}", f"tcp:{req.forwardPort}"], timeout=5
        )
        if res.status.name != "SUCCESS":
            # continue; forwarding is optional if direct route exists
            pass
    except Exception:
        pass

    frida_started = False
    frida_msg = None
    if req.manageFrida:
        try:
            from core.frida_framework.frida_connection import FridaConnection

            fc = FridaConnection()
            frida_started = fc.start_frida_server()
        except Exception as e:
            frida_msg = type(e).__name__

    # summarize devices
    items = _frida_list_devices()
    # Nudge remote registration as part of success flow
    try:
        import frida  # type: ignore

        dm = frida.get_device_manager()
        dm.add_remote_device(f"127.0.0.1:{req.forwardPort}")
        items = _frida_list_devices()
    except Exception:
        pass
    return {"ok": True, "device": device, "frida_started": frida_started, "frida_message": frida_msg, "devices": items}


@router.post("/frida/corellium/ensure")
def frida_corellium_ensure(
    req: FridaEnsureRequest, authorization: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    """Robustly ensure adb connection + frida-server + port-forwarding are active.

    Steps per attempt:
      - adb disconnect (best effort)
      - adb connect ip:port (bounded)
      - adb forward tcp:forwardPort -> tcp:forwardPort (best effort)
      - optional: start frida-server via framework
      - probe health and register remote device
    Retries with small backoff.
    """
    _require_roles(authorization, ["admin", "analyst"])  # admin or analyst
    if os.getenv("AODS_STATIC_ONLY_HARD", "0") == "1":
        raise HTTPException(status_code=409, detail="external tools denied in static-only hard mode")
    device = f"{req.ip}:{req.port}"
    attempts = max(1, min(10, int(req.retries)))
    summary: Dict[str, Any] = {"attempts": attempts, "steps": []}

    for i in range(attempts):
        step: Dict[str, Any] = {"try": i + 1}
        try:
            from core.external.unified_tool_executor import execute_adb_command

            try:
                execute_adb_command(["disconnect", device], timeout=4)
            except Exception:
                pass
            res = execute_adb_command(["connect", device], timeout=12)
            step["adb_connect"] = res.status.name
            if res.status.name != "SUCCESS":
                summary["steps"].append(step)
                time.sleep(1.0 * (i + 1))
                continue
            try:
                fr = execute_adb_command(
                    ["-s", device, "forward", f"tcp:{req.forwardPort}", f"tcp:{req.forwardPort}"], timeout=5
                )
                step["adb_forward"] = fr.status.name
            except Exception as e:
                step["adb_forward"] = f"error:{type(e).__name__}"

            frida_started = False
            if req.manageFrida:
                try:
                    from core.frida_framework.frida_connection import FridaConnection

                    fc = FridaConnection()
                    frida_started = fc.start_frida_server()
                except Exception as e:
                    step["frida_start_error"] = type(e).__name__
            step["frida_started"] = frida_started

            # Probe and register remote
            payload = _probe_frida_health(forward_port=req.forwardPort, timeout_sec=1.5)
            step["health1"] = payload
            try:
                if payload.get("portOpen"):
                    import frida  # type: ignore

                    dm = frida.get_device_manager()
                    dm.add_remote_device(f"127.0.0.1:{req.forwardPort}")
                    step["registered1"] = True
                else:
                    # If port isn't open yet, retry forward once and probe again
                    try:
                        fr2 = execute_adb_command(
                            ["-s", device, "forward", f"tcp:{req.forwardPort}", f"tcp:{req.forwardPort}"], timeout=5
                        )
                        step["adb_forward_retry"] = fr2.status.name
                    except Exception as e2:
                        step["adb_forward_retry"] = f"error:{e2}"
                    time.sleep(0.4)
                    payload = _probe_frida_health(forward_port=req.forwardPort, timeout_sec=1.2)
                    step["health_retry_after_forward"] = payload
                    if payload.get("portOpen"):
                        try:
                            import frida  # type: ignore

                            dm = frida.get_device_manager()
                            dm.add_remote_device(f"127.0.0.1:{req.forwardPort}")
                            step["registered_retry"] = True
                        except Exception as e3:
                            step["registered_retry_error"] = type(e3).__name__
                    else:
                        step["registered_retry"] = False
            except Exception as e:
                step["registered_error"] = type(e).__name__
            # Second confirm probe after small delay to avoid flap-ok
            time.sleep(0.4)
            payload2 = _probe_frida_health(forward_port=req.forwardPort, timeout_sec=1.2)
            step["health2"] = payload2

            summary["steps"].append(step)
            if payload2.get("portOpen") or payload.get("portOpen"):
                # success when port reachable on either probe
                items = _frida_list_devices()
                return {
                    "ok": True,
                    "device": device,
                    "frida_started": frida_started,
                    "devices": items,
                    "summary": summary,
                }
        except Exception as e:
            step["error"] = type(e).__name__
            summary["steps"].append(step)
        time.sleep(1.0 * (i + 1))

    return {"ok": False, "device": device, "summary": summary}


@router.get("/frida/devices/{device_id}/processes")
def frida_processes(device_id: str, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst"])  # admin or analyst
    return {"items": _frida_list_processes(device_id)}


@router.post("/frida/attach", response_model=AttachResponse)
def frida_attach(req: AttachRequest, authorization: Optional[str] = Header(default=None)) -> AttachResponse:
    info = _require_roles(authorization, ["admin", "analyst"])  # admin or analyst
    if os.getenv("AODS_STATIC_ONLY_HARD", "0") == "1":
        raise HTTPException(status_code=409, detail="external tools denied in static-only hard mode")
    sess_id = uuid.uuid4().hex
    with _FRIDA_LOCK:
        _FRIDA_SESSIONS[sess_id] = {
            "deviceId": req.deviceId,
            "pid": req.pid,
            "packageName": req.packageName,
            "user": info.get("user", "api"),
            "startedAt": _now_iso(),
        }
    _audit(
        "frida_attach",
        info.get("user", "api"),
        sess_id,
        {"deviceId": req.deviceId, "pid": req.pid, "packageName": req.packageName},
    )
    return AttachResponse(sessionId=sess_id, status="attached")


@router.post("/frida/detach")
def frida_detach(sessionId: str = Query(...), authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    info = _require_roles(authorization, ["admin", "analyst"])  # admin or analyst
    removed = False
    with _FRIDA_LOCK:
        if sessionId in _FRIDA_SESSIONS:
            _FRIDA_SESSIONS.pop(sessionId, None)
            removed = True
    if removed:
        _audit("frida_detach", info.get("user", "api"), sessionId)
        return {"ok": True}
    raise HTTPException(status_code=404, detail="session not found")


@router.post("/frida/ws-token")
def frida_ws_token(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    info = _require_roles(authorization, ["admin", "analyst"])  # admin or analyst
    if os.getenv("AODS_STATIC_ONLY_HARD", "0") == "1":
        raise HTTPException(status_code=409, detail="ws token denied in static-only hard mode")
    tok = secrets.token_urlsafe(24)
    exp = time.time() + 5 * 60
    with _FRIDA_WS_TOKENS_LOCK:
        _FRIDA_WS_TOKENS[tok] = {"exp": exp, "user": info.get("user", "api")}
    _audit("frida_ws_token", info.get("user", "api"), None, {"exp": exp})
    return {"token": tok, "expiresAt": exp}


@router.websocket("/frida/ws")
async def frida_ws(websocket: WebSocket):
    # Secure token validation via subprotocol; short-lived, single-use tokens
    try:
        if os.getenv("AODS_STATIC_ONLY_HARD", "0") == "1":
            try:
                await websocket.close(code=1008)
            except Exception:
                pass
            return
        try:
            ws_logger = get_logger("aods.ws")
            ws_logger.info(
                "ws_handshake_start",
                client_ip=websocket.client.host if websocket.client else "unknown",
                origin=websocket.headers.get("origin"),
                ws_headers={k: v for k, v in websocket.headers.items() if k.lower().startswith("sec-websocket")},
            )
        except Exception:
            pass
        # Dev bypass: allow connecting without token/origin checks when explicitly enabled
        if os.getenv("AODS_WS_DEV_NOAUTH", "0") == "1":
            try:
                # Honor offered subprotocol if present to satisfy browser expectations
                protos = websocket.headers.get("sec-websocket-protocol") or ""
                parts = [p.strip() for p in protos.split(",") if p.strip()]
                chosen = None
                for p in parts:
                    if p.lower() == "aods-frida":
                        chosen = "aods-frida"
                        break
                if chosen:
                    await websocket.accept(subprotocol=chosen)
                else:
                    await websocket.accept()
                await websocket.send_json(_redact_pii({"type": "hello", "ts": _now_iso(), "dev": True}))
                _WS_DEV_MAX_MSG = 65536
                while True:
                    try:
                        raw = await websocket.receive_text()
                        if len(raw) > _WS_DEV_MAX_MSG:
                            await websocket.close(code=1009)
                            break
                        msg = json.loads(raw)
                        await websocket.send_json(_redact_pii({"type": "ack", "received": msg}))
                    except WebSocketDisconnect:
                        break
                    except json.JSONDecodeError:
                        await websocket.send_json(_redact_pii({"type": "error", "error": "invalid JSON"}))
                        break
                    except Exception as e:
                        await websocket.send_json(_redact_pii({"type": "error", "error": type(e).__name__}))
                        break
                return
            except Exception:
                try:
                    await websocket.close()
                except Exception:
                    pass
                return

        # Basic per-IP rate limiting for handshake attempts
        ip = websocket.client.host if websocket.client else "unknown"
        now = time.time()
        bucket = _WS_RATE_LIMIT.get(ip)
        if not bucket or now > bucket[1]:
            # reset window (60s)
            _WS_RATE_LIMIT[ip] = [0, now + 60.0]
        else:
            if bucket[0] >= 30:  # max 30 attempts/min
                await websocket.close(code=4429)
                return
            bucket[0] += 1

        # Optional Origin check when present
        origin = websocket.headers.get("origin")
        if origin:
            allow_all = os.getenv("AODS_WS_ORIGIN_ALLOW_ALL", "0") == "1"
            if allow_all:
                logger.warning("AODS_WS_ORIGIN_ALLOW_ALL is set - WebSocket origin check BYPASSED (testing only)")
            if not allow_all and origin not in _WS_ALLOWED_ORIGINS:
                await websocket.close(code=4403)
                return

        # Extract token from Sec-WebSocket-Protocol header or query string (fallback)
        protos = websocket.headers.get("sec-websocket-protocol") or ""
        parts = [p.strip() for p in protos.split(",") if p.strip()]
        token = None
        chosen = None
        for p in parts:
            if p.lower() == "aods-frida":
                chosen = "aods-frida"
            if p.startswith("token."):
                token = p[len("token.") :]
        if not token:
            try:
                qp = websocket.query_params or {}
                token = qp.get("token") if hasattr(qp, "get") else None
            except Exception:
                token = None
        if not token:
            await websocket.close(code=4401)
            return

        with _FRIDA_WS_TOKENS_LOCK:
            tok_info = _FRIDA_WS_TOKENS.get(token)
            if tok_info:
                # Support both old (float) and new (dict) format
                exp = tok_info["exp"] if isinstance(tok_info, dict) else tok_info
                if exp >= now:
                    _FRIDA_WS_TOKENS.pop(token, None)  # single-use
                else:
                    await websocket.close(code=4403)
                    return
            else:
                await websocket.close(code=4403)
                return

        try:
            if chosen:
                await websocket.accept(subprotocol=chosen)
            else:
                await websocket.accept()
        except Exception:
            # Best-effort accept without subprotocol
            await websocket.accept()
        # Simple heartbeat
        await websocket.send_json(_redact_pii({"type": "hello", "ts": _now_iso()}))
        _WS_MAX_MSG_SIZE = 65536  # 64KB max per message
        while True:
            try:
                raw = await websocket.receive_text()
                if len(raw) > _WS_MAX_MSG_SIZE:
                    await websocket.close(code=1009)  # message too big
                    break
                msg = json.loads(raw)
                await websocket.send_json(_redact_pii({"type": "ack", "received": msg}))
            except WebSocketDisconnect:
                break
            except json.JSONDecodeError:
                await websocket.send_json(_redact_pii({"type": "error", "error": "invalid JSON"}))
                break
            except Exception as e:
                await websocket.send_json(_redact_pii({"type": "error", "error": type(e).__name__}))
                break
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass


@router.post("/frida/session/{session_id}/baseline", response_model=FridaBaselineResponse)
def frida_baseline(session_id: str, authorization: Optional[str] = Header(default=None)) -> FridaBaselineResponse:
    # MVP: return static facts; future: run baseline script via analyzer
    _require_roles(authorization, ["admin", "analyst"])  # admin or analyst
    with _FRIDA_LOCK:
        sess = _FRIDA_SESSIONS.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="session not found")
    facts = {
        "env": {"arch": "arm64", "platform": "android"},
        "antiDebug": {"detected": False},
        "sslHooks": {"available": True},
    }
    # Optional analyzer-backed enrichment
    try:
        if os.getenv("AODS_FRIDA_ANALYZER_ENABLE", "0") == "1":
            from core.apk_ctx import APKContext  # type: ignore

            ctx = APKContext(apk_path_str=str(_get_frida_placeholder_apk()))
            ctx.package_name = sess.get("packageName") or None
            analyzer = ctx.get_frida_analyzer()
            if analyzer:
                info = analyzer.get_connection_status()
                facts["connectionStatus"] = info
    except Exception:
        pass
    return FridaBaselineResponse(facts=facts)


@router.post("/frida/session/{session_id}/rpc", response_model=FridaRPCResponse)
def frida_rpc(
    session_id: str,
    body: FridaRPCRequest,
    authorization: Optional[str] = Header(default=None),
    x_frida_mode: Optional[str] = Header(default=None),
    x_frida_package: Optional[str] = Header(default=None),
) -> FridaRPCResponse:
    _require_roles(authorization, ["admin"])  # admin-only
    with _FRIDA_LOCK:
        if session_id not in _FRIDA_SESSIONS:
            raise HTTPException(status_code=404, detail="session not found")
    if _frida_mode(x_frida_mode) == "read_only":
        return FridaRPCResponse(
            id=uuid.uuid4().hex, fn=body.function, status="error", error="read-only mode: RPC disabled"
        )
    # MVP: echo result; future: call rpc.exports via analyzer
    call_id = uuid.uuid4().hex
    try:
        # Broadcast RPC call event to Live Events (best-effort)
        try:
            target_pkg = x_frida_package
            if not target_pkg:
                with _FRIDA_LOCK:
                    sess = _FRIDA_SESSIONS.get(session_id)
                if sess:
                    target_pkg = sess.get("packageName")
            if target_pkg:
                _push_frida_event(
                    target_pkg,
                    {
                        "ts": _now_iso(),
                        "script": "rpc",
                        "msg": {"type": "rpc_call", "id": call_id, "fn": body.function, "args": body.args or {}},
                    },
                )
        except Exception:
            pass

        result = {"echo": body.args or {}}
        # Optional analyzer-backed RPC (guarded)
        if os.getenv("AODS_FRIDA_ANALYZER_ENABLE", "0") == "1":
            try:
                from core.apk_ctx import APKContext  # type: ignore

                ctx = APKContext(apk_path=_get_frida_placeholder_apk())
                analyzer = ctx.get_frida_analyzer()
                if analyzer and hasattr(analyzer, "script_manager"):
                    # Placeholder: return connection status on any fn
                    result = {"connectionStatus": analyzer.get_connection_status()}
            except Exception:
                pass
        resp = FridaRPCResponse(id=call_id, fn=body.function, status="ok", result=result)
        try:
            target_pkg2 = x_frida_package
            if not target_pkg2:
                with _FRIDA_LOCK:
                    sess = _FRIDA_SESSIONS.get(session_id)
                if sess:
                    target_pkg2 = sess.get("packageName")
            if target_pkg2:
                _push_frida_event(
                    target_pkg2,
                    {
                        "ts": _now_iso(),
                        "script": "rpc",
                        "msg": {
                            "type": "rpc_result",
                            "id": call_id,
                            "fn": body.function,
                            "status": "ok",
                            "result": result,
                        },
                    },
                )
        except Exception:
            pass
        return resp
    except Exception as e:
        try:
            target_pkg3 = x_frida_package
            if not target_pkg3:
                with _FRIDA_LOCK:
                    sess = _FRIDA_SESSIONS.get(session_id)
                if sess:
                    target_pkg3 = sess.get("packageName")
            if target_pkg3:
                _push_frida_event(
                    target_pkg3,
                    {
                        "ts": _now_iso(),
                        "script": "rpc",
                        "msg": {
                            "type": "rpc_result",
                            "id": call_id,
                            "fn": body.function,
                            "status": "error",
                            "error": type(e).__name__,
                        },
                    },
                )
        except Exception:
            pass
        return FridaRPCResponse(id=call_id, fn=body.function, status="error", error=type(e).__name__)
