"""
FastAPI server exposing minimal endpoints for the AODS UI roadmap.

Endpoints (prefix /api):
- GET    /health                          → basic health check
- GET    /tools/status                    → external tools availability (ADB/FRIDA/JADX)
- POST   /scans/start                     → start a scan for an APK
- GET    /scans/{session_id}/progress     → scan progress/status
- GET    /scans/results                   → discover latest report JSONs

Notes:
- This is a focused, minimal surface to unblock Phase 2 UI integration.
- Scan progress is coarse (running/completed/failed) until richer plumbing is wired.
- Uses subprocess to invoke dyna.py in a background thread; respects env flags.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import secrets
import threading
import zipfile
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Configure structured logging before other AODS imports
from core.logging_config import (
    configure_structlog,
    get_logger,
    bind_user_context,
)

configure_structlog()
logger = get_logger(__name__)

from fastapi import FastAPI, APIRouter, HTTPException, Header, Query, UploadFile, File  # noqa: E402
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse, JSONResponse  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from starlette.middleware.base import BaseHTTPMiddleware  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402
from fastapi.openapi.utils import get_openapi  # noqa: E402
from starlette.staticfiles import StaticFiles  # noqa: E402

from core.external.unified_tool_executor import get_global_executor, ToolType  # noqa: E402
from core.enterprise.rbac_manager import (  # noqa: E402
    ResourceType as RBACResourceType,
    Permission as RBACPermission,
)
from core.api.middleware import RequestLoggingMiddleware  # noqa: E402

# Define API router early so decorators below can reference it
api = APIRouter(prefix="/api")

# ---------------------------------------------------------------------------
# Shared state and auth helpers (extracted to separate modules)
# ---------------------------------------------------------------------------
from core.api.shared_state import (  # noqa: E402
    REPO_ROOT,
    CI_GATES_DIR,
    AUDIT_LOG,
    CURATION_DIR,
    _SESSIONS_LOCK,
    _SESSIONS,
    _BATCH_LOCK,
    _BATCH_JOBS,
    _TOKENS_LOCK,
    _TOKENS,
)
from core.api.auth_helpers import (  # noqa: E402
    _extract_token,
    _get_user_info,
    _require_roles,
    _enforce_access,
    _authenticate_user,
    _audit,
    _now_iso,
    _RBAC,
)


class StartScanRequest(BaseModel):
    apkPath: str = Field(..., max_length=2048, description="Absolute path to APK file to scan")
    packageName: Optional[str] = Field(
        default=None, max_length=256,
        description="Explicit package name to skip auto-detection."
    )
    enableThresholdFiltering: Optional[bool] = Field(
        default=False,
        description="If true, backend reporting will filter findings below ML thresholds (High/Critical always preserved).",  # noqa: E501
    )

    class ScanOptions(BaseModel):
        # Core (already supported)
        enableThresholdFiltering: Optional[bool] = Field(default=None)
        staticOnly: Optional[bool] = Field(default=None)
        resourceConstrained: Optional[bool] = Field(default=None)
        fridaMode: Optional[str] = Field(default=None, max_length=32, description="standard|read_only|advanced")
        maxWorkers: Optional[int] = Field(default=None, ge=1, le=64)
        timeoutsProfile: Optional[str] = Field(default=None, max_length=32, description="default|slow|fast")
        pluginsInclude: Optional[List[str]] = Field(default=None, max_length=100)
        pluginsExclude: Optional[List[str]] = Field(default=None, max_length=100)
        # New core wiring (Stage 1)
        profile: Optional[str] = Field(default=None, max_length=32, description="lightning|fast|standard|deep")
        mode: Optional[str] = Field(default=None, max_length=32, description="safe|deep")
        formats: Optional[List[str]] = Field(default=None, max_length=10, description="txt|json|csv|html|all")
        # CI flags
        ciMode: Optional[bool] = Field(default=None)
        failOnCritical: Optional[bool] = Field(default=None)
        failOnHigh: Optional[bool] = Field(default=None)
        # Package confirmation
        autoConfirmPackage: Optional[bool] = Field(
            default=None, description="If true, auto-accept low-confidence package detection (useful for CI/batch mode)"
        )
        # Frameworks & Compliance (Stage 2)
        frameworks: Optional[List[str]] = Field(
            default=None, max_length=10, description="flutter|react_native|xamarin|pwa|all"
        )
        compliance: Optional[str] = Field(default=None, max_length=32, description="nist|masvs|owasp|iso27001")
        # ML / Dedup / Progressive
        mlConfidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
        mlModelsPath: Optional[str] = Field(default=None, max_length=2048)
        dedupStrategy: Optional[str] = Field(
            default=None, max_length=32, description="basic|intelligent|aggressive|conservative"
        )
        dedupThreshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)
        progressiveAnalysis: Optional[bool] = Field(default=None)
        sampleRate: Optional[float] = Field(default=None, ge=0.1, le=1.0)
        # Agent flags
        agentEnabled: Optional[bool] = Field(default=None, description="Enable agentic post-scan analysis")
        agentSteps: Optional[List[str]] = Field(
            default=None, max_length=6,
            description="Agent steps to run: narrate, verify, triage, remediate, orchestrate, pipeline",
        )

    scanOptions: Optional[ScanOptions] = Field(
        default=None, description="Optional per-scan options applied contextually (validated and audited)"
    )


class PackageDetectionInfo(BaseModel):
    """Package detection result with confidence scoring."""

    packageName: str = Field(..., description="Detected or confirmed package name")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence (0.0-1.0)")
    method: str = Field(
        ..., description="Detection method: aapt_badging|aapt_xmltree|manifest_parsing|filename_generation"
    )
    appName: Optional[str] = Field(default=None, description="Application label if available")
    versionName: Optional[str] = Field(default=None, description="Version name if available")
    needsConfirmation: bool = Field(
        default=False, description="True if confidence is below threshold and user confirmation is needed"
    )


class StartScanResponse(BaseModel):
    sessionId: str
    status: str  # "queued" | "awaiting_confirmation" | "running" | "completed" | "failed" | "cancelled"
    startedAt: str
    packageDetection: Optional[PackageDetectionInfo] = Field(
        default=None, description="Package detection info when status is awaiting_confirmation"
    )
    warning: Optional[str] = Field(
        default=None, description="Warning message (e.g., when low-confidence package is auto-accepted in CI mode)"
    )


class ScanProgressResponse(BaseModel):
    id: str
    pct: float
    stage: str
    message: Optional[str] = None
    startedAt: Optional[str] = None
    finishedAt: Optional[str] = None


class ScanResultSummary(BaseModel):
    findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanResultItem(BaseModel):
    id: str
    startedAt: str
    finishedAt: Optional[str] = None
    profile: Optional[str] = None
    apkName: Optional[str] = None
    summary: ScanResultSummary
    path: str


class StartBatchRequest(BaseModel):
    manifest: Optional[str] = Field(None, max_length=2048, description="Path to manifest.json with sources[][].files[]")
    apkList: Optional[str] = Field(None, max_length=2048, description="Path to newline-separated list of APK paths")
    profile: str = Field("lightning", max_length=32, description="Scan profile")
    concurrency: int = Field(4, ge=1, le=16)
    outDir: str = Field("artifacts/scans/lightning", max_length=2048)


class StartBatchResponse(BaseModel):
    jobId: str
    pid: Optional[int] = None
    status: str


class AuditEvent(BaseModel):
    timestamp: str
    user: str
    action: str
    resource: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class LoginRequest(BaseModel):
    username: str = Field(..., max_length=256)
    password: str = Field(..., max_length=256)
    roles: Optional[List[str]] = Field(default=None, max_length=10)


class LoginResponse(BaseModel):
    token: str
    user: str
    roles: List[str]


class FridaUploadRequest(BaseModel):
    mode: str = Field("inline", max_length=32, description="inline|file|url")
    name: str = Field(..., max_length=256, description="Script name identifier")
    content: Optional[str] = Field(None, max_length=50_000, description="Inline JS when mode=inline")
    path: Optional[str] = Field(None, max_length=2048, description="File path when mode=file")
    url: Optional[str] = Field(None, max_length=2048, description="Remote URL when mode=url")


class FridaTargetedRunRequest(BaseModel):
    types: List[str] = Field(default_factory=list, max_length=50)
    durationSec: int = 30


class ConfirmPackageRequest(BaseModel):
    """Request to confirm package name for a pending scan."""

    packageName: str = Field(..., max_length=256, description="User-confirmed or user-entered package name")


def _validate_apk_file(apk_path: Path) -> Tuple[bool, str]:
    """
    Validate that a file is a valid APK (ZIP archive containing AndroidManifest.xml).

    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is empty.
    """
    MIN_APK_SIZE = 1024  # Minimum 1KB - real APKs are much larger

    # Check file size
    try:
        file_size = apk_path.stat().st_size
        if file_size < MIN_APK_SIZE:
            return False, f"File too small ({file_size} bytes). Valid APKs are typically > 100KB."
    except OSError as e:
        return False, f"Cannot read file: {e}"

    # Check if it's a valid ZIP file
    if not zipfile.is_zipfile(apk_path):
        return False, "File is not a valid ZIP/APK archive"

    # Check for AndroidManifest.xml
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            if "AndroidManifest.xml" not in zf.namelist():
                return False, "File is missing AndroidManifest.xml - not a valid APK"
    except zipfile.BadZipFile as e:
        return False, f"Corrupted ZIP file: {e}"
    except Exception as e:
        return False, f"Error reading APK: {e}"

    return True, ""


def _safe_bool_env(name: str, default: str = "0") -> str:
    val = os.getenv(name, default)
    return "1" if str(val).strip() in {"1", "true", "True", "yes"} else "0"


@api.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "timestamp": _now_iso()}


@api.get("/schemas/{schema_name}")
def get_schema(schema_name: str, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    """
    Retrieve a JSON schema by name.

    Available schemas:
    - result_schema: Expected fields in scan results (for unknown field highlighting)
    """
    # Strip .json extension if present
    if schema_name.endswith(".json"):
        schema_name = schema_name[:-5]

    # Sanitize schema name to prevent path traversal
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "", schema_name)
    if not safe_name or safe_name != schema_name:
        raise HTTPException(status_code=400, detail="Invalid schema name")

    schema_path = REPO_ROOT / "config" / "schemas" / f"{safe_name}.json"
    if not schema_path.exists():
        raise HTTPException(status_code=404, detail="schema not found")

    try:
        return json.loads(schema_path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning("schema_load_failed", schema=safe_name, error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail="Failed to load schema")


@api.get("/health/ml")
def health_ml(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    """Health check for ML subsystems (models, calibration, FP reducer)."""
    checks: Dict[str, Any] = {"timestamp": _now_iso()}

    # Check malware detection models
    try:
        from pathlib import Path as _P

        models_dir = _P(__file__).resolve().parent.parent.parent / "models"
        malware_models = (
            list((models_dir / "malware_detection_hybrid").glob("*.pkl"))
            if (models_dir / "malware_detection_hybrid").exists()
            else []
        )
        checks["malware_detection"] = {
            "status": "ok" if malware_models else "degraded",
            "models_found": len(malware_models),
        }
    except Exception:
        checks["malware_detection"] = {"status": "error"}

    # Check calibration models
    try:
        from pathlib import Path as _P

        cal_dir = _P(__file__).resolve().parent.parent.parent / "models" / "calibration"
        cal_files = list(cal_dir.glob("*.json")) if cal_dir.exists() else []
        checks["calibration"] = {
            "status": "ok" if cal_files else "degraded",
            "models_found": len(cal_files),
        }
    except Exception:
        checks["calibration"] = {"status": "error"}

    # Check FP reducer
    try:
        from pathlib import Path as _P

        fp_dir = _P(__file__).resolve().parent.parent.parent / "models" / "unified_ml" / "false_positive"
        fp_files = list(fp_dir.glob("*.pkl")) if fp_dir.exists() else []
        checks["fp_reducer"] = {
            "status": "ok" if fp_files else "not_trained",
            "models_found": len(fp_files),
        }
    except Exception:
        checks["fp_reducer"] = {"status": "error"}

    overall = (
        "ok"
        if all(c.get("status") == "ok" for c in checks.values() if isinstance(c, dict) and "status" in c)
        else "degraded"
    )
    checks["status"] = overall
    return checks


@api.get("/health/plugins")
def health_plugins(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    """Health check for plugin subsystem."""
    checks: Dict[str, Any] = {"timestamp": _now_iso()}

    try:
        from core.plugins.unified_manager import UnifiedPluginManager

        mgr = UnifiedPluginManager()
        mgr.discover_plugins()
        total = len(mgr.plugins)
        checks["discovery"] = {
            "status": "ok" if total > 0 else "error",
            "plugins_discovered": total,
        }
    except Exception:
        checks["discovery"] = {"status": "error"}

    # Check plugin directories
    try:
        from pathlib import Path as _P

        plugins_dir = _P(__file__).resolve().parent.parent.parent / "plugins"
        v2_count = len(list(plugins_dir.glob("*/v2_plugin.py")))
        checks["v2_plugins"] = {
            "status": "ok" if v2_count > 50 else "degraded",
            "v2_plugin_count": v2_count,
        }
    except Exception:
        checks["v2_plugins"] = {"status": "error"}

    overall = (
        "ok"
        if all(c.get("status") == "ok" for c in checks.values() if isinstance(c, dict) and "status" in c)
        else "degraded"
    )
    checks["status"] = overall
    return checks


@api.get("/health/scan")
def health_scan(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    """Health check for scan infrastructure."""
    checks: Dict[str, Any] = {"timestamp": _now_iso()}

    # Check JADX availability
    try:
        import shutil

        jadx_path = shutil.which("jadx")
        checks["jadx"] = {
            "status": "ok" if jadx_path else "missing",
        }
    except Exception:
        checks["jadx"] = {"status": "error"}

    # Check active scans
    try:
        with _SESSIONS_LOCK:
            active = sum(1 for s in _SESSIONS.values() if s.get("status") in ("queued", "running"))
            total = len(_SESSIONS)
        checks["sessions"] = {
            "status": "ok",
            "active_scans": active,
            "total_sessions": total,
        }
    except Exception:
        checks["sessions"] = {"status": "error"}

    # Check report output directory
    try:
        from pathlib import Path as _P

        reports_dir = _P(__file__).resolve().parent.parent.parent / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        writable = os.access(str(reports_dir), os.W_OK)
        report_count = len(list(reports_dir.glob("*.json")))
        checks["reports"] = {
            "status": "ok" if writable else "error",
            "writable": writable,
            "report_count": report_count,
        }
    except Exception:
        checks["reports"] = {"status": "error"}

    overall = (
        "ok"
        if all(c.get("status") == "ok" for c in checks.values() if isinstance(c, dict) and "status" in c)
        else "degraded"
    )
    checks["status"] = overall
    return checks


@api.get("/info")
def info() -> Dict[str, Any]:
    """Basic API information and server time for footer display."""
    return {
        "apiVersion": "0.1.0",
        "serverTime": _now_iso(),
    }


@api.get("/tools/status")
def tools_status(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    execu = get_global_executor()
    adb = execu.get_tool_info(ToolType.ADB)
    frida = execu.get_tool_info(ToolType.FRIDA)
    jadx = execu.get_tool_info(ToolType.JADX)
    now = _now_iso()
    # attach last_checked and basic install hints when missing

    def _augment(tool: Dict[str, Any], name: str) -> Dict[str, Any]:
        t = dict(tool or {})
        t.setdefault("last_checked", now)
        if not t.get("available"):
            if name == "adb":
                t.setdefault("install_hint", "Install Android platform-tools (adb) and add to PATH")
            if name == "jadx":
                t.setdefault("install_hint", "Install JADX and ensure 'jadx' is on PATH")
            if name == "frida":
                t.setdefault("install_hint", "pip install frida-tools frida")
        return t

    # Ghidra status for native binary analysis
    ghidra_info: Dict[str, Any] = {"available": False, "last_checked": now}
    try:
        from core.native_decompiler.ghidra_bridge import GhidraBridge
        ghidra_info = GhidraBridge().get_status()
        ghidra_info["last_checked"] = now
    except Exception:
        ghidra_info["install_hint"] = "Native decompiler module not available"

    return {
        "adb": _augment(adb, "adb"),
        "frida": _augment(frida, "frida"),
        "jadx": _augment(jadx, "jadx"),
        "ghidra": ghidra_info,
    }


@api.get("/optional-deps/status")
def optional_deps_status(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    try:
        from core.optional_dependencies import optional_deps as _opt

        return _opt.get_feature_status()
    except Exception as e:
        logger.error("optional_deps_status_failed", error_type=type(e).__name__)
        return {"error": "failed to load optional dependencies"}


@api.post("/apk/inspect")
def apk_inspect(file: UploadFile = File(...), authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """Inspect an APK file uploaded by the user and return basic facts (e.g., package name).

    This endpoint saves the uploaded APK to a temporary file, attempts to extract the
    package name via aapt or manifest inspection, then deletes the temp file.
    """
    _require_roles(authorization, ["admin", "analyst"])  # at least analyst
    import tempfile
    import subprocess as _sp
    import re as _re

    pkg: Optional[str] = None
    temp_path: Optional[Path] = None
    try:
        # Persist to a temp .apk to support tools requiring filesystem access
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tf:
            temp_path = Path(tf.name)
            data = file.file.read()
            tf.write(data)
            tf.flush()

        # Method 1: Androguard (preferred when available)
        try:
            try:
                from androguard.core.bytecodes.apk import APK as _AGAPK  # type: ignore

                try:
                    apk_obj = _AGAPK(str(temp_path))
                    pkg = apk_obj.get_package()
                except Exception:
                    pkg = None
            except Exception:
                pkg = None
        except Exception:
            pkg = None

        # Method 2: aapt dump badging
        if not pkg:
            try:
                res = _sp.run(["aapt", "dump", "badging", str(temp_path)], capture_output=True, text=True, timeout=15)
                if res.returncode == 0:
                    for ln in (res.stdout or "").splitlines():
                        if ln.startswith("package:"):
                            m = _re.search(r"name='([^']+)'", ln)
                            if m:
                                pkg = m.group(1)
                                break
            except Exception:
                pass

        # Method 3: Basic manifest probing via zipfile
        if not pkg:
            try:
                import zipfile as _zip

                with _zip.ZipFile(temp_path, "r") as zf:
                    if "AndroidManifest.xml" in zf.namelist():
                        raw = zf.read("AndroidManifest.xml")
                        s = str(raw)
                        cands = _re.findall(r"([a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+)", s)
                        for cand in cands:
                            if "." in cand and not cand.startswith("android."):
                                pkg = cand
                                break
            except Exception:
                pass

        if not pkg:
            raise HTTPException(status_code=422, detail="could not extract package name from APK")
        return {"packageName": pkg}
    finally:
        try:
            if temp_path and temp_path.exists():
                temp_path.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass


def _check_login_rate_limit(username: str) -> None:
    """Enforce per-username login rate limiting. Raises 429 if exceeded."""
    from core.api.shared_state import (
        _LOGIN_ATTEMPTS_LOCK, _LOGIN_ATTEMPTS,
        LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECONDS, LOGIN_LOCKOUT_SECONDS,
    )
    now = time.time()
    with _LOGIN_ATTEMPTS_LOCK:
        attempts = _LOGIN_ATTEMPTS.get(username, [])
        # Prune old attempts outside window
        cutoff = now - max(LOGIN_WINDOW_SECONDS, LOGIN_LOCKOUT_SECONDS)
        attempts = [t for t in attempts if t > cutoff]
        _LOGIN_ATTEMPTS[username] = attempts

        # Count recent attempts in the rate window
        recent = [t for t in attempts if t > now - LOGIN_WINDOW_SECONDS]
        if len(recent) >= LOGIN_MAX_ATTEMPTS:
            # Check if still in lockout period from the last attempt
            last = max(recent) if recent else 0
            if now - last < LOGIN_LOCKOUT_SECONDS:
                raise HTTPException(
                    status_code=429,
                    detail="too many login attempts, try again later",
                )


def _record_login_attempt(username: str) -> None:
    """Record a failed login attempt for rate limiting."""
    from core.api.shared_state import _LOGIN_ATTEMPTS_LOCK, _LOGIN_ATTEMPTS
    now = time.time()
    with _LOGIN_ATTEMPTS_LOCK:
        _LOGIN_ATTEMPTS.setdefault(username, []).append(now)


@api.post("/auth/login", response_model=LoginResponse)
def auth_login(req: LoginRequest) -> LoginResponse:
    """
    Authenticate user and issue access token.

    Verifies credentials against configured users (via AODS_*_PASSWORD env vars).
    In development mode (AODS_AUTH_DISABLED=1), accepts any credentials.
    """
    if not req.username or not req.password:
        raise HTTPException(status_code=400, detail="missing credentials")

    # Rate limiting: block brute-force attempts
    _check_login_rate_limit(req.username)

    # Authenticate user with PBKDF2 password verification
    auth_result = _authenticate_user(req.username, req.password)
    if not auth_result:
        _record_login_attempt(req.username)
        # Add small delay to mitigate timing attacks on username enumeration
        time.sleep(0.1)
        raise HTTPException(status_code=401, detail="invalid credentials")

    # Get user's roles from authentication result
    user_roles = auth_result.get("roles", [])

    # Consult RBAC manager to filter to active roles only
    available_roles = set(_RBAC.role_manager.roles.keys())
    roles: List[str] = []
    for r in user_roles:
        role_def = _RBAC.role_manager.roles.get(r)
        if role_def and role_def.is_active:
            roles.append(r)

    # Fallback to viewer if no roles match (shouldn't happen with proper config)
    if not roles and "viewer" in available_roles:
        roles = ["viewer"]

    # Issue token
    token = secrets.token_urlsafe(24)
    with _TOKENS_LOCK:
        try:
            expiry_hours = float(os.environ.get("AODS_JWT_EXPIRY_HOURS", "24"))
        except (ValueError, TypeError):
            expiry_hours = 24.0
        _TOKENS[token] = {
            "user": req.username, "roles": roles, "issued": _now_iso(),
            "exp": time.time() + expiry_hours * 3600,
        }

    # Log authentication (audit trail)
    auth_mode = auth_result.get("auth_mode", "normal")
    if auth_mode == "disabled":
        logger.warning("user_login", username=req.username, auth_mode="disabled")
    else:
        logger.info("user_login", username=req.username, roles=roles)

    # Bind user context for subsequent logging in this request
    bind_user_context(user_id=req.username, username=req.username, roles=roles)

    return LoginResponse(token=token, user=req.username, roles=roles)


@api.get("/auth/me")
def auth_me(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    info = _get_user_info(authorization)
    if not info:
        raise HTTPException(status_code=401, detail="unauthorized")
    return info


@api.post("/auth/logout")
def auth_logout(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """
    Logout user and invalidate access token.

    Removes the token from the active tokens store, effectively terminating
    the session. Subsequent requests with this token will be rejected.

    Returns:
        Success message with logout timestamp
    """
    tok = _extract_token(authorization)
    if not tok:
        raise HTTPException(status_code=401, detail="no token provided")

    with _TOKENS_LOCK:
        info = _TOKENS.pop(tok, None)

    if not info:
        # Token was already invalid/expired - still return success
        logger.info("logout_attempt_invalid_token", message="Logout with invalid/expired token")
        return {"message": "logged out", "timestamp": _now_iso()}

    username = info.get("user", "unknown")
    logger.info("user_logout", username=username)
    _audit("logout", username)

    return {"message": "logged out", "user": username, "timestamp": _now_iso()}


@api.get("/apk/exists")
def apk_exists(
    path: str = Query(..., description="Absolute path to APK file"), authorization: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    """Lightweight existence check for an APK path on the API host.

    Returns { exists: bool, isFile: bool } with minimal validation to avoid starting a scan
    just to validate user input in the UI.
    """
    _enforce_access(authorization, RBACResourceType.APK_ANALYSIS, RBACPermission.EXECUTE)
    try:
        p = Path(path)
        exists = p.exists()
        is_file = p.is_file() if exists else False
        return {"exists": bool(exists), "isFile": bool(is_file)}
    except Exception:
        raise HTTPException(status_code=400, detail="invalid path")


class ApkInspectPathRequest(BaseModel):
    apk_path: str = Field(..., max_length=2048, description="Server-side path to APK file")


@api.post("/apk/inspect-path")
def apk_inspect_path(
    body: ApkInspectPathRequest, authorization: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    """Inspect an APK by server-side path. Returns package name and file info."""
    _require_roles(authorization, ["admin", "analyst"])
    p = Path(body.apk_path).resolve()
    if not p.suffix.lower() == ".apk":
        raise HTTPException(status_code=400, detail="Path must end with .apk")
    # Restrict to REPO_ROOT to prevent arbitrary file read
    try:
        p.relative_to(REPO_ROOT.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="path outside allowed directory")
    if not p.exists() or not p.is_file():
        raise HTTPException(status_code=404, detail="APK file not found")

    result: Dict[str, Any] = {
        "apk_path": str(p),
        "file_size": p.stat().st_size,
        "file_name": p.name,
    }

    # Try to extract package name
    package_name = None
    try:
        # Attempt androguard
        from androguard.core.apk import APK as AndroAPK  # type: ignore[import-untyped]
        a = AndroAPK(str(p))
        package_name = a.get_package()
    except Exception:
        pass

    if not package_name:
        try:
            # Attempt aapt
            import subprocess
            out = subprocess.check_output(
                ["aapt", "dump", "badging", str(p)], timeout=10, stderr=subprocess.DEVNULL
            ).decode("utf-8", errors="replace")
            for line in out.splitlines():
                if line.startswith("package:"):
                    import re as _re
                    m = _re.search(r"name='([^']+)'", line)
                    if m:
                        package_name = m.group(1)
                    break
        except Exception:
            pass

    if not package_name:
        try:
            # Fall back to zipfile manifest check
            with zipfile.ZipFile(str(p)) as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    result["warning"] = "Package name requires Androguard or AAPT"
        except Exception:
            pass

    if package_name:
        result["packageName"] = package_name

    return result


# --- Frida Custom Script Endpoints (admin only; guarded; minimal MVP) ---


@api.get("/jobs/history")
def list_job_history(
    days: int = Query(default=7, ge=1, le=90),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Aggregate job history from scans and batch jobs.

    Args:
        days: Number of days to look back (1-90, default 7)

    Returns:
        { scans: [...], batch: [...], summary: {...} }
    """
    _require_roles(authorization, ["admin", "analyst"])

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    cutoff_ts = cutoff.timestamp()

    scans: List[Dict[str, Any]] = []
    batch_jobs: List[Dict[str, Any]] = []

    # Collect scans from sessions
    with _SESSIONS_LOCK:
        for sid, sess in _SESSIONS.items():
            created = sess.get("createdAt", 0)
            if created >= cutoff_ts:
                scans.append(
                    {
                        "id": sid,
                        "status": sess.get("status"),
                        "apkPath": sess.get("apkPath"),
                        "startedAt": sess.get("startedAt"),
                        "finishedAt": sess.get("finishedAt"),
                    }
                )

    # Collect batch jobs
    with _BATCH_LOCK:
        for job_id, job in _BATCH_JOBS.items():
            created = job.get("createdAt", 0)
            if created >= cutoff_ts:
                batch_jobs.append(
                    {
                        "id": job_id,
                        "status": job.get("status"),
                        "totalApks": job.get("totalApks"),
                        "completed": job.get("completed", 0),
                        "failed": job.get("failed", 0),
                        "startedAt": job.get("startedAt"),
                        "finishedAt": job.get("finishedAt"),
                    }
                )

    # Summary stats
    scan_statuses = {}
    for s in scans:
        st = str(s.get("status", "unknown")).lower()
        scan_statuses[st] = scan_statuses.get(st, 0) + 1

    return {
        "scans": scans,
        "batch": batch_jobs,
        "summary": {
            "totalScans": len(scans),
            "totalBatch": len(batch_jobs),
            "scanStatuses": scan_statuses,
            "days": days,
        },
    }


@api.get("/reports/list")
def list_reports(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    """List report artifacts from reports/ and artifacts/reports/.

    Aggregates JSON, HTML, CSV, and PDF reports from standard output directories
    plus *_security_report_*.json from the repo root.
    """
    roots = [REPO_ROOT / "artifacts" / "reports", REPO_ROOT / "reports", REPO_ROOT]
    items: List[Dict[str, Any]] = []
    for root in roots:
        if not root.exists():
            continue
        try:
            patterns = (
                ["*.json", "*.html", "*.csv", "*.pdf"]
                if (root != REPO_ROOT)
                else ["*_security_report_*.json"]
            )
            paths = []
            for pat in patterns:
                paths.extend(list(root.glob(pat)))
            for p in paths:
                try:
                    items.append(
                        {
                            "name": p.name,
                            "path": str(p.relative_to(REPO_ROOT)),
                            "size": p.stat().st_size,
                            "modified": int(p.stat().st_mtime * 1000),
                        }
                    )
                except Exception:
                    continue
        except Exception:
            continue
    # De-duplicate by full path
    seen: Set[str] = set()
    deduped: List[Dict[str, Any]] = []
    for it in items:
        p = it.get("path")
        if not p or p in seen:
            continue
        seen.add(p)
        deduped.append(it)
    deduped.sort(key=lambda it: it.get("modified", 0), reverse=True)
    return {"items": deduped}


@api.get("/reports/read")
def read_report(path: str, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    """Read a small JSON/text report from either reports/ or artifacts/reports/."""
    if not path or ".." in path or path.startswith("/"):
        raise HTTPException(status_code=400, detail="invalid path")
    abs_path = (REPO_ROOT / path).resolve()
    allowed_roots = [
        (REPO_ROOT / "artifacts" / "reports").resolve(),
        (REPO_ROOT / "reports").resolve(),
        REPO_ROOT.resolve(),
    ]
    try:
        if not any(root in abs_path.parents or abs_path == root for root in allowed_roots):
            raise HTTPException(status_code=400, detail="path escapes allowed roots")
    except Exception:
        raise HTTPException(status_code=400, detail="invalid path")
    # If file is at repository root, only allow known report patterns for safety
    try:
        if abs_path.parent == REPO_ROOT.resolve():
            name = abs_path.name
            if not (name.endswith(".json") and ("_security_report_" in name or name.startswith("aods_parallel_"))):
                raise HTTPException(status_code=400, detail="unsupported root report path")
    except Exception:
        raise
    if not abs_path.exists() or not abs_path.is_file():
        raise HTTPException(status_code=404, detail="report not found")
    stat = abs_path.stat()
    if stat.st_size > 2 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="report too large to preview")
    try:
        text = abs_path.read_text(errors="replace")
    except Exception:
        raise HTTPException(status_code=500, detail="failed to read report")
    ext = abs_path.suffix.lower()
    if ext == ".json":
        ctype = "application/json"
    elif ext in {".md", ".markdown"}:
        ctype = "text/markdown"
    elif ext in {".html", ".htm"}:
        ctype = "text/html"
    else:
        ctype = "text/plain"
    return {
        "path": str(abs_path.relative_to(REPO_ROOT)),
        "size": stat.st_size,
        "mtime": int(stat.st_mtime * 1000),
        "contentType": ctype,
        "content": text,
    }


@api.get("/reports/download")
def download_report(path: str, authorization: Optional[str] = Header(default=None)):
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    """Download a report from reports/ or artifacts/reports/."""
    if not path or ".." in path or path.startswith("/"):
        raise HTTPException(status_code=400, detail="invalid path")
    abs_path = (REPO_ROOT / path).resolve()
    allowed_roots = [
        (REPO_ROOT / "artifacts" / "reports").resolve(),
        (REPO_ROOT / "reports").resolve(),
        REPO_ROOT.resolve(),
    ]
    try:
        if not any(root in abs_path.parents or abs_path == root for root in allowed_roots):
            raise HTTPException(status_code=400, detail="path escapes allowed roots")
    except Exception:
        raise HTTPException(status_code=400, detail="invalid path")
    # Restrict root-level downloads to known report patterns
    if abs_path.parent == REPO_ROOT.resolve():
        name = abs_path.name
        if not (name.endswith(".json") and "_security_report_" in name):
            raise HTTPException(status_code=400, detail="unsupported root report path")
    if not abs_path.exists() or not abs_path.is_file():
        raise HTTPException(status_code=404, detail="report not found")
    return FileResponse(str(abs_path), filename=abs_path.name)


class ReportGenerateRequest(BaseModel):
    """Request body for on-demand report generation."""

    result_id: str = Field(..., max_length=256, description="Scan result ID (JSON report stem)")
    format: str = Field(..., max_length=16, description="Output format: html, csv, json, pdf")


@api.post("/reports/generate")
def generate_report(
    body: ReportGenerateRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Generate a report in the requested format from an existing scan result.

    Reads the JSON scan result, extracts findings, and invokes the AODS
    reporting engine to produce HTML, CSV, JSON, or PDF output. Returns the
    generated file as a download.
    """
    _require_roles(authorization, ["admin", "analyst"])

    fmt = body.format.lower().strip()
    SUPPORTED = {"html", "csv", "json", "pdf"}
    if fmt not in SUPPORTED:
        raise HTTPException(
            status_code=400,
            detail="unsupported format",
        )

    # Locate the source JSON report
    result_id = body.result_id.strip()
    if not result_id or ".." in result_id or "/" in result_id:
        raise HTTPException(status_code=400, detail="Invalid result_id")

    reports_dir = REPO_ROOT / "reports"
    candidate: Optional[Path] = None
    for p in (reports_dir,):
        if not p.exists():
            continue
        match = p / f"{result_id}.json"
        if match.exists():
            candidate = match
            break
    # Also check artifacts/reports and repo root
    if not candidate:
        for root in [REPO_ROOT / "artifacts" / "reports", REPO_ROOT]:
            if not root.exists():
                continue
            for p in root.glob("*.json"):
                if p.stem == result_id:
                    candidate = p
                    break
            if candidate:
                break

    if not candidate or not candidate.exists():
        raise HTTPException(status_code=404, detail="Scan result not found")

    # Load findings from the JSON report
    try:
        data = json.loads(candidate.read_text(errors="replace"))
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to read scan result")

    findings = []
    if isinstance(data, dict):
        findings = data.get("vulnerabilities", data.get("findings", []))
    if not isinstance(findings, list):
        findings = []

    if not findings:
        raise HTTPException(status_code=400, detail="No findings in the scan result to generate a report from")

    # Extract metadata
    meta = {}
    if isinstance(data, dict):
        raw_meta = data.get("metadata", {})
        if isinstance(raw_meta, dict):
            meta = {
                "package_name": raw_meta.get("package_name", raw_meta.get("apk_name", result_id)),
                "apk_path": raw_meta.get("apk_path", ""),
                "profile": raw_meta.get("profile", ""),
                "total_findings": raw_meta.get("total_findings", len(findings)),
            }
        else:
            meta = {"package_name": result_id}

    pkg_name = meta.get("package_name", result_id)
    base_filename = f"{pkg_name}_security_report"

    if fmt == "json":
        # For JSON, just return the existing report as a download
        return FileResponse(str(candidate), filename=f"{base_filename}.json", media_type="application/json")

    # Generate report via reporting engine
    try:
        from core.shared_infrastructure.reporting.unified_facade import create_report_manager
        from core.shared_infrastructure.reporting.data_structures import ReportFormat

        fmt_map = {"html": ReportFormat.HTML, "csv": ReportFormat.CSV, "pdf": ReportFormat.PDF}
        report_format = fmt_map.get(fmt)
        if not report_format:
            raise HTTPException(status_code=400, detail="unsupported report format")

        rpt_mgr = create_report_manager()
        output_dir = str(REPO_ROOT / "reports")
        os.makedirs(output_dir, exist_ok=True)

        result = rpt_mgr.generate_security_report(
            findings=findings,
            metadata=meta,
            formats=[report_format],
            output_directory=output_dir,
            base_filename=base_filename,
        )

        # Find the generated file path
        file_paths = result.get("file_paths", {})
        generated_path = file_paths.get(fmt) or file_paths.get(fmt.upper())

        if not generated_path or not Path(generated_path).exists():
            # Fallback: look for the file in the output directory
            ext = fmt if fmt != "pdf" else "pdf"
            fallback = Path(output_dir) / f"{base_filename}.{ext}"
            if fallback.exists():
                generated_path = str(fallback)
            else:
                raise HTTPException(status_code=500, detail="Report generated but output file not found")

        media_types = {
            "html": "text/html",
            "csv": "text/csv",
            "pdf": "application/pdf",
        }

        return FileResponse(
            str(generated_path),
            filename=f"{base_filename}.{fmt}",
            media_type=media_types.get(fmt, "application/octet-stream"),
        )
    except HTTPException:
        raise
    except ImportError:
        raise HTTPException(status_code=501, detail="Reporting engine not available")
    except Exception:
        raise HTTPException(status_code=500, detail="Report generation failed")


@api.get("/mappings/sources")
def get_mapping_sources(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    """Return authoritative mapping sources metadata if configured."""
    try:
        try:
            from core.reporting.security_framework_mapper import SecurityFrameworkMapper  # type: ignore
        except Exception:
            raise HTTPException(status_code=500, detail="mapper import failed")
        mapper = SecurityFrameworkMapper()
        return mapper.sources_meta or {}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="failed to load mapping sources")


@api.get("/artifacts/list")
def list_artifacts(subdir: str = "ci_gates", authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    # Curated artifact roots only
    allowed = {
        "ci_gates": REPO_ROOT / "artifacts" / "ci_gates",
        "ml_baselines": REPO_ROOT / "artifacts" / "ml_baselines",
        "scans": REPO_ROOT / "artifacts" / "scans",
        "reports": REPO_ROOT / "artifacts" / "reports",
        "plugin_audit": REPO_ROOT / "artifacts" / "plugin_audit",
        "logs": REPO_ROOT / "artifacts" / "logs",
        "ui_perf": REPO_ROOT / "artifacts" / "ui_perf",
        "ml_datasets/metrics": REPO_ROOT / "artifacts" / "ml_datasets" / "metrics",
    }
    base = allowed.get(subdir)
    if base is None:
        raise HTTPException(status_code=400, detail="unsupported subdir")
    if not base.exists():
        return {"subdir": subdir, "items": []}
    items = []
    try:
        for p in sorted(base.glob("**/*")):
            if len(items) >= 500:
                break
            rel = str(p.relative_to(base))
            stat = p.stat()
            items.append(
                {
                    "name": p.name,
                    "relPath": rel,
                    "isDir": p.is_dir(),
                    "size": 0 if p.is_dir() else stat.st_size,
                    "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
                }
            )
    except Exception:
        raise HTTPException(status_code=500, detail="artifact listing failed")
    return {"subdir": subdir, "root": str(base), "items": items}


@api.get("/artifacts/read")
def read_artifact(subdir: str, relPath: str, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    allowed = {
        "ci_gates": REPO_ROOT / "artifacts" / "ci_gates",
        "ml_baselines": REPO_ROOT / "artifacts" / "ml_baselines",
        "scans": REPO_ROOT / "artifacts" / "scans",
        "reports": REPO_ROOT / "artifacts" / "reports",
        "plugin_audit": REPO_ROOT / "artifacts" / "plugin_audit",
        "logs": REPO_ROOT / "artifacts" / "logs",
        "ui_perf": REPO_ROOT / "artifacts" / "ui_perf",
        "ml_datasets/metrics": REPO_ROOT / "artifacts" / "ml_datasets" / "metrics",
    }
    base = allowed.get(subdir)
    if base is None:
        raise HTTPException(status_code=400, detail="unsupported subdir")
    if not relPath or ".." in relPath or relPath.startswith("/"):
        raise HTTPException(status_code=400, detail="invalid relPath")
    abs_path = (base / relPath).resolve()
    try:
        if base.resolve() not in abs_path.parents and abs_path != base.resolve():
            raise HTTPException(status_code=400, detail="path escapes base")
    except Exception:
        raise HTTPException(status_code=400, detail="invalid path")
    if not abs_path.exists() or not abs_path.is_file():
        raise HTTPException(status_code=404, detail="artifact not found")
    stat = abs_path.stat()
    max_bytes = 2 * 1024 * 1024  # 2MB limit
    if stat.st_size > max_bytes:
        raise HTTPException(status_code=413, detail="artifact too large to preview")
    try:
        text = abs_path.read_text(errors="replace")
    except Exception:
        raise HTTPException(status_code=500, detail="failed to read artifact")
    ext = abs_path.suffix.lower()
    if ext == ".json":
        ctype = "application/json"
    elif ext in {".md", ".markdown"}:
        ctype = "text/markdown"
    elif ext in {".html", ".htm"}:
        ctype = "text/html"
    else:
        ctype = "text/plain"
    return {
        "subdir": subdir,
        "relPath": relPath,
        "size": stat.st_size,
        "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "contentType": ctype,
        "content": text,
    }


@api.get("/artifacts/download")
def download_artifact(subdir: str, relPath: str, authorization: Optional[str] = Header(default=None)):
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    allowed = {
        "ci_gates": REPO_ROOT / "artifacts" / "ci_gates",
        "ml_baselines": REPO_ROOT / "artifacts" / "ml_baselines",
        "scans": REPO_ROOT / "artifacts" / "scans",
        "reports": REPO_ROOT / "artifacts" / "reports",
        "plugin_audit": REPO_ROOT / "artifacts" / "plugin_audit",
        "logs": REPO_ROOT / "artifacts" / "logs",
        "ui_perf": REPO_ROOT / "artifacts" / "ui_perf",
        "ml_datasets/metrics": REPO_ROOT / "artifacts" / "ml_datasets" / "metrics",
    }
    base = allowed.get(subdir)
    if base is None:
        raise HTTPException(status_code=400, detail="unsupported subdir")
    if not relPath or ".." in relPath or relPath.startswith("/"):
        raise HTTPException(status_code=400, detail="invalid relPath")
    abs_path = (base / relPath).resolve()
    try:
        if base.resolve() not in abs_path.parents and abs_path != base.resolve():
            raise HTTPException(status_code=400, detail="path escapes base")
    except Exception:
        raise HTTPException(status_code=400, detail="invalid path")
    if not abs_path.exists() or not abs_path.is_file():
        raise HTTPException(status_code=404, detail="artifact not found")
    return FileResponse(str(abs_path), filename=abs_path.name)


@api.get("/artifacts/read_chunk")
def read_artifact_chunk(
    subdir: str,
    relPath: str,
    offset: int = 0,
    numBytes: int = 131072,  # 128KB default
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    allowed = {
        "ci_gates": REPO_ROOT / "artifacts" / "ci_gates",
        "ml_baselines": REPO_ROOT / "artifacts" / "ml_baselines",
        "scans": REPO_ROOT / "artifacts" / "scans",
        "reports": REPO_ROOT / "artifacts" / "reports",
        "plugin_audit": REPO_ROOT / "artifacts" / "plugin_audit",
        "logs": REPO_ROOT / "artifacts" / "logs",
        "ui_perf": REPO_ROOT / "artifacts" / "ui_perf",
        "ml_datasets/metrics": REPO_ROOT / "artifacts" / "ml_datasets" / "metrics",
    }
    base = allowed.get(subdir)
    if base is None:
        raise HTTPException(status_code=400, detail="unsupported subdir")
    if not relPath or ".." in relPath or relPath.startswith("/"):
        raise HTTPException(status_code=400, detail="invalid relPath")
    abs_path = (base / relPath).resolve()
    try:
        if base.resolve() not in abs_path.parents and abs_path != base.resolve():
            raise HTTPException(status_code=400, detail="path escapes base")
    except Exception:
        raise HTTPException(status_code=400, detail="invalid path")
    if not abs_path.exists() or not abs_path.is_file():
        raise HTTPException(status_code=404, detail="artifact not found")
    size = abs_path.stat().st_size
    if offset < 0 or numBytes <= 0:
        raise HTTPException(status_code=400, detail="invalid range")
    next_off = min(size, offset + numBytes)
    try:
        with abs_path.open("rb") as f:
            f.seek(offset)
            chunk = f.read(numBytes)
        text = chunk.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=500, detail="failed to read chunk")
    return {
        "subdir": subdir,
        "relPath": relPath,
        "size": size,
        "offset": offset,
        "nextOffset": next_off,
        "eof": next_off >= size,
        "content": text,
    }


@api.get("/gates/summary")
def gates_summary(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """Return consolidated CI gates summary if available; otherwise a best-effort scan."""
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    if CI_GATES_DIR.exists():
        summary_path = CI_GATES_DIR / "gate_summary.json"
        if summary_path.exists():
            try:
                data = json.loads(summary_path.read_text(errors="replace"))
                return {"source": str(summary_path), "summary": data}
            except Exception:
                pass
        # Fallback: scan for gate json files and infer basic status fields
        items: List[Dict[str, Any]] = []
        try:
            # Include nested gate summaries (e.g., decomp_completeness/summary.json)
            for p in sorted(CI_GATES_DIR.rglob("*.json")):
                try:
                    obj = json.loads(p.read_text(errors="replace"))
                except Exception:
                    obj = {}
                status = obj.get("status") or obj.get("gate_status") or "unknown"
                name = obj.get("name") or p.stem
                try:
                    rel = str(p.relative_to(CI_GATES_DIR))
                except Exception:
                    rel = p.name
                items.append(
                    {
                        "name": name,
                        "status": status,
                        "mtime": datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z"),
                        "path": str(p),
                        "relPath": rel,
                    }
                )
        except Exception:
            raise HTTPException(status_code=500, detail="failed to scan gates")
        totals = {
            "PASS": sum(1 for i in items if str(i.get("status", "")).upper() == "PASS"),
            "WARN": sum(1 for i in items if str(i.get("status", "")).upper() == "WARN"),
            "FAIL": sum(1 for i in items if str(i.get("status", "")).upper() == "FAIL"),
            "UNKNOWN": sum(1 for i in items if str(i.get("status", "")).upper() not in {"PASS", "WARN", "FAIL"}),
        }
        return {"source": str(CI_GATES_DIR), "items": items, "totals": totals}
    return {"source": None, "items": [], "totals": {}}


# In-memory last totals cache for deltas (non-persistent)
_LAST_GATES_TOTALS: Optional[Dict[str, int]] = None


@api.get("/gates/deltas")
def gates_deltas(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """Return WARN/FAIL deltas vs last request (best-effort, in-memory only).

    If no prior totals exist, returns delta = {} and previous = {}.
    """
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    global _LAST_GATES_TOTALS
    cur = gates_summary(authorization=authorization)
    totals = (cur.get("totals") or {}) if isinstance(cur, dict) else {}
    prev = _LAST_GATES_TOTALS or {}
    # Normalize keys

    def _get(d: Dict[str, Any], k: str) -> int:
        try:
            return int(d.get(k, 0) or 0)
        except Exception:
            return 0

    d_warn = max(0, _get(totals, "WARN") - _get(prev, "WARN")) if prev else 0
    d_fail = max(0, _get(totals, "FAIL") - _get(prev, "FAIL")) if prev else 0
    delta: Dict[str, int] = {}
    if d_warn > 0:
        delta["WARN"] = d_warn
    if d_fail > 0:
        delta["FAIL"] = d_fail
    _LAST_GATES_TOTALS = {"PASS": _get(totals, "PASS"), "WARN": _get(totals, "WARN"), "FAIL": _get(totals, "FAIL")}
    return {"totals": _LAST_GATES_TOTALS, "previous": prev, "delta": delta}


# ============================= Schema Serving =================================


# ============================= UI Config Endpoint ============================


@api.get("/config")
def get_ui_config() -> Dict[str, Any]:
    """Return runtime UI configuration.

    This endpoint provides a fallback when ui-config.json is unavailable.
    Configuration is derived from environment variables with sensible defaults.

    Environment variables:
        AODS_API_URL: Base URL for API (default: http://127.0.0.1:8088/api)
        AODS_WEB_BASE_PATH: Base path for UI routes (default: /ui)
        AODS_APP_TITLE: Application title (default: AODS Security Scanner)

    Returns:
        UI configuration object with apiBaseUrl, webBasePath, and metadata
    """
    # Get values from environment with defaults
    api_url = os.environ.get("AODS_API_URL", "http://127.0.0.1:8088/api")
    web_base_path = os.environ.get("AODS_WEB_BASE_PATH", "/ui")
    app_title = os.environ.get("AODS_APP_TITLE", "AODS Security Scanner")

    # Additional runtime info
    return {
        "apiBaseUrl": api_url,
        "webBasePath": web_base_path,
        "appTitle": app_title,
        "environment": os.environ.get("AODS_ENV", "development"),
        "version": "1.0.0",
        "features": {
            "mlEnabled": os.environ.get("AODS_DISABLE_ML", "0") != "1",
            "fridaEnabled": os.environ.get("AODS_STATIC_ONLY_HARD", "0") != "1",
            "auditLogEnabled": True,
            "batchEnabled": True,
        },
        "source": "api",
    }


# ============================= Curation API ==================================


class CurationImportRequest(BaseModel):
    aodsReportPath: str = Field(..., max_length=2048)
    externalPath: str = Field(..., max_length=2048)
    tool: str = Field("external", max_length=64)


@api.post("/curation/import")
def curation_import(req: CurationImportRequest, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _enforce_access(authorization, RBACResourceType.API_ENDPOINT, RBACPermission.EXECUTE)
    try:
        from tools.ci.curation.discrepancy_builder import build_discrepancies  # type: ignore
    except Exception:
        raise HTTPException(status_code=500, detail="curation module missing")

    aods_p = Path(req.aodsReportPath).resolve()
    ext_p = Path(req.externalPath).resolve()
    repo = REPO_ROOT.resolve()
    # Restrict both paths to REPO_ROOT to prevent arbitrary file read
    try:
        aods_p.relative_to(repo)
    except ValueError:
        raise HTTPException(status_code=403, detail="aodsReportPath outside allowed directory")
    try:
        ext_p.relative_to(repo)
    except ValueError:
        raise HTTPException(status_code=403, detail="externalPath outside allowed directory")
    if not aods_p.exists() or not ext_p.exists():
        raise HTTPException(status_code=400, detail="invalid input paths")
    try:
        aods_obj = json.loads(aods_p.read_text(errors="replace"))
    except Exception:
        raise HTTPException(status_code=400, detail="failed to read aods report")
    try:
        ext_obj = json.loads(ext_p.read_text(errors="replace"))
    except Exception:
        raise HTTPException(status_code=400, detail="failed to read external results")

    if not isinstance(ext_obj, list):
        ext_obj = ext_obj.get("results") or ext_obj.get("findings") or []
        if not isinstance(ext_obj, list):
            ext_obj = []

    tasks, summary = build_discrepancies(aods_obj, ext_obj, tool=req.tool)
    CURATION_DIR.mkdir(parents=True, exist_ok=True)
    (CURATION_DIR / "tasks.json").write_text(json.dumps(tasks, indent=2), encoding="utf-8")
    (CURATION_DIR / "summary.json").write_text(
        json.dumps({"status": "OK", "tool": req.tool, **summary}, indent=2), encoding="utf-8"
    )
    return {
        "status": "OK",
        "counts": summary,
        "paths": {"tasks": str(CURATION_DIR / "tasks.json"), "summary": str(CURATION_DIR / "summary.json")},
    }


@api.get("/curation/tasks")
def curation_tasks(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    tasks_p = CURATION_DIR / "tasks.json"
    if not tasks_p.exists():
        return {"tasks": []}
    try:
        obj = json.loads(tasks_p.read_text(errors="replace"))
    except Exception:
        obj = []
    return {"tasks": obj}


class CurationReviewRequest(BaseModel):
    id: str = Field(..., max_length=256)
    action: str = Field(..., max_length=32)  # "verify" | "fp" | "skip"
    notes: Optional[str] = Field(default=None, max_length=5000)


@api.post("/curation/review")
def curation_review(req: CurationReviewRequest, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _enforce_access(authorization, RBACResourceType.API_ENDPOINT, RBACPermission.EXECUTE)
    tasks_p = CURATION_DIR / "tasks.json"
    reviews_p = CURATION_DIR / "reviews.json"
    tasks = []  # noqa: F841
    if tasks_p.exists():
        try:
            _tasks = json.loads(tasks_p.read_text(errors="replace"))  # noqa: F841
        except Exception:
            pass
    # Append review record
    review_rec = {
        "id": req.id,
        "action": req.action,
        "notes": req.notes or "",
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    existing = []
    if reviews_p.exists():
        try:
            existing = json.loads(reviews_p.read_text(errors="replace"))
        except Exception:
            existing = []
    existing.append(review_rec)
    reviews_p.parent.mkdir(parents=True, exist_ok=True)
    reviews_p.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return {"status": "OK", "review": review_rec}


@api.get("/curation/summary")
def curation_summary(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_roles(authorization, ["admin", "analyst", "viewer"])
    summ_p = CURATION_DIR / "summary.json"
    rev_p = CURATION_DIR / "reviews.json"
    out: Dict[str, Any] = {"counts": {}, "reviews": []}
    try:
        if summ_p.exists():
            out["counts"] = json.loads(summ_p.read_text(errors="replace"))
    except Exception:
        out["counts"] = {}
    try:
        if rev_p.exists():
            out["reviews"] = json.loads(rev_p.read_text(errors="replace"))
    except Exception:
        out["reviews"] = []
    return out


def _parse_iso8601(ts: str) -> Optional[datetime]:
    try:
        # Support trailing Z by converting to +00:00
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except Exception:
        return None


@api.get("/audit/events")
def list_audit_events(
    user: Optional[str] = None,
    action: Optional[str] = None,
    resourceContains: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    order: str = "desc",
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """List audit events from the UI audit log.

    Requires admin or auditor role. Supports basic filters, pagination, and ordering.
    """
    _require_roles(authorization, ["admin", "auditor"])

    limit = max(1, min(1000, int(limit)))
    offset = max(0, int(offset))
    order = (order or "desc").lower()
    if order not in {"asc", "desc"}:
        raise HTTPException(status_code=400, detail="invalid order")

    if not AUDIT_LOG.exists():
        return {"total": 0, "items": []}

    since_dt = _parse_iso8601(since) if since else None
    until_dt = _parse_iso8601(until) if until else None

    rows: List[Dict[str, Any]] = []
    try:
        with AUDIT_LOG.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                # Basic schema guard
                if not isinstance(obj, dict):
                    continue
                ts = obj.get("timestamp")
                dt = _parse_iso8601(ts) if isinstance(ts, str) else None
                # Normalize datetimes to UTC for comparison (handle mixed tz-aware/naive)
                if dt:
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                if since_dt:
                    since_cmp = since_dt if since_dt.tzinfo else since_dt.replace(tzinfo=timezone.utc)
                    if not dt or dt < since_cmp:
                        continue
                if until_dt:
                    until_cmp = until_dt if until_dt.tzinfo else until_dt.replace(tzinfo=timezone.utc)
                    if not dt or dt > until_cmp:
                        continue
                if user and obj.get("user") != user:
                    continue
                if action and obj.get("action") != action:
                    continue
                if resourceContains:
                    rc = str(obj.get("resource") or "")
                    if resourceContains not in rc:
                        continue
                rows.append(
                    {
                        "timestamp": ts,
                        "user": obj.get("user"),
                        "action": obj.get("action"),
                        "resource": obj.get("resource"),
                        "details": obj.get("details"),
                    }
                )
    except Exception:
        raise HTTPException(status_code=500, detail="failed to read audit log")

    # Sort by timestamp if available (normalize to UTC for consistent comparison)
    def sort_key(o: Dict[str, Any]):
        d = _parse_iso8601(o.get("timestamp") or "")
        if d is None:
            return datetime.min.replace(tzinfo=timezone.utc)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d

    rows.sort(key=sort_key, reverse=(order == "desc"))
    total = len(rows)
    sliced = rows[offset : offset + limit]
    return {"total": total, "items": sliced}


@api.get("/audit/export")
def export_audit_log(authorization: Optional[str] = Header(default=None)) -> StreamingResponse:
    """Stream raw audit log as text/plain. Admin-only."""
    _require_roles(authorization, ["admin"])  # admin-only
    if not AUDIT_LOG.exists():
        # Return empty stream
        return StreamingResponse(iter([b""]), media_type="text/plain")

    def iterator():
        with AUDIT_LOG.open("rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                yield chunk

    return StreamingResponse(iterator(), media_type="text/plain")


# --- Package Confirmation Timeout Cleanup ---


def build_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Lifespan event handler for startup/shutdown tasks."""

        # Startup: Pre-load ML models and calibrators to avoid first-request latency
        def _preload_ml():
            try:
                # Pre-load calibrator (lightweight, ~5ms)
                from core.ml.calibration_loader import load_calibrator

                _cal = load_calibrator()
                logger.info(f"Pre-loaded calibrator: {type(_cal).__name__}")
            except Exception as e:
                logger.debug(f"Calibrator pre-load skipped: {e}")

            # Pre-warm ML pipeline if not disabled
            if os.environ.get("AODS_DISABLE_ML", "0") != "1":
                try:
                    from core.unified_ml_pipeline import UnifiedMLPipeline, MLPipelineConfig

                    cfg = MLPipelineConfig(enable_classifier_cache=True)
                    _pipeline = UnifiedMLPipeline(cfg)
                    stats = _pipeline.registry.get_registry_stats()
                    logger.info(f"Pre-loaded ML pipeline: {stats.get('total_models', 0)} models registered")
                except Exception as e:
                    logger.debug(f"ML pipeline pre-load skipped: {e}")

        # Run ML preloading in background to not block server startup
        asyncio.get_event_loop().run_in_executor(None, _preload_ml)
        yield
        # Shutdown: cleanup if needed (currently no-op)

    _is_prod = os.environ.get("AODS_ENV", "").lower() == "production"
    app = FastAPI(
        title="AODS API",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None if _is_prod else "/docs",
        redoc_url=None if _is_prod else "/redoc",
        openapi_url=None if _is_prod else "/openapi.json",
    )

    class CSPMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            response = await call_next(request)
            try:
                # Determine if running in production mode
                is_production = os.environ.get("AODS_ENV", "").lower() == "production"

                # Base CSP directives
                directives = [
                    "default-src 'self'",
                    "img-src 'self' data: blob:",  # Allow blob for dynamic images
                    # style-src: 'unsafe-inline' required for MUI/emotion CSS-in-JS
                    "style-src 'self' 'unsafe-inline'",
                    "font-src 'self' data:",
                    "object-src 'none'",
                    "base-uri 'self'",
                    "frame-ancestors 'none'",
                    "form-action 'self'",  # Prevent form hijacking
                    "manifest-src 'self'",  # Allow PWA manifests
                ]

                # script-src: Production removes 'unsafe-inline' for security
                # Dev mode keeps it for Vite HMR (Hot Module Replacement)
                if is_production:
                    directives.append("script-src 'self'")
                else:
                    directives.append("script-src 'self' 'unsafe-inline'")

                # Connect sources - stricter in production
                if is_production:
                    # Production: HTTPS + WSS for Frida WebSocket
                    directives.append("connect-src 'self' wss: https:")
                    directives.append("upgrade-insecure-requests")  # Enforce HTTPS
                else:
                    # Dev mode: allow local dev servers + WebSocket for Frida console
                    directives.append(
                        "connect-src 'self' "
                        "http://127.0.0.1:8088 http://127.0.0.1:5088 "
                        "ws://127.0.0.1:8088 ws://127.0.0.1:5088 "
                        "http://localhost:8088 http://localhost:5088 "
                        "ws://localhost:8088 ws://localhost:5088"
                    )

                csp = "; ".join(directives)
                response.headers.setdefault("Content-Security-Policy", csp)

                # Additional security headers
                response.headers.setdefault("X-Content-Type-Options", "nosniff")
                response.headers.setdefault("X-Frame-Options", "DENY")
                response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
                response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

                # HSTS: enforce HTTPS in production (1 year, includeSubDomains)
                if is_production:
                    response.headers.setdefault(
                        "Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains",
                    )
            except Exception:
                pass
            return response

    # Request logging middleware (adds X-Request-ID, logs requests)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(CSPMiddleware)
    # CORS: configurable via AODS_CORS_ORIGINS (comma-separated), defaults to localhost
    _cors_env = os.environ.get("AODS_CORS_ORIGINS", "").strip()
    _cors_origins = [o.strip() for o in _cors_env.split(",") if o.strip()] if _cors_env else [
        "http://localhost",
        "http://127.0.0.1",
        "http://localhost:5088",
        "http://127.0.0.1:5088",
        "http://127.0.0.1:8088",
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            "X-AODS-CSRF",
            "X-Request-ID",
        ],
    )

    # Include extracted route modules
    from core.api.routes.scans import router as scans_router
    from core.api.routes.frida import router as frida_router
    from core.api.routes.ml import router as ml_router
    from core.api.routes.dev import router as dev_router
    from core.api.routes.admin import router as admin_router
    from core.api.routes.malware import router as malware_router

    api.include_router(scans_router)
    api.include_router(frida_router)
    api.include_router(ml_router)
    api.include_router(dev_router)
    api.include_router(admin_router)
    api.include_router(malware_router)

    # Include autoresearch routes (optional, needs SQLite history)
    try:
        from core.api.routes.autoresearch import router as autoresearch_router

        api.include_router(autoresearch_router)
        logger.info("autoresearch_routes_registered")
    except ImportError as e:
        logger.debug("autoresearch_routes_skipped", reason=str(e))

    # Include vector search routes (optional, enabled via AODS_VECTOR_DB_ENABLED)
    try:
        from core.api.routes.vector_search import router as vector_router

        api.include_router(vector_router)
        logger.info("vector_search_routes_registered")
    except ImportError as e:
        logger.debug("vector_search_routes_skipped", reason=str(e))

    # Include agent routes (optional, enabled via AODS_AGENT_ENABLED)
    try:
        from core.api.routes.agent import router as agent_router

        api.include_router(agent_router)
        logger.info("agent_routes_registered")
    except ImportError as e:
        logger.debug("agent_routes_skipped", reason=str(e))

    # Mount combined API router on the app - must happen AFTER all sub-routers
    # are included, since include_router copies routes at call time.
    app.include_router(api)

    # Global exception handler to prevent stack traces from leaking to clients
    from starlette.requests import Request as StarletteRequest
    from starlette.responses import JSONResponse as StarletteJSONResponse

    @app.exception_handler(Exception)
    async def _global_exception_handler(request: StarletteRequest, exc: Exception):
        logger.error("unhandled_exception", path=request.url.path, exc_type=type(exc).__name__)
        return StarletteJSONResponse(status_code=500, content={"detail": "Internal server error"})

    # Serve design mockups under /design for easy access from UI
    try:
        app.mount("/design", StaticFiles(directory=str(REPO_ROOT / "design" / "ui")), name="design-ui")
    except Exception:
        pass
    # Optionally serve production UI under /ui if built
    try:
        ui_dist = REPO_ROOT / "design" / "ui" / "react-app" / "dist"
        if ui_dist.exists():
            # Serve assets directly and provide SPA fallback for all /ui routes
            assets_dir = ui_dist / "assets"
            if assets_dir.exists():
                app.mount("/ui/assets", StaticFiles(directory=str(assets_dir)), name="ui-assets")
                # Back-compat for builds that reference /assets/* (no /ui base)
                app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="root-assets")
            # Serve local axe bundle (when available) to support blocking A11Y audits without CSP issues
            from starlette.responses import FileResponse  # local import to avoid startup cost if unused

            axe_dist_root = ui_dist / "axe.min.js"
            axe_assets = ui_dist / "assets" / "axe.min.js"
            if axe_dist_root.exists() or axe_assets.exists():

                @app.get("/ui/axe.min.js")
                def _ui_axe_bundle():
                    p = axe_dist_root if axe_dist_root.exists() else axe_assets
                    return FileResponse(str(p), media_type="application/javascript")

            # Serve UI config at /ui/config/ui-config.json (MUST be before SPA catch-all)
            @app.get("/ui/config/ui-config.json")
            def _ui_config():
                try:
                    cfg = ui_dist / "config" / "ui-config.json"
                    if cfg.exists():
                        content = cfg.read_text(encoding="utf-8", errors="replace")
                        return JSONResponse(json.loads(content))
                except Exception as e:
                    logger.error(f"Error reading UI config: {e}")
                # fallback minimal config
                return JSONResponse(
                    {
                        "environment": "local",
                        "webBasePath": "/ui",
                        "apiBaseUrl": "/api",
                        "workspaceRoot": str(ui_dist),
                        "defaultLinkMode": "browser",
                    }
                )

            # SPA catch-all (serves index.html for client-side routing)
            @app.get("/ui", response_class=HTMLResponse)
            @app.get("/ui/{path:path}", response_class=HTMLResponse)
            @app.head("/ui")
            @app.head("/ui/{path:path}")
            def _ui_spa(path: str = ""):
                # Serve static files from config directory (fallback if explicit route misses)
                if path.startswith("config/"):
                    static_file = ui_dist / path
                    if static_file.exists() and static_file.is_file():
                        content = static_file.read_text(encoding="utf-8", errors="replace")
                        if path.endswith(".json"):
                            return JSONResponse(json.loads(content))
                        return HTMLResponse(content=content)
                try:
                    html = (ui_dist / "index.html").read_text(encoding="utf-8", errors="replace")
                    # Rely on global CSP middleware for headers to avoid conflicts
                    return HTMLResponse(content=html)
                except Exception:
                    raise HTTPException(status_code=404, detail="UI not built")

    except Exception:
        pass

    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description="AODS API",
            routes=app.routes,
        )
        components = schema.setdefault("components", {})
        security_schemes = components.setdefault("securitySchemes", {})
        security_schemes["bearerAuth"] = {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi  # type: ignore

    @app.get("/", response_class=HTMLResponse)
    def root() -> str:
        return (
            '<!doctype html><html><head><meta charset="utf-8"><title>AODS API</title>'
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; style-src 'self' 'unsafe-inline'\"></head>"  # noqa: E501
            '<body style="font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; padding: 20px;">'
            "<h1>AODS API</h1>"
            "<p>Welcome. Explore the endpoints below:</p>"
            "<ul>"
            '<li><a href="/docs">OpenAPI Docs</a></li>'
            '<li><a href="/api/health">/api/health</a></li>'
            '<li><a href="/api/tools/status">/api/tools/status</a></li>'
            '<li><a href="/api/scans/results">/api/scans/results</a></li>'
            '<li><a href="/api/gates/summary">/api/gates/summary</a></li>'
            '<li><a href="/ui">Open UI</a></li>'
            '<li><a href="/ui/config/ui-config.json">UI Config</a></li>'
            '<li><a href="/design/index.html">Open Design (Mockups)</a></li>'
            "</ul>"
            "</body></html>"
        )

    # Start background cleanup thread for expired package confirmation sessions
    from core.api.routes.scans import _cleanup_expired_confirmation_sessions

    cleanup_thread = threading.Thread(target=_cleanup_expired_confirmation_sessions, daemon=True)
    cleanup_thread.start()

    return app


app = build_app()


if __name__ == "__main__":
    try:
        import uvicorn  # type: ignore
    except Exception as e:
        sys.stderr.write(f"uvicorn required: {e}\n")
        sys.exit(2)
    uvicorn.run("core.api.server:app", host="127.0.0.1", port=8088, reload=False, server_header=False)
