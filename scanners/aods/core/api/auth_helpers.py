"""
AODS API Authentication & Authorization Helpers
================================================

Shared auth functions used by API route modules:
- Token extraction and validation
- User authentication (PBKDF2-SHA256)
- RBAC enforcement
- PII redaction
- Audit logging
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import logging as _stdlib_logging
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException

from core.enterprise.rbac_manager import (
    RBACManager,
    AccessRequest as RBACAccessRequest,
    ResourceType as RBACResourceType,
    Permission as RBACPermission,
)
from core.logging_config import get_logger, get_request_context
from core.api.shared_state import (
    REPO_ROOT,
    AUDIT_LOG,
    _TOKENS,
    _TOKENS_LOCK,
    _USERS,
    _USERS_LOCK,
    _PII_PATTERNS,
)

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# RBAC Manager
# ---------------------------------------------------------------------------

_RBAC = RBACManager(config={"audit_log_file": str((REPO_ROOT / "artifacts" / "ui_rbac_audit.log").resolve())})

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Token Extraction / Validation
# ---------------------------------------------------------------------------


def _extract_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def _get_user_info(authorization: Optional[str]) -> Optional[Dict[str, Any]]:
    # Allow anonymous access when auth is disabled (development mode)
    if os.environ.get("AODS_AUTH_DISABLED", "0") == "1":
        return {"user": "dev_user", "roles": ["admin", "analyst", "viewer"], "auth_mode": "disabled"}
    tok = _extract_token(authorization)
    if not tok:
        return None
    with _TOKENS_LOCK:
        info = _TOKENS.get(tok)
        if info is None:
            return None
        if info.get("exp", 0) < time.time():
            _TOKENS.pop(tok, None)
            return None
        return info


# ---------------------------------------------------------------------------
# RBAC Enforcement
# ---------------------------------------------------------------------------


def _require_roles(authorization: Optional[str], required: List[str]) -> Dict[str, Any]:
    info = _get_user_info(authorization)
    if not info:
        logger.warning("access_denied", reason="unauthenticated", required_roles=required)
        raise HTTPException(status_code=401, detail="unauthorized")
    roles = info.get("roles") or []
    if required and not any(r in roles for r in required):
        logger.warning(
            "access_denied",
            reason="insufficient_roles",
            user=info.get("user"),
            user_roles=roles,
            required_roles=required,
        )
        _audit(
            "access_denied",
            info.get("user", "unknown"),
            details={"reason": "insufficient_roles", "required": required, "had": roles},
        )
        raise HTTPException(status_code=403, detail="forbidden")
    return info


def _enforce_access(
    authorization: Optional[str], resource_type: RBACResourceType, permission: RBACPermission
) -> Dict[str, Any]:
    info = _get_user_info(authorization)
    if not info:
        logger.warning(
            "access_denied", reason="unauthenticated", resource_type=str(resource_type), permission=str(permission)
        )
        raise HTTPException(status_code=401, detail="unauthorized")
    req = RBACAccessRequest(
        user_id=info.get("user", "api_user"),
        username=info.get("user", "api_user"),
        roles=list(info.get("roles") or []),
        resource_type=resource_type,
        resource_id=None,
        permission=permission,
        context={},
    )
    res = _RBAC.check_access(req)
    if not res.allowed:
        logger.warning(
            "access_denied",
            reason="rbac_denied",
            user=info.get("user"),
            resource_type=str(resource_type),
            permission=str(permission),
        )
        _audit(
            "access_denied",
            info.get("user", "unknown"),
            details={"reason": "rbac_denied", "resource_type": str(resource_type), "permission": str(permission)},
        )
        raise HTTPException(status_code=403, detail="forbidden")
    return info


# ---------------------------------------------------------------------------
# Resource Ownership
# ---------------------------------------------------------------------------


def _can_access_resource(user_info: Dict[str, Any], resource_owner: Optional[str]) -> bool:
    """Check if a user can access a resource based on ownership."""
    roles = user_info.get("roles") or []
    if "admin" in roles:
        return True
    if not resource_owner:
        return True
    user = user_info.get("user", "")
    return user == resource_owner


def _filter_owned_resources(
    user_info: Dict[str, Any], resources: List[Dict[str, Any]], owner_key: str = "owner"
) -> List[Dict[str, Any]]:
    """Filter a list of resources to only those the user can access."""
    roles = user_info.get("roles") or []
    if "admin" in roles:
        return resources
    user = user_info.get("user", "")
    return [r for r in resources if not r.get(owner_key) or r.get(owner_key) == user]


# ---------------------------------------------------------------------------
# Password Hashing
# ---------------------------------------------------------------------------


def _hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """Hash a password using PBKDF2-SHA256."""
    if salt is None:
        salt = secrets.token_bytes(32)
    elif isinstance(salt, str):
        salt = base64.b64decode(salt)

    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations=100000, dklen=32)
    return base64.b64encode(pw_hash).decode("utf-8"), base64.b64encode(salt).decode("utf-8")


def _verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    """Verify a password against stored hash and salt."""
    computed_hash, _ = _hash_password(password, base64.b64decode(stored_salt))
    return secrets.compare_digest(computed_hash, stored_hash)


# ---------------------------------------------------------------------------
# User Management
# ---------------------------------------------------------------------------


def _init_default_users() -> None:
    """Initialize default users from environment variables."""
    with _USERS_LOCK:
        if os.environ.get("AODS_AUTH_DISABLED", "0") == "1":
            logger.warning("auth_disabled", message="Authentication is disabled (development mode)")
            return

        # Admin user
        admin_password = os.environ.get("AODS_ADMIN_PASSWORD")
        if admin_password:
            pw_hash, salt = _hash_password(admin_password)
            _USERS["admin"] = {"password_hash": pw_hash, "salt": salt, "roles": ["admin", "analyst", "viewer"]}
            logger.info("user_configured", username="admin", source="AODS_ADMIN_PASSWORD")
        else:
            generated_password = secrets.token_urlsafe(16)
            pw_hash, salt = _hash_password(generated_password)
            _USERS["admin"] = {"password_hash": pw_hash, "salt": salt, "roles": ["admin", "analyst", "viewer"]}
            logger.warning(
                "admin_password_generated",
                message="No AODS_ADMIN_PASSWORD set - generated temporary password",
            )
            # Print to stderr only (not structured logs) so the operator sees it
            # but it won't appear in log aggregation systems.
            print(
                f"[AODS] Generated admin password: {generated_password}",
                file=sys.stderr,
            )

        # Analyst user (optional)
        analyst_password = os.environ.get("AODS_ANALYST_PASSWORD")
        if analyst_password:
            pw_hash, salt = _hash_password(analyst_password)
            _USERS["analyst"] = {"password_hash": pw_hash, "salt": salt, "roles": ["analyst", "viewer"]}
            logger.info("user_configured", username="analyst", source="AODS_ANALYST_PASSWORD")

        # Viewer user (optional)
        viewer_password = os.environ.get("AODS_VIEWER_PASSWORD")
        if viewer_password:
            pw_hash, salt = _hash_password(viewer_password)
            _USERS["viewer"] = {"password_hash": pw_hash, "salt": salt, "roles": ["viewer"]}
            logger.info("user_configured", username="viewer", source="AODS_VIEWER_PASSWORD")


def _authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate a user with username and password."""
    if os.environ.get("AODS_AUTH_DISABLED", "0") == "1":
        return {
            "user": username,
            "roles": ["viewer"] if username != "admin" else ["admin", "analyst", "viewer"],
            "auth_mode": "disabled",
        }

    with _USERS_LOCK:
        user = _USERS.get(username)
        if not user:
            # Run dummy PBKDF2 to prevent timing-based username enumeration  - 
            # without this, non-existent users return instantly while real users
            # take ~50-100ms for PBKDF2 (100K iterations).
            _hash_password(password, secrets.token_bytes(32))
            return None
        if _verify_password(password, user["password_hash"], user["salt"]):
            return {"user": username, "roles": user["roles"]}

    return None


# ---------------------------------------------------------------------------
# Audit Logging
# ---------------------------------------------------------------------------


def _sanitize_audit_details(details: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Truncate overly long string values in audit log details to prevent log bloat."""
    if not details:
        return details
    _MAX_DETAIL_LEN = 256
    sanitized = {}
    for k, v in details.items():
        if isinstance(v, str):
            v = v[:_MAX_DETAIL_LEN].replace("\n", " ").replace("\r", " ")
        sanitized[k] = v
    return sanitized


def _audit(action: str, user: str, resource: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
    try:
        # Guard against daemon threads calling _audit after stderr is closed
        # during interpreter shutdown - prevents ValueError noise in test output
        if sys.stderr is None or sys.stderr.closed:
            return
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        ctx = get_request_context()
        evt = {
            "timestamp": _now_iso(),
            "user": user,
            "action": action,
            "resource": resource,
            "details": _sanitize_audit_details(details),
            "request_id": ctx.get("request_id"),
        }
        with AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(evt) + "\n")
        # Suppress "--- Logging error ---" noise when stderr is closed during
        # daemon thread shutdown (Python's logging module prints this internally
        # before our try/except can intercept it)
        _prev = _stdlib_logging.raiseExceptions
        _stdlib_logging.raiseExceptions = False
        try:
            logger.info("audit_event", action=action, audit_user=user, resource=resource)
        finally:
            _stdlib_logging.raiseExceptions = _prev
    except (ValueError, OSError):
        pass
    except Exception:
        pass


def _audit_ml_decision(
    finding_id: str,
    stage: str,
    decision: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Log an ML pipeline decision to the audit trail.

    Only emits when AODS_ML_AUDIT=1 (off by default - can be verbose).

    Args:
        finding_id: Finding title or ID (no PII - title only).
        stage: Pipeline stage (noise_dampener, ml_ensemble, heuristic_rules).
        decision: Decision made (keep, filter, dampen).
        details: Additional context (rule name, confidence, etc.).
    """
    if os.environ.get("AODS_ML_AUDIT", "0") not in ("1", "true"):
        return
    _audit("ml_decision", "ml_system", finding_id, {
        "stage": stage,
        "decision": decision,
        **(details or {}),
    })


# ---------------------------------------------------------------------------
# PII Redaction
# ---------------------------------------------------------------------------


def _redact_pii_in_text(text: str) -> str:
    out = text
    for pat, repl in _PII_PATTERNS:
        out = pat.sub(repl, out)
    return out


def _redact_pii(obj: Any) -> Any:
    if isinstance(obj, str):
        return _redact_pii_in_text(obj)
    if isinstance(obj, dict):
        return {k: _redact_pii(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_pii(v) for v in obj]
    return obj


# Initialize default users on module load
_init_default_users()
