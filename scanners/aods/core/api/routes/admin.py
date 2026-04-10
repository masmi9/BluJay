"""
AODS API Admin Routes
=====================

Admin-only endpoints for user and role management.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)

import os

from core.api.auth_helpers import _require_roles, _RBAC, _audit
from core.api.shared_state import _USERS, _USERS_LOCK

router = APIRouter(tags=["admin"])

# Role name → role set mapping
_ROLE_MAP = {
    "admin": ["admin", "analyst", "viewer"],
    "analyst": ["analyst", "viewer"],
    "viewer": ["viewer"],
    "auditor": ["auditor"],
    "api_user": ["api_user"],
}


@router.get("/admin/users")
async def list_users(authorization: Optional[str] = Header(None)):
    """List all users with their roles (admin only)."""
    _require_roles(authorization, ["admin"])
    with _USERS_LOCK:
        users = []
        for username, info in _USERS.items():
            users.append({
                "username": username,
                "roles": list(info.get("roles", [])),
            })
    return {"users": users}


@router.get("/admin/roles")
async def list_roles(authorization: Optional[str] = Header(None)):
    """Return role hierarchy from RBAC manager (admin only)."""
    _require_roles(authorization, ["admin"])
    hierarchy = _RBAC.role_manager.get_role_hierarchy()
    roles = {}
    for role_name, details in hierarchy.items():
        roles[role_name] = {
            "description": details.get("description", ""),
            "permissions": details.get("permissions", []),
            "resource_permissions": details.get("resource_permissions", {}),
        }
    return {"roles": roles}


class UpdateRoleRequest(BaseModel):
    role: str = Field(..., max_length=64)


@router.put("/admin/users/{username}/role")
async def update_user_role(
    username: str,
    body: UpdateRoleRequest,
    authorization: Optional[str] = Header(None),
):
    """Change a user's role (admin only). Prevents self-demotion."""
    info = _require_roles(authorization, ["admin"])

    # Prevent self-demotion
    if info.get("user") == username:
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    if body.role not in _ROLE_MAP:
        raise HTTPException(
            status_code=400,
            detail="invalid role",
        )

    with _USERS_LOCK:
        user = _USERS.get(username)
        if not user:
            raise HTTPException(status_code=404, detail="user not found")
        old_roles = list(user.get("roles", []))
        user["roles"] = list(_ROLE_MAP[body.role])

    _audit(
        "change_user_role",
        info.get("user", "admin"),
        resource=username,
        details={"old_roles": old_roles, "new_role": body.role, "new_roles": list(_ROLE_MAP[body.role])},
    )
    logger.info("user_role_changed", username=username, new_role=body.role)

    return {"ok": True}


# ---------------------------------------------------------------------------
# Environment Variables (admin only)
# ---------------------------------------------------------------------------

# Vars that must never be exposed or modified via API
_SENSITIVE_VARS = {"AODS_ADMIN_PASSWORD", "AODS_ANALYST_PASSWORD", "AODS_VIEWER_PASSWORD", "AODS_JWT_SECRET"}


@router.get("/admin/env")
async def get_env_summary(authorization: Optional[str] = Header(None)):
    """Return all registered AODS environment variables grouped by category (admin only).

    Sensitive values (passwords, secrets) are masked.
    """
    _require_roles(authorization, ["admin"])
    try:
        from core.shared_infrastructure.configuration.env_var_registry import get_env_var_summary
        summary = get_env_var_summary()
    except ImportError:
        raise HTTPException(status_code=501, detail="env var registry unavailable")

    # Mask sensitive values
    for _cat, vars_list in summary.items():
        for v in vars_list:
            if v.get("name") in _SENSITIVE_VARS:
                v["current"] = "********" if v.get("is_set") else v.get("default")
                v["default"] = "********"
    return {"categories": summary}


class UpdateEnvVarRequest(BaseModel):
    value: str = Field(..., max_length=1024)


@router.put("/admin/env/{name}")
async def update_env_var(
    name: str,
    body: UpdateEnvVarRequest,
    authorization: Optional[str] = Header(None),
):
    """Update a runtime environment variable (admin only).

    Changes take effect for subsequent operations but do not persist across restarts.
    Sensitive variables (passwords, secrets) cannot be changed via this endpoint.
    """
    info = _require_roles(authorization, ["admin"])

    if name in _SENSITIVE_VARS:
        raise HTTPException(status_code=403, detail="sensitive variable cannot be changed via API")

    try:
        from core.shared_infrastructure.configuration.env_var_registry import ENV_VAR_REGISTRY
    except ImportError:
        raise HTTPException(status_code=501, detail="env var registry unavailable")

    if name not in ENV_VAR_REGISTRY:
        raise HTTPException(status_code=404, detail="unknown variable")

    defn = ENV_VAR_REGISTRY[name]

    # Validate allowed values if defined
    if defn.allowed_values:
        parsed = body.value
        if defn.var_type == bool:
            parsed = body.value.lower() in ("1", "true", "yes", "on")
        elif defn.var_type == int:
            try:
                parsed = int(body.value)
            except ValueError:
                raise HTTPException(status_code=400, detail="expected integer value")
        elif defn.var_type == float:
            try:
                parsed = float(body.value)
            except ValueError:
                raise HTTPException(status_code=400, detail="expected float value")
        if parsed not in defn.allowed_values:
            raise HTTPException(
                status_code=400,
                detail="invalid value for this parameter",
            )

    old_value = os.environ.get(name, "")
    os.environ[name] = body.value

    _audit(
        "update_env_var",
        info.get("user", "admin"),
        resource=name,
        details={"old": old_value, "new": body.value},
    )
    logger.info("env_var_updated", name=name, user=info.get("user"))

    return {"ok": True, "name": name, "value": body.value}


# ---------------------------------------------------------------------------
# Audit log query endpoint
# ---------------------------------------------------------------------------


@router.get("/audit/events")
def list_audit_events(
    action: Optional[str] = None,
    user: Optional[str] = None,
    resource: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    authorization: Optional[str] = Header(default=None),
):
    """Query audit log events with optional filtering.

    Requires admin or auditor role.
    Parses the JSONL audit log and returns matching events.

    Args:
        action: Filter by action type (e.g., ml_decision, toggle_change).
        user: Filter by username.
        resource: Filter by resource (substring match).
        limit: Maximum events to return (1-500, default 100).
        offset: Skip first N matching events.
    """
    _require_roles(authorization, ["admin", "auditor"])

    from core.api.shared_state import AUDIT_LOG
    import json

    if not AUDIT_LOG.exists():
        return {"events": [], "total": 0, "offset": offset, "limit": limit}

    limit = max(1, min(500, limit))
    offset = max(0, min(10000, offset))

    events = []
    try:
        with open(AUDIT_LOG, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue

                # Apply filters
                if action and evt.get("action") != action:
                    continue
                if user and evt.get("user") != user:
                    continue
                if resource and resource.lower() not in (evt.get("resource") or "").lower():
                    continue

                events.append(evt)
    except OSError:
        raise HTTPException(status_code=500, detail="Failed to read audit log")

    # Reverse for newest-first, apply offset/limit
    events.reverse()
    total = len(events)
    page = events[offset:offset + limit]

    return {
        "events": page,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": (offset + limit) < total,
    }
