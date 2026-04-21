"""IODS API Auth Helpers."""
from __future__ import annotations

import secrets
from typing import Dict, Optional

from core.api.shared_state import _TOKENS, _TOKENS_LOCK


def _extract_token(authorization: Optional[str]) -> Optional[str]:
    """Extract bearer token from Authorization header."""
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def _get_user_info(token: str) -> Optional[Dict]:
    with _TOKENS_LOCK:
        return _TOKENS.get(token)


def create_token(user_id: str, role: str = "analyst") -> str:
    """Create and store a new API token."""
    token = secrets.token_urlsafe(32)
    with _TOKENS_LOCK:
        _TOKENS[token] = {"user_id": user_id, "role": role}
    return token


def _require_roles(token: Optional[str], allowed_roles: list) -> bool:
    """Return True if token belongs to one of the allowed roles."""
    if not token:
        return False
    user = _get_user_info(token)
    if not user:
        return False
    return user.get("role") in allowed_roles


def _enforce_access(token: Optional[str], allowed_roles: list) -> None:
    from fastapi import HTTPException
    if not _require_roles(token, allowed_roles):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
