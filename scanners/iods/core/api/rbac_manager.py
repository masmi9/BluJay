"""
IODS RBAC Manager – role-based access control.

Roles: admin, analyst, viewer, auditor, api_user
"""
from __future__ import annotations

from enum import Enum
from typing import Dict, Set


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    AUDITOR = "auditor"
    API_USER = "api_user"


class Permission(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"


class ResourceType(str, Enum):
    SCANS = "scans"
    REPORTS = "reports"
    SETTINGS = "settings"
    BATCH_JOBS = "batch_jobs"
    ADMIN = "admin"


# Role → Resource → Permissions
_ROLE_PERMISSIONS: Dict[str, Dict[str, Set[str]]] = {
    Role.ADMIN: {
        ResourceType.SCANS: {Permission.READ, Permission.WRITE, Permission.EXECUTE, Permission.DELETE},
        ResourceType.REPORTS: {Permission.READ, Permission.WRITE, Permission.DELETE},
        ResourceType.SETTINGS: {Permission.READ, Permission.WRITE},
        ResourceType.BATCH_JOBS: {Permission.READ, Permission.WRITE, Permission.EXECUTE, Permission.DELETE},
        ResourceType.ADMIN: {Permission.READ, Permission.WRITE},
    },
    Role.ANALYST: {
        ResourceType.SCANS: {Permission.READ, Permission.WRITE, Permission.EXECUTE},
        ResourceType.REPORTS: {Permission.READ, Permission.WRITE},
        ResourceType.SETTINGS: {Permission.READ},
        ResourceType.BATCH_JOBS: {Permission.READ, Permission.WRITE, Permission.EXECUTE},
        ResourceType.ADMIN: set(),
    },
    Role.VIEWER: {
        ResourceType.SCANS: {Permission.READ},
        ResourceType.REPORTS: {Permission.READ},
        ResourceType.SETTINGS: set(),
        ResourceType.BATCH_JOBS: {Permission.READ},
        ResourceType.ADMIN: set(),
    },
    Role.AUDITOR: {
        ResourceType.SCANS: {Permission.READ},
        ResourceType.REPORTS: {Permission.READ},
        ResourceType.SETTINGS: {Permission.READ},
        ResourceType.BATCH_JOBS: {Permission.READ},
        ResourceType.ADMIN: set(),
    },
    Role.API_USER: {
        ResourceType.SCANS: {Permission.READ, Permission.EXECUTE},
        ResourceType.REPORTS: {Permission.READ},
        ResourceType.SETTINGS: set(),
        ResourceType.BATCH_JOBS: {Permission.READ, Permission.EXECUTE},
        ResourceType.ADMIN: set(),
    },
}


def check_permission(role: str, resource: str, permission: str) -> bool:
    """Return True if the role has the given permission on the resource."""
    role_perms = _ROLE_PERMISSIONS.get(role, {})
    resource_perms = role_perms.get(resource, set())
    return permission in resource_perms
