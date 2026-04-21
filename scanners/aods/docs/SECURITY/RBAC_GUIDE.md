# AODS Role-Based Access Control (RBAC) Guide

This document describes the RBAC system used in AODS for controlling access to resources and API endpoints.

## Overview

AODS implements a role-based access control system with:
- **Role-based permissions** - Users are assigned roles that grant specific permissions
- **Resource-level access control** - Fine-grained control over specific resources
- **Ownership tracking** - Scan ownership enforced for non-admin users

## Roles

### Role Definitions

| Role | Description | Use Case |
|------|-------------|----------|
| `admin` | Full system administrator | System configuration, user management, all operations |
| `analyst` | Security analyst | Running scans, viewing results, generating reports |
| `viewer` | Read-only access | Viewing results and dashboards |
| `auditor` | Audit and compliance | Accessing audit logs, compliance reports |
| `api_user` | API automation | Viewing scan results (cannot start scans - see note below) |

> **Note**: The `api_user` role currently has `CREATE` and `READ` permissions on APK Analysis but lacks `EXECUTE`. Since `/api/scans/start` and `/api/scans/{id}/cancel` require `EXECUTE` permission, `api_user` cannot start or cancel scans with the default role configuration.

### Role Assignment

The RBAC engine supports **role inheritance** (hierarchical roles), but the **default built-in roles are defined without parent roles**, so they behave as independent permission sets. The admin user is provisioned with multiple roles `["admin", "analyst", "viewer"]` (union of permissions).

When a user authenticates, their assigned roles are checked against endpoint requirements. A user with `["admin", "analyst", "viewer"]` effectively has the union of all three roles' permissions.

### Default User Provisioning (Current Behavior)

Users are provisioned at API startup via environment variables. Admins can also manage user roles via the Admin API (see Admin Endpoint Permissions below) or the Admin Panel UI (see below):

- `admin` user is always created (password from `AODS_ADMIN_PASSWORD`, or auto-generated and logged if unset)
- `analyst` user is created only if `AODS_ANALYST_PASSWORD` is set
- `viewer` user is created only if `AODS_VIEWER_PASSWORD` is set

The `auditor` and `api_user` roles exist in RBAC, but there is **no default account** created for them by environment variables.

## Permission Matrix

### Resource Permissions

| Resource | admin | analyst | viewer | auditor | api_user |
|----------|-------|---------|--------|---------|----------|
| APK Analysis | CRUD+X | CR+X | R | - | CR |
| Reports | CRUD+A | CRU | R | R | - |
| User Management | CRUD+A | - | - | - | - |
| System Config | CRUD+A | - | - | - | - |
| Audit Logs | R+Audit | - | - | R+Audit | - |
| Plugins | CRUD+X | R+X | - | - | X |
| ML Models | CRUD+X | R+X | - | - | X |
| Dashboard | CRUD | R | R | R | - |
| Export | CR+X | CR | - | - | - |

**Legend**: C=Create, R=Read, U=Update, D=Delete, X=Execute, A=Admin, Audit=Audit permission

### API Endpoint Permissions

| Endpoint | Auth Required | Roles |
|----------|---------------|-------|
| `POST /api/scans/start` | Yes | admin, analyst (requires EXECUTE) |
| `POST /api/scans/{id}/cancel` | Yes | admin, analyst (owner or admin only) |
| `GET /api/scans/results` | Yes | admin, analyst, viewer, api_user |
| `GET /api/scans/result/{id}` | Yes | admin, analyst, viewer, api_user |
| `GET /api/scans/result/{id}/chunk` | Yes | admin, analyst, viewer, api_user |
| `GET /api/scans/{id}/progress` | Yes | admin, analyst, viewer, api_user |
| `GET /api/scans/{id}/progress/stream` | Yes | admin, analyst, viewer, api_user (owner check) |
| `GET /api/scans/{id}/logs/stream` | Yes | admin, analyst, viewer, api_user (owner check) |
| `GET /api/scans/{id}/details` | Yes | admin, analyst, viewer (owner check) |
| `GET /api/scans/active` | Yes | admin, analyst (owner-filtered for analyst) |
| `GET /api/scans/recent` | Yes | admin, analyst, viewer (see note below) |
| `GET /api/artifacts/*` | No | Public |
| `GET /api/audit/events` | Yes | admin, auditor |
| `GET /api/audit/export` | Yes | admin only |
| `POST /api/audit/event` | No | Public (UI audit logging) |
| `GET /api/gates/*` | No | Public |
| `GET /api/ml/*` | Mixed | Most endpoints public; some require auth |
| `GET /api/config` | No | Public |
| `GET /api/health` | No | Public |

> **Note**: `/api/scans/recent` merges **in-memory sessions** (owner-filtered for non-admins) with **persisted report files** (which generally do not include owner metadata and therefore are not strictly owner-filtered).

### Agent Endpoint Permissions

Agent endpoints require `AODS_AGENT_ENABLED=1`:

| Endpoint | Roles |
|----------|-------|
| `POST /api/agent/tasks` | admin, analyst |
| `GET /api/agent/tasks/{id}` | admin, analyst |
| `GET /api/agent/tasks/{id}/transcript` | admin, analyst |
| `POST /api/agent/pipeline` | admin, analyst |
| `GET /api/agent/stats` | admin, analyst |
| `GET /api/agent/config` | **admin only** |
| `POST /api/agent/triage/feedback` | admin, analyst |
| `GET /api/agent/triage/feedback/history` | admin, analyst |

### Admin Endpoint Permissions

| Endpoint | Roles |
|----------|-------|
| `GET /api/admin/users` | **admin only** |
| `GET /api/admin/roles` | **admin only** |
| `PUT /api/admin/users/{username}/role` | **admin only** |

### Frida Endpoint Permissions

Frida endpoints have **mixed** permissions - not all are uniformly "admin, analyst":

| Endpoint | Roles |
|----------|-------|
| `GET /api/frida/health` | admin, analyst |
| `GET /api/frida/devices` | admin, analyst |
| `GET /api/frida/devices/{id}/processes` | admin, analyst |
| `POST /api/frida/attach` | admin, analyst |
| `POST /api/frida/detach` | admin, analyst |
| `POST /api/frida/ws-token` | admin, analyst |
| `GET /api/frida/session/{pkg}/status` | admin, analyst |
| `GET /api/frida/session/{pkg}/events/stream` | admin, analyst |
| `POST /api/frida/session/{pkg}/scripts` | **admin only** |
| `DELETE /api/frida/session/{pkg}/scripts/{name}` | **admin only** |
| `POST /api/frida/session/{id}/baseline` | admin, analyst |
| `POST /api/frida/corellium/connect` | admin, analyst |
| `POST /api/frida/corellium/ensure` | admin, analyst |
| `POST /api/frida/session/{id}/rpc` | **admin only** |
| `POST /api/frida/session/{pkg}/run-targeted` | **admin only** |
| `GET /api/frida/telemetry/recent` | **admin only** |
| `GET /api/frida/telemetry/summary` | **admin only** |
| `GET /api/frida/telemetry/download` | **admin only** |

## Admin Panel UI

The React frontend provides an **Admin Panel** at `/admin` (`RBACAdmin.tsx`) for managing user roles via the browser. This page is restricted to users with the `admin` role (enforced by `RequireRoles`).

**Features:**
- Lists all provisioned users and their current roles
- Allows admins to change a user's role via a dropdown (calls `PUT /api/admin/users/{username}/role`)
- Displays available roles fetched from `GET /api/admin/roles`

**Access:** Navigate to `/admin` in the UI while authenticated as an admin user.

## Feedback Analytics UI

The **FeedbackAnalytics** page at `/feedback` (`FeedbackAnalytics.tsx`) provides visibility into triage feedback collected during agent-assisted scans. This page is restricted to `admin` and `analyst` roles.

**Features:**
- Displays triage feedback entries extracted from scan reports
- Exports feedback as JSON via `GET /api/agent/triage/feedback/export`
- Supports filtering by scan ID

**Access:** Navigate to `/feedback` in the UI while authenticated as an admin or analyst.

## Authentication

### Bearer Token Authentication

AODS uses opaque bearer tokens (not JWT) for API authentication. Tokens are stored server-side with a 24-hour expiry.

#### Login

```bash
curl -X POST http://127.0.0.1:8088/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "<your-password>"}'
```

Response:
```json
{
  "token": "abc123...",
  "user": "admin",
  "roles": ["admin", "analyst", "viewer"]
}
```

#### Using the Token

Include the token in the `Authorization` header:

```bash
curl http://127.0.0.1:8088/api/scans/results \
  -H "Authorization: Bearer abc123..."
```

#### SSE Streams

For Server-Sent Events (SSE) endpoints, browsers don't support custom headers with `EventSource`, so AODS supports a `token` query parameter. Non-browser clients can also use the `Authorization` header.

```bash
curl "http://127.0.0.1:8088/api/scans/{id}/progress/stream?token=abc123..."
```

#### Token Expiry

Tokens expire after 24 hours by default (configurable via `AODS_JWT_EXPIRY_HOURS`). There is no refresh endpoint - users must re-login to obtain a new token.

## Environment Variables

### Authentication Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AODS_ADMIN_PASSWORD` | *auto-generated* | Admin user password. If not set, a random password is generated and logged at startup. |
| `AODS_ANALYST_PASSWORD` | *(none)* | Analyst user password. User only created if set. |
| `AODS_VIEWER_PASSWORD` | *(none)* | Viewer user password. User only created if set. |
| `AODS_AUTH_DISABLED` | `0` | Set to `1` to disable authentication (development only). |

### Security Recommendations

For production deployments:

```bash
# Set strong passwords (required - no defaults!)
export AODS_ADMIN_PASSWORD="<strong-random-password>"
export AODS_ANALYST_PASSWORD="<strong-random-password>"
export AODS_VIEWER_PASSWORD="<strong-random-password>"

# Never disable auth in production
# export AODS_AUTH_DISABLED=0  # (default)
```

> **Warning**: If `AODS_ADMIN_PASSWORD` is not set, the server generates a random password and logs it. Check server logs for the generated password.

## Resource Ownership

AODS tracks scan ownership for access control. Ownership is enforced for **in-memory scan sessions** on both read and write operations for the endpoints listed below (streams/details/cancel/active list).

- **Admins** can access and modify any scan
- **Analysts/Viewers** can only access their own scans (streams, details, cancel)
- **Active scans list** is filtered by ownership for non-admins
- **Recent scans list** is owner-filtered for in-memory sessions, but may also include persisted report files without owner metadata (see note in the endpoint table)

Ownership is tracked in the server's in-memory session store. When a scan is started, the initiating user is recorded as the owner in the session's `"owner"` field.

### Ownership Enforcement

The `_can_access_resource()` function checks ownership:
- Admin users bypass ownership checks
- If no owner is set, access is allowed (backwards compatibility)
- Otherwise, non-admin users can only access resources they own

Endpoints with ownership checks:
- `GET /api/scans/{id}/progress/stream` - owner check
- `GET /api/scans/{id}/logs/stream` - owner check
- `GET /api/scans/{id}/details` - owner check
- `POST /api/scans/{id}/cancel` - owner check
- `GET /api/scans/active` - filtered by owner (analyst)
- `GET /api/scans/recent` - sessions filtered by owner; reports may not be

## Audit Logging

### UI Audit Log

User actions from the UI are logged to `artifacts/ui_audit.log`:

```json
{
  "timestamp": "2026-02-02T12:00:00Z",
  "user": "analyst1",
  "action": "start_scan",
  "resource": "/path/to/app.apk",
  "details": {"sessionId": "abc123"},
  "request_id": "req-456"
}
```

### RBAC Decision Log

RBAC access decisions are logged to `artifacts/ui_rbac_audit.log` (configured via RBACManager).

## Troubleshooting

### Common Issues

**401 Unauthorized**
- Token expired (24h lifetime) or invalid
- Missing `Authorization` header
- Solution: Re-login to obtain a new token

**403 Forbidden**
- User lacks required permissions for the endpoint
- Trying to access another user's scan (non-admin)
- Solution: Check role permissions, use admin account if needed

**Token Not Working with SSE**
- Browser `EventSource` requires token as query parameter (cannot set `Authorization` header)
- Solution: Use `?token=<token>` in URL (non-browser clients may use either header or query token)

**No Password Set - Random Generated**
- If `AODS_ADMIN_PASSWORD` is not set, check server logs for the auto-generated password
- Search logs for `admin_password_generated`

### Debugging

Enable debug logging:

```bash
export AODS_LOG_LEVEL=DEBUG
```

Check current user info:

```bash
curl http://127.0.0.1:8088/api/auth/me \
  -H "Authorization: Bearer <token>"
```
