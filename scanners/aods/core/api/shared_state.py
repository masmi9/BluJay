"""
AODS API Shared State
=====================

Module-level state variables, locks, constants, and caching utilities
shared across API route modules. Centralized here to avoid circular imports.
"""

from __future__ import annotations

import os
import re
import time
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Set, Tuple

# ---------------------------------------------------------------------------
# Path Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
DYNA_PATH = REPO_ROOT / "dyna.py"
REPORTS_DIR = REPO_ROOT / "reports"
CI_GATES_DIR = REPO_ROOT / "artifacts" / "ci_gates"
BATCH_JOBS_DIR = REPO_ROOT / "artifacts" / "batch_jobs"
AUDIT_LOG = REPO_ROOT / "artifacts" / "ui_audit.log"
UPLOADS_DIR = REPO_ROOT / "artifacts" / "scans" / "uploads"
CURATION_DIR = REPO_ROOT / "artifacts" / "curation"
SCHEMAS_DIR = REPO_ROOT / "config" / "schemas"

# ---------------------------------------------------------------------------
# Session / Scan State
# ---------------------------------------------------------------------------

_SESSIONS_LOCK = threading.RLock()
_SESSIONS: Dict[str, Dict[str, Any]] = {}
_BATCH_LOCK = threading.RLock()
_BATCH_JOBS: Dict[str, Dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# Auth / Token State
# ---------------------------------------------------------------------------

_TOKENS_LOCK = threading.RLock()
_TOKENS: Dict[str, Dict[str, Any]] = {}
_USERS_LOCK = threading.RLock()
_USERS: Dict[str, Dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# Login Rate Limiting
# ---------------------------------------------------------------------------

_LOGIN_ATTEMPTS_LOCK = threading.Lock()
# { ip_or_username: [timestamp, ...] }
_LOGIN_ATTEMPTS: Dict[str, List[float]] = {}
LOGIN_MAX_ATTEMPTS = 10  # per window
LOGIN_WINDOW_SECONDS = 300.0  # 5 minutes
LOGIN_LOCKOUT_SECONDS = 600.0  # 10 minute lockout after exceeding limit

# ---------------------------------------------------------------------------
# Scan Concurrency Limits
# ---------------------------------------------------------------------------

MAX_ACTIVE_SCANS_PER_USER = 5
MAX_ACTIVE_SCANS_GLOBAL = 20

# ---------------------------------------------------------------------------
# Session / Batch Cleanup TTLs
# ---------------------------------------------------------------------------

COMPLETED_SESSION_TTL = 86400.0  # 24 hours - remove completed/failed/cancelled sessions
COMPLETED_BATCH_TTL = 86400.0 * 7  # 7 days - remove finished batch jobs
MAX_BATCH_JOBS = 500  # hard cap on stored batch jobs
SSE_IDLE_TIMEOUT = 1800.0  # 30 minutes - close idle SSE connections

# ---------------------------------------------------------------------------
# Expensive Operation Rate Limiting
# ---------------------------------------------------------------------------

_EXPENSIVE_OPS_LOCK = threading.Lock()
# { "operation:user": last_start_timestamp }
_EXPENSIVE_OPS_LAST: Dict[str, float] = {}

# Cooldowns (seconds) - minimum interval between successive calls per user
EXPENSIVE_OP_COOLDOWNS: Dict[str, float] = {
    "ml_calibration": 300.0,   # 5 minutes between ML calibration runs
    "vector_rebuild": 600.0,   # 10 minutes between vector index rebuilds
    "batch_start": 60.0,       # 1 minute between batch job starts per user
    "agent_task": 10.0,        # 10 seconds between agent task starts per user
    "agent_pipeline": 60.0,    # 1 minute between pipeline runs per user
}

# ---------------------------------------------------------------------------
# Agent Concurrency Limits
# ---------------------------------------------------------------------------

MAX_AGENT_TASKS_PER_USER = 3
MAX_AGENT_TASKS_GLOBAL = 10
_ACTIVE_AGENT_TASKS_LOCK = threading.Lock()
_ACTIVE_AGENT_TASKS: Dict[str, int] = {}  # { username: count }
_ACTIVE_AGENT_TASKS_TOTAL = 0


def acquire_agent_slot(user: str) -> None:
    """Acquire a concurrency slot for an agent task. Raises 429 if limits exceeded."""
    from fastapi import HTTPException

    global _ACTIVE_AGENT_TASKS_TOTAL
    with _ACTIVE_AGENT_TASKS_LOCK:
        user_count = _ACTIVE_AGENT_TASKS.get(user, 0)
        if user_count >= MAX_AGENT_TASKS_PER_USER:
            raise HTTPException(
                status_code=429,
                detail=f"agent concurrency limit - max {MAX_AGENT_TASKS_PER_USER} active tasks per user",
            )
        if _ACTIVE_AGENT_TASKS_TOTAL >= MAX_AGENT_TASKS_GLOBAL:
            raise HTTPException(
                status_code=429,
                detail=f"agent concurrency limit - max {MAX_AGENT_TASKS_GLOBAL} active tasks globally",
            )
        _ACTIVE_AGENT_TASKS[user] = user_count + 1
        _ACTIVE_AGENT_TASKS_TOTAL += 1


def release_agent_slot(user: str) -> None:
    """Release a concurrency slot when agent task completes."""
    global _ACTIVE_AGENT_TASKS_TOTAL
    with _ACTIVE_AGENT_TASKS_LOCK:
        count = _ACTIVE_AGENT_TASKS.get(user, 1)
        if count <= 1:
            _ACTIVE_AGENT_TASKS.pop(user, None)
        else:
            _ACTIVE_AGENT_TASKS[user] = count - 1
        _ACTIVE_AGENT_TASKS_TOTAL = max(0, _ACTIVE_AGENT_TASKS_TOTAL - 1)


def check_expensive_op_rate(operation: str, user: str) -> None:
    """Raise HTTPException(429) if the operation was invoked too recently by this user."""
    from fastapi import HTTPException

    cooldown = EXPENSIVE_OP_COOLDOWNS.get(operation, 60.0)
    key = f"{operation}:{user}"
    now = time.time()
    with _EXPENSIVE_OPS_LOCK:
        last = _EXPENSIVE_OPS_LAST.get(key, 0.0)
        remaining = cooldown - (now - last)
        if remaining > 0:
            raise HTTPException(
                status_code=429,
                detail=f"rate limited - retry after {int(remaining)}s",
            )
        _EXPENSIVE_OPS_LAST[key] = now


# ---------------------------------------------------------------------------
# Frida State
# ---------------------------------------------------------------------------

_FRIDA_EVENTS_LOCK = threading.RLock()
_FRIDA_EVENTS: Dict[str, List[Dict[str, Any]]] = {}
_FRIDA_HEALTH_CACHE_LOCK = threading.RLock()
_FRIDA_HEALTH_CACHE: Dict[str, Any] = {"ts": 0.0, "payload": None}
_FRIDA_PROCS_CACHE_LOCK = threading.RLock()
_FRIDA_PROCS_CACHE: Dict[str, Dict[str, Any]] = {}
_FRIDA_LOCK = threading.RLock()
_FRIDA_SESSIONS: Dict[str, Dict[str, Any]] = {}
_FRIDA_WS_TOKENS_LOCK = threading.RLock()
_FRIDA_WS_TOKENS: Dict[str, Any] = {}
_WS_RATE_LIMIT: Dict[str, List[float]] = {}
_WS_ALLOWED_ORIGINS: Set[str] = set(
    [
        os.getenv("AODS_UI_ORIGIN", "http://127.0.0.1:5088"),
        os.getenv("AODS_UI_ORIGIN_ALT", "http://127.0.0.1:8088"),
        "http://localhost:5088",
        "http://localhost:8088",
        "http://127.0.0.1:8088",
    ]
)

# ---------------------------------------------------------------------------
# ML State
# ---------------------------------------------------------------------------

_ML_STATUS_LOCK = threading.Lock()
_ML_STATUS: Dict[str, Any] = {"running": False, "lastRun": None}

# ---------------------------------------------------------------------------
# File Cache (TTL-based)
# ---------------------------------------------------------------------------

_FILE_CACHE_TTL = 10.0  # seconds
_file_cache: Dict[str, Tuple[float, Any]] = {}
_file_cache_lock = threading.Lock()


def _get_cached_or_compute(cache_key: str, compute_fn: Callable, ttl: float = _FILE_CACHE_TTL) -> Any:
    """Get cached value or compute and cache it with TTL."""
    now = time.time()
    with _file_cache_lock:
        if cache_key in _file_cache:
            cached_time, cached_value = _file_cache[cache_key]
            if now - cached_time < ttl:
                return cached_value
        value = compute_fn()
        _file_cache[cache_key] = (now, value)
        return value


def _invalidate_file_cache(prefix: str = "") -> None:
    """Invalidate cache entries matching prefix (or all if empty)."""
    with _file_cache_lock:
        if not prefix:
            _file_cache.clear()
        else:
            keys_to_remove = [k for k in _file_cache if k.startswith(prefix)]
            for k in keys_to_remove:
                _file_cache.pop(k, None)


# ---------------------------------------------------------------------------
# PII Patterns
# ---------------------------------------------------------------------------


_PII_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b(?:[0-9a-fA-F]{32,}|[A-Za-z0-9_-]{32,})\b"), "[REDACTED_TOKEN]"),
]

# ---------------------------------------------------------------------------
# Dev Server Controls
# ---------------------------------------------------------------------------

_DEV_LOG_DIR = REPO_ROOT / ".logs" / "dev"
_API_PID_FILES = [
    _DEV_LOG_DIR / "api.pid",
    REPO_ROOT / "artifacts" / "pids" / "api.pid",
]
_UI_PID_FILES = [
    _DEV_LOG_DIR / "ui.pid",
    REPO_ROOT / "artifacts" / "pids" / "ui.pid",
]
_DEVCTL = REPO_ROOT / "scripts" / "devctl.sh"

# ---------------------------------------------------------------------------
# Package Confirmation
# ---------------------------------------------------------------------------

PACKAGE_CONFIDENCE_THRESHOLD = 0.8
PACKAGE_CONFIRMATION_TIMEOUT = 300  # 5 minutes
_CONFIRMATION_CLEANUP_INTERVAL = 60  # seconds
