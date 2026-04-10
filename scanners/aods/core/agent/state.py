"""
core.agent.state - Thread-safe agent task state management.

Maintains an in-memory registry of agent tasks with CRUD operations.
Each task tracks status, observations, token usage, and timing.

Persistence: tasks are also stored in SQLite (best-effort) so they
survive server restarts.  DB path defaults to ``data/agent_tasks.db``
relative to the repo root and can be overridden via the
``AODS_AGENT_TASK_DB`` environment variable.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)


_AGENT_TASKS: Dict[str, Dict[str, Any]] = {}
_LOCK = threading.RLock()
_MAX_IN_MEMORY_TASKS = 5000  # Prevent unbounded memory growth

AgentTaskStatus = Literal["pending", "running", "completed", "failed", "cancelled"]

# ---------------------------------------------------------------------------
# SQLite persistence helpers
# ---------------------------------------------------------------------------

_db_conn: Optional[sqlite3.Connection] = None

_DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "data" / "agent_tasks.db"

_CREATE_TABLE_SQL = """\
CREATE TABLE IF NOT EXISTS agent_tasks (
    id             TEXT PRIMARY KEY,
    agent_type     TEXT NOT NULL,
    scan_id        TEXT,
    user           TEXT,
    params         TEXT,
    status         TEXT NOT NULL DEFAULT 'pending',
    created_at     TEXT,
    started_at     TEXT,
    completed_at   TEXT,
    observations   TEXT,
    result         TEXT,
    error          TEXT,
    token_usage    TEXT,
    iterations     INTEGER DEFAULT 0
)
"""

_INSERT_SQL = """\
INSERT OR REPLACE INTO agent_tasks
    (id, agent_type, scan_id, user, params, status, created_at, started_at,
     completed_at, observations, result, error, token_usage, iterations)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_UPDATE_SQL = """\
UPDATE agent_tasks SET
    agent_type   = ?,
    scan_id      = ?,
    user         = ?,
    params       = ?,
    status       = ?,
    created_at   = ?,
    started_at   = ?,
    completed_at = ?,
    observations = ?,
    result       = ?,
    error        = ?,
    token_usage  = ?,
    iterations   = ?
WHERE id = ?
"""

_LOAD_RECENT_SQL = """\
SELECT id, agent_type, scan_id, user, params, status, created_at, started_at,
       completed_at, observations, result, error, token_usage, iterations
FROM agent_tasks
ORDER BY created_at DESC
LIMIT ?
"""


def _json_dumps(obj: Any) -> Optional[str]:
    """Serialize *obj* to JSON string; return None for None."""
    if obj is None:
        return None
    return json.dumps(obj)


def _json_loads(raw: Optional[str], default: Any = None) -> Any:
    """Deserialize JSON string; return *default* on failure or None input."""
    if raw is None:
        return default
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return default


def _get_db() -> Optional[sqlite3.Connection]:
    """Return (and lazily create) the module-level DB connection."""
    global _db_conn
    if _db_conn is not None:
        return _db_conn
    try:
        db_path_str = os.environ.get("AODS_AGENT_TASK_DB")
        db_path = Path(db_path_str) if db_path_str else _DEFAULT_DB_PATH
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(_CREATE_TABLE_SQL)
        conn.commit()
        _db_conn = conn
        logger.debug("agent_task_db_connected", path=str(db_path))
        return _db_conn
    except Exception as exc:
        logger.warning("agent_task_db_init_failed", error=str(exc))
        return None


def _db_insert(task: Dict[str, Any]) -> None:
    """Best-effort INSERT into SQLite."""
    try:
        conn = _get_db()
        if conn is None:
            return
        conn.execute(
            _INSERT_SQL,
            (
                task["id"],
                task["agent_type"],
                task.get("scan_id"),
                task.get("user"),
                _json_dumps(task.get("params")),
                task["status"],
                task.get("created_at"),
                task.get("started_at"),
                task.get("completed_at"),
                _json_dumps(task.get("observations")),
                _json_dumps(task.get("result")),
                task.get("error"),
                _json_dumps(task.get("token_usage")),
                task.get("iterations", 0),
            ),
        )
        conn.commit()
    except Exception as exc:
        logger.warning("agent_task_db_insert_failed", task_id=task.get("id"), error=str(exc))


def _db_update(task: Dict[str, Any]) -> None:
    """Best-effort UPDATE the SQLite row for *task*."""
    try:
        conn = _get_db()
        if conn is None:
            return
        conn.execute(
            _UPDATE_SQL,
            (
                task["agent_type"],
                task.get("scan_id"),
                task.get("user"),
                _json_dumps(task.get("params")),
                task["status"],
                task.get("created_at"),
                task.get("started_at"),
                task.get("completed_at"),
                _json_dumps(task.get("observations")),
                _json_dumps(task.get("result")),
                task.get("error"),
                _json_dumps(task.get("token_usage")),
                task.get("iterations", 0),
                task["id"],
            ),
        )
        conn.commit()
    except Exception as exc:
        logger.warning("agent_task_db_update_failed", task_id=task.get("id"), error=str(exc))


def _db_load_tasks(limit: int = 1000) -> Dict[str, Dict[str, Any]]:
    """Load recent tasks from SQLite into memory. Returns empty dict on failure."""
    tasks: Dict[str, Dict[str, Any]] = {}
    try:
        conn = _get_db()
        if conn is None:
            return tasks
        cursor = conn.execute(_LOAD_RECENT_SQL, (limit,))
        for row in cursor.fetchall():
            (
                tid, agent_type, scan_id, user, params_raw, status,
                created_at, started_at, completed_at, observations_raw,
                result_raw, error, token_usage_raw, iterations,
            ) = row
            tasks[tid] = {
                "id": tid,
                "agent_type": agent_type,
                "scan_id": scan_id,
                "user": user,
                "params": _json_loads(params_raw, {}),
                "status": status,
                "created_at": created_at,
                "started_at": started_at,
                "completed_at": completed_at,
                "observations": _json_loads(observations_raw, []),
                "result": _json_loads(result_raw),
                "error": error,
                "token_usage": _json_loads(token_usage_raw, {"input_tokens": 0, "output_tokens": 0}),
                "iterations": iterations or 0,
                "_start_time": None,
            }
        logger.debug("agent_task_db_loaded", count=len(tasks))
    except Exception as exc:
        logger.warning("agent_task_db_load_failed", error=str(exc))
    return tasks


# ---------------------------------------------------------------------------
# Module init - load persisted tasks
# ---------------------------------------------------------------------------

def _init_from_db() -> None:
    """Populate ``_AGENT_TASKS`` from SQLite on module import."""
    loaded = _db_load_tasks(limit=1000)
    if loaded:
        with _LOCK:
            _AGENT_TASKS.update(loaded)


_init_from_db()


def _evict_oldest_tasks() -> None:
    """Remove oldest completed tasks when in-memory dict exceeds limit.

    Must be called while holding _LOCK.  Only evicts tasks in terminal
    states (completed, failed, cancelled).  Keeps the most recent tasks
    up to _MAX_IN_MEMORY_TASKS.
    """
    if len(_AGENT_TASKS) <= _MAX_IN_MEMORY_TASKS:
        return
    # Sort by created_at; evict oldest terminal tasks
    _TERMINAL_STATES = {"completed", "failed", "cancelled"}
    terminal = [
        (tid, t.get("created_at", ""))
        for tid, t in _AGENT_TASKS.items()
        if t.get("status") in _TERMINAL_STATES
    ]
    terminal.sort(key=lambda x: x[1])
    evict_count = len(_AGENT_TASKS) - _MAX_IN_MEMORY_TASKS
    evicted = 0
    for tid, _ in terminal:
        if evicted >= evict_count:
            break
        del _AGENT_TASKS[tid]
        evicted += 1
    if evicted:
        logger.debug("agent_tasks_evicted", count=evicted, remaining=len(_AGENT_TASKS))


# ---------------------------------------------------------------------------
# Public API (signatures unchanged)
# ---------------------------------------------------------------------------


def create_agent_task(
    agent_type: str,
    scan_id: Optional[str] = None,
    user: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None,
) -> str:
    """Create a new agent task and return its ID.

    Args:
        agent_type: Type of agent (analyze, narrate, verify, triage).
        scan_id: Optional scan session ID to analyze.
        user: Username who initiated the task.
        params: Additional parameters for the agent.

    Returns:
        The new task ID.
    """
    task_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    task = {
        "id": task_id,
        "agent_type": agent_type,
        "scan_id": scan_id,
        "user": user,
        "params": params or {},
        "status": "pending",
        "created_at": now,
        "started_at": None,
        "completed_at": None,
        "observations": [],
        "result": None,
        "error": None,
        "token_usage": {"input_tokens": 0, "output_tokens": 0},
        "iterations": 0,
        "_start_time": None,
    }
    with _LOCK:
        _AGENT_TASKS[task_id] = task
        _evict_oldest_tasks()
        _db_insert(task)
    return task_id


def update_agent_task(task_id: str, **updates: Any) -> Optional[Dict[str, Any]]:
    """Update fields on an agent task.

    Args:
        task_id: The task ID to update.
        **updates: Fields to update (status, result, error, iterations, token_usage).

    Returns:
        The updated task dict, or None if not found.
    """
    with _LOCK:
        task = _AGENT_TASKS.get(task_id)
        if not task:
            return None

        for key, value in updates.items():
            if key == "token_usage" and isinstance(value, dict):
                for k, v in value.items():
                    task["token_usage"][k] = task["token_usage"].get(k, 0) + v
            elif key in task:
                task[key] = value

        # Auto-set timestamps based on status transitions
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if updates.get("status") == "running" and not task.get("started_at"):
            task["started_at"] = now
            task["_start_time"] = time.monotonic()
        elif updates.get("status") in ("completed", "failed", "cancelled"):
            task["completed_at"] = now

        _db_update(task)
        return _sanitize_task(task)


def get_agent_task(task_id: str) -> Optional[Dict[str, Any]]:
    """Get a single agent task by ID.

    Returns:
        Task dict (sanitized, no internal fields) or None.
    """
    with _LOCK:
        task = _AGENT_TASKS.get(task_id)
        if not task:
            return None
        return _sanitize_task(task)


def list_agent_tasks(
    user: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List agent tasks, optionally filtered.

    Args:
        user: Filter by user who created the task.
        status: Filter by task status.
        limit: Maximum number of tasks to return.

    Returns:
        List of sanitized task dicts, newest first.
    """
    with _LOCK:
        tasks = list(_AGENT_TASKS.values())

    if user:
        tasks = [t for t in tasks if t.get("user") == user]
    if status:
        tasks = [t for t in tasks if t.get("status") == status]

    # Sort by created_at descending
    tasks.sort(key=lambda t: t.get("created_at", ""), reverse=True)
    return [_sanitize_task(t) for t in tasks[:limit]]


def append_observation(task_id: str, observation: Dict[str, Any]) -> bool:
    """Append an observation to a task's observation log.

    Args:
        task_id: The task ID.
        observation: Observation dict with type, content, timestamp, etc.

    Returns:
        True if appended, False if task not found.
    """
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    observation.setdefault("timestamp", now)
    with _LOCK:
        task = _AGENT_TASKS.get(task_id)
        if not task:
            logger.debug("append_observation_task_not_found", task_id=task_id)
            return False
        task["observations"].append(observation)
    _db_update(task)
    return True


def cancel_agent_task(task_id: str) -> bool:
    """Mark a task as cancelled.

    Returns:
        True if cancelled, False if task not found or already terminal.
    """
    with _LOCK:
        task = _AGENT_TASKS.get(task_id)
        if not task:
            return False
        if task["status"] in ("completed", "failed", "cancelled"):
            return False
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        task["status"] = "cancelled"
        task["completed_at"] = now
    _db_update(task)
    return True


def get_task_elapsed(task_id: str) -> Optional[float]:
    """Return elapsed wall-clock seconds for a running task, or None."""
    with _LOCK:
        task = _AGENT_TASKS.get(task_id)
        if not task or not task.get("_start_time"):
            return None
        return time.monotonic() - task["_start_time"]


def _sanitize_task(task: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of the task without internal fields."""
    return {k: v for k, v in task.items() if not k.startswith("_")}
