"""
core.autoresearch.history - SQLite experiment history.

Stores experiment results in a SQLite database for cross-session tracking.
Follows the best-effort persistence pattern from core.agent.state.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)

from .parameter_space import REPO_ROOT

DEFAULT_DB_PATH = REPO_ROOT / "data" / "autoresearch" / "experiments.db"

_CREATE_TABLE_SQL = """\
CREATE TABLE IF NOT EXISTS experiments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL,
    experiment_num  INTEGER NOT NULL,
    params_json     TEXT,
    aqs             REAL,
    detection_score REAL,
    fp_penalty      REAL,
    stability_bonus REAL,
    accepted        INTEGER DEFAULT 0,
    reason          TEXT,
    per_apk_json    TEXT,
    elapsed_seconds REAL,
    baseline_aqs    REAL,
    created_at      TEXT
)
"""

_INSERT_SQL = """\
INSERT INTO experiments
    (run_id, experiment_num, params_json, aqs, detection_score, fp_penalty,
     stability_bonus, accepted, reason, per_apk_json, elapsed_seconds,
     baseline_aqs, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class ExperimentHistory:
    """SQLite-backed experiment history."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path or DEFAULT_DB_PATH
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self) -> None:
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(_CREATE_TABLE_SQL)
            self._conn.commit()
        except Exception as e:
            logger.warning("experiment_db_init_failed", error=str(e))
            self._conn = None

    def record(
        self,
        run_id: str,
        experiment_num: int,
        params: Dict[str, float],
        aqs: float,
        detection_score: float,
        fp_penalty: float,
        stability_bonus: float,
        accepted: bool,
        reason: str,
        per_apk: List[Dict[str, Any]],
        elapsed_seconds: float,
        baseline_aqs: float = 0.0,
    ) -> None:
        """Record an experiment result. Best-effort - never raises."""
        with self._lock:
            try:
                if self._conn is None:
                    return
                now = datetime.now(timezone.utc).isoformat()
                self._conn.execute(
                    _INSERT_SQL,
                    (
                        run_id,
                        experiment_num,
                        json.dumps(params),
                        aqs,
                        detection_score,
                        fp_penalty,
                        stability_bonus,
                        1 if accepted else 0,
                        reason,
                        json.dumps(per_apk),
                        elapsed_seconds,
                        baseline_aqs,
                        now,
                    ),
                )
                self._conn.commit()
            except Exception as e:
                logger.warning("experiment_record_failed", error=str(e))

    def get_best(self, n: int = 5, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get the top N experiments by AQS."""
        with self._lock:
            try:
                if self._conn is None:
                    return []
                if run_id:
                    cursor = self._conn.execute(
                        "SELECT * FROM experiments WHERE run_id = ? ORDER BY aqs DESC LIMIT ?",
                        (run_id, n),
                    )
                else:
                    cursor = self._conn.execute(
                        "SELECT * FROM experiments ORDER BY aqs DESC LIMIT ?",
                        (n,),
                    )
                return [self._row_to_dict(row) for row in cursor.fetchall()]
            except Exception as e:
                logger.warning("experiment_get_best_failed", error=str(e))
                return []

    def get_recent(self, n: int = 10, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get the most recent N experiments."""
        with self._lock:
            try:
                if self._conn is None:
                    return []
                if run_id:
                    cursor = self._conn.execute(
                        "SELECT * FROM experiments WHERE run_id = ? ORDER BY id DESC LIMIT ?",
                        (run_id, n),
                    )
                else:
                    cursor = self._conn.execute(
                        "SELECT * FROM experiments ORDER BY id DESC LIMIT ?",
                        (n,),
                    )
                return [self._row_to_dict(row) for row in cursor.fetchall()]
            except Exception as e:
                logger.warning("experiment_get_recent_failed", error=str(e))
                return []

    def get_accepted(self, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all accepted experiments for a run."""
        with self._lock:
            try:
                if self._conn is None:
                    return []
                if run_id:
                    cursor = self._conn.execute(
                        "SELECT * FROM experiments WHERE run_id = ? AND accepted = 1 ORDER BY aqs DESC",
                        (run_id,),
                    )
                else:
                    cursor = self._conn.execute(
                        "SELECT * FROM experiments WHERE accepted = 1 ORDER BY aqs DESC",
                    )
                return [self._row_to_dict(row) for row in cursor.fetchall()]
            except Exception as e:
                logger.warning("experiment_get_accepted_failed", error=str(e))
                return []

    def export_json(self, path: Path, run_id: Optional[str] = None) -> None:
        """Export all experiments to a JSON file."""
        with self._lock:
            try:
                if self._conn is None:
                    return
                if run_id:
                    cursor = self._conn.execute(
                        "SELECT * FROM experiments WHERE run_id = ? ORDER BY id",
                        (run_id,),
                    )
                else:
                    cursor = self._conn.execute("SELECT * FROM experiments ORDER BY id")
                rows = [self._row_to_dict(row) for row in cursor.fetchall()]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(rows, indent=2))
            except Exception as e:
                logger.warning("experiment_export_failed", error=str(e))

    @staticmethod
    def _row_to_dict(row: tuple) -> Dict[str, Any]:
        """Convert a SQLite row tuple to a dict."""
        return {
            "id": row[0],
            "run_id": row[1],
            "experiment_num": row[2],
            "params": json.loads(row[3]) if row[3] else {},
            "aqs": row[4],
            "detection_score": row[5],
            "fp_penalty": row[6],
            "stability_bonus": row[7],
            "accepted": bool(row[8]),
            "reason": row[9],
            "per_apk": json.loads(row[10]) if row[10] else [],
            "elapsed_seconds": row[11],
            "baseline_aqs": row[12],
            "created_at": row[13],
        }

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
