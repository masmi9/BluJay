"""
core.ioc_correlator - Cross-APK IoC Correlation Engine.

Maintains a SQLite index of Indicators of Compromise (IoCs) extracted
during malware detection scans.  When a new scan produces IoCs, the
correlator checks whether the same values have appeared in other APKs
and returns correlation data (shared C2 servers, wallet reuse, etc.).

Enable via ``AODS_IOC_CORRELATOR_ENABLED=1``.  Database defaults to
``data/ioc_index.db`` (override with ``AODS_IOC_DB_PATH``).

Thread-safe: all writes are serialized through a threading lock and
the SQLite connection uses ``check_same_thread=False``.
"""

from __future__ import annotations

import os
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


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENABLED = os.environ.get("AODS_IOC_CORRELATOR_ENABLED", "0") == "1"
_DEFAULT_DB_PATH = Path(__file__).parent.parent / "data" / "ioc_index.db"

# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------

_CREATE_TABLE_SQL = """\
CREATE TABLE IF NOT EXISTS iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type    TEXT NOT NULL,
    value       TEXT NOT NULL,
    scan_id     TEXT NOT NULL,
    apk_name    TEXT NOT NULL DEFAULT '',
    finding_id  TEXT NOT NULL DEFAULT '',
    family_name TEXT NOT NULL DEFAULT '',
    category    TEXT NOT NULL DEFAULT '',
    confidence  REAL NOT NULL DEFAULT 0.0,
    severity    TEXT NOT NULL DEFAULT 'medium',
    file_path   TEXT NOT NULL DEFAULT '',
    indexed_at  TEXT NOT NULL
)
"""

_CREATE_UNIQUE_IDX = """\
CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_scan
    ON iocs (value, scan_id, ioc_type)
"""

_CREATE_VALUE_IDX = """\
CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs (value)
"""

_CREATE_TYPE_IDX = """\
CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs (ioc_type)
"""

_CREATE_SCAN_IDX = """\
CREATE INDEX IF NOT EXISTS idx_ioc_scan ON iocs (scan_id)
"""

_INSERT_SQL = """\
INSERT OR IGNORE INTO iocs
    (ioc_type, value, scan_id, apk_name, finding_id, family_name,
     category, confidence, severity, file_path, indexed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------


class IoCCorrelator:
    """Cross-APK IoC correlation engine backed by SQLite."""

    def __init__(self, db_path: Optional[str] = None, enabled: Optional[bool] = None):
        self._enabled = enabled if enabled is not None else _ENABLED
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None

        if self._enabled:
            path_str = db_path or os.environ.get("AODS_IOC_DB_PATH", "")
            db = Path(path_str) if path_str else _DEFAULT_DB_PATH
            db.parent.mkdir(parents=True, exist_ok=True)
            self._db_path = str(db)
            self._init_db()

    @property
    def enabled(self) -> bool:
        return self._enabled

    # ------------------------------------------------------------------
    # DB lifecycle
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Create tables and indices."""
        try:
            self._conn = sqlite3.connect(
                self._db_path, timeout=10.0, check_same_thread=False,
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute(_CREATE_TABLE_SQL)
            self._conn.execute(_CREATE_UNIQUE_IDX)
            self._conn.execute(_CREATE_VALUE_IDX)
            self._conn.execute(_CREATE_TYPE_IDX)
            self._conn.execute(_CREATE_SCAN_IDX)
            self._conn.commit()
            logger.info("IoC correlator initialized", db_path=self._db_path)
        except Exception:
            logger.warning("IoC correlator DB init failed", exc_info=True)
            self._conn = None

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def index_iocs(
        self,
        iocs: List[Dict[str, Any]],
        scan_id: str,
        apk_name: str = "",
        finding_id: str = "",
        family_name: str = "",
        category: str = "",
    ) -> int:
        """Index IoCs from a scan into the correlation database.

        Each IoC dict should have at minimum: ``type``, ``value``.
        Optional keys: ``severity``, ``file``, ``confidence``.

        Returns the number of newly indexed IoCs.
        """
        if not self._enabled or not self._conn or not iocs:
            return 0

        now = datetime.now(timezone.utc).isoformat()
        rows = []
        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            value = ioc.get("value", "").strip()
            if not value:
                continue
            rows.append((
                ioc_type,
                value[:500],
                scan_id,
                apk_name[:200],
                finding_id,
                family_name,
                category,
                float(ioc.get("confidence", 0.0)),
                ioc.get("severity", "medium"),
                ioc.get("file", "")[:500],
                now,
            ))

        if not rows:
            return 0

        inserted = 0
        with self._lock:
            try:
                cursor = self._conn.cursor()
                for row in rows:
                    cursor.execute(_INSERT_SQL, row)
                    inserted += cursor.rowcount
                self._conn.commit()
            except Exception:
                logger.warning("IoC index_iocs failed", exc_info=True)
                try:
                    self._conn.rollback()
                except Exception:
                    pass
        return inserted

    # ------------------------------------------------------------------
    # Correlation queries
    # ------------------------------------------------------------------

    def find_correlations(
        self, ioc_value: str, exclude_scan_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Find all scan entries that share a specific IoC value.

        Returns list of dicts with scan_id, apk_name, ioc_type, family_name,
        category, severity, confidence, file_path, indexed_at.
        """
        if not self._enabled or not self._conn:
            return []

        try:
            if exclude_scan_id:
                rows = self._conn.execute(
                    "SELECT ioc_type, value, scan_id, apk_name, finding_id, "
                    "family_name, category, confidence, severity, file_path, indexed_at "
                    "FROM iocs WHERE value = ? AND scan_id != ? ORDER BY indexed_at DESC",
                    (ioc_value.strip(), exclude_scan_id),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT ioc_type, value, scan_id, apk_name, finding_id, "
                    "family_name, category, confidence, severity, file_path, indexed_at "
                    "FROM iocs WHERE value = ? ORDER BY indexed_at DESC",
                    (ioc_value.strip(),),
                ).fetchall()
            return [self._row_to_dict(r) for r in rows]
        except Exception:
            logger.warning("IoC find_correlations failed", exc_info=True)
            return []

    def find_scan_correlations(
        self, scan_id: str
    ) -> Dict[str, Any]:
        """Find all cross-APK IoC correlations for a given scan.

        Returns a dict with:
        - ``shared_iocs``: list of IoC values found in other scans
        - ``correlated_apks``: set of APK names that share IoCs
        - ``correlations``: detailed per-IoC correlation data
        - ``total_shared``: count of shared IoC values
        """
        if not self._enabled or not self._conn:
            return {"shared_iocs": [], "correlated_apks": [], "correlations": [], "total_shared": 0}

        try:
            # Get all IoC values for this scan
            scan_iocs = self._conn.execute(
                "SELECT DISTINCT value, ioc_type FROM iocs WHERE scan_id = ?",
                (scan_id,),
            ).fetchall()

            if not scan_iocs:
                return {"shared_iocs": [], "correlated_apks": [], "correlations": [], "total_shared": 0}

            shared_iocs = []
            correlated_apks: set = set()
            correlations = []

            for value, ioc_type in scan_iocs:
                # Find the same value in OTHER scans
                others = self._conn.execute(
                    "SELECT DISTINCT scan_id, apk_name, ioc_type, family_name, "
                    "category, confidence, severity, indexed_at "
                    "FROM iocs WHERE value = ? AND scan_id != ? "
                    "ORDER BY indexed_at DESC",
                    (value, scan_id),
                ).fetchall()

                if others:
                    shared_iocs.append(value)
                    other_apks = []
                    for row in others:
                        apk = row[1]
                        if apk:
                            correlated_apks.add(apk)
                        other_apks.append({
                            "scan_id": row[0],
                            "apk_name": row[1],
                            "ioc_type": row[2],
                            "family_name": row[3],
                            "category": row[4],
                            "confidence": row[5],
                            "severity": row[6],
                            "indexed_at": row[7],
                        })
                    correlations.append({
                        "ioc_value": value,
                        "ioc_type": ioc_type,
                        "seen_in_scans": len(others),
                        "other_apks": other_apks[:20],  # Cap per IoC
                    })

            return {
                "shared_iocs": shared_iocs,
                "correlated_apks": sorted(correlated_apks),
                "correlations": correlations,
                "total_shared": len(shared_iocs),
            }
        except Exception:
            logger.warning("IoC find_scan_correlations failed", exc_info=True)
            return {"shared_iocs": [], "correlated_apks": [], "correlations": [], "total_shared": 0}

    def get_ioc_clusters(self, min_apks: int = 2) -> List[Dict[str, Any]]:
        """Find IoC values shared across multiple APKs (cluster detection).

        Returns list of clusters, each with the IoC value, type, and the
        APK names / scan IDs that share it.  Only returns IoCs appearing
        in >= ``min_apks`` distinct APK names.
        """
        if not self._enabled or not self._conn:
            return []

        try:
            # Find IoC values with entries in multiple distinct scans
            rows = self._conn.execute(
                "SELECT value, ioc_type, COUNT(DISTINCT scan_id) as scan_count, "
                "GROUP_CONCAT(DISTINCT apk_name) as apks "
                "FROM iocs "
                "GROUP BY value, ioc_type "
                "HAVING COUNT(DISTINCT scan_id) >= ? "
                "ORDER BY scan_count DESC "
                "LIMIT 200",
                (min_apks,),
            ).fetchall()

            clusters = []
            for value, ioc_type, scan_count, apks_concat in rows:
                apk_list = [a for a in (apks_concat or "").split(",") if a]
                # Also get the scan details
                details = self._conn.execute(
                    "SELECT DISTINCT scan_id, apk_name, family_name, category, "
                    "severity, indexed_at "
                    "FROM iocs WHERE value = ? ORDER BY indexed_at DESC",
                    (value,),
                ).fetchall()

                clusters.append({
                    "ioc_value": value,
                    "ioc_type": ioc_type,
                    "scan_count": scan_count,
                    "apk_names": apk_list,
                    "details": [
                        {
                            "scan_id": d[0],
                            "apk_name": d[1],
                            "family_name": d[2],
                            "category": d[3],
                            "severity": d[4],
                            "indexed_at": d[5],
                        }
                        for d in details[:50]  # Cap
                    ],
                })

            return clusters
        except Exception:
            logger.warning("IoC get_ioc_clusters failed", exc_info=True)
            return []

    # ------------------------------------------------------------------
    # Stats / admin
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Return index statistics."""
        if not self._enabled or not self._conn:
            return {
                "enabled": self._enabled,
                "total_iocs": 0,
                "unique_values": 0,
                "scan_count": 0,
                "type_distribution": {},
            }

        try:
            total = self._conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            unique = self._conn.execute("SELECT COUNT(DISTINCT value) FROM iocs").fetchone()[0]
            scans = self._conn.execute("SELECT COUNT(DISTINCT scan_id) FROM iocs").fetchone()[0]

            type_rows = self._conn.execute(
                "SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type ORDER BY COUNT(*) DESC"
            ).fetchall()
            type_dist = {r[0]: r[1] for r in type_rows}

            return {
                "enabled": True,
                "total_iocs": total,
                "unique_values": unique,
                "scan_count": scans,
                "type_distribution": type_dist,
            }
        except Exception:
            logger.warning("IoC get_stats failed", exc_info=True)
            return {"enabled": self._enabled, "total_iocs": 0, "unique_values": 0,
                    "scan_count": 0, "type_distribution": {}}

    def delete_scan_iocs(self, scan_id: str) -> int:
        """Delete all IoCs for a specific scan. Returns deleted count."""
        if not self._enabled or not self._conn:
            return 0

        with self._lock:
            try:
                cursor = self._conn.execute(
                    "DELETE FROM iocs WHERE scan_id = ?", (scan_id,)
                )
                self._conn.commit()
                return cursor.rowcount
            except Exception:
                logger.warning("IoC delete_scan_iocs failed", exc_info=True)
                return 0

    def clear(self) -> int:
        """Delete all IoCs. Returns deleted count."""
        if not self._enabled or not self._conn:
            return 0

        with self._lock:
            try:
                cursor = self._conn.execute("DELETE FROM iocs")
                self._conn.commit()
                return cursor.rowcount
            except Exception:
                logger.warning("IoC clear failed", exc_info=True)
                return 0

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: tuple) -> Dict[str, Any]:
        """Convert a query row to a dict."""
        return {
            "ioc_type": row[0],
            "value": row[1],
            "scan_id": row[2],
            "apk_name": row[3],
            "finding_id": row[4],
            "family_name": row[5],
            "category": row[6],
            "confidence": row[7],
            "severity": row[8],
            "file_path": row[9],
            "indexed_at": row[10],
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_instance: Optional[IoCCorrelator] = None
_instance_lock = threading.Lock()


def get_ioc_correlator() -> IoCCorrelator:
    """Return the singleton IoCCorrelator instance."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = IoCCorrelator()
    return _instance


def reset_ioc_correlator() -> None:
    """Reset the singleton (for testing)."""
    global _instance
    with _instance_lock:
        if _instance is not None:
            _instance.close()
        _instance = None
