"""IODS API Shared State – in-memory session and job tracking."""
from __future__ import annotations

import os
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
REPORTS_DIR = REPO_ROOT / "reports"

_SESSIONS_LOCK = threading.Lock()
_SESSIONS: dict = {}   # session_id → {status, ipa_path, findings, ...}

_BATCH_LOCK = threading.Lock()
_BATCH_JOBS: dict = {}  # job_id → {status, targets, results, ...}

_TOKENS_LOCK = threading.Lock()
_TOKENS: dict = {}  # token → {user_id, role, expires}
