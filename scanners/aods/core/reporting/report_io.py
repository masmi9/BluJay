#!/usr/bin/env python3
"""
Helpers for loading AODS reports that may be plaintext JSON or encrypted (.enc).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

from .encryption_at_rest_manager import EncryptionAtRestManager


def load_report_auto(path: str) -> Dict[str, Any]:
    """Load a report that may be JSON or encrypted (.enc).

    - If file ends with .enc or AODS_ENCRYPTION_PROVIDER != 'noop', attempt decrypt.
    - Else, load as JSON.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))

    provider = os.getenv("AODS_ENCRYPTION_PROVIDER", "noop").strip().lower()

    if p.suffix == ".enc" or provider in {"fernet", "auto"}:
        mgr = EncryptionAtRestManager(provider=provider, key_b64=os.getenv("AODS_ENCRYPTION_KEY_B64"))
        data = mgr.decrypt_bytes(p.read_bytes())
        return json.loads(data.decode("utf-8", errors="replace"))

    # Plaintext JSON
    return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
