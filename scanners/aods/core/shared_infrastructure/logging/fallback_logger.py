#!/usr/bin/env python3
"""
FallbackLogger
==============

Centralized helper for logging component-level fallbacks with:
- Default DEBUG severity to reduce noise
- Optional WARN via env AODS_FALLBACK_WARN=1
- Log-once semantics per unique (component, action, reason)
- Optional structured metadata emission
"""

from __future__ import annotations

import os
import json
import threading
from typing import Any, Dict, Optional


class FallbackLogger:
    _lock = threading.Lock()
    _logged_keys = set()

    @classmethod
    def _should_warn(cls) -> bool:
        try:
            return os.getenv("AODS_FALLBACK_WARN", "0") == "1"
        except Exception:
            return False

    @classmethod
    def log(
        cls,
        component: str,
        action: str,
        reason: str,
        logger: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a fallback event once per unique key.

        Args:
            component: Subsystem or module name
            action: Short action identifier
            reason: Human-friendly reason
            logger: Logger-like object with .debug/.warning
            metadata: Optional structured details to include
        """
        key = (component, action, reason)
        with cls._lock:
            if key in cls._logged_keys:
                return
            cls._logged_keys.add(key)

        payload = {
            "component": component,
            "action": action,
            "reason": reason,
        }
        if isinstance(metadata, dict) and metadata:
            payload.update({"meta": metadata})

        message = f"fallback_event: {json.dumps(payload, separators=(",", ":"))}"

        # Demote to DEBUG by default; allow WARN via env toggle
        if cls._should_warn():
            try:
                logger.warning(message)
            except Exception:
                pass
        else:
            try:
                # Some call sites use output managers; prefer .debug if present
                log_fn = getattr(logger, "debug", None)
                if callable(log_fn):
                    log_fn(message)
                else:
                    # Fallback to .info
                    getattr(logger, "info", lambda *_a, **_k: None)(message)
            except Exception:
                pass
