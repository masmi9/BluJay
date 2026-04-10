#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Set
import re
from collections import deque
import random

try:  # optional advisory file locking on POSIX
    import fcntl  # type: ignore
except Exception:  # pragma: no cover
    fcntl = None  # type: ignore


DEFAULT_EVENTS_PATH = Path("artifacts/frida/telemetry/events.jsonl")


@dataclass
class InjectionEvent:
    timestamp: str
    package: str
    scenario: str
    mode: str  # attach | spawn | auto | unknown
    success: bool
    errors_count: int
    duration_sec: float
    device: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None


def get_events_path() -> Path:
    env_path = os.environ.get("AODS_FRIDA_TELEMETRY_PATH")
    if env_path:
        return Path(env_path)
    return DEFAULT_EVENTS_PATH


def _telemetry_enabled() -> bool:
    # AODS_FRIDA_TELEMETRY: '1' (default) enables, '0' disables
    val = os.environ.get("AODS_FRIDA_TELEMETRY", "1").strip()
    return val not in {"0", "false", "False", "off", "OFF"}


def _rotate_if_needed(path: Path) -> None:
    try:
        max_mb = float(os.environ.get("AODS_FRIDA_TELEMETRY_MAX_MB", "5"))
        max_bytes = int(max_mb * 1024 * 1024)
    except Exception:
        max_bytes = 5 * 1024 * 1024
    try:
        if path.exists() and path.stat().st_size > max_bytes:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            rotated = path.with_name(f"{path.stem}.{ts}{path.suffix}")
            path.rename(rotated)
            _purge_old(path)
    except Exception:
        # best-effort rotation; never block logging
        pass


def _purge_old(path: Path) -> None:
    """Purge old rotated telemetry files by count and age.

    Controlled via:
      - AODS_FRIDA_TELEMETRY_MAX_ROTATED (default 5)
      - AODS_FRIDA_TELEMETRY_MAX_AGE_DAYS (default 30)
    """
    try:
        max_files = int(os.environ.get("AODS_FRIDA_TELEMETRY_MAX_ROTATED", "5"))
    except Exception:
        max_files = 5
    try:
        max_age_days = float(os.environ.get("AODS_FRIDA_TELEMETRY_MAX_AGE_DAYS", "30"))
    except Exception:
        max_age_days = 30.0
    try:
        parent = path.parent
        stem = path.stem  # e.g., events
        suffix = path.suffix  # .jsonl
        rotated = sorted(
            parent.glob(f"{stem}.*{suffix}"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        # Enforce max rotated files (keep newest first)
        for p in rotated[max_files:]:
            try:
                p.unlink(missing_ok=True)  # type: ignore[arg-type]
            except Exception:
                pass
        # Enforce max age
        now_ts = datetime.now(timezone.utc).timestamp()
        for p in rotated:
            try:
                age_days = (now_ts - p.stat().st_mtime) / 86400.0
                if age_days > max_age_days:
                    p.unlink(missing_ok=True)  # type: ignore[arg-type]
            except Exception:
                continue
    except Exception:
        # never block on purge errors
        pass


def log_injection_event(event: InjectionEvent) -> None:
    if not _telemetry_enabled():
        return
    # Sampling (0.0..1.0), default 1.0
    try:
        rate = float(os.environ.get("AODS_FRIDA_TELEMETRY_SAMPLE_RATE", "1.0"))
    except Exception:
        rate = 1.0
    if rate <= 0.0:
        return
    if rate < 1.0:
        try:
            if random.random() > max(0.0, min(1.0, rate)):
                return
        except Exception:
            pass
    path = get_events_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    _rotate_if_needed(path)
    # Scrub privacy-sensitive fields before logging
    payload = asdict(event)
    payload = _scrub_payload(payload)
    line = json.dumps(payload, separators=(",", ":"))
    try:
        with open(path, "a", encoding="utf-8") as f:
            try:
                if fcntl is not None:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)  # type: ignore[attr-defined]
            except Exception:
                pass
            f.write(line + "\n")
            try:
                if fcntl is not None:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)  # type: ignore[attr-defined]
            except Exception:
                pass
    except Exception:
        # Never let telemetry crash the runtime
        pass


def new_event(
    package: str,
    scenario: str,
    mode: str,
    success: bool,
    errors_count: int,
    duration_sec: float,
    device: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> InjectionEvent:
    return InjectionEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        package=package,
        scenario=scenario,
        mode=mode,
        success=success,
        errors_count=errors_count,
        duration_sec=duration_sec,
        device=device,
        extra=extra,
    )


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_URL_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{0,4}\b")


def _get_allow_keys() -> Set[str]:
    # Allowlist for extra fields; defaults are conservative
    env_file = os.environ.get("AODS_FRIDA_TELEMETRY_ALLOWLIST")
    if env_file and Path(env_file).exists():
        try:
            data = json.loads(Path(env_file).read_text(encoding="utf-8", errors="ignore"))
            if isinstance(data, list):
                return {str(x) for x in data}
        except Exception:
            pass
    env_keys = os.environ.get("AODS_FRIDA_TELEMETRY_ALLOW_KEYS")
    if env_keys:
        return {k.strip() for k in env_keys.split(",") if k.strip()}
    # Defaults preserve non-sensitive analytics
    return {"note", "vulns", "hint", "mode_hint", "planner_seed"}


def _mask_string(value: str) -> str:
    # Mask emails
    if _EMAIL_RE.search(value or ""):
        return _EMAIL_RE.sub("***@redacted", value)
    # Mask URLs
    if _URL_RE.search(value or ""):
        return _URL_RE.sub("https://redacted", value)
    # Mask IP addresses (IPv4/IPv6)
    if _IPV4_RE.search(value or ""):
        value = _IPV4_RE.sub("0.0.0.0", value)
    if _IPV6_RE.search(value or ""):
        value = _IPV6_RE.sub("::", value)
    # Mask likely secrets (long single-token strings with no whitespace)
    if isinstance(value, str) and len(value) >= 24 and not any(ch.isspace() for ch in value):
        return "***"
    return value


def _scrub_extra(extra: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(extra, dict):
        return None
    allowed = _get_allow_keys()
    sanitized: Dict[str, Any] = {}
    for key, val in extra.items():
        if key not in allowed:
            continue
        if isinstance(val, str):
            sanitized[key] = _mask_string(val)
        elif isinstance(val, (int, float, bool)):
            sanitized[key] = val
        else:
            # Drop complex types by default
            continue
    return sanitized if sanitized else None


def _scrub_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    # Only scrub the 'extra' field and obvious string secrets in device/package
    if "extra" in payload:
        payload["extra"] = _scrub_extra(payload.get("extra"))
    for k in ("device", "package"):
        v = payload.get(k)
        if isinstance(v, str):
            payload[k] = _mask_string(v)
    return payload


def read_recent(limit: int = 100) -> list[Dict[str, Any]]:
    """Return the most recent telemetry events (best effort).

    Uses a deque to keep memory bounded, tolerates malformed lines.
    """
    path = get_events_path()
    out: deque[Dict[str, Any]] = deque(maxlen=max(1, limit))
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        out.append(obj)
                except Exception:
                    continue
    except Exception:
        return list(out)
    return list(out)
