#!/usr/bin/env python3
"""
Lightweight MSTG Coverage Tracer
--------------------------------
Writes JSONL events to artifacts/compliance/mstg_coverage/events.jsonl.

Usage:
  tracer = get_tracer()
  tracer.start_check("MASVS-NETWORK-1")
  tracer.end_check("MASVS-NETWORK-1", "PASS")
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_TRACER_LOCK = threading.RLock()
_TRACER_INSTANCE: Optional["MSTGTracer"] = None


@dataclass
class _Event:
    control_id: str
    status: str  # PASS/FAIL/INFO
    ts: float
    plugin: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "status": self.status,
            "ts": self.ts,
            "plugin": self.plugin,
        }


"""
MSTG Coverage Tracer

Thread-safe JSONL event emitter for MASVS/MASTG coverage.

Features:
- Env-gated: AODS_MSTG_TRACING=1 enables tracing (default off)
- Queued writer with background flush thread
- Bounded queue with backpressure (drops oldest and counts drops)
- Flush interval configurable via AODS_MSTG_TRACE_FLUSH_MS (default 250)
- Max queue size via AODS_MSTG_TRACE_MAX_Q (default 1000)
- Events path via AODS_MSTG_EVENTS (default artifacts/compliance/mstg_coverage/events.jsonl)
"""

import json  # noqa: F811, E402
import os  # noqa: F811, E402
import threading  # noqa: E402
import time  # noqa: F811, E402
from dataclasses import dataclass  # noqa: E402
from pathlib import Path  # noqa: F811, E402
from queue import Queue, Full, Empty  # noqa: E402
from typing import Any, Dict, Optional  # noqa: F811, E402


def _bool_env(name: str, default: str = "0") -> bool:
    return os.getenv(name, default) == "1"


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


def _events_path() -> Path:
    raw = os.getenv("AODS_MSTG_EVENTS", "artifacts/compliance/mstg_coverage/events.jsonl")
    p = Path(raw)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


@dataclass
class _TraceEvent:
    ts: float
    event: str  # "start" | "end"
    mstg_id: str
    status: Optional[str] = None  # PASS|FAIL|SKIP|MANUAL for end
    meta: Optional[Dict[str, Any]] = None


class MSTGTracer:
    def __init__(self) -> None:
        self.enabled = _bool_env("AODS_MSTG_TRACING", "0")
        self.flush_ms = _int_env("AODS_MSTG_TRACE_FLUSH_MS", 250)
        self.max_q = _int_env("AODS_MSTG_TRACE_MAX_Q", 1000)
        self.events_path = _events_path()

        self._q: Queue[_TraceEvent] = Queue(maxsize=self.max_q)
        self._writer_lock = threading.RLock()
        self._stop = threading.Event()
        self._drops = 0
        self._thread: Optional[threading.Thread] = None
        self._local = threading.local()

        if self.enabled:
            self._start_thread()

    # Public API -----------------------------------------------------------
    def start_check(self, mstg_id: str, meta: Optional[Dict[str, Any]] = None) -> None:
        if not self.enabled:
            return
        setattr(self._local, "current_mstg_id", mstg_id)
        self._enqueue(_TraceEvent(ts=time.time(), event="start", mstg_id=mstg_id, meta=meta))

    def end_check(self, mstg_id: Optional[str], status: str, evidence_path: Optional[str] = None) -> None:
        if not self.enabled:
            return
        final_id = mstg_id or getattr(self._local, "current_mstg_id", None)
        if not final_id:
            return
        meta: Dict[str, Any] = {}
        if evidence_path:
            meta["evidence_path"] = evidence_path
        self._enqueue(_TraceEvent(ts=time.time(), event="end", mstg_id=final_id, status=status, meta=meta))
        # Clear thread-local current id to avoid accidental reuse
        try:
            delattr(self._local, "current_mstg_id")
        except Exception:
            pass

    def get_drop_count(self) -> int:
        return int(self._drops)

    def shutdown(self) -> None:
        if not self.enabled:
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    # Internal -------------------------------------------------------------
    def _start_thread(self) -> None:
        self._thread = threading.Thread(target=self._writer_loop, name="mstg-tracer-writer", daemon=True)
        self._thread.start()

    def _enqueue(self, ev: _TraceEvent) -> None:
        try:
            self._q.put_nowait(ev)
        except Full:
            # Drop oldest then append newest
            try:
                _ = self._q.get_nowait()
            except Empty:
                pass
            self._drops += 1
            try:
                self._q.put_nowait(ev)
            except Full:
                # If still full, drop silently to avoid deadlock
                self._drops += 1

    def _writer_loop(self) -> None:
        # Open file lazily on first write
        f = None
        last_flush = time.time()
        try:
            while not self._stop.is_set():
                try:
                    ev = self._q.get(timeout=self.flush_ms / 1000.0)
                except Empty:
                    ev = None
                if ev is not None:
                    line = json.dumps(
                        {
                            "ts": ev.ts,
                            "event": ev.event,
                            "mstg_id": ev.mstg_id,
                            **({"status": ev.status} if ev.status is not None else {}),
                            **({"meta": ev.meta} if ev.meta else {}),
                        },
                        separators=(",", ":"),
                    )
                    with self._writer_lock:
                        if f is None:
                            self.events_path.parent.mkdir(parents=True, exist_ok=True)
                            f = self.events_path.open("a", encoding="utf-8")
                        f.write(line + "\n")
                now = time.time()
                if f is not None and (now - last_flush) * 1000.0 >= self.flush_ms:
                    try:
                        f.flush()
                    except Exception:
                        pass
                    last_flush = now
        finally:
            if f is not None:
                try:
                    f.flush()
                    f.close()
                except Exception:
                    pass


class MSTGTraceContext:
    def __init__(self, tracer: MSTGTracer, mstg_id: str, meta: Optional[Dict[str, Any]] = None) -> None:
        self.tracer = tracer
        self.mstg_id = mstg_id
        self.meta = meta

    def __enter__(self) -> "MSTGTraceContext":
        self.tracer.start_check(self.mstg_id, self.meta)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        status = "FAIL" if exc_type is not None else "PASS"
        self.tracer.end_check(self.mstg_id, status)


_global_tracer: Optional[MSTGTracer] = None


def get_tracer() -> MSTGTracer:
    global _global_tracer
    if _global_tracer is None:
        _global_tracer = MSTGTracer()
    return _global_tracer
