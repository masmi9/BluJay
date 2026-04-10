#!/usr/bin/env python3
from __future__ import annotations
import json
import os
from pathlib import Path
import threading
from typing import Optional


class ExecutionPathGuard:
    """
    Singleton guard to freeze and validate the orchestrator execution path.

    - First caller freezes the path (env > explicit > default)
    - Subsequent divergent requests are rejected with a single WARN
    - Provides helper to record the path into APKContext metadata
    """

    _instance: Optional[ExecutionPathGuard] = None
    _lock = threading.Lock()

    VALID_PATHS = {"canonical", "enhanced", "legacy", "unified"}

    def __init__(self) -> None:
        self._path: Optional[str] = None
        self._warned_divergence: bool = False
        self._divergence_detected: bool = False

    @classmethod
    def get_guard(cls) -> "ExecutionPathGuard":
        with cls._lock:
            if cls._instance is None:
                cls._instance = ExecutionPathGuard()
            return cls._instance

    def _normalize(self, path: Optional[str]) -> Optional[str]:
        if path is None:
            return None
        p = str(path).strip().lower()
        return p if p in self.VALID_PATHS else None

    def resolve_env_default(self) -> Optional[str]:
        # Map environment toggles to canonical path
        if os.environ.get("AODS_CANONICAL", "0") == "1":
            return "canonical"
        return self._normalize(os.environ.get("AODS_ORCHESTRATION_PATH"))

    def freeze(self, requested: Optional[str]) -> str:
        """
        Freeze the execution path on first call. Returns the active path.
        Precedence: env > requested > default("canonical").
        """
        with self._lock:
            if self._path is None:
                env_path = self.resolve_env_default()
                chosen = env_path or self._normalize(requested) or "canonical"
                self._path = chosen
            return self._path

    def validate(self, requested: Optional[str], logger=None) -> str:
        """
        Validate a subsequent path request. If it differs from frozen path,
        emit a single warning and return the frozen path instead.
        """
        # Freeze on first use honoring the requested value/environment
        req = self._normalize(requested)
        frozen = self.freeze(req)
        if req is not None and req != frozen:
            self._divergence_detected = True
            if not self._warned_divergence:
                if logger is not None:
                    try:
                        logger.warning(
                            "ExecutionPathGuard: mixed-path request '%s' ignored; using frozen '%s'",
                            req,
                            frozen,
                        )
                    except Exception:
                        pass
                self._warned_divergence = True
        return frozen

    def record_in_context(self, apk_ctx) -> None:
        try:
            path = self.freeze(None)
            if hasattr(apk_ctx, "analysis_metadata") and isinstance(apk_ctx.analysis_metadata, dict):
                apk_ctx.analysis_metadata["execution_path"] = path
        except Exception:
            # Non-fatal best-effort metadata enrichment
            pass

    def write_run_manifest(self, apk_ctx=None, output_path: Optional[str] = None) -> Optional[str]:
        """
        Write a run manifest JSON capturing execution_path and divergence flag.
        Honors AODS_RUN_MANIFEST_PATH to override destination.
        Returns the path written, or None if failed.
        """
        try:
            out = output_path or os.environ.get("AODS_RUN_MANIFEST_PATH") or "artifacts/run_manifest.json"
            path = Path(out)
            path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "execution_path": self.freeze(None) or "unknown",
                "divergence_detected": bool(self._divergence_detected),
            }
            # Persist also to environment for CI gates if needed
            try:
                os.environ["AODS_EXECUTION_PATH_ACTIVE"] = data["execution_path"]
                if data["divergence_detected"]:
                    os.environ["AODS_EXECUTION_PATH_DIVERGENCE"] = "1"
            except Exception:
                pass
            # Include analysis_id if present
            try:
                if apk_ctx is not None and hasattr(apk_ctx, "analysis_id"):
                    data["analysis_id"] = getattr(apk_ctx, "analysis_id")
            except Exception:
                pass
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            return str(path)
        except Exception:
            return None
