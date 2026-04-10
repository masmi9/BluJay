"""
core.agent.cli_progress - CLI progress output for agent pipeline execution.

Streams pipeline observations to stderr so CLI users see real-time
progress instead of silence during long-running agent pipelines.
"""

from __future__ import annotations

import sys
import time
from typing import Any, Dict


class CLIProgressReporter:
    """Streams agent pipeline progress to stderr.

    Used as a progress_callback for run_pipeline() during CLI execution.
    Each significant event (step start, complete, skip, fallback) is
    printed to stderr with elapsed time.

    Args:
        verbose: If False, suppresses all output.
        stream: Output stream (default stderr).
    """

    def __init__(self, verbose: bool = True, stream: Any = None) -> None:
        self.verbose = verbose
        self._stream = stream or sys.stderr
        self._start_time = time.monotonic()

    def report(self, event_type: str, data: Dict[str, Any]) -> None:
        """Report a pipeline event.

        Args:
            event_type: Event type string (matches SSE observation types).
            data: Event data dict with agent_type, content, etc.
        """
        if not self.verbose:
            return

        elapsed = time.monotonic() - self._start_time
        prefix = f"  [{elapsed:6.1f}s]"
        agent = data.get("agent_type", "")

        if event_type == "pipeline_step_start":
            self._write(f"{prefix} {agent}: starting...")

        elif event_type == "pipeline_step_complete":
            status = data.get("step_status", "unknown")
            method = data.get("method", "llm")
            step_time = data.get("elapsed_seconds", 0)
            tokens = sum(data.get("token_usage", {}).values())
            line = f"{prefix} {agent}: {status} ({step_time:.1f}s, {tokens} tokens)"
            if method == "heuristic_fallback":
                line += " [HEURISTIC FALLBACK]"
            self._write(line)

        elif event_type == "pipeline_step_skipped":
            condition = data.get("condition", "disabled")
            self._write(f"{prefix} {agent}: skipped ({condition})")

        elif event_type == "heuristic_fallback":
            self._write(f"{prefix} WARNING: {agent} used heuristic fallback - LLM unavailable")

    def _write(self, line: str) -> None:
        """Write a line to the output stream."""
        try:
            self._stream.write(line + "\n")
            self._stream.flush()
        except Exception:
            pass
