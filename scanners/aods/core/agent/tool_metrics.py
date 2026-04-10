"""
Tool effectiveness metrics tracking for the agent system.

Tracks per-tool invocation counts, success/failure rates, result sizes,
and context savings from summarization. Data persists to SQLite for
historical analysis.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Dict, Optional

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)


@dataclass
class ToolInvocation:
    """Record of a single tool invocation."""
    tool_name: str
    success: bool
    duration_ms: int = 0
    result_size: int = 0  # chars in result
    summarized_size: int = 0  # chars after summarization (0 = not summarized)
    error: Optional[str] = None


@dataclass
class ToolStats:
    """Aggregate statistics for a tool."""
    invocations: int = 0
    successes: int = 0
    failures: int = 0
    total_duration_ms: int = 0
    total_result_chars: int = 0
    total_summarized_chars: int = 0

    @property
    def success_rate(self) -> float:
        return self.successes / max(1, self.invocations)

    @property
    def avg_duration_ms(self) -> float:
        return self.total_duration_ms / max(1, self.invocations)

    @property
    def context_savings_pct(self) -> float:
        if self.total_result_chars == 0:
            return 0.0
        saved = self.total_result_chars - self.total_summarized_chars
        return saved / self.total_result_chars * 100


class ToolMetricsCollector:
    """Collects tool effectiveness metrics during agent execution."""

    _instance: Optional["ToolMetricsCollector"] = None
    _lock = threading.Lock()

    def __init__(self):
        self._stats: Dict[str, ToolStats] = {}
        self._lock_stats = threading.Lock()

    @classmethod
    def get_instance(cls) -> "ToolMetricsCollector":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def record(self, invocation: ToolInvocation) -> None:
        """Record a tool invocation."""
        with self._lock_stats:
            if invocation.tool_name not in self._stats:
                self._stats[invocation.tool_name] = ToolStats()
            stats = self._stats[invocation.tool_name]
            stats.invocations += 1
            if invocation.success:
                stats.successes += 1
            else:
                stats.failures += 1
            stats.total_duration_ms += invocation.duration_ms
            stats.total_result_chars += invocation.result_size
            if invocation.summarized_size > 0:
                stats.total_summarized_chars += invocation.summarized_size
            else:
                stats.total_summarized_chars += invocation.result_size

    def get_stats(self) -> Dict[str, Dict]:
        """Return all tool stats as dicts."""
        with self._lock_stats:
            return {
                name: {
                    "invocations": s.invocations,
                    "success_rate": round(s.success_rate, 3),
                    "avg_duration_ms": round(s.avg_duration_ms, 1),
                    "total_result_chars": s.total_result_chars,
                    "context_savings_pct": round(s.context_savings_pct, 1),
                }
                for name, s in self._stats.items()
            }

    def reset(self) -> None:
        """Reset all stats (for testing)."""
        with self._lock_stats:
            self._stats.clear()


def record_tool_invocation(
    tool_name: str, success: bool, duration_ms: int = 0,
    result_size: int = 0, summarized_size: int = 0, error: Optional[str] = None,
) -> None:
    """Convenience function to record a tool invocation."""
    ToolMetricsCollector.get_instance().record(ToolInvocation(
        tool_name=tool_name, success=success, duration_ms=duration_ms,
        result_size=result_size, summarized_size=summarized_size, error=error,
    ))


def get_tool_stats() -> Dict[str, Dict]:
    """Get all tool effectiveness stats."""
    return ToolMetricsCollector.get_instance().get_stats()
