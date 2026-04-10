#!/usr/bin/env python3
"""
Shadow Mode for ML-Driven Frida Injection Planner.

Shadow mode allows comparing the contextual bandit planner against the
heuristic baseline without impacting production. The heuristic executes
normally while the planner's decisions are logged for offline analysis.

Usage:
    from core.frida.shadow_mode import ShadowModeRunner

    # Create runner
    runner = ShadowModeRunner()

    # Record a shadow comparison
    runner.record_comparison(
        context=injection_context,
        heuristic_action=heuristic_arm,
        planner_action=planner_arm,
        heuristic_outcome=outcome,
    )

    # Export results
    runner.export_report()

Environment Variables:
    AODS_FRIDA_SHADOW_MODE=1         Enable shadow mode
    AODS_FRIDA_SHADOW_SAMPLE_RATE    Sampling rate (0.0-1.0, default 1.0)
    AODS_FRIDA_SHADOW_REPORT_PATH    Custom report path
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class InjectionOutcome:
    """Outcome of an injection attempt."""

    success: bool
    event_yield: float  # Events/hooks per minute
    errors: int
    crashes: int
    duration_sec: float
    sse_ws_stability: float = 1.0


@dataclass
class ShadowComparison:
    """A single shadow mode comparison record."""

    timestamp: str
    run_id: str
    package_name: str

    # Actions selected
    heuristic_action: str
    planner_action: str
    actions_agree: bool

    # Context features (subset for analysis)
    context_features: Dict[str, Any]

    # Heuristic outcome (actual execution)
    heuristic_outcome: Optional[InjectionOutcome] = None

    # Planner prediction (not executed, estimated)
    planner_predicted_yield: float = 0.0
    planner_confidence: float = 0.0

    # Comparison metrics
    would_planner_improve: bool = False
    estimated_improvement: float = 0.0


@dataclass
class ShadowModeReport:
    """Aggregated shadow mode report."""

    timestamp: str
    run_id: str
    total_comparisons: int
    agreement_rate: float
    avg_heuristic_yield: float
    avg_planner_predicted_yield: float
    planner_would_improve_rate: float
    avg_estimated_improvement: float
    comparisons: List[ShadowComparison] = field(default_factory=list)


class ShadowModeRunner:
    """
    Shadow mode runner for comparing planner vs heuristic.

    In shadow mode:
    - Heuristic executes normally (production path unchanged)
    - Planner decision is logged but NOT executed
    - Comparison metrics are collected for offline analysis
    """

    DEFAULT_REPORT_PATH = Path("artifacts/frida/shadow_mode")

    def __init__(
        self,
        report_path: Optional[Path] = None,
        sample_rate: float = 1.0,
    ):
        self.report_path = report_path or self._get_report_path()
        self.sample_rate = sample_rate
        self.run_id = str(uuid.uuid4())[:8]
        self._comparisons: List[ShadowComparison] = []
        self._lock = threading.RLock()

        # Load planner lazily
        self._planner = None

    def _get_report_path(self) -> Path:
        """Get report path from env or default."""
        env_path = os.environ.get("AODS_FRIDA_SHADOW_REPORT_PATH")
        if env_path:
            return Path(env_path)
        return self.DEFAULT_REPORT_PATH

    def _get_planner(self):
        """Lazy-load the contextual bandit planner."""
        if self._planner is None:
            try:
                from core.frida_framework.injection_planner import (
                    ContextualBanditPlanner,
                )

                self._planner = ContextualBanditPlanner()
            except ImportError:
                self._planner = None
        return self._planner

    def is_enabled(self) -> bool:
        """Check if shadow mode is enabled."""
        return os.environ.get("AODS_FRIDA_SHADOW_MODE", "0") == "1"

    def should_sample(self) -> bool:
        """Check if this execution should be sampled."""
        import random

        env_rate = os.environ.get("AODS_FRIDA_SHADOW_SAMPLE_RATE")
        if env_rate:
            try:
                self.sample_rate = float(env_rate)
            except ValueError:
                pass
        return random.random() < self.sample_rate

    def record_comparison(
        self,
        context: Any,
        heuristic_action: str,
        planner_action: str,
        heuristic_outcome: Optional[InjectionOutcome] = None,
        planner_predicted_yield: float = 0.0,
        planner_confidence: float = 0.0,
    ) -> ShadowComparison:
        """
        Record a shadow comparison between heuristic and planner.

        Args:
            context: FridaInjectionContext or dict with context features
            heuristic_action: Action ID selected by heuristic
            planner_action: Action ID that planner would have selected
            heuristic_outcome: Actual outcome from heuristic execution
            planner_predicted_yield: Planner's predicted event yield
            planner_confidence: Planner's confidence in prediction

        Returns:
            The recorded comparison
        """
        # Extract context features
        if hasattr(context, "package_name"):
            package = context.package_name
            features = {
                "target_sdk": getattr(context, "target_sdk", 0),
                "has_webview": getattr(context, "has_webview", False),
                "has_ssl_pinning": getattr(context, "has_ssl_pinning", False),
                "has_native_libs": getattr(context, "has_native_libs", False),
                "is_emulator": getattr(context, "is_emulator", False),
            }
        else:
            package = str(context.get("package", "unknown") if isinstance(context, dict) else "unknown")
            features = context if isinstance(context, dict) else {}

        # Compute comparison metrics
        actions_agree = heuristic_action == planner_action

        would_improve = False
        estimated_improvement = 0.0
        if heuristic_outcome and planner_predicted_yield > 0:
            heuristic_yield = heuristic_outcome.event_yield
            if planner_predicted_yield > heuristic_yield:
                would_improve = True
                estimated_improvement = planner_predicted_yield - heuristic_yield

        comparison = ShadowComparison(
            timestamp=datetime.now(timezone.utc).isoformat(),
            run_id=self.run_id,
            package_name=package,
            heuristic_action=heuristic_action,
            planner_action=planner_action,
            actions_agree=actions_agree,
            context_features=features,
            heuristic_outcome=heuristic_outcome,
            planner_predicted_yield=planner_predicted_yield,
            planner_confidence=planner_confidence,
            would_planner_improve=would_improve,
            estimated_improvement=estimated_improvement,
        )

        with self._lock:
            self._comparisons.append(comparison)

        return comparison

    def get_planner_decision(self, context: Any) -> tuple[str, float]:
        """
        Get what the planner would decide (without executing).

        Args:
            context: FridaInjectionContext

        Returns:
            Tuple of (action_id, confidence)
        """
        planner = self._get_planner()
        if planner is None:
            return ("baseline_ssl", 0.0)

        try:
            action = planner.select_action(context)
            # Estimate confidence from arm statistics
            stats = planner.arm_stats.get(action.arm_id)
            confidence = stats.success_rate if stats and stats.pulls > 0 else 0.5
            return (action.arm_id, confidence)
        except Exception:
            return ("baseline_ssl", 0.0)

    def get_report(self) -> ShadowModeReport:
        """Generate aggregated report from collected comparisons."""
        with self._lock:
            comparisons = list(self._comparisons)

        total = len(comparisons)
        if total == 0:
            return ShadowModeReport(
                timestamp=datetime.now(timezone.utc).isoformat(),
                run_id=self.run_id,
                total_comparisons=0,
                agreement_rate=0.0,
                avg_heuristic_yield=0.0,
                avg_planner_predicted_yield=0.0,
                planner_would_improve_rate=0.0,
                avg_estimated_improvement=0.0,
                comparisons=[],
            )

        # Compute aggregates
        agreements = sum(1 for c in comparisons if c.actions_agree)
        agreement_rate = agreements / total

        heuristic_yields = [c.heuristic_outcome.event_yield for c in comparisons if c.heuristic_outcome is not None]
        avg_heuristic = sum(heuristic_yields) / len(heuristic_yields) if heuristic_yields else 0.0

        planner_yields = [c.planner_predicted_yield for c in comparisons]
        avg_planner = sum(planner_yields) / len(planner_yields) if planner_yields else 0.0

        improvements = [c for c in comparisons if c.would_planner_improve]
        improve_rate = len(improvements) / total

        avg_improvement = (
            sum(c.estimated_improvement for c in improvements) / len(improvements) if improvements else 0.0
        )

        return ShadowModeReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            run_id=self.run_id,
            total_comparisons=total,
            agreement_rate=agreement_rate,
            avg_heuristic_yield=avg_heuristic,
            avg_planner_predicted_yield=avg_planner,
            planner_would_improve_rate=improve_rate,
            avg_estimated_improvement=avg_improvement,
            comparisons=comparisons,
        )

    def export_report(self, path: Optional[Path] = None) -> Path:
        """
        Export shadow mode report to JSON.

        Args:
            path: Custom export path (defaults to artifacts/frida/shadow_mode/)

        Returns:
            Path to exported report
        """
        report = self.get_report()

        out_dir = path or self.report_path
        out_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_file = out_dir / f"shadow_mode_{self.run_id}_{timestamp}.json"

        # Convert to JSON-serializable format
        data = {
            "timestamp": report.timestamp,
            "run_id": report.run_id,
            "total_comparisons": report.total_comparisons,
            "agreement_rate": report.agreement_rate,
            "avg_heuristic_yield": report.avg_heuristic_yield,
            "avg_planner_predicted_yield": report.avg_planner_predicted_yield,
            "planner_would_improve_rate": report.planner_would_improve_rate,
            "avg_estimated_improvement": report.avg_estimated_improvement,
            "comparisons": [
                {
                    "timestamp": c.timestamp,
                    "package_name": c.package_name,
                    "heuristic_action": c.heuristic_action,
                    "planner_action": c.planner_action,
                    "actions_agree": c.actions_agree,
                    "context_features": c.context_features,
                    "heuristic_outcome": asdict(c.heuristic_outcome) if c.heuristic_outcome else None,
                    "planner_predicted_yield": c.planner_predicted_yield,
                    "planner_confidence": c.planner_confidence,
                    "would_planner_improve": c.would_planner_improve,
                    "estimated_improvement": c.estimated_improvement,
                }
                for c in report.comparisons
            ],
        }

        out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        # Also write latest symlink
        latest = out_dir / "latest.json"
        try:
            if latest.exists():
                latest.unlink()
            latest.symlink_to(out_file.name)
        except Exception:
            pass  # Symlink may fail on some systems

        return out_file

    def reset(self) -> None:
        """Reset collected comparisons."""
        with self._lock:
            self._comparisons.clear()
            self.run_id = str(uuid.uuid4())[:8]


# Global runner instance
_global_runner: Optional[ShadowModeRunner] = None


def get_shadow_runner() -> ShadowModeRunner:
    """Get or create the global shadow mode runner."""
    global _global_runner
    if _global_runner is None:
        _global_runner = ShadowModeRunner()
    return _global_runner


def is_shadow_mode_enabled() -> bool:
    """Check if shadow mode is enabled."""
    return os.environ.get("AODS_FRIDA_SHADOW_MODE", "0") == "1"


def record_shadow_comparison(
    context: Any,
    heuristic_action: str,
    heuristic_outcome: Optional[InjectionOutcome] = None,
) -> Optional[ShadowComparison]:
    """
    Convenience function to record a shadow comparison.

    Automatically queries the planner for its decision.

    Args:
        context: FridaInjectionContext
        heuristic_action: Action selected by heuristic
        heuristic_outcome: Outcome from heuristic execution

    Returns:
        ShadowComparison if recorded, None if shadow mode disabled
    """
    if not is_shadow_mode_enabled():
        return None

    runner = get_shadow_runner()
    if not runner.should_sample():
        return None

    # Get planner decision
    planner_action, confidence = runner.get_planner_decision(context)

    # Estimate planner yield from arm statistics
    planner = runner._get_planner()
    predicted_yield = 0.0
    if planner:
        stats = planner.arm_stats.get(planner_action)
        if stats and stats.pulls > 0:
            # Use historical success rate * baseline yield
            predicted_yield = stats.success_rate * 10.0  # Baseline 10 events/min

    return runner.record_comparison(
        context=context,
        heuristic_action=heuristic_action,
        planner_action=planner_action,
        heuristic_outcome=heuristic_outcome,
        planner_predicted_yield=predicted_yield,
        planner_confidence=confidence,
    )


__all__ = [
    "ShadowModeRunner",
    "ShadowComparison",
    "ShadowModeReport",
    "InjectionOutcome",
    "get_shadow_runner",
    "is_shadow_mode_enabled",
    "record_shadow_comparison",
]
