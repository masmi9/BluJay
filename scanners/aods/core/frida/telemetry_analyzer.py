#!/usr/bin/env python3
"""
InjectionTelemetryAnalyzer: Analyzes Frida injection events for policy compliance.

Provides:
- Violation rate calculation (disallowed modes, safety guard disabled, etc.)
- Crash/failure rate calculation
- Safety guard compliance statistics
- SSE/WS reliability correlation (if available)

Usage:
    from core.frida.telemetry_analyzer import InjectionTelemetryAnalyzer

    analyzer = InjectionTelemetryAnalyzer()
    result = analyzer.analyze()

    if result.violation_rate > 0.02:
        print(f"Violation rate {result.violation_rate:.2%} exceeds threshold")
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.frida.telemetry import get_events_path


@dataclass
class SafetyViolation:
    """A single safety violation event."""

    timestamp: str
    package: str
    violation_type: str  # disallowed_mode | safety_guard_disabled | injection_failure | crash
    details: str
    severity: str = "warning"  # warning | critical


@dataclass
class TelemetryAnalysisResult:
    """Result of injection telemetry analysis."""

    timestamp: str
    events_analyzed: int
    time_window_hours: float

    # Core metrics
    total_injections: int
    successful_injections: int
    failed_injections: int
    crashes: int

    # Rates (0.0 - 1.0)
    success_rate: float
    failure_rate: float
    crash_rate: float
    violation_rate: float

    # Mode breakdown
    modes_used: Dict[str, int]
    disallowed_modes_used: Dict[str, int]

    # Safety guard
    safety_guard_enabled_count: int
    safety_guard_disabled_count: int
    safety_guard_unknown_count: int

    # Violations
    violations: List[SafetyViolation] = field(default_factory=list)

    # Policy compliance
    policy_compliant: bool = True
    policy_violations_summary: List[str] = field(default_factory=list)

    # SSE/WS correlation (if available)
    sse_ws_correlation: Optional[Dict[str, Any]] = None


class InjectionTelemetryAnalyzer:
    """
    Analyzes Frida injection telemetry events for policy compliance.

    Reads events from the telemetry JSONL file and computes:
    - Violation rates
    - Crash rates
    - Safety guard compliance
    - Mode usage statistics
    """

    DEFAULT_ALLOWED_MODES = {"attach", "spawn", "auto"}

    def __init__(
        self,
        events_path: Optional[Path] = None,
        allowed_modes: Optional[Set[str]] = None,
        max_violation_rate: float = 0.02,
        max_crash_rate: float = 0.01,
        require_safety_guard: bool = True,
        time_window_hours: float = 24.0,
    ):
        self.events_path = events_path or get_events_path()
        self.allowed_modes = allowed_modes or self._load_allowed_modes()
        self.max_violation_rate = max_violation_rate
        self.max_crash_rate = max_crash_rate
        self.require_safety_guard = require_safety_guard
        self.time_window_hours = time_window_hours

    def _load_allowed_modes(self) -> Set[str]:
        """Load allowed modes from config or env."""
        env_modes = os.environ.get("AODS_FRIDA_ALLOWED_MODES")
        if env_modes:
            return {m.strip().lower() for m in env_modes.split(",") if m.strip()}

        try:
            from tools.ci.gates.gates_config import get_frida_policy_config

            cfg = get_frida_policy_config()
            return set(cfg.get("allowed_modes", list(self.DEFAULT_ALLOWED_MODES)))
        except Exception:
            return self.DEFAULT_ALLOWED_MODES.copy()

    def _read_events(self, limit: int = 10000) -> List[Dict[str, Any]]:
        """Read events from the configured events path."""
        from collections import deque

        out: deque[Dict[str, Any]] = deque(maxlen=max(1, limit))
        try:
            with open(self.events_path, "r", encoding="utf-8", errors="ignore") as f:
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

    def analyze(self, limit: int = 10000) -> TelemetryAnalysisResult:
        """
        Analyze recent injection events.

        Args:
            limit: Maximum number of events to analyze

        Returns:
            TelemetryAnalysisResult with computed metrics
        """
        events = self._read_events(limit)

        # Filter to time window
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.time_window_hours)
        filtered_events = []
        for evt in events:
            try:
                ts = evt.get("timestamp", "")
                if ts:
                    evt_time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if evt_time >= cutoff:
                        filtered_events.append(evt)
            except Exception:
                # Include events with unparseable timestamps
                filtered_events.append(evt)

        return self._compute_metrics(filtered_events)

    def _compute_metrics(self, events: List[Dict[str, Any]]) -> TelemetryAnalysisResult:
        """Compute metrics from filtered events."""
        total = len(events)
        successful = 0
        failed = 0
        crashes = 0
        modes_used: Dict[str, int] = {}
        disallowed_modes: Dict[str, int] = {}
        safety_enabled = 0
        safety_disabled = 0
        safety_unknown = 0
        violations: List[SafetyViolation] = []

        for evt in events:
            # Count success/failure
            if evt.get("success"):
                successful += 1
            else:
                failed += 1

            # Check for crashes (high error count or crash flag)
            errors = evt.get("errors_count", 0)
            extra = evt.get("extra", {}) or {}
            is_crash = errors >= 5 or extra.get("crash", False)
            if is_crash:
                crashes += 1
                violations.append(
                    SafetyViolation(
                        timestamp=evt.get("timestamp", ""),
                        package=evt.get("package", "unknown"),
                        violation_type="crash",
                        details=f"Crash detected: {errors} errors",
                        severity="critical",
                    )
                )

            # Track mode usage
            mode = evt.get("mode", "unknown").lower()
            modes_used[mode] = modes_used.get(mode, 0) + 1

            if mode not in self.allowed_modes and mode != "unknown":
                disallowed_modes[mode] = disallowed_modes.get(mode, 0) + 1
                violations.append(
                    SafetyViolation(
                        timestamp=evt.get("timestamp", ""),
                        package=evt.get("package", "unknown"),
                        violation_type="disallowed_mode",
                        details=f"Disallowed injection mode: {mode}",
                        severity="warning",
                    )
                )

            # Track safety guard status (from extra field)
            guard = extra.get("safety_guard")
            if guard == "enabled" or guard is True:
                safety_enabled += 1
            elif guard == "disabled" or guard is False:
                safety_disabled += 1
                if self.require_safety_guard:
                    violations.append(
                        SafetyViolation(
                            timestamp=evt.get("timestamp", ""),
                            package=evt.get("package", "unknown"),
                            violation_type="safety_guard_disabled",
                            details="Safety guard was disabled during injection",
                            severity="critical",
                        )
                    )
            else:
                safety_unknown += 1

        # Compute rates
        success_rate = successful / total if total > 0 else 0.0
        failure_rate = failed / total if total > 0 else 0.0
        crash_rate = crashes / total if total > 0 else 0.0
        violation_count = len([v for v in violations if v.violation_type != "crash"])
        violation_rate = violation_count / total if total > 0 else 0.0

        # Check policy compliance
        policy_violations: List[str] = []
        compliant = True

        if violation_rate > self.max_violation_rate:
            policy_violations.append(f"Violation rate {violation_rate:.2%} exceeds max {self.max_violation_rate:.2%}")
            compliant = False

        if crash_rate > self.max_crash_rate:
            policy_violations.append(f"Crash rate {crash_rate:.2%} exceeds max {self.max_crash_rate:.2%}")
            compliant = False

        if self.require_safety_guard and safety_disabled > 0:
            policy_violations.append(f"Safety guard disabled in {safety_disabled} events")
            compliant = False

        if disallowed_modes:
            policy_violations.append(f"Disallowed modes used: {list(disallowed_modes.keys())}")
            compliant = False

        return TelemetryAnalysisResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            events_analyzed=total,
            time_window_hours=self.time_window_hours,
            total_injections=total,
            successful_injections=successful,
            failed_injections=failed,
            crashes=crashes,
            success_rate=success_rate,
            failure_rate=failure_rate,
            crash_rate=crash_rate,
            violation_rate=violation_rate,
            modes_used=modes_used,
            disallowed_modes_used=disallowed_modes,
            safety_guard_enabled_count=safety_enabled,
            safety_guard_disabled_count=safety_disabled,
            safety_guard_unknown_count=safety_unknown,
            violations=violations,
            policy_compliant=compliant,
            policy_violations_summary=policy_violations,
        )

    def log_violation(self, violation: SafetyViolation) -> None:
        """
        Log a safety violation to the violations log file.

        This creates a separate violations log for audit purposes.
        """
        log_path = Path("artifacts/frida/violations.jsonl")
        log_path.parent.mkdir(parents=True, exist_ok=True)

        entry = {
            "logged_at": datetime.now(timezone.utc).isoformat(),
            **asdict(violation),
        }

        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        except Exception:
            pass  # Never fail on logging

    def get_violations_log_path(self) -> Path:
        """Return the path to the violations log."""
        return Path("artifacts/frida/violations.jsonl")

    def to_dict(self, result: TelemetryAnalysisResult) -> Dict[str, Any]:
        """Convert analysis result to dictionary for JSON serialization."""
        d = asdict(result)
        # Convert violations to dicts
        d["violations"] = [asdict(v) for v in result.violations]
        return d


def analyze_injection_telemetry(
    time_window_hours: float = 24.0,
    max_violation_rate: float = 0.02,
    max_crash_rate: float = 0.01,
) -> TelemetryAnalysisResult:
    """
    Convenience function to analyze injection telemetry.

    Returns analysis result with violation and crash rates.
    """
    analyzer = InjectionTelemetryAnalyzer(
        time_window_hours=time_window_hours,
        max_violation_rate=max_violation_rate,
        max_crash_rate=max_crash_rate,
    )
    return analyzer.analyze()


__all__ = [
    "InjectionTelemetryAnalyzer",
    "TelemetryAnalysisResult",
    "SafetyViolation",
    "analyze_injection_telemetry",
]
