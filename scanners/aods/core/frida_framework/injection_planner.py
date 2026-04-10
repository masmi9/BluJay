#!/usr/bin/env python3
"""
Contextual Bandit Injection Planner for Frida Dynamic Analysis.

Implements epsilon-greedy arm selection for optimal script bundle ordering
with safety constraints and reward-based learning.

Usage:
    from core.frida_framework.injection_planner import (
        ContextualBanditPlanner,
        FridaInjectionContext,
        InjectionAction,
    )

    # Create context from APK analysis
    context = FridaInjectionContext.from_apk_signals(signals)

    # Select an action (injection strategy)
    planner = ContextualBanditPlanner()
    action = planner.select_action(context)

    # Execute and record reward
    planner.update(action, reward=0.8)
"""

from __future__ import annotations

import json
import math
import os
import random
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Try to import APKAnalysisSignals from script_suggester
try:
    from core.frida_framework.script_suggester import APKAnalysisSignals
except ImportError:
    APKAnalysisSignals = None  # type: ignore


@dataclass
class FridaInjectionContext:
    """
    Context for injection decision-making.

    Captures app characteristics, device info, and historical performance.
    """

    # App characteristics
    package_name: str
    target_sdk: int = 30
    min_sdk: int = 21
    abi: str = "arm64-v8a"

    # Framework detection
    has_webview: bool = False
    has_okhttp: bool = False
    has_retrofit: bool = False
    has_flutter: bool = False
    has_react_native: bool = False
    has_native_libs: bool = False

    # Security indicators
    has_ssl_pinning: bool = False
    has_root_detection: bool = False
    has_emulator_detection: bool = False
    has_obfuscation: bool = False

    # Historical context (from telemetry)
    recent_success_rate: float = 1.0
    recent_crash_rate: float = 0.0
    avg_event_yield: float = 10.0
    injection_attempts: int = 0

    # Device context
    device_api_level: int = 30
    is_emulator: bool = False

    @classmethod
    def from_apk_signals(cls, signals: Any) -> "FridaInjectionContext":
        """Create context from APKAnalysisSignals."""
        if signals is None:
            return cls(package_name="unknown")

        package = getattr(signals, "package_name", None) or "unknown"

        # Extract framework indicators
        libraries = getattr(signals, "libraries", {}) or {}
        lib_names = set(str(k).lower() for k in libraries.keys())

        has_webview = any("webview" in c.lower() for c in (getattr(signals, "classes", []) or []))
        has_okhttp = "okhttp" in lib_names or any(
            "okhttp" in c.lower() for c in (getattr(signals, "classes", []) or [])
        )
        has_retrofit = "retrofit" in lib_names
        has_flutter = any("flutter" in str(n).lower() for n in (getattr(signals, "native_libraries", []) or []))
        has_react_native = any("react" in str(n).lower() for n in (getattr(signals, "native_libraries", []) or []))
        has_native = len(getattr(signals, "native_libraries", []) or []) > 0

        # Security indicators
        classes = getattr(signals, "classes", []) or []
        class_lower = [c.lower() for c in classes]
        has_ssl = any("sslpinning" in c or "certpinning" in c or "trustmanager" in c for c in class_lower)
        has_root = any("rootbeer" in c or "rootdetect" in c for c in class_lower)
        has_emu = any("emulator" in c or "antiemu" in c for c in class_lower)

        obf = getattr(signals, "obfuscation_indicators", {}) or {}
        has_obf = bool(obf.get("detected", False))

        return cls(
            package_name=package,
            has_webview=has_webview,
            has_okhttp=has_okhttp,
            has_retrofit=has_retrofit,
            has_flutter=has_flutter,
            has_react_native=has_react_native,
            has_native_libs=has_native,
            has_ssl_pinning=has_ssl,
            has_root_detection=has_root,
            has_emulator_detection=has_emu,
            has_obfuscation=has_obf,
        )

    def to_feature_vector(self) -> List[float]:
        """Convert context to numeric feature vector for ML."""
        return [
            float(self.target_sdk) / 34.0,
            float(self.min_sdk) / 34.0,
            1.0 if self.has_webview else 0.0,
            1.0 if self.has_okhttp else 0.0,
            1.0 if self.has_retrofit else 0.0,
            1.0 if self.has_flutter else 0.0,
            1.0 if self.has_react_native else 0.0,
            1.0 if self.has_native_libs else 0.0,
            1.0 if self.has_ssl_pinning else 0.0,
            1.0 if self.has_root_detection else 0.0,
            1.0 if self.has_emulator_detection else 0.0,
            1.0 if self.has_obfuscation else 0.0,
            self.recent_success_rate,
            self.recent_crash_rate,
            min(1.0, self.avg_event_yield / 20.0),
            1.0 if self.is_emulator else 0.0,
        ]


@dataclass
class InjectionAction:
    """
    An injection action (arm) representing a script bundle strategy.

    Attributes:
        arm_id: Unique identifier for this arm
        scripts: Ordered list of script template IDs
        injection_mode: Frida injection mode (attach/spawn)
        retry_on_failure: Whether to retry on injection failure
        timeout_ms: Injection timeout in milliseconds
        safety_annotations: Safety flags for this action
    """

    arm_id: str
    scripts: List[str]
    injection_mode: str = "attach"
    retry_on_failure: bool = True
    timeout_ms: int = 30000
    safety_annotations: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.arm_id)


@dataclass
class ArmStatistics:
    """Statistics for a bandit arm."""

    arm_id: str
    pulls: int = 0
    total_reward: float = 0.0
    successes: int = 0
    failures: int = 0
    crashes: int = 0

    @property
    def mean_reward(self) -> float:
        """Average reward for this arm."""
        if self.pulls == 0:
            return 0.0
        return self.total_reward / self.pulls

    @property
    def success_rate(self) -> float:
        """Success rate for this arm."""
        total = self.successes + self.failures
        if total == 0:
            return 0.0
        return self.successes / total


# Predefined arms (script bundle orderings)
PREDEFINED_ARMS: List[InjectionAction] = [
    # Arm 0: Conservative baseline (SSL bypass only)
    InjectionAction(
        arm_id="baseline_ssl",
        scripts=["ssl_bypass_comprehensive.js"],
        injection_mode="attach",
        safety_annotations={"conservative": True},
    ),
    # Arm 1: SSL + WebView (common web-heavy apps)
    InjectionAction(
        arm_id="ssl_webview",
        scripts=["ssl_bypass_comprehensive.js", "webview_security_analysis.js"],
        injection_mode="attach",
    ),
    # Arm 2: Full security coverage
    InjectionAction(
        arm_id="full_coverage",
        scripts=[
            "ssl_bypass_comprehensive.js",
            "webview_security_analysis.js",
            "crypto_hooks.js",
            "storage_hooks.js",
        ],
        injection_mode="attach",
    ),
    # Arm 3: Native + SSL (native-heavy apps)
    InjectionAction(
        arm_id="native_ssl",
        scripts=["ssl_bypass_comprehensive.js", "native_hooks.js"],
        injection_mode="spawn",
        safety_annotations={"requires_spawn": True},
    ),
    # Arm 4: Root/emulator bypass first
    InjectionAction(
        arm_id="bypass_first",
        scripts=[
            "universal_emulator_bypass.js",
            "ssl_bypass_comprehensive.js",
            "webview_security_analysis.js",
        ],
        injection_mode="spawn",
    ),
    # Arm 5: Crypto-focused (banking/finance)
    InjectionAction(
        arm_id="crypto_focus",
        scripts=[
            "ssl_bypass_comprehensive.js",
            "crypto_hooks.js",
            "storage_hooks.js",
        ],
        injection_mode="attach",
        safety_annotations={"sensitive_data": True},
    ),
    # Arm 6: Storage-focused (data-heavy apps)
    InjectionAction(
        arm_id="storage_focus",
        scripts=[
            "storage_hooks.js",
            "ssl_bypass_comprehensive.js",
        ],
        injection_mode="attach",
    ),
    # Arm 7: Aggressive full scan
    InjectionAction(
        arm_id="aggressive_full",
        scripts=[
            "universal_emulator_bypass.js",
            "ssl_bypass_comprehensive.js",
            "webview_security_analysis.js",
            "crypto_hooks.js",
            "storage_hooks.js",
        ],
        injection_mode="spawn",
        timeout_ms=60000,
        safety_annotations={"aggressive": True},
    ),
]


class ContextualBanditPlanner:
    """
    Epsilon-greedy contextual bandit for injection planning.

    Selects injection strategies (arms) based on context and historical rewards.
    Uses epsilon-greedy exploration with optional context-based arm preference.
    """

    DEFAULT_ARMS = PREDEFINED_ARMS
    DEFAULT_EPSILON = 0.1
    DEFAULT_STATS_PATH = Path("artifacts/frida/planner_stats.json")

    def __init__(
        self,
        arms: Optional[List[InjectionAction]] = None,
        epsilon: float = DEFAULT_EPSILON,
        stats_path: Optional[Path] = None,
        seed: Optional[int] = None,
    ):
        """
        Initialize the planner.

        Args:
            arms: List of available arms (injection strategies)
            epsilon: Exploration rate (0.0-1.0)
            stats_path: Path to persist arm statistics
            seed: Random seed for reproducibility
        """
        self.arms = arms or self.DEFAULT_ARMS.copy()
        self.epsilon = epsilon
        self.stats_path = stats_path or self.DEFAULT_STATS_PATH

        # Initialize arm statistics
        self.arm_stats: Dict[str, ArmStatistics] = {arm.arm_id: ArmStatistics(arm_id=arm.arm_id) for arm in self.arms}

        # Thread safety
        self._lock = threading.RLock()

        # Random generator with optional seed
        env_seed = os.environ.get("AODS_FRIDA_PLANNER_SEED")
        if seed is not None:
            self._rng = random.Random(seed)
        elif env_seed:
            self._rng = random.Random(int(env_seed))
        else:
            self._rng = random.Random()

        # Load persisted stats
        self._load_stats()

    def select_action(
        self,
        context: FridaInjectionContext,
        force_exploration: bool = False,
    ) -> InjectionAction:
        """
        Select an injection action based on context.

        Uses epsilon-greedy: explore with probability epsilon,
        otherwise exploit best arm for this context.

        Args:
            context: Injection context
            force_exploration: If True, always explore

        Returns:
            Selected injection action
        """
        with self._lock:
            # Filter arms by safety constraints
            eligible_arms = self._filter_eligible_arms(context)
            if not eligible_arms:
                eligible_arms = [self.arms[0]]  # Fallback to first arm

            # Epsilon-greedy selection
            if force_exploration or self._rng.random() < self.epsilon:
                # Explore: random arm
                action = self._rng.choice(eligible_arms)
            else:
                # Exploit: best arm for this context
                action = self._select_best_arm(context, eligible_arms)

            return action

    def _filter_eligible_arms(self, context: FridaInjectionContext) -> List[InjectionAction]:
        """Filter arms based on context and safety constraints."""
        eligible = []
        for arm in self.arms:
            annotations = arm.safety_annotations

            # Skip aggressive arms if recent crash rate is high
            if annotations.get("aggressive") and context.recent_crash_rate > 0.05:
                continue

            # Skip spawn mode if not allowed
            if arm.injection_mode == "spawn":
                allowed_modes = os.environ.get("AODS_FRIDA_ALLOWED_MODES", "attach,spawn,auto")
                if "spawn" not in allowed_modes.lower():
                    continue

            eligible.append(arm)

        return eligible

    def _select_best_arm(
        self,
        context: FridaInjectionContext,
        eligible_arms: List[InjectionAction],
    ) -> InjectionAction:
        """Select best arm using UCB1 with context bonus."""
        total_pulls = sum(self.arm_stats[arm.arm_id].pulls for arm in eligible_arms)

        best_arm = eligible_arms[0]
        best_score = float("-inf")

        for arm in eligible_arms:
            stats = self.arm_stats[arm.arm_id]

            # Base UCB1 score
            if stats.pulls == 0:
                ucb_score = float("inf")  # Prioritize unexplored arms
            else:
                exploitation = stats.mean_reward
                exploration = math.sqrt(2 * math.log(max(1, total_pulls)) / stats.pulls)
                ucb_score = exploitation + exploration

            # Context bonus: prefer arms matching context
            context_bonus = self._compute_context_bonus(arm, context)

            score = ucb_score + context_bonus

            if score > best_score:
                best_score = score
                best_arm = arm

        return best_arm

    def _compute_context_bonus(
        self,
        arm: InjectionAction,
        context: FridaInjectionContext,
    ) -> float:
        """Compute context-dependent bonus for an arm."""
        bonus = 0.0

        # WebView bonus
        if context.has_webview and "webview_security_analysis.js" in arm.scripts:
            bonus += 0.1

        # Native bonus
        if context.has_native_libs and "native_hooks.js" in arm.scripts:
            bonus += 0.1

        # Crypto bonus for finance apps
        if context.has_ssl_pinning and "crypto_hooks.js" in arm.scripts:
            bonus += 0.1

        # Emulator bypass bonus
        if context.is_emulator and "universal_emulator_bypass.js" in arm.scripts:
            bonus += 0.15

        # Root detection bypass bonus
        if context.has_root_detection and "universal_emulator_bypass.js" in arm.scripts:
            bonus += 0.1

        # Flutter/RN penalty for standard hooks (need specialized)
        if context.has_flutter or context.has_react_native:
            if arm.arm_id in ("baseline_ssl", "ssl_webview"):
                bonus -= 0.05

        return bonus

    def update(
        self,
        action: InjectionAction,
        reward: float,
        success: bool = True,
        crashed: bool = False,
    ) -> None:
        """
        Update arm statistics with observed reward.

        Args:
            action: The action that was taken
            reward: Observed reward (typically in [-1, 1])
            success: Whether injection succeeded
            crashed: Whether injection caused a crash
        """
        with self._lock:
            if action.arm_id not in self.arm_stats:
                self.arm_stats[action.arm_id] = ArmStatistics(arm_id=action.arm_id)

            stats = self.arm_stats[action.arm_id]
            stats.pulls += 1
            stats.total_reward += reward

            if success:
                stats.successes += 1
            else:
                stats.failures += 1

            if crashed:
                stats.crashes += 1

            # Persist stats periodically
            if stats.pulls % 10 == 0:
                self._save_stats()

    def compute_reward(
        self,
        event_yield: float,
        injection_success: bool,
        crashes: int = 0,
        sse_ws_stability: float = 1.0,
        baseline_yield: float = 10.0,
    ) -> float:
        """
        Compute reward from injection outcome.

        Reward = event_yield_normalized - error_penalty - perf_penalty

        Args:
            event_yield: Events/hooks discovered per minute
            injection_success: Whether injection succeeded
            crashes: Number of crashes
            sse_ws_stability: SSE/WS stability score (0-1)
            baseline_yield: Baseline event yield for normalization

        Returns:
            Reward in range [-1, 1]
        """
        # Event yield benefit (normalized to 0-1)
        yield_norm = min(1.0, event_yield / baseline_yield)

        # Error penalty
        error_penalty = 0.0
        if not injection_success:
            error_penalty += 1.0
        error_penalty += crashes * 0.1

        # Performance penalty (SSE/WS degradation)
        perf_penalty = 1.0 - sse_ws_stability

        # Combined reward with weights
        reward = (yield_norm * 1.0) - (error_penalty * 5.0) - (perf_penalty * 2.0)

        # Clamp to [-1, 1]
        return max(-1.0, min(1.0, reward))

    def get_statistics(self) -> Dict[str, Any]:
        """Get current arm statistics."""
        with self._lock:
            return {
                arm_id: {
                    "pulls": stats.pulls,
                    "mean_reward": stats.mean_reward,
                    "success_rate": stats.success_rate,
                    "crashes": stats.crashes,
                }
                for arm_id, stats in self.arm_stats.items()
            }

    def _load_stats(self) -> None:
        """Load arm statistics from file."""
        try:
            if self.stats_path.exists():
                data = json.loads(self.stats_path.read_text(encoding="utf-8"))
                for arm_id, stats_dict in data.get("arms", {}).items():
                    if arm_id in self.arm_stats:
                        s = self.arm_stats[arm_id]
                        s.pulls = stats_dict.get("pulls", 0)
                        s.total_reward = stats_dict.get("total_reward", 0.0)
                        s.successes = stats_dict.get("successes", 0)
                        s.failures = stats_dict.get("failures", 0)
                        s.crashes = stats_dict.get("crashes", 0)
        except Exception:
            pass  # Start fresh on load failure

    def _save_stats(self) -> None:
        """Persist arm statistics to file."""
        try:
            self.stats_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "epsilon": self.epsilon,
                "arms": {
                    arm_id: {
                        "pulls": stats.pulls,
                        "total_reward": stats.total_reward,
                        "successes": stats.successes,
                        "failures": stats.failures,
                        "crashes": stats.crashes,
                    }
                    for arm_id, stats in self.arm_stats.items()
                },
            }
            self.stats_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass  # Best effort persistence

    def reset_stats(self) -> None:
        """Reset all arm statistics."""
        with self._lock:
            for arm_id in self.arm_stats:
                self.arm_stats[arm_id] = ArmStatistics(arm_id=arm_id)
            self._save_stats()


def get_default_planner() -> ContextualBanditPlanner:
    """Get or create the default planner instance."""
    return ContextualBanditPlanner()


__all__ = [
    "ContextualBanditPlanner",
    "FridaInjectionContext",
    "InjectionAction",
    "ArmStatistics",
    "PREDEFINED_ARMS",
    "get_default_planner",
]
