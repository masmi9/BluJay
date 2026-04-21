#!/usr/bin/env python3
"""
Enhanced Plugin Performance Metrics System
==========================================

Advanced performance monitoring and analytics for AODS plugins that goes far beyond
basic success_rate tracking. Provides detailed insights for optimization and debugging.

ENHANCEMENTS OVER EXISTING SYSTEM:
- Detailed timing metrics (execution phases, bottleneck identification)
- Performance trend analysis and historical tracking
- Plugin efficiency scoring and comparative analysis
- Resource utilization tracking (memory, CPU impact)
- Failure pattern analysis and prediction
- Performance-based plugin ranking and recommendations

INTEGRATION:
- Builds upon existing ExecutionMetrics class
- Compatible with current plugin manager architecture
- Provides backward compatibility with existing success_rate tracking
"""

import time
import threading
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Any, Optional, Tuple

try:
    from core.logging_config import get_logger
except ImportError:
    import logging as stdlib_logging

    get_logger = stdlib_logging.getLogger

logger = get_logger(__name__)


class PerformanceCategory(Enum):
    """Plugin performance categories for analysis."""

    EXCELLENT = "excellent"  # Top 10% performers
    GOOD = "good"  # 10-25% performers
    AVERAGE = "average"  # 25-75% performers
    BELOW_AVERAGE = "below_average"  # 75-90% performers
    POOR = "poor"  # Bottom 10% performers


class ExecutionPhase(Enum):
    """Plugin execution phases for detailed timing."""

    INITIALIZATION = "initialization"
    ANALYSIS = "analysis"
    PROCESSING = "processing"
    RESULT_GENERATION = "result_generation"
    CLEANUP = "cleanup"


@dataclass
class DetailedExecutionRecord:
    """Detailed record of a single plugin execution."""

    plugin_name: str
    execution_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    success: bool = False
    total_time_seconds: float = 0.0

    # Phase timing breakdown
    phase_timings: Dict[ExecutionPhase, float] = field(default_factory=dict)

    # Performance characteristics
    memory_peak_mb: float = 0.0
    findings_count: int = 0
    vulnerabilities_found: int = 0
    false_positives_detected: int = 0

    # Quality metrics
    confidence_score: float = 0.0
    accuracy_score: float = 0.0

    # Error details
    error_message: Optional[str] = None
    timeout_occurred: bool = False

    # Context information
    apk_size_mb: float = 0.0
    complexity_category: str = "unknown"

    def calculate_efficiency_score(self) -> float:
        """Calculate plugin efficiency score (0.0-10.0)."""
        if not self.success or self.total_time_seconds <= 0:
            return 0.0

        # Base score from execution time (faster = better)
        time_score = max(0, 5 - (self.total_time_seconds / 10))  # 0-5 points

        # Results quality bonus
        if self.findings_count > 0:
            results_score = min(3, self.vulnerabilities_found * 0.5)  # 0-3 points
        else:
            results_score = 0

        # Accuracy bonus
        accuracy_bonus = self.accuracy_score * 2  # 0-2 points

        return min(10.0, time_score + results_score + accuracy_bonus)


@dataclass
class PluginPerformanceProfile:
    """Full performance profile for a plugin."""

    plugin_name: str

    # Basic execution statistics
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    timeout_executions: int = 0

    # Timing statistics
    total_execution_time: float = 0.0
    average_execution_time: float = 0.0
    median_execution_time: float = 0.0
    min_execution_time: float = float("inf")
    max_execution_time: float = 0.0
    execution_time_std_dev: float = 0.0

    # Performance trends (last 50 executions)
    recent_execution_times: deque = field(default_factory=lambda: deque(maxlen=50))
    recent_success_rate: float = 0.0
    performance_trend: str = "stable"  # improving, stable, degrading

    # Quality metrics
    average_efficiency_score: float = 0.0
    average_confidence_score: float = 0.0
    average_findings_count: float = 0.0

    # Resource utilization
    average_memory_usage_mb: float = 0.0
    peak_memory_usage_mb: float = 0.0

    # Performance category
    performance_category: PerformanceCategory = PerformanceCategory.AVERAGE

    # Bottleneck analysis
    slowest_phase: Optional[ExecutionPhase] = None
    phase_time_breakdown: Dict[ExecutionPhase, float] = field(default_factory=dict)

    # Last update timestamp
    last_updated: datetime = field(default_factory=datetime.now)

    def calculate_success_rate(self) -> float:
        """Calculate success rate percentage."""
        if self.total_executions == 0:
            return 0.0
        return (self.successful_executions / self.total_executions) * 100

    def is_high_performer(self) -> bool:
        """Check if plugin is a high performer."""
        return (
            self.performance_category in [PerformanceCategory.EXCELLENT, PerformanceCategory.GOOD]
            and self.calculate_success_rate() >= 85.0
            and self.average_efficiency_score >= 6.0
        )

    def get_performance_issues(self) -> List[str]:
        """Identify performance issues with the plugin."""
        issues = []

        if self.calculate_success_rate() < 70:
            issues.append(f"Low success rate ({self.calculate_success_rate():.1f}%)")

        if self.timeout_executions > (self.total_executions * 0.1):
            issues.append("Frequent timeouts")

        if self.average_execution_time > 120:  # 2 minutes
            issues.append("Slow execution times")

        if self.performance_trend == "degrading":
            issues.append("Performance degrading over time")

        if self.average_efficiency_score < 4.0:
            issues.append("Low efficiency score")

        return issues


# MIGRATED: EnhancedPluginPerformanceTracker class removed - now using unified infrastructure
# from core.shared_infrastructure.monitoring.performance_tracker import get_unified_performance_tracker


class EnhancedPluginPerformanceTracker:
    """
    Enhanced Plugin Performance Tracking System.

    Provides full performance monitoring beyond basic success_rate tracking:
    - Detailed execution timing and phase analysis
    - Performance trends and historical tracking
    - Plugin efficiency scoring and ranking
    - Bottleneck identification and optimization recommendations
    """

    def __init__(self, max_history_per_plugin: int = 100):
        """Initialize enhanced performance tracker."""
        self.logger = get_logger(__name__)
        self.max_history_per_plugin = max_history_per_plugin

        # Performance data storage
        self.plugin_profiles: Dict[str, PluginPerformanceProfile] = {}
        self.execution_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_history_per_plugin))

        # Real-time tracking
        self.active_executions: Dict[str, DetailedExecutionRecord] = {}
        self.performance_lock = threading.Lock()

        # Analytics cache
        self._performance_rankings: Optional[List[Tuple[str, float]]] = None
        self._last_analysis_time: Optional[datetime] = None
        self._analysis_cache_duration = timedelta(minutes=5)

        self.logger.info("Enhanced Plugin Performance Tracker initialized")

    def start_execution_tracking(self, plugin_name: str, execution_context: Dict[str, Any] = None) -> str:
        """Start tracking a plugin execution."""
        execution_id = f"{plugin_name}_{int(time.time() * 1000000)}"
        context = execution_context or {}

        record = DetailedExecutionRecord(
            plugin_name=plugin_name,
            execution_id=execution_id,
            start_time=datetime.now(),
            apk_size_mb=context.get("apk_size_mb", 0.0),
            complexity_category=context.get("complexity_category", "unknown"),
        )

        with self.performance_lock:
            self.active_executions[execution_id] = record

        return execution_id

    def track_execution_phase(self, execution_id: str, phase: ExecutionPhase, duration_seconds: float):
        """Track timing for a specific execution phase."""
        with self.performance_lock:
            if execution_id in self.active_executions:
                self.active_executions[execution_id].phase_timings[phase] = duration_seconds

    def finish_execution_tracking(
        self, execution_id: str, success: bool, results: Dict[str, Any] = None
    ) -> DetailedExecutionRecord:
        """Finish tracking a plugin execution and update performance profile."""
        results = results or {}

        with self.performance_lock:
            if execution_id not in self.active_executions:
                self.logger.warning(f"Execution ID {execution_id} not found in active tracking")
                return None

            record = self.active_executions[execution_id]
            record.end_time = datetime.now()
            record.success = success
            record.total_time_seconds = (record.end_time - record.start_time).total_seconds()

            # Extract results data
            record.findings_count = results.get("findings_count", 0)
            record.vulnerabilities_found = results.get("vulnerabilities_found", 0)
            record.false_positives_detected = results.get("false_positives_detected", 0)
            record.confidence_score = results.get("confidence_score", 0.0)
            record.accuracy_score = results.get("accuracy_score", 0.0)
            record.error_message = results.get("error_message")
            record.timeout_occurred = results.get("timeout_occurred", False)
            record.memory_peak_mb = results.get("memory_peak_mb", 0.0)

            # Update plugin performance profile
            self._update_plugin_profile(record)

            # Store in execution history
            self.execution_history[record.plugin_name].append(record)

            # Remove from active tracking
            del self.active_executions[execution_id]

            return record

    def _update_plugin_profile(self, record: DetailedExecutionRecord):
        """Update the performance profile for a plugin based on execution record."""
        plugin_name = record.plugin_name

        if plugin_name not in self.plugin_profiles:
            self.plugin_profiles[plugin_name] = PluginPerformanceProfile(plugin_name=plugin_name)

        profile = self.plugin_profiles[plugin_name]

        # Update basic statistics
        profile.total_executions += 1
        if record.success:
            profile.successful_executions += 1
        else:
            profile.failed_executions += 1

        if record.timeout_occurred:
            profile.timeout_executions += 1

        # Update timing statistics
        profile.total_execution_time += record.total_time_seconds
        profile.recent_execution_times.append(record.total_time_seconds)

        # Calculate derived timing metrics
        all_times = list(profile.recent_execution_times)
        if all_times:
            profile.average_execution_time = statistics.mean(all_times)
            profile.median_execution_time = statistics.median(all_times)
            profile.min_execution_time = min(profile.min_execution_time, record.total_time_seconds)
            profile.max_execution_time = max(profile.max_execution_time, record.total_time_seconds)

            if len(all_times) > 1:
                profile.execution_time_std_dev = statistics.stdev(all_times)

        # Update quality metrics
        efficiency_score = record.calculate_efficiency_score()
        profile.average_efficiency_score = self._update_running_average(
            profile.average_efficiency_score, efficiency_score, profile.total_executions
        )

        profile.average_confidence_score = self._update_running_average(
            profile.average_confidence_score, record.confidence_score, profile.total_executions
        )

        profile.average_findings_count = self._update_running_average(
            profile.average_findings_count, record.findings_count, profile.total_executions
        )

        # Update resource utilization
        if record.memory_peak_mb > 0:
            profile.average_memory_usage_mb = self._update_running_average(
                profile.average_memory_usage_mb, record.memory_peak_mb, profile.total_executions
            )
            profile.peak_memory_usage_mb = max(profile.peak_memory_usage_mb, record.memory_peak_mb)

        # Update phase timing breakdown
        for phase, duration in record.phase_timings.items():
            if phase not in profile.phase_time_breakdown:
                profile.phase_time_breakdown[phase] = duration
            else:
                profile.phase_time_breakdown[phase] = self._update_running_average(
                    profile.phase_time_breakdown[phase], duration, profile.total_executions
                )

        # Identify slowest phase
        if profile.phase_time_breakdown:
            profile.slowest_phase = max(
                profile.phase_time_breakdown.keys(), key=lambda x: profile.phase_time_breakdown[x]
            )

        # Calculate recent success rate and performance trend
        recent_executions = list(self.execution_history[plugin_name])[-20:]  # Last 20 executions
        if recent_executions:
            recent_successes = sum(1 for ex in recent_executions if ex.success)
            profile.recent_success_rate = (recent_successes / len(recent_executions)) * 100

            # Analyze performance trend
            if len(recent_executions) >= 10:
                mid_point = len(recent_executions) // 2
                earlier_avg = statistics.mean([ex.total_time_seconds for ex in recent_executions[:mid_point]])
                later_avg = statistics.mean([ex.total_time_seconds for ex in recent_executions[mid_point:]])

                if later_avg < earlier_avg * 0.9:
                    profile.performance_trend = "improving"
                elif later_avg > earlier_avg * 1.1:
                    profile.performance_trend = "degrading"
                else:
                    profile.performance_trend = "stable"

        profile.last_updated = datetime.now()

        # Clear analysis cache
        self._performance_rankings = None

    def _update_running_average(self, current_avg: float, new_value: float, count: int) -> float:
        """Update a running average with a new value."""
        if count <= 1:
            return new_value
        return current_avg + (new_value - current_avg) / count

    def get_plugin_profile(self, plugin_name: str) -> Optional[PluginPerformanceProfile]:
        """Get full performance profile for a plugin."""
        return self.plugin_profiles.get(plugin_name)

    def get_performance_rankings(self, limit: int = None) -> List[Tuple[str, float, PerformanceCategory]]:
        """Get plugins ranked by performance."""
        # Use cached rankings if available and recent
        now = datetime.now()
        if (
            self._performance_rankings
            and self._last_analysis_time
            and now - self._last_analysis_time < self._analysis_cache_duration
        ):
            return self._performance_rankings[:limit] if limit else self._performance_rankings

        # Calculate performance scores for all plugins
        plugin_scores = []
        for plugin_name, profile in self.plugin_profiles.items():
            if profile.total_executions < 3:  # Skip plugins with insufficient data
                continue

            # Calculate full performance score
            success_rate_score = profile.calculate_success_rate() / 10  # 0-10
            efficiency_score = profile.average_efficiency_score  # 0-10
            speed_score = max(0, 10 - (profile.average_execution_time / 12))  # 0-10 (2 minutes = 5 points)

            # Weight the scores
            total_score = success_rate_score * 0.4 + efficiency_score * 0.4 + speed_score * 0.2

            # Categorize performance
            if total_score >= 8.5:
                category = PerformanceCategory.EXCELLENT
            elif total_score >= 7.0:
                category = PerformanceCategory.GOOD
            elif total_score >= 5.0:
                category = PerformanceCategory.AVERAGE
            elif total_score >= 3.0:
                category = PerformanceCategory.BELOW_AVERAGE
            else:
                category = PerformanceCategory.POOR

            # Update profile category
            profile.performance_category = category

            plugin_scores.append((plugin_name, total_score, category))

        # Sort by score (highest first)
        plugin_scores.sort(key=lambda x: x[1], reverse=True)

        # Cache results
        self._performance_rankings = plugin_scores
        self._last_analysis_time = now

        return plugin_scores[:limit] if limit else plugin_scores

    def get_bottleneck_analysis(self) -> Dict[str, Any]:
        """Analyze performance bottlenecks across all plugins."""
        bottlenecks = {
            "slowest_plugins": [],
            "most_timeouts": [],
            "lowest_success_rate": [],
            "common_slow_phases": defaultdict(list),
            "recommendations": [],
        }

        # Analyze each plugin
        for plugin_name, profile in self.plugin_profiles.items():
            if profile.total_executions < 3:
                continue

            # Identify slowest plugins
            if profile.average_execution_time > 60:  # > 1 minute
                bottlenecks["slowest_plugins"].append(
                    {
                        "name": plugin_name,
                        "avg_time": profile.average_execution_time,
                        "slowest_phase": profile.slowest_phase.value if profile.slowest_phase else "unknown",
                    }
                )

            # Identify timeout-prone plugins
            if profile.timeout_executions > 0:
                timeout_rate = (profile.timeout_executions / profile.total_executions) * 100
                bottlenecks["most_timeouts"].append(
                    {"name": plugin_name, "timeout_rate": timeout_rate, "timeout_count": profile.timeout_executions}
                )

            # Identify low success rate plugins
            success_rate = profile.calculate_success_rate()
            if success_rate < 80:
                bottlenecks["lowest_success_rate"].append(
                    {"name": plugin_name, "success_rate": success_rate, "issues": profile.get_performance_issues()}
                )

            # Analyze common slow phases
            if profile.slowest_phase:
                bottlenecks["common_slow_phases"][profile.slowest_phase.value].append(
                    {"plugin": plugin_name, "phase_time": profile.phase_time_breakdown.get(profile.slowest_phase, 0)}
                )

        # Sort results
        bottlenecks["slowest_plugins"].sort(key=lambda x: x["avg_time"], reverse=True)
        bottlenecks["most_timeouts"].sort(key=lambda x: x["timeout_rate"], reverse=True)
        bottlenecks["lowest_success_rate"].sort(key=lambda x: x["success_rate"])

        # Generate recommendations
        if bottlenecks["slowest_plugins"]:
            bottlenecks["recommendations"].append(
                "Consider optimizing the slowest plugins or increasing their timeout values"
            )

        if bottlenecks["most_timeouts"]:
            bottlenecks["recommendations"].append(
                "Plugins with high timeout rates may need performance optimization or timeout adjustment"
            )

        if bottlenecks["common_slow_phases"]:
            slowest_phase = max(
                bottlenecks["common_slow_phases"].keys(), key=lambda x: len(bottlenecks["common_slow_phases"][x])
            )
            bottlenecks["recommendations"].append(
                f"Consider optimizing the {slowest_phase} phase - it's the bottleneck for multiple plugins"
            )

        return bottlenecks

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get full performance summary."""
        total_plugins = len(self.plugin_profiles)
        if total_plugins == 0:
            return {"total_plugins": 0, "message": "No plugin performance data available"}

        # Calculate aggregate statistics
        total_executions = sum(p.total_executions for p in self.plugin_profiles.values())
        total_successful = sum(p.successful_executions for p in self.plugin_profiles.values())
        sum(p.failed_executions for p in self.plugin_profiles.values())
        total_timeouts = sum(p.timeout_executions for p in self.plugin_profiles.values())

        # Calculate performance distribution
        rankings = self.get_performance_rankings()
        category_distribution = defaultdict(int)
        for _, _, category in rankings:
            category_distribution[category.value] += 1

        return {
            "total_plugins_tracked": total_plugins,
            "total_executions": total_executions,
            "overall_success_rate": (total_successful / total_executions * 100) if total_executions > 0 else 0,
            "total_timeouts": total_timeouts,
            "timeout_rate": (total_timeouts / total_executions * 100) if total_executions > 0 else 0,
            "performance_distribution": dict(category_distribution),
            "top_performers": rankings[:5],
            "bottom_performers": rankings[-5:] if len(rankings) > 5 else [],
            "active_executions": len(self.active_executions),
            "last_analysis_time": self._last_analysis_time.isoformat() if self._last_analysis_time else None,
        }


def create_enhanced_performance_tracker(max_history: int = 100) -> EnhancedPluginPerformanceTracker:
    """Factory function to create enhanced performance tracker."""
    # MIGRATED: EnhancedPluginPerformanceTracker instantiation removed - now using unified infrastructure
    from core.shared_infrastructure.monitoring.performance_tracker import get_unified_performance_tracker

    return get_unified_performance_tracker()
