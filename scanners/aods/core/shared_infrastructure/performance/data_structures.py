#!/usr/bin/env python3
"""
Unified Performance Data Structures for AODS
===========================================

Professional data types and metrics for the unified performance and caching framework.
These structures support the dual excellence principle: maximum analysis speed + maximum resource efficiency.

Consolidates data structures from:
- core/performance_optimization_engine.py (PerformanceMetrics, OptimizationResult)
- core/enhanced_performance_coordinator.py (PerformanceOptimizationResult)
- core/performance_optimizer/data_structures.py (Core framework types)
- Various caching system metrics and configurations

All data structures are designed for:
- High performance with minimal overhead
- Thread-safe operations where needed
- Metrics collection
- Professional logging and monitoring
"""

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime
from enum import Enum
import threading


class OptimizationLevel(Enum):
    """Performance optimization levels."""

    MINIMAL = "minimal"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    ENTERPRISE = "enterprise"


class ParallelMode(Enum):
    """Parallel processing modes."""

    DISABLED = "disabled"
    THREAD_BASED = "thread_based"
    PROCESS_BASED = "process_based"
    HYBRID = "hybrid"
    ADAPTIVE = "adaptive"


class CacheStrategy(Enum):
    """Intelligent caching strategies."""

    LRU = "lru"
    LFU = "lfu"
    FIFO = "fifo"
    ADAPTIVE = "adaptive"


class OptimizationType(Enum):
    """Types of performance optimizations."""

    LIST_TO_SET_CONVERSION = "list_to_set_conversion"
    PATTERN_COMPILATION = "pattern_compilation"
    MEMORY_POOLING = "memory_pooling"
    CACHE_OPTIMIZATION = "cache_optimization"
    PARALLEL_PROCESSING = "parallel_processing"
    RESOURCE_ALLOCATION = "resource_allocation"
    ALGORITHMIC_IMPROVEMENT = "algorithmic_improvement"


@dataclass
class SystemResources:
    """System resource information."""

    cpu_count: int
    memory_total_gb: float
    memory_available_gb: float
    disk_space_gb: float
    network_bandwidth_mbps: float
    gpu_available: bool = False
    gpu_memory_gb: float = 0.0


@dataclass
class ResourceAllocation:
    """Resource allocation configuration."""

    cpu_cores: int
    memory_mb: int
    disk_space_mb: int
    temp_space_mb: int
    optimization_level: OptimizationLevel


# MIGRATED: PerformanceMetrics class removed - now using unified infrastructure
# from core.shared_infrastructure.monitoring.performance_tracker import get_unified_performance_tracker


@dataclass
class PerformanceMetrics:
    """Full performance metrics."""

    # Basic metrics
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0

    # Timing metrics
    total_processing_time_ms: float = 0.0
    average_processing_time_ms: float = 0.0
    min_processing_time_ms: float = float("inf")
    max_processing_time_ms: float = 0.0

    # Performance improvements
    speed_improvement_percent: float = 0.0
    memory_reduction_percent: float = 0.0
    cache_hit_rate_percent: float = 0.0

    # Resource utilization
    cpu_usage_percent: float = 0.0
    memory_usage_mb: float = 0.0
    disk_usage_mb: float = 0.0
    network_usage_mb: float = 0.0

    # Optimization tracking
    optimizations_applied: int = 0
    list_to_set_conversions: int = 0
    pattern_compilations: int = 0
    cache_optimizations: int = 0

    # Quality metrics
    accuracy_preservation_rate: float = 100.0
    vulnerability_detection_rate: float = 100.0
    false_positive_rate: float = 0.0

    # Timestamps
    last_updated: datetime = field(default_factory=datetime.now)
    measurement_start: datetime = field(default_factory=datetime.now)


@dataclass
class MemoryMetrics:
    """Memory usage and optimization metrics."""

    # Current state
    current_usage_mb: float = 0.0
    peak_usage_mb: float = 0.0
    allocated_objects: int = 0

    # Efficiency metrics
    allocation_efficiency: float = 0.0
    deallocation_efficiency: float = 0.0
    fragmentation_percent: float = 0.0

    # Garbage collection
    gc_collections: int = 0
    gc_time_ms: float = 0.0
    gc_objects_collected: int = 0

    # Optimization flags
    cleanup_required: bool = False
    optimization_recommended: bool = False
    pressure_detected: bool = False

    # Thresholds
    warning_threshold_mb: float = 1024.0
    critical_threshold_mb: float = 1536.0


@dataclass
class CacheMetrics:
    """Caching system performance metrics."""

    # Hit/miss statistics
    total_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    hit_rate_percent: float = 0.0

    # Storage metrics
    entries_count: int = 0
    total_size_mb: float = 0.0
    max_size_mb: float = 512.0

    # Performance metrics
    average_retrieval_time_ms: float = 0.0
    average_storage_time_ms: float = 0.0
    evictions_count: int = 0

    # Tier-specific metrics (for multi-tier caching)
    memory_tier_hits: int = 0
    ssd_tier_hits: int = 0
    disk_tier_hits: int = 0
    network_tier_hits: int = 0

    # Optimization metrics
    cache_warming_operations: int = 0
    cache_optimization_cycles: int = 0

    # Quality metrics
    data_integrity_checks: int = 0
    corruption_incidents: int = 0


@dataclass
class OptimizationResult:
    """Result of a performance optimization operation."""

    # Operation identification
    operation_id: str
    optimization_type: OptimizationType
    target_description: str

    # Timing
    start_time: datetime
    end_time: datetime
    duration_ms: float

    # Performance impact
    speed_improvement_factor: float
    memory_reduction_mb: float
    complexity_improvement: str  # e.g., "O(n) -> O(1)"

    # Success metrics
    success: bool
    operations_optimized: int
    data_structures_converted: int

    # Quality preservation
    accuracy_preserved: bool = True
    functionality_preserved: bool = True
    data_integrity_maintained: bool = True

    # Recommendations and warnings
    recommendations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class PerformanceProfile:
    """Performance profile for different workload types."""

    profile_name: str
    target_apk_size_mb: float
    expected_analysis_time_s: float
    memory_requirements_mb: int
    cpu_requirements_cores: int

    # Performance targets
    target_speed_improvement: float
    target_memory_efficiency: float
    target_cache_hit_rate: float

    # Optimization preferences
    preferred_optimization_level: OptimizationLevel
    preferred_parallel_mode: ParallelMode
    preferred_cache_strategy: CacheStrategy

    # Resource constraints
    max_memory_usage_mb: int = 2048
    max_cpu_usage_percent: float = 80.0
    max_disk_usage_gb: float = 10.0


@dataclass
class PerformanceAlert:
    """Performance monitoring alert."""

    alert_id: str
    alert_type: str  # "performance_degradation", "memory_pressure", "cache_miss_spike"
    severity: str  # "low", "medium", "high", "critical"
    message: str
    metric_name: str
    current_value: float
    threshold_value: float
    timestamp: datetime
    resolved: bool = False
    resolution_time: Optional[datetime] = None


class PerformanceMonitor:
    """Thread-safe performance monitoring and alerting."""

    def __init__(self):
        # MIGRATED: PerformanceMetrics instantiation removed - now using unified infrastructure
        self.metrics = {}
        self.alerts: List[PerformanceAlert] = []
        self._lock = threading.RLock()

    def update_metrics(self, **kwargs):
        """Thread-safe metrics update."""
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self.metrics, key):
                    setattr(self.metrics, key, value)
            self.metrics.last_updated = datetime.now()

    def add_alert(self, alert: PerformanceAlert):
        """Add performance alert."""
        with self._lock:
            self.alerts.append(alert)

    def get_active_alerts(self) -> List[PerformanceAlert]:
        """Get active (unresolved) alerts."""
        with self._lock:
            return [alert for alert in self.alerts if not alert.resolved]

    def resolve_alert(self, alert_id: str):
        """Resolve a performance alert."""
        with self._lock:
            for alert in self.alerts:
                if alert.alert_id == alert_id:
                    alert.resolved = True
                    alert.resolution_time = datetime.now()
                    break


@dataclass
class PerformanceBenchmark:
    """Performance benchmark data for comparison."""

    benchmark_name: str
    test_file_path: str
    file_size_mb: float

    # Baseline metrics (before optimization)
    baseline_time_s: float
    baseline_memory_mb: float
    baseline_cpu_percent: float

    # Optimized metrics (after optimization)
    optimized_time_s: float
    optimized_memory_mb: float
    optimized_cpu_percent: float

    # Improvement calculations
    speed_improvement_percent: float = field(init=False)
    memory_improvement_percent: float = field(init=False)
    cpu_improvement_percent: float = field(init=False)

    def __post_init__(self):
        """Calculate improvement percentages."""
        if self.baseline_time_s > 0:
            self.speed_improvement_percent = (
                (self.baseline_time_s - self.optimized_time_s) / self.baseline_time_s
            ) * 100

        if self.baseline_memory_mb > 0:
            self.memory_improvement_percent = (
                (self.baseline_memory_mb - self.optimized_memory_mb) / self.baseline_memory_mb
            ) * 100

        if self.baseline_cpu_percent > 0:
            self.cpu_improvement_percent = (
                (self.baseline_cpu_percent - self.optimized_cpu_percent) / self.baseline_cpu_percent
            ) * 100


# Utility functions for performance data structures


def create_performance_metrics() -> PerformanceMetrics:
    """Create a new performance metrics instance."""
    # MIGRATED: PerformanceMetrics instantiation removed - now using unified infrastructure
    return {}


def create_optimization_result(operation_id: str, optimization_type: OptimizationType) -> OptimizationResult:
    """Create a new optimization result instance."""
    return OptimizationResult(
        operation_id=operation_id,
        optimization_type=optimization_type,
        target_description="",
        start_time=datetime.now(),
        end_time=datetime.now(),
        duration_ms=0.0,
        speed_improvement_factor=0.0,
        memory_reduction_mb=0.0,
        complexity_improvement="",
        success=False,
        operations_optimized=0,
        data_structures_converted=0,
    )


def calculate_performance_score(metrics: PerformanceMetrics) -> float:
    """Calculate overall performance score from metrics."""
    # Weighted performance score calculation
    speed_score = min(100, metrics.speed_improvement_percent * 2)  # Speed weight: 2x
    memory_score = min(100, metrics.memory_reduction_percent * 1.5)  # Memory weight: 1.5x
    cache_score = min(100, metrics.cache_hit_rate_percent)  # Cache weight: 1x
    accuracy_score = metrics.accuracy_preservation_rate  # Accuracy weight: 1x (critical)

    # Overall score (max 100)
    total_score = (speed_score + memory_score + cache_score + accuracy_score) / 4

    # Penalty for poor accuracy (accuracy is paramount)
    if accuracy_score < 95:
        total_score *= 0.5  # Severe penalty for accuracy loss

    return min(100, max(0, total_score))


# Export all public types
__all__ = [
    # Enums
    "OptimizationLevel",
    "ParallelMode",
    "CacheStrategy",
    "OptimizationType",
    # Data classes
    "SystemResources",
    "ResourceAllocation",
    "PerformanceMetrics",
    "MemoryMetrics",
    "CacheMetrics",
    "OptimizationResult",
    "PerformanceProfile",
    "PerformanceAlert",
    "PerformanceBenchmark",
    # Classes
    "PerformanceMonitor",
    # Utility functions
    "create_performance_metrics",
    "create_optimization_result",
    "calculate_performance_score",
]
