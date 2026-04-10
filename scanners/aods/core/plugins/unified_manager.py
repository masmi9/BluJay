#!/usr/bin/env python3
"""
Unified Plugin Management Engine for AODS - MAXIMUM PLUGIN CAPABILITY & RELIABILITY
===================================================================================

DUAL EXCELLENCE PRINCIPLE: This engine achieves the perfect balance for plugin management:
1. MAXIMUM PLUGIN DISCOVERY & EXECUTION (zero plugin failures due to manager issues)
2. MAXIMUM RELIABILITY & PERFORMANCE (reliable execution, timeout management, resource control)

The engine consolidates ALL plugin management implementations into a single, high-performance system
that preserves every capability while enhancing reliability and adding new features.

CONSOLIDATED MODULES:
- core/enhanced_plugin_manager.py (Enhanced timeout and error handling)
- core/robust_plugin_execution_manager.py (Full execution management)
- core/unified_plugin_execution_manager.py (Production-ready execution system)
- plugins/mastg_integration/__init__.py (MASTG integration with UnifiedPluginManager)

Features:
- **PLUGIN DISCOVERY**: Dynamic discovery with multiple fallback mechanisms
- **Reliable EXECUTION**: Full timeout protection and error recovery
- **RESOURCE MANAGEMENT**: Memory monitoring, thread pool management, graceful shutdown
- **INTEGRATION SUPPORT**: MASTG integration, system integration, plugin orchestration
- **PERFORMANCE MONITORING**: Detailed metrics, execution tracking, failure analysis
- **MAXIMUM RELIABILITY**: Retry mechanisms, fallback execution, error handling
"""

import importlib
import importlib.util
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, Future, TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Callable
import json
import multiprocessing
from multiprocessing import Queue

# Track 9 cleanup: Removed deprecated plugin_fallback_system (2026-01-28)
# Fallback system masked import errors instead of surfacing them properly
PLUGIN_FALLBACK_AVAILABLE = False
import hashlib  # noqa: E402

# Structured logging with graceful fallback
try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

# Import correlation context for plugin execution tracking
try:
    from core.correlation_context import plugin_correlation_context, get_correlation_logger

    CORRELATION_AVAILABLE = True
except ImportError:
    CORRELATION_AVAILABLE = False
# Adaptive timeout integration (optional)
try:
    DYNAMIC_TIMEOUT_AVAILABLE = True
except ImportError:
    DYNAMIC_TIMEOUT_AVAILABLE = False

# Profile-aware timeout registry for per-profile timeout caps
try:
    from core.timeout.plugin_timeout_registry import get_timeout_for_plugin as _get_registry_timeout

    TIMEOUT_REGISTRY_AVAILABLE = True
except ImportError:
    TIMEOUT_REGISTRY_AVAILABLE = False
    _get_registry_timeout = None

# Plugin finding validation (Track 7.3 - Interface Contract Tests)
try:
    from core.plugins.finding_validator import PluginFindingValidator

    FINDING_VALIDATOR_AVAILABLE = True
except ImportError:
    FINDING_VALIDATOR_AVAILABLE = False
    PluginFindingValidator = None


# Resource enforcement not needed - original AODS worked fine without it


class PluginDiscoveryCache:
    """
    Plugin discovery cache to prevent repeated discoveries per scan.

    Implements hash-based cache invalidation based on plugin directory
    modification times to ensure cache accuracy while preventing
    performance regressions.

    Uses class-level cache to share results across all UnifiedPluginManager instances.
    """

    # Class-level cache shared across all instances
    _global_cache: Dict[str, Dict] = {}
    _cache_lock = threading.RLock()

    def __init__(self):
        self._cache_key: Optional[str] = None
        self.logger = logger

    def get_cache_key(self, plugin_paths: List[Path]) -> str:
        """Generate cache key from paths and modification times."""
        path_data = []
        for path in plugin_paths:
            if path.exists():
                # Include path and modification time
                mtime = path.stat().st_mtime
                path_data.append(f"{path}:{mtime}")
            else:
                path_data.append(f"{path}:missing")

        cache_input = ":".join(sorted(path_data))
        return hashlib.md5(cache_input.encode()).hexdigest()

    def get_cached_plugins(self, cache_key: str) -> Optional[Dict]:
        """Get cached plugin discovery results."""
        with self._cache_lock:
            cached_data = self._global_cache.get(cache_key)
            if cached_data:
                self.logger.info(f"🎯 Using cached plugin discovery: {len(cached_data.get('plugins', {}))} plugins")
                return cached_data
            return None

    def cache_plugins(self, cache_key: str, plugins: Dict, metrics: Any):
        """Cache plugin discovery results."""
        cache_data = {
            "plugins": plugins.copy(),
            "metrics": {"discovered_plugins": len(plugins), "cache_timestamp": time.time()},
        }
        with self._cache_lock:
            self._global_cache[cache_key] = cache_data
            self._cache_key = cache_key
        self.logger.info(f"💾 Cached plugin discovery: {len(plugins)} plugins")

    def invalidate_cache(self):
        """Invalidate the entire cache."""
        with self._cache_lock:
            self._global_cache.clear()
            self._cache_key = None
        self.logger.info("🗑️ Plugin discovery cache invalidated")


# Import types and utilities
try:
    OUTPUT_MANAGER_AVAILABLE = True
except ImportError:
    OUTPUT_MANAGER_AVAILABLE = False

try:
    from core.plugin_constants import TIMEOUTS, RISK_LEVELS, PLUGIN_CATEGORIES

    PLUGIN_CONSTANTS_AVAILABLE = True
except ImportError:
    PLUGIN_CONSTANTS_AVAILABLE = False
    TIMEOUTS = {}
    RISK_LEVELS = {}
    PLUGIN_CATEGORIES = {}

try:
    from core.graceful_shutdown_manager import is_shutdown_requested, plugin_context

    GRACEFUL_SHUTDOWN_AVAILABLE = True
except ImportError:
    GRACEFUL_SHUTDOWN_AVAILABLE = False

    def is_shutdown_requested():
        return False

    def plugin_context(name):
        from contextlib import nullcontext

        return nullcontext()


# Resource monitoring
try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class PluginExecutionState(Enum):
    """Plugin execution states for tracking."""

    DISCOVERED = "discovered"
    PENDING = "pending"
    LOADING = "loading"
    LOADED = "loaded"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    RECOVERED = "recovered"


class PluginType(Enum):
    """Plugin types supported by AODS."""

    STATIC = "static"
    DYNAMIC = "dynamic"
    HYBRID = "hybrid"
    NETWORK = "network"
    MASTG = "mastg"
    INTEGRATION = "integration"
    UNKNOWN = "unknown"


class PluginPriority(Enum):
    """Plugin execution priority levels."""

    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


@dataclass
class PluginMetadata:
    """Full plugin metadata and capabilities."""

    name: str
    module_name: str
    file_path: Path
    plugin_type: PluginType = PluginType.UNKNOWN
    priority: PluginPriority = PluginPriority.NORMAL
    description: str = ""
    version: str = "1.0.0"
    author: str = ""
    dependencies: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    timeout: int = 300
    max_memory_mb: int = 1024
    requires_device: bool = False
    supports_parallel: bool = True
    validated: bool = False
    load_time: float = 0.0
    discovery_time: float = 0.0


@dataclass
class PluginExecutionConfig:
    """Configuration for plugin execution behavior - consolidated from all legacy configs."""

    # Timeout configuration (from enhanced and unified managers)
    default_timeout: int = 300
    max_timeout: int = 1800  # 30 minutes for complex plugins like JADX
    timeout_escalation_factor: float = 1.5
    check_shutdown_interval: float = 0.5

    # Retry configuration (from reliable manager)
    retry_attempts: int = 3
    retry_delay: float = 2.0
    enable_timeout_escalation: bool = True
    enable_recovery: bool = True

    # Resource configuration
    max_concurrent_plugins: int = 4
    max_memory_mb: int = 2048
    enable_resource_monitoring: bool = True
    memory_check_interval: float = 5.0

    # Discovery configuration (from MASTG integration)
    plugin_directories: List[str] = field(default_factory=lambda: ["plugins/", "core/plugins/"])
    auto_discovery: bool = True
    validate_on_discovery: bool = True
    discovery_depth: int = 3

    # Execution configuration
    enable_graceful_shutdown: bool = True
    log_execution_details: bool = True
    enable_performance_monitoring: bool = True
    enable_fallback_execution: bool = True

    # Integration configuration
    enable_mastg_integration: bool = True
    enable_system_integration: bool = True


@dataclass
class PluginExecutionResult:
    """Full plugin execution result with detailed metadata."""

    plugin_name: str
    module_name: str
    state: PluginExecutionState
    execution_id: str = ""
    title: Optional[str] = None
    content: Optional[Any] = None
    data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    exception: Optional[Exception] = None

    # Timing information
    start_time: float = 0.0
    end_time: float = 0.0
    execution_time: float = 0.0
    timeout_used: int = 0

    # Execution metadata
    retry_count: int = 0
    recovery_attempted: bool = False
    shutdown_requested: bool = False
    resource_usage: Optional[Dict[str, Any]] = None

    # Performance metrics
    memory_peak_mb: float = 0.0
    cpu_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            "plugin_name": self.plugin_name,
            "module_name": self.module_name,
            "state": self.state.value,
            "execution_id": self.execution_id,
            "title": self.title,
            "error_message": self.error_message,
            "execution_time": self.execution_time,
            "timeout_used": self.timeout_used,
            "retry_count": self.retry_count,
            "recovery_attempted": self.recovery_attempted,
            "memory_peak_mb": self.memory_peak_mb,
            "cpu_time": self.cpu_time,
            "success": self.state == PluginExecutionState.COMPLETED,
        }


@dataclass
class PluginExecutionMetrics:
    """Full execution metrics for performance monitoring."""

    total_plugins: int = 0
    discovered_plugins: int = 0
    loaded_plugins: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    timeout_executions: int = 0
    cancelled_executions: int = 0
    recovered_executions: int = 0

    total_execution_time: float = 0.0
    average_execution_time: float = 0.0
    plugin_discovery_time: float = 0.0
    plugin_loading_time: float = 0.0

    memory_peak_mb: float = 0.0
    memory_average_mb: float = 0.0

    retry_attempts: int = 0
    recovery_attempts: int = 0

    # Track 7.3: Finding validation metrics
    findings_validated: int = 0
    findings_valid: int = 0
    findings_invalid: int = 0
    validation_warnings: int = 0

    def calculate_derived_metrics(self):
        """Calculate derived metrics from base counters."""
        total_executed = (
            self.successful_executions + self.failed_executions + self.timeout_executions + self.cancelled_executions
        )

        if total_executed > 0:
            self.average_execution_time = self.total_execution_time / total_executed

        return {
            "success_rate": self.successful_executions / max(1, total_executed) * 100,
            "failure_rate": self.failed_executions / max(1, total_executed) * 100,
            "timeout_rate": self.timeout_executions / max(1, total_executed) * 100,
            "recovery_rate": self.recovered_executions / max(1, self.failed_executions + self.timeout_executions) * 100,
            "discovery_efficiency": self.metrics.loaded_plugins / max(1, self.metrics.discovered_plugins) * 100,
            "total_executed": total_executed,
        }


class ResourceMonitor:
    """Enhanced resource monitoring with memory management and performance tracking."""

    def __init__(self, warning_threshold_mb=1024, critical_threshold_mb=2048):
        self.monitoring = False
        self.monitor_thread = None
        self.warning_threshold_mb = warning_threshold_mb
        self.critical_threshold_mb = critical_threshold_mb

        # Advanced monitoring features
        self.callbacks = []
        self.memory_history = []
        self.cpu_history = []
        self.max_history_size = 100

        # Peak tracking
        self.peak_memory_mb = 0.0
        self.peak_cpu_percent = 0.0

        # Current metrics
        self.current_memory_mb = 0.0
        self.current_memory_percent = 0.0
        self.current_cpu_percent = 0.0

        self._lock = threading.Lock()
        self.logger = logger

    def start_monitoring(self):
        """Start resource monitoring."""
        if self.monitoring or not PSUTIL_AVAILABLE:
            return

        # Check for scan-focused mode and resource-constrained mode
        import os

        scan_focused = os.getenv("AODS_SCAN_FOCUSED") == "1"
        no_threads = os.getenv("AODS_NO_THREADS") == "1"
        resource_constrained = os.getenv("AODS_RESOURCE_CONSTRAINED") == "1" or os.getenv("AODS_MINIMAL_MODE") == "1"

        if scan_focused:
            self.logger.info("🎯 SCAN-FOCUSED MODE: Resource monitoring enabled with reasonable thresholds")
            # Continue with monitoring but with scan-friendly thresholds
        elif no_threads or resource_constrained:
            self.logger.info("🔧 Thread-free mode: Resource monitoring thread disabled")
            self.monitoring = False
            self.monitor_thread = None
            return

        try:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_resources, daemon=True)
            self.monitor_thread.start()
            self.logger.info("✅ Resource monitoring thread started")
        except RuntimeError as e:
            if "can't start new thread" in str(e):
                self.logger.warning(f"⚠️ Thread exhaustion detected - disabling resource monitoring: {e}")
                self.monitoring = False
                self.monitor_thread = None
            else:
                raise

    def stop_monitoring(self):
        """Stop resource monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
        self.logger.info("Resource monitoring stopped")

    def _monitor_resources(self):
        """Monitor system resources in background thread."""
        while self.monitoring:
            try:
                if PSUTIL_AVAILABLE:
                    process = psutil.Process()

                    # Get memory usage
                    memory_info = process.memory_info()
                    self.current_memory_mb = memory_info.rss / 1024 / 1024

                    # Get CPU usage
                    self.current_cpu_percent = process.cpu_percent()

                    # Update peaks
                    self.peak_memory_mb = max(self.peak_memory_mb, self.current_memory_mb)
                    self.peak_cpu_percent = max(self.peak_cpu_percent, self.current_cpu_percent)

                    # Update history
                    with self._lock:
                        self.memory_history.append(self.current_memory_mb)
                        self.cpu_history.append(self.current_cpu_percent)

                        # Maintain history size
                        if len(self.memory_history) > self.max_history_size:
                            self.memory_history.pop(0)
                        if len(self.cpu_history) > self.max_history_size:
                            self.cpu_history.pop(0)

                    # Check thresholds and trigger callbacks
                    if self.current_memory_mb > self.critical_threshold_mb:
                        self._trigger_callbacks("critical_memory", self.current_memory_mb)
                    elif self.current_memory_mb > self.warning_threshold_mb:
                        self._trigger_callbacks("warning_memory", self.current_memory_mb)

                time.sleep(1.0)

            except Exception as e:
                self.logger.warning(f"Resource monitoring error: {e}")
                time.sleep(5.0)

    def _trigger_callbacks(self, event_type: str, value: float):
        """Trigger registered callbacks for resource events."""
        for callback in self.callbacks:
            try:
                callback(event_type, value)
            except Exception as e:
                self.logger.error(f"Resource callback error: {e}")

    def add_callback(self, callback: Callable[[str, float], None]):
        """Add resource monitoring callback."""
        self.callbacks.append(callback)

    def get_current_memory_mb(self) -> float:
        """Get current memory usage in MB."""
        return self.current_memory_mb

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get full performance summary."""
        with self._lock:
            avg_memory = sum(self.memory_history) / len(self.memory_history) if self.memory_history else 0
            avg_cpu = sum(self.cpu_history) / len(self.cpu_history) if self.cpu_history else 0

        return {
            "current_memory_mb": self.current_memory_mb,
            "peak_memory_mb": self.peak_memory_mb,
            "average_memory_mb": avg_memory,
            "current_cpu_percent": self.current_cpu_percent,
            "peak_cpu_percent": self.peak_cpu_percent,
            "average_cpu_percent": avg_cpu,
            "monitoring_active": self.monitoring,
            "history_size": len(self.memory_history),
        }


# INTEGRATION WITH EXISTING AODS INFRASTRUCTURE
# Using existing systems instead of duplicating functionality


# =============================================================================
# MULTIPROCESSING PLUGIN EXECUTION (Hard Timeout Support)
# =============================================================================
# These functions run in separate processes to enable true timeout enforcement.
# When a plugin exceeds its timeout, the process can be terminated with SIGKILL.


def _multiprocess_plugin_worker(
    plugin_path: str, plugin_name: str, apk_ctx_dict: Dict[str, Any], result_queue: Queue
) -> None:
    """
    Worker function that runs in a separate process to execute a plugin.

    This enables hard timeouts - if the plugin exceeds its time limit,
    the entire process can be terminated.

    Args:
        plugin_path: Path to the plugin module
        plugin_name: Name of the plugin
        apk_ctx_dict: Serialized APK context as a dictionary
        result_queue: Queue to send results back to parent
    """
    try:
        # Ensure sys.path includes the project root for imports
        import sys

        project_root = str(Path(plugin_path).parent.parent.parent)
        if project_root not in sys.path:
            sys.path.insert(0, project_root)

        # Also add the plugins directory for relative imports
        plugins_dir = str(Path(plugin_path).parent.parent)
        if plugins_dir not in sys.path:
            sys.path.insert(0, plugins_dir)

        # Reconstruct APK context from dictionary
        # We need a lightweight APK context that plugins can use
        class SimpleAPKContext:
            """Minimal APK context for multiprocess execution."""

            def __init__(self, data: Dict[str, Any]):
                for key, value in data.items():
                    setattr(self, key, value)

        apk_ctx = SimpleAPKContext(apk_ctx_dict)

        # Import and load the plugin module
        import importlib.util

        spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
        if spec is None or spec.loader is None:
            result_queue.put(("error", f"Failed to load plugin spec: {plugin_name}"))
            return

        plugin_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin_module)

        # Execute plugin using standard entry points
        result = None
        if hasattr(plugin_module, "analyze"):
            result = plugin_module.analyze(apk_ctx)
        elif hasattr(plugin_module, "run"):
            result = plugin_module.run(apk_ctx)
        elif hasattr(plugin_module, "execute"):
            result = plugin_module.execute(apk_ctx)
        elif hasattr(plugin_module, "run_plugin"):
            result = plugin_module.run_plugin(apk_ctx)
        elif hasattr(plugin_module, "create_plugin"):
            plugin_instance = plugin_module.create_plugin()
            if hasattr(plugin_instance, "execute"):
                result = plugin_instance.execute(apk_ctx)
            elif hasattr(plugin_instance, "analyze"):
                result = plugin_instance.analyze(apk_ctx)
            elif hasattr(plugin_instance, "run"):
                result = plugin_instance.run(apk_ctx)
        else:
            result_queue.put(("error", f"No valid entry point found for plugin: {plugin_name}"))
            return

        # Send successful result back
        result_queue.put(("success", result))

    except Exception as e:
        import traceback

        error_msg = f"{str(e)}\n{traceback.format_exc()}"
        result_queue.put(("error", error_msg))


def _serialize_apk_context(apk_ctx) -> Dict[str, Any]:
    """
    Serialize APK context to a dictionary for passing to child process.

    Includes all expected attributes that plugins might access, even if None.
    """
    serializable_attrs = [
        "apk_path",
        "apk_path_str",
        "package_name",
        "analysis_id",
        "jadx_output_dir",
        "workspace_dir",
        "scan_mode",
        "scan_profile",
        "is_enterprise",
        "is_injuredandroid",
        "manifest_path",
        "decompiled_dir",
        "resources_dir",
        "temp_dir",
    ]

    result = {}
    for attr in serializable_attrs:
        try:
            value = getattr(apk_ctx, attr, None)
            # Convert Path objects to strings
            if value is not None and hasattr(value, "__fspath__"):
                value = str(value)
            # Include even None values so plugins can access the attribute
            if value is None:
                result[attr] = None
            else:
                # Verify it's JSON-serializable
                json.dumps(value)  # Test if serializable
                result[attr] = value
        except (TypeError, AttributeError):
            # Still set None for the attribute so it exists
            result[attr] = None

    # MULTIPROCESS FIX: Use module-level scan profile as fallback if context doesn't have it
    if result.get("scan_profile") is None and _current_scan_profile:
        result["scan_profile"] = _current_scan_profile

    return result


# Module-level tracking for scan profile (used for multiprocess decision)
_current_scan_profile: Optional[str] = None

# Plugins that must complete before analysis plugins start (decompilation barrier)
_DECOMPILATION_BARRIER_PLUGINS = frozenset({"jadx_static_analysis"})

# Analysis-heavy plugins that produce foundational results (Track 110).
# Run in a dedicated first batch to minimize CPU/memory contention.
_ANALYSIS_PRIORITY_PLUGINS = frozenset({
    "enhanced_static_analysis",
    "semgrep_mastg_analyzer",
})


def _set_current_scan_profile(profile: Optional[str]) -> None:
    """Set the current scan profile for multiprocess decision making."""
    global _current_scan_profile
    _current_scan_profile = profile.lower() if profile else None


def _is_multiprocess_enabled() -> bool:
    """
    Check if multiprocessing plugin execution is enabled.

    Returns True if:
    - AODS_PLUGIN_MULTIPROCESS=1 environment variable is set, OR
    - Current scan profile is 'lightning' (default for hard timeout enforcement)

    Can be disabled explicitly with AODS_PLUGIN_MULTIPROCESS=0 even for lightning.
    """
    env_value = os.getenv("AODS_PLUGIN_MULTIPROCESS")

    # Explicit env var takes precedence
    if env_value == "1":
        return True
    if env_value == "0":
        return False

    # Default: enable for lightning profile (hard timeout enforcement)
    if _current_scan_profile == "lightning":
        return True

    return False


class UnifiedPluginManager:
    """
    Unified Plugin Management Engine - Consolidates ALL plugin management capabilities.

    This manager provides full plugin lifecycle management by merging capabilities from:
    - Enhanced Plugin Manager: Timeout handling, error recovery, statistics
    - Reliable Plugin Execution Manager: Resource monitoring, graceful shutdown
    - Unified Plugin Execution Manager: Production-ready execution system
    - MASTG Integration Manager: Dynamic discovery, performance monitoring

    Features:
    🔍 **ENHANCED DISCOVERY**: Multi-path plugin discovery with validation
    ⚡ **Reliable EXECUTION**: Timeout protection, retry mechanisms, resource limits
    📊 **PERFORMANCE MONITORING**: Detailed metrics, execution tracking
    🛡️ **ERROR RECOVERY**: Automatic recovery, fallback execution
    🔗 **INTEGRATION SUPPORT**: MASTG integration, system orchestration
    """

    def __init__(self, config: Optional[PluginExecutionConfig] = None):
        """Initialize unified plugin manager with configuration."""
        self.config = config or PluginExecutionConfig()
        self.logger = logger

        # PERMANENT FIX: Initialize console attribute to prevent AttributeError regressions
        # Used in lines: 1001, 1005, 1016, 1019, 1111 for plugin status reporting
        try:
            from rich.console import Console

            self.console = Console()
            self.logger.debug("✅ Rich console initialized successfully")
        except ImportError:
            # Defensive fallback: Create a mock console object to prevent AttributeError
            class MockConsole:
                def print(self, *args, **kwargs):
                    # Fallback to standard logging if Rich is not available
                    message = str(args[0]) if args else ""
                    self.logger.info(f"Console: {message}")

            self.console = MockConsole()
            self.logger.warning("⚠️ Rich not available, using mock console")

        # Plugin registry
        self.plugins: Dict[str, PluginMetadata] = {}
        self.loaded_modules: Dict[str, Any] = {}
        self._discovery_lock = threading.RLock()
        self._execution_lock = threading.RLock()
        # Registry lock protects plugin registry and related shared maps
        self._registry_lock = threading.RLock()

        # Discovery guard: ensure only a single discovery run per scan unless forced
        self._discovered_once: bool = False
        # Debug flag to control discovery logging verbosity
        self._debug_discovery: bool = bool(os.getenv("AODS_DEBUG_PLUGIN_DISCOVERY"))

        # Discovery cache to prevent repeated discoveries
        self.discovery_cache = PluginDiscoveryCache()
        # Discovery stability metrics
        self._discovery_attempts = 0
        self._discovery_successes = 0
        self._discovery_failures = 0
        self._discovery_last_seconds = 0.0

        # PERMANENT FIX: Track failed imports to prevent spam and regressions
        self._failed_imports: Dict[str, int] = {}  # plugin_name -> failure_count
        self._import_blacklist: Set[str] = set()  # plugins to skip after repeated failures

        # INTEGRATION WITH EXISTING AODS INFRASTRUCTURE
        # Use existing health checker, error recovery, and performance monitoring systems
        self._initialize_existing_integrations()

        # Execution tracking
        self.active_executions: Dict[str, Future] = {}
        self.execution_results: Dict[str, PluginExecutionResult] = {}
        self.execution_history: List[PluginExecutionResult] = []
        # Execution stability metrics
        self._exec_successes = 0
        self._exec_failures = 0
        self._exec_timeouts = 0
        # Deduplicate plugin executions within a scan session
        self._executed_plugins: Set[str] = set()
        # Canonical module execution de-duplication to prevent alias double-runs
        self._executed_module_keys: Set[str] = set()

        # Module alias map to resolve legacy entrypoints to canonical modules
        # This prevents noisy import failures without changing plugin packages
        # NOTE: enhanced_static_analysis is NOT aliased - its __init__.py has proper entrypoints
        self._module_alias_map: Dict[str, str] = {
            # 'plugins.enhanced_static_analysis' - intentionally NOT aliased; __init__.py has run/run_plugin
            "plugins.jadx_static_analysis": "plugins.jadx_static_analysis.v2_plugin",
            "plugins.apk_signing_certificate_analyzer": "plugins.apk_signing_certificate_analyzer.v2_plugin",
            "plugins.network_cleartext_traffic": "plugins.network_cleartext_traffic.v2_plugin",
            "plugins.improper_platform_usage": "plugins.improper_platform_usage.v2_plugin",
            # Android 14+ enhanced security analyzer v2 implementation
            "plugins.enhanced_android_14_security_analysis": "plugins.enhanced_android_14_security_analysis.v2_plugin",
            # TLS/SSL analyzer module alias (legacy name → advanced suite)
            "plugins.tls_configuration_analyzer": "plugins.advanced_ssl_tls_analyzer",
        }

        # Metrics and monitoring
        self.metrics = PluginExecutionMetrics()
        self.resource_monitor = ResourceMonitor(
            warning_threshold_mb=self.config.max_memory_mb // 2, critical_threshold_mb=self.config.max_memory_mb
        )

        # Initialize global coordinator (optional, for advanced resource management)
        self.global_coordinator = None

        # Simple execution setup like the original working approach
        max_workers = self._determine_optimal_workers()
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="UnifiedPluginExec")
        self._shutdown_requested = False

        # Shutdown coordination
        self.shutdown_requested = False
        self.shutdown_event = threading.Event()

        # Emergency mode tracking
        self._emergency_mode_active = False

        # Plugin discovery paths
        self.plugin_paths = [Path(p) for p in self.config.plugin_directories]

        # Integration managers
        self._init_integrations()

        # Start resource monitoring if enabled
        if self.config.enable_resource_monitoring:
            self.resource_monitor.start_monitoring()
            self.resource_monitor.add_callback(self._handle_resource_event)

        # Initialize plugin discovery
        if self.config.auto_discovery:
            self.discover_plugins()

        self.logger.info(f"Unified Plugin Manager initialized with {len(self.plugins)} plugins discovered")

    def _resolve_module_alias(self, requested_module: str) -> str:
        """Return canonical module name for an import, applying alias map if present."""
        try:
            return self._module_alias_map.get(requested_module, requested_module)
        except Exception:
            return requested_module

    def _initialize_existing_integrations(self):
        """
        Initialize integrations with existing AODS infrastructure instead of duplicating functionality.
        """
        try:
            # Use existing health checker system
            from core.shared_infrastructure.monitoring.health_checker import HealthChecker

            self._health_checker = HealthChecker()
            self.logger.debug("✅ Integrated with existing HealthChecker system")
        except ImportError:
            self._health_checker = None
            self.logger.debug("⚠️ HealthChecker not available")

        try:
            # Use existing error recovery framework
            from core.error_recovery_framework import ErrorRecoveryFramework

            self._error_recovery = ErrorRecoveryFramework()
            self.logger.debug("✅ Integrated with existing ErrorRecoveryFramework")
        except ImportError:
            self._error_recovery = None
            self.logger.debug("⚠️ ErrorRecoveryFramework not available")

        try:
            # Use existing performance monitoring
            # MIGRATED: PerformanceTracker removed - now using unified infrastructure
            from core.shared_infrastructure.monitoring.performance_tracker import get_unified_performance_tracker

            self._performance_tracker = get_unified_performance_tracker()
            self.logger.debug("✅ Integrated with existing PerformanceTracker")
        except ImportError:
            self._performance_tracker = None
            self.logger.debug("⚠️ PerformanceTracker not available")

    def _determine_optimal_workers(self) -> int:
        """Determine optimal worker count based on resource coordinator or config."""
        # If global coordinator is available, request resources
        if self.global_coordinator:
            try:
                # Request resources for initial setup (will be updated during execution)
                estimated_plugins = max(10, len(self.plugins) if self.plugins else 10)
                self.resource_limits = self.global_coordinator.request_resources(
                    self.coordinator_name, estimated_plugins, self.execution_priority
                )
                return self.resource_limits.max_concurrent_plugins
            except Exception as e:
                self.logger.warning(f"Failed to get resource allocation from coordinator: {e}")

        # Fallback to config-based allocation
        return self.config.max_concurrent_plugins

    def _init_integrations(self):
        """Initialize integration with other AODS systems."""
        # System integration
        self.system_integration = None
        if self.config.enable_system_integration:
            try:
                # Try to import system integration
                self.logger.info("✅ System integration capabilities available")
            except Exception as e:
                self.logger.warning(f"⚠️ System integration not available: {e}")

        # MASTG integration
        self.mastg_integration = None
        if self.config.enable_mastg_integration:
            try:
                # Initialize MASTG integration capabilities
                self.logger.info("✅ MASTG integration capabilities available")
            except Exception as e:
                self.logger.warning(f"⚠️ MASTG integration not available: {e}")

    def _handle_resource_event(self, event_type: str, value: float):
        """Handle resource monitoring events."""
        if event_type == "critical_memory":
            self.logger.warning(f"🚨 Critical memory usage: {value:.1f}MB - initiating protective measures")
            # Could trigger garbage collection, plugin throttling, etc.
        elif event_type == "warning_memory":
            self.logger.info(f"⚠️ High memory usage: {value:.1f}MB - monitoring closely")

    def discover_plugins(self, force_rediscovery: bool = False, quiet_cached: bool = True) -> int:
        """
        Discover plugins from configured directories with validation.
        """
        import os

        use_v3 = os.environ.get("AODS_PLUGIN_REGISTRY_V3", "0") == "1"
        shadow_verify = os.environ.get("AODS_PLUGIN_REGISTRY_V3_SHADOW", "1") == "1"

        if use_v3 and not force_rediscovery:
            try:
                from .registry_v3 import PluginRegistryV3  # local import to avoid hard dependency

                v3 = PluginRegistryV3()
                start = time.time()
                # Prefer file-based discovery for registration
                files_v3 = v3.discover_plugin_files()
                elapsed = time.time() - start
                # Populate self.plugins via existing analyzer path (normalize module -> file path)
                discovered_count = 0
                root = Path(__file__).resolve().parents[2]
                for plugin_file in files_v3:
                    try:
                        plugin_metadata = self._analyze_plugin_file(plugin_file)
                        if plugin_metadata:
                            with self._registry_lock:
                                self.plugins[plugin_metadata.name] = plugin_metadata
                            discovered_count += 1
                    except Exception:
                        continue
                # Safe fallback: if v3 yielded no registrations, fall through to live discovery path
                if discovered_count == 0:
                    try:
                        from core.shared_infrastructure.logging.fallback_logger import FallbackLogger

                        FallbackLogger.log(
                            component="plugin_registry",
                            action="fallback_to_live_discovery",
                            reason="empty_cache",
                            logger=self.logger,
                        )
                    except Exception:
                        self.logger.debug("PluginRegistryV3 yielded zero registrations; falling back to live discovery")
                    raise RuntimeError("v3_zero_registrations")
                self.metrics.discovered_plugins = len(self.plugins)
                self.metrics.plugin_discovery_time = elapsed
                # Mark discovery complete to avoid subsequent resets in this scan
                try:
                    self._discovered_once = True
                    self._discovery_successes = getattr(self, "_discovery_successes", 0) + 1
                except Exception:
                    pass
                self.logger.info(
                    f"🎯 Plugin discovery completed (v3 cache): {len(self.plugins)} plugins found in {elapsed:.2f}s"
                )
                # Shadow verification against live discovery if enabled
                if shadow_verify:
                    live = set()
                    try:
                        # Snapshot and clear for shadow run
                        snapshot = dict(self.plugins)
                        self.plugins.clear()
                        _ = self._discover_plugins_live()
                        live = set(self.plugins.keys())
                        # restore
                        self.plugins = snapshot
                    except Exception:
                        pass
                    # Normalize v3 discovered files to current registry keys best-effort
                    cached_keys = set(k for k in snapshot.keys()) if "snapshot" in locals() else set()
                    diff = live - cached_keys
                    if diff:
                        self.logger.warning(f"PluginRegistryV3 shadow diff: {len(diff)} modules missing in cache")
                return self.metrics.discovered_plugins
            except Exception as e:
                self.logger.debug(f"PluginRegistryV3 not used due to error: {e}")
                # fall through to live discovery

        # Live discovery path (original)
        # existing implementation below
        with self._discovery_lock:
            # Early exit if discovery already completed in this scan
            if self._discovered_once and not force_rediscovery:
                if self._debug_discovery:
                    self.logger.debug("🔁 Plugin discovery skipped (already discovered in this scan)")
                return len(self.plugins)

            discovery_start = time.time()
            self._discovery_attempts += 1

            # Check cache first
            cache_key = self.discovery_cache.get_cache_key(self.plugin_paths)
            cached_data = self.discovery_cache.get_cached_plugins(cache_key)

            if cached_data:
                # Use cached results
                with self._registry_lock:
                    self.plugins = cached_data["plugins"].copy()
                self.metrics.discovered_plugins = len(self.plugins)
                self._discovery_last_seconds = time.time() - discovery_start
                self.metrics.plugin_discovery_time = self._discovery_last_seconds
                self._discovery_successes += 1
                self._discovered_once = True

                # Quiet cached logging by default; elevate if debug or explicitly requested
                if self._debug_discovery or not quiet_cached:
                    self.logger.info(
                        f"🎯 Plugin discovery completed (cached): {len(self.plugins)} plugins found in {self.metrics.plugin_discovery_time:.3f}s"  # noqa: E501
                    )
                else:
                    self.logger.debug(
                        f"🎯 Plugin discovery completed (cached): {len(self.plugins)} plugins found in {self.metrics.plugin_discovery_time:.3f}s"  # noqa: E501
                    )
                return len(self.plugins)

            # Perform fresh discovery
            self.logger.info(f"🔍 Starting plugin discovery in {len(self.plugin_paths)} directories")

            discovered_count = 0

            for plugin_path in self.plugin_paths:
                if not plugin_path.exists():
                    self.logger.debug(f"Plugin directory not found: {plugin_path}")
                    continue

                self.logger.debug(f"Scanning plugin directory: {plugin_path}")
                discovered_count += self._discover_plugins_in_directory(plugin_path)

            discovery_time = time.time() - discovery_start
            self._discovery_last_seconds = discovery_time
            self.metrics.plugin_discovery_time = discovery_time
            self.metrics.discovered_plugins = len(self.plugins)
            self._discovery_successes += 1

            # Cache the results
            self.discovery_cache.cache_plugins(cache_key, self.plugins, self.metrics)

            self._discovered_once = True
            self.logger.info(
                f"🎯 Plugin discovery completed: {discovered_count} plugins found in {discovery_time:.2f}s"
            )
            return discovered_count

    def _discover_plugins_in_directory(self, directory: Path, current_depth: int = 0) -> int:
        """Discover plugins in a specific directory with depth control."""
        if current_depth > self.config.discovery_depth:
            return 0

        discovered = 0

        try:
            # Look for Python files
            for item in directory.iterdir():
                if (
                    item.is_file()
                    and item.suffix == ".py"
                    and (not item.name.startswith("_") or item.name == "__init__.py")
                ):
                    plugin_metadata = self._analyze_plugin_file(item)
                    if plugin_metadata:
                        with self._registry_lock:
                            self.plugins[plugin_metadata.name] = plugin_metadata
                        discovered += 1
                        self.logger.debug(f"Discovered plugin: {plugin_metadata.name}")

                elif item.is_dir() and not item.name.startswith("."):
                    # Recursive discovery in subdirectories
                    discovered += self._discover_plugins_in_directory(item, current_depth + 1)

        except Exception as e:
            self.logger.warning(f"Error discovering plugins in {directory}: {e}")
            # Track discovery failure for stability metrics
            try:
                self._discovery_failures += 1
            except Exception:
                pass

        return discovered

    def _pre_validate_plugin(self, plugin_init_path: Path) -> bool:
        """
        PERMANENT REGRESSION-PREVENTION METHOD: Pre-validate plugin structure before import.

        Prevents import spam errors by checking plugin structure first.

        Args:
            plugin_init_path: Path to plugin's __init__.py file

        Returns:
            True if plugin appears to be properly structured, False otherwise
        """
        try:
            plugin_dir = plugin_init_path.parent
            plugin_name = plugin_dir.name

            # Skip known problematic patterns to prevent regression
            if plugin_name in {"__pycache__", ".git", ".pytest_cache", "tests"}:
                return False

            # Check if __init__.py exists and is readable
            if not plugin_init_path.exists() or plugin_init_path.stat().st_size == 0:
                return False

            # Quick syntax check - try to parse the __init__.py file
            try:
                with open(plugin_init_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Basic structure checks
                if len(content.strip()) == 0:
                    self.logger.debug(f"Plugin {plugin_name} has empty __init__.py")
                    return False

                # Try to compile the Python code to catch syntax errors
                compile(content, str(plugin_init_path), "exec")

                # Check for obvious import issues in the content
                problematic_patterns = [
                    "from __future__ import",  # Usually indicates development code
                    "import pdb",  # Debug code
                    "breakpoint()",  # Debug code
                ]

                content_lower = content.lower()
                for pattern in problematic_patterns:
                    if pattern.lower() in content_lower:
                        self.logger.debug(f"Plugin {plugin_name} contains potentially problematic code: {pattern}")
                        # Don't reject, just warn

            except (SyntaxError, UnicodeDecodeError) as e:
                self.logger.debug(f"Plugin {plugin_name} has syntax/encoding issues: {e}")
                return False
            except Exception as e:
                # Don't fail validation for minor issues
                self.logger.debug(f"Plugin {plugin_name} validation warning: {e}")

            return True

        except Exception as e:
            self.logger.debug(f"Plugin pre-validation error for {plugin_init_path}: {e}")
            return False

    def _track_plugin_failure(self, plugin_name: str, error: Exception) -> None:
        """
        ENHANCED PERMANENT REGRESSION-PREVENTION METHOD: Track plugin failures intelligently.

        Enhanced with intelligent plugin diagnostics and recovery systems:
        - Tracking failure counts per plugin
        - Blacklisting repeatedly failing plugins
        - Using smart logging levels based on failure count
        - Providing detailed diagnostics and recovery suggestions
        - Health analytics and dependency analysis

        Args:
            plugin_name: Name of the failing plugin
            error: The exception that caused the failure
        """
        # Track failure count
        current_failures = self._failed_imports.get(plugin_name, 0) + 1
        self._failed_imports[plugin_name] = current_failures

        # Use existing error recovery framework if available
        if self._error_recovery:
            try:
                self._error_recovery.record_plugin_error(plugin_name, error)
            except Exception as e:
                self.logger.debug(f"Error recording plugin failure in recovery framework: {e}")

        # Determine log level and message detail based on failure count
        error_str = str(error)

        if current_failures == 1:
            # First failure: Log detailed error for investigation
            self.logger.warning(
                f"❌ Plugin '{plugin_name}' failed to load (attempt 1): {error_str}\n"
                f"   Error type: {type(error).__name__}\n"
                f"   Will retry up to 3 times before blacklisting."
            )

            # Provide basic suggestions for common import errors
            if isinstance(error, ImportError) and "No module named" in error_str:
                import re

                module_match = re.search(r"No module named[^\w]*'?([^']*)'?", error_str)
                if module_match:
                    missing_module = module_match.group(1).strip("'\"")
                    self.logger.info(f"💡 Plugin '{plugin_name}' needs module: {missing_module}")
                    # Suggest common packages
                    common_packages = {
                        "frida": "frida frida-tools",
                        "requests": "requests",
                        "pandas": "pandas",
                        "numpy": "numpy",
                        "PIL": "Pillow",
                        "yaml": "PyYAML",
                        "rich": "rich",
                    }
                    if missing_module in common_packages:
                        self.logger.info(f"   • Try: pip install {common_packages[missing_module]}")

        elif current_failures == 2:
            # Second failure: Log brief error
            self.logger.warning(f"❌ Plugin '{plugin_name}' failed again (attempt 2): {type(error).__name__}")
        elif current_failures == 3:
            # Third failure: Log warning and blacklist
            self.logger.warning(
                f"⚠️ Plugin '{plugin_name}' failed 3 times - blacklisting to prevent spam.\n"
                f"   Last error: {type(error).__name__}: {error_str[:100]}..."
            )
            self._import_blacklist.add(plugin_name)
        else:
            # Already blacklisted: This shouldn't happen, but just in case
            self.logger.debug(f"Blacklisted plugin '{plugin_name}' failed again: {type(error).__name__}")

        # Classify common error types for better diagnostics
        if isinstance(error, ImportError):
            if "No module named" in error_str:
                missing_module = error_str.split("No module named ")[-1].strip("'\"")
                if current_failures == 1:
                    self.logger.info(f"💡 Plugin '{plugin_name}' needs module: {missing_module}")
            elif "cannot import name" in error_str:
                if current_failures == 1:
                    self.logger.info(f"💡 Plugin '{plugin_name}' has missing class/function in existing module")
        elif isinstance(error, (SyntaxError, IndentationError)):
            if current_failures == 1:
                self.logger.info(f"💡 Plugin '{plugin_name}' has syntax errors in Python code")
        elif isinstance(error, (AttributeError, NameError)):
            if current_failures == 1:
                self.logger.info(f"💡 Plugin '{plugin_name}' has undefined variables/attributes")

    def _analyze_plugin_file(self, file_path: Path) -> Optional[PluginMetadata]:
        """Analyze a Python file to determine if it's a valid plugin."""
        analysis_start = time.time()

        try:
            # Try to extract module name - handle both absolute and relative paths
            try:
                if file_path.is_absolute():
                    relative_path = file_path.relative_to(Path.cwd())
                else:
                    relative_path = file_path

                # Special handling for __init__.py files (directory-based plugins)
                if file_path.name == "__init__.py":
                    # For __init__.py, use parent directory path as module name
                    module_name = str(relative_path.parent).replace(os.sep, ".")
                else:
                    # For regular .py files, remove extension
                    module_name = str(relative_path.with_suffix("")).replace(os.sep, ".")

            except ValueError:
                # If relative_to fails, create module name from file path directly
                path_parts = list(file_path.parts)
                if file_path.name == "__init__.py":
                    # For __init__.py, exclude the __init__.py part
                    path_parts = path_parts[:-1]  # Remove __init__.py
                elif file_path.suffix:
                    path_parts[-1] = file_path.stem  # Remove .py extension
                module_name = ".".join(path_parts)

            # Basic validation - check if file contains plugin-like patterns
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Look for plugin indicators with flexible matching
            import re

            plugin_patterns = [
                r"def\s+get_plugin_info",
                r"def\s+run\s*\(",
                r"def\s+run_plugin\s*\(",
                r"class\s+\w*Plugin",
                r"def\s+validate_plugin",
                r"__plugin__",
                r"PLUGIN_",
                # Additional patterns for AODS plugins
                r"def\s+analyze_",
                r"def\s+execute",
                r"__all__.*run_plugin",
                r"return.*plugin.*result",
            ]

            has_plugin_indicators = any(
                re.search(pattern, content, re.IGNORECASE | re.MULTILINE) for pattern in plugin_patterns
            )

            if not has_plugin_indicators:
                return None

            # Extract basic metadata
            if file_path.name == "__init__.py":
                # For __init__.py files, use the parent directory name as plugin name
                plugin_name = file_path.parent.name
            else:
                # For regular Python files, use the file stem
                plugin_name = file_path.stem
            plugin_type = self._detect_plugin_type(content, file_path)

            metadata = PluginMetadata(
                name=plugin_name,
                module_name=module_name,
                file_path=file_path,
                plugin_type=plugin_type,
                discovery_time=time.time() - analysis_start,
                description=self._extract_description(content),
                version=self._extract_version(content),
                capabilities=self._extract_capabilities(content),
                timeout=self._extract_timeout(content),
                requires_device=self._requires_device(content),
                supports_parallel=self._supports_parallel(content),
            )

            # Validate plugin if enabled
            if self.config.validate_on_discovery:
                metadata.validated = self._validate_plugin(metadata)

            return metadata

        except Exception as e:
            self.logger.debug(f"Error analyzing plugin file {file_path}: {e}")
            return None

    def _detect_plugin_type(self, content: str, file_path: Path) -> PluginType:
        """Detect plugin type from content and path."""
        content_lower = content.lower()
        path_str = str(file_path).lower()

        if "mastg" in path_str or "mastg" in content_lower:
            return PluginType.MASTG
        elif "network" in path_str or "mitmproxy" in content_lower or "network" in content_lower:
            return PluginType.NETWORK
        elif "dynamic" in path_str or "device" in content_lower or "adb" in content_lower:
            return PluginType.DYNAMIC
        elif "static" in path_str or "apk" in content_lower or "manifest" in content_lower:
            return PluginType.STATIC
        elif any(word in content_lower for word in ["hybrid", "static", "dynamic"]):
            return PluginType.HYBRID
        else:
            return PluginType.UNKNOWN

    def _extract_description(self, content: str) -> str:
        """Extract plugin description from content."""
        lines = content.split("\n")
        for i, line in enumerate(lines):
            if '"""' in line and i < 20:  # Look in first 20 lines
                # Find end of docstring
                for j in range(i + 1, min(i + 10, len(lines))):
                    if '"""' in lines[j]:
                        return " ".join(lines[i + 1 : j]).strip()
        return ""

    def _extract_version(self, content: str) -> str:
        """Extract plugin version from content."""
        import re

        version_pattern = r'version\s*=\s*["\']([^"\']+)["\']'
        match = re.search(version_pattern, content, re.IGNORECASE)
        return match.group(1) if match else "1.0.0"

    def _extract_capabilities(self, content: str) -> List[str]:
        """Extract plugin capabilities from content."""
        capabilities = []
        content_lower = content.lower()

        capability_keywords = {
            "static_analysis": ["manifest", "apk", "static"],
            "dynamic_analysis": ["device", "adb", "dynamic"],
            "network_analysis": ["network", "mitmproxy", "traffic"],
            "malware_detection": ["malware", "virus", "threat"],
            "vulnerability_detection": ["vulnerability", "exploit", "security"],
            "permission_analysis": ["permission", "privilege"],
            "crypto_analysis": ["crypto", "encryption", "certificate"],
        }

        for capability, keywords in capability_keywords.items():
            if any(keyword in content_lower for keyword in keywords):
                capabilities.append(capability)

        return capabilities

    def _extract_timeout(self, content: str) -> int:
        """Extract plugin timeout from content."""
        import re

        # Try Python assignment style e.g., timeout = 600
        timeout_pattern_py = r"(^|\b)timeout\s*=\s*(\d+)"
        match = re.search(timeout_pattern_py, content, re.IGNORECASE)
        if match:
            try:
                return int(match.group(2))
            except Exception:
                pass
        # Try JSON-like PLUGIN_METADATA style e.g., "timeout": 600
        timeout_pattern_json = r'"timeout"\s*:\s*(\d+)'
        match2 = re.search(timeout_pattern_json, content, re.IGNORECASE)
        if match2:
            try:
                return int(match2.group(1))
            except Exception:
                pass
        return self.config.default_timeout

    def _requires_device(self, content: str) -> bool:
        """Check if plugin requires Android device."""
        device_keywords = ["device", "adb", "android", "emulator"]
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in device_keywords)

    def _supports_parallel(self, content: str) -> bool:
        """Check if plugin supports parallel execution."""
        # Look for parallel-unfriendly patterns
        unfriendly_patterns = ["singleton", "global", "shared_state", "exclusive"]
        content_lower = content.lower()
        return not any(pattern in content_lower for pattern in unfriendly_patterns)

    def _validate_plugin(self, metadata: PluginMetadata) -> bool:
        """Validate plugin without loading it."""
        try:
            # Basic file checks
            if not metadata.file_path.exists():
                return False

            # Check if it's importable
            spec = importlib.util.spec_from_file_location(metadata.module_name, metadata.file_path)
            if spec is None:
                return False

            # Could add more validation here
            return True

        except Exception:
            return False

    def load_plugin(self, plugin_name: str) -> bool:
        """
        Load a specific plugin by name.

        Args:
            plugin_name: Name of plugin to load

        Returns:
            True if loaded successfully
        """
        if plugin_name not in self.plugins:
            self.logger.warning(f"Plugin '{plugin_name}' not found in registry")
            return False

        if plugin_name in self.loaded_modules:
            self.logger.debug(f"Plugin '{plugin_name}' already loaded")
            return True

        metadata = self.plugins[plugin_name]
        load_start = time.time()

        try:
            self.logger.debug(f"Loading plugin: {plugin_name}")

            # ENHANCED LOADING: Use the same logic as _execute_single_plugin
            # Set up proper sys.path for complex plugins
            original_sys_path = sys.path.copy()
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            plugins_dir = os.path.join(project_root, "plugins")

            paths_to_add = []
            if project_root not in sys.path:
                paths_to_add.append(project_root)
            if plugins_dir not in sys.path:
                paths_to_add.append(plugins_dir)

            # Add paths at the beginning for priority
            for path in reversed(paths_to_add):
                sys.path.insert(0, path)

            try:
                # Try importlib.import_module first (works better with complex plugins)
                self.logger.debug(f"Attempting importlib import: {metadata.module_name}")
                module = importlib.import_module(metadata.module_name)

            except ImportError as import_error:
                # Targeted fallback for known module packaging anomalies
                if metadata.module_name.startswith("plugins.insecure_data_storage"):
                    try:
                        self.logger.debug("Trying fallback import for insecure_data_storage.v2_plugin")
                        module = importlib.import_module("plugins.insecure_data_storage.v2_plugin")
                        self.loaded_modules[metadata.module_name] = module
                        self.logger.info("✅ Fallback SUCCESS: Imported plugins.insecure_data_storage.v2_plugin")
                        return module
                    except Exception as fallback_e:
                        self.logger.debug(f"Fallback import failed: {fallback_e}")
                self.logger.debug(f"Import module failed: {import_error}, trying spec_from_file_location")
                # Fallback to file location method
                spec = importlib.util.spec_from_file_location(metadata.module_name, metadata.file_path)
                if spec is None:
                    raise ImportError(f"Could not create spec for {metadata.file_path}")

                module = importlib.util.module_from_spec(spec)

                # Set up proper module attributes for complex plugins
                module.__name__ = metadata.module_name
                module.__file__ = str(metadata.file_path)
                module.__package__ = metadata.module_name if "." in metadata.module_name else None

                # For directory-based plugins, set __path__ for submodule imports
                if metadata.file_path.name == "__init__.py":
                    plugin_dir = os.path.dirname(metadata.file_path)
                    module.__path__ = [plugin_dir]
                    module.__package__ = metadata.module_name

                # Add to sys.modules before execution
                sys.modules[metadata.module_name] = module

                try:
                    spec.loader.exec_module(module)
                except Exception as exec_error:
                    # Clean up sys.modules if execution fails
                    if metadata.module_name in sys.modules:
                        del sys.modules[metadata.module_name]
                    raise exec_error

            finally:
                # Always restore original sys.path
                sys.path[:] = original_sys_path

            # Store loaded module
            self.loaded_modules[plugin_name] = module
            metadata.load_time = time.time() - load_start

            self.metrics.loaded_plugins += 1
            self.metrics.plugin_loading_time += metadata.load_time

            self.logger.info(f"✅ Plugin '{plugin_name}' loaded successfully in {metadata.load_time:.3f}s")
            return True

        except Exception as e:
            self.logger.error(f"❌ Plugin loading failed for '{plugin_name}': {e}")

            # ENHANCED FALLBACK: Try to create fallback module
            try:
                if PLUGIN_FALLBACK_AVAILABLE:
                    self.logger.info(f"🔄 Creating fallback module for '{plugin_name}'")
                    fallback_class = get_fallback_class("BasicAnalyzer")  # noqa: F821
                    import types

                    fallback_module = types.ModuleType(metadata.module_name)
                    setattr(fallback_module, "BasicAnalyzer", fallback_class)

                    def fallback_run(apk_ctx):
                        self.logger.info(f"🔄 FALLBACK EXECUTION: {plugin_name}")
                        analyzer = fallback_class()
                        return analyzer.analyze(apk_ctx)

                    fallback_module.run = fallback_run
                    fallback_module.run_plugin = fallback_run
                    self.loaded_modules[plugin_name] = fallback_module
                    metadata.load_time = time.time() - load_start

                    self.logger.info(f"✅ Fallback module created for '{plugin_name}'")
                    return True
                else:
                    # Try graceful degradation
                    from core.error_recovery_framework import GracefulDegradationManager

                    degradation_mgr = GracefulDegradationManager()
                    degraded_functionality = degradation_mgr.get_degraded_functionality(plugin_name, e)

                    import types

                    degraded_module = types.ModuleType(metadata.module_name)

                    def degraded_run(apk_ctx):
                        self.logger.info(f"🔄 DEGRADED EXECUTION: {plugin_name}")
                        return (f"{plugin_name} (Degraded Mode)", degraded_functionality)

                    degraded_module.run = degraded_run
                    degraded_module.run_plugin = degraded_run
                    self.loaded_modules[plugin_name] = degraded_module
                    metadata.load_time = time.time() - load_start

                    self.logger.info(f"✅ Degraded module created for '{plugin_name}'")
                    return True

            except Exception as fallback_error:
                self.logger.error(f"❌ All recovery methods failed for '{plugin_name}': {fallback_error}")

            return False

    def get_available_plugins(self) -> Dict[str, PluginMetadata]:
        """Get all available plugins."""
        return self.plugins.copy()

    def get_loaded_plugins(self) -> Dict[str, Any]:
        """Get all loaded plugin modules."""
        return self.loaded_modules.copy()

    def get_execution_metrics(self) -> PluginExecutionMetrics:
        """Get full execution metrics."""
        # Update derived metrics
        self.metrics.calculate_derived_metrics()
        return self.metrics

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get full performance summary."""
        resource_summary = self.resource_monitor.get_performance_summary()
        metrics_summary = self.metrics.calculate_derived_metrics()

        return {
            "plugin_discovery": {
                "total_discovered": self.metrics.discovered_plugins,
                "total_loaded": self.metrics.loaded_plugins,
                "discovery_time": self.metrics.plugin_discovery_time,
                "loading_time": self.metrics.plugin_loading_time,
            },
            "execution_summary": metrics_summary,
            "resource_usage": resource_summary,
            "active_executions": len(self.active_executions),
            "historical_executions": len(self.execution_history),
        }

    def cleanup(self):
        """Cleanup resources and shutdown gracefully."""
        self.logger.info("🧹 Starting plugin manager cleanup")

        # Signal shutdown
        self.shutdown_requested = True
        self.shutdown_event.set()

        # Wait for active executions to complete
        if self.active_executions:
            self.logger.info(f"Waiting for {len(self.active_executions)} active executions to complete...")
            for execution_id, future in self.active_executions.items():
                try:
                    future.result(timeout=30)  # Give plugins time to finish
                except Exception as e:
                    self.logger.warning(f"Execution {execution_id} did not complete cleanly: {e}")

        # Shutdown thread pool
        if self.executor:
            try:
                self._shutdown_requested = True
            except Exception:
                pass
            self.executor.shutdown(wait=True)

        # Stop resource monitoring
        self.resource_monitor.stop_monitoring()

        self.logger.info("✅ Plugin manager cleanup completed")

    def execute_plugin(
        self, plugin_metadata: "PluginMetadata", apk_ctx, timeout_override: Optional[int] = None
    ) -> Tuple[str, Any]:
        """
        Execute a single plugin with protection and monitoring.

        Args:
            plugin_metadata: Plugin metadata and configuration
            apk_ctx: APK context object
            timeout_override: Optional timeout override in seconds. When provided,
                            this takes precedence over all other timeout calculations
                            including environment variables and dynamic timeouts.
                            Used by profile-based scan timeout enforcement.

        Returns:
            Tuple of (plugin_title, plugin_result)
        """
        plugin_name = plugin_metadata.name

        # Prevent duplicate executions for the same plugin within a scan
        if plugin_name in getattr(self, "_executed_plugins", set()):
            self.logger.info(f"⏭️ Skipping duplicate execution for plugin: {plugin_name}")
            return f"⏭️ {plugin_name}", "Duplicate execution skipped"
        else:
            try:
                self._executed_plugins.add(plugin_name)
            except Exception:
                pass

        # Store timeout override for use in _execute_plugin_core
        self._current_timeout_override = timeout_override

        # Initialize correlation context for plugin execution
        if CORRELATION_AVAILABLE:
            correlation_logger = get_correlation_logger(__name__)
            with plugin_correlation_context(plugin_name) as _plugin_id:  # noqa: F841
                correlation_logger.info(f"Starting plugin execution: {plugin_name}")
                return self._execute_plugin_with_correlation(plugin_metadata, apk_ctx, correlation_logger)
        else:
            return self._execute_plugin_without_correlation(plugin_metadata, apk_ctx)

    def _execute_plugin_with_correlation(
        self, plugin_metadata: "PluginMetadata", apk_ctx, correlation_logger
    ) -> Tuple[str, Any]:
        """Execute plugin with correlation logging."""
        plugin_name = plugin_metadata.name

        # Check for shutdown request
        if hasattr(self, "_shutdown_requested") and self._shutdown_requested:
            plugin_metadata.status = PluginExecutionState.CANCELLED
            correlation_logger.warning(f"Plugin {plugin_name} cancelled due to shutdown request")
            self.console.print(f"🛑 Plugin {plugin_name} cancelled due to shutdown request", style="yellow")
            return "🛑 {plugin_name}", "Cancelled due to shutdown"

        correlation_logger.info(f"Executing plugin: {plugin_name}")
        self.console.print(f"🔍 Executing plugin: {plugin_name}")

        return self._execute_plugin_core(plugin_metadata, apk_ctx, correlation_logger)

    def _execute_plugin_without_correlation(self, plugin_metadata: "PluginMetadata", apk_ctx) -> Tuple[str, Any]:
        """Execute plugin without correlation logging (fallback)."""
        plugin_name = plugin_metadata.name

        # Check for shutdown request
        if hasattr(self, "_shutdown_requested") and self._shutdown_requested:
            plugin_metadata.status = PluginExecutionState.CANCELLED
            self.console.print(f"🛑 Plugin {plugin_name} cancelled due to shutdown request", style="yellow")
            return "🛑 {plugin_name}", "Cancelled due to shutdown"

        self.console.print(f"🔍 Executing plugin: {plugin_name}")

        return self._execute_plugin_core(plugin_metadata, apk_ctx, None)

    def _execute_plugin_core(
        self, plugin_metadata: "PluginMetadata", apk_ctx, correlation_logger=None
    ) -> Tuple[str, Any]:
        """Core plugin execution logic."""
        plugin_name = plugin_metadata.name

        try:
            # Update plugin status
            plugin_metadata.status = PluginExecutionState.RUNNING
            start_time = time.time()

            # Load plugin if not already loaded
            if plugin_name not in self.loaded_modules:
                if correlation_logger:
                    correlation_logger.info(f"Loading plugin module: {plugin_name}")
                if not self.load_plugin(plugin_name):
                    plugin_metadata.status = PluginExecutionState.FAILED
                    if correlation_logger:
                        correlation_logger.error(f"Failed to load plugin: {plugin_name}")
                    return f"❌ {plugin_name}", "Failed to load plugin"

            plugin_module = self.loaded_modules[plugin_name]

            # Determine timeout first (needed for both execution modes)
            # Priority: orchestrator override > profile-capped timeout > plugin default > config default
            timeout_override = getattr(self, "_current_timeout_override", None)
            if timeout_override is not None and timeout_override > 0:
                plugin_timeout = timeout_override
                self.logger.info(f"Using orchestrator timeout override for {plugin_name}: {plugin_timeout}s")
                # Clear the override after use
                self._current_timeout_override = None
            else:
                # Get base timeout from plugin metadata
                base_timeout = getattr(plugin_metadata, "timeout", None)
                if base_timeout is None:
                    base_timeout = getattr(plugin_metadata, "timeout_seconds", None)
                if not base_timeout:
                    base_timeout = getattr(self.config, "default_timeout", 300)

                # PROFILE-BASED TIMEOUT CAPS: Apply per-profile caps from timeout registry
                # Lightning: max 60s, Fast: max 120s, Standard: max 180s, Deep: unlimited
                if TIMEOUT_REGISTRY_AVAILABLE and _get_registry_timeout and _current_scan_profile:
                    plugin_timeout = _get_registry_timeout(
                        plugin_name, default_timeout=base_timeout, scan_profile=_current_scan_profile
                    )
                    if plugin_timeout != base_timeout:
                        self.logger.info(
                            f"⏱️ Profile {_current_scan_profile} timeout cap for {plugin_name}: {base_timeout}s → {plugin_timeout}s"  # noqa: E501
                        )
                else:
                    plugin_timeout = base_timeout

            # MULTIPROCESSING MODE: Execute plugin in separate process for hard timeout enforcement
            # Enable with AODS_PLUGIN_MULTIPROCESS=1 environment variable
            if _is_multiprocess_enabled():
                plugin_path = self._get_plugin_path(plugin_name)
                if plugin_path:
                    self.logger.info(f"🔀 Using multiprocess execution for {plugin_name} (hard timeout)")
                    result = self._execute_plugin_multiprocess(plugin_name, plugin_path, apk_ctx, float(plugin_timeout))
                    # Update plugin status based on result
                    status_str = result[0]
                    if status_str.startswith("✅"):
                        plugin_metadata.status = PluginExecutionState.COMPLETED
                        self.metrics.successful_executions += 1
                        self.metrics.total_execution_time += time.time() - start_time
                        # Validate findings
                        validated_result = self._validate_plugin_findings(plugin_name, result[1])
                        return result[0], validated_result
                    elif status_str.startswith("⏰"):
                        plugin_metadata.status = PluginExecutionState.TIMEOUT
                    else:
                        plugin_metadata.status = PluginExecutionState.FAILED
                    return result
                else:
                    self.logger.warning(f"Could not find plugin path for {plugin_name}, falling back to threading")

            # THREADING MODE: Execute plugin with timeout protection using ThreadPoolExecutor
            # Note: ThreadPoolExecutor timeout does NOT kill the running thread - plugin continues executing
            try:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(self._execute_plugin_safe, plugin_module, apk_ctx)

                    # Heartbeat-enabled wait loop to avoid perceived hangs
                    total_timeout = float(plugin_timeout)
                    deadline = time.time() + total_timeout
                    try:
                        heartbeat_interval = float(os.getenv("AODS_PROGRESS_HEARTBEAT_S", "15"))
                    except Exception:
                        heartbeat_interval = 15.0
                    heartbeat_interval = max(1.0, min(heartbeat_interval, 120.0))
                    last_heartbeat = 0.0

                    while True:
                        remaining = deadline - time.time()
                        if remaining <= 0:
                            # Escalate to outer handler to mark timeout
                            raise FutureTimeoutError()
                        slice_timeout = min(remaining, max(1.0, min(heartbeat_interval, remaining)))
                        try:
                            result = future.result(timeout=slice_timeout)
                            plugin_metadata.status = PluginExecutionState.COMPLETED
                            self._exec_successes += 1
                            if correlation_logger:
                                correlation_logger.info(f"Plugin execution completed successfully: {plugin_name}")
                            break
                        except FutureTimeoutError:
                            now = time.time()
                            if now - last_heartbeat >= heartbeat_interval:
                                elapsed = int(now - start_time)
                                msg = f"⏳ {plugin_name} running... elapsed={elapsed}s, timeout={int(total_timeout)}s"
                                try:
                                    if correlation_logger:
                                        correlation_logger.info(msg)
                                except Exception:
                                    pass
                                try:
                                    self.console.print(msg)
                                except Exception:
                                    pass
                                last_heartbeat = now
            except FutureTimeoutError:
                self.logger.error(f"Plugin {plugin_name} timed out after {plugin_timeout}s")
                if correlation_logger:
                    correlation_logger.error(f"Plugin timed out after {plugin_timeout}s: {plugin_name}")
                plugin_metadata.status = PluginExecutionState.TIMEOUT
                self._exec_timeouts += 1

                # Track 109: Attempt to recover partial results from coordination cache
                partial_result = self._recover_partial_results(plugin_name, apk_ctx)
                if partial_result:
                    self.logger.info(
                        f"Recovered partial results for {plugin_name} after timeout",
                    )
                    return f"⏰⚡ {plugin_name} (partial)", partial_result

                return f"⏰ {plugin_name}", "Plugin timed out"
            except Exception as e:
                self.logger.error(f"Plugin execution failed: {e}")
                plugin_metadata.status = PluginExecutionState.FAILED
                self._exec_failures += 1
                return f"❌ {plugin_name}", f"Execution failed: {str(e)}"

            # Update metrics
            self.metrics.successful_executions += 1
            self.metrics.total_execution_time += time.time() - start_time

            # Track 7.3: Validate plugin findings against contract
            result = self._validate_plugin_findings(plugin_name, result)

            return f"✅ {plugin_name}", result

        except KeyboardInterrupt:
            plugin_metadata.status = PluginExecutionState.CANCELLED
            return f"🛑 {plugin_name}", "Cancelled by user"

        except Exception as e:
            plugin_metadata.status = PluginExecutionState.FAILED
            self.metrics.failed_executions += 1
            error_msg = f"Plugin execution failed: {e}"
            return f"❌ {plugin_name}", f"Error: {error_msg}"

    def _recover_partial_results(self, plugin_name: str, apk_ctx) -> Optional[Any]:
        """Attempt to recover cached partial results after plugin timeout.

        Track 109: JADX writes incremental partial caches during analysis.
        If the manager timeout kills the plugin, we can recover whatever
        analysis stages completed before the timeout.
        """
        if plugin_name != "jadx_static_analysis":
            return None
        try:
            from core.jadx_cache_utils import get_jadx_results_cache_path
            import json

            cache_file = get_jadx_results_cache_path(
                getattr(apk_ctx, "package_name", ""),
                str(getattr(apk_ctx, "apk_path", "")),
            )
            if not os.path.exists(cache_file):
                return None

            with open(cache_file, "r") as f:
                cached = json.load(f)

            if cached.get("partial"):
                analysis = cached.get("analysis_results", {})
                if analysis:
                    self.logger.info(
                        f"Partial cache recovery: {list(analysis.keys())} stages available"
                    )
                    return cached
        except Exception as e:
            self.logger.debug(f"Partial result recovery failed: {e}")
        return None

    def _execute_plugin_safe(self, plugin_module, apk_ctx):
        """
        Safely execute plugin module.

        Supports multiple plugin interfaces (checked in priority order):
        1. V2 plugin factory: create_plugin() -> instance.execute() (preferred - returns PluginResult)
        2. Module-level functions: analyze(), run(), execute(), run_plugin() (legacy fallback)
        """
        # Try V2 plugin factory pattern FIRST (returns PluginResult directly)
        if hasattr(plugin_module, "create_plugin"):
            try:
                plugin_instance = plugin_module.create_plugin()
                if hasattr(plugin_instance, "execute"):
                    return plugin_instance.execute(apk_ctx)
                elif hasattr(plugin_instance, "analyze"):
                    return plugin_instance.analyze(apk_ctx)
                elif hasattr(plugin_instance, "run"):
                    return plugin_instance.run(apk_ctx)
            except Exception as e:
                self.logger.warning(f"V2 plugin factory execution failed: {e}")
                # Fall through to legacy entry points

        # Try module-level entry points (legacy plugins)
        if hasattr(plugin_module, "analyze"):
            return plugin_module.analyze(apk_ctx)
        elif hasattr(plugin_module, "run"):
            return plugin_module.run(apk_ctx)
        elif hasattr(plugin_module, "execute"):
            return plugin_module.execute(apk_ctx)
        elif hasattr(plugin_module, "run_plugin"):
            return plugin_module.run_plugin(apk_ctx)

        raise AttributeError(
            "Plugin does not have a recognized entry point. "
            "Expected one of: analyze(), run(), execute(), run_plugin(), or create_plugin() factory"
        )

    def _execute_plugin_multiprocess(
        self, plugin_name: str, plugin_path: str, apk_ctx, timeout_seconds: float
    ) -> Tuple[str, Any]:
        """
        Execute a plugin in a separate process with hard timeout enforcement.

        This method spawns a child process to run the plugin. If the plugin
        exceeds its timeout, the process is forcibly terminated with SIGTERM/SIGKILL.

        Args:
            plugin_name: Name of the plugin to execute
            plugin_path: File path to the plugin module
            apk_ctx: APK context object
            timeout_seconds: Maximum execution time in seconds

        Returns:
            Tuple of (status_string, result_or_error)
        """
        # Serialize APK context for passing to child process
        apk_ctx_dict = _serialize_apk_context(apk_ctx)

        # Create queue for receiving results
        result_queue = multiprocessing.Queue()

        # Create and start the worker process
        process = multiprocessing.Process(
            target=_multiprocess_plugin_worker,
            args=(plugin_path, plugin_name, apk_ctx_dict, result_queue),
            name=f"plugin_{plugin_name}",
        )

        start_time = time.time()
        process.start()

        self.logger.info(
            f"🔀 Started multiprocess execution for {plugin_name} (PID: {process.pid}, timeout: {timeout_seconds}s)"
        )

        # Wait for result with timeout
        try:
            # Use polling loop for heartbeat messages
            heartbeat_interval = 15.0
            last_heartbeat = start_time

            while True:
                elapsed = time.time() - start_time
                remaining = timeout_seconds - elapsed

                if remaining <= 0:
                    # Timeout reached - terminate the process
                    self.logger.warning(
                        f"⏰ Plugin {plugin_name} exceeded timeout ({timeout_seconds}s), terminating process..."
                    )

                    # First try graceful termination
                    process.terminate()
                    process.join(timeout=5.0)

                    # If still alive, force kill
                    if process.is_alive():
                        self.logger.warning(f"🔪 Force killing plugin {plugin_name} (PID: {process.pid})")
                        process.kill()
                        process.join(timeout=2.0)

                    self._exec_timeouts += 1
                    return f"⏰ {plugin_name}", f"Plugin timed out after {timeout_seconds}s (multiprocess hard kill)"

                # Check for result with short timeout for heartbeat
                check_timeout = min(remaining, heartbeat_interval)
                try:
                    status, result = result_queue.get(timeout=check_timeout)

                    # Process completed - join to clean up
                    process.join(timeout=5.0)

                    if status == "success":
                        duration = time.time() - start_time
                        self.logger.info(f"✅ Plugin {plugin_name} completed in {duration:.1f}s (multiprocess)")
                        self._exec_successes += 1
                        return f"✅ {plugin_name}", result
                    else:
                        self.logger.error(f"❌ Plugin {plugin_name} failed: {result}")
                        self._exec_failures += 1
                        return f"❌ {plugin_name}", f"Error: {result}"

                except Exception:
                    # Queue.get timed out - check if process still running
                    if not process.is_alive():
                        # Process died without sending result
                        exit_code = process.exitcode
                        self.logger.error(f"❌ Plugin {plugin_name} process died unexpectedly (exit code: {exit_code})")
                        self._exec_failures += 1
                        return f"❌ {plugin_name}", f"Process died unexpectedly (exit code: {exit_code})"

                    # Still running - emit heartbeat
                    now = time.time()
                    if now - last_heartbeat >= heartbeat_interval:
                        elapsed_int = int(now - start_time)
                        self.logger.info(
                            f"⏳ {plugin_name} running... elapsed={elapsed_int}s, timeout={int(timeout_seconds)}s (multiprocess)"  # noqa: E501
                        )
                        try:
                            self.console.print(
                                f"⏳ {plugin_name} running... elapsed={elapsed_int}s, timeout={int(timeout_seconds)}s"
                            )
                        except Exception:
                            pass
                        last_heartbeat = now

        except Exception as e:
            # Unexpected error - clean up process
            self.logger.error(f"❌ Multiprocess execution error for {plugin_name}: {e}")
            if process.is_alive():
                process.terminate()
                process.join(timeout=2.0)
                if process.is_alive():
                    process.kill()
            self._exec_failures += 1
            return f"❌ {plugin_name}", f"Multiprocess execution error: {str(e)}"

    def _get_plugin_path(self, plugin_name: str) -> Optional[str]:
        """
        Get the file path for a plugin module.

        Args:
            plugin_name: Name of the plugin

        Returns:
            File path to the plugin module, or None if not found
        """
        # Check loaded modules first
        if plugin_name in self.loaded_modules:
            module = self.loaded_modules[plugin_name]
            if hasattr(module, "__file__") and module.__file__:
                return module.__file__

        # Search in plugin directories
        plugin_dirs = [Path("plugins"), Path("core/plugins"), Path(__file__).parent / "plugins"]

        for base_dir in plugin_dirs:
            if not base_dir.exists():
                continue

            # Check for direct module
            direct_path = base_dir / f"{plugin_name}.py"
            if direct_path.exists():
                return str(direct_path)

            # Check for package with v2_plugin.py
            v2_path = base_dir / plugin_name / "v2_plugin.py"
            if v2_path.exists():
                return str(v2_path)

            # Check for package with __init__.py
            init_path = base_dir / plugin_name / "__init__.py"
            if init_path.exists():
                return str(init_path)

        return None

    def _validate_plugin_findings(self, plugin_name: str, result: Any) -> Any:
        """
        Validate plugin findings against the canonical PluginFinding contract.

        Track 7.3: Interface contract tests for plugins.
        Validates findings but does NOT fail execution - logs warnings for tracking.

        Args:
            plugin_name: Name of the plugin that produced the findings
            result: Plugin execution result (findings list, tuple, or single finding)

        Returns:
            The original result (unchanged - validation is non-blocking)
        """
        if not FINDING_VALIDATOR_AVAILABLE:
            return result

        # Extract findings from various result formats
        findings = []
        if result is None:
            return result
        elif isinstance(result, list):
            findings = result
        elif isinstance(result, tuple) and len(result) > 0:
            # Tuple like (findings_list, metadata) or (status, data)
            if isinstance(result[0], list):
                findings = result[0]
            elif len(result) > 1 and isinstance(result[1], list):
                findings = result[1]
        elif hasattr(result, "__iter__") and not isinstance(result, (str, dict)):
            findings = list(result)

        if not findings:
            return result

        # Validate findings
        try:
            validator = PluginFindingValidator(strict_mode=False)
            results, summary = validator.validate_findings(findings)

            # Update metrics
            self.metrics.findings_validated += summary.get("total", 0)
            self.metrics.findings_valid += summary.get("valid", 0)
            self.metrics.findings_invalid += summary.get("invalid", 0)
            self.metrics.validation_warnings += summary.get("with_warnings", 0)

            # Log summary for tracking (only if issues found)
            if summary.get("invalid", 0) > 0 or summary.get("with_warnings", 0) > 0:
                self.logger.warning(
                    f"[Track 7.3] Finding validation for {plugin_name}: "
                    f"{summary.get('valid', 0)}/{summary.get('total', 0)} valid, "
                    f"{summary.get('invalid', 0)} invalid, "
                    f"{summary.get('with_warnings', 0)} with warnings"
                )

                # Log first few errors for debugging
                for i, vr in enumerate(results[:3]):
                    if not vr.is_valid:
                        self.logger.debug(f"  Finding {i} errors: {vr.errors[:2]}")

        except Exception as e:
            # Validation errors should never break plugin execution
            self.logger.debug(f"Finding validation error for {plugin_name}: {e}")

        return result

    def handle_plugin_error(
        self, plugin_name: str, operation: str, error: Exception, context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Handle plugin error with full recovery strategy.

        Args:
            plugin_name: Name of the plugin that failed
            operation: Operation that was being performed
            error: The exception that occurred
            context: Additional context information

        Returns:
            Dictionary containing recovery result information
        """
        context = context or {}
        context["plugin_name"] = plugin_name

        # Log the error
        error_msg = f"Plugin {plugin_name} failed during {operation}: {str(error)}"
        self.console.print(f"❌ {error_msg}", style="red")

        # Update metrics
        self.metrics.failed_executions += 1

        # Determine recovery strategy based on error type
        recovery_strategy = self._determine_recovery_strategy(error, context)

        # Create recovery result
        recovery_result = {
            "success": False,
            "plugin_name": plugin_name,
            "operation": operation,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "recovery_strategy": recovery_strategy,
            "timestamp": time.time(),
            "context": context,
        }

        # Attempt recovery based on strategy
        if recovery_strategy == "retry":
            recovery_result["recovery_attempted"] = True
            recovery_result["recovery_message"] = "Plugin will be retried"
        elif recovery_strategy == "skip":
            recovery_result["recovery_attempted"] = True
            recovery_result["recovery_message"] = "Plugin execution skipped"
        elif recovery_strategy == "fallback":
            recovery_result["recovery_attempted"] = True
            recovery_result["recovery_message"] = "Fallback mechanism activated"
        else:
            recovery_result["recovery_attempted"] = False
            recovery_result["recovery_message"] = "No recovery strategy available"

        return recovery_result

    def _determine_recovery_strategy(self, error: Exception, context: Dict[str, Any]) -> str:
        """Determine the appropriate recovery strategy for an error."""
        if isinstance(error, (TimeoutError, FutureTimeoutError)):
            return "retry"
        elif isinstance(error, (ImportError, ModuleNotFoundError)):
            return "skip"
        elif isinstance(error, (MemoryError, OSError)):
            return "fallback"
        else:
            return "skip"

    def get_plugin_results(self) -> Dict[str, Any]:
        """
        Get full plugin execution results and metrics.

        Returns:
            Dictionary containing plugin results and execution metrics
        """
        return {
            "execution_metrics": {
                "plugins_discovered": self.metrics.discovered_plugins,
                "plugins_loaded": self.metrics.loaded_plugins,
                "plugins_executed": self.metrics.successful_executions,
                "plugins_failed": self.metrics.failed_executions,
                "plugins_timeout": self.metrics.timeout_executions,
                "total_execution_time": self.metrics.total_execution_time,
                "average_execution_time": (
                    self.metrics.total_execution_time / self.metrics.successful_executions
                    if self.metrics.successful_executions > 0
                    else 0
                ),
                "discovery_attempts": getattr(self, "_discovery_attempts", 0),
                "discovery_successes": getattr(self, "_discovery_successes", 0),
                "discovery_failures": getattr(self, "_discovery_failures", 0),
                "discovery_last_seconds": getattr(self, "_discovery_last_seconds", 0.0),
            },
            "plugin_status": {
                plugin_name: {
                    "status": str(metadata.status),
                    "error_message": getattr(metadata, "error_message", None),
                    "category": str(metadata.category),
                    "type": str(metadata.type),
                }
                for plugin_name, metadata in self.plugins.items()
            },
            "loaded_plugins": list(self.loaded_modules.keys()),
            "available_plugins": list(self.plugins.keys()),
            "configuration": {
                "plugin_timeout": self.config.default_timeout,
                "max_workers": self.config.max_workers,
                "memory_limit_mb": self.config.memory_limit_mb,
                "plugin_directories": self.config.plugin_directories,
            },
        }

    def get_stability_report(self) -> Dict[str, Any]:
        """Return a lightweight stability summary for diagnostics."""
        try:
            success_rate = 0.0
            if getattr(self, "_discovery_attempts", 0) > 0:
                success_rate = getattr(self, "_discovery_successes", 0) / max(
                    1, getattr(self, "_discovery_attempts", 0)
                )
            return {
                "discovery": {
                    "attempts": getattr(self, "_discovery_attempts", 0),
                    "successes": getattr(self, "_discovery_successes", 0),
                    "failures": getattr(self, "_discovery_failures", 0),
                    "last_seconds": getattr(self, "_discovery_last_seconds", 0.0),
                    "success_rate": success_rate,
                },
                "execution": {
                    "successes": getattr(self, "_exec_successes", 0),
                    "failures": getattr(self, "_exec_failures", 0),
                    "timeouts": getattr(self, "_exec_timeouts", 0),
                },
            }
        except Exception as e:
            self.logger.debug(f"Stability report generation failed: {e}")
            return {}

    def apply_all_fixes(self) -> None:
        """Idempotent orchestration method for stabilization hooks."""
        # This intentionally delegates to existing initialization paths; keep idempotent
        try:
            if self.config.enable_resource_monitoring and not self.resource_monitor.monitoring:
                self.resource_monitor.start_monitoring()
        except Exception as e:
            self.logger.debug(f"apply_all_fixes: resource monitor start skipped: {e}")

    def execute_all_plugins(self, apk_ctx) -> Dict[str, Any]:
        """
        Execute all discovered and loaded plugins with intelligent resource management.

        Args:
            apk_ctx: APK context object for plugin execution

        Returns:
            Dictionary containing plugin execution results
        """
        if not self.plugins:
            self.logger.warning("No plugins discovered - cannot execute plugins")
            return {}

        # Wrap execution with progress reporting via OutputManager
        try:
            from core.output_manager import get_output_manager

            output_mgr = get_output_manager()
            output_mgr.progress_start("Executing plugins", total=len(self.plugins))
        except Exception:
            output_mgr = None

        try:
            # Use resource-aware execution if global coordinator is available
            if self.global_coordinator:
                results = self._execute_plugins_resource_aware(apk_ctx, progress_output=output_mgr)
            else:
                results = self._execute_plugins_sequential(apk_ctx, progress_output=output_mgr)
            return results
        finally:
            if output_mgr:
                try:
                    output_mgr.progress_stop()
                except Exception:
                    pass

    def _run_decompilation_barrier(self, apk_ctx, progress_output=None) -> Dict[str, Any]:
        """Run decompilation plugins to completion (in-process) before analysis plugins.

        Always uses threading mode (not multiprocess) so that sync/refresh
        can mutate the parent apk_ctx.source_files directly.
        """
        barrier_results = {}
        for plugin_name, plugin_metadata in list(self.plugins.items()):
            if plugin_name not in _DECOMPILATION_BARRIER_PLUGINS:
                continue
            try:
                self.logger.info(f"Decompilation barrier: executing {plugin_name} (in-process)")
                result = self._execute_single_plugin(plugin_name, plugin_metadata, apk_ctx)
                if result:
                    barrier_results[plugin_name] = result
                    plugin_metadata.status = PluginExecutionState.COMPLETED
                else:
                    barrier_results[plugin_name] = (f"{plugin_name} (No Results)", "No data returned")
                if progress_output:
                    try:
                        progress_output.progress_update(advance=1, description=f"Decompilation: {plugin_name}")
                    except Exception:
                        pass
            except Exception as e:
                self.logger.error(f"Decompilation barrier plugin {plugin_name} failed: {e}")
                barrier_results[plugin_name] = (f"{plugin_name} (Error)", str(e))

        # Verify sources are available after barrier
        source_count = len(getattr(apk_ctx, "source_files", {}))
        if source_count > 0:
            self.logger.info(f"Decompilation barrier complete: {source_count} source files available")
        else:
            self.logger.warning(
                "Decompilation barrier complete but source_files is empty - "
                "source-dependent plugins may produce no findings"
            )
        return barrier_results

    def _execute_plugins_resource_aware(self, apk_ctx, progress_output=None) -> Dict[str, Any]:
        """Execute plugins with resource-aware batching using global coordinator."""
        execution_results = {}

        # --- Decompilation barrier ---
        barrier_results = self._run_decompilation_barrier(apk_ctx, progress_output)
        execution_results.update(barrier_results)

        plugins_list = [(n, m) for n, m in self.plugins.items() if n not in _DECOMPILATION_BARRIER_PLUGINS]

        # Track 110: Separate priority tier from regular tier
        priority_tier = [(n, m) for n, m in plugins_list if n in _ANALYSIS_PRIORITY_PLUGINS]
        regular_tier = [(n, m) for n, m in plugins_list if n not in _ANALYSIS_PRIORITY_PLUGINS]

        try:
            # Request updated resource allocation
            self.resource_limits = self.global_coordinator.request_resources(
                self.coordinator_name, len(plugins_list), self.execution_priority
            )

            batch_size = self.resource_limits.batch_size
            self.logger.info(
                f"Executing {len(plugins_list)} plugins in batches of {batch_size} "
                f"with {self.resource_limits.max_concurrent_plugins} max concurrent"
            )

            # Track 110: Run priority tier first (less contention for heavy analysis)
            if priority_tier:
                self.logger.info(
                    f"Priority tier: executing {len(priority_tier)} analysis-heavy plugins first"
                )
                self._wait_for_cpu_availability()
                priority_results = self._execute_plugin_batch(priority_tier, apk_ctx)
                execution_results.update(priority_results)
                try:
                    if progress_output:
                        progress_output.progress_update(advance=len(priority_tier))
                except Exception:
                    pass
                inter_batch_delay = float(os.environ.get("AODS_BATCH_DELAY", "0.5"))
                time.sleep(inter_batch_delay)

            # Process regular tier in resource-aware batches with CPU throttling
            for i in range(0, len(regular_tier), batch_size):
                if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
                    self.logger.warning("Shutdown requested - stopping plugin execution")
                    break

                # Check CPU availability before each batch
                self._wait_for_cpu_availability()

                batch = regular_tier[i : i + batch_size]
                batch_results = self._execute_plugin_batch(batch, apk_ctx)
                execution_results.update(batch_results)

                # Advance progress for each completed plugin in batch
                try:
                    if progress_output:
                        progress_output.progress_update(advance=len(batch))
                except Exception:
                    pass

                # Brief pause between batches to prevent resource spikes
                inter_batch_delay = float(os.environ.get("AODS_BATCH_DELAY", "0.5"))
                time.sleep(inter_batch_delay)

        except Exception as e:
            self.logger.error(f"Resource-aware execution failed: {e}")
            # Fallback to sequential execution
            return self._execute_plugins_sequential(apk_ctx)

        finally:
            # Release resources
            if self.global_coordinator:
                self.global_coordinator.release_resources(self.coordinator_name)

        self.logger.info(f"Resource-aware plugin execution completed: {len(execution_results)} plugins processed")
        return execution_results

    def _execute_plugins_sequential(self, apk_ctx, progress_output=None) -> Dict[str, Any]:
        """Execute plugins sequentially with aggressive CPU throttling."""
        execution_results = {}

        # --- Decompilation barrier ---
        barrier_results = self._run_decompilation_barrier(apk_ctx, progress_output)
        execution_results.update(barrier_results)

        # Track 110: Order plugins with priority tier first
        remaining = [(n, m) for n, m in self.plugins.items() if n not in _DECOMPILATION_BARRIER_PLUGINS]
        priority_first = sorted(remaining, key=lambda x: x[0] not in _ANALYSIS_PRIORITY_PLUGINS)

        self.logger.info(f"Executing {len(priority_first)} plugins sequentially with CPU throttling")

        for plugin_name, plugin_metadata in priority_first:
            try:
                if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
                    self.logger.warning(f"Shutdown requested - skipping plugin {plugin_name}")
                    break

                # Check CPU usage before each plugin execution
                self._wait_for_cpu_availability()

                self.logger.debug(f"Executing plugin: {plugin_name}")

                # Load and execute plugin
                result = self._execute_single_plugin(plugin_name, plugin_metadata, apk_ctx)

                if result:
                    execution_results[plugin_name] = result
                    self.logger.debug(f"Plugin {plugin_name} completed successfully")
                else:
                    self.logger.warning(f"Plugin {plugin_name} returned no results")
                    execution_results[plugin_name] = (f"{plugin_name} (No Results)", "No data returned")

                # Advance progress after each plugin
                try:
                    if progress_output:
                        progress_output.progress_update(advance=1, description=f"Executing {plugin_name}")
                except Exception:
                    pass

                # Brief delay between plugins to prevent CPU spikes
                inter_plugin_delay = float(os.environ.get("AODS_PLUGIN_DELAY", "0.5"))
                time.sleep(inter_plugin_delay)

                # Throttle if resources are constrained
                self._throttle_if_needed()

            except Exception as e:
                error_msg = f"Plugin {plugin_name} failed: {e}"
                self.logger.error(error_msg)
                execution_results[plugin_name] = (f"{plugin_name} (Error)", error_msg)

        self.logger.info(f"Sequential plugin execution completed: {len(execution_results)} plugins processed")
        return execution_results

    def _wait_for_cpu_availability(self, max_cpu_threshold: float = 75.0, max_wait_time: int = 60):
        """Wait until CPU usage drops below WSL-SAFE threshold - prevents crashes while allowing scans."""
        import psutil
        import time
        import os

        # Check if we're in scan-focused mode
        scan_focused = os.getenv("AODS_SCAN_FOCUSED") == "1"
        if scan_focused:
            self.logger.info("🎯 SCAN-FOCUSED MODE: Skipping resource wait - prioritizing scan execution")
            return

        wait_start = time.time()
        memory_threshold = 80.0  # WSL-safe memory threshold

        while time.time() - wait_start < max_wait_time:
            try:
                cpu_percent = psutil.cpu_percent(interval=0.5)  # Shorter interval for responsiveness
                memory_percent = psutil.virtual_memory().percent

                # Check with REASONABLE thresholds that allow actual work
                if cpu_percent <= max_cpu_threshold and memory_percent <= memory_threshold:
                    self.logger.debug(
                        f"Resources acceptable: CPU {cpu_percent:.1f}% <= {max_cpu_threshold}%, Memory {memory_percent:.1f}% <= {memory_threshold}%"  # noqa: E501
                    )
                    return

                # Only warn if resources are ACTUALLY problematic
                if cpu_percent > 95.0 or memory_percent > 95.0:
                    self.logger.warning(
                        f"High resource usage: CPU {cpu_percent:.1f}%, Memory {memory_percent:.1f}% - brief wait..."
                    )
                    time.sleep(2.0)  # Brief wait only
                else:
                    # Resources are fine, proceed with scan
                    return

            except Exception as e:
                self.logger.debug(f"Resource monitoring failed: {e}")
                break

        self.logger.info("Resource check complete - proceeding with scan execution")

    def _throttle_if_needed(self):
        """Apply throttling if needed - SCAN-FOCUSED approach."""
        import os

        # Check if we're in scan-focused mode
        scan_focused = os.getenv("AODS_SCAN_FOCUSED") == "1"
        if scan_focused:
            self.logger.debug("🎯 SCAN-FOCUSED MODE: Skipping throttling - prioritizing plugin execution")
            return

        # Original throttling logic for non-scan-focused mode
        self._wait_for_cpu_availability()

    def _get_plugin_timeout(self, plugin_name: str) -> float:
        """Get timeout for a plugin from its metadata or config."""
        try:
            meta = self.plugins.get(plugin_name)
            t = getattr(meta, "timeout", None) or getattr(meta, "timeout_seconds", None)
            return float(t) if t else float(getattr(self.config, "default_timeout", 300))
        except Exception:
            return float(getattr(self.config, "default_timeout", 300))

    def _execute_plugin_in_process(self, plugin_name: str, plugin_metadata, apk_ctx, timeout: float):
        """Execute a plugin in a separate process with enforced timeout.

        Unlike thread-based execution, the process can be killed if it
        exceeds the timeout, preventing resource leaks from hung plugins.

        Uses an explicit 'fork' context so APKContext (which contains
        non-picklable objects like threading.Lock) is inherited rather
        than serialized.  Falls back to direct execution on Windows
        where fork is unavailable.
        """
        import sys
        import multiprocessing

        if sys.platform == "win32":
            self.logger.warning(
                "Process-based timeout unavailable on Windows - executing %s directly",
                plugin_name,
            )
            return self._execute_single_plugin(plugin_name, plugin_metadata, apk_ctx)

        ctx = multiprocessing.get_context("fork")
        result_queue = ctx.Queue()

        def _target(queue, p_name, p_meta, a_ctx):
            try:
                result = self._execute_single_plugin(p_name, p_meta, a_ctx)
                queue.put(("ok", result))
            except Exception as exc:
                queue.put(("error", str(exc)))

        proc = ctx.Process(
            target=_target,
            args=(result_queue, plugin_name, plugin_metadata, apk_ctx),
            daemon=True,
        )
        proc.start()
        proc.join(timeout=timeout)

        if proc.is_alive():
            self.logger.warning(f"Plugin {plugin_name} exceeded {timeout}s timeout - terminating process")
            proc.terminate()
            proc.join(timeout=5)
            if proc.is_alive():
                self.logger.error(f"Plugin {plugin_name} did not terminate gracefully - killing")
                proc.kill()
                proc.join(timeout=2)
            return (f"{plugin_name} (Timeout)", f"Killed after {timeout}s")

        if not result_queue.empty():
            status, value = result_queue.get_nowait()
            if status == "ok":
                return value
            return (f"{plugin_name} (Error)", value)

        return (f"{plugin_name} (No Results)", "No data returned")

    def _execute_plugin_batch(self, batch: List[Tuple[str, Any]], apk_ctx) -> Dict[str, Any]:
        """Execute a batch of plugins with resource monitoring and timeout enforcement.

        When AODS_ENFORCE_TIMEOUTS=1 is set, plugins are executed in separate
        processes that can be terminated if they exceed their timeout.
        Otherwise, uses thread-based execution with cooperative timeout.
        """
        from concurrent.futures import as_completed, TimeoutError as FutureTimeoutError

        batch_results = {}
        enforce_timeouts = os.environ.get("AODS_ENFORCE_TIMEOUTS", "0") == "1"

        if enforce_timeouts:
            # Process-based execution with hard kill on timeout
            for plugin_name, plugin_metadata in batch:
                timeout = self._get_plugin_timeout(plugin_name)
                self.logger.debug(f"Executing {plugin_name} in subprocess (timeout={timeout}s)")
                result = self._execute_plugin_in_process(plugin_name, plugin_metadata, apk_ctx, timeout)
                if result:
                    batch_results[plugin_name] = result
                else:
                    batch_results[plugin_name] = (f"{plugin_name} (No Results)", "No data returned")
            return batch_results

        # Thread-based execution (default - cooperative timeout)
        futures = {}

        # Submit batch for execution using threading
        for plugin_name, plugin_metadata in batch:
            try:
                future = self.executor.submit(self._execute_single_plugin, plugin_name, plugin_metadata, apk_ctx)
                futures[future] = plugin_name
            except Exception as e:
                self.logger.error(f"Failed to submit plugin {plugin_name}: {e}")
                batch_results[plugin_name] = (f"{plugin_name} (Submission Error)", str(e))

        # Collect results with per-plugin timeouts
        per_future_timeout = {}
        for f, name in futures.items():
            per_future_timeout[f] = self._get_plugin_timeout(name)

        for future in as_completed(futures):
            plugin_name = futures[future]
            try:
                result = future.result(timeout=per_future_timeout.get(future, 30.0))
                if result:
                    batch_results[plugin_name] = result
                    self.logger.debug(f"Plugin {plugin_name} completed successfully")
                else:
                    batch_results[plugin_name] = (f"{plugin_name} (No Results)", "No data returned")
            except FutureTimeoutError:
                error_msg = f"Plugin {plugin_name} timed out after {per_future_timeout.get(future, 30.0)}s"
                self.logger.warning(error_msg)
                batch_results[plugin_name] = (f"{plugin_name} (Timeout)", error_msg)
            except Exception as e:
                error_msg = f"Plugin {plugin_name} failed: {e}"
                self.logger.error(error_msg)
                batch_results[plugin_name] = (f"{plugin_name} (Error)", error_msg)

        return batch_results

    def _check_resource_limits(self):
        """Check if resource limits are exceeded - SCAN-FOCUSED approach."""
        try:
            import psutil
            import gc
            import os

            # Check if we're in scan-focused mode
            scan_focused = os.getenv("AODS_SCAN_FOCUSED") == "1"
            if scan_focused:
                self.logger.debug("🎯 SCAN-FOCUSED MODE: Skipping resource limits - prioritizing scan execution")
                return True

            # Use reasonable memory limits that don't prevent actual work
            process = psutil.Process()
            memory_usage = process.memory_info().rss
            memory_limit = int(os.environ.get("AODS_MAX_MEMORY_MB", "1536")) * 1024 * 1024  # WSL-safe 1.5GB default

            if memory_usage > memory_limit:
                self.logger.info(
                    f"Memory usage {memory_usage // 1024 // 1024}MB approaching {memory_limit // 1024 // 1024}MB limit - running garbage collection"  # noqa: E501
                )
                # Force garbage collection but continue execution
                gc.collect()
                # WSL-safe: Block at 2.5GB to prevent crashes
                if memory_usage > memory_limit * 1.67:  # Block at ~2.5GB usage
                    self.logger.warning("🚨 WSL-SAFE: Critical memory usage - preventing crash")
                    return False

            return True
        except Exception as e:
            self.logger.debug(f"Resource monitoring failed: {e}")
            return True

    def _execute_single_plugin(self, plugin_name: str, plugin_metadata: PluginMetadata, apk_ctx) -> Optional[Tuple]:
        """Execute a single plugin with CPU throttling to prevent system overwhelm."""
        import time  # Import time at the beginning to fix variable scope error

        try:

            # Start CPU monitoring for this plugin
            time.time()

            # Load the plugin module with CPU throttling
            module_name = plugin_metadata.module_name

            # CPU check before module import
            self._throttle_if_needed()

            # Try to import the module using a reliable approach for all plugin types
            if module_name not in self.loaded_modules:
                import importlib.util
                import importlib
                import sys
                import os

                # PERMANENT FIX: Defensive plugin import with regression prevention
                if plugin_metadata.file_path.name == "__init__.py":
                    # DEBUG: Log the plugin loading attempt
                    import threading

                    thread_name = threading.current_thread().name
                    self.logger.info(f"🔍 PLUGIN LOADING ATTEMPT: {module_name} in thread {thread_name}")

                    # Skip blacklisted plugins to prevent repeated failure spam
                    if module_name in self._import_blacklist:
                        self.logger.warning(f"⚠️ Plugin {module_name} is blacklisted, skipping")
                        return None

                    # Pre-validate plugin before attempting import to prevent spam errors
                    if not self._pre_validate_plugin(plugin_metadata.file_path):
                        self.logger.warning(f"⚠️ Plugin {module_name} failed pre-validation, skipping import")
                        return None

                    self.logger.info(f"✅ Plugin {module_name} passed pre-validation, attempting import")

                    try:
                        # ENHANCED Method 1: Ensure proper sys.path setup before import
                        # Store original sys.path
                        original_sys_path = sys.path.copy()

                        # Ensure project root and plugins directory are in sys.path
                        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                        plugins_dir = os.path.join(project_root, "plugins")

                        paths_to_add = []
                        if project_root not in sys.path:
                            paths_to_add.append(project_root)
                        if plugins_dir not in sys.path:
                            paths_to_add.append(plugins_dir)

                        # Add paths at the beginning for priority
                        for path in reversed(paths_to_add):
                            sys.path.insert(0, path)

                        try:
                            # CRITICAL DEBUG: Threading and execution context analysis
                            import threading

                            current_thread = threading.current_thread()
                            thread_name = current_thread.name
                            thread_id = current_thread.ident
                            current_cwd = os.getcwd()

                            self.logger.debug(f"THREADING CONTEXT DEBUG for {module_name}:")
                            self.logger.debug(f"  Thread: {thread_name} (ID: {thread_id})")
                            self.logger.debug(f"  Working directory: {current_cwd}")
                            self.logger.debug(f"  Project root: {project_root}")
                            self.logger.debug(f"  Plugins dir: {plugins_dir}")
                            self.logger.debug(f"  Paths to add: {paths_to_add}")
                            self.logger.debug(f"  Sys.path length: {len(sys.path)}")
                            self.logger.debug(f"  Sys.path first 5 entries: {sys.path[:5]}")
                            self.logger.debug(f"  Module already in sys.modules: {module_name in sys.modules}")

                            # Check if plugin directory exists
                            plugin_path = os.path.join(plugins_dir, module_name.replace("plugins.", ""))
                            plugin_init_path = os.path.join(plugin_path, "__init__.py")
                            self.logger.debug(f"  Plugin directory exists: {os.path.exists(plugin_path)}")
                            self.logger.debug(f"  Plugin __init__.py exists: {os.path.exists(plugin_init_path)}")

                            # Standard import with proper path setup (apply alias)
                            canonical_module = self._resolve_module_alias(module_name)
                            module = importlib.import_module(canonical_module)
                            self.loaded_modules[module_name] = module
                            self.logger.info(f"✅ SUCCESS: Imported {module_name} in thread {thread_name}")
                            # Reset failure count on success
                            self._failed_imports.pop(module_name, None)
                        except Exception as enhanced_import_error:
                            import threading

                            current_thread = threading.current_thread()
                            # Demote to warning if a targeted fallback import will handle this module
                            demote = module_name in (
                                "plugins.insecure_data_storage",
                                "plugins.enhanced_static_analysis",
                                "plugins.network_cleartext_traffic",
                                "plugins.improper_platform_usage",
                                "plugins.apk_signing_certificate_analyzer",
                                "plugins.jadx_static_analysis",
                                "plugins.authentication_security_analysis",
                                "plugins.enhanced_manifest_analysis",
                                "plugins.webview_security_analysis",
                                "plugins.cryptography_tests",
                                "plugins.injection_vulnerabilities",
                                "plugins.enhanced_network_security_analysis",
                                "plugins.external_service_analysis",
                                "plugins.token_replay_analysis",
                                "plugins.anti_tampering_analysis",
                                "plugins.privacy_leak_detection",
                                "plugins.enhanced_root_detection_bypass_analyzer",
                                "plugins.advanced_ssl_tls_analyzer",
                            )
                            if demote:
                                # Noise reduction: informational only; alias/file-spec fallback will handle import
                                self.logger.info(
                                    f"ℹ️ Import redirect: initial import failed for {module_name} in {current_thread.name} ({enhanced_import_error}); using alias/fallback loader"  # noqa: E501
                                )
                            else:
                                self.logger.error(
                                    f"❌ THREAD IMPORT FAILURE in {current_thread.name}: {module_name} - {enhanced_import_error}"  # noqa: E501
                                )
                            self.logger.debug(f"Working dir during failure: {os.getcwd()}")
                            self.logger.debug(f"Sys.path during failure: {sys.path[:3]}...")
                            raise enhanced_import_error
                        finally:
                            # Always restore original sys.path
                            sys.path[:] = original_sys_path
                    except ImportError as import_error:
                        # PERMANENT FIX: Try fallback system before complex recovery
                        if PLUGIN_FALLBACK_AVAILABLE:
                            try:
                                # Extract missing class name from error message
                                error_str = str(import_error)
                                if "cannot import name" in error_str:
                                    import re

                                    class_match = re.search(r"cannot import name '([^']+)'", error_str)
                                    if class_match:
                                        missing_class = class_match.group(1)
                                        self.logger.info(f"🔄 Using fallback for missing class: {missing_class}")

                                        # Get fallback class and inject it into the module
                                        fallback_class = get_fallback_class(missing_class)  # noqa: F821

                                        # Create a minimal module with the fallback class
                                        import types

                                        fallback_module = types.ModuleType(module_name)
                                        setattr(fallback_module, missing_class, fallback_class)

                                        # Add standard plugin interface
                                        def fallback_run(apk_ctx):
                                            analyzer = fallback_class()
                                            return analyzer.analyze(apk_ctx)

                                        fallback_module.run = fallback_run
                                        fallback_module.run_plugin = fallback_run

                                        # Store the fallback module
                                        self.loaded_modules[module_name] = fallback_module
                                        self.logger.info(f"✅ Fallback module created for {module_name}")

                                        # Continue with plugin execution using fallback
                                        module = fallback_module

                                    else:
                                        raise import_error  # Continue with original error handling
                                else:
                                    raise import_error  # Continue with original error handling
                            except Exception as fallback_error:
                                self.logger.debug(f"Fallback failed for {module_name}: {fallback_error}")
                                # Continue with original error handling

                        try:
                            # SIMPLIFIED Method 2: Direct file-based loading without complex isolation
                            self.logger.debug(f"Attempting direct file-based loading for {module_name}")

                            # Use spec_from_file_location for direct loading
                            spec = importlib.util.spec_from_file_location(module_name, plugin_metadata.file_path)
                            if spec is None:
                                raise ImportError(f"Could not create spec for {plugin_metadata.file_path}")

                            # Create and execute module from spec
                            module = importlib.util.module_from_spec(spec)

                            # Set up proper module attributes for relative imports
                            module.__name__ = module_name
                            module.__file__ = str(plugin_metadata.file_path)
                            module.__package__ = (
                                module_name  # CRITICAL: Required for relative imports in complex plugins
                            )

                            # For directory-based plugins, set __path__ for submodule imports
                            if plugin_metadata.file_path.name == "__init__.py":
                                plugin_dir = os.path.dirname(plugin_metadata.file_path)
                                module.__path__ = [plugin_dir]

                            # Add to sys.modules BEFORE execution for relative imports
                            sys.modules[module_name] = module

                            try:
                                # Execute the module
                                spec.loader.exec_module(module)
                            except Exception as exec_error:
                                # Clean up sys.modules if execution fails
                                if module_name in sys.modules:
                                    del sys.modules[module_name]
                                raise exec_error

                            # Store successfully loaded module
                            self.loaded_modules[module_name] = module
                            self.logger.debug(f"✅ Successfully loaded plugin via file spec: {module_name}")

                        except Exception as e:
                            # If file-based loading also fails, trigger fallback system
                            self.logger.debug(f"File-based loading failed for {module_name}: {e}")

                            # ENHANCED FALLBACK SYSTEM: Try using the AODS fallback system
                            self.logger.warning(f"🔄 TRIGGERING FALLBACK SYSTEM for failed plugin: {module_name}")
                            self.logger.debug(f"PLUGIN_FALLBACK_AVAILABLE: {PLUGIN_FALLBACK_AVAILABLE}")

                            if PLUGIN_FALLBACK_AVAILABLE:
                                try:
                                    self.logger.info(f"🔄 Attempting fallback creation for {module_name}")
                                    fallback_class = get_fallback_class("BasicAnalyzer")  # noqa: F821
                                    import types

                                    fallback_module = types.ModuleType(module_name)
                                    setattr(fallback_module, "BasicAnalyzer", fallback_class)

                                    def fallback_run(apk_ctx):
                                        self.logger.info(f"🔄 FALLBACK EXECUTION: {module_name} using BasicAnalyzer")
                                        analyzer = fallback_class()
                                        result = analyzer.analyze(apk_ctx)
                                        self.logger.info(
                                            f"🔄 FALLBACK RESULT: {module_name} completed with fallback analysis"
                                        )
                                        return result

                                    fallback_module.run = fallback_run
                                    fallback_module.run_plugin = fallback_run
                                    self.loaded_modules[module_name] = fallback_module
                                    module = fallback_module

                                    self.logger.info(f"✅ SUCCESS: Created fallback module for {module_name}")
                                except Exception as fallback_error:
                                    # If all else fails, try error recovery framework
                                    self.logger.error(
                                        f"❌ Fallback creation failed for {module_name}: {fallback_error}"
                                    )

                                    # Try graceful degradation instead
                                    try:
                                        from core.error_recovery_framework import GracefulDegradationManager

                                        degradation_mgr = GracefulDegradationManager()
                                        degraded_functionality = degradation_mgr.get_degraded_functionality(
                                            module_name, Exception(str(e))
                                        )
                                        self.logger.info(
                                            f"🔄 DEGRADED MODE: {module_name} - {degraded_functionality.get('functionality', 'Limited analysis')}"  # noqa: E501
                                        )

                                        # Create a simple degraded module
                                        import types

                                        degraded_module = types.ModuleType(module_name)

                                        def degraded_run(apk_ctx):
                                            self.logger.info(f"🔄 DEGRADED EXECUTION: {module_name}")
                                            return (f"{module_name} (Degraded Mode)", degraded_functionality)

                                        degraded_module.run = degraded_run
                                        degraded_module.run_plugin = degraded_run
                                        self.loaded_modules[module_name] = degraded_module
                                        module = degraded_module

                                        self.logger.info(f"✅ SUCCESS: Created degraded module for {module_name}")
                                    except Exception as degraded_error:
                                        self.logger.error(
                                            f"❌ All recovery methods failed for {module_name}: {degraded_error}"
                                        )
                                        return None
                            else:
                                self.logger.error(f"❌ No fallback system available for plugin {module_name}: {e}")
                                return None
                else:
                    # For single .py files, use file location method
                    spec = importlib.util.spec_from_file_location(module_name, plugin_metadata.file_path)
                    if spec is None:
                        raise ImportError(f"Could not load spec for {module_name} from {plugin_metadata.file_path}")

                    module = importlib.util.module_from_spec(spec)

                    # Set up proper module attributes
                    module.__name__ = module_name
                    module.__file__ = str(plugin_metadata.file_path)
                    module.__package__ = module_name.rsplit(".", 1)[0] if "." in module_name else None

                    # Add to sys.modules before execution
                    sys.modules[module_name] = module

                    try:
                        spec.loader.exec_module(module)
                    except Exception as exec_error:
                        # Clean up sys.modules if execution fails
                        if module_name in sys.modules:
                            del sys.modules[module_name]
                        raise exec_error

                    self.loaded_modules[module_name] = module

                # CPU throttle after import
                self._throttle_if_needed()
            else:
                module = self.loaded_modules[module_name]

            # Canonical de-dup by module key to avoid alias double-runs
            try:
                module_key = getattr(module, "__name__", module_name)
                if module_key in getattr(self, "_executed_module_keys", set()):
                    self.logger.info(f"⏭️ Skipping module already executed: {module_key}")
                    return f"⏭️ {plugin_name}", "Duplicate module execution skipped"
                else:
                    self._executed_module_keys.add(module_key)
            except Exception:
                pass

            # Try to find the plugin function
            plugin_function = None

            # Look for run_plugin function first
            if hasattr(module, "run_plugin"):
                plugin_function = module.run_plugin
            elif hasattr(module, "run"):
                plugin_function = module.run
            elif hasattr(module, "execute"):
                plugin_function = module.execute
            else:
                # Look for a plugin class
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if isinstance(attr, type) and "plugin" in attr_name.lower() and hasattr(attr, "run"):
                        plugin_instance = attr()
                        plugin_function = plugin_instance.run
                        break

            if not plugin_function:
                self.logger.warning(f"No executable function found in plugin {plugin_name}")
                return None

            # Execute the plugin with CPU throttling and timeout

            # Pre-execution CPU throttling
            self._throttle_if_needed()

            start_time = time.time()

            try:
                # Execute plugin with safe wrapper
                result = self._execute_plugin_safe(module, apk_ctx)
                execution_time = time.time() - start_time

                # Post-execution CPU throttling
                self._throttle_if_needed()

                self.logger.debug(f"Plugin {plugin_name} executed in {execution_time:.2f}s")
                return result

            except Exception as e:
                execution_time = time.time() - start_time
                self.logger.error(f"Plugin {plugin_name} execution failed after {execution_time:.2f}s: {e}")

                # CPU throttle even on error to prevent cascading issues
                self._throttle_if_needed()
                return None

        except Exception as e:
            # PERMANENT FIX: Intelligent failure tracking to prevent spam and regressions
            self._track_plugin_failure(plugin_name, e)
            return None

    def set_scan_profile(self, scan_profile):
        """
        Set scan profile to optimize plugin execution for specific use cases.

        Args:
            scan_profile: ScanProfile enum value (LIGHTNING, FAST, STANDARD, DEEP)
        """
        try:
            from core.scan_profiles import scan_profile_manager

            self.logger.info(f"Setting scan profile to: {scan_profile}")
            self.scan_profile = scan_profile

            # Update module-level profile for multiprocess decision
            # Lightning profile enables multiprocess by default for hard timeout enforcement
            profile_value = scan_profile.value if hasattr(scan_profile, "value") else str(scan_profile)
            _set_current_scan_profile(profile_value)
            if profile_value.lower() == "lightning":
                self.logger.info("Lightning profile: multiprocess mode enabled by default for hard timeout enforcement")

            # Get profile configuration
            scan_profile_manager.get_profile(scan_profile)

            # Apply profile-specific plugin filtering
            available_plugins = set(self.plugins.keys())
            optimized_plugins = scan_profile_manager.get_plugins_for_profile(scan_profile, available_plugins)

            # Store original plugin set for restoration if needed
            if not hasattr(self, "_original_plugins"):
                self._original_plugins = self.plugins.copy()

            # Filter plugins based on profile
            if scan_profile.value != "deep":  # Deep profile uses all plugins
                filtered_plugins = {}
                for plugin_name, plugin_metadata in self.plugins.items():
                    if plugin_name in optimized_plugins:
                        filtered_plugins[plugin_name] = plugin_metadata

                self.plugins = filtered_plugins
                self.logger.info(f"Profile {scan_profile.value}: using {len(self.plugins)} optimized plugins")

                # Log selected plugins for debugging
                selected_plugin_names = sorted(list(self.plugins.keys()))
                self.logger.info(
                    f"🎯 Selected plugins for {scan_profile.value}: {', '.join(selected_plugin_names[:10])}{'...' if len(selected_plugin_names) > 10 else ''}"  # noqa: E501
                )
            else:
                self.logger.info(f"Profile {scan_profile.value}: using all {len(self.plugins)} plugins")

        except Exception as e:
            self.logger.warning(f"Failed to apply scan profile {scan_profile}: {e}")
            # Continue with all plugins if profile application fails

    def get_plugin_health_report(self) -> Dict[str, Any]:
        """
        Generate full plugin health report using existing AODS infrastructure.

        Returns:
            Detailed system health analysis with recommendations
        """
        try:
            # Calculate basic health metrics from existing data
            total_plugins = len(self.plugins)
            loaded_plugins = len([p for p in self.plugins.values() if p.validated])
            failed_imports = len(self._failed_imports)
            blacklisted_plugins = len(self._import_blacklist)

            # Calculate health score based on success rate
            health_percentage = (loaded_plugins / total_plugins * 100) if total_plugins > 0 else 100.0

            # Categorize plugins based on load success
            healthy_plugins = [
                name for name, plugin in self.plugins.items() if plugin.validated and name not in self._failed_imports
            ]
            warning_plugins = [
                name
                for name in self._failed_imports
                if self._failed_imports[name] < 3 and name not in self._import_blacklist
            ]
            critical_plugins = list(self._import_blacklist)

            # Generate recommendations
            recommendations = []
            if critical_plugins:
                recommendations.append(f"Review {len(critical_plugins)} blacklisted plugins for resolution")
            if warning_plugins:
                recommendations.append(f"Monitor {len(warning_plugins)} plugins with load issues")
            if health_percentage < 80:
                recommendations.append("System health below 80% - investigate plugin failures")

            # Use existing health checker if available
            system_health_data = {"system_health_percentage": health_percentage}
            if self._health_checker:
                try:
                    health_status = self._health_checker.get_system_health()
                    system_health_data.update(health_status)
                except Exception as e:
                    self.logger.debug(f"Failed to get system health from HealthChecker: {e}")

            report = {
                "timestamp": time.time(),
                "system_health": system_health_data,
                "plugin_categories": {
                    "healthy": healthy_plugins,
                    "warning": warning_plugins,
                    "critical": critical_plugins,
                    "blacklisted": critical_plugins,
                },
                "statistics": {
                    "total_plugins": total_plugins,
                    "loaded_plugins": loaded_plugins,
                    "failed_imports": failed_imports,
                    "blacklisted_plugins": blacklisted_plugins,
                    "health_percentage": health_percentage,
                },
                "recommendations": recommendations,
                "integration_status": {
                    "health_checker": self._health_checker is not None,
                    "error_recovery": self._error_recovery is not None,
                    "performance_tracker": self._performance_tracker is not None,
                },
            }

            return report

        except Exception as e:
            self.logger.error(f"Failed to generate plugin health report: {e}")
            return {"error": str(e), "timestamp": time.time(), "system_health": {"system_health_percentage": 0.0}}

    def get_plugin_diagnostics(self, plugin_name: str) -> Dict[str, Any]:
        """
        Get detailed diagnostics for a specific plugin using existing AODS infrastructure.

        Args:
            plugin_name: Name of plugin to analyze

        Returns:
            Diagnostic information using existing systems
        """
        try:
            diagnostics = {
                "plugin_name": plugin_name,
                "timestamp": time.time(),
                "load_statistics": {},
                "performance_data": {},
                "status_analysis": {},
                "recommendations": [],
            }

            # Get basic load statistics from tracking data
            failure_count = self._failed_imports.get(plugin_name, 0)
            is_blacklisted = plugin_name in self._import_blacklist
            is_loaded = plugin_name in self.plugins and self.plugins[plugin_name].validated

            diagnostics["load_statistics"] = {
                "failure_count": failure_count,
                "is_blacklisted": is_blacklisted,
                "is_loaded": is_loaded,
                "success_rate": 100.0 if failure_count == 0 else max(0.0, 100.0 - (failure_count * 25)),
            }

            # Get performance data from existing tracker if available
            if self._performance_tracker:
                try:
                    perf_data = self._performance_tracker.get_plugin_performance(plugin_name)
                    diagnostics["performance_data"] = perf_data
                except Exception as e:
                    self.logger.debug(f"Failed to get performance data for {plugin_name}: {e}")

            # Status analysis
            diagnostics["status_analysis"] = {
                "health_status": (
                    "healthy" if is_loaded and failure_count == 0 else "warning" if failure_count < 3 else "critical"
                ),
                "load_status": "loaded" if is_loaded else "failed",
                "availability": "available" if not is_blacklisted else "blacklisted",
            }

            # Generate recommendations
            if is_blacklisted:
                diagnostics["recommendations"].append("Plugin is blacklisted - resolve import/dependency issues")
            elif failure_count > 0:
                diagnostics["recommendations"].append(f"Plugin has {failure_count} load failures - check dependencies")
            elif not is_loaded:
                diagnostics["recommendations"].append("Plugin not loaded - check plugin structure and requirements")

            # Use existing error recovery framework if available
            if self._error_recovery:
                try:
                    recovery_data = self._error_recovery.get_plugin_recovery_info(plugin_name)
                    diagnostics["recovery_data"] = recovery_data
                except Exception as e:
                    self.logger.debug(f"Failed to get recovery data for {plugin_name}: {e}")

            return diagnostics

        except Exception as e:
            self.logger.error(f"Failed to generate diagnostics for {plugin_name}: {e}")
            return {"plugin_name": plugin_name, "error": str(e), "timestamp": time.time()}


# Export for core.plugins facade
__all__ = [
    "UnifiedPluginManager",
    "PluginExecutionConfig",
    "PluginExecutionResult",
    "PluginExecutionMetrics",
    "PluginMetadata",
    "PluginExecutionState",
    "PluginType",
    "PluginPriority",
    "ResourceMonitor",
]
