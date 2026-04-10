"""
AODS Execution Framework - Unified Facade
==========================================

This module provides the unified interface for all parallel execution,
scan orchestration, and execution management functionality in AODS.

Usage:
    from core.execution import ExecutionManager, ParallelExecutor

    # Unified execution interface
    executor = ExecutionManager()
    results = executor.run_parallel_analysis(plugins, targets)

Architectural Guidelines:
    - ALL parallel execution imports MUST go through this facade
    - No direct imports from core.unified_parallel_framework
    - No direct imports from core.parallel_* modules
    - Use this facade to maintain architectural boundaries
"""

# Version information
__version__ = "1.0.0"
__all__ = [
    # Core execution interfaces
    "ExecutionManager",
    "ParallelExecutor",
    "ScanOrchestrator",
    "UnifiedExecutionManager",  # Alias for ExecutionManager
    "ExecutionMode",  # Execution mode enumeration
    # Result types
    "ExecutionResult",
    "ScanResult",
    # Configuration
    "ExecutionConfig",
    "ParallelConfig",
    # Exceptions
    "ExecutionError",
    "TimeoutError",
    "ResourceError",
]

# Import warnings for deprecated modules
import logging
import warnings
import os
import json
import time
from pathlib import Path
import tempfile  # noqa: F401

# Import critical infrastructure components
from .adb_lifecycle_manager import (  # noqa: F401
    ADBLifecycleManager,
    DeviceInfo,
    DeviceState,
    ConnectionHealth,
    get_adb_lifecycle_manager,
    integrate_with_execution_manager,
)


def _warn_deprecated_import(old_module: str, new_interface: str):
    """Warn about deprecated direct imports."""
    warnings.warn(
        f"Direct import from '{old_module}' is deprecated. "
        f"Use 'from core.execution import {new_interface}' instead.",
        DeprecationWarning,
        stacklevel=3,
    )


def _atomic_write_json(path: Path, payload: dict) -> None:
    """
    Write JSON atomically by writing to a temp file in the same directory and renaming.
    This minimizes the chance of producing a partially written artifact.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp_path.replace(path)
    except Exception:
        # Best-effort; if atomic replace fails, fall back to direct write
        try:
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            pass


# Facade implementations connecting to unified framework


class ExecutionManager:
    """
    Unified execution manager providing single interface for all execution operations.

    This facade consolidates:
    - core.unified_parallel_framework
    - core.parallel_analysis_engine
    - core.parallel_scan_manager
    - core.enhanced_scan_orchestrator
    """

    def __init__(self, config=None):
        """Initialize execution manager with configuration."""
        self.config = config or {}

        # Import unified framework (lazy loading to avoid circular imports)
        from core.unified_parallel_framework import UnifiedParallelManager, UnifiedConfig  # noqa: F401

        # Merge with unified configuration manager defaults if available
        try:
            from core.shared_infrastructure.configuration import UnifiedConfigurationManager

            _ucm = UnifiedConfigurationManager()
            # Pull common execution defaults if present
            max_workers_cfg = _ucm.get_configuration_value("execution.max_workers", self.config.get("max_workers", 4))
            timeout_cfg = _ucm.get_configuration_value("execution.timeout_seconds", self.config.get("timeout", 300))
            memory_limit_cfg = _ucm.get_configuration_value(
                "execution.memory_limit_gb", self.config.get("memory_limit_gb", 8.0)
            )
            enable_monitoring_cfg = _ucm.get_configuration_value(
                "execution.enable_performance_monitoring", self.config.get("enable_monitoring", True)
            )
            # Normalize types
            try:
                self.config["max_workers"] = int(max_workers_cfg)
            except Exception:
                self.config.setdefault("max_workers", 4)
            try:
                self.config["timeout"] = int(timeout_cfg)
            except Exception:
                self.config.setdefault("timeout", 300)
            try:
                self.config["memory_limit_gb"] = float(memory_limit_cfg)
            except Exception:
                self.config.setdefault("memory_limit_gb", 8.0)
            self.config["enable_monitoring"] = bool(enable_monitoring_cfg)
        except Exception:
            pass

        # Convert facade config to unified config
        unified_config = self._convert_config(config)
        self._manager = UnifiedParallelManager(unified_config)

        # Store the converted config for strategy initialization
        self._unified_config = unified_config

        # Execution tracking
        self._current_executions = {}
        self._execution_history = []

        self.logger = logging.getLogger(__name__)

        # Initialize critical infrastructure
        self._adb_manager = integrate_with_execution_manager(self)

        self.logger.info(
            "ExecutionManager initialized with full infrastructure",
            extra={
                "config": self.config,
                "adb_devices": len(self._adb_manager.get_available_devices()),
            },
        )

    def _convert_config(self, facade_config):
        """Convert facade configuration to unified framework configuration."""
        from core.unified_parallel_framework import UnifiedConfig

        if not facade_config:
            return UnifiedConfig()

        # Map facade config parameters to unified config
        return UnifiedConfig(
            max_workers=facade_config.get("max_workers", 4),
            memory_limit_gb=facade_config.get("memory_limit_gb", 8.0),
            timeout_seconds=facade_config.get("timeout", 300),
            enable_monitoring=facade_config.get("enable_monitoring", True),
            enable_caching=facade_config.get("enable_caching", True),
            retry_attempts=facade_config.get("retry_attempts", 3),
            preferred_strategy=facade_config.get("strategy"),
            enable_adaptive_selection=facade_config.get("adaptive", True),
            enable_process_separation=facade_config.get("process_separation", True),
        )

    def run_comprehensive_analysis(self, args):
        """
        Run full AODS analysis using canonical consolidated execution.

        This method provides the unified entry point for all AODS analysis modes:
        - Static analysis
        - Dynamic analysis
        - Parallel execution
        - Plugin orchestration
        - Report generation

        Args:
            args: Command line arguments from dyna.py

        Returns:
            dict: Analysis results with status and data
        """
        try:
            self.logger.info("Starting full AODS analysis via canonical execution")

            # Import required components through canonical paths
            from core.plugins import UnifiedPluginManager
            from core.shared_infrastructure.reporting import UnifiedReportingManager

            # Initialize components using dependency injection
            plugin_manager = UnifiedPluginManager()
            reporting_manager = UnifiedReportingManager()

            # Execute analysis workflow
            analysis_results = {"status": "success", "scan_results": {}, "vulnerabilities": [], "reports": {}}

            # Step 1: Plugin Discovery and Execution
            self.logger.info("Step 1: Plugin discovery and execution")
            # Use actual methods that exist in UnifiedPluginManager
            # Single discovery per scan; rely on manager guard and keep cached logs quiet
            plugin_discovery_count = plugin_manager.discover_plugins(force_rediscovery=False, quiet_cached=True)
            self.logger.info(f"Discovered {plugin_discovery_count} plugins")

            # Create APK context (simplified for now - would need actual APK context from args)
            from core.apk_ctx import APKContext

            apk_ctx = APKContext(args.apk, args.pkg) if hasattr(args, "apk") and hasattr(args, "pkg") else None

            if apk_ctx:
                plugin_results = plugin_manager.execute_all_plugins(apk_ctx)
                analysis_results["scan_results"] = plugin_results

                # Step 2: Vulnerability Processing
                self.logger.info("Step 2: Vulnerability processing and enhancement")
                if plugin_results and "vulnerabilities" in plugin_results:
                    analysis_results["vulnerabilities"] = plugin_results["vulnerabilities"]
                elif plugin_results:
                    # Extract vulnerabilities from plugin results if in different format
                    vulnerabilities = []
                    for plugin_result in plugin_results.get("results", []):
                        if isinstance(plugin_result, dict) and "vulnerabilities" in plugin_result:
                            vulnerabilities.extend(plugin_result["vulnerabilities"])
                    analysis_results["vulnerabilities"] = vulnerabilities

                # Step 3: Report Generation
                self.logger.info("Step 3: Report generation using unified reporting")
                if analysis_results["vulnerabilities"]:
                    # Use actual method that exists in UnifiedReportingManager
                    report_results = reporting_manager.generate_security_report(analysis_results["vulnerabilities"])
                    analysis_results["reports"] = report_results
            else:
                self.logger.warning("Cannot create APK context - missing APK path or package name")
                return {"status": "error", "error": "Missing required APK context"}

            # Step 4: Success Summary
            vulnerability_count = len(analysis_results["vulnerabilities"])
            self.logger.info(
                f"Canonical execution completed successfully: {vulnerability_count} vulnerabilities analyzed"
            )

            return analysis_results

        except Exception as e:
            self.logger.error(f"Canonical execution failed: {e}")
            import traceback

            self.logger.debug(f"Canonical execution traceback: {traceback.format_exc()}")
            return {"status": "error", "error": str(e)}

    def run_parallel_analysis(self, plugins, targets, config=None):
        """Run parallel analysis using unified execution framework."""
        from core.unified_parallel_framework import create_plugin_task

        execution_id = f"exec_{len(self._execution_history)}"

        # Log execution start
        self.logger.info(
            "Starting parallel analysis execution",
            extra={
                "execution_id": execution_id,
                "plugin_count": len(plugins),
                "target_count": len(targets),
                "total_tasks": len(plugins) * len(targets),
            },
        )

        # Check device availability
        available_devices = self._adb_manager.get_available_devices()
        if available_devices:
            self.logger.info(
                f"Available devices: {len(available_devices)}",
                extra={"devices": [{"id": d.device_id, "model": d.model} for d in available_devices]},
            )
        else:
            self.logger.warning("No available devices detected")

        try:
            # Convert plugins and targets to unified framework tasks
            tasks = []
            for plugin in plugins:
                for target in targets:
                    task = create_plugin_task(
                        plugin_function=plugin,
                        apk_path=target.get("apk_path") if isinstance(target, dict) else target,
                        plugin_metadata={"name": getattr(plugin, "__name__", "unknown")},
                    )
                    tasks.append(task)

            # Execute through unified framework with bounded retries/backoff (opt-in via env)
            retry_attempts = 0
            min_success = 0.0
            backoff_ms = 250
            try:
                retry_attempts = int(os.getenv("AODS_EXEC_RETRY_ATTEMPTS", "0"))
                min_success = float(os.getenv("AODS_EXEC_RETRY_MIN_SUCCESS", "0.99"))
                backoff_ms = int(os.getenv("AODS_EXEC_RETRY_BACKOFF_MS", "250"))
            except Exception:
                pass

            summary = self._manager.execute_parallel(tasks)
            if retry_attempts > 0 and summary.success_rate < min_success:
                for attempt in range(retry_attempts):
                    delay = max(0, backoff_ms * (2**attempt)) / 1000.0
                    if delay > 0:
                        self.logger.info(
                            f"Retry {attempt + 1}/{retry_attempts} after backoff {delay:.3f}s due to success_rate={summary.success_rate:.3f} < {min_success:.3f}"  # noqa: E501
                        )
                        time.sleep(delay)
                    try:
                        retry_summary = self._manager.execute_parallel(tasks)
                        self.logger.info(
                            "Retry completed",
                            extra={
                                "attempt": attempt + 1,
                                "success_rate": retry_summary.success_rate,
                                "total_time": retry_summary.total_execution_time,
                            },
                        )
                        if (retry_summary.success_rate > summary.success_rate) or (
                            retry_summary.success_rate >= min_success
                        ):
                            summary = retry_summary
                        if summary.success_rate >= min_success:
                            break
                    except Exception as re:
                        self.logger.warning(f"Retry attempt {attempt + 1} failed: {re}")

            # Get resource usage from unified manager
            resource_usage = {}
            if hasattr(self._manager.resource_monitor, "get_performance_summary"):
                perf_summary = self._manager.resource_monitor.get_performance_summary()
                resource_usage = {
                    "memory_mb": perf_summary.get("peak_memory_mb", 0),
                    "cpu_percent": perf_summary.get("peak_cpu_percent", 0),
                    "avg_memory_percent": perf_summary.get("average_memory_percent", 0),
                    "avg_cpu_percent": perf_summary.get("average_cpu_percent", 0),
                }

            # Store execution for status tracking
            self._current_executions[execution_id] = summary
            self._execution_history.append(summary)

            # Log successful completion
            self.logger.info(
                "Parallel analysis execution completed successfully",
                extra={
                    "execution_id": execution_id,
                    "success_rate": summary.success_rate,
                    "total_time": summary.total_execution_time,
                    "strategy_used": summary.strategy_used,
                    "efficiency": summary.parallel_efficiency,
                },
            )

            # Emit structured runtime metrics (opt-in via env)
            try:
                if os.getenv("AODS_EMIT_RUNTIME_METRICS", "1") == "1":
                    out_dir = Path("artifacts/ci_gates")
                    out_dir.mkdir(parents=True, exist_ok=True)
                    out_path = out_dir / "runtime_metrics.json"
                    metrics_payload = {
                        "success_rate": summary.success_rate,
                        "total_tasks": summary.total_tasks,
                        "successful_tasks": summary.successful_tasks,
                        "failed_tasks": summary.failed_tasks,
                        "timeouts": getattr(summary, "timeouts", 0),
                        "execution_time": summary.total_execution_time,
                        "strategy_used": summary.strategy_used,
                    }
                    try:
                        _atomic_write_json(out_path, metrics_payload)
                    except Exception:
                        pass
            except Exception:
                pass

            return {
                "execution_id": execution_id,
                "correlation_id": execution_id,
                "success": summary.success_rate > 0.8,
                "total_tasks": summary.total_tasks,
                "successful_tasks": summary.successful_tasks,
                "failed_tasks": summary.failed_tasks,
                "execution_time": summary.total_execution_time,
                "strategy_used": summary.strategy_used,
                "efficiency": summary.parallel_efficiency,
                "resource_usage": resource_usage,
                "available_devices": len(available_devices),
                "results": [result.result for result in summary.results if result.success],
            }

        except Exception as e:
            self.logger.error(
                "Parallel execution failed",
                extra={"execution_id": execution_id, "error": str(e), "error_type": type(e).__name__},
            )

            # Emit failure metrics (opt-in via env)
            try:
                if os.getenv("AODS_EMIT_RUNTIME_METRICS", "1") == "1":
                    out_dir = Path("artifacts/ci_gates")
                    out_dir.mkdir(parents=True, exist_ok=True)
                    out_path = out_dir / "runtime_metrics.json"
                    fail_payload = {
                        "success_rate": 0.0,
                        "total_tasks": 0,
                        "successful_tasks": 0,
                        "failed_tasks": 1,
                        "timeouts": 0,
                        "execution_time": 0,
                        "strategy_used": "unknown",
                        "error": str(e),
                    }
                    try:
                        _atomic_write_json(out_path, fail_payload)
                    except Exception:
                        pass
            except Exception:
                pass

            return {
                "execution_id": execution_id,
                "correlation_id": execution_id,
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
                "execution_time": 0,
                "results": [],
            }

    def get_execution_status(self, execution_id=None):
        """Get current execution status."""
        if execution_id:
            if execution_id in self._current_executions:
                summary = self._current_executions[execution_id]
                return {
                    "execution_id": execution_id,
                    "status": "completed",
                    "success_rate": summary.success_rate,
                    "total_tasks": summary.total_tasks,
                    "strategy_used": summary.strategy_used,
                    "resource_utilization": summary.resource_utilization,
                }
            else:
                return {"error": f"Execution {execution_id} not found"}
        else:
            # Return status of all executions
            return {
                "total_executions": len(self._execution_history),
                "recent_executions": [
                    {
                        "execution_id": f"exec_{i}",
                        "success_rate": summary.success_rate,
                        "strategy_used": summary.strategy_used,
                        "execution_time": summary.total_execution_time,
                    }
                    for i, summary in enumerate(self._execution_history[-5:])
                ],
            }

    def run_contract_tests(self) -> dict:
        """Run full contract tests on execution components."""
        components = {
            "execution_manager": self,
            "adb_manager": self._adb_manager,
        }

        # Add ParallelExecutor if available
        if hasattr(self, "_manager") and hasattr(self._manager, "strategies"):
            # Get a strategy instance for testing
            strategies = self._manager.strategies
            if strategies:
                components["parallel_executor"] = list(strategies.values())[0]

        return self._contract_suite.run_contract_tests(components)

    def get_governance_status(self) -> dict:
        """Get full governance and compliance status."""
        return {
            "adb_status": self._adb_manager.get_status_summary(),
            "infrastructure_health": {
                "adb_devices": len(self._adb_manager.get_available_devices()),
            },
        }


class ParallelExecutor:
    """Simplified parallel executor for basic parallel operations."""

    def __init__(self, max_workers=None):
        """Initialize parallel executor."""
        self.max_workers = max_workers or 4

        # Import and initialize unified framework
        from core.unified_parallel_framework import UnifiedParallelManager, UnifiedConfig

        config = UnifiedConfig(max_workers=self.max_workers)
        self._manager = UnifiedParallelManager(config)

    def execute(self, tasks):
        """Execute tasks in parallel."""
        from core.unified_parallel_framework import create_custom_task

        # Convert generic tasks to unified framework tasks
        unified_tasks = []
        for i, task in enumerate(tasks):
            if callable(task):
                # Task is a function
                unified_task = create_custom_task(task_function=task, task_id=f"task_{i}", metadata={"index": i})
            elif isinstance(task, dict) and "function" in task:
                # Task is a dictionary with function and args
                unified_task = create_custom_task(
                    task_function=task["function"],
                    task_id=task.get("id", f"task_{i}"),
                    metadata=task.get("metadata", {}),
                    context=task.get("context", {}),
                )
            else:
                raise ValueError(f"Invalid task format: {task}")

            unified_tasks.append(unified_task)

        # Execute through unified framework
        try:
            summary = self._manager.execute_parallel(unified_tasks)

            return {
                "success": summary.success_rate > 0.8,
                "results": [result.result for result in summary.results],
                "execution_time": summary.total_execution_time,
                "strategy_used": summary.strategy_used,
                "efficiency": summary.parallel_efficiency,
            }

        except Exception as e:
            return {"success": False, "error": str(e), "results": []}


class ScanOrchestrator:
    """Unified scan orchestration interface."""

    def __init__(self, config=None):
        """Initialize scan orchestrator with unified execution framework."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Use proper unified execution framework instead of deprecated ParallelScanManager
        from .unified_manager import UnifiedExecutionManager, ExecutionMode

        # Initialize unified execution manager
        self._execution_manager = UnifiedExecutionManager()

        # Set up execution context
        self._execution_mode = ExecutionMode.PARALLEL  # Default to parallel execution

    def orchestrate_scan(self, apk_path, scan_config):
        """Orchestrate complete scan workflow using unified execution framework."""
        try:
            # Create APK context for unified execution
            from core.apk_ctx import APKContext

            apk_ctx = APKContext(apk_path_str=apk_path, package_name=scan_config.get("package_name", ""))

            # Store APK context for future enhancements
            self.apk_context = apk_ctx

            # SCAN PROFILE OPTIMIZATION: Use UnifiedPluginManager with proper scan profile support
            try:
                from core.plugins import UnifiedPluginManager
                from core.scan_profiles import ScanProfile

                # Map profile string to ScanProfile enum
                profile_map = {
                    "lightning": ScanProfile.LIGHTNING,
                    "fast": ScanProfile.FAST,
                    "standard": ScanProfile.STANDARD,
                    "deep": ScanProfile.DEEP,
                }

                # Get scan profile from config (default to standard)
                profile_name = scan_config.get("profile", "standard")
                scan_profile = profile_map.get(profile_name, ScanProfile.STANDARD)

                # Create UnifiedPluginManager with scan profile optimization
                plugin_manager = UnifiedPluginManager()
                plugin_manager.set_scan_profile(scan_profile)

                self.logger.info(
                    f"🎯 ScanOrchestrator using {scan_profile.value} profile with {len(plugin_manager.plugins)} plugins"
                )

                # Get optimized plugin metadata objects for the selected profile
                discovered_plugins = list(plugin_manager.plugins.values())

            except Exception as e:
                self.logger.warning(f"Failed to use UnifiedPluginManager with scan profiles: {e}")
                # Fallback to create_plugin_manager
                from core.plugins import create_plugin_manager

                plugin_manager = create_plugin_manager(
                    scan_mode=scan_config.get("mode", "safe"),
                    vulnerable_app_mode=scan_config.get("vulnerable_app_mode", False),
                )
                # Load plugins to enable traditional AODS system (required for proper initialization)
                plugin_manager.load_plugins()
                discovered_plugins = (
                    plugin_manager.get_available_plugins() if hasattr(plugin_manager, "get_available_plugins") else []
                )
                # Set profile_name for fallback case to ensure timeout optimization still works
                profile_name = scan_config.get("profile", "standard")

            self.logger.info(f"🔧 Unified orchestrator discovered {len(discovered_plugins)} plugins")

            # Execute using unified execution manager with discovered plugins
            execution_result = self._execution_manager.execute(
                plugins=discovered_plugins,  # Pass discovered plugins, not empty list
                apk_ctx=apk_ctx,
                mode=self._execution_mode,
                scan_profile=profile_name,  # Pass scan profile for timeout optimization
                vulnerable_app_mode=scan_config.get("vulnerable_app_mode", False),
                scan_types=scan_config.get("scan_types", ["static", "dynamic"]),
                disable_static_analysis=scan_config.get("disable_static_analysis", False),
                disable_dynamic_analysis=scan_config.get("disable_dynamic_analysis", False),
                timeout=scan_config.get("static_timeout", 1800),
            )

            # Perform result consolidation if enabled
            consolidated_results = execution_result.results
            if scan_config.get("consolidate", True):
                consolidated_results = self._consolidate_results(execution_result.results, scan_config)

            # Convert unified result to expected format
            return {
                "success": execution_result.success,
                "static_results": self._extract_static_results(execution_result.results),
                "dynamic_results": self._extract_dynamic_results(execution_result.results),
                "consolidated_results": consolidated_results,
                "execution_time": execution_result.execution_time,
                "scan_summary": {
                    "strategy_used": execution_result.strategy_used,
                    "total_plugins": execution_result.total_plugins,
                    "successful_plugins": execution_result.successful_plugins,
                    "failed_plugins": execution_result.failed_plugins,
                },
            }

        except Exception as e:
            logger.error(f"Unified scan orchestration failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "execution_time": 0,
                "static_results": None,
                "dynamic_results": None,
                "consolidated_results": None,
                "scan_summary": {},
            }

    def _extract_static_results(self, unified_results):
        """Extract static analysis results from unified execution results."""
        static_results = {}

        # Extract static analysis plugin results
        for plugin_name, plugin_result in unified_results.items():
            if self._is_static_plugin(plugin_name):
                static_results[plugin_name] = plugin_result

        return static_results

    def _extract_dynamic_results(self, unified_results):
        """Extract dynamic analysis results from unified execution results."""
        dynamic_results = {}

        # Extract dynamic analysis plugin results
        for plugin_name, plugin_result in unified_results.items():
            if self._is_dynamic_plugin(plugin_name):
                dynamic_results[plugin_name] = plugin_result

        return dynamic_results

    def _is_static_plugin(self, plugin_name):
        """Determine if a plugin is for static analysis."""
        static_keywords = [
            "static",
            "manifest",
            "jadx",
            "decompil",
            "code_quality",
            "certificate",
            "signing",
            "permission",
            "component",
            "library",
            "dependency",
            "binary",
        ]
        plugin_lower = plugin_name.lower()
        return any(keyword in plugin_lower for keyword in static_keywords)

    def _is_dynamic_plugin(self, plugin_name):
        """Determine if a plugin is for dynamic analysis."""
        dynamic_keywords = [
            "dynamic",
            "frida",
            "runtime",
            "objection",
            "hook",
            "instrumentation",
            "behavior",
            "execution",
            "memory",
            "network",
            "traffic",
            "interaction",
        ]
        plugin_lower = plugin_name.lower()
        return any(keyword in plugin_lower for keyword in dynamic_keywords)

    def _consolidate_results(self, results, scan_config):
        """Consolidate scan results using the unified consolidation framework."""
        try:
            from .consolidation.consolidation_manager import ModularConsolidationManager, ConsolidationConfig
            from .consolidation.consolidation_manager import ConsolidationType

            # Create consolidation configuration
            consolidation_config = ConsolidationConfig(
                strategy_type=ConsolidationType.STATIC_DYNAMIC,
                enable_deduplication=True,
                enable_prioritization=True,
                enable_filtering=True,
            )

            # Initialize consolidation manager
            consolidation_manager = ModularConsolidationManager(consolidation_config)

            # Future: Enhanced evidence collection integration here

            # Perform consolidation
            consolidated_result = consolidation_manager.consolidate_results(results)

            return consolidated_result.findings if consolidated_result else results

        except Exception as e:
            logger.warning(f"Result consolidation failed: {e}, returning raw results")
            return results


# Result types
class ExecutionResult:  # noqa: F811
    """Standard execution result container."""

    def __init__(self, success=False, data=None, errors=None):
        """Initialize execution result."""
        self.success = success
        self.data = data or {}
        self.errors = errors or []


class ScanResult:
    """Standard scan result container."""

    def __init__(self, apk_path="", results=None, metadata=None):
        """Initialize scan result."""
        self.apk_path = apk_path
        self.results = results or {}
        self.metadata = metadata or {}


# Configuration classes
class ExecutionConfig:
    """Execution configuration container."""

    def __init__(self, **kwargs):
        """Initialize execution configuration."""
        self.max_workers = kwargs.get("max_workers", 4)
        self.timeout = kwargs.get("timeout", 300)
        self.retry_count = kwargs.get("retry_count", 3)


class ParallelConfig:
    """Parallel execution configuration."""

    def __init__(self, **kwargs):
        """Initialize parallel configuration."""
        self.strategy = kwargs.get("strategy", "thread")
        self.max_parallel = kwargs.get("max_parallel", 4)
        self.resource_limits = kwargs.get("resource_limits", {})


# Exceptions
class ExecutionError(Exception):
    """Base execution error."""


class TimeoutError(ExecutionError):
    """Execution timeout error."""


class ResourceError(ExecutionError):
    """Resource limit exceeded error."""


# Import ExecutionMode from unified framework
try:
    from core.unified_parallel_framework.execution_engine import ExecutionMode as UnifiedExecutionMode

    # Create compatibility ExecutionMode with backward compatibility for parallel_scan_manager
    from enum import Enum

    class ExecutionMode(Enum):
        # Map to unified framework values for compatibility
        SEQUENTIAL = "sequential"
        PARALLEL = "thread_based"
        PROCESS_SEPARATED = "process_based"
        ADAPTIVE = "adaptive"
        # Additional unified framework modes
        THREAD_BASED = "thread_based"
        PROCESS_BASED = "process_based"
        HYBRID = "hybrid"
        PLUGIN_OPTIMIZED = "plugin_optimized"
        ANALYSIS_SEPARATED = "analysis_separated"

        @classmethod
        def to_unified_mode(cls, mode):
            """Convert to unified framework ExecutionMode."""
            mapping = {
                cls.SEQUENTIAL: UnifiedExecutionMode.SEQUENTIAL,
                cls.PARALLEL: UnifiedExecutionMode.THREAD_BASED,
                cls.PROCESS_SEPARATED: UnifiedExecutionMode.PROCESS_BASED,
                cls.ADAPTIVE: UnifiedExecutionMode.ADAPTIVE,
                cls.THREAD_BASED: UnifiedExecutionMode.THREAD_BASED,
                cls.PROCESS_BASED: UnifiedExecutionMode.PROCESS_BASED,
                cls.HYBRID: UnifiedExecutionMode.HYBRID,
                cls.PLUGIN_OPTIMIZED: UnifiedExecutionMode.PLUGIN_OPTIMIZED,
                cls.ANALYSIS_SEPARATED: UnifiedExecutionMode.ANALYSIS_SEPARATED,
            }
            return mapping.get(mode, UnifiedExecutionMode.ADAPTIVE)

except ImportError:
    # Fallback ExecutionMode if unified framework not available
    from enum import Enum

    class ExecutionMode(Enum):
        PARALLEL = "parallel"
        SEQUENTIAL = "sequential"
        PROCESS_SEPARATED = "process_separated"
        ADAPTIVE = "adaptive"

        @classmethod
        def to_unified_mode(cls, mode):
            """Fallback method when unified framework not available."""
            return mode


# Create alias for UnifiedExecutionManager to point to ExecutionManager
UnifiedExecutionManager = ExecutionManager


# Canonical factory functions for AODS_CANONICAL execution path
from .unified_manager import create_execution_manager, UnifiedExecutionManager  # noqa: F401, E402

# Create alias for canonical execution
ExecutionManager = UnifiedExecutionManager

# Import dynamic timeout management for enhanced performance
try:
    from core.timeout.dynamic_timeout_manager import DynamicTimeoutManager, create_dynamic_timeout_manager  # noqa: F401

    DYNAMIC_TIMEOUT_AVAILABLE = True
except ImportError:
    DYNAMIC_TIMEOUT_AVAILABLE = False

# Log facade initialization

logger = logging.getLogger(__name__)
logger.info("AODS Execution Facade initialized - Phase 0 structure ready for Phase 1 implementation")
if DYNAMIC_TIMEOUT_AVAILABLE:
    logger.info("🔥 Dynamic Timeout Management enabled - performance optimization active")
