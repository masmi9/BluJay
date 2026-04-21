#!/usr/bin/env python3
"""
Parallel Execution Strategy

Thread-based parallel plugin execution strategy consolidating logic from:
- ParallelAnalysisEngine
- Individual plugin ThreadPoolExecutor implementations
- Enhanced parallel execution systems
"""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Any, Dict, List, Optional, Tuple

from .base_strategy import ExecutionStrategy, StrategyResult
from ..shared.plugin_executor import PluginExecutor, PluginExecutionResult, PluginStatus

logger = logging.getLogger(__name__)


class ParallelExecutionStrategy(ExecutionStrategy):
    """
    Thread-based parallel execution strategy.

    Consolidates parallel execution logic from multiple systems while
    eliminating code duplication.
    """

    def __init__(self, config: Any, plugin_executor: PluginExecutor):
        """Initialize parallel execution strategy."""
        super().__init__(config, plugin_executor)
        self.strategy_name = "Parallel"

        # Parallel execution state
        self._active_futures: Dict[Future, Any] = {}
        self._execution_lock = threading.RLock()

        logger.info(f"Parallel execution strategy initialized with {self.config.max_workers} workers")

    def can_execute(self, plugins: List[Any], context: Dict[str, Any]) -> bool:
        """Check if parallel execution is suitable for the given plugins."""
        # Don't use parallel for very few plugins
        if len(plugins) < self.config.parallel_threshold_plugins:
            return False

        # Check system resources
        if not self.config.enable_parallel_execution:
            return False

        # Check for plugins that require sequential execution
        sequential_plugins = self._count_sequential_only_plugins(plugins)
        if sequential_plugins > len(plugins) * 0.7:  # More than 70% require sequential
            return False

        return True

    def execute(self, plugins: List[Any], apk_ctx: Any, context: Optional[Dict[str, Any]] = None) -> StrategyResult:
        """
        Execute plugins in parallel using thread pool.

        Args:
            plugins: List of plugins to execute
            apk_ctx: APK context for analysis
            context: Additional execution context

        Returns:
            StrategyResult with execution details
        """
        start_time = time.time()
        context = context or {}

        self.logger.info(f"Starting parallel execution of {len(plugins)} plugins")

        # Create strategy result
        result = StrategyResult(strategy_name=self.strategy_name, total_plugins=len(plugins), start_time=start_time)

        try:
            # Filter plugins for parallel execution
            parallel_plugins, sequential_plugins = self._categorize_plugins(plugins)

            # Execute parallel plugins
            if parallel_plugins:
                parallel_results = self._execute_parallel_plugins(parallel_plugins, apk_ctx)
                result.plugin_results.update(parallel_results)

            # Execute sequential plugins (if any)
            if sequential_plugins:
                self.logger.info(f"Executing {len(sequential_plugins)} plugins sequentially")
                sequential_results = self._execute_sequential_plugins(sequential_plugins, apk_ctx)
                result.plugin_results.update(sequential_results)

            # Calculate final statistics
            result.execution_time = time.time() - start_time
            result.successful_plugins = sum(1 for r in result.plugin_results.values() if r.success)
            result.failed_plugins = sum(1 for r in result.plugin_results.values() if r.failed)
            result.success = result.failed_plugins == 0

            self.logger.info(
                f"Parallel execution completed in {result.execution_time:.2f}s "
                f"({result.successful_plugins}/{result.total_plugins} successful)"
            )

        except Exception as e:
            result.execution_time = time.time() - start_time
            result.error = str(e)
            result.success = False
            self.logger.error(f"Parallel execution failed: {e}")

        return result

    def _execute_parallel_plugins(self, plugins: List[Any], apk_ctx: Any) -> Dict[str, PluginExecutionResult]:
        """Execute plugins in parallel using thread pool."""
        results = {}

        # Determine optimal worker count
        max_workers = min(self.config.max_workers, len(plugins))

        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="AODS-Parallel") as executor:

            # Submit all plugins for execution
            future_to_plugin = {}
            for plugin in plugins:
                future = executor.submit(self._execute_single_plugin, plugin, apk_ctx)
                future_to_plugin[future] = plugin

            # Collect results as they complete
            with self._execution_lock:
                self._active_futures = future_to_plugin.copy()

            # MAXIMUM DETECTION SOLUTION: Adaptive timeout with detection preservation
            # Strategy: Allow plugins time to find vulnerabilities, but prevent system collapse

            # Tier 1: Fast plugins (should complete quickly)
            fast_plugins = [
                "enhanced_manifest_analysis",
                "apk_signing_certificate_analyzer",
                "improper_platform_usage",
                "network_cleartext_traffic",
            ]

            # Tier 2: Medium plugins (moderate complexity)
            medium_plugins = [
                "cryptography_tests",
                "authentication_security_analysis",
                "webview_security_analysis",
                "privacy_controls_analysis",
            ]

            # Tier 3: Heavy plugins (complex analysis, need more time)
            heavy_plugins = [
                "frida_dynamic_analysis",
                "enhanced_static_analysis",
                "runtime_decryption_analysis",
                "jadx_static_analysis",
            ]

            completed_count = 0
            total_plugins = len(future_to_plugin)
            start_time = time.time()  # Track execution start time

            # DETECTION-FIRST APPROACH: Process plugins as they complete, with adaptive timeouts
            for future in as_completed(future_to_plugin):
                plugin = future_to_plugin[future]
                plugin_name = self.plugin_executor._get_plugin_name(plugin)

                try:
                    # Adaptive timeout based on plugin complexity and system state
                    if plugin_name in fast_plugins:
                        individual_timeout = 60  # 1 minute for fast plugins
                    elif plugin_name in medium_plugins:
                        individual_timeout = 180  # 3 minutes for medium plugins
                    elif plugin_name in heavy_plugins:
                        individual_timeout = 600  # 10 minutes for heavy plugins (MAXIMUM DETECTION)
                    else:
                        individual_timeout = 300  # 5 minutes default

                    # DETECTION PRESERVATION: Give plugins adequate time to find vulnerabilities
                    plugin_result = future.result(timeout=individual_timeout)
                    results[plugin_name] = plugin_result
                    completed_count += 1

                    self.logger.info(
                        f"✅ Plugin '{plugin_name}' completed ({completed_count}/{total_plugins}): {plugin_result.status.value}"  # noqa: E501
                    )

                    # SUCCESS METRIC: Log if plugin found vulnerabilities
                    if hasattr(plugin_result, "result") and plugin_result.result:
                        vuln_count = 0
                        if isinstance(plugin_result.result, dict):
                            vuln_count = len(plugin_result.result.get("vulnerabilities", []))
                        elif isinstance(plugin_result.result, list):
                            vuln_count = len(plugin_result.result)

                        if vuln_count > 0:
                            self.logger.info(f"🔍 Plugin '{plugin_name}' found {vuln_count} potential vulnerabilities")

                except Exception as e:
                    # GRACEFUL DEGRADATION: Don't let one plugin failure stop others
                    error_result = PluginExecutionResult(
                        plugin_name=plugin_name,
                        status=PluginStatus.TIMEOUT if "timeout" in str(e).lower() else PluginStatus.FAILED,
                        error=str(e),
                        result=self.plugin_executor._create_error_result(plugin_name, str(e)),
                    )
                    results[plugin_name] = error_result
                    completed_count += 1

                    # DETECTION IMPACT LOGGING: Distinguish between timeouts and real failures
                    if "timeout" in str(e).lower():
                        self.logger.warning(
                            f"⏰ Plugin '{plugin_name}' timed out ({completed_count}/{total_plugins}) - may have missed vulnerabilities"  # noqa: E501
                        )
                    else:
                        self.logger.warning(
                            f"❌ Plugin '{plugin_name}' failed ({completed_count}/{total_plugins}): {e}"
                        )

                # Remove from active futures
                with self._execution_lock:
                    if future in self._active_futures:
                        del self._active_futures[future]

                # SYSTEM HEALTH CHECK: If too many plugins are hanging, implement emergency measures
                if completed_count < total_plugins * 0.3 and time.time() - start_time > 1800:  # 30 minutes
                    self.logger.warning(
                        f"🚨 EMERGENCY: Only {completed_count}/{total_plugins} plugins completed in 30 minutes"
                    )
                    self.logger.warning("Implementing emergency timeout to preserve partial results...")

                    # Cancel remaining plugins but preserve what we have
                    for remaining_future, remaining_plugin in future_to_plugin.items():
                        remaining_plugin_name = self.plugin_executor._get_plugin_name(remaining_plugin)
                        if remaining_plugin_name not in results:
                            remaining_future.cancel()

                            emergency_result = PluginExecutionResult(
                                plugin_name=remaining_plugin_name,
                                status=PluginStatus.TIMEOUT,
                                error="Emergency timeout - system preservation",
                                result=self.plugin_executor._create_error_result(
                                    remaining_plugin_name, "Emergency timeout"
                                ),
                            )
                            results[remaining_plugin_name] = emergency_result
                            self.logger.warning(f"🚨 Emergency timeout: {remaining_plugin_name}")
                    break

        return results

    def _execute_sequential_plugins(self, plugins: List[Any], apk_ctx: Any) -> Dict[str, PluginExecutionResult]:
        """Execute plugins sequentially (for those that can't run in parallel)."""
        results = {}

        for plugin in plugins:
            plugin_name = self.plugin_executor._get_plugin_name(plugin)
            try:
                plugin_result = self._execute_single_plugin(plugin, apk_ctx)
                results[plugin_name] = plugin_result

                self.logger.debug(f"Sequential plugin '{plugin_name}' completed: {plugin_result.status.value}")

            except Exception as e:
                error_result = PluginExecutionResult(
                    plugin_name=plugin_name,
                    status=PluginStatus.FAILED,
                    error=str(e),
                    result=self.plugin_executor._create_error_result(plugin_name, str(e)),
                )
                results[plugin_name] = error_result
                self.logger.error(f"Sequential plugin '{plugin_name}' failed: {e}")

        return results

    def _execute_single_plugin(self, plugin: Any, apk_ctx: Any) -> PluginExecutionResult:
        """Execute a single plugin using the unified plugin executor."""
        return self.plugin_executor.execute_plugin(plugin, apk_ctx)

    def _categorize_plugins(self, plugins: List[Any]) -> Tuple[List[Any], List[Any]]:
        """
        Categorize plugins into parallel-safe and sequential-only.

        Returns:
            Tuple of (parallel_plugins, sequential_plugins)
        """
        parallel_plugins = []
        sequential_plugins = []

        for plugin in plugins:
            if self._is_plugin_parallel_safe(plugin):
                parallel_plugins.append(plugin)
            else:
                sequential_plugins.append(plugin)

        return parallel_plugins, sequential_plugins

    def _is_plugin_parallel_safe(self, plugin: Any) -> bool:
        """Check if plugin is safe for parallel execution."""
        plugin_name = self.plugin_executor._get_plugin_name(plugin).lower()

        # Plugins that should run sequentially
        sequential_patterns = [
            "anti_tampering",  # May interfere with other plugins
            "root_detection",  # Device state dependent
            "device_manager",  # Device access conflicts
        ]

        # Check if plugin explicitly supports parallel execution
        if hasattr(plugin, "supports_parallel"):
            return getattr(plugin, "supports_parallel", True)

        # Check for sequential-only patterns
        for pattern in sequential_patterns:
            if pattern in plugin_name:
                return False

        # Default to parallel-safe
        return True

    def _count_sequential_only_plugins(self, plugins: List[Any]) -> int:
        """Count plugins that require sequential execution."""
        count = 0
        for plugin in plugins:
            if not self._is_plugin_parallel_safe(plugin):
                count += 1
        return count

    def get_active_executions(self) -> Dict[str, Dict[str, Any]]:
        """Get information about currently active plugin executions."""
        with self._execution_lock:
            active_info = {}
            for future, plugin in self._active_futures.items():
                plugin_name = self.plugin_executor._get_plugin_name(plugin)
                active_info[plugin_name] = {
                    "running": future.running(),
                    "done": future.done(),
                    "cancelled": future.cancelled(),
                }
            return active_info

    def cancel_execution(self) -> bool:
        """Cancel all active plugin executions."""
        cancelled_count = 0

        with self._execution_lock:
            for future in list(self._active_futures.keys()):
                if future.cancel():
                    cancelled_count += 1

        self.logger.info(f"Cancelled {cancelled_count} active plugin executions")
        return cancelled_count > 0
