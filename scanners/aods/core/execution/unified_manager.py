#!/usr/bin/env python3
"""
Unified Execution Manager

Main orchestrator for all execution strategies, providing a single entry point
that eliminates duplication while preserving all execution modes.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from core.execution.shared import ConfigurationManager
from core.execution import ExecutionMode
from .shared.plugin_executor import PluginExecutor, PluginExecutionResult

# Migrated to canonical timeout system (Phase 7)
from core.timeout import UnifiedTimeoutManager as TimeoutManager
from .strategies.base_strategy import ExecutionStrategy, StrategyResult
from .strategies.parallel_strategy import ParallelExecutionStrategy
from .strategies.sequential_strategy import SequentialExecutionStrategy
from .strategies.process_strategy import ProcessSeparationStrategy
from .strategies.adaptive_strategy import AdaptiveExecutionStrategy

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Result of unified execution."""

    strategy_used: str
    total_plugins: int
    successful_plugins: int
    failed_plugins: int
    execution_time: float
    results: Dict[str, Any]
    success: bool
    error: Optional[str] = None
    statistics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionContext:
    """Context for plugin execution."""

    apk_ctx: Any
    mode: ExecutionMode
    additional_context: Dict[str, Any] = field(default_factory=dict)


class UnifiedExecutionManager:
    """
    Unified execution manager providing single entry point for all execution modes.

    This manager eliminates duplication by:
    - Using shared components (timeout, resource monitoring, etc.)
    - Providing strategy-based execution (parallel, process, sequential, adaptive)
    - Maintaining full backward compatibility with existing interfaces
    - Offering consistent configuration and error handling
    """

    def __init__(self, config: Optional[dict] = None):
        """Initialize unified execution manager."""
        self.config_manager = ConfigurationManager()
        try:
            unified_cfg = self.config_manager.get_configuration()
            self.config = getattr(unified_cfg, "execution", unified_cfg)
        except Exception:
            self.config = type("ExecCfg", (), {})()
        self.logger = logging.getLogger(__name__)

        # Normalize expected attributes for strategies
        try:
            if not hasattr(self.config, "max_workers"):
                # Map common unified field to expected name
                if hasattr(self.config, "max_concurrent_processes"):
                    setattr(self.config, "max_workers", getattr(self.config, "max_concurrent_processes"))
                else:
                    setattr(self.config, "max_workers", 1)
        except Exception:
            pass

        # Initialize shared components (eliminates duplication)
        self.timeout_manager = TimeoutManager()
        self.plugin_executor = PluginExecutor(self.timeout_manager)

        # Initialize execution strategies
        self.strategies = self._initialize_strategies()

        # Execution state
        self.current_execution: Optional[StrategyResult] = None
        self._execution_history: List[ExecutionResult] = []

        self.logger.info(f"Unified execution manager initialized with {len(self.strategies)} strategies")

    def _initialize_strategies(self) -> Dict[str, ExecutionStrategy]:
        """Initialize all available execution strategies."""
        strategies = {}

        try:
            strategies[ExecutionMode.PARALLEL.value] = ParallelExecutionStrategy(self.config, self.plugin_executor)
            logger.debug("Parallel strategy initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize parallel strategy: {e}")

        try:
            strategies[ExecutionMode.SEQUENTIAL.value] = SequentialExecutionStrategy(self.config, self.plugin_executor)
            logger.debug("Sequential strategy initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize sequential strategy: {e}")

        try:
            strategies[ExecutionMode.PROCESS_SEPARATED.value] = ProcessSeparationStrategy(
                self.config, self.plugin_executor
            )
            logger.debug("Process separation strategy initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize process separation strategy: {e}")

        try:
            strategies[ExecutionMode.ADAPTIVE.value] = AdaptiveExecutionStrategy(self.config, self.plugin_executor)
            logger.debug("Adaptive strategy initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize adaptive strategy: {e}")

        logger.info(f"Initialized {len(strategies)} execution strategies")
        return strategies

    def execute(
        self,
        plugins: List[Any],
        apk_ctx: Any,
        mode: Optional[Union[str, ExecutionMode]] = None,
        scan_profile: Optional[str] = None,
        **kwargs,
    ) -> ExecutionResult:
        """
        Execute plugins using the unified execution framework.

        Args:
            plugins: List of plugins to execute
            apk_ctx: APK context for analysis
            mode: Execution mode (parallel, process_separated, sequential, adaptive)
            **kwargs: Additional execution parameters

        Returns:
            ExecutionResult with full execution details
        """
        start_time = time.time()

        # Configure plugin executor with scan profile for timeout optimization
        if scan_profile:
            self.plugin_executor.set_scan_profile(scan_profile)
            self.logger.debug(f"Plugin executor configured with scan profile: {scan_profile}")

        # Normalize execution mode
        if mode is None:
            configured_mode = getattr(self.config, "scan_mode", None)
            try:
                execution_mode = ExecutionMode(configured_mode) if configured_mode else ExecutionMode.ADAPTIVE
            except Exception:
                execution_mode = ExecutionMode.ADAPTIVE
        elif isinstance(mode, str):
            execution_mode = ExecutionMode(mode.lower())
        else:
            execution_mode = mode

        self.logger.info(f"Starting unified execution: {len(plugins)} plugins, mode={execution_mode.value}")

        # Create execution context
        context = ExecutionContext(apk_ctx=apk_ctx, mode=execution_mode, additional_context=kwargs)

        # Select execution strategy
        strategy = self._select_strategy(execution_mode, plugins, context)
        if not strategy:
            # Fallback to any available strategy
            if self.strategies:
                strategy_name = list(self.strategies.keys())[0]
                strategy = self.strategies[strategy_name]
                self.logger.warning(f"Requested mode {execution_mode.value} unavailable, using {strategy_name}")
            else:
                raise RuntimeError("No execution strategies available")

        # Execute using selected strategy
        try:
            strategy_result = strategy.execute(plugins, apk_ctx, context.additional_context)
            self.current_execution = strategy_result

            # Convert to unified result format
            result = ExecutionResult(
                strategy_used=strategy_result.strategy_name,
                total_plugins=strategy_result.total_plugins,
                successful_plugins=strategy_result.successful_plugins,
                failed_plugins=strategy_result.failed_plugins,
                execution_time=strategy_result.execution_time,
                results=self._convert_plugin_results(strategy_result.plugin_results),
                success=strategy_result.success,
                error=strategy_result.error,
                statistics=self._gather_execution_statistics(strategy_result),
            )

            # Record in history
            self._execution_history.append(result)

            self.logger.info(
                f"Execution completed: {result.strategy_used}, "
                f"{result.successful_plugins}/{result.total_plugins} successful, "
                f"{result.execution_time:.2f}s"
            )

            return result

        except Exception as e:
            error_result = ExecutionResult(
                strategy_used=strategy.strategy_name if strategy else "unknown",
                total_plugins=len(plugins),
                successful_plugins=0,
                failed_plugins=len(plugins),
                execution_time=time.time() - start_time,
                results={},
                success=False,
                error=str(e),
            )

            self.logger.error(f"Execution failed: {e}")
            return error_result

    def _select_strategy(
        self, mode: ExecutionMode, plugins: List[Any], context: ExecutionContext
    ) -> Optional[ExecutionStrategy]:
        """Select execution strategy based on mode and context."""

        # Direct mode selection
        if mode.value in self.strategies:
            strategy = self.strategies[mode.value]

            # Check if strategy can handle the plugins
            if strategy.can_execute(plugins, context.additional_context):
                return strategy
            else:
                self.logger.warning(f"Strategy {mode.value} cannot handle current plugins")

        # Fallback selection for adaptive mode or failed direct selection
        suitable_strategies = []
        for strategy_name, strategy in self.strategies.items():
            if strategy.can_execute(plugins, context.additional_context):
                suitable_strategies.append((strategy_name, strategy))

        if suitable_strategies:
            # Prefer adaptive if available and requested
            if mode == ExecutionMode.ADAPTIVE:
                for name, strategy in suitable_strategies:
                    if name == ExecutionMode.ADAPTIVE.value:
                        return strategy

            # Return first suitable strategy
            return suitable_strategies[0][1]

        return None

    def _convert_plugin_results(self, plugin_results: Dict[str, PluginExecutionResult]) -> Dict[str, Any]:
        """Convert plugin execution results to legacy format."""
        converted = {}
        for plugin_name, result in plugin_results.items():
            if hasattr(result, "result") and result.result:
                converted[plugin_name] = result.result
            else:
                # Create tuple format for compatibility
                status = "✅" if result.success else "❌"
                converted[plugin_name] = (f"{status} {plugin_name}", result.error or "Unknown result")
        return converted

    def _gather_execution_statistics(self, strategy_result: StrategyResult) -> Dict[str, Any]:
        """Gather full execution statistics."""
        stats = {
            "strategy_name": strategy_result.strategy_name,
            "execution_time": strategy_result.execution_time,
            "success_rate": (
                strategy_result.successful_plugins / strategy_result.total_plugins
                if strategy_result.total_plugins > 0
                else 0
            ),
            "plugin_breakdown": {
                "total": strategy_result.total_plugins,
                "successful": strategy_result.successful_plugins,
                "failed": strategy_result.failed_plugins,
            },
        }

        # Add strategy-specific characteristics
        if hasattr(strategy_result, "get_execution_characteristics"):
            stats["strategy_characteristics"] = strategy_result.get_execution_characteristics()

        return stats

    def get_execution_statistics(self) -> Dict[str, Any]:
        """Get full execution statistics."""
        if not self._execution_history:
            return {
                "total_executions": 0,
                "strategy_usage": {},
                "average_execution_time": 0.0,
                "overall_success_rate": 0.0,
            }

        # Calculate strategy usage
        strategy_usage = {}
        total_time = 0.0
        total_success = 0
        total_plugins = 0

        for execution in self._execution_history:
            strategy = execution.strategy_used
            strategy_usage[strategy] = strategy_usage.get(strategy, 0) + 1
            total_time += execution.execution_time
            total_success += execution.successful_plugins
            total_plugins += execution.total_plugins

        return {
            "total_executions": len(self._execution_history),
            "strategy_usage": strategy_usage,
            "average_execution_time": total_time / len(self._execution_history),
            "overall_success_rate": total_success / total_plugins if total_plugins > 0 else 0.0,
            "available_strategies": list(self.strategies.keys()),
        }

    def get_strategy_details(self, strategy_name: str) -> Dict[str, Any]:
        """Get detailed information about a specific strategy."""
        if strategy_name not in self.strategies:
            return {"error": f"Strategy {strategy_name} not available"}

        strategy = self.strategies[strategy_name]
        details = {"name": strategy_name, "class": strategy.__class__.__name__, "available": True}

        # Get strategy characteristics if available
        if hasattr(strategy, "get_execution_characteristics"):
            details["characteristics"] = strategy.get_execution_characteristics()

        # Get strategy-specific statistics if available (for adaptive strategy)
        if hasattr(strategy, "get_strategy_statistics"):
            details["statistics"] = strategy.get_strategy_statistics()

        return details

    def shutdown(self):
        """Cleanup and shutdown execution manager."""
        self.logger.info("Shutting down unified execution manager...")

        # Cleanup strategies
        for strategy in self.strategies.values():
            if hasattr(strategy, "cleanup"):
                try:
                    strategy.cleanup()
                except Exception as e:
                    self.logger.warning(f"Error cleaning up strategy: {e}")

        # Clear state
        self.current_execution = None
        self._execution_history.clear()

        self.logger.info("Unified execution manager shutdown complete")

    # Backward compatibility methods
    def execute_plugins_parallel(self, plugins: List[Any], apk_ctx: Any) -> Dict[str, Any]:
        """Backward compatibility method for parallel execution."""
        result = self.execute(plugins, apk_ctx, mode=ExecutionMode.PARALLEL)
        return result.results

    def execute_plugins_sequential(self, plugins: List[Any], apk_ctx: Any) -> Dict[str, Any]:
        """Backward compatibility method for sequential execution."""
        result = self.execute(plugins, apk_ctx, mode=ExecutionMode.SEQUENTIAL)
        return result.results

    def run_comprehensive_analysis(self, args) -> Dict[str, Any]:
        """
        Run full AODS analysis using the canonical execution path.

        This is the main entry point for AODS_CANONICAL=1 execution mode.
        Provides unified, consolidated analysis with full dependency injection.

        Args:
            args: Command line arguments and configuration

        Returns:
            Dict with analysis results and status
        """
        try:
            self.logger.info("🚀 Starting canonical analysis")

            # Create execution context from args
            context = self._create_execution_context_from_args(args)

            # Determine optimal execution strategy based on analysis requirements
            strategy_mode = self._determine_optimal_strategy(args)

            # Get plugins to execute based on scan mode
            plugins_to_execute = self._get_plugins_for_scan_mode(args)

            self.logger.info(f"📋 Executing {len(plugins_to_execute)} plugins using {strategy_mode.value} strategy")

            # Execute analysis using unified execution manager
            result = self.execute(plugins_to_execute, context.apk_ctx, strategy_mode)

            if result.success:
                # Generate full report using unified reporting
                report_result = self._generate_canonical_report(result, args, context)

                return {
                    "status": "success",
                    "execution_result": result,
                    "report_result": report_result,
                    "statistics": result.statistics,
                    "execution_time": result.execution_time,
                    "canonical_path": True,
                }
            else:
                self.logger.warning(f"⚠️ Canonical execution completed with errors: {result.error}")
                return {
                    "status": "partial_success",
                    "execution_result": result,
                    "error": result.error,
                    "statistics": result.statistics,
                    "canonical_path": True,
                }

        except Exception as e:
            self.logger.error(f"❌ Canonical analysis failed: {e}")
            return {"status": "error", "error": str(e), "canonical_path": True}

    def _create_execution_context_from_args(self, args) -> ExecutionContext:
        """Create execution context from command line arguments."""
        # Extract APK context from args
        apk_ctx = getattr(args, "apk_context", None)
        if not apk_ctx and hasattr(args, "apk"):
            # Create minimal APK context if not provided
            apk_ctx = type(
                "APKContext",
                (),
                {
                    "apk_path": args.apk,
                    "package_name": getattr(args, "pkg", "unknown"),
                    "analysis_id": f"canonical_{int(time.time())}",
                },
            )()

        # Determine execution mode from args
        mode = ExecutionMode.ADAPTIVE  # Default to adaptive
        if hasattr(args, "mode"):
            mode_mapping = {
                "lightning": ExecutionMode.PARALLEL,
                "fast": ExecutionMode.PARALLEL,
                "standard": ExecutionMode.ADAPTIVE,
                "deep": ExecutionMode.SEQUENTIAL,
            }
            mode = mode_mapping.get(args.mode, ExecutionMode.ADAPTIVE)

        # Create additional context from args
        additional_context = {
            "scan_mode": getattr(args, "mode", "standard"),
            "output_format": getattr(args, "output_format", "json"),
            "verbose": getattr(args, "verbose", False),
            "canonical_execution": True,
            "args": args,  # Include full args for compatibility
        }

        return ExecutionContext(apk_ctx=apk_ctx, mode=mode, additional_context=additional_context)

    def _determine_optimal_strategy(self, args) -> ExecutionMode:
        """Determine optimal execution strategy based on analysis requirements."""
        # Check for specific strategy preferences
        if hasattr(args, "parallel") and args.parallel:
            return ExecutionMode.PARALLEL
        if hasattr(args, "sequential") and args.sequential:
            return ExecutionMode.SEQUENTIAL
        if hasattr(args, "process_separated") and args.process_separated:
            return ExecutionMode.PROCESS_SEPARATED

        # Determine based on scan mode
        scan_mode = getattr(args, "mode", "standard")
        strategy_mapping = {
            "lightning": ExecutionMode.PARALLEL,
            "fast": ExecutionMode.PARALLEL,
            "standard": ExecutionMode.ADAPTIVE,
            "deep": ExecutionMode.SEQUENTIAL,
        }

        return strategy_mapping.get(scan_mode, ExecutionMode.ADAPTIVE)

    def _get_plugins_for_scan_mode(self, args) -> List[str]:
        """Get list of plugins to execute based on scan mode and arguments."""
        scan_mode = getattr(args, "mode", "standard")

        # Base plugin sets for different scan modes
        plugin_sets = {
            "lightning": ["manifest_analyzer", "basic_static_analyzer", "quick_security_scan"],
            "fast": [
                "manifest_analyzer",
                "static_analyzer",
                "security_analyzer",
                "permission_analyzer",
                "basic_dynamic_analyzer",
            ],
            "standard": [
                "manifest_analyzer",
                "static_analyzer",
                "security_analyzer",
                "permission_analyzer",
                "dynamic_analyzer",
                "network_analyzer",
                "crypto_analyzer",
                "vulnerability_scanner",
            ],
            "deep": [
                "manifest_analyzer",
                "static_analyzer",
                "security_analyzer",
                "permission_analyzer",
                "dynamic_analyzer",
                "network_analyzer",
                "crypto_analyzer",
                "vulnerability_scanner",
                "advanced_static_analyzer",
                "behavioral_analyzer",
                "malware_detector",
                "privacy_analyzer",
            ],
        }

        base_plugins = plugin_sets.get(scan_mode, plugin_sets["standard"])

        # Add conditional plugins based on args
        if getattr(args, "with_frida", False):
            base_plugins.append("frida_dynamic_analyzer")
        if getattr(args, "with_objection", False):
            base_plugins.append("objection_analyzer")
        if getattr(args, "network_analysis", False):
            base_plugins.extend(["network_traffic_analyzer", "ssl_analyzer"])

        return base_plugins

    def _generate_canonical_report(
        self, execution_result: ExecutionResult, args, context: ExecutionContext
    ) -> Dict[str, Any]:
        """Generate full report using unified reporting system."""
        try:
            # Convert execution results to findings format
            findings = self._convert_execution_results_to_findings(execution_result)

            # Create basic report structure
            report = {
                "scan_summary": {
                    "total_plugins": execution_result.total_plugins,
                    "successful_plugins": execution_result.successful_plugins,
                    "failed_plugins": execution_result.failed_plugins,
                    "execution_time": execution_result.execution_time,
                    "strategy_used": execution_result.strategy_used,
                },
                "vulnerabilities": findings,
                "statistics": execution_result.statistics,
                "canonical_execution": True,
            }

            return {"format": getattr(args, "output_format", "json"), "report": report, "canonical_reporting": True}

        except Exception as e:
            self.logger.error(f"Canonical report generation failed: {e}")
            return {"format": "error", "error": str(e), "canonical_reporting": True}

    def _convert_execution_results_to_findings(self, execution_result: ExecutionResult) -> List[Dict[str, Any]]:
        """Convert execution results to findings format for reporting."""
        findings = []

        for plugin_name, plugin_result in execution_result.results.items():
            if isinstance(plugin_result, tuple):
                # Legacy tuple format (status, data)
                status, data = plugin_result
                if "✅" in status:
                    # Extract findings from successful plugin results
                    if isinstance(data, dict) and "vulnerabilities" in data:
                        findings.extend(data["vulnerabilities"])
                    elif isinstance(data, list):
                        findings.extend(data)
            elif isinstance(plugin_result, dict):
                # Modern dict format
                if "vulnerabilities" in plugin_result:
                    findings.extend(plugin_result["vulnerabilities"])
                elif "findings" in plugin_result:
                    findings.extend(plugin_result["findings"])

        return findings


def create_execution_manager(config: Optional[dict] = None) -> UnifiedExecutionManager:
    """Factory function to create unified execution manager."""
    return UnifiedExecutionManager(config)
