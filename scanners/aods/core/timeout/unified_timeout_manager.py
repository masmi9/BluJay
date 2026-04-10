#!/usr/bin/env python3
"""
Unified Timeout Manager - Canonical Implementation
=================================================

Consolidates all timeout management implementations into a single, modular, canonical system.
This eliminates the 4+ timeout manager duplications identified in Phase 7 analysis.

CONSOLIDATES:
- core/execution/shared/timeout_manager.py (TimeoutManager)
- core/performance_optimizer/timeout_manager.py (EnterpriseTimeoutManager)
- core/unified_parallel_framework/execution_strategies.py (TimeoutManager)
- core/system_integration_fixes.py (PluginTimeoutManager)

MODULAR ARCHITECTURE PRINCIPLES:
- Single Responsibility: Unified timeout management
- Dependency Injection: Configurable timeout strategies
- Interface-Based Design: Common timeout interface
- Open/Closed: Extensible timeout strategies
- Composition: Combines best features from all implementations
"""

import logging
import time
import asyncio
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional, List
from abc import ABC, abstractmethod
import concurrent.futures

# Intelligent Timeout Optimization Integration
try:
    from ..timeout_optimizer import IntelligentTimeoutOptimizer

    INTELLIGENT_TIMEOUT_AVAILABLE = True
except ImportError:
    INTELLIGENT_TIMEOUT_AVAILABLE = False

logger = logging.getLogger(__name__)


class TimeoutStrategy(Enum):
    """Timeout handling strategies consolidated from all implementations."""

    FAIL_FAST = "fail_fast"  # Immediate failure (from enterprise)
    GRACEFUL_DEGRADATION = "graceful"  # Graceful with partial results (from enterprise)
    RETRY_BACKOFF = "retry_backoff"  # Retry with backoff (from enterprise)
    ADAPTIVE = "adaptive"  # Adaptive strategy (from enterprise)
    ESCALATION = "escalation"  # Escalation strategy (from shared)
    PLUGIN_OPTIMIZED = "plugin_optimized"  # Plugin-specific (from system_integration)


class TimeoutType(Enum):
    """Types of timeouts for different operations."""

    PLUGIN = "plugin"  # Plugin execution timeouts
    PROCESS = "process"  # Process execution timeouts
    CRITICAL = "critical"  # Critical operation timeouts
    DEFAULT = "default"  # Default timeout type
    NETWORK = "network"  # Network operation timeouts
    ANALYSIS = "analysis"  # Analysis operation timeouts


class TimeoutSeverity(Enum):
    """Timeout severity levels for escalation."""

    LOW = "low"  # Non-critical timeouts
    MEDIUM = "medium"  # Important timeouts
    HIGH = "high"  # Critical timeouts
    CRITICAL = "critical"  # System-critical timeouts


@dataclass
class TimeoutConfiguration:
    """Unified timeout configuration consolidating all implementations."""

    # Basic timeout values (optimized for AODS plugin complexity - 2025-08-27)
    plugin_timeout: int = 294  # Plugin execution timeout (optimized from 120s)
    process_timeout: int = 2400  # Process execution timeout (optimized from 1800s)
    critical_timeout: int = 600  # Critical operation timeout (optimized from 300s)
    network_timeout: int = 120  # Network operation timeout (optimized from 60s)
    analysis_timeout: int = 1800  # Analysis operation timeout (optimized from 900s)
    default_timeout: int = 180  # Default timeout (optimized from 60s)

    # Advanced configuration (optimized for analysis - 2025-08-27)
    max_timeout_seconds: float = 3600.0  # Maximum allowed timeout (optimized from 1800s)
    min_timeout_seconds: float = 30.0  # Minimum allowed timeout (optimized from 1s)

    # Strategy configuration
    default_strategy: TimeoutStrategy = TimeoutStrategy.ADAPTIVE

    # Escalation configuration (enhanced for resilient execution - 2025-08-27)
    enable_escalation: bool = True
    escalation_factor: float = 2.0  # Escalation factor (optimized from 1.5)
    max_escalations: int = 3  # Max escalations (optimized from 2)

    # Retry configuration (enhanced for resilience - 2025-08-27)
    retry_attempts: int = 3
    backoff_multiplier: float = 2.5  # Backoff multiplier (optimized from 2.0)

    # Feature flags
    enable_partial_results: bool = True
    enable_timeout_warnings: bool = True
    enable_monitoring: bool = True


@dataclass
class TimeoutContext:
    """Context information for timeout operations."""

    operation_name: str
    timeout_type: TimeoutType
    timeout_seconds: float
    strategy: TimeoutStrategy
    severity: TimeoutSeverity = TimeoutSeverity.MEDIUM
    metadata: Dict[str, Any] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)


@dataclass
class TimeoutResult:
    """Result of timeout-managed operation."""

    success: bool
    completed: bool
    timed_out: bool
    result: Any = None
    partial_result: Any = None
    execution_time_seconds: float = 0.0
    timeout_seconds: float = 0.0
    retry_count: int = 0
    escalation_count: int = 0
    error_message: Optional[str] = None
    strategy_used: Optional[str] = None
    context: Optional[TimeoutContext] = None


class TimeoutException(Exception):
    """Unified timeout exception."""

    def __init__(self, context: TimeoutContext, elapsed: float):
        self.context = context
        self.elapsed = elapsed
        super().__init__(
            f"Operation '{context.operation_name}' ({context.timeout_type.value}) "
            f"timed out after {elapsed:.1f}s (limit: {context.timeout_seconds}s)"
        )


class ITimeoutStrategy(ABC):
    """Interface for timeout strategies following modular architecture."""

    @abstractmethod
    def execute(self, operation: Callable, context: TimeoutContext) -> TimeoutResult:
        """Execute operation with timeout strategy."""

    @abstractmethod
    async def execute_async(self, operation: Callable, context: TimeoutContext) -> TimeoutResult:
        """Execute async operation with timeout strategy."""


class FailFastStrategy(ITimeoutStrategy):
    """Fail-fast timeout strategy."""

    def execute(self, operation: Callable, context: TimeoutContext) -> TimeoutResult:
        """Execute with immediate failure on timeout."""
        start_time = time.time()

        try:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(operation)
                result = future.result(timeout=context.timeout_seconds)

            execution_time = time.time() - start_time
            return TimeoutResult(
                success=True,
                completed=True,
                timed_out=False,
                result=result,
                execution_time_seconds=execution_time,
                timeout_seconds=context.timeout_seconds,
                strategy_used="fail_fast",
                context=context,
            )

        except concurrent.futures.TimeoutError:
            execution_time = time.time() - start_time
            return TimeoutResult(
                success=False,
                completed=False,
                timed_out=True,
                execution_time_seconds=execution_time,
                timeout_seconds=context.timeout_seconds,
                error_message=f"Operation timed out after {context.timeout_seconds}s",
                strategy_used="fail_fast",
                context=context,
            )
        except Exception as e:
            execution_time = time.time() - start_time
            return TimeoutResult(
                success=False,
                completed=False,
                timed_out=False,
                execution_time_seconds=execution_time,
                timeout_seconds=context.timeout_seconds,
                error_message=str(e),
                strategy_used="fail_fast",
                context=context,
            )

    async def execute_async(self, operation: Callable, context: TimeoutContext) -> TimeoutResult:
        """Execute async operation with fail-fast strategy."""
        start_time = time.time()

        try:
            result = await asyncio.wait_for(operation(), timeout=context.timeout_seconds)
            execution_time = time.time() - start_time

            return TimeoutResult(
                success=True,
                completed=True,
                timed_out=False,
                result=result,
                execution_time_seconds=execution_time,
                timeout_seconds=context.timeout_seconds,
                strategy_used="fail_fast_async",
                context=context,
            )

        except asyncio.TimeoutError:
            execution_time = time.time() - start_time
            return TimeoutResult(
                success=False,
                completed=False,
                timed_out=True,
                execution_time_seconds=execution_time,
                timeout_seconds=context.timeout_seconds,
                error_message=f"Async operation timed out after {context.timeout_seconds}s",
                strategy_used="fail_fast_async",
                context=context,
            )
        except Exception as e:
            execution_time = time.time() - start_time
            return TimeoutResult(
                success=False,
                completed=False,
                timed_out=False,
                execution_time_seconds=execution_time,
                timeout_seconds=context.timeout_seconds,
                error_message=str(e),
                strategy_used="fail_fast_async",
                context=context,
            )


class RetryBackoffStrategy(ITimeoutStrategy):
    """Retry with exponential backoff strategy."""

    def __init__(self, config: TimeoutConfiguration):
        self.config = config

    def execute(self, operation: Callable, context: TimeoutContext) -> TimeoutResult:
        """Execute with retry and exponential backoff."""
        start_time = time.time()
        retry_count = 0
        last_error = None

        for attempt in range(self.config.retry_attempts):
            try:
                # Calculate timeout for this attempt
                attempt_timeout = min(context.timeout_seconds / (attempt + 1), context.timeout_seconds)

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(operation)
                    result = future.result(timeout=attempt_timeout)

                execution_time = time.time() - start_time
                return TimeoutResult(
                    success=True,
                    completed=True,
                    timed_out=False,
                    result=result,
                    execution_time_seconds=execution_time,
                    timeout_seconds=context.timeout_seconds,
                    retry_count=retry_count,
                    strategy_used="retry_backoff",
                    context=context,
                )

            except (concurrent.futures.TimeoutError, Exception) as e:
                last_error = e
                retry_count += 1

                if attempt < self.config.retry_attempts - 1:
                    # Exponential backoff
                    backoff_time = self.config.backoff_multiplier**attempt
                    time.sleep(backoff_time)

        execution_time = time.time() - start_time
        return TimeoutResult(
            success=False,
            completed=False,
            timed_out=isinstance(last_error, concurrent.futures.TimeoutError),
            execution_time_seconds=execution_time,
            timeout_seconds=context.timeout_seconds,
            retry_count=retry_count,
            error_message=str(last_error),
            strategy_used="retry_backoff",
            context=context,
        )

    async def execute_async(self, operation: Callable, context: TimeoutContext) -> TimeoutResult:
        """Execute async operation with retry and backoff."""
        start_time = time.time()
        retry_count = 0
        last_error = None

        for attempt in range(self.config.retry_attempts):
            try:
                attempt_timeout = min(context.timeout_seconds / (attempt + 1), context.timeout_seconds)

                result = await asyncio.wait_for(operation(), timeout=attempt_timeout)
                execution_time = time.time() - start_time

                return TimeoutResult(
                    success=True,
                    completed=True,
                    timed_out=False,
                    result=result,
                    execution_time_seconds=execution_time,
                    timeout_seconds=context.timeout_seconds,
                    retry_count=retry_count,
                    strategy_used="retry_backoff_async",
                    context=context,
                )

            except (asyncio.TimeoutError, Exception) as e:
                last_error = e
                retry_count += 1

                if attempt < self.config.retry_attempts - 1:
                    backoff_time = self.config.backoff_multiplier**attempt
                    await asyncio.sleep(backoff_time)

        execution_time = time.time() - start_time
        return TimeoutResult(
            success=False,
            completed=False,
            timed_out=isinstance(last_error, asyncio.TimeoutError),
            execution_time_seconds=execution_time,
            timeout_seconds=context.timeout_seconds,
            retry_count=retry_count,
            error_message=str(last_error),
            strategy_used="retry_backoff_async",
            context=context,
        )


class UnifiedTimeoutManager:
    """
    Canonical timeout manager consolidating all AODS timeout implementations.

    This manager follows modular architecture principles and provides a single,
    authoritative interface for all timeout management needs across AODS.
    """

    def __init__(self, config: Optional[TimeoutConfiguration] = None):
        """Initialize unified timeout manager."""
        self.config = config or TimeoutConfiguration()
        self.logger = logging.getLogger(f"{__name__}.UnifiedTimeoutManager")

        # Initialize timeout strategies (dependency injection)
        self._strategies: Dict[TimeoutStrategy, ITimeoutStrategy] = {
            TimeoutStrategy.FAIL_FAST: FailFastStrategy(),
            TimeoutStrategy.RETRY_BACKOFF: RetryBackoffStrategy(self.config),
            # Additional strategies can be injected here
        }

        # Monitoring and statistics
        self._operation_stats: Dict[str, List[float]] = {}
        self._timeout_counts: Dict[TimeoutType, int] = {}

        # Intelligent timeout optimization integration
        self._intelligent_optimizer = None
        if INTELLIGENT_TIMEOUT_AVAILABLE:
            try:
                self._intelligent_optimizer = IntelligentTimeoutOptimizer()
                self.logger.info("IntelligentTimeoutOptimizer integrated successfully")
            except Exception as e:
                self.logger.warning(f"Failed to initialize IntelligentTimeoutOptimizer: {e}")

        self.logger.info("UnifiedTimeoutManager initialized with consolidated timeout strategies")

    def get_timeout_for_type(self, timeout_type: TimeoutType) -> int:
        """Get timeout value for specific operation type."""
        timeout_mapping = {
            TimeoutType.PLUGIN: self.config.plugin_timeout,
            TimeoutType.PROCESS: self.config.process_timeout,
            TimeoutType.CRITICAL: self.config.critical_timeout,
            TimeoutType.NETWORK: self.config.network_timeout,
            TimeoutType.ANALYSIS: self.config.analysis_timeout,
            TimeoutType.DEFAULT: self.config.default_timeout,
        }
        return timeout_mapping.get(timeout_type, self.config.default_timeout)

    def get_optimized_timeout_for_plugin(self, plugin_name: str, apk_path: Optional[str] = None) -> int:
        """
        Get optimized timeout for specific plugin using IntelligentTimeoutOptimizer.

        This method eliminates the need for deferred imports by providing a unified
        interface to intelligent timeout optimization.

        Args:
            plugin_name: Name of the plugin
            apk_path: Optional path to APK for size-based optimization

        Returns:
            Optimized timeout value in seconds
        """
        if self._intelligent_optimizer and apk_path:
            try:
                return self._intelligent_optimizer.get_optimized_timeout(plugin_name, apk_path)
            except Exception as e:
                self.logger.warning(f"Failed to get optimized timeout for {plugin_name}: {e}")

        # Fallback to standard plugin timeout
        return self.get_timeout_for_type(TimeoutType.PLUGIN)

    def create_context(
        self,
        operation_name: str,
        timeout_type: TimeoutType = TimeoutType.DEFAULT,
        timeout_seconds: Optional[float] = None,
        strategy: Optional[TimeoutStrategy] = None,
        severity: TimeoutSeverity = TimeoutSeverity.MEDIUM,
        **metadata,
    ) -> TimeoutContext:
        """Create timeout context for operation."""

        if timeout_seconds is None:
            timeout_seconds = self.get_timeout_for_type(timeout_type)

        if strategy is None:
            strategy = self.config.default_strategy

        return TimeoutContext(
            operation_name=operation_name,
            timeout_type=timeout_type,
            timeout_seconds=timeout_seconds,
            strategy=strategy,
            severity=severity,
            metadata=metadata,
        )

    def execute_with_timeout(self, operation: Callable, context: TimeoutContext) -> TimeoutResult:
        """Execute operation with unified timeout management."""

        # Get appropriate strategy
        strategy = self._strategies.get(context.strategy)
        if not strategy:
            # Fallback to fail-fast
            strategy = self._strategies[TimeoutStrategy.FAIL_FAST]
            self.logger.warning(f"Strategy {context.strategy} not available, using fail-fast")

        # Execute with strategy
        result = strategy.execute(operation, context)

        # Update statistics
        self._update_statistics(context, result)

        return result

    async def execute_async_with_timeout(self, operation: Callable, context: TimeoutContext) -> TimeoutResult:
        """Execute async operation with unified timeout management."""

        strategy = self._strategies.get(context.strategy)
        if not strategy:
            strategy = self._strategies[TimeoutStrategy.FAIL_FAST]
            self.logger.warning(f"Strategy {context.strategy} not available, using fail-fast")

        result = await strategy.execute_async(operation, context)
        self._update_statistics(context, result)

        return result

    @contextmanager
    def timeout_context(
        self,
        operation_name: str,
        timeout_type: TimeoutType = TimeoutType.DEFAULT,
        timeout_seconds: Optional[float] = None,
    ):
        """Context manager for timeout operations."""
        context = self.create_context(operation_name, timeout_type, timeout_seconds)

        try:
            yield context
        except Exception as e:
            self.logger.error(f"Error in timeout context for {operation_name}: {e}")
            raise

    def _update_statistics(self, context: TimeoutContext, result: TimeoutResult):
        """Update timeout statistics for monitoring."""
        if not self.config.enable_monitoring:
            return

        # Update operation statistics
        if context.operation_name not in self._operation_stats:
            self._operation_stats[context.operation_name] = []

        self._operation_stats[context.operation_name].append(result.execution_time_seconds)

        # Update timeout counts
        if result.timed_out:
            if context.timeout_type not in self._timeout_counts:
                self._timeout_counts[context.timeout_type] = 0
            self._timeout_counts[context.timeout_type] += 1

    def get_statistics(self) -> Dict[str, Any]:
        """Get timeout management statistics."""
        return {
            "operation_stats": dict(self._operation_stats),
            "timeout_counts": {k.value: v for k, v in self._timeout_counts.items()},
            "total_operations": sum(len(stats) for stats in self._operation_stats.values()),
            "total_timeouts": sum(self._timeout_counts.values()),
        }

    def register_strategy(self, strategy_type: TimeoutStrategy, strategy: ITimeoutStrategy):
        """Register custom timeout strategy (dependency injection)."""
        self._strategies[strategy_type] = strategy
        self.logger.info(f"Registered custom timeout strategy: {strategy_type}")


# Factory function for canonical timeout manager creation


def create_unified_timeout_manager(config: Optional[TimeoutConfiguration] = None) -> UnifiedTimeoutManager:
    """Create unified timeout manager with optional configuration."""
    return UnifiedTimeoutManager(config)


# Convenience functions for common timeout operations


def execute_with_plugin_timeout(operation: Callable, timeout_seconds: Optional[int] = None) -> TimeoutResult:
    """Execute operation with plugin timeout."""
    manager = create_unified_timeout_manager()
    context = manager.create_context("plugin_operation", TimeoutType.PLUGIN, timeout_seconds)
    return manager.execute_with_timeout(operation, context)


def execute_with_process_timeout(operation: Callable, timeout_seconds: Optional[int] = None) -> TimeoutResult:
    """Execute operation with process timeout."""
    manager = create_unified_timeout_manager()
    context = manager.create_context("process_operation", TimeoutType.PROCESS, timeout_seconds)
    return manager.execute_with_timeout(operation, context)


# Export canonical interface
__all__ = [
    "UnifiedTimeoutManager",
    "TimeoutConfiguration",
    "TimeoutContext",
    "TimeoutResult",
    "TimeoutException",
    "TimeoutStrategy",
    "TimeoutType",
    "TimeoutSeverity",
    "ITimeoutStrategy",
    "create_unified_timeout_manager",
    "execute_with_plugin_timeout",
    "execute_with_process_timeout",
]
