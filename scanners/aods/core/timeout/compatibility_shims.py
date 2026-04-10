#!/usr/bin/env python3
"""
Timeout System Compatibility Shims
==================================

Provides backward compatibility for the EnterpriseTimeoutManager while
redirecting to the unified timeout manager.
"""

import warnings
import logging
from typing import Any, Callable, Dict, Optional
from enum import Enum

from .unified_timeout_manager import UnifiedTimeoutManager, TimeoutConfiguration, TimeoutType, TimeoutStrategy

logger = logging.getLogger(__name__)


class DeprecationLevel(Enum):
    """Levels of deprecation warnings."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


def issue_deprecation_warning(old_system: str, new_system: str, level: DeprecationLevel = DeprecationLevel.WARNING):
    """Issue a deprecation warning for legacy timeout systems."""
    message = (
        f"{old_system} is deprecated and will be removed in a future version. "
        f"Use {new_system} instead. "
        f"See documentation for migration guide."
    )

    if level == DeprecationLevel.INFO:
        logger.info(f"DEPRECATION: {message}")
    elif level == DeprecationLevel.WARNING:
        warnings.warn(message, DeprecationWarning, stacklevel=3)
        logger.warning(f"DEPRECATION: {message}")
    elif level == DeprecationLevel.ERROR:
        logger.error(f"DEPRECATION: {message}")


class EnterpriseTimeoutManagerShim:
    """
    Compatibility shim for core/performance_optimizer/timeout_manager.py

    Provides backward compatibility for the EnterpriseTimeoutManager class.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        issue_deprecation_warning(
            "EnterpriseTimeoutManager from core.performance_optimizer.timeout_manager",
            "UnifiedTimeoutManager from core.timeout",
            DeprecationLevel.WARNING,
        )

        unified_config = self._map_enterprise_config(config or {})
        self._unified_manager = UnifiedTimeoutManager(unified_config)

    def _map_enterprise_config(self, enterprise_config: Dict[str, Any]) -> TimeoutConfiguration:
        """Map enterprise configuration to unified configuration."""
        return TimeoutConfiguration(
            plugin_timeout=enterprise_config.get("plugin_timeout", 120),
            process_timeout=enterprise_config.get("process_timeout", 1800),
            critical_timeout=enterprise_config.get("critical_timeout", 300),
            network_timeout=enterprise_config.get("network_timeout", 60),
            analysis_timeout=enterprise_config.get("analysis_timeout", 900),
            default_timeout=enterprise_config.get("default_timeout", 60),
            max_timeout_seconds=enterprise_config.get("max_timeout_seconds", 1800.0),
            min_timeout_seconds=enterprise_config.get("min_timeout_seconds", 1.0),
            default_strategy=TimeoutStrategy.ADAPTIVE,
            enable_escalation=enterprise_config.get("enable_escalation", True),
            escalation_factor=enterprise_config.get("escalation_factor", 1.5),
            max_escalations=enterprise_config.get("max_escalations", 2),
            retry_attempts=enterprise_config.get("retry_attempts", 3),
            backoff_multiplier=enterprise_config.get("backoff_multiplier", 2.0),
            enable_partial_results=enterprise_config.get("enable_partial_results", True),
            enable_timeout_warnings=enterprise_config.get("enable_timeout_warnings", True),
            enable_monitoring=enterprise_config.get("enable_monitoring", True),
        )

    def execute_with_strategy(self, operation: Callable, strategy: str, timeout_seconds: int, **kwargs) -> Any:
        """Execute operation with specific timeout strategy (enterprise feature)."""
        strategy_mapping = {
            "fail_fast": TimeoutStrategy.FAIL_FAST,
            "graceful_degradation": TimeoutStrategy.GRACEFUL_DEGRADATION,
            "retry_backoff": TimeoutStrategy.RETRY_BACKOFF,
            "adaptive": TimeoutStrategy.ADAPTIVE,
            "escalation": TimeoutStrategy.ESCALATION,
        }

        timeout_strategy = strategy_mapping.get(strategy.lower(), TimeoutStrategy.FAIL_FAST)

        context = self._unified_manager.create_context(
            operation_name=kwargs.get("operation_name", "enterprise_operation"),
            timeout_type=TimeoutType.ANALYSIS,
            timeout_seconds=timeout_seconds,
            strategy=timeout_strategy,
        )

        timeout_result = self._unified_manager.execute_with_timeout(operation, context)

        if timeout_result.success:
            return timeout_result.result
        else:
            if timeout_result.timed_out:
                raise TimeoutError(f"Enterprise operation timed out after {timeout_seconds} seconds")
            else:
                raise RuntimeError(timeout_result.error_message or "Enterprise operation failed")
