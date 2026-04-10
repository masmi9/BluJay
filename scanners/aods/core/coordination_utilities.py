"""
AODS Core Coordination Utilities
===============================

Standardized utilities for handling coordination results across all AODS plugins.
Prevents UnboundLocalError patterns and ensures consistent error handling.

Author: AODS Development Team
Version: 1.0.0
"""

from typing import Any, List, Dict, Optional, Callable
from dataclasses import dataclass
from enum import Enum

# Structlog with graceful fallback
try:
    from core.logging_config import get_logger

    _module_logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    _module_logger = stdlib_logging.getLogger(__name__)


class CoordinationStatus(Enum):
    """Standardized coordination status values."""

    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FALLBACK_SUCCESS = "fallback_success"
    FAILURE = "failure"
    TIMEOUT = "timeout"


@dataclass
class CoordinationResult:
    """Standardized coordination result container."""

    status: CoordinationStatus
    results: List[Any]
    error_message: Optional[str] = None
    fallback_used: bool = False
    metadata: Optional[Dict[str, Any]] = None


class StandardizedCoordinationHandler:
    """
    Standardized coordination result handler for AODS plugins.

    Prevents UnboundLocalError patterns by ensuring variables are always initialized
    and provides consistent error handling across all plugins.
    """

    def __init__(self, logger=None):
        """Initialize the coordination handler."""
        self.logger = logger or _module_logger

    def execute_with_fallback(
        self,
        primary_operation: Callable[[], Any],
        fallback_operation: Optional[Callable[[], Any]] = None,
        result_extractor: Optional[Callable[[Any], List[Any]]] = None,
        operation_name: str = "coordination",
    ) -> CoordinationResult:
        """
        Execute an operation with standardized fallback handling.

        Args:
            primary_operation: Primary coordination function to execute
            fallback_operation: Optional fallback function if primary fails
            result_extractor: Function to extract results from primary operation
            operation_name: Name for logging purposes

        Returns:
            CoordinationResult with standardized structure
        """
        # Initialize safe defaults - prevents UnboundLocalError
        results = []
        status = CoordinationStatus.FAILURE
        error_message = None
        fallback_used = False

        # Attempt primary operation
        try:
            self.logger.info("Starting coordination operation", operation=operation_name)
            primary_result = primary_operation()

            # Extract results using provided extractor or default logic
            if result_extractor:
                results = result_extractor(primary_result) or []
            elif hasattr(primary_result, "results"):
                results = getattr(primary_result, "results", []) or []
            elif isinstance(primary_result, list):
                results = primary_result or []
            else:
                results = [primary_result] if primary_result is not None else []

            status = CoordinationStatus.SUCCESS
            self.logger.info(
                "Coordination operation completed successfully", operation=operation_name, result_count=len(results)
            )

        except Exception as e:
            self.logger.warning("Coordination operation failed", operation=operation_name, error=str(e))
            error_message = str(e)

            # Attempt fallback if provided
            if fallback_operation:
                try:
                    self.logger.info("Attempting coordination fallback", operation=operation_name)
                    fallback_result = fallback_operation()

                    # Extract fallback results
                    if isinstance(fallback_result, list):
                        results = fallback_result or []
                    else:
                        results = [fallback_result] if fallback_result is not None else []

                    status = CoordinationStatus.FALLBACK_SUCCESS
                    fallback_used = True
                    self.logger.info(
                        "Coordination fallback completed", operation=operation_name, result_count=len(results)
                    )

                except Exception as fallback_error:
                    self.logger.error(
                        "Coordination fallback also failed", operation=operation_name, error=str(fallback_error)
                    )
                    error_message = f"Primary: {e}, Fallback: {fallback_error}"
                    results = []  # Ensure safe empty list

        return CoordinationResult(
            status=status,
            results=results,
            error_message=error_message,
            fallback_used=fallback_used,
            metadata={"operation_name": operation_name},
        )

    def extract_hook_results(self, coordinator: Any, hook_engine: Any) -> List[Any]:
        """
        Standardized hook result extraction logic.

        Args:
            coordinator: Coordination object
            hook_engine: Hook engine object

        Returns:
            List of extracted results (empty list if extraction fails)
        """
        results = []

        # Try coordinator first
        if coordinator:
            results = getattr(coordinator, "hook_results", []) or []
            if results:
                self.logger.debug("Extracted results from coordinator", count=len(results))
                return results

        # Try hook engine
        if hook_engine and hasattr(hook_engine, "get_results"):
            try:
                results = hook_engine.get_results() or []
                if results:
                    self.logger.debug("Extracted results from hook engine", count=len(results))
                    return results
            except Exception as e:
                self.logger.warning("Failed to extract results from hook engine", error=str(e))

        # Try other common result attributes
        for attr in ["results", "findings", "vulnerabilities"]:
            if coordinator and hasattr(coordinator, attr):
                try:
                    results = getattr(coordinator, attr, []) or []
                    if results:
                        self.logger.debug("Extracted results from coordinator attribute", count=len(results), attr=attr)
                        return results
                except Exception:
                    continue

        self.logger.debug("No results extracted - returning empty list")
        return []


def create_standardized_handler(logger: Optional[Any] = None) -> StandardizedCoordinationHandler:
    """Factory function to create standardized coordination handler."""
    return StandardizedCoordinationHandler(logger)


# Convenience function for quick coordination handling
def handle_coordination_with_fallback(
    primary_op: Callable,
    fallback_op: Optional[Callable] = None,
    logger: Optional[Any] = None,
    operation_name: str = "operation",
) -> CoordinationResult:
    """
    Quick coordination handling with standardized error patterns.

    Usage:
        result = handle_coordination_with_fallback(
            primary_op=lambda: coordinator.execute(),
            fallback_op=lambda: engine.basic_monitoring(),
            logger=self.logger,
            operation_name="runtime_analysis"
        )

        # Result is always safe to use
        for item in result.results:
            process(item)
    """
    handler = create_standardized_handler(logger)
    return handler.execute_with_fallback(primary_op, fallback_op, operation_name=operation_name)
