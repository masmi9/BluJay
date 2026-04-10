#!/usr/bin/env python3
"""
Correlation Context Management for AODS
======================================

Provides scan and plugin correlation IDs for enhanced debugging and tracing.
Uses Python's contextvars for thread-safe context propagation.

Features:
- Scan-level correlation IDs for end-to-end tracing
- Plugin-level correlation IDs for individual plugin execution tracking
- Thread-safe context propagation using contextvars
- Automatic ID generation with meaningful prefixes
- Integration with logging for enhanced debugging

Usage:
    from core.correlation_context import set_scan_correlation_id, get_scan_correlation_id

    # Set scan correlation ID at the start of a scan
    scan_id = set_scan_correlation_id()

    # Use in logging
    logger.info(f"[{scan_id}] Starting full scan")

    # Plugin execution
    with plugin_correlation_context("ssl_analyzer"):
        logger.info(f"[{get_correlation_ids()}] Analyzing SSL configuration")
"""

import logging
import uuid
from contextvars import ContextVar
from contextlib import contextmanager
from typing import Optional
from datetime import datetime

# Context variables for correlation IDs
scan_correlation_id: ContextVar[Optional[str]] = ContextVar("scan_correlation_id", default=None)
plugin_correlation_id: ContextVar[Optional[str]] = ContextVar("plugin_correlation_id", default=None)


def generate_scan_id() -> str:
    """Generate a unique scan correlation ID."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    short_uuid = str(uuid.uuid4())[:8]
    return f"scan_{timestamp}_{short_uuid}"


def generate_plugin_id(plugin_name: str) -> str:
    """Generate a unique plugin correlation ID."""
    timestamp = datetime.now().strftime("%H%M%S")
    short_uuid = str(uuid.uuid4())[:6]
    clean_name = plugin_name.replace(" ", "_").replace("-", "_").lower()
    return f"plugin_{clean_name}_{timestamp}_{short_uuid}"


def set_scan_correlation_id(scan_id: Optional[str] = None) -> str:
    """
    Set the scan correlation ID for the current context.

    Args:
        scan_id: Optional custom scan ID. If None, generates a new one.

    Returns:
        The scan correlation ID that was set.
    """
    if scan_id is None:
        scan_id = generate_scan_id()

    scan_correlation_id.set(scan_id)
    return scan_id


def get_scan_correlation_id() -> Optional[str]:
    """Get the current scan correlation ID."""
    return scan_correlation_id.get()


def set_plugin_correlation_id(plugin_name: str, plugin_id: Optional[str] = None) -> str:
    """
    Set the plugin correlation ID for the current context.

    Args:
        plugin_name: Name of the plugin being executed.
        plugin_id: Optional custom plugin ID. If None, generates a new one.

    Returns:
        The plugin correlation ID that was set.
    """
    if plugin_id is None:
        plugin_id = generate_plugin_id(plugin_name)

    plugin_correlation_id.set(plugin_id)
    return plugin_id


def get_plugin_correlation_id() -> Optional[str]:
    """Get the current plugin correlation ID."""
    return plugin_correlation_id.get()


def get_correlation_ids() -> str:
    """
    Get a formatted string with both scan and plugin correlation IDs.

    Returns:
        Formatted correlation ID string for logging.
    """
    scan_id = get_scan_correlation_id()
    plugin_id = get_plugin_correlation_id()

    if scan_id and plugin_id:
        return f"{scan_id}|{plugin_id}"
    elif scan_id:
        return scan_id
    elif plugin_id:
        return plugin_id
    else:
        return "no_correlation"


@contextmanager
def scan_correlation_context(scan_id: Optional[str] = None):
    """
    Context manager for scan correlation ID.

    Args:
        scan_id: Optional custom scan ID. If None, generates a new one.
    """
    old_scan_id = get_scan_correlation_id()
    try:
        set_scan_correlation_id(scan_id)
        yield get_scan_correlation_id()
    finally:
        if old_scan_id is not None:
            scan_correlation_id.set(old_scan_id)
        else:
            scan_correlation_id.set(None)


@contextmanager
def plugin_correlation_context(plugin_name: str, plugin_id: Optional[str] = None):
    """
    Context manager for plugin correlation ID.

    Args:
        plugin_name: Name of the plugin being executed.
        plugin_id: Optional custom plugin ID. If None, generates a new one.
    """
    old_plugin_id = get_plugin_correlation_id()
    try:
        set_plugin_correlation_id(plugin_name, plugin_id)
        yield get_plugin_correlation_id()
    finally:
        if old_plugin_id is not None:
            plugin_correlation_id.set(old_plugin_id)
        else:
            plugin_correlation_id.set(None)


class CorrelationLoggerAdapter(logging.LoggerAdapter):
    """
    Logger adapter that automatically includes correlation IDs in log messages.

    Usage:
        logger = CorrelationLoggerAdapter(logging.getLogger(__name__))
        logger.info("This message will include correlation IDs")
    """

    def process(self, msg, kwargs):
        correlation_ids = get_correlation_ids()
        if correlation_ids != "no_correlation":
            return f"[{correlation_ids}] {msg}", kwargs
        return msg, kwargs


def get_correlation_logger(name: str) -> CorrelationLoggerAdapter:
    """
    Get a logger that automatically includes correlation IDs.

    Args:
        name: Logger name (typically __name__)

    Returns:
        CorrelationLoggerAdapter instance
    """
    base_logger = logging.getLogger(name)
    return CorrelationLoggerAdapter(base_logger, {})


# Convenience function for quick correlation ID logging


def log_with_correlation(logger: logging.Logger, level: int, msg: str, *args, **kwargs):
    """
    Log a message with correlation IDs included.

    Args:
        logger: Logger instance
        level: Log level (logging.INFO, logging.DEBUG, etc.)
        msg: Log message
        *args, **kwargs: Additional arguments for logger
    """
    correlation_ids = get_correlation_ids()
    if correlation_ids != "no_correlation":
        msg = f"[{correlation_ids}] {msg}"

    logger.log(level, msg, *args, **kwargs)
