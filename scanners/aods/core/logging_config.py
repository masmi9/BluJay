"""
Centralized structlog configuration for AODS.

Provides structured logging with request correlation, supporting both
JSON output (production/log aggregation) and colored console output (development).

Environment Variables:
    AODS_LOG_FORMAT: 'json', 'console', or 'auto' (detect TTY). Default: 'auto'
    AODS_LOG_LEVEL: DEBUG, INFO, WARNING, ERROR. Default: INFO
    AODS_LOG_INCLUDE_TIMESTAMP: '1' to include ISO timestamp. Default: '1'

Usage:
    from core.logging_config import configure_structlog, get_logger

    # Call once at application startup (before other logging)
    configure_structlog()

    # Get a logger for your module
    logger = get_logger(__name__)
    logger.info("user_login", username="alice", ip="192.168.1.1")

    # Bind request context (in middleware)
    bind_request_context(request_id="abc123", user_id="user1")

    # Clear at request end
    clear_request_context()

Context Management:
    This module uses structlog's native contextvars API for request-scoped
    context. The `merge_contextvars` processor automatically adds bound
    context to all log entries within the same async/thread context.
"""

import logging
import os
import sys
from typing import Any

import structlog
from structlog.contextvars import (
    bind_contextvars,
    clear_contextvars,
    get_contextvars,
    unbind_contextvars,
)

# Track if structlog has been configured
_configured = False


def _get_log_level() -> int:
    """Get log level from environment variable."""
    level_str = os.environ.get("AODS_LOG_LEVEL", "INFO").upper()
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "WARN": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    return level_map.get(level_str, logging.INFO)


def _get_log_format() -> str:
    """Determine log format from environment or TTY detection."""
    fmt = os.environ.get("AODS_LOG_FORMAT", "auto").lower()
    if fmt in ("json", "console"):
        return fmt
    # Auto-detect: use console if stderr is a TTY, else JSON
    return "console" if sys.stderr.isatty() else "json"


def _should_include_timestamp() -> bool:
    """Check if timestamps should be included."""
    return os.environ.get("AODS_LOG_INCLUDE_TIMESTAMP", "1") == "1"


def configure_structlog(force: bool = False) -> None:
    """
    Initialize structlog with appropriate processors for the environment.

    Args:
        force: If True, reconfigure even if already configured.

    Should be called once at application startup, before any logging.
    """
    global _configured
    if _configured and not force:
        return

    log_format = _get_log_format()
    log_level = _get_log_level()
    include_timestamp = _should_include_timestamp()

    # Shared processors for all formats
    # Note: merge_contextvars handles all context binding via structlog's native API
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if include_timestamp:
        shared_processors.insert(0, structlog.processors.TimeStamper(fmt="iso"))

    if log_format == "json":
        # Production: JSON output for log aggregation
        shared_processors.append(structlog.processors.format_exc_info)
        renderer = structlog.processors.JSONRenderer()
    else:
        # Development: colored console output
        shared_processors.append(structlog.dev.set_exc_info)
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure stdlib logging to use structlog formatting
    formatter = structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)

    # Reduce noise from third-party libraries
    for lib_logger in ("urllib3", "httpx", "httpcore", "asyncio"):
        logging.getLogger(lib_logger).setLevel(logging.WARNING)

    _configured = True


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """
    Get a structlog logger for the given module name.

    Args:
        name: Logger name, typically __name__

    Returns:
        A bound structlog logger
    """
    return structlog.get_logger(name)


def bind_request_context(**kwargs: Any) -> None:
    """
    Bind context variables for the current request.

    These values will be automatically added to all log entries
    within the current async context / thread via structlog's
    native contextvars integration.

    Common fields:
        request_id: Unique request identifier
        user_id: Authenticated user ID
        username: Authenticated username
        method: HTTP method
        path: Request path
        client_ip: Client IP address

    Example:
        bind_request_context(request_id="abc123", user_id="user1")
    """
    bind_contextvars(**kwargs)


def clear_request_context() -> None:
    """
    Clear all request context variables.

    Should be called at the end of each request to prevent context leakage.
    Uses structlog's native clear_contextvars().
    """
    clear_contextvars()


def get_request_context() -> dict[str, Any]:
    """
    Get the current request context.

    Returns:
        Dictionary of current context variables (copy)

    Useful for audit logging or passing context to other systems.
    """
    return dict(get_contextvars())


def unbind_request_context(*keys: str) -> None:
    """
    Remove specific keys from the request context.

    Args:
        *keys: Variable names to remove from context

    Example:
        unbind_request_context("temporary_token")
    """
    unbind_contextvars(*keys)


def bind_user_context(user_id: str | None, username: str | None, roles: list[str] | None = None) -> None:
    """
    Bind user context after successful authentication.

    Args:
        user_id: User's unique identifier
        username: User's display name
        roles: List of user roles (optional)
    """
    ctx: dict[str, Any] = {}
    if user_id is not None:
        ctx["user_id"] = user_id
    if username is not None:
        ctx["username"] = username
    if roles is not None:
        ctx["roles"] = roles
    bind_request_context(**ctx)


def bind_scan_context(
    scan_id: str | None = None,
    apk_path: str | None = None,
    package_name: str | None = None,
    scan_mode: str | None = None,
    profile: str | None = None,
) -> None:
    """
    Bind scan context for dyna.py orchestrator.

    These values will be automatically added to all log entries
    within the current scan execution context.

    Args:
        scan_id: Unique scan identifier (typically a UUID)
        apk_path: Path to the APK being analyzed
        package_name: Package name of the application
        scan_mode: Scan mode (safe/deep)
        profile: Scan profile (lightning/fast/standard/deep)

    Example:
        bind_scan_context(
            scan_id="abc123",
            apk_path="/path/to/app.apk",
            package_name="com.example.app",
            scan_mode="deep",
            profile="standard"
        )
    """
    ctx: dict[str, Any] = {}
    if scan_id is not None:
        ctx["scan_id"] = scan_id
    if apk_path is not None:
        ctx["apk_path"] = apk_path
    if package_name is not None:
        ctx["package_name"] = package_name
    if scan_mode is not None:
        ctx["scan_mode"] = scan_mode
    if profile is not None:
        ctx["profile"] = profile
    bind_request_context(**ctx)


def clear_scan_context() -> None:
    """
    Clear scan context at the end of a scan.

    Alias for clear_request_context() for semantic clarity in dyna.py.
    """
    clear_request_context()
