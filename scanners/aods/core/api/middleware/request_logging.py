"""
Request logging middleware for AODS API.

Provides structured request/response logging with:
- Automatic request ID generation
- Request context binding (method, path, client_ip)
- Duration tracking
- X-Request-ID header propagation
"""

import time
import uuid
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from core.logging_config import (
    bind_request_context,
    clear_request_context,
    get_logger,
)

logger = get_logger(__name__)

# Paths to skip verbose logging (health checks, etc.)
QUIET_PATHS = frozenset(
    {
        "/api/health",
        "/health",
        "/api/health/",
        "/health/",
    }
)


def _get_client_ip(request: Request) -> str:
    """Extract client IP, considering X-Forwarded-For header."""
    # Check for forwarded header (reverse proxy)
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # Take the first IP in the chain
        return forwarded.split(",")[0].strip()
    # Fall back to direct client
    if request.client:
        return request.client.host
    return "unknown"


def _generate_request_id() -> str:
    """Generate a unique request ID."""
    return str(uuid.uuid4())


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that logs requests and responses with structured data.

    Features:
    - Generates or propagates X-Request-ID header
    - Binds request context (request_id, method, path, client_ip)
    - Logs request_started and request_completed events
    - Tracks request duration
    - Clears context after request to prevent leakage

    Usage:
        app.add_middleware(RequestLoggingMiddleware)
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request with logging."""
        # Get or generate request ID
        request_id = request.headers.get("x-request-id")
        if not request_id:
            request_id = _generate_request_id()

        method = request.method
        path = request.url.path
        client_ip = _get_client_ip(request)

        # Bind request context for all logs during this request
        bind_request_context(
            request_id=request_id,
            method=method,
            path=path,
            client_ip=client_ip,
        )

        # Check if this is a quiet path (health checks)
        is_quiet = path in QUIET_PATHS

        start_time = time.perf_counter()

        if not is_quiet:
            logger.info("request_started")

        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as exc:
            # Log error and re-raise
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                "request_failed",
                duration_ms=round(duration_ms, 2),
                error=str(exc),
                error_type=type(exc).__name__,
            )
            clear_request_context()
            raise

        duration_ms = (time.perf_counter() - start_time) * 1000

        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id

        if not is_quiet:
            log_level = "info" if status_code < 400 else "warning" if status_code < 500 else "error"
            getattr(logger, log_level)(
                "request_completed",
                status_code=status_code,
                duration_ms=round(duration_ms, 2),
            )

        # Clear context to prevent leakage to other requests
        clear_request_context()

        return response
