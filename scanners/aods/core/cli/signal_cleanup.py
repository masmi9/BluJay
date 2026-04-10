"""
core.cli.signal_cleanup - Signal handlers and process cleanup (Track 46).

Contains signal_handler_fallback, is_shutdown_requested, cleanup_processes,
and related cleanup functions extracted from dyna.py.
"""

import os
import signal
import time
import threading
import logging

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from core.output_manager import get_output_manager

from core.cli.feature_flags import (
    SHUTDOWN_EVENT,
    CLEANUP_REGISTRY,
    PSUTIL_AVAILABLE,
)

# Conditionally import psutil (mirrors feature_flags gate)
if PSUTIL_AVAILABLE:
    import psutil

# Fallback signal handler functions (moved outside the except block)


def signal_handler_fallback(signum, frame):
    """Basic signal handler for clean shutdown."""
    output_mgr = get_output_manager()
    signal_name = signal.Signals(signum).name
    output_mgr.warning(f"Received {signal_name} signal - initiating clean shutdown...")

    SHUTDOWN_EVENT.set()

    # Run all registered cleanup functions
    for cleanup_func in CLEANUP_REGISTRY:
        try:
            cleanup_func()
        except Exception as e:
            output_mgr.debug(f"Cleanup function failed: {e}")

    # Force exit after cleanup
    output_mgr.info("Clean shutdown completed")
    os._exit(0)


def is_shutdown_requested():
    """Check if shutdown has been requested."""
    return SHUTDOWN_EVENT.is_set()


def cleanup_processes():
    """Enhanced process cleanup with psutil integration."""
    output_mgr = get_output_manager()

    try:
        current_pid = os.getpid()

        if PSUTIL_AVAILABLE:
            # Use psutil for full process cleanup
            current_process = psutil.Process(current_pid)
            children = current_process.children(recursive=True)

            # Terminate child processes gracefully
            for child in children:
                try:
                    child.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Wait for graceful termination
            gone, alive = psutil.wait_procs(children, timeout=3)

            # Force kill remaining processes
            for p in alive:
                try:
                    p.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        # Additional cleanup for specific tools
        try:
            # Gate ADB cleanup in static-only mode to avoid noisy retries
            static_only = bool(os.getenv("AODS_STATIC_ONLY", "0") == "1")
        except Exception:
            # Be conservative on errors: assume static-only to avoid dynamic-tool churn
            static_only = True

        if not static_only:
            cleanup_adb_connections()

        # Shut down global tool executor's thread pool to allow clean exit
        try:
            from core.external.unified_tool_executor import shutdown_global_executor

            shutdown_global_executor()
        except Exception:
            pass

        cleanup_threads()

    except Exception as e:
        output_mgr.debug(f"Process cleanup error: {e}")


def cleanup_adb_connections():
    """Clean up ADB connections and ports."""
    try:
        # Kill any hanging adb processes
        try:
            from core.external.unified_tool_executor import adb_kill_server

            _ = adb_kill_server(timeout=5.0)
        except Exception:
            pass

        # Remove any port forwards
        try:
            from core.external.unified_tool_executor import adb_remove_all_forwards

            _ = adb_remove_all_forwards(timeout=5.0)
        except Exception:
            pass
    except Exception:
        pass


def cleanup_threads():
    """Clean up any remaining threads."""
    main_thread = threading.current_thread()

    for thread in threading.enumerate():
        if thread != main_thread and thread.is_alive():
            if hasattr(thread, "join"):
                try:
                    thread.join(timeout=1.0)
                except Exception:
                    pass


def force_exit_after_timeout(timeout_seconds=10):
    """Force exit after timeout if non-daemon threads prevent clean shutdown."""

    def timeout_handler():
        time.sleep(timeout_seconds)
        # If we're still alive after the timeout, non-daemon threads are blocking exit
        os._exit(0)

    timeout_thread = threading.Thread(target=timeout_handler, daemon=True)
    timeout_thread.start()


# NOTE: Signal handler registration is done in dyna.py (the orchestrator),
# NOT at import time here, to avoid side-effects during module import and
# to keep registration order deterministic.
