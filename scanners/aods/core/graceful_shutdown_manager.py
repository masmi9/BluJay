"""
Graceful shutdown manager for AODS.

This module provides a shutdown system for AODS.
"""

import atexit
import logging
import os
import signal
import subprocess
import threading
import time
from contextlib import contextmanager
from typing import Callable, Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)


class ShutdownState(Enum):
    """Shutdown states for tracking progress."""

    RUNNING = "running"
    SHUTDOWN_INITIATED = "shutdown_initiated"
    PLUGINS_STOPPING = "plugins_stopping"
    PROCESSES_TERMINATING = "processes_terminating"
    CLEANUP_COMPLETE = "cleanup_complete"
    FORCE_EXIT = "force_exit"


@dataclass
class ShutdownConfig:
    """Configuration for graceful shutdown behavior."""

    graceful_timeout: int = 10  # Seconds to wait for graceful shutdown
    plugin_timeout: int = 5  # Seconds to wait for plugin termination
    process_timeout: int = 3  # Seconds to wait for process termination
    force_timeout: int = 15  # Total timeout before force exit
    cleanup_temp_files: bool = True
    cleanup_processes: bool = True
    save_partial_results: bool = True


class GracefulShutdownManager:
    """
    Full graceful shutdown manager for AODS.

    This manager provides:
    - Signal handling with re-entry protection
    - Coordinated shutdown across all components
    - Timeout-based escalation to force termination
    - Plugin and process cleanup
    - Partial result preservation
    """

    _instance: Optional["GracefulShutdownManager"] = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        """Singleton pattern to ensure only one shutdown manager exists."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config: Optional[ShutdownConfig] = None):
        """Initialize the graceful shutdown manager."""
        if hasattr(self, "_initialized"):
            return

        self.config = config or ShutdownConfig()
        self.state = ShutdownState.RUNNING
        self.shutdown_event = threading.Event()
        self.cleanup_functions: List[Callable] = []
        self.active_plugins: Set[str] = set()
        self.active_processes: Dict[str, any] = {}
        self.shutdown_lock = threading.Lock()
        self.signal_received = False

        # Output manager for logging
        self.output_mgr = None

        # Register signal handlers
        self._register_signal_handlers()

        # Register atexit handler
        atexit.register(self._emergency_cleanup)

        self._initialized = True
        logger.info("Graceful shutdown manager initialized")

    def set_output_manager(self, output_mgr):
        """Set the output manager for logging."""
        self.output_mgr = output_mgr

    def _log(self, level: str, message: str):
        """Log message using output manager or fallback to logger.

        Handles closed file handles gracefully during interpreter shutdown.
        """
        # Check if we're in interpreter shutdown
        # This prevents "Logging error" diagnostics during pytest teardown
        import sys

        # Check if interpreter is finalizing (Python 3.7+) or streams are closed
        if (
            getattr(sys, "_finalizing", False)
            or sys.stderr is None
            or (hasattr(sys.stderr, "closed") and sys.stderr.closed)
        ):
            return

        # Disable logging temporarily during atexit to prevent handler errors
        # The logging module's handlers may have stale stream references
        if getattr(self, "_in_atexit_cleanup", False):
            # Use direct stderr print as a fallback during atexit
            try:
                import sys as _sys

                if _sys.stderr and not getattr(_sys.stderr, "closed", False):
                    print(message, file=_sys.stderr)
            except (ValueError, OSError, AttributeError):
                pass
            return

        try:
            if self.output_mgr:
                getattr(self.output_mgr, level)(message)
            else:
                getattr(logger, level)(message)
        except (ValueError, OSError):
            # Stream may be closed during interpreter shutdown
            pass

    def _register_signal_handlers(self):
        """Register signal handlers with re-entry protection.

        signal.signal() only works in the main thread.  When plugins
        instantiate this manager from a worker thread we skip signal
        registration - the main thread will have already registered
        handlers (or will do so later).
        """
        import threading

        if threading.current_thread() is not threading.main_thread():
            logger.debug("Skipping signal handler registration (not main thread)")
            return

        def protected_signal_handler(signum, frame):
            with self.shutdown_lock:
                if self.signal_received:
                    # Signal already being handled, ignore subsequent signals
                    return
                self.signal_received = True
                self._handle_shutdown_signal(signum, frame)

        signal.signal(signal.SIGINT, protected_signal_handler)
        signal.signal(signal.SIGTERM, protected_signal_handler)

        # On Windows, also handle CTRL_C_EVENT
        if os.name == "nt":
            try:
                signal.signal(signal.CTRL_C_EVENT, protected_signal_handler)
            except AttributeError:
                pass

    def _handle_shutdown_signal(self, signum: int, frame):
        """Handle shutdown signal with proper coordination."""
        signal_name = signal.Signals(signum).name if hasattr(signal, "Signals") else f"Signal {signum}"
        self._log("warning", f"🛑 Received {signal_name} - initiating graceful shutdown...")

        # Set shutdown state
        self.state = ShutdownState.SHUTDOWN_INITIATED
        self.shutdown_event.set()

        # EARLY: Ensure minimal report exists or upgrade placeholder before lengthy cleanup
        try:
            self._write_or_upgrade_minimal_report(status="aborted", message=f"Scan terminating due to {signal_name}")
        except Exception:
            pass

        # Start shutdown process in separate thread to avoid blocking signal handler
        shutdown_thread = threading.Thread(target=self._execute_graceful_shutdown, name="GracefulShutdown", daemon=True)
        shutdown_thread.start()

        # Start force exit timer
        force_exit_thread = threading.Thread(target=self._force_exit_timer, name="ForceExitTimer", daemon=True)
        force_exit_thread.start()

    def _execute_graceful_shutdown(self):
        """Execute the graceful shutdown sequence."""
        try:
            self._log("info", "🔄 Starting graceful shutdown sequence...")

            # EARLY: Best-effort write to avoid missing report if cleanup stalls
            try:
                self._write_or_upgrade_minimal_report(
                    status="aborted", message="Scan terminated during graceful shutdown"
                )
            except Exception:
                pass

            # Step 1: Stop plugins gracefully
            self._shutdown_plugins()

            # Step 2: Terminate processes
            self._terminate_processes()

            # Step 3: Run cleanup functions
            self._run_cleanup_functions()

            # Perform final cleanup and exit procedures
            self._final_cleanup()

            self.state = ShutdownState.CLEANUP_COMPLETE
            self._log("info", "✅ Graceful shutdown completed successfully")

        except Exception as e:
            self._log("error", f"❌ Error during graceful shutdown: {e}")
        finally:
            # Exit cleanly
            os._exit(0)

    def _shutdown_plugins(self):
        """Shutdown active plugins gracefully."""
        if not self.active_plugins:
            return

        self.state = ShutdownState.PLUGINS_STOPPING
        self._log("info", f"🔌 Stopping {len(self.active_plugins)} active plugins...")

        # Send shutdown signal to all plugins
        for plugin_name in list(self.active_plugins):
            try:
                self._stop_plugin(plugin_name)
            except Exception as e:
                self._log("debug", f"Error stopping plugin {plugin_name}: {e}")

        # Wait for plugins to stop
        start_time = time.time()
        while self.active_plugins and (time.time() - start_time) < self.config.plugin_timeout:
            time.sleep(0.1)

        if self.active_plugins:
            self._log("warning", f"⚠️ {len(self.active_plugins)} plugins did not stop gracefully")

    def _stop_plugin(self, plugin_name: str):
        """Stop a specific plugin."""
        # This will be implemented by plugins that register themselves
        # For now, just remove from active set
        self.active_plugins.discard(plugin_name)

    def _terminate_processes(self):
        """Terminate active processes."""
        if not self.active_processes:
            return

        self.state = ShutdownState.PROCESSES_TERMINATING
        self._log("info", f"🔄 Terminating {len(self.active_processes)} active processes...")

        # Terminate processes gracefully first
        for process_name, process in list(self.active_processes.items()):
            try:
                self._terminate_process(process_name, process)
            except Exception as e:
                self._log("debug", f"Error terminating process {process_name}: {e}")

        # Wait for processes to terminate
        start_time = time.time()
        while self.active_processes and (time.time() - start_time) < self.config.process_timeout:
            time.sleep(0.1)

        # Force kill remaining processes
        for process_name, process in list(self.active_processes.items()):
            try:
                self._force_kill_process(process_name, process)
            except Exception as e:
                self._log("debug", f"Error force killing process {process_name}: {e}")

    def _terminate_process(self, process_name: str, process):
        """Terminate a specific process gracefully."""
        try:
            if hasattr(process, "terminate"):
                process.terminate()
            elif hasattr(process, "kill"):
                process.kill()
            else:
                # Assume it's a PID
                os.kill(int(process), signal.SIGTERM)
        except (ProcessLookupError, OSError):
            # Process already terminated
            pass
        finally:
            self.active_processes.pop(process_name, None)

    def _force_kill_process(self, process_name: str, process):
        """Force kill a specific process."""
        try:
            if hasattr(process, "kill"):
                process.kill()
            else:
                # Assume it's a PID
                os.kill(int(process), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            # Process already terminated
            pass
        finally:
            self.active_processes.pop(process_name, None)

    def _run_cleanup_functions(self):
        """Run all registered cleanup functions."""
        if not self.cleanup_functions:
            return

        self._log("info", f"🧹 Running {len(self.cleanup_functions)} cleanup functions...")

        for cleanup_func in self.cleanup_functions:
            try:
                cleanup_func()
            except Exception as e:
                self._log("debug", f"Cleanup function failed: {e}")

    def _final_cleanup(self):
        """Perform final cleanup operations."""
        self._log("info", "🔧 Performing final cleanup...")

        # Cleanup system processes
        if self.config.cleanup_processes:
            self._cleanup_system_processes()

        # Cleanup temporary files
        if self.config.cleanup_temp_files:
            self._cleanup_temp_files()

        # Cleanup ADB and Drozer
        self._cleanup_external_tools()

        # Cleanup any hanging processes that might block terminal
        self._cleanup_hanging_processes()

        # Reset signal handlers to default to prevent terminal blocking
        self._reset_signal_handlers()

        # Best-effort: write or update minimal report for CI/tools when output path is known
        try:
            self._write_or_upgrade_minimal_report(status="aborted", message="Scan terminated during graceful shutdown")
        except Exception:
            pass

    def _cleanup_system_processes(self):
        """Cleanup system processes using psutil if available."""
        if not PSUTIL_AVAILABLE:
            return

        try:
            current_pid = os.getpid()
            current_process = psutil.Process(current_pid)
            children = current_process.children(recursive=True)

            # Terminate child processes
            for child in children:
                try:
                    child.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Wait for termination
            gone, alive = psutil.wait_procs(children, timeout=2)

            # Force kill remaining
            for p in alive:
                try:
                    p.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        except Exception as e:
            self._log("debug", f"System process cleanup error: {e}")

    def _cleanup_temp_files(self):
        """Cleanup temporary files and directories."""
        try:
            # Cleanup common temp directories
            import tempfile
            _tmp = tempfile.gettempdir()
            temp_patterns = [
                f"{_tmp}/aods_*", f"{_tmp}/drozer_*", f"{_tmp}/intent_fuzzing_*", f"{_tmp}/frida_*",
            ]

            for pattern in temp_patterns:
                try:
                    subprocess.run(["rm", "-rf"] + [pattern], capture_output=True, timeout=2)
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass

        except Exception as e:
            self._log("debug", f"Temp file cleanup error: {e}")

    def _cleanup_external_tools(self):
        """Cleanup external tools like ADB and Drozer."""
        try:
            # Kill drozer processes safely (avoid raw pkill)
            try:
                from core.external.unified_tool_executor import kill_processes_by_pattern

                kill_processes_by_pattern("drozer")
            except Exception:
                pass

            # Kill ADB server and remove forwards via unified executor
            try:
                from core.external.unified_tool_executor import adb_kill_server, adb_remove_all_forwards

                _ = adb_kill_server(timeout=2.0)
                _ = adb_remove_all_forwards(timeout=2.0)
            except Exception:
                pass

        except Exception as e:
            self._log("debug", f"External tool cleanup error: {e}")

    def _reset_signal_handlers(self):
        """Reset signal handlers to default to prevent terminal blocking."""
        try:
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            signal.signal(signal.SIGTERM, signal.SIG_DFL)

            if os.name == "nt":
                try:
                    signal.signal(signal.CTRL_C_EVENT, signal.SIG_DFL)
                except AttributeError:
                    pass

            self._log("debug", "Signal handlers reset to default")
        except Exception as e:
            self._log("debug", f"Signal handler reset error: {e}")

    def _cleanup_hanging_processes(self):
        """Forcibly cleanup any hanging JADX or subprocess that might block terminal."""
        try:
            # Kill any hanging JADX, Python dyna, and ADB processes
            try:
                from core.external.unified_tool_executor import kill_processes_by_pattern

                kill_processes_by_pattern("jadx")
                kill_processes_by_pattern("dyna.py")
                kill_processes_by_pattern("adb")
            except Exception:
                pass

            self._log("debug", "Hanging processes cleaned up")
        except Exception as e:
            self._log("debug", f"Hanging process cleanup error: {e}")

    def _force_exit_timer(self):
        """Force exit after timeout if graceful shutdown fails."""
        time.sleep(self.config.force_timeout)

        if self.state != ShutdownState.CLEANUP_COMPLETE:
            self.state = ShutdownState.FORCE_EXIT
            self._log("warning", f"⚠️ Force exit after {self.config.force_timeout}s timeout")
            # Last-chance minimal report write
            try:
                self._write_or_upgrade_minimal_report(
                    status="aborted", message=f"Force exit after {self.config.force_timeout}s timeout"
                )
            except Exception:
                pass
            os._exit(1)

    def _emergency_cleanup(self):
        """Emergency cleanup called by atexit."""
        # Mark that we're in atexit cleanup (for safe logging)
        self._in_atexit_cleanup = True

        # OPTIMIZATION: Don't trigger emergency cleanup if already shutting down properly
        if self.state in [ShutdownState.SHUTDOWN_INITIATED, ShutdownState.CLEANUP_COMPLETE, ShutdownState.FORCE_EXIT]:
            return  # Already handled

        # LIGHTNING MODE: Minimal cleanup for Lightning scans to avoid delays
        is_lightning_scan = (hasattr(self, "_lightning_mode") and self._lightning_mode) or (
            # Check if any active plugins suggest Lightning mode
            any("lightning" in str(plugin).lower() for plugin in self.active_plugins)
        )

        if self.state == ShutdownState.RUNNING:
            if is_lightning_scan:
                self._log("debug", "⚡ Lightning mode: minimal emergency cleanup")
                # Only essential cleanup for Lightning
                self._cleanup_essential_only()
            else:
                self._log("warning", "🚨 Emergency cleanup triggered")
                self._cleanup_external_tools()

    def _cleanup_essential_only(self):
        """Essential-only cleanup for Lightning mode to minimize overhead."""
        try:
            # Only clean up critical resources
            if hasattr(self, "active_processes") and self.active_processes:
                for process in list(self.active_processes):
                    try:
                        if process.poll() is None:  # Still running
                            process.terminate()
                    except BaseException:
                        pass  # Ignore errors in Lightning mode
                self.active_processes.clear()
        except BaseException:
            pass  # Silent failure in Lightning mode

    def set_lightning_mode(self, enabled: bool = True):
        """Enable Lightning mode for minimal cleanup overhead."""
        self._lightning_mode = enabled
        if enabled:
            self._log("debug", "⚡ Lightning mode enabled: optimized cleanup behavior")

    # Public API methods

    def register_cleanup(self, func: Callable):
        """Register a cleanup function to be called during shutdown."""
        self.cleanup_functions.append(func)

    def register_plugin(self, plugin_name: str):
        """Register an active plugin."""
        self.active_plugins.add(plugin_name)

    def unregister_plugin(self, plugin_name: str):
        """Unregister a plugin (called when plugin completes)."""
        self.active_plugins.discard(plugin_name)

    def register_process(self, process_name: str, process):
        """Register an active process."""
        self.active_processes[process_name] = process

    def unregister_process(self, process_name: str):
        """Unregister a process (called when process completes)."""
        self.active_processes.pop(process_name, None)

    def is_shutdown_requested(self) -> bool:
        """Check if shutdown has been requested."""
        return self.shutdown_event.is_set()

    def wait_for_shutdown(self, timeout: Optional[float] = None) -> bool:
        """Wait for shutdown signal."""
        return self.shutdown_event.wait(timeout)

    @contextmanager
    def plugin_context(self, plugin_name: str):
        """Context manager for plugin execution."""
        self.register_plugin(plugin_name)
        try:
            yield
        finally:
            self.unregister_plugin(plugin_name)

    @contextmanager
    def process_context(self, process_name: str, process):
        """Context manager for process execution."""
        self.register_process(process_name, process)
        try:
            yield
        finally:
            self.unregister_process(process_name)

    def shutdown_now(self):
        """Trigger immediate graceful shutdown."""
        with self.shutdown_lock:
            if not self.signal_received:
                self.signal_received = True
                self._handle_shutdown_signal(signal.SIGTERM, None)

    # Internal helpers
    def _write_or_upgrade_minimal_report(self, status: str, message: str):
        """Write or upgrade the minimal JSON report at AODS_OUTPUT_PATH.

        If the file is missing/empty, create it. If it exists with 'started'/'running',
        upgrade to the provided status. Ignore errors silently.
        """
        try:
            out_path = os.environ.get("AODS_OUTPUT_PATH")
            if not out_path:
                # Fallback: parse command-line arguments for --output
                try:
                    import sys as _sys

                    argv = list(_sys.argv)
                    for i, arg in enumerate(argv):
                        if arg == "--output" and i + 1 < len(argv):
                            out_path = argv[i + 1]
                            break
                        if arg.startswith("--output="):
                            out_path = arg.split("=", 1)[1]
                            break
                except Exception:
                    out_path = None
            if not out_path:
                return
            import json as _json
            from pathlib import Path as _Path

            p = _Path(out_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            write_minimal = (not p.exists()) or (p.exists() and p.stat().st_size == 0)
            if not write_minimal and p.exists():
                try:
                    current = _json.loads(p.read_text(encoding="utf-8", errors="ignore") or "{}")
                    current_status = str(current.get("status", "")).lower()
                    if current_status in ("started", "running"):
                        write_minimal = True
                except Exception:
                    write_minimal = True
            if write_minimal:
                # Populate CI-relevant metadata to avoid unknowns gate failures
                try:
                    apk_path = os.environ.get("AODS_CURRENT_APK") or os.environ.get("AODS_APK_PATH") or ""
                    pkg_name = ""
                    if apk_path:
                        try:
                            from pathlib import Path as _P

                            pkg_name = _P(apk_path).stem or "apk"
                        except Exception:
                            pkg_name = "apk"
                    scan_mode = "static" if os.environ.get("AODS_STATIC_ONLY_HARD", "0") == "1" else "standard"
                    metadata_obj = {
                        "target_apk_path": apk_path or "unknown",
                        "package_name": pkg_name or "unknown",
                        "analysis_duration": 0,
                        "total_findings": 0,
                        "scan_mode": scan_mode,
                    }
                except Exception:
                    metadata_obj = {
                        "target_apk_path": "unknown",
                        "package_name": "unknown",
                        "analysis_duration": 0,
                        "total_findings": 0,
                        "scan_mode": "standard",
                    }
                minimal = {"status": status, "message": message, "findings": [], "metadata": metadata_obj}
                p.write_text(_json.dumps(minimal, indent=2), encoding="utf-8")
        except Exception:
            pass


# Global instance
_shutdown_manager: Optional[GracefulShutdownManager] = None


def get_shutdown_manager(config: Optional[ShutdownConfig] = None) -> GracefulShutdownManager:
    """Get the global shutdown manager instance."""
    global _shutdown_manager
    if _shutdown_manager is None:
        _shutdown_manager = GracefulShutdownManager(config)
    return _shutdown_manager


def reset_shutdown_manager():
    """Reset the global shutdown manager instance to prevent lingering effects."""
    global _shutdown_manager
    if _shutdown_manager is not None:
        try:
            # Force cleanup and reset signal handlers
            _shutdown_manager._cleanup_hanging_processes()
            _shutdown_manager._reset_signal_handlers()
            _shutdown_manager = None
        except Exception:
            # Force reset even if cleanup fails
            _shutdown_manager = None


def initialize_graceful_shutdown(output_mgr=None, config: Optional[ShutdownConfig] = None):
    """Initialize graceful shutdown for AODS."""
    manager = get_shutdown_manager(config)
    if output_mgr:
        manager.set_output_manager(output_mgr)
    return manager


# Convenience functions for backward compatibility


def register_cleanup(func: Callable):
    """Register a cleanup function."""
    get_shutdown_manager().register_cleanup(func)


def is_shutdown_requested() -> bool:
    """Check if shutdown has been requested."""
    return get_shutdown_manager().is_shutdown_requested()


def plugin_context(plugin_name: str):
    """Context manager for plugin execution."""
    return get_shutdown_manager().plugin_context(plugin_name)


def process_context(process_name: str, process):
    """Context manager for process execution."""
    return get_shutdown_manager().process_context(process_name, process)


def emergency_shutdown():
    """Emergency shutdown trigger."""
    with get_shutdown_manager().shutdown_lock:
        if not get_shutdown_manager().signal_received:
            get_shutdown_manager().signal_received = True
            get_shutdown_manager()._handle_shutdown_signal(signal.SIGTERM, None)
