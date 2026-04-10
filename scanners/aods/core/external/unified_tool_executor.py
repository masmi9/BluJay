"""
Unified External Tool Execution Framework

This module provides a standardized approach to executing external tools
(ADB, Frida, JADX) with consistent error handling, resource cleanup, and
timeout management across all AODS components.
"""

import subprocess
import time
import os
import signal
import psutil
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

# MIGRATED: Import unified caching infrastructure
from core.shared_infrastructure.performance.caching_consolidation import get_unified_cache_manager, CacheType
from .policy import ExternalToolPolicy

try:
    from core.logging_config import get_logger
except ImportError:
    import logging as stdlib_logging

    get_logger = stdlib_logging.getLogger

logger = get_logger(__name__)


# Global semaphore to cap concurrent external processes (ADB/JADX/Frida/etc.)
_GLOBAL_PROC_SEMAPHORE = None


def _get_global_process_semaphore() -> threading.BoundedSemaphore:
    """Create or retrieve a global semaphore for external process concurrency.
    The limit is configured via AODS_MAX_EXTERNAL_PROCS (default depends on mode).
    """
    global _GLOBAL_PROC_SEMAPHORE
    if _GLOBAL_PROC_SEMAPHORE is None:
        # Detect constrained mode
        resource_constrained = os.getenv("AODS_RESOURCE_CONSTRAINED") == "1" or os.getenv("AODS_MINIMAL_MODE") == "1"

        default_max = 1 if resource_constrained else 2
        try:
            max_procs = int(os.getenv("AODS_MAX_EXTERNAL_PROCS", str(default_max)))
        except Exception:
            max_procs = default_max

        if max_procs < 1:
            max_procs = 1

        _GLOBAL_PROC_SEMAPHORE = threading.BoundedSemaphore(value=max_procs)
    return _GLOBAL_PROC_SEMAPHORE


class ToolType(Enum):
    """Supported external tool types."""

    ADB = "adb"
    FRIDA = "frida"
    JADX = "jadx"
    AAPT = "aapt"
    PYTHON = "python"
    CUSTOM = "custom"


class ExecutionStatus(Enum):
    """Execution status for tool operations."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    RESOURCE_ERROR = "resource_error"


@dataclass
class ToolConfiguration:
    """Configuration for external tool execution."""

    tool_type: ToolType
    executable_path: Optional[str] = None
    timeout_seconds: float = 30.0
    max_memory_mb: Optional[int] = None
    max_retries: int = 3
    retry_delay: float = 1.0
    environment_vars: Dict[str, str] = field(default_factory=dict)
    working_directory: Optional[str] = None
    capture_output: bool = True
    text_mode: bool = True
    shell_mode: bool = False
    safety_checks: bool = True
    cleanup_on_failure: bool = True
    resource_monitoring: bool = True


@dataclass
class ExecutionResult:
    """Result of external tool execution."""

    status: ExecutionStatus
    return_code: int
    stdout: str
    stderr: str
    execution_time: float
    peak_memory_mb: Optional[float] = None
    process_id: Optional[int] = None
    command: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    cleanup_performed: bool = False
    retry_count: int = 0


class UnifiedToolExecutor:
    """
    Unified executor for all external tools with standardized patterns.

    Provides:
    - Consistent subprocess execution patterns
    - Timeout management with process tree cleanup
    - Resource monitoring and limits
    - Retry logic with exponential backoff
    - Safety checks for dangerous commands
    - Automatic cleanup of temporary resources
    - Process isolation and signal handling
    """

    def __init__(self):
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        self.active_processes: Dict[str, subprocess.Popen] = {}
        # Configure lightweight monitoring pool; size via env for flexibility
        resource_constrained = os.getenv("AODS_RESOURCE_CONSTRAINED") == "1" or os.getenv("AODS_MINIMAL_MODE") == "1"
        try:
            default_threads = 2 if resource_constrained else 4
            pool_size = int(os.getenv("AODS_TOOL_EXECUTOR_THREADS", str(default_threads)))
        except Exception:
            pool_size = 2 if resource_constrained else 4
        if pool_size < 1:
            pool_size = 1
        self._shutting_down = False
        self.executor = ThreadPoolExecutor(max_workers=pool_size, thread_name_prefix="tool-executor")

        # MIGRATED: Use unified caching infrastructure for tool paths cache
        self.cache_manager = get_unified_cache_manager()
        self.tool_paths_cache: Dict[ToolType, Optional[str]] = {}

        # Default configurations for common tools
        self.default_configs = {
            ToolType.ADB: ToolConfiguration(
                tool_type=ToolType.ADB, timeout_seconds=30.0, max_retries=3, safety_checks=True
            ),
            ToolType.FRIDA: ToolConfiguration(
                tool_type=ToolType.FRIDA, timeout_seconds=60.0, max_retries=2, resource_monitoring=True
            ),
            ToolType.JADX: ToolConfiguration(
                tool_type=ToolType.JADX,
                timeout_seconds=300.0,  # 5 minutes for decompilation
                max_memory_mb=2048,
                max_retries=2,
                resource_monitoring=True,
            ),
            ToolType.AAPT: ToolConfiguration(tool_type=ToolType.AAPT, timeout_seconds=30.0, max_retries=2),
        }

    def execute_tool(
        self,
        tool_type: ToolType,
        command_args: List[str],
        config: Optional[ToolConfiguration] = None,
        input_data: Optional[str] = None,
    ) -> ExecutionResult:
        """
        Execute an external tool with unified error handling and cleanup.

        Args:
            tool_type: Type of tool to execute
            command_args: Command arguments (excluding executable path)
            config: Optional configuration override
            input_data: Optional input data to pass to stdin

        Returns:
            ExecutionResult with full execution information
        """
        # Use provided config or default
        if config is None:
            config = self.default_configs.get(tool_type, ToolConfiguration(tool_type=tool_type))

        start_time = time.time()

        try:
            # Static-only external tools policy enforcement (pre-check before any resolution)
            if ExternalToolPolicy.is_denied(tool_type):
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    return_code=-1,
                    stdout="",
                    stderr=ExternalToolPolicy.denial_reason(tool_type),
                    execution_time=0.0,
                    error_message=ExternalToolPolicy.denial_reason(tool_type),
                )

            # Find executable path
            executable = self._find_executable(tool_type, config.executable_path)
            if not executable:
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    return_code=-1,
                    stdout="",
                    stderr=f"Executable for {tool_type.value} not found",
                    execution_time=0.0,
                    error_message=f"Tool {tool_type.value} not available",
                )

            # Build full command
            full_command = [executable] + command_args

            # Apply safety checks
            if config.safety_checks and not self._validate_command_safety(full_command):
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    return_code=-1,
                    stdout="",
                    stderr="Command blocked by safety checks",
                    execution_time=0.0,
                    command=full_command,
                    error_message="Dangerous command blocked",
                )

            # Execute with retries
            for attempt in range(config.max_retries + 1):
                try:
                    result = self._execute_with_monitoring(full_command, config, input_data, attempt)

                    # Success or non-retryable failure
                    if result.status == ExecutionStatus.SUCCESS or attempt == config.max_retries:
                        result.retry_count = attempt
                        return result

                    # Retry delay
                    if attempt < config.max_retries:
                        delay = config.retry_delay * (2**attempt)  # Exponential backoff
                        self.logger.info(f"Retrying {tool_type.value} execution in {delay}s (attempt {attempt + 1})")
                        time.sleep(delay)

                except Exception as e:
                    if attempt == config.max_retries:
                        return ExecutionResult(
                            status=ExecutionStatus.FAILURE,
                            return_code=-1,
                            stdout="",
                            stderr=str(e),
                            execution_time=time.time() - start_time,
                            command=full_command,
                            error_message=f"Execution failed after {config.max_retries + 1} attempts: {e}",
                            retry_count=attempt,
                        )

                    # Wait before retry
                    if attempt < config.max_retries:
                        delay = config.retry_delay * (2**attempt)
                        time.sleep(delay)

            # Should not reach here
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                return_code=-1,
                stdout="",
                stderr="Unexpected execution path",
                execution_time=time.time() - start_time,
                command=full_command,
                error_message="Unexpected execution failure",
            )

        except Exception as e:
            self.logger.error(f"Tool execution failed: {e}")
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                return_code=-1,
                stdout="",
                stderr=str(e),
                execution_time=time.time() - start_time,
                error_message=f"Execution error: {e}",
            )

    def _execute_with_monitoring(
        self, command: List[str], config: ToolConfiguration, input_data: Optional[str], attempt: int
    ) -> ExecutionResult:
        """Execute command with resource monitoring and timeout handling."""
        start_time = time.time()
        peak_memory_mb = 0.0
        process = None
        acquired_slot = False
        process_id = None

        try:
            # Acquire global external process slot to prevent system exhaustion
            sem = _get_global_process_semaphore()
            # Reasonable acquire timeout to avoid indefinite blocking before process timeout kicks in
            try:
                acquire_timeout = min(30.0, max(5.0, (config.timeout_seconds or 30.0) * 0.25))
            except Exception:
                acquire_timeout = 15.0
            acquired_slot = sem.acquire(timeout=acquire_timeout)
            if not acquired_slot:
                return ExecutionResult(
                    status=ExecutionStatus.RESOURCE_ERROR,
                    return_code=-1,
                    stdout="",
                    stderr=f"External process concurrency limit reached (waited {acquire_timeout}s)",
                    execution_time=time.time() - start_time,
                    command=command,
                    error_message="Concurrency throttle engaged",
                )

            # Prepare environment
            env = os.environ.copy()
            env.update(config.environment_vars)

            # Start process
            self.logger.info(
                f"Executing {' '.join(command)} (attempt {attempt + 1}, timeout: {config.timeout_seconds}s)"
            )

            # Security: shell_mode=True enables command injection - block it
            if config.shell_mode:
                raise ValueError(
                    "shell_mode=True is disabled for security (command injection risk). "
                    "Use argument lists instead."
                )

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE if config.capture_output else None,
                stderr=subprocess.PIPE if config.capture_output else None,
                stdin=subprocess.PIPE if input_data else None,
                text=config.text_mode,
                shell=False,
                env=env,
                cwd=config.working_directory,
                preexec_fn=os.setsid if os.name != "nt" else None,
            )

            process_id = str(process.pid)
            self.active_processes[process_id] = process

            # Monitor execution with timeout
            if config.resource_monitoring:
                stdout, stderr, peak_memory_mb = self._monitor_process_with_resources(
                    process, config.timeout_seconds, config.max_memory_mb, input_data
                )
            else:
                try:
                    stdout, stderr = process.communicate(input=input_data, timeout=config.timeout_seconds)
                except subprocess.TimeoutExpired:
                    self._terminate_process_tree(process)
                    return ExecutionResult(
                        status=ExecutionStatus.TIMEOUT,
                        return_code=-1,
                        stdout="",
                        stderr=f"Process timed out after {config.timeout_seconds} seconds",
                        execution_time=time.time() - start_time,
                        process_id=process.pid,
                        command=command,
                        error_message="Execution timeout",
                    )

            execution_time = time.time() - start_time

            # Clean up process tracking
            if process_id in self.active_processes:
                del self.active_processes[process_id]

            # Determine status
            if process.returncode == 0:
                status = ExecutionStatus.SUCCESS
                error_message = None
            else:
                status = ExecutionStatus.FAILURE
                error_message = f"Process exited with code {process.returncode}"

            return ExecutionResult(
                status=status,
                return_code=process.returncode,
                stdout=stdout or "",
                stderr=stderr or "",
                execution_time=execution_time,
                peak_memory_mb=peak_memory_mb if peak_memory_mb > 0 else None,
                process_id=process.pid,
                command=command,
                error_message=error_message,
            )

        except subprocess.TimeoutExpired:
            if process:
                self._terminate_process_tree(process)
            return ExecutionResult(
                status=ExecutionStatus.TIMEOUT,
                return_code=-1,
                stdout="",
                stderr=f"Process timed out after {config.timeout_seconds} seconds",
                execution_time=time.time() - start_time,
                process_id=process.pid if process else None,
                command=command,
                error_message="Execution timeout",
            )

        except Exception as e:
            if process:
                self._terminate_process_tree(process)
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                return_code=-1,
                stdout="",
                stderr=str(e),
                execution_time=time.time() - start_time,
                process_id=process.pid if process else None,
                command=command,
                error_message=f"Execution error: {e}",
            )
        finally:
            # Cleanup
            if process_id and process_id in self.active_processes:
                del self.active_processes[process_id]
            if acquired_slot:
                try:
                    _get_global_process_semaphore().release()
                except Exception:
                    pass

    def _monitor_process_with_resources(
        self, process: subprocess.Popen, timeout: float, max_memory_mb: Optional[int], input_data: Optional[str]
    ) -> tuple:
        """Monitor process execution with resource limits."""
        start_time = time.time()
        peak_memory_mb = 0.0

        try:
            # Start communication in background (guard executor state)
            try:
                if self._shutting_down or self.executor._shutdown:
                    raise RuntimeError("Executor is shutting down")
                future = self.executor.submit(process.communicate, input_data)
            except (RuntimeError, Exception) as e:
                logger.debug(f"Resource monitoring submission failed: {e}")
                # Fallback: do direct communicate with timeout
                try:
                    stdout, stderr = process.communicate(input=input_data, timeout=max(5.0, timeout))
                    return stdout, stderr, peak_memory_mb
                except subprocess.TimeoutExpired:
                    self._terminate_process_tree(process)
                    raise

            # Monitor resources
            while not future.done():
                try:
                    # Check timeout
                    elapsed = time.time() - start_time
                    if elapsed > timeout:
                        self._terminate_process_tree(process)
                        raise subprocess.TimeoutExpired(process.args, timeout)

                    # Monitor memory usage
                    if process.poll() is None:  # Process still running
                        try:
                            proc = psutil.Process(process.pid)
                            memory_mb = proc.memory_info().rss / (1024 * 1024)
                            peak_memory_mb = max(peak_memory_mb, memory_mb)

                            # Check memory limit
                            if max_memory_mb and memory_mb > max_memory_mb:
                                self.logger.warning(
                                    f"Process {process.pid} exceeded memory limit ({memory_mb:.1f}MB > {max_memory_mb}MB)"  # noqa: E501
                                )
                                self._terminate_process_tree(process)
                                raise RuntimeError(
                                    f"Process exceeded memory limit: {memory_mb:.1f}MB > {max_memory_mb}MB"
                                )

                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            # Process ended or access denied
                            pass

                    time.sleep(0.1)  # Small delay to avoid busy waiting

                except Exception as e:
                    self.logger.debug(f"Resource monitoring error: {e}")
                    break

            # Get results
            try:
                stdout, stderr = future.result(timeout=1.0)
                return stdout, stderr, peak_memory_mb
            except FutureTimeoutError:
                self._terminate_process_tree(process)
                raise subprocess.TimeoutExpired(process.args, timeout)

        except subprocess.TimeoutExpired:
            raise
        except Exception as e:
            self.logger.error(f"Resource monitoring failed: {e}")
            # Fallback to basic communication
            try:
                stdout, stderr = process.communicate(
                    input=input_data, timeout=max(5.0, timeout - (time.time() - start_time))
                )
                return stdout, stderr, peak_memory_mb
            except subprocess.TimeoutExpired:
                self._terminate_process_tree(process)
                raise

    def _find_executable(self, tool_type: ToolType, explicit_path: Optional[str] = None) -> Optional[str]:
        """Find executable path for the specified tool."""
        if explicit_path:
            if os.path.isfile(explicit_path) and os.access(explicit_path, os.X_OK):
                return explicit_path
            else:
                self.logger.warning(f"Explicit path {explicit_path} not found or not executable")

        # Check unified cache first (namespaced key), then local memo
        try:
            cache_key = f"tool_paths:{tool_type.value}"
            cached = self.cache_manager.retrieve(cache_key, CacheType.GENERAL)
            if isinstance(cached, str) and cached:
                self.tool_paths_cache[tool_type] = cached
                return cached
        except Exception:
            pass
        if tool_type in self.tool_paths_cache:
            return self.tool_paths_cache[tool_type]

        # Common paths for each tool type
        search_paths = {
            ToolType.ADB: ["adb", "/usr/bin/adb", "/usr/local/bin/adb", "~/Android/Sdk/platform-tools/adb"],
            ToolType.FRIDA: ["frida", "/usr/bin/frida", "/usr/local/bin/frida"],
            ToolType.JADX: ["jadx", "jadx-cli", "/usr/bin/jadx", "/usr/local/bin/jadx", "/opt/jadx/bin/jadx"],
            ToolType.AAPT: ["aapt", "/usr/bin/aapt", "/usr/local/bin/aapt"],
            ToolType.PYTHON: ["python3", "python", "/usr/bin/python3", "/usr/local/bin/python3"],
        }

        paths_to_check = search_paths.get(tool_type, [tool_type.value])

        for path in paths_to_check:
            expanded_path = os.path.expanduser(path)

            # Check if it's an absolute path
            if os.path.isabs(expanded_path):
                if os.path.isfile(expanded_path) and os.access(expanded_path, os.X_OK):
                    self.tool_paths_cache[tool_type] = expanded_path
                    try:
                        self.cache_manager.store(cache_key, expanded_path, CacheType.GENERAL, ttl_hours=24, tags=["tool_paths"])  # type: ignore  # noqa: E501
                    except Exception:
                        pass
                    return expanded_path
            else:
                # Check in PATH
                try:
                    result = subprocess.run(["which", path], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0 and result.stdout.strip():
                        found_path = result.stdout.strip()
                        self.tool_paths_cache[tool_type] = found_path
                        try:
                            self.cache_manager.store(cache_key, found_path, CacheType.GENERAL, ttl_hours=24, tags=["tool_paths"])  # type: ignore  # noqa: E501
                        except Exception:
                            pass
                        return found_path
                except Exception:
                    pass

        # Not found
        self.tool_paths_cache[tool_type] = None
        return None

    def _validate_command_safety(self, command: List[str]) -> bool:
        """Validate command for safety (prevent dangerous operations)."""
        if not command:
            return False

        # Convert to lowercase string for checking
        cmd_str = " ".join(command).lower()

        # Dangerous patterns to block
        dangerous_patterns = [
            "rm -rf /",
            "format",
            "wipe",
            "factory",
            "dd if=",
            "mkfs",
            "fdisk",
            "parted",
            "> /dev/",
            "chmod 777 /",
            "chown root /",
        ]

        for pattern in dangerous_patterns:
            if pattern in cmd_str:
                self.logger.warning(f"Blocked dangerous command pattern: {pattern}")
                return False

        return True

    def _terminate_process_tree(self, process: subprocess.Popen) -> None:
        """Terminate process and all its children."""
        if not process or process.poll() is not None:
            return

        try:
            # Get process tree
            parent = psutil.Process(process.pid)
            children = parent.children(recursive=True)

            # Terminate children first
            for child in children:
                try:
                    child.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Terminate parent
            parent.terminate()

            # Wait for graceful termination
            gone, alive = psutil.wait_procs(children + [parent], timeout=3)

            # Force kill if still alive
            for proc in alive:
                try:
                    proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Process already gone or access denied
            pass
        except Exception as e:
            self.logger.error(f"Error terminating process tree: {e}")
            # Fallback to basic termination
            try:
                if os.name != "nt":
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                else:
                    process.terminate()
            except Exception:
                pass

    def cleanup_all_processes(self) -> None:
        """Clean up all active processes."""
        for process_id, process in list(self.active_processes.items()):
            try:
                self._terminate_process_tree(process)
            except Exception as e:
                self.logger.error(f"Error cleaning up process {process_id}: {e}")

        self.active_processes.clear()

    def shutdown(self) -> None:
        """Idempotent shutdown that avoids unnecessary cleanup when no sessions exist."""
        if getattr(self, "_shutting_down", False):
            return
        self._shutting_down = True
        try:
            if self.active_processes:
                self.cleanup_all_processes()
        finally:
            try:
                self.executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                # Python < 3.9 doesn't support cancel_futures
                self.executor.shutdown(wait=False)
            except Exception:
                pass

    def get_tool_info(self, tool_type: ToolType) -> Dict[str, Any]:
        """Get information about a tool's availability and configuration."""
        executable = self._find_executable(tool_type)
        config = self.default_configs.get(tool_type)

        info = {
            "tool_type": tool_type.value,
            "available": executable is not None,
            "executable_path": executable,
            "default_timeout": config.timeout_seconds if config else None,
            "max_retries": config.max_retries if config else None,
        }

        # Try to get version info
        if executable and tool_type != ToolType.CUSTOM:
            try:
                version_args = {
                    ToolType.ADB: ["version"],
                    ToolType.JADX: ["--version"],
                    ToolType.AAPT: ["version"],
                    ToolType.PYTHON: ["--version"],
                }.get(tool_type, ["--version"])

                result = subprocess.run([executable] + version_args, capture_output=True, text=True, timeout=5)

                if result.returncode == 0:
                    info["version"] = result.stdout.strip() or result.stderr.strip()

            except Exception as e:
                info["version_error"] = str(e)

        return info

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()


# Convenience functions for common operations
def execute_adb_command(
    command_args: List[str], device_id: Optional[str] = None, timeout: float = 30.0
) -> ExecutionResult:
    """Execute ADB command with standardized handling."""
    # Static-only hard gate: avoid adb calls entirely
    if os.getenv("AODS_STATIC_ONLY") == "1" or os.getenv("AODS_STATIC_ONLY_HARD") == "1":
        return ExecutionResult(
            status=ExecutionStatus.CANCELLED,
            return_code=-1,
            stdout="",
            stderr="ADB disabled in static-only mode",
            execution_time=0.0,
            error_message="Tool ADB denied by ExternalToolPolicy",
        )
    executor = get_global_executor()

    # Add device targeting if specified
    if device_id:
        command_args = ["-s", device_id] + command_args

    config = ToolConfiguration(tool_type=ToolType.ADB, timeout_seconds=timeout, safety_checks=True)

    return executor.execute_tool(ToolType.ADB, command_args, config)


def execute_jadx_decompilation(
    apk_path: str, output_dir: str, timeout: float = 300.0, memory_limit_mb: int = 2048
) -> ExecutionResult:
    """Execute JADX decompilation with standardized handling."""
    executor = get_global_executor()

    # Prefer centralized decompilation policy; fallback to legacy flags on error
    try:
        from core.decompilation_policy_resolver import get_decompilation_policy
        import os as _os

        profile = _os.getenv("AODS_APP_PROFILE", "production")
        policy = get_decompilation_policy(apk_path=apk_path, profile=profile, plugin_requirements=None)
        policy_flags = list(policy.flags)
        command_args = ["-d", output_dir, "--show-bad-code", *policy_flags, apk_path]
    except Exception:
        command_args = ["-d", output_dir, "--show-bad-code", apk_path]

    config = ToolConfiguration(
        tool_type=ToolType.JADX, timeout_seconds=timeout, max_memory_mb=memory_limit_mb, resource_monitoring=True
    )

    return executor.execute_tool(ToolType.JADX, command_args, config)


def execute_frida_script(script_path: str, target_process: str, timeout: float = 60.0) -> ExecutionResult:
    """Execute Frida script with standardized handling."""
    # Static-only hard gate: avoid frida calls entirely
    if os.getenv("AODS_STATIC_ONLY") == "1" or os.getenv("AODS_STATIC_ONLY_HARD") == "1":
        return ExecutionResult(
            status=ExecutionStatus.CANCELLED,
            return_code=-1,
            stdout="",
            stderr="Frida disabled in static-only mode",
            execution_time=0.0,
            error_message="Tool FRIDA denied by ExternalToolPolicy",
        )
    executor = get_global_executor()

    command_args = ["-l", script_path, target_process]

    config = ToolConfiguration(tool_type=ToolType.FRIDA, timeout_seconds=timeout, resource_monitoring=True)

    return executor.execute_tool(ToolType.FRIDA, command_args, config)


# Global executor instance for reuse
_global_executor: Optional[UnifiedToolExecutor] = None


def get_global_executor() -> UnifiedToolExecutor:
    """Get or create global executor instance."""
    global _global_executor
    if _global_executor is None:
        _global_executor = UnifiedToolExecutor()
    return _global_executor


def shutdown_global_executor() -> None:
    """Shut down the global executor if it exists, releasing its thread pool."""
    global _global_executor
    if _global_executor is not None:
        try:
            _global_executor.shutdown()
        except Exception:
            pass
        _global_executor = None


# Additional convenience helpers for common external tool flows
def list_adb_devices(timeout: float = 10.0) -> List[str]:
    """Return list of connected ADB devices (raw lines excluding header)."""
    result = execute_adb_command(["devices"], timeout=timeout)
    if result.status != ExecutionStatus.SUCCESS:
        return []
    lines = [ln.strip() for ln in (result.stdout or "").splitlines()]
    return [ln for ln in lines[1:] if ln]


def adb_kill_server(timeout: float = 10.0) -> ExecutionResult:
    return execute_adb_command(["kill-server"], timeout=timeout)


def adb_start_server(timeout: float = 10.0) -> ExecutionResult:
    return execute_adb_command(["start-server"], timeout=timeout)


def adb_remove_all_forwards(timeout: float = 10.0) -> ExecutionResult:
    return execute_adb_command(["forward", "--remove-all"], timeout=timeout)


def execute_adb_shell(shell_args: List[str], timeout: float = 10.0) -> ExecutionResult:
    """Execute an ADB shell command with given args (e.g., ['ps'])."""
    return execute_adb_command(["shell"] + list(shell_args), timeout=timeout)


def check_frida_available(timeout: float = 5.0) -> Dict[str, Any]:
    """Return FRIDA tool availability/version info using unified executor."""
    execu = get_global_executor()
    info = execu.get_tool_info(ToolType.FRIDA)
    # If version not present, try --version once
    if info.get("available") and not info.get("version"):
        _ = execu.execute_tool(
            ToolType.FRIDA, ["--version"], ToolConfiguration(tool_type=ToolType.FRIDA, timeout_seconds=timeout)
        )
        info.update(execu.get_tool_info(ToolType.FRIDA))
    return info


def kill_processes_by_pattern(pattern: str, timeout_seconds: float = 2.0) -> int:
    """Terminate processes whose cmdline or name contains the given pattern.
    Returns number of processes signaled. Avoids raw pkill.
    """
    count = 0
    try:
        for proc in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
            try:
                name = proc.info.get("name") or ""
                cmd = " ".join(proc.info.get("cmdline") or [])
                if pattern in name or pattern in cmd:
                    proc.terminate()
                    count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        # Wait briefly for termination
        psutil.wait_procs([p for p in psutil.process_iter() if p.is_running()], timeout=timeout_seconds)
    except Exception:
        # Best effort; return count so far
        pass
    return count
