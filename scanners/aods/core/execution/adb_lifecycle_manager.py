#!/usr/bin/env python3
"""
ADB Lifecycle Management Framework
==================================

Full Android Debug Bridge (ADB) lifecycle management with device connection
pooling, health monitoring, and automatic recovery for the unified execution framework.

Features:
- Device connection pooling and lifecycle management
- Device resource limits and cleanup procedures
- Device health monitoring and automatic recovery
- Integration with unified parallel execution framework
- Connection state management and failover
"""

import logging
import subprocess
import threading
import time
import weakref
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Callable
import uuid

try:
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class DeviceState(Enum):
    """Device connection states."""

    UNKNOWN = "unknown"
    OFFLINE = "offline"
    DEVICE = "device"
    UNAUTHORIZED = "unauthorized"
    CONNECTING = "connecting"
    RECOVERY = "recovery"
    FASTBOOT = "fastboot"
    SIDELOAD = "sideload"


class ConnectionHealth(Enum):
    """Connection health status."""

    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"


@dataclass
class DeviceInfo:
    """Information about an Android device."""

    device_id: str
    state: DeviceState
    model: Optional[str] = None
    android_version: Optional[str] = None
    api_level: Optional[int] = None
    architecture: Optional[str] = None
    connected_at: Optional[float] = None
    last_seen: Optional[float] = None
    connection_count: int = 0
    health: ConnectionHealth = ConnectionHealth.UNKNOWN

    def __post_init__(self):
        if self.connected_at is None:
            self.connected_at = time.time()
        if self.last_seen is None:
            self.last_seen = time.time()


@dataclass
class ConnectionPool:
    """ADB connection pool configuration and state."""

    max_connections: int = 5
    max_concurrent_per_device: int = 2
    connection_timeout: float = 30.0
    health_check_interval: float = 60.0
    max_retry_attempts: int = 3
    retry_delay: float = 2.0
    cleanup_interval: float = 300.0  # 5 minutes

    # Runtime state
    active_connections: Dict[str, Set[str]] = field(default_factory=dict)
    connection_history: List[Dict[str, Any]] = field(default_factory=list)
    last_cleanup: float = field(default_factory=time.time)


class ADBCommand:
    """Represents an ADB command execution request."""

    def __init__(self, command: List[str], device_id: Optional[str] = None, timeout: float = 30.0, retries: int = 3):
        self.id = str(uuid.uuid4())
        self.command = command
        self.device_id = device_id
        self.timeout = timeout
        self.retries = retries
        self.created_at = time.time()
        self.started_at: Optional[float] = None
        self.completed_at: Optional[float] = None
        self.result: Optional[subprocess.CompletedProcess] = None
        self.error: Optional[Exception] = None


class DeviceHealthMonitor:
    """Monitors device health and connection stability."""

    def __init__(self, lifecycle_manager: "ADBLifecycleManager"):
        self.lifecycle_manager = weakref.ref(lifecycle_manager)
        self.logger = logging.getLogger(__name__)
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.health_metrics: Dict[str, Dict[str, Any]] = {}

    def start_monitoring(self):
        """Start device health monitoring."""
        if self.monitoring:
            return

        # Check for resource-constrained mode
        import os

        resource_constrained = os.getenv("AODS_RESOURCE_CONSTRAINED") == "1" or os.getenv("AODS_MINIMAL_MODE") == "1"

        if resource_constrained:
            self.logger.info("🔧 Resource-constrained mode: ADB health monitoring thread disabled")
            self.monitoring = False
            self.monitor_thread = None
            return

        try:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True, name="ADB-HealthMonitor")
            self.monitor_thread.start()
            self.logger.info("Device health monitoring started")
        except RuntimeError as e:
            if "can't start new thread" in str(e):
                self.logger.warning(f"⚠️ Thread exhaustion detected - disabling ADB health monitoring: {e}")
                self.monitoring = False
                self.monitor_thread = None
            else:
                raise

    def stop_monitoring(self):
        """Stop device health monitoring."""
        self.monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)
        self.logger.info("Device health monitoring stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.monitoring:
            try:
                manager = self.lifecycle_manager()
                if manager:
                    self._check_all_devices(manager)
                time.sleep(manager.pool.health_check_interval if manager else 60)
            except Exception as e:
                self.logger.error(f"Health monitoring error: {e}")
                time.sleep(10)  # Brief pause on error

    def _check_all_devices(self, manager: "ADBLifecycleManager"):
        """Check health of all known devices."""
        current_time = time.time()

        for device_id, device in manager.devices.items():
            try:
                # Update last seen time
                device.last_seen = current_time

                # Check basic connectivity
                is_responsive = self._check_device_responsive(manager, device_id)

                # Update health metrics
                if device_id not in self.health_metrics:
                    self.health_metrics[device_id] = {
                        "response_times": [],
                        "failures": 0,
                        "last_failure": None,
                        "uptime_start": current_time,
                    }

                metrics = self.health_metrics[device_id]

                if is_responsive:
                    device.health = ConnectionHealth.HEALTHY
                    # Reset failure count on successful check
                    metrics["failures"] = 0
                else:
                    metrics["failures"] += 1
                    metrics["last_failure"] = current_time

                    # Update health based on failure count
                    if metrics["failures"] >= 3:
                        device.health = ConnectionHealth.CRITICAL
                        self._handle_critical_device(manager, device_id)
                    elif metrics["failures"] >= 2:
                        device.health = ConnectionHealth.UNHEALTHY
                    else:
                        device.health = ConnectionHealth.DEGRADED

            except Exception as e:
                self.logger.error(f"Error checking device {device_id}: {e}")
                device.health = ConnectionHealth.CRITICAL

    def _check_device_responsive(self, manager: "ADBLifecycleManager", device_id: str) -> bool:
        """Check if device is responsive to basic commands."""
        try:
            start_time = time.time()
            result = manager._execute_adb_command(["shell", "echo", "ping"], device_id, timeout=10.0)
            response_time = time.time() - start_time

            # Store response time
            metrics = self.health_metrics.get(device_id, {})
            response_times = metrics.get("response_times", [])
            response_times.append(response_time)

            # Keep only recent response times (last 10)
            if len(response_times) > 10:
                response_times = response_times[-10:]

            metrics["response_times"] = response_times

            return result.returncode == 0
        except Exception:
            return False

    def _handle_critical_device(self, manager: "ADBLifecycleManager", device_id: str):
        """Handle device in critical state."""
        self.logger.warning(f"Device {device_id} in critical state - attempting recovery")

        # Attempt device recovery
        try:
            manager._recover_device(device_id)
        except Exception as e:
            self.logger.error(f"Device recovery failed for {device_id}: {e}")

    def get_health_summary(self) -> Dict[str, Any]:
        """Get health summary for all monitored devices."""
        summary = {
            "total_devices": len(self.health_metrics),
            "healthy_devices": 0,
            "degraded_devices": 0,
            "unhealthy_devices": 0,
            "critical_devices": 0,
            "average_response_time": 0.0,
            "devices": {},
        }

        total_response_time = 0.0
        total_responses = 0

        for device_id, metrics in self.health_metrics.items():
            response_times = metrics.get("response_times", [])
            avg_response = sum(response_times) / len(response_times) if response_times else 0.0

            total_response_time += sum(response_times)
            total_responses += len(response_times)

            summary["devices"][device_id] = {
                "failures": metrics.get("failures", 0),
                "last_failure": metrics.get("last_failure"),
                "uptime_start": metrics.get("uptime_start"),
                "average_response_time": avg_response,
                "recent_responses": len(response_times),
            }

        if total_responses > 0:
            summary["average_response_time"] = total_response_time / total_responses

        return summary


class ADBLifecycleManager:
    """
    Full ADB lifecycle manager with device pooling and health monitoring.

    This manager provides:
    - Device discovery and connection management
    - Connection pooling with resource limits
    - Health monitoring and automatic recovery
    - Integration with unified execution framework
    """

    def __init__(self, pool_config: Optional[ConnectionPool] = None):
        self.pool = pool_config or ConnectionPool()
        self.logger = logging.getLogger(__name__)

        # Check for resource-constrained mode
        import os

        resource_constrained = os.getenv("AODS_RESOURCE_CONSTRAINED") == "1" or os.getenv("AODS_MINIMAL_MODE") == "1"

        # Device management
        self.devices: Dict[str, DeviceInfo] = {}
        self.device_lock = threading.RLock()

        # Connection management - use minimal workers in resource-constrained mode
        max_workers = 1 if resource_constrained else self.pool.max_connections

        try:
            self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ADB-Executor")
        except RuntimeError as e:
            if "can't start new thread" in str(e):
                self.logger.warning(f"⚠️ Thread exhaustion detected - using direct execution for ADB commands: {e}")
                self.executor = None  # Will use direct execution
            else:
                raise

        self.active_commands: Dict[str, ADBCommand] = {}
        self.command_lock = threading.Lock()

        # Health monitoring
        self.health_monitor = DeviceHealthMonitor(self)

        # Cleanup management
        self.cleanup_thread: Optional[threading.Thread] = None
        self.cleanup_running = False

        # Callbacks
        self.device_callbacks: List[Callable[[str, DeviceState], None]] = []
        self.health_callbacks: List[Callable[[str, ConnectionHealth], None]] = []

        # Initialize
        self._discover_devices()
        if not resource_constrained:
            self._start_cleanup_timer()
        else:
            self.logger.info("🔧 Resource-constrained mode: ADB cleanup thread disabled")

        worker_info = "direct execution" if self.executor is None else f"{max_workers} workers"
        self.logger.info(f"ADB Lifecycle Manager initialized with {len(self.devices)} devices ({worker_info})")

    def start(self):
        """Start the ADB lifecycle manager."""
        self.health_monitor.start_monitoring()
        self.logger.info("ADB Lifecycle Manager started")

    def stop(self):
        """Stop the ADB lifecycle manager and cleanup resources."""
        self.logger.info("Stopping ADB Lifecycle Manager...")

        # Stop health monitoring
        self.health_monitor.stop_monitoring()

        # Stop cleanup timer
        self.cleanup_running = False
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5.0)

        # Cancel active commands
        with self.command_lock:
            for command_id, command in self.active_commands.items():
                self.logger.warning(f"Cancelling active command: {command_id}")

        # Shutdown executor
        self.executor.shutdown(wait=True, timeout=10.0)

        self.logger.info("ADB Lifecycle Manager stopped")

    def _discover_devices(self):
        """Discover connected Android devices."""
        try:
            from core.external.unified_tool_executor import execute_adb_command

            result = execute_adb_command(["devices", "-l"], timeout=30.0)
            if getattr(result, "exit_code", getattr(result, "return_code", 0)) != 0:
                self.logger.warning("ADB not available or no devices found")
                return
            stdout_text = str(getattr(result, "stdout", ""))
            lines = stdout_text.strip().split("\n")[1:]  # Skip header

            with self.device_lock:
                for line in lines:
                    if line.strip() and "\t" in line:
                        parts = line.split("\t")
                        device_id = parts[0].strip()
                        state_str = parts[1].strip()

                        try:
                            state = DeviceState(state_str)
                        except ValueError:
                            state = DeviceState.UNKNOWN

                        if device_id not in self.devices:
                            device_info = DeviceInfo(device_id=device_id, state=state)
                            self.devices[device_id] = device_info
                            self._notify_device_callback(device_id, state)

                            # Get additional device info
                            self._populate_device_info(device_info)
                        else:
                            # Update existing device state
                            old_state = self.devices[device_id].state
                            self.devices[device_id].state = state
                            if old_state != state:
                                self._notify_device_callback(device_id, state)

            self.logger.info(f"Discovered {len(self.devices)} devices")

        except subprocess.TimeoutExpired:
            self.logger.error("ADB device discovery timed out")
        except Exception as e:
            self.logger.error(f"Error discovering devices: {e}")

    def _populate_device_info(self, device: DeviceInfo):
        """Populate additional device information."""
        if device.state != DeviceState.DEVICE:
            return  # Can only get info from connected devices

        try:
            # Get device model
            result = self._execute_adb_command(["shell", "getprop", "ro.product.model"], device.device_id)
            if result.returncode == 0:
                device.model = result.stdout.strip()

            # Get Android version
            result = self._execute_adb_command(["shell", "getprop", "ro.build.version.release"], device.device_id)
            if result.returncode == 0:
                device.android_version = result.stdout.strip()

            # Get API level
            result = self._execute_adb_command(["shell", "getprop", "ro.build.version.sdk"], device.device_id)
            if result.returncode == 0:
                try:
                    device.api_level = int(result.stdout.strip())
                except ValueError:
                    pass

            # Get architecture
            result = self._execute_adb_command(["shell", "getprop", "ro.product.cpu.abi"], device.device_id)
            if result.returncode == 0:
                device.architecture = result.stdout.strip()

        except Exception as e:
            self.logger.warning(f"Could not populate device info for {device.device_id}: {e}")

    def _execute_adb_command(self, command: List[str], device_id: Optional[str] = None, timeout: float = 30.0):
        """Execute an ADB command with device targeting using unified executor."""
        try:
            from core.external.unified_tool_executor import execute_adb_command

            args = command if device_id is None else (["-s", device_id] + command)
            return execute_adb_command(args, timeout=timeout)
        except Exception as e:
            self.logger.error(f"ADB command failed: {e}")

            class _Failed:
                returncode = 1
                stdout = ""
                stderr = str(e)

            return _Failed()

    def _recover_device(self, device_id: str):
        """Attempt to recover a problematic device."""
        self.logger.info(f"Attempting recovery for device {device_id}")

        try:
            # Try to restart ADB server using unified executor
            from core.external.unified_tool_executor import adb_kill_server, adb_start_server

            _ = adb_kill_server(timeout=10.0)
            time.sleep(2)
            _ = adb_start_server(timeout=10.0)

            # Rediscover devices
            self._discover_devices()

        except Exception as e:
            self.logger.error(f"Device recovery failed: {e}")

    def execute_command_async(
        self, command: List[str], device_id: Optional[str] = None, timeout: float = 30.0, retries: int = 3
    ) -> Future:
        """Execute an ADB command asynchronously."""
        adb_command = ADBCommand(command, device_id, timeout, retries)

        with self.command_lock:
            self.active_commands[adb_command.id] = adb_command

        # Handle direct execution mode when no thread pool is available
        if self.executor is None:
            from concurrent.futures import Future

            future = Future()
            try:
                result = self._execute_command_with_retry(adb_command)
                future.set_result(result)
            except Exception as e:
                future.set_exception(e)
            finally:
                # Cleanup command
                with self.command_lock:
                    self.active_commands.pop(adb_command.id, None)
            return future

        future = self.executor.submit(self._execute_command_with_retry, adb_command)

        # Add callback to cleanup
        def cleanup_command(fut):
            with self.command_lock:
                self.active_commands.pop(adb_command.id, None)

        future.add_done_callback(cleanup_command)

        return future

    def _execute_command_with_retry(self, adb_command: ADBCommand) -> subprocess.CompletedProcess:
        """Execute ADB command with retry logic."""
        adb_command.started_at = time.time()

        for attempt in range(adb_command.retries + 1):
            try:
                result = self._execute_adb_command(adb_command.command, adb_command.device_id, adb_command.timeout)

                adb_command.completed_at = time.time()
                adb_command.result = result

                if result.returncode == 0:
                    return result
                elif attempt < adb_command.retries:
                    self.logger.warning(
                        f"Command failed (attempt {attempt + 1}/{adb_command.retries + 1}): "
                        f"{' '.join(adb_command.command)}"
                    )
                    time.sleep(self.pool.retry_delay * (attempt + 1))  # Exponential backoff

            except subprocess.TimeoutExpired as e:
                adb_command.error = e
                if attempt < adb_command.retries:
                    self.logger.warning(f"Command timed out (attempt {attempt + 1}), retrying...")
                    time.sleep(self.pool.retry_delay)
                else:
                    raise
            except Exception as e:
                adb_command.error = e
                if attempt < adb_command.retries:
                    self.logger.warning(f"Command error (attempt {attempt + 1}): {e}")
                    time.sleep(self.pool.retry_delay)
                else:
                    raise

        # If we get here, all retries failed
        raise RuntimeError(f"Command failed after {adb_command.retries + 1} attempts")

    def get_available_devices(self) -> List[DeviceInfo]:
        """Get list of available devices."""
        with self.device_lock:
            return [
                device
                for device in self.devices.values()
                if device.state == DeviceState.DEVICE and device.health != ConnectionHealth.CRITICAL
            ]

    def get_device_info(self, device_id: str) -> Optional[DeviceInfo]:
        """Get information about a specific device."""
        with self.device_lock:
            return self.devices.get(device_id)

    def add_device_callback(self, callback: Callable[[str, DeviceState], None]):
        """Add callback for device state changes."""
        self.device_callbacks.append(callback)

    def add_health_callback(self, callback: Callable[[str, ConnectionHealth], None]):
        """Add callback for device health changes."""
        self.health_callbacks.append(callback)

    def _notify_device_callback(self, device_id: str, state: DeviceState):
        """Notify device state change callbacks."""
        for callback in self.device_callbacks:
            try:
                callback(device_id, state)
            except Exception as e:
                self.logger.error(f"Device callback error: {e}")

    def _notify_health_callback(self, device_id: str, health: ConnectionHealth):
        """Notify device health change callbacks."""
        for callback in self.health_callbacks:
            try:
                callback(device_id, health)
            except Exception as e:
                self.logger.error(f"Health callback error: {e}")

    def _start_cleanup_timer(self):
        """Start periodic cleanup timer."""
        # Check for resource-constrained mode
        import os

        resource_constrained = os.getenv("AODS_RESOURCE_CONSTRAINED") == "1" or os.getenv("AODS_MINIMAL_MODE") == "1"

        if resource_constrained:
            self.logger.info("🔧 Resource-constrained mode: ADB cleanup thread disabled")
            self.cleanup_running = False
            self.cleanup_thread = None
            return

        try:
            self.cleanup_running = True
            self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="ADB-Cleanup")
            self.cleanup_thread.start()
            self.logger.info("✅ ADB cleanup thread started")
        except RuntimeError as e:
            if "can't start new thread" in str(e):
                self.logger.warning(f"⚠️ Thread exhaustion detected - disabling ADB cleanup thread: {e}")
                self.cleanup_running = False
                self.cleanup_thread = None
            else:
                raise

    def _cleanup_loop(self):
        """Periodic cleanup loop."""
        while self.cleanup_running:
            try:
                time.sleep(self.pool.cleanup_interval)
                if self.cleanup_running:
                    self._perform_cleanup()
            except Exception as e:
                self.logger.error(f"Cleanup error: {e}")

    def _perform_cleanup(self):
        """Perform periodic cleanup tasks."""
        current_time = time.time()

        # Clean up old connection history
        with self.device_lock:
            self.pool.connection_history = [
                entry
                for entry in self.pool.connection_history
                if current_time - entry.get("timestamp", 0) < 3600  # Keep 1 hour
            ]

        # Rediscover devices to update status
        self._discover_devices()

        self.logger.debug("Periodic cleanup completed")

    def get_status_summary(self) -> Dict[str, Any]:
        """Get full status summary."""
        with self.device_lock:
            device_summary = {}
            for device_id, device in self.devices.items():
                device_summary[device_id] = {
                    "state": device.state.value,
                    "health": device.health.value,
                    "model": device.model,
                    "android_version": device.android_version,
                    "api_level": device.api_level,
                    "architecture": device.architecture,
                    "connected_at": device.connected_at,
                    "last_seen": device.last_seen,
                    "connection_count": device.connection_count,
                }

        with self.command_lock:
            active_commands = len(self.active_commands)

        health_summary = self.health_monitor.get_health_summary()

        return {
            "total_devices": len(self.devices),
            "available_devices": len(self.get_available_devices()),
            "active_commands": active_commands,
            "pool_config": {
                "max_connections": self.pool.max_connections,
                "max_concurrent_per_device": self.pool.max_concurrent_per_device,
                "connection_timeout": self.pool.connection_timeout,
            },
            "devices": device_summary,
            "health": health_summary,
        }


# Global ADB lifecycle manager instance
_adb_manager: Optional[ADBLifecycleManager] = None
_manager_lock = threading.Lock()


def get_adb_lifecycle_manager(pool_config: Optional[ConnectionPool] = None) -> ADBLifecycleManager:
    """Get the global ADB lifecycle manager instance."""
    global _adb_manager

    with _manager_lock:
        if _adb_manager is None:
            _adb_manager = ADBLifecycleManager(pool_config)
            _adb_manager.start()

    return _adb_manager


def shutdown_adb_lifecycle_manager():
    """Shutdown the global ADB lifecycle manager."""
    global _adb_manager

    with _manager_lock:
        if _adb_manager is not None:
            _adb_manager.stop()
            _adb_manager = None


# Integration with unified execution framework
def integrate_with_execution_manager(execution_manager):
    """Integrate ADB lifecycle manager with unified execution framework."""
    adb_manager = get_adb_lifecycle_manager()

    # Add device state callback to log changes
    def log_device_changes(device_id: str, state: DeviceState):
        execution_manager.logger.info(f"Device {device_id} state changed to {state.value}")

    adb_manager.add_device_callback(log_device_changes)

    # Add health callback to log health changes
    def log_health_changes(device_id: str, health: ConnectionHealth):
        execution_manager.logger.info(f"Device {device_id} health changed to {health.value}")

    adb_manager.add_health_callback(log_health_changes)

    return adb_manager
