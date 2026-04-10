"""
Device Manager for Advanced Dynamic Analysis Plugin

This module handles device connection, validation, and management for dynamic analysis.
Provides full device state management and error handling.
"""

import logging
from typing import Dict, List, Optional, Tuple

# MIGRATED: Add unified timeout manager support
from core.timeout import UnifiedTimeoutManager, TimeoutType

from .data_structures import DeviceInfo, DeviceStatus, DEFAULT_TIMEOUT

logger = logging.getLogger(__name__)


class DeviceManager:
    """Manages device connections and validation for dynamic analysis"""

    def __init__(self, default_duration: int = DEFAULT_TIMEOUT):
        """Initialize device manager with configuration"""
        self.default_duration = default_duration
        self.connected_devices: Dict[str, DeviceInfo] = {}
        self.logger = logging.getLogger(__name__)

        # MIGRATED: Initialize unified timeout manager for all device operations
        self._timeout_manager = UnifiedTimeoutManager()

    def _adb_exec(self, args: List[str], device_id: Optional[str] = None, timeout: float = 30.0):
        """Execute an ADB command via the unified executor with subprocess fallback.

        Returns an object with returncode, stdout, stderr similar to subprocess.CompletedProcess.
        """
        try:
            from core.external.unified_tool_executor import execute_adb_command

            cmd_args = (["-s", device_id] + args) if device_id else list(args)
            result = execute_adb_command(cmd_args, timeout=timeout)

            class _Resp:
                pass

            resp = _Resp()
            resp.returncode = getattr(result, "exit_code", getattr(result, "return_code", 0))
            resp.stdout = str(getattr(result, "stdout", ""))
            resp.stderr = str(getattr(result, "stderr", ""))
            return resp
        except Exception as sub_exc:
            # Disallow raw subprocess for ADB to comply with External Tools CI Guard
            class _Fail:
                returncode = 127
                stdout = ""
                stderr = f"Unified executor unavailable for ADB: {sub_exc}"

            return _Fail()

    def check_device_connection(self) -> DeviceInfo:
        """
        Check device connection status and retrieve device information

        Returns:
            DeviceInfo: Complete device information and status
        """
        try:
            # MIGRATED: Use unified timeout manager for device connection check
            with self._timeout_manager.timeout_context(
                operation_name="device_connection_check",
                timeout_type=TimeoutType.NETWORK,
                timeout_seconds=self.default_duration,
            ):
                result = self._adb_exec(["devices", "-l"], timeout=self.default_duration)

            if result.returncode != 0:
                self.logger.error(f"ADB devices command failed: {result.stderr}")
                return DeviceInfo(
                    device_id="unknown",
                    status=DeviceStatus.UNKNOWN,
                    error_message=f"ADB command failed: {result.stderr}",
                )

            # Parse device list
            devices = self._parse_device_list(result.stdout)

            if not devices:
                self.logger.warning("No devices found")
                return DeviceInfo(
                    device_id="none", status=DeviceStatus.DISCONNECTED, error_message="No devices connected"
                )

            # Get the first available device
            device_id = list(devices.keys())[0]
            device_status = devices[device_id]

            # Get detailed device information
            device_info = self._get_device_details(device_id, device_status)

            # Cache the device information
            self.connected_devices[device_id] = device_info

            return device_info

        except TimeoutError:
            self.logger.error("Device connection check exceeded duration limit")
            return DeviceInfo(
                device_id="connection_failed",
                status=DeviceStatus.UNKNOWN,
                error_message="Device connection check exceeded duration limit",
            )
        except Exception as e:
            self.logger.error(f"Error checking device connection: {e}")
            return DeviceInfo(
                device_id="error", status=DeviceStatus.UNKNOWN, error_message=f"Error checking device: {str(e)}"
            )

    def _parse_device_list(self, adb_output: str) -> Dict[str, DeviceStatus]:
        """Parse ADB devices output to extract device information"""
        devices = {}
        lines = adb_output.strip().split("\n")

        for line in lines:
            if line.startswith("List of devices"):
                continue
            if not line.strip():
                continue

            # Parse device line format: "device_id	status	device_info"
            parts = line.split("\t")
            if len(parts) >= 2:
                device_id = parts[0].strip()
                status_str = parts[1].strip()

                # Map ADB status to our enum
                if status_str == "device":
                    status = DeviceStatus.CONNECTED
                elif status_str == "unauthorized":
                    status = DeviceStatus.UNAUTHORIZED
                elif status_str == "offline":
                    status = DeviceStatus.OFFLINE
                else:
                    status = DeviceStatus.UNKNOWN

                devices[device_id] = status

        return devices

    def _get_device_details(self, device_id: str, status: DeviceStatus) -> DeviceInfo:
        """Get detailed information about a specific device"""
        device_info = DeviceInfo(device_id=device_id, status=status)

        if status != DeviceStatus.CONNECTED:
            return device_info

        try:
            # Get Android version
            android_version = self._get_device_property(device_id, "ro.build.version.release")
            if android_version:
                device_info.android_version = android_version

            # Get API level
            api_level_str = self._get_device_property(device_id, "ro.build.version.sdk")
            if api_level_str and api_level_str.isdigit():
                device_info.api_level = int(api_level_str)

            # Get manufacturer
            manufacturer = self._get_device_property(device_id, "ro.product.manufacturer")
            if manufacturer:
                device_info.manufacturer = manufacturer

            # Get model
            model = self._get_device_property(device_id, "ro.product.model")
            if model:
                device_info.model = model

            # Get architecture
            architecture = self._get_device_property(device_id, "ro.product.cpu.abi")
            if architecture:
                device_info.architecture = architecture

            # Check root status
            device_info.root_status = self._check_root_status(device_id)

        except Exception as e:
            self.logger.warning(f"Error getting device details for {device_id}: {e}")
            device_info.error_message = f"Error getting device details: {str(e)}"

        return device_info

    def _get_device_property(self, device_id: str, property_name: str) -> Optional[str]:
        """Get a specific property from the device"""
        try:
            # MIGRATED: Route device property query through UnifiedTimeoutManager
            with self._timeout_manager.timeout_context(
                operation_name="device_property_query", timeout_type=TimeoutType.NETWORK, timeout_seconds=10
            ):
                result = self._adb_exec(["shell", "getprop", property_name], device_id, timeout=10)

            if result.returncode == 0:
                return result.stdout.strip()

        except (TimeoutError, Exception) as e:
            self.logger.debug(f"Error getting property {property_name} from {device_id}: {e}")

        return None

    def _check_root_status(self, device_id: str) -> bool:
        """Check if device is rooted"""
        try:
            # MIGRATED: Route root status check through UnifiedTimeoutManager
            with self._timeout_manager.timeout_context(
                operation_name="device_root_check", timeout_type=TimeoutType.NETWORK, timeout_seconds=10
            ):
                result = self._adb_exec(["shell", "su", "-c", "id"], device_id, timeout=10)

            return result.returncode == 0 and "uid=0" in result.stdout

        except (TimeoutError, Exception):
            return False

    def get_connected_devices(self) -> List[DeviceInfo]:
        """Get list of all connected devices"""
        return list(self.connected_devices.values())

    def get_device_info(self, device_id: str) -> Optional[DeviceInfo]:
        """Get information about a specific device"""
        return self.connected_devices.get(device_id)

    def is_device_ready(self, device_id: str) -> bool:
        """Check if device is ready for analysis"""
        device_info = self.connected_devices.get(device_id)
        if not device_info:
            return False

        return (
            device_info.status == DeviceStatus.CONNECTED
            and device_info.android_version is not None
            and device_info.api_level is not None
        )

    def enable_debugging(self, device_id: str) -> bool:
        """Enable USB debugging on device"""
        try:
            # MIGRATED: Route debug mode enablement through UnifiedTimeoutManager
            with self._timeout_manager.timeout_context(
                operation_name="device_debug_enable", timeout_type=TimeoutType.NETWORK, timeout_seconds=10
            ):
                result = self._adb_exec(
                    ["shell", "settings", "put", "global", "adb_enabled", "1"], device_id, timeout=10
                )

            return result.returncode == 0

        except (TimeoutError, Exception) as e:
            self.logger.error(f"Error enabling debugging on {device_id}: {e}")
            return False

    def install_certificates(self, device_id: str, cert_path: str) -> bool:
        """Install certificates for network interception"""
        try:
            # MIGRATED: Route certificate installation through UnifiedTimeoutManager
            with self._timeout_manager.timeout_context(
                operation_name="device_cert_push", timeout_type=TimeoutType.NETWORK, timeout_seconds=30
            ):
                result = self._adb_exec(["push", cert_path, "/sdcard/cert.pem"], device_id, timeout=30)

            if result.returncode != 0:
                return False

            # Install certificate (requires root)
            with self._timeout_manager.timeout_context(
                operation_name="device_cert_install", timeout_type=TimeoutType.NETWORK, timeout_seconds=30
            ):
                result = self._adb_exec(
                    ["shell", "su", "-c", "cp /sdcard/cert.pem /system/etc/security/cacerts/"], device_id, timeout=30
                )

            return result.returncode == 0

        except (TimeoutError, Exception) as e:
            self.logger.error(f"Error installing certificates on {device_id}: {e}")
            return False

    def cleanup_device(self, device_id: str) -> bool:
        """Clean up device after analysis"""
        try:
            # MIGRATED: Route device cleanup through UnifiedTimeoutManager
            with self._timeout_manager.timeout_context(
                operation_name="device_cleanup_files", timeout_type=TimeoutType.NETWORK, timeout_seconds=10
            ):
                _ = self._adb_exec(["shell", "rm", "-rf", "/sdcard/aods_temp/"], device_id, timeout=10)

            # Clear logcat
            with self._timeout_manager.timeout_context(
                operation_name="device_cleanup_logs", timeout_type=TimeoutType.NETWORK, timeout_seconds=10
            ):
                _ = self._adb_exec(["logcat", "-c"], device_id, timeout=10)

            return True

        except Exception as e:
            self.logger.error(f"Error cleaning up device {device_id}: {e}")
            return False

    def get_device_logs(self, device_id: str, duration: int = 30) -> List[str]:
        """Get device logs for analysis"""
        try:
            # MIGRATED: Route device log collection through UnifiedTimeoutManager
            with self._timeout_manager.timeout_context(
                operation_name="device_log_collection", timeout_type=TimeoutType.NETWORK, timeout_seconds=duration
            ):
                result = self._adb_exec(["logcat", "-d", "-v", "time"], device_id, timeout=duration)

            if result.returncode == 0:
                return result.stdout.split("\n")

        except (TimeoutError, Exception) as e:
            self.logger.error(f"Error getting logs from {device_id}: {e}")

        return []

    def validate_device_requirements(self, device_id: str) -> Tuple[bool, List[str]]:
        """Validate device meets requirements for dynamic analysis"""
        issues = []
        device_info = self.connected_devices.get(device_id)

        if not device_info:
            issues.append("Device not found")
            return False, issues

        if device_info.status != DeviceStatus.CONNECTED:
            issues.append(f"Device status: {device_info.status.value}")

        if device_info.api_level and device_info.api_level < 21:
            issues.append(f"API level {device_info.api_level} too low (minimum 21)")

        if not device_info.root_status:
            issues.append("Device not rooted (some features may not work)")

        return len(issues) == 0, issues
