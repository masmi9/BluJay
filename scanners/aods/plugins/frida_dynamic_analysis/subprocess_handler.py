"""
Subprocess execution handler for Frida Dynamic Analysis Plugin.

This module provides reliable subprocess execution with proper error handling,
caching, and timeout management for external tool interactions.
"""

import logging
import subprocess
import time
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

# MIGRATED: Import unified caching infrastructure
from core.shared_infrastructure.performance.caching_consolidation import get_unified_cache_manager, CacheType

from .data_structures import SubprocessConfig, FridaTestResult, FridaTestCache

logger = logging.getLogger(__name__)


@dataclass
class SubprocessResult:
    """Result of subprocess execution with detailed information."""

    success: bool
    returncode: int
    stdout: str
    stderr: str
    execution_time: float
    command: List[str]
    error_message: Optional[str] = None
    timed_out: bool = False


class SubprocessHandler:
    """Handle subprocess execution with caching and error management."""

    def __init__(self, cache_ttl: int = 300):
        self.cache = FridaTestCache(ttl=cache_ttl)
        self._lock = threading.RLock()

    def execute_with_cache(self, config: SubprocessConfig, cache_key: Optional[str] = None) -> SubprocessResult:
        """Execute subprocess with caching support."""
        # Check cache if key provided
        if cache_key:
            cached_result = self.cache.get(cache_key)
            if cached_result and cached_result.subprocess_result:
                logger.debug(f"Using cached subprocess result for {cache_key}")
                return SubprocessResult(**cached_result.subprocess_result)

        # Execute subprocess
        result = self.execute(config)

        # Cache result if key provided and successful
        if cache_key and result.success:
            test_result = FridaTestResult(
                test_type=None,  # Not applicable for subprocess
                status=None,  # Not applicable for subprocess
                success=result.success,
                evidence={},
                subprocess_result=result.__dict__,
            )
            self.cache.set(cache_key, test_result)

        return result

    def execute(self, config: SubprocessConfig) -> SubprocessResult:
        """Execute subprocess with error handling, preferring unified executor.

        Routes ADB/Frida/JADX through the UnifiedToolExecutor when possible
        to satisfy CI external tools guard; falls back to subprocess when needed.
        """
        start_time = time.time()

        # Try unified executor path when applicable
        try:
            tool = (config.command[0] if config.command else "").lower()
            from core.external.unified_tool_executor import (
                execute_adb_command,
                execute_frida_script,
                execute_jadx_decompilation,
            )

            if tool == "adb":
                # Pass through arguments after 'adb'
                result = execute_adb_command(config.command[1:], timeout=config.timeout)
                execution_time = time.time() - start_time
                return SubprocessResult(
                    success=(getattr(result, "exit_code", 0) == 0),
                    returncode=getattr(result, "exit_code", 0),
                    stdout=str(getattr(result, "stdout", "") or ""),
                    stderr=str(getattr(result, "stderr", "") or ""),
                    execution_time=execution_time,
                    command=config.command,
                )
            if tool.startswith("frida"):
                # Generic support: if it's a script, route via execute_frida_script
                # Otherwise, attempt unified executor run via frida tool with args
                # Note: execute_frida_script expects a path; we fallback to subprocess if shape mismatches
                if (
                    len(config.command) >= 2
                    and config.command[0] in ("frida", "frida.exe")
                    and config.command[1].endswith(".js")
                ):
                    result = execute_frida_script(config.command[1], config.command[2:], timeout=config.timeout)
                    execution_time = time.time() - start_time
                    return SubprocessResult(
                        success=(getattr(result, "exit_code", 0) == 0),
                        returncode=getattr(result, "exit_code", 0),
                        stdout=str(getattr(result, "stdout", "") or ""),
                        stderr=str(getattr(result, "stderr", "") or ""),
                        execution_time=execution_time,
                        command=config.command,
                    )
            if tool.startswith("jadx"):
                # If it's a decompilation command and includes an APK, attempt unified API
                apk_args = [arg for arg in config.command[1:] if arg.lower().endswith(".apk")]
                if apk_args:
                    result = execute_jadx_decompilation(apk_args[0], output_dir=None, timeout=config.timeout)
                    execution_time = time.time() - start_time
                    return SubprocessResult(
                        success=(getattr(result, "exit_code", 0) == 0),
                        returncode=getattr(result, "exit_code", 0),
                        stdout=str(getattr(result, "stdout", "") or ""),
                        stderr=str(getattr(result, "stderr", "") or ""),
                        execution_time=execution_time,
                        command=config.command,
                    )
        except Exception:
            # Fall back to raw subprocess below
            pass

        try:
            logger.debug(f"Executing command: {' '.join(config.command)}")
            process = subprocess.run(
                config.command,
                capture_output=config.capture_output,
                text=config.text,
                timeout=config.timeout,
                shell=config.shell,
                cwd=config.cwd,
                env=config.env,
            )
            execution_time = time.time() - start_time
            return SubprocessResult(
                success=process.returncode == 0,
                returncode=process.returncode,
                stdout=process.stdout or "",
                stderr=process.stderr or "",
                execution_time=execution_time,
                command=config.command,
            )

        except subprocess.TimeoutExpired as e:
            execution_time = time.time() - start_time
            logger.warning(f"Command timed out after {config.timeout}s: {' '.join(config.command)}")

            return SubprocessResult(
                success=False,
                returncode=-1,
                stdout=e.stdout or "",
                stderr=e.stderr or "",
                execution_time=execution_time,
                command=config.command,
                error_message=f"Command timed out after {config.timeout} seconds",
                timed_out=True,
            )

        except FileNotFoundError as e:
            execution_time = time.time() - start_time
            logger.error(f"Command not found: {config.command[0]}")

            return SubprocessResult(
                success=False,
                returncode=-1,
                stdout="",
                stderr=str(e),
                execution_time=execution_time,
                command=config.command,
                error_message=f"Command not found: {config.command[0]}",
            )

        except PermissionError as e:
            execution_time = time.time() - start_time
            logger.error(f"Permission denied executing: {' '.join(config.command)}")

            return SubprocessResult(
                success=False,
                returncode=-1,
                stdout="",
                stderr=str(e),
                execution_time=execution_time,
                command=config.command,
                error_message=f"Permission denied: {str(e)}",
            )

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Unexpected error executing command: {str(e)}")

            return SubprocessResult(
                success=False,
                returncode=-1,
                stdout="",
                stderr=str(e),
                execution_time=execution_time,
                command=config.command,
                error_message=f"Unexpected error: {str(e)}",
            )


class FridaEnvironmentValidator:
    """Validate Frida environment and dependencies."""

    def __init__(self, subprocess_handler: SubprocessHandler):
        self.subprocess_handler = subprocess_handler

        # MIGRATED: Use unified caching infrastructure for validation cache
        self.cache_manager = get_unified_cache_manager()
        self._cache_ttl = 60  # 1 minute cache for environment checks

    def validate_frida_environment(self) -> Dict[str, Any]:
        """Validate complete Frida environment with caching."""
        cache_key = "frida_environment_validation"

        # Check cache via unified cache manager
        cached_wrapper = self.cache_manager.retrieve(cache_key, CacheType.GENERAL)
        if cached_wrapper and isinstance(cached_wrapper, dict):
            cached_time = cached_wrapper.get("timestamp", 0)
            cached_result = cached_wrapper.get("data")
            if cached_result is not None and time.time() - cached_time < self._cache_ttl:
                return cached_result

        # Perform validation
        validation_result = {
            "frida_available": False,
            "frida_version": None,
            "devices_available": False,
            "device_list": [],
            "adb_available": False,
            "frida_server_running": False,
            "errors": [],
            "is_ready": False,
        }

        # Check Frida installation
        frida_check = self._check_frida_installation()
        validation_result.update(frida_check)

        # Check ADB availability
        adb_check = self._check_adb_availability()
        validation_result.update(adb_check)

        # Check connected devices (only if ADB is available)
        if validation_result["adb_available"]:
            device_check = self._check_connected_devices()
            validation_result.update(device_check)

        # Check Frida server (only if devices are available)
        if validation_result["devices_available"]:
            server_check = self._check_frida_server()
            validation_result.update(server_check)

        # Determine overall readiness
        validation_result["is_ready"] = (
            validation_result["frida_available"]
            and validation_result["adb_available"]
            and validation_result["devices_available"]
            and len(validation_result["errors"]) == 0
        )

        # Cache result via unified cache manager
        self.cache_manager.store(
            cache_key,
            {"timestamp": time.time(), "data": validation_result},
            CacheType.GENERAL,
            ttl_hours=1 / 60,
            tags=["frida_env_validation"],
        )

        return validation_result

    def _check_frida_installation(self) -> Dict[str, Any]:
        """Check if Frida is properly installed."""
        # Try virtual environment path first, then system path
        import sys
        import os

        venv_frida = os.path.join(os.path.dirname(sys.executable), "frida")
        frida_cmd = venv_frida if os.path.exists(venv_frida) else "frida"

        config = SubprocessConfig(command=[frida_cmd, "--version"], timeout=10)

        result = self.subprocess_handler.execute_with_cache(config, "frida_version_check")

        if result.success:
            return {"frida_available": True, "frida_version": result.stdout.strip()}
        else:
            return {
                "frida_available": False,
                "frida_version": None,
                "errors": [result.error_message or "Frida not found or not working"],
            }

    def _check_adb_availability(self) -> Dict[str, Any]:
        """Check if ADB is available."""
        try:
            from core.external.unified_tool_executor import get_global_executor, ToolType

            execu = get_global_executor()
            info = execu.get_tool_info(ToolType.ADB)
            return {"adb_available": bool(info.get("available"))}
        except Exception as e:
            return {"adb_available": False, "errors": [str(e)]}

    def _check_connected_devices(self) -> Dict[str, Any]:
        """Check for connected Android devices using ADB (workaround for frida-ls-devices hanging)."""
        # WORKAROUND: Use adb devices instead of frida-ls-devices which hangs
        try:
            from core.external.unified_tool_executor import list_adb_devices

            device_lines = list_adb_devices(timeout=10.0)
            if device_lines:
                devices = []
                for line in device_lines:
                    if "device" in line and "offline" not in line:
                        parts = line.split("\t")
                        if len(parts) >= 2:
                            devices.append({"id": parts[0], "status": parts[1]})
                        else:
                            devices.append({"raw": line})
                return {"devices": devices, "device_count": len(devices)}
            return {"devices": [], "device_count": 0}
        except Exception:
            # Fallback to subprocess handler if unified executor path fails
            config = SubprocessConfig(command=["adb", "devices"], timeout=10)
            result = self.subprocess_handler.execute(config)  # Don't cache device list

            if result.success:
                # Parse ADB device list
                devices = []
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if not line or line.startswith("List of devices"):
                        continue
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        devices.append({"id": parts[0], "status": parts[1]})
                return {"devices": devices, "device_count": len(devices)}
            else:
                return {"devices": [], "device_count": 0}

    def _check_frida_server(self) -> Dict[str, Any]:
        """Check if Frida server is running on device."""
        # Try virtual environment path first, then system path
        import sys
        import os

        venv_frida_ps = os.path.join(os.path.dirname(sys.executable), "frida-ps")
        frida_ps_cmd = venv_frida_ps if os.path.exists(venv_frida_ps) else "frida-ps"

        config = SubprocessConfig(command=[frida_ps_cmd, "-U"], timeout=15)

        result = self.subprocess_handler.execute(config)  # Don't cache process list

        if result.success:
            return {"frida_server_running": True}
        else:
            return {
                "frida_server_running": False,
                "errors": [result.error_message or "Frida server not running or not accessible"],
            }

    def get_installation_guidance(self) -> Dict[str, List[str]]:
        """Get installation guidance for missing components."""
        return {
            "frida_installation": [
                "Install Frida tools: pip install frida-tools",
                "Download frida-server from: https://github.com/frida/frida/releases",
                "Push to device: adb push frida-server /data/local/tmp/",
                "Make executable: adb shell chmod 755 /data/local/tmp/frida-server",
                "Run as root: adb shell su -c '/data/local/tmp/frida-server &'",
            ],
            "adb_installation": [
                "Install Android SDK platform tools",
                "Add platform-tools to PATH",
                "Enable USB debugging on device",
                "Connect device via USB",
            ],
            "device_connection": [
                "Connect Android device via USB",
                "Enable USB debugging in Developer Options",
                "Accept USB debugging prompt on device",
                "Verify connection: adb devices",
            ],
            "frida_server": [
                "Ensure device is rooted",
                "Download correct frida-server architecture",
                "Start frida-server as root on device",
                "Verify connection: frida-ps -U",
            ],
        }


def create_subprocess_handler(cache_ttl: int = 300) -> SubprocessHandler:
    """Factory function to create subprocess handler."""
    return SubprocessHandler(cache_ttl=cache_ttl)


def create_environment_validator(subprocess_handler: SubprocessHandler) -> FridaEnvironmentValidator:
    """Factory function to create environment validator."""
    return FridaEnvironmentValidator(subprocess_handler)
