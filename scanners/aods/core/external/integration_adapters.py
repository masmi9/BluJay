"""
Integration Adapters for Unified Tool Executor

This module provides adapter classes that integrate the unified tool executor
with existing AODS systems, providing backward compatibility while enabling
the benefits of standardized execution.
"""

import os
import tempfile
import shutil
from typing import Dict, List, Optional, Any, Union
from pathlib import Path

from .unified_tool_executor import ToolType, ToolConfiguration, ExecutionStatus, get_global_executor

try:
    from core.logging_config import get_logger
except ImportError:
    import logging as stdlib_logging

    get_logger = stdlib_logging.getLogger

logger = get_logger(__name__)


class ADBExecutorAdapter:
    """
    Adapter for ADB operations using unified tool executor.

    Provides backward compatibility with existing ADB usage patterns
    while leveraging the unified execution framework.
    """

    def __init__(self, device_id: Optional[str] = None, timeout: float = 30.0):
        self.device_id = device_id
        self.timeout = timeout
        self.executor = get_global_executor()
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")

    def execute_command(self, command_args: List[str], **kwargs) -> Dict[str, Any]:
        """
        Execute ADB command with unified executor.

        Args:
            command_args: ADB command arguments (without 'adb' prefix)
            **kwargs: Additional configuration options

        Returns:
            Dictionary with execution results in legacy format
        """
        # Add device targeting if specified
        if self.device_id:
            command_args = ["-s", self.device_id] + command_args

        # Create configuration
        config = ToolConfiguration(
            tool_type=ToolType.ADB,
            timeout_seconds=kwargs.get("timeout", self.timeout),
            safety_checks=kwargs.get("safety_checks", True),
            max_retries=kwargs.get("max_retries", 3),
        )

        # Execute command
        result = self.executor.execute_tool(ToolType.ADB, command_args, config)

        # Convert to legacy format
        return {
            "returncode": result.return_code,
            "output": result.stdout,
            "error": result.stderr,
            "success": result.status == ExecutionStatus.SUCCESS,
            "execution_time": result.execution_time,
            "timeout": result.status == ExecutionStatus.TIMEOUT,
        }

    def check_device_connection(self) -> bool:
        """Check if device is connected and responsive."""
        result = self.execute_command(["devices"])
        if result["success"] and self.device_id:
            return self.device_id in result["output"]
        return result["success"]

    def install_apk(self, apk_path: str, replace: bool = True) -> bool:
        """Install APK on device."""
        args = ["install"]
        if replace:
            args.append("-r")
        args.append(apk_path)

        result = self.execute_command(args, timeout=120.0)  # Longer timeout for installation
        return result["success"]

    def uninstall_package(self, package_name: str) -> bool:
        """Uninstall package from device."""
        result = self.execute_command(["uninstall", package_name])
        return result["success"]

    def start_activity(self, package_name: str, activity_name: str) -> bool:
        """Start activity on device."""
        component = f"{package_name}/{activity_name}"
        result = self.execute_command(["shell", "am", "start", "-n", component])
        return result["success"]

    def get_device_logs(self, duration: int = 30) -> List[str]:
        """Get device logs."""
        result = self.execute_command(["logcat", "-d", "-v", "time"], timeout=duration)
        if result["success"]:
            return result["output"].split("\n")
        return []

    def cleanup_device(self) -> bool:
        """Clean up device after analysis."""
        try:
            # Remove temporary files
            self.execute_command(["shell", "rm", "-rf", "/sdcard/aods_temp/"])

            # Clear logcat
            self.execute_command(["logcat", "-c"])

            return True
        except Exception as e:
            self.logger.error(f"Device cleanup error: {e}")
            return False


class JADXExecutorAdapter:
    """
    Adapter for JADX operations using unified tool executor.

    Provides backward compatibility with existing JADX usage patterns
    while leveraging the unified execution framework.
    """

    def __init__(self, timeout: float = 300.0, memory_limit_mb: int = 2048):
        self.timeout = timeout
        self.memory_limit_mb = memory_limit_mb
        self.executor = get_global_executor()
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")

    def decompile_apk(self, apk_path: str, output_dir: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """
        Decompile APK using unified executor.

        Args:
            apk_path: Path to APK file
            output_dir: Output directory (created if None)
            **kwargs: Additional configuration options

        Returns:
            Dictionary with decompilation results in legacy format
        """
        # Create output directory if not specified
        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix="aods_jadx_")
        else:
            os.makedirs(output_dir, exist_ok=True)

        # Build command arguments using centralized decompilation policy
        command_args = ["-d", output_dir, "--show-bad-code"]
        try:
            from core.decompilation_policy_resolver import get_decompilation_policy

            profile = os.getenv("AODS_APP_PROFILE", "production")
            # Support deobf as a soft preference via env or kwargs (policy stays source of truth)
            policy = get_decompilation_policy(apk_path=apk_path, profile=profile, plugin_requirements=None)
            command_args.extend(policy.flags)
        except Exception:
            # Safe fallback without raw banned flags
            pass
        command_args.append(apk_path)

        # Create configuration
        config = ToolConfiguration(
            tool_type=ToolType.JADX,
            timeout_seconds=kwargs.get("timeout", self.timeout),
            max_memory_mb=kwargs.get("memory_limit_mb", self.memory_limit_mb),
            resource_monitoring=True,
            max_retries=kwargs.get("max_retries", 2),
        )

        # Execute decompilation
        result = self.executor.execute_tool(ToolType.JADX, command_args, config)

        # Convert to legacy format
        return {
            "success": result.status == ExecutionStatus.SUCCESS,
            "output_dir": output_dir if result.status == ExecutionStatus.SUCCESS else None,
            "execution_time": result.execution_time,
            "peak_memory_mb": result.peak_memory_mb,
            "error": result.stderr if result.status != ExecutionStatus.SUCCESS else None,
            "timeout": result.status == ExecutionStatus.TIMEOUT,
            "return_code": result.return_code,
        }

    def analyze_decompiled_code(self, decompiled_dir: str) -> Dict[str, Any]:
        """Analyze decompiled code for patterns."""
        analysis_results = {
            "java_files": [],
            "manifest_info": {},
            "crypto_patterns": [],
            "network_patterns": [],
            "file_count": 0,
        }

        try:
            decompiled_path = Path(decompiled_dir)

            # Find Java files
            java_files = list(decompiled_path.rglob("*.java"))
            analysis_results["java_files"] = [str(f) for f in java_files]
            analysis_results["file_count"] = len(java_files)

            # Look for AndroidManifest.xml
            manifest_path = decompiled_path / "AndroidManifest.xml"
            if manifest_path.exists():
                analysis_results["manifest_info"]["path"] = str(manifest_path)
                analysis_results["manifest_info"]["exists"] = True

            self.logger.info(f"Analyzed {len(java_files)} Java files in {decompiled_dir}")

        except Exception as e:
            self.logger.error(f"Code analysis error: {e}")
            analysis_results["error"] = str(e)

        return analysis_results

    def cleanup_decompilation(self, output_dir: str) -> bool:
        """Clean up decompilation output directory."""
        try:
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
                self.logger.debug(f"Cleaned up decompilation directory: {output_dir}")
                return True
        except Exception as e:
            self.logger.error(f"Cleanup error: {e}")
        return False


class FridaExecutorAdapter:
    """
    Adapter for Frida operations using unified tool executor.

    Provides backward compatibility with existing Frida usage patterns
    while leveraging the unified execution framework.
    """

    def __init__(self, timeout: float = 60.0):
        self.timeout = timeout
        self.executor = get_global_executor()
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")

    def execute_script(self, script_path: str, target_process: str, **kwargs) -> Dict[str, Any]:
        """
        Execute Frida script using unified executor.

        Args:
            script_path: Path to Frida script
            target_process: Target process name or PID
            **kwargs: Additional configuration options

        Returns:
            Dictionary with execution results in legacy format
        """
        command_args = ["-l", script_path, target_process]

        # Add additional arguments
        if kwargs.get("device_id"):
            command_args = ["-D", kwargs["device_id"]] + command_args
        if kwargs.get("spawn", False):
            command_args.insert(-1, "-f")

        # Create configuration
        config = ToolConfiguration(
            tool_type=ToolType.FRIDA,
            timeout_seconds=kwargs.get("timeout", self.timeout),
            resource_monitoring=True,
            max_retries=kwargs.get("max_retries", 2),
        )

        # Execute script
        result = self.executor.execute_tool(ToolType.FRIDA, command_args, config)

        # Convert to legacy format
        return {
            "success": result.status == ExecutionStatus.SUCCESS,
            "output": result.stdout,
            "error": result.stderr,
            "execution_time": result.execution_time,
            "timeout": result.status == ExecutionStatus.TIMEOUT,
            "return_code": result.return_code,
        }

    def check_frida_server(self, device_id: Optional[str] = None) -> bool:
        """Check if Frida server is running on device."""
        command_args = ["ps"]
        if device_id:
            command_args = ["-D", device_id] + command_args

        config = ToolConfiguration(tool_type=ToolType.FRIDA, timeout_seconds=10.0)

        result = self.executor.execute_tool(ToolType.FRIDA, command_args, config)
        return result.status == ExecutionStatus.SUCCESS

    def list_processes(self, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List processes on target device."""
        command_args = ["ps"]
        if device_id:
            command_args = ["-D", device_id] + command_args

        config = ToolConfiguration(tool_type=ToolType.FRIDA, timeout_seconds=15.0)

        result = self.executor.execute_tool(ToolType.FRIDA, command_args, config)

        processes = []
        if result.status == ExecutionStatus.SUCCESS:
            # Parse process list (simplified)
            for line in result.stdout.split("\n"):
                if line.strip() and not line.startswith("PID"):
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        processes.append({"pid": parts[0], "name": parts[1] if len(parts) > 1 else "unknown"})

        return processes


class UnifiedToolCleanupManager:
    """
    Centralized cleanup manager for all external tool operations.

    Ensures proper cleanup of processes, temporary files, and resources
    across all tool adapters.
    """

    def __init__(self):
        self.executor = get_global_executor()
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        self.temp_directories: List[str] = []
        self.active_adapters: List[Union[ADBExecutorAdapter, JADXExecutorAdapter, FridaExecutorAdapter]] = []

    def register_temp_directory(self, directory: str) -> None:
        """Register temporary directory for cleanup."""
        if directory and directory not in self.temp_directories:
            self.temp_directories.append(directory)

    def register_adapter(self, adapter: Union[ADBExecutorAdapter, JADXExecutorAdapter, FridaExecutorAdapter]) -> None:
        """Register adapter for cleanup."""
        if adapter not in self.active_adapters:
            self.active_adapters.append(adapter)

    def cleanup_all(self) -> None:
        """Perform cleanup of all resources."""
        self.logger.info("Starting full external tool cleanup")

        # Cleanup active processes
        try:
            self.executor.cleanup_all_processes()
            self.logger.debug("Cleaned up active processes")
        except Exception as e:
            self.logger.error(f"Process cleanup error: {e}")

        # Cleanup temporary directories
        for temp_dir in self.temp_directories:
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                    self.logger.debug(f"Cleaned up temp directory: {temp_dir}")
            except Exception as e:
                self.logger.error(f"Temp directory cleanup error: {e}")

        self.temp_directories.clear()

        # Cleanup ADB resources
        try:
            from .unified_tool_executor import execute_adb_command

            execute_adb_command(["kill-server"])
            execute_adb_command(["forward", "--remove-all"])
            self.logger.debug("Cleaned up ADB resources")
        except Exception as e:
            self.logger.debug(f"ADB cleanup error: {e}")

        # Clear adapter references
        self.active_adapters.clear()

        self.logger.info("External tool cleanup completed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup_all()


# Global cleanup manager instance
_global_cleanup_manager: Optional[UnifiedToolCleanupManager] = None


def get_global_cleanup_manager() -> UnifiedToolCleanupManager:
    """Get or create global cleanup manager instance."""
    global _global_cleanup_manager
    if _global_cleanup_manager is None:
        _global_cleanup_manager = UnifiedToolCleanupManager()
    return _global_cleanup_manager
