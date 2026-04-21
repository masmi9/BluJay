#!/usr/bin/env python3
"""
Frida Connection Manager

Core Frida connection and device management functionality.
Provides reliable Frida server management, device detection, and session handling.

Components:
- FridaConnection: Main connection management class
- Device detection and validation
- Frida server lifecycle management
- Session attachment and management

"""

import logging
import subprocess
import time
import requests
import tempfile
import os
import shutil
from typing import Optional, Tuple, Any

# Import AODS configuration management
try:
    from ..shared_infrastructure.configuration.environment_manager import EnvironmentManager

    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False


class FridaConnection:
    """Core Frida connection and device management."""

    def __init__(self, package_name: str = None, device_id: str = None):
        """Initialize Frida connection manager."""
        self.package_name = package_name
        self.device_id = device_id
        self.device = None
        self.session = None
        self.frida = None
        self.is_available = False
        self.connection_timeout = 30

        # Load configuration from AODS environment manager
        self._load_configuration()

        # Initialize Frida availability check
        self._check_frida_availability()

    def _load_configuration(self) -> None:
        """Load Frida configuration from AODS environment manager."""
        try:
            if CONFIG_AVAILABLE:
                env_manager = EnvironmentManager()
                env_config = env_manager.get_environment_configuration()
                config = env_config.get_effective_config()
                frida_config = config.get("dynamic_analysis", {}).get("frida", {})

                # Load configuration with fallbacks
                self.auto_install_enabled = frida_config.get("auto_install_enabled", True)
                self.server_install_timeout = frida_config.get("server_install_timeout", 120)
                self.fallback_version = frida_config.get("fallback_version", "16.1.4")
                self.download_timeout = frida_config.get("download_timeout", 60)
                self.github_releases_url = frida_config.get(
                    "github_releases_url", "https://api.github.com/repos/frida/frida/releases/latest"
                )

                # Architecture mapping
                supported_archs = frida_config.get(
                    "supported_architectures", ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]
                )
                self.supported_architectures = {
                    arch: arch.replace("-v8a", "").replace("-v7a", "").replace("armeabi", "arm")
                    for arch in supported_archs
                }

                logging.info("Loaded Frida configuration from AODS environment manager")
            else:
                # Fallback configuration
                self._set_fallback_configuration()

        except Exception as e:
            logging.warning(f"Failed to load configuration, using fallbacks: {e}")
            self._set_fallback_configuration()

    def _set_fallback_configuration(self) -> None:
        """Set fallback configuration when environment manager is unavailable."""
        self.auto_install_enabled = True
        self.server_install_timeout = 120
        self.fallback_version = "16.1.4"
        self.download_timeout = 60
        self.github_releases_url = "https://api.github.com/repos/frida/frida/releases/latest"
        self.supported_architectures = {"arm64-v8a": "arm64", "armeabi-v7a": "arm", "x86_64": "x86_64", "x86": "x86"}

    def _check_frida_availability(self) -> None:
        """Check if Frida is available and properly configured.
        Accepts USB, remote/tcp and emulator devices (Corellium often appears as remote).
        """
        try:
            import frida

            self.frida = frida
            devices = frida.enumerate_devices()
            # Accept common device types
            preferred_types = {"usb", "tether", "remote", "tcp", "local", "emulator"}
            candidates = [d for d in devices if getattr(d, "type", None) in preferred_types]
            if not candidates and devices:
                # Fallback: any device present
                candidates = list(devices)
            if candidates:
                self.device = candidates[0]
                self.is_available = True
                logging.info(f"Frida available with device: {self.device.name}")
            else:
                logging.warning("No compatible Frida devices found")
                self.is_available = False
        except ImportError:
            logging.error("Frida not installed - dynamic analysis unavailable")
            self.is_available = False
        except Exception as e:
            logging.error(f"Frida initialization failed: {e}")
            self.is_available = False

    def check_frida_availability(self) -> Tuple[bool, str]:
        """
        Check if Frida is available and properly configured.

        Returns:
            Tuple of (is_available, status_message)
        """
        try:
            frida_version = ""
            try:
                # Query FRIDA version via unified executor
                from core.external.unified_tool_executor import get_global_executor, ToolType

                execu = get_global_executor()
                info = execu.get_tool_info(ToolType.FRIDA)
                frida_version = (info.get("version") or "").strip()
            except Exception:
                logging.debug("Unified executor FRIDA version check failed; continuing with python fallback")

            # Prefer CLI device listing if available using unified executor (custom tool)
            try:
                from core.external.unified_tool_executor import (
                    get_global_executor,
                    ToolType,
                    ToolConfiguration,
                    ExecutionStatus,
                )

                execu = get_global_executor()
                frida_ls = shutil.which("frida-ls-devices")
                if frida_ls:
                    cfg = ToolConfiguration(tool_type=ToolType.CUSTOM, executable_path=frida_ls, timeout_seconds=5.0)
                    result = execu.execute_tool(ToolType.CUSTOM, [], cfg)
                    if result.status == ExecutionStatus.SUCCESS:
                        devices_output = (result.stdout or "").lower()
                        if any(tag in devices_output for tag in ("usb", "emulator", "remote", "tcp")):
                            return True, f"Frida {frida_version or 'unknown'} available with connected devices"
                else:
                    logging.debug("frida-ls-devices not found; falling back to python enumeration")
            except Exception:
                logging.debug("Unified executor frida-ls-devices check failed; falling back to python enumeration")

            # Python fallback with remote registration when 27042 is open
            try:
                # Best-effort: if local forward is up, register remote device to speed up detection
                try:
                    import socket

                    s = socket.socket()
                    s.settimeout(0.8)
                    s.connect(("127.0.0.1", int(os.getenv("AODS_FRIDA_FORWARD_PORT", "27042"))))
                    s.close()
                    try:
                        import frida as _f

                        _f.get_device_manager().add_remote_device(
                            f"127.0.0.1:{os.getenv('AODS_FRIDA_FORWARD_PORT', '27042')}"
                        )
                    except Exception:
                        pass
                except Exception:
                    pass

                self._check_frida_availability()
                if self.is_available:
                    return (
                        True,
                        f"Frida {frida_version or 'unknown'} available (python) with device {getattr(self.device, 'name', 'unknown')}",  # noqa: E501
                    )
                return False, "No compatible Frida devices found (python)"
            except Exception as e:
                return False, f"Frida check failed (python): {e}"

        except subprocess.TimeoutExpired:
            return False, "Frida command timed out"
        except Exception:
            # Do not leak low-level FileNotFoundError to UI; provide concise hint
            return False, "Frida check failed (unexpected error)"

    def _detect_device_architecture(self) -> Optional[str]:
        """
        Detect the architecture of the connected Android device.

        Returns:
            Device architecture string or None if detection fails
        """
        try:
            # Use unified executor for adb shell getprop
            from core.external.unified_tool_executor import execute_adb_command, ExecutionStatus

            cmd = ["shell", "getprop", "ro.product.cpu.abi"]
            result = execute_adb_command(cmd, device_id=self.device_id, timeout=10.0)
            if result.status == ExecutionStatus.SUCCESS and result.return_code == 0:
                detected_arch = (result.stdout or "").strip()
                logging.info(f"Detected device architecture: {detected_arch}")
                return detected_arch
            else:
                logging.warning(f"Failed to detect architecture: {result.stderr}")
                return None
        except Exception as e:
            logging.error(f"Architecture detection failed: {e}")
            return None

    def _get_latest_frida_version(self) -> Optional[str]:
        """
        Get the latest Frida version from GitHub releases.

        Returns:
            Latest version string or None if unavailable
        """
        try:
            response = requests.get(self.github_releases_url, timeout=self.download_timeout)
            if response.status_code == 200:
                latest_version = response.json()["tag_name"]
                logging.info(f"Latest Frida version: {latest_version}")
                return latest_version
            else:
                logging.warning("Failed to fetch latest Frida version")
                return None

        except Exception as e:
            logging.warning(f"Version check failed, using fallback: {e}")
            return None

    def _download_frida_server(self, architecture: str, version: str) -> Optional[str]:
        """
        Download frida-server binary for the specified architecture and version.

        Args:
            architecture: Device architecture
            version: Frida version to download

        Returns:
            Path to downloaded binary or None if download fails
        """
        try:
            # Map Android architecture to Frida naming
            frida_arch = self.supported_architectures.get(architecture)
            if not frida_arch:
                logging.error(f"Unsupported architecture: {architecture}")
                return None

            # Construct download URL
            binary_name = f"frida-server-{version}-android-{frida_arch}"
            download_url = f"https://github.com/frida/frida/releases/download/{version}/{binary_name}.xz"

            logging.info(f"Downloading {binary_name} from GitHub releases...")

            # Download to temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".xz") as temp_file:
                response = requests.get(download_url, timeout=self.download_timeout)
                if response.status_code == 200:
                    temp_file.write(response.content)
                    temp_xz_path = temp_file.name
                else:
                    logging.error(f"Download failed: HTTP {response.status_code}")
                    return None

            # Extract xz file
            temp_binary_path = temp_xz_path.replace(".xz", "")
            extract_cmd = ["unxz", "-c", temp_xz_path]

            with open(temp_binary_path, "wb") as output_file:
                result = subprocess.run(extract_cmd, stdout=output_file, capture_output=False, timeout=30)

            if result.returncode == 0:
                # Clean up compressed file
                os.unlink(temp_xz_path)
                os.chmod(temp_binary_path, 0o755)
                logging.info("Successfully downloaded and extracted frida-server")
                return temp_binary_path
            else:
                logging.error("Failed to extract frida-server")
                return None

        except Exception as e:
            logging.error(f"Frida server download failed: {e}")
            return None

    def _install_frida_server(self, binary_path: str) -> bool:
        """
        Install frida-server binary to device.

        Args:
            binary_path: Path to frida-server binary

        Returns:
            True if installation successful, False otherwise
        """
        try:
            from core.external.unified_tool_executor import execute_adb_command, ExecutionStatus

            logging.info("Installing frida-server to device...")

            # Push binary to device
            result = execute_adb_command(
                ["push", binary_path, "/data/local/tmp/frida-server"], device_id=self.device_id, timeout=30.0
            )
            if result.status != ExecutionStatus.SUCCESS or result.return_code != 0:
                logging.error(f"Failed to push frida-server: {result.stderr}")
                return False

            # Make binary executable
            result = execute_adb_command(
                ["shell", "chmod", "755", "/data/local/tmp/frida-server"], device_id=self.device_id, timeout=10.0
            )
            if result.status != ExecutionStatus.SUCCESS or result.return_code != 0:
                logging.warning(f"Failed to set executable permissions: {result.stderr}")
                # Continue anyway, might still work

            logging.info("Frida server installation completed")

            # Clean up local binary
            try:
                os.unlink(binary_path)
            except Exception:
                pass

            return True

        except Exception as e:
            logging.error(f"Frida server installation failed: {e}")
            return False

    def _check_frida_server_status(self) -> bool:
        """
        Check if frida-server is currently running on the device.

        Returns:
            True if server is running, False otherwise
        """
        try:
            from core.external.unified_tool_executor import (
                get_global_executor,
                ToolType,
                ToolConfiguration,
                ExecutionStatus,
            )

            execu = get_global_executor()
            frida_ps = shutil.which("frida-ps")
            if not frida_ps:
                return False
            args = ["-U"] if not self.device_id else ["-D", self.device_id]
            cfg = ToolConfiguration(tool_type=ToolType.CUSTOM, executable_path=frida_ps, timeout_seconds=15.0)
            result = execu.execute_tool(ToolType.CUSTOM, args, cfg)
            return result.status == ExecutionStatus.SUCCESS and result.return_code == 0
        except Exception as e:
            logging.debug(f"Server status check failed: {e}")
            return False

    def start_frida_server(self) -> bool:
        """
        Start Frida server on the target device with enhanced auto-installation.

        Returns:
            bool: True if server started successfully, False otherwise
        """
        try:
            logging.info("Starting Frida server with enhanced capabilities...")

            # Check if Frida server is already running
            if self._check_frida_server_status():
                logging.info("Frida server is already running")
                return True

            # Try to start existing frida-server first
            if self._start_existing_server():
                return True

            # If auto-install is enabled and no server exists, install one
            if self.auto_install_enabled:
                logging.info("Attempting automatic frida-server installation...")

                # Detect device architecture
                architecture = self._detect_device_architecture()
                if not architecture:
                    logging.warning("Could not detect device architecture, skipping auto-install")
                    return False

                # Get latest Frida version (with fallback)
                version = self._get_latest_frida_version()
                if not version:
                    # Fallback to configured stable version
                    version = self.fallback_version
                    logging.info(f"Using configured fallback version: {version}")

                # Download and install frida-server
                binary_path = self._download_frida_server(architecture, version)
                if binary_path and self._install_frida_server(binary_path):
                    logging.info("Auto-installation completed, attempting to start server...")
                    return self._start_existing_server()
                else:
                    logging.warning("Auto-installation failed")

            logging.warning("Frida server startup failed - manual installation may be required")
            return False

        except Exception as e:
            logging.error(f"Enhanced Frida server startup failed: {e}")
            return False

    def _start_existing_server(self) -> bool:
        """
        Start frida-server that's already installed on the device.

        Returns:
            True if server started successfully, False otherwise
        """
        try:
            from core.external.unified_tool_executor import execute_adb_command

            # Try to start frida-server via unified executor
            _ = execute_adb_command(
                ["shell", "su", "-c", "/data/local/tmp/frida-server &"], device_id=self.device_id, timeout=10.0
            )

            # Wait for server to start
            time.sleep(3)

            # Verify server is running
            if self._check_frida_server_status():
                logging.info("Frida server started successfully")
                return True
            else:
                logging.warning("Frida server may not be running")
                return False

        except Exception as e:
            logging.error(f"Failed to start existing frida-server: {e}")
            return False

    def attach_to_app(self, package_name: str = None) -> bool:
        """
        Attach Frida to the target application.

        Args:
            package_name: Package name to attach to (uses instance package_name if not provided)

        Returns:
            bool: True if attachment successful, False otherwise
        """
        target_package = package_name or self.package_name
        if not target_package:
            logging.error("No package name provided for attachment")
            return False

        try:
            if not self.frida:
                import frida

                self.frida = frida

            # Get device
            if self.device_id:
                device = self.frida.get_device(self.device_id)
            else:
                device = self.frida.get_usb_device()

            # Try to attach to running process first
            try:
                self.session = device.attach(target_package)
                logging.info(f"Attached to running process: {target_package}")
                return True
            except self.frida.ProcessNotFoundError:
                # App not running, try to spawn it
                logging.info(f"App not running, attempting to spawn: {target_package}")
                pid = device.spawn([target_package])
                self.session = device.attach(pid)
                device.resume(pid)
                logging.info(f"Spawned and attached to: {target_package}")
                return True

        except ImportError:
            logging.error("Frida Python bindings not installed. Install with: pip install frida")
            return False
        except Exception as e:
            logging.error(f"Failed to attach to app: {e}")
            return False

    def get_device(self) -> Optional[Any]:
        """Get the current Frida device."""
        return self.device

    def get_session(self) -> Optional[Any]:
        """Get the current Frida session."""
        return self.session

    def is_connected(self) -> bool:
        """Check if Frida is connected and session is active."""
        return self.session is not None and self.is_available

    def disconnect(self) -> bool:
        """Disconnect Frida session and cleanup resources."""
        try:
            if self.session:
                self.session.detach()
                self.session = None
                logging.info("Frida session detached")

            return True

        except Exception as e:
            logging.error(f"Failed to disconnect Frida session: {e}")
            return False

    def cleanup(self) -> None:
        """Clean up Frida resources."""
        self.disconnect()
        self.device = None
        self.is_available = False


# Export the connection manager
__all__ = ["FridaConnection"]
