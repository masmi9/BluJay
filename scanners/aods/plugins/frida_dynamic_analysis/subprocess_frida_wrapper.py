#!/usr/bin/env python3
"""
Subprocess-based Frida execution wrapper to isolate hanging issues.

This module provides a reliable way to execute Frida dynamic analysis in an isolated
subprocess with proper timeout handling, preventing the main process from hanging.
"""

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, Any

from core.logging_config import get_logger

logger = get_logger(__name__)

# Modern external tool execution via unified executor
try:
    UNIFIED_EXECUTOR_AVAILABLE = True
except ImportError:
    UNIFIED_EXECUTOR_AVAILABLE = False
    logger.warning("unified_executor_unavailable", fallback="direct_subprocess")


class SubprocessFridaWrapper:
    """
    Wrapper for executing Frida dynamic analysis in an isolated subprocess.

    This prevents hanging issues from affecting the main AODS process while
    still providing full Frida functionality.
    """

    def __init__(self, timeout: int = 300):
        """
        Initialize the subprocess wrapper.

        Args:
            timeout: Maximum execution time in seconds (default: 5 minutes)
        """
        self.timeout = timeout
        self.venv_python = self._get_venv_python()

    def _get_venv_python(self) -> str:
        """Get the path to the virtual environment Python executable."""
        venv_path = Path(__file__).parent.parent.parent / "aods_venv" / "bin" / "python"
        if venv_path.exists():
            return str(venv_path)
        return sys.executable

    def execute_frida_analysis(self, apk_path: str, package_name: str = None) -> Dict[str, Any]:
        """
        Execute Frida dynamic analysis in an isolated subprocess.

        Args:
            apk_path: Path to the APK file to analyze
            package_name: Optional package name (will be auto-detected if not provided)

        Returns:
            Dictionary containing analysis results or error information
        """
        logger.info(f"🔄 Starting subprocess Frida analysis for: {apk_path}")

        # Create temporary files for communication
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as input_file:
            input_data = {"apk_path": apk_path, "package_name": package_name, "timestamp": time.time()}
            json.dump(input_data, input_file)
            input_file_path = input_file.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as output_file:
            output_file_path = output_file.name

        try:
            # Create the subprocess execution script
            execution_script = self._create_execution_script()

            # Execute Frida analysis in subprocess
            cmd = [self.venv_python, "-c", execution_script, input_file_path, output_file_path]

            logger.info(f"🚀 Executing Frida subprocess with {self.timeout}s timeout")
            start_time = time.time()

            result = subprocess.run(
                cmd, timeout=self.timeout, capture_output=True, text=True, cwd=Path(__file__).parent.parent.parent
            )

            execution_time = time.time() - start_time
            logger.info(f"⏱️ Subprocess completed in {execution_time:.2f}s")

            # Read results from output file
            try:
                with open(output_file_path, "r") as f:
                    results = json.load(f)

                if result.returncode == 0:
                    logger.info("✅ Frida analysis completed successfully")
                    results["execution_time"] = execution_time
                    return results
                else:
                    logger.error(f"❌ Subprocess failed with return code {result.returncode}")
                    logger.error(f"STDERR: {result.stderr}")
                    return self._create_error_result(f"Subprocess failed: {result.stderr}", execution_time)

            except (json.JSONDecodeError, FileNotFoundError) as e:
                logger.error(f"❌ Failed to read subprocess results: {e}")
                # Attempt to salvage minimal JSON from stdout/stderr
                salvage = None
                try:
                    if result.stdout and result.stdout.strip().startswith("{"):
                        salvage = json.loads(result.stdout.strip())
                    elif result.stderr and result.stderr.strip().startswith("{"):
                        salvage = json.loads(result.stderr.strip())
                except Exception:
                    salvage = None
                if salvage:
                    logger.info("✅ Salvaged JSON from subprocess stream")
                    salvage["execution_time"] = execution_time
                    return salvage
                return self._create_error_result(f"Failed to read results: {e}", execution_time)

        except subprocess.TimeoutExpired:
            logger.error(f"⏰ Frida subprocess timed out after {self.timeout}s")
            return self._create_error_result(f"Analysis timed out after {self.timeout}s", self.timeout)

        except Exception as e:
            logger.error(f"❌ Subprocess execution failed: {e}")
            return self._create_error_result(f"Execution failed: {e}", 0)

        finally:
            # Cleanup temporary files
            try:
                Path(input_file_path).unlink(missing_ok=True)
                Path(output_file_path).unlink(missing_ok=True)
            except Exception as e:
                logger.warning(f"⚠️ Failed to cleanup temp files: {e}")

    def _create_execution_script(self) -> str:
        """Create the Python script to execute in the subprocess."""
        return """
import json
import sys
import logging
import os

def main():
    try:
        input_file = sys.argv[1]
        output_file = sys.argv[2]

        # Read input parameters
        with open(input_file, 'r') as f:
            params = json.load(f)

        apk_path = params['apk_path']
        package_name = params.get('package_name')

        # Import and execute Frida analysis
        from plugins.frida_dynamic_analysis.main import run_plugin

        # Create a mock APK context if needed
        class MockAPKContext:
            def __init__(self, apk_path, package_name=None):
                self.apk_path = apk_path
                self.package_name = package_name or "unknown.package"
                self.decompiled_path = None

        apk_context = MockAPKContext(apk_path, package_name)

        # Execute the plugin
        results = run_plugin(apk_context)

        # Prepare output - ensure results is a dict
        if not isinstance(results, dict):
            results = {'success': False, 'error': 'Invalid result format', 'findings': []}

        output_data = {
            'success': results.get('success', True),
            'results': results,
            'plugin_name': 'frida_dynamic_analysis',
            'apk_path': apk_path,
            'package_name': package_name,
            'findings': results.get('findings', []),
            'vulnerabilities': results.get('vulnerabilities', results.get('findings', [])),
            'execution_time': results.get('execution_time', 0),
            'analysis_method': results.get('analysis_method', 'subprocess_execution')
        }

        # Write results
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)

        print("✅ Frida analysis completed successfully")

    except Exception as e:
        error_data = {
            'success': False,
            'error': str(e),
            'error_type': type(e).__name__,
            'plugin_name': 'frida_dynamic_analysis',
            'findings': [],
            'vulnerabilities': [],
            'execution_time': 0,
            'analysis_method': 'subprocess_execution_failed'
        }

        try:
            with open(output_file, 'w') as f:
                json.dump(error_data, f, indent=2)
        except Exception as write_error:
            # Fallback: write minimal JSON
            try:
                with open(output_file, 'w') as f:
                    f.write('{"success": false, "error": "Failed to write results", "findings": []}')
            except Exception:
                pass

        print(f"❌ Frida analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
"""

    def _create_error_result(self, error_message: str, execution_time: float) -> Dict[str, Any]:
        """Create a standardized error result."""
        return {
            "success": False,
            "error": error_message,
            "execution_time": execution_time,
            "results": [],
            "plugin_name": "frida_dynamic_analysis",
            "fallback_mode": True,
        }

    def test_frida_availability(self) -> Dict[str, Any]:
        """
        Test if Frida is available and working in subprocess mode.

        Returns:
            Dictionary with availability status and details
        """
        logger.info("🧪 Testing Frida availability in subprocess mode")

        test_script = """
import sys
import json

def test_frida():
    try:
        # Test basic import
        import frida

        # Test device enumeration with timeout
        import signal

        def timeout_handler(signum, frame):
            raise TimeoutError("Device enumeration timed out")

        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(10)  # 10 second timeout

        try:
            devices = frida.enumerate_devices()
            device_count = len(devices)
        except TimeoutError:
            device_count = -1  # Indicates timeout
        finally:
            signal.alarm(0)

        return {
            'available': True,
            'device_count': device_count,
            'frida_version': frida.__version__
        }

    except ImportError as e:
        return {
            'available': False,
            'error': f"Import failed: {e}"
        }
    except Exception as e:
        return {
            'available': False,
            'error': f"Test failed: {e}"
        }

if __name__ == "__main__":
    result = test_frida()
    print(json.dumps(result))
"""

        try:
            result = subprocess.run([self.venv_python, "-c", test_script], timeout=30, capture_output=True, text=True)

            if result.returncode == 0:
                test_result = json.loads(result.stdout.strip())
                logger.info(f"🔍 Frida test result: {test_result}")
                return test_result
            else:
                logger.error(f"❌ Frida test failed: {result.stderr}")
                return {"available": False, "error": result.stderr}

        except subprocess.TimeoutExpired:
            logger.error("⏰ Frida test timed out")
            return {"available": False, "error": "Test timed out"}
        except Exception as e:
            logger.error(f"❌ Frida test exception: {e}")
            return {"available": False, "error": str(e)}


def create_frida_wrapper(timeout: int = 300) -> SubprocessFridaWrapper:
    """
    Factory function to create a Frida subprocess wrapper.

    Args:
        timeout: Maximum execution time in seconds

    Returns:
        Configured SubprocessFridaWrapper instance
    """
    return SubprocessFridaWrapper(timeout=timeout)


if __name__ == "__main__":
    # Test the wrapper
    wrapper = SubprocessFridaWrapper(timeout=60)

    print("🧪 Testing Frida availability...")
    availability = wrapper.test_frida_availability()
    print(f"📊 Result: {json.dumps(availability, indent=2)}")

    if availability.get("available"):
        print("✅ Frida is available for subprocess execution")
    else:
        print(f"❌ Frida not available: {availability.get('error')}")
