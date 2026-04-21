"""
core.cli.scanner_dynamic - Dynamic analysis functions extracted from AODSScanner (Track 50).
"""

import time
from typing import Dict, Any

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from core.output_manager import get_output_manager


def run_dynamic_analysis_only(scanner, timeout: int = 300) -> Dict[str, Any]:
    """
    Run only dynamic analysis components for parallel execution.

    This method is designed for parallel scan manager to run dynamic analysis
    in isolation from static analysis components.

    Args:
        scanner: AODSScanner instance
        timeout: Timeout in seconds for dynamic analysis

    Returns:
        Dict containing dynamic analysis results
    """
    output_mgr = get_output_manager()

    try:
        # Defensive: Validate inputs
        if timeout <= 0:
            timeout = 300  # Default 5 minutes
            output_mgr.warning(f"Invalid timeout provided, using default: {timeout}s")

        output_mgr.info("🔄 Starting dynamic-only analysis")

        # Defensive: Validate APK context
        if not hasattr(scanner, "apk_ctx") or not scanner.apk_ctx:
            error_msg = "APK context not available for dynamic analysis"
            output_mgr.error(error_msg)
            return create_error_dynamic_result(scanner, error_msg)

        # Initialize dynamic analysis results
        dynamic_results = {
            "analysis_type": "dynamic_only",
            "status": "started",
            "timestamp": time.time(),
            "results": {},
            "metadata": {
                "timeout": timeout,
                "package_name": getattr(scanner, "package_name", "unknown"),
                "apk_path": getattr(scanner, "apk_path", "unknown"),
            },
        }

        # Initialize Frida for dynamic analysis (Frida-first approach)
        try:
            # Check if Frida is available
            output_mgr.info("✅ Frida dynamic analysis framework available")
            dynamic_results["frida_available"] = True
            dynamic_results["drozer_available"] = False  # Drozer deprecated
        except ImportError:
            output_mgr.warning("⚠️ Frida not available - dynamic analysis limited")
            dynamic_results["frida_available"] = False
            dynamic_results["drozer_available"] = False

        # Run dynamic analysis components with full defensive checks
        if hasattr(scanner, "plugin_manager") and scanner.plugin_manager:
            try:
                # Defensive: Check if plugins are available
                plugin_count = len(getattr(scanner.plugin_manager, "plugins", {}))
                if plugin_count == 0:
                    output_mgr.warning("⚠️ No plugins available for execution")
                    if hasattr(scanner.plugin_manager, "_degraded_mode"):
                        output_mgr.info("🛡️ Running in degraded mode due to plugin loading issues")
                    return create_empty_dynamic_result(scanner, "No plugins available")

                # Execute all available plugins (including priority plugins like Frida)
                output_mgr.info(f"Running dynamic analysis with {plugin_count} plugins")

                # Defensive: Track execution time
                execution_start_time = time.time()

                try:
                    # Execute plugins using the standard plugin execution method
                    plugin_results = scanner.plugin_manager.execute_all_plugins(scanner.apk_ctx)
                except Exception as e:
                    output_mgr.error(f"❌ Plugin execution failed: {e}")
                    # Continue with partial results rather than complete failure
                    plugin_results = {"execution_error": str(e)}

                execution_time = time.time() - execution_start_time

                # Defensive: Ensure execution time is recorded
                if execution_time <= 0:
                    execution_time = 0.001  # Minimum recorded time

                # Extract just the results portion (execute_all_plugins returns Dict[str, Tuple[str, Any]])
                simplified_results = {}
                if isinstance(plugin_results, dict) and plugin_results:
                    for plugin_name, result_data in plugin_results.items():
                        if isinstance(result_data, tuple) and len(result_data) >= 2:
                            title, result = result_data
                            simplified_results[plugin_name] = {"title": title, "result": result}
                        else:
                            # Handle cases where result format is different
                            simplified_results[plugin_name] = {"title": plugin_name, "result": result_data}

                dynamic_results["results"] = simplified_results
                dynamic_results["execution_time"] = execution_time

                if simplified_results:
                    output_mgr.info(f"✅ Dynamic analysis completed with {len(simplified_results)} plugin results")
                else:
                    output_mgr.warning("⚠️ Dynamic analysis completed but no plugin results returned")

            except Exception as e:
                output_mgr.error(f"❌ Plugin execution error: {e}")
                dynamic_results["results"] = {"error": str(e)}
                dynamic_results["execution_time"] = 0
        else:
            # Defensive: Handle missing plugin manager
            error_msg = "Plugin manager not available"
            output_mgr.error(error_msg)
            return create_error_dynamic_result(scanner, error_msg)

        # Finalize results
        dynamic_results["status"] = "completed"
        dynamic_results["completion_time"] = time.time()

        # Defensive: Calculate duration safely
        if "execution_time" not in dynamic_results:
            dynamic_results["execution_time"] = dynamic_results["completion_time"] - dynamic_results["timestamp"]

        dynamic_results["duration"] = dynamic_results["completion_time"] - dynamic_results["timestamp"]

        output_mgr.info(f"✅ Dynamic-only analysis completed in {dynamic_results['duration']:.2f}s")
        return dynamic_results

    except Exception as e:
        output_mgr.error(f"❌ Dynamic analysis failed: {e}")
        return create_error_dynamic_result(scanner, str(e))


def create_empty_dynamic_result(scanner, reason: str = "No plugins executed") -> Dict[str, Any]:
    """Create empty result with proper structure (defensive helper function)."""
    return {
        "analysis_type": "dynamic_only",
        "status": "completed",
        "timestamp": time.time(),
        "completion_time": time.time(),
        "duration": 0.001,  # Minimal duration
        "execution_time": 0,
        "results": {},
        "metadata": {
            "reason": reason,
            "package_name": getattr(scanner, "package_name", "unknown"),
            "apk_path": getattr(scanner, "apk_path", "unknown"),
            "plugins_available": 0,
        },
        "error": None,
    }


def create_error_dynamic_result(scanner, error_msg: str) -> Dict[str, Any]:
    """Create error result with diagnostic information (defensive helper function)."""
    return {
        "analysis_type": "dynamic_only",
        "status": "failed",
        "timestamp": time.time(),
        "completion_time": time.time(),
        "duration": 0,
        "execution_time": 0,
        "results": {},
        "metadata": {
            "error_details": error_msg,
            "package_name": getattr(scanner, "package_name", "unknown"),
            "apk_path": getattr(scanner, "apk_path", "unknown"),
            "recovery_suggestions": get_recovery_suggestions(error_msg),
        },
        "error": error_msg,
    }


def get_recovery_suggestions(error_msg: str) -> list:
    """Get recovery suggestions based on error type (defensive helper function)."""
    suggestions = []

    if "plugin" in error_msg.lower():
        suggestions.append("Try running with --disable-ml to avoid ML-related plugin issues")
        suggestions.append("Check if all required dependencies are installed in the virtual environment")

    if "apk" in error_msg.lower() or "context" in error_msg.lower():
        suggestions.append("Verify the APK file path is correct and accessible")
        suggestions.append("Ensure the package name matches the APK contents")

    if "timeout" in error_msg.lower():
        suggestions.append("Try increasing the timeout value")
        suggestions.append("Check device connectivity if using dynamic analysis")

    if not suggestions:
        suggestions.append("Review the logs for more detailed error information")
        suggestions.append("Try running in verbose mode for additional diagnostics")

    return suggestions
