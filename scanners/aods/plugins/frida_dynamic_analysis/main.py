#!/usr/bin/env python3
"""
Frida Dynamic Analysis Plugin

This plugin performs runtime security analysis using Frida instrumentation.
Includes subprocess isolation and fallback mechanisms for reliability.
"""

import logging
import os
import time
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def run_plugin(apk_path: str, output_dir: str = ".", options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Main entry point for Frida dynamic analysis plugin.

    Uses subprocess isolation as primary execution method with fallback to
    direct execution if subprocess fails.

    Args:
        apk_path: Path to APK file or APKContext object
        output_dir: Output directory for results
        options: Optional configuration parameters

    Returns:
        Analysis results dictionary
    """
    # Skip in static-only mode - Frida requires device/emulator
    if os.getenv("AODS_STATIC_ONLY_HARD", "0") == "1" or os.getenv("AODS_STATIC_ONLY", "0") == "1":
        logger.info("⏭️ Skipping Frida dynamic analysis in static-only mode")
        try:
            from core.policy_decision_logger import get_policy_logger, PolicyOutcome

            get_policy_logger().log_frida_safety(
                outcome=PolicyOutcome.SKIPPED,
                operation="dynamic_analysis",
                reason="Static-only mode enabled",
            )
        except Exception:
            pass
        return {
            "success": True,
            "status": "skipped",
            "analysis_method": "static_only_skip",
            "findings": [],
            "vulnerabilities": [],
            "total_findings": 0,
            "execution_time": 0.0,
            "status_message": "Frida dynamic analysis skipped in static-only mode",
        }

    try:
        logger.info(f"🔍 Starting Frida dynamic analysis for {apk_path}")
        start_time = time.time()

        # Try subprocess isolation first (recommended approach)
        try:
            logger.info("🔧 Attempting subprocess isolation execution...")
            result = _run_via_subprocess(apk_path, output_dir, options)
            if result.get("success"):
                logger.info(f"✅ Subprocess execution completed successfully in {time.time() - start_time:.2f}s")
                return result
            else:
                logger.info("Subprocess execution failed, trying direct execution (expected in some environments)...")
        except Exception as e:
            logger.info(f"Subprocess execution error: {e}, trying direct execution...")
            try:
                from core.policy_decision_logger import get_policy_logger, PolicyOutcome

                get_policy_logger().log_frida_safety(
                    outcome=PolicyOutcome.DEGRADED,
                    operation="subprocess_isolation",
                    reason=f"Subprocess failed, falling back to direct: {e}",
                )
            except Exception:
                pass

        # Fallback to direct execution
        try:
            logger.info("🔧 Attempting direct execution...")
            result = _run_direct_execution(apk_path, output_dir, options)
            if result.get("success"):
                logger.info(f"✅ Direct execution completed successfully in {time.time() - start_time:.2f}s")
                return result
            else:
                logger.info("Direct execution failed, using fallback analyzer (no device or static-only)...")
        except Exception as e:
            logger.info(f"Direct execution error: {e}, using fallback analyzer...")
            try:
                from core.policy_decision_logger import get_policy_logger, PolicyOutcome

                get_policy_logger().log_frida_safety(
                    outcome=PolicyOutcome.DEGRADED,
                    operation="direct_execution",
                    reason=f"Direct execution failed, falling back to mock: {e}",
                )
            except Exception:
                pass

        # Final fallback to mock results
        logger.info("🔧 Using fallback analyzer...")
        return _run_fallback_analyzer(apk_path, output_dir, options)

    except Exception as e:
        logger.error(f"❌ All execution methods failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "findings": [],
            "plugin_name": "frida_dynamic_analysis",
            "analysis_method": "all_methods_failed",
        }


def _run_via_subprocess(apk_path: str, output_dir: str, options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Execute Frida analysis in isolated subprocess."""
    try:
        # Import subprocess wrapper
        from .subprocess_frida_wrapper import SubprocessFridaWrapper

        # Extract package name from options or APK context
        package_name = None
        if hasattr(apk_path, "package_name"):
            package_name = apk_path.package_name
        elif options:
            package_name = options.get("package_name")
        # Resolve timeout from options or environment (default 300s)
        timeout = 300
        if options and isinstance(options, dict):
            try:
                timeout = int(options.get("timeout", timeout))
            except Exception:
                pass
        env_timeout = os.getenv("AODS_FRIDA_TIMEOUT")
        if env_timeout:
            try:
                timeout = int(env_timeout)
            except Exception:
                logger.debug("Invalid AODS_FRIDA_TIMEOUT value; using default", exc_info=False)

        wrapper = SubprocessFridaWrapper(timeout=timeout)
        return wrapper.execute_frida_analysis(str(apk_path), package_name)

    except ImportError:
        logger.warning("Subprocess wrapper not available")
        raise Exception("Subprocess wrapper import failed")
    except Exception as e:
        logger.error(f"Subprocess execution failed: {e}")
        raise


def _run_direct_execution(apk_path: str, output_dir: str, options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Execute Frida analysis directly in-process with a safe minimal context."""
    try:
        # Import enhanced analyzer with lazy loading
        from .enhanced_frida_analyzer import EnhancedFridaDynamicAnalyzer

        # Extract package name from options or APK context
        package_name = "unknown.package"
        if hasattr(apk_path, "package_name"):
            package_name = getattr(apk_path, "package_name") or package_name
        elif options:
            package_name = options.get("package_name", package_name)
        # Merge options and honor environment-configured timeout for direct analysis
        merged_options: Dict[str, Any] = dict(options) if options else {}
        timeout = 300
        try:
            timeout = int(merged_options.get("timeout", timeout))
        except Exception:
            pass
        env_timeout = os.getenv("AODS_FRIDA_TIMEOUT")
        if env_timeout:
            try:
                timeout = int(env_timeout)
            except Exception:
                logger.debug("Invalid AODS_FRIDA_TIMEOUT value; using default", exc_info=False)
        merged_options["timeout"] = timeout

        # Initialize analyzer, passing merged options as config
        analyzer = EnhancedFridaDynamicAnalyzer(package_name, merged_options)

        # Create a minimal APK context expected by analyzer.analyze()
        class _MinimalAPKContext:
            def __init__(self, path, pkg):
                self.apk_path = path
                self.package_name = pkg
                # Commonly referenced attributes guarded in analyzer
                self.decompiled_apk_dir = None
                self.decompiled_path = None

        apk_ctx = _MinimalAPKContext(apk_path, package_name)
        # Provide frida_manager on the minimal context for analyzers that expect it
        frida_manager_instance = None
        try:
            # Prefer unified manager if available
            from core.unified_analysis_managers import get_frida_manager

            try:
                frida_manager_instance = get_frida_manager(package_name, strategy="auto")
            except Exception:
                frida_manager_instance = None
        except Exception:
            try:
                # Fallback to direct FridaManager if exposed
                from core.unified_analysis_managers import FridaManager

                try:
                    frida_manager_instance = FridaManager(package_name)
                except Exception:
                    frida_manager_instance = None
            except Exception:
                frida_manager_instance = None
        setattr(apk_ctx, "frida_manager", frida_manager_instance)

        # Run analysis with minimal context; analyzer handles full vs basic path
        return analyzer.analyze(apk_ctx)

    except ImportError as e:
        logger.warning(f"Enhanced analyzer import failed: {e}", exc_info=True)
        raise Exception("Enhanced analyzer import failed")
    except Exception as e:
        logger.error(f"Direct execution failed: {e}", exc_info=True)
        raise


def _run_fallback_analyzer(apk_path: str, output_dir: str, options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Fallback analyzer that provides mock results."""
    try:
        from .frida_fallback_analyzer import FridaFallbackAnalyzer

        # Extract package name from options or APK context
        package_name = "unknown.package"
        if hasattr(apk_path, "package_name"):
            package_name = apk_path.package_name or package_name
        elif options:
            package_name = options.get("package_name", package_name)

        analyzer = FridaFallbackAnalyzer(package_name, options or {})
        return analyzer.analyze(apk_path)

    except ImportError:
        logger.warning("Fallback analyzer not available, using emergency fallback")
        return _emergency_fallback(apk_path, options)
    except Exception as e:
        logger.error(f"Fallback analyzer failed: {e}")
        return _emergency_fallback(apk_path, options)


def _emergency_fallback(apk_path: str, options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Emergency fallback when Frida analysis cannot be performed.

    Returns success=False with empty findings to avoid polluting scan results
    with mock data. Diagnostic info is preserved in 'fallback_info' field.
    """
    logger.warning("🚨 Using emergency fallback - Frida dynamic analysis unavailable")

    # Extract package name for diagnostic info
    if hasattr(apk_path, "package_name"):
        package_name = apk_path.package_name or "unknown.package"
    else:
        package_name = options.get("package_name", "unknown.package") if options else "unknown.package"

    # Diagnostic info (NOT reported as findings/vulnerabilities)
    fallback_info = {
        "status": "unavailable",
        "package": package_name,
        "reason": "Frida dynamic analysis could not be performed",
        "recommendation": "Check Frida installation and device connectivity",
    }

    return {
        "success": False,  # Indicate analysis failed - don't pretend it succeeded
        "plugin_name": "frida_dynamic_analysis",
        "execution_time": 0.1,
        "findings": [],  # Empty - no mock data polluting results
        "vulnerabilities": [],  # Empty - no mock data polluting results
        "analysis_method": "emergency_fallback",
        "total_findings": 0,
        "status_message": "Frida dynamic analysis unavailable - check installation",
        "fallback_info": fallback_info,  # Diagnostic info preserved separately
    }


def run(apk_path: str, output_dir: str = ".", options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Alias for run_plugin for backward compatibility."""
    return run_plugin(apk_path, output_dir, options)


if __name__ == "__main__":
    # Test the plugin
    print("🧪 Testing Frida dynamic analysis plugin...")

    test_options = {"package_name": "com.test.app"}
    result = run_plugin("test.apk", options=test_options)

    print(f"📊 Success: {result.get('success')}")
    print(f"🔧 Method: {result.get('analysis_method')}")
    print(f"📈 Findings: {result.get('total_findings', 0)}")
    print("✅ Plugin test completed!")
