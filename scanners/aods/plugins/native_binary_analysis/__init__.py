#!/usr/bin/env python3
"""
Native Binary Analysis Plugin

Provides static and dynamic analysis of native code components within Android APKs,
including ARM/x86 libraries, native vulnerabilities, and security assessments.
"""

import logging
from typing import Dict, List, Any, Optional  # noqa: F401

logger = logging.getLogger(__name__)

# Interface migration flag - StandardizedVulnerability interface not yet implemented
# Setting to False prevents NameError when checking migration availability
INTERFACE_MIGRATION_AVAILABLE = False


try:
    from .binary_analyzer import BinaryAnalyzer

    ANALYZER_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Binary Analyzer not available: {e}")
    ANALYZER_AVAILABLE = False

    # Fallback analyzer class
    class BinaryAnalyzer:
        def __init__(self, *args, **kwargs):
            pass

        def analyze(self, apk_ctx=None) -> Dict[str, Any]:
            return {"status": "unavailable", "error": "Binary analyzer not available", "findings": []}

        def run(self, apk_ctx=None):
            return self.analyze(apk_ctx)


# Export main classes
__all__ = ["BinaryAnalyzer", "ANALYZER_AVAILABLE"]


def analyze(apk_ctx=None) -> Dict[str, Any]:
    """Entry point for native binary analysis."""
    try:
        if not ANALYZER_AVAILABLE:
            return {"status": "unavailable", "error": "Binary analyzer not available - using fallback", "findings": []}

        # Create required dependencies for BinaryAnalyzer
        try:
            from core.shared_infrastructure.dependency_injection import AnalysisContext
            from .confidence_calculator import BinaryConfidenceCalculator
            import logging as log

            # Extract APK path from context for AnalysisContext constructor
            if apk_ctx and hasattr(apk_ctx, "apk_path"):
                apk_path = str(apk_ctx.apk_path)
            elif apk_ctx and hasattr(apk_ctx, "apk_path_str"):
                apk_path = str(apk_ctx.apk_path_str)
            else:
                apk_path = "unknown.apk"  # Fallback for missing APK path

            context = AnalysisContext(apk_path)
            confidence_calc = BinaryConfidenceCalculator()
            analyzer_logger = log.getLogger(__name__)

            analyzer = BinaryAnalyzer(context, confidence_calc, analyzer_logger)
            result = analyzer.analyze(apk_ctx)

            # INTERFACE STANDARDIZATION: Migrate to StandardizedVulnerability if available
            if INTERFACE_MIGRATION_AVAILABLE and isinstance(result, dict) and result.get("findings"):
                try:
                    standardized_vulnerabilities = migrate_to_standardized_vulnerabilities(result)  # noqa: F821
                    if standardized_vulnerabilities:
                        logger.info(
                            f"🔄 Migrated {len(standardized_vulnerabilities)} native binary vulnerabilities to standardized format"  # noqa: E501
                        )
                        # Store standardized vulnerabilities in result for downstream processing
                        result["standardized_vulnerabilities"] = standardized_vulnerabilities
                except Exception as e:
                    logger.warning(f"Interface migration failed, continuing with original format: {e}")

            return result
        except ImportError:
            # Fall back to simple analyzer
            fallback_analyzer = BinaryAnalyzer()  # Use fallback class
            return fallback_analyzer.analyze(apk_ctx)
    except Exception as e:
        logger.error(f"Native binary analysis failed: {e}")
        return {"status": "error", "error": str(e), "findings": []}


def run(apk_ctx=None):
    """Legacy entry point for compatibility."""
    return analyze(apk_ctx)


def run_plugin(apk_ctx=None):
    """
    Standard AODS plugin entry point for native binary analysis.

    CRITICAL FIX: Implements standardized AODS plugin interface with full
    error handling and path validation to prevent 'stem' attribute errors.

    BROADER AODS SCOPE CONSIDERATIONS:
    - Follows AODS standard plugin interface conventions across all plugins
    - Maintains consistency with unified plugin management system
    - Provides error handling and graceful degradation
    - Integrates with AODS logging and reporting infrastructure
    - Supports multiple plugin invocation patterns used throughout AODS
    - Ensures proper APK context validation and path handling

    Args:
        apk_ctx: APK context object containing APK path and metadata

    Returns:
        Tuple of (analysis_title, analysis_results) in AODS standard format
    """
    try:
        from rich.text import Text

        # AODS COMPATIBILITY: Validate APK context and handle missing parameters
        if apk_ctx is None:
            logger.error("Native binary analysis: apk_ctx parameter is None")
            error_text = Text("Native Binary Analysis Error: APK context not provided", style="red")
            return "Native Binary Analysis", error_text

        # CRITICAL FIX: Validate APK path handling to prevent 'stem' attribute errors
        if not hasattr(apk_ctx, "apk_path") and not hasattr(apk_ctx, "apk_path_str"):
            logger.error("Native binary analysis: APK context missing path information")
            error_text = Text("Native Binary Analysis Error: APK path not found in context", style="red")
            return "Native Binary Analysis", error_text

        # AODS SCOPE: Enhanced error handling with specific Path/string validation
        try:
            # Perform the analysis using the main analyze function
            result = analyze(apk_ctx)

            # Format results for AODS standard return format
            if isinstance(result, dict):
                if result.get("status") == "error":
                    error_text = Text()
                    error_text.append("Native Binary Analysis Failed\n", style="red bold")
                    error_text.append(f"Error: {result.get('error', 'Unknown error')}\n", style="red")
                    return "Native Binary Analysis", error_text
                elif result.get("status") == "unavailable":
                    warning_text = Text()
                    warning_text.append("Native Binary Analysis Unavailable\n", style="yellow bold")
                    warning_text.append(f"Reason: {result.get('error', 'Analyzer not available')}\n", style="yellow")
                    return "Native Binary Analysis", warning_text
                else:
                    # Success case - format findings
                    findings = result.get("findings", [])
                    if findings:
                        success_text = Text()
                        success_text.append(f"Native Binary Analysis - {len(findings)} findings\n", style="bold blue")
                        for i, finding in enumerate(findings[:10]):  # Show first 10 findings
                            title = finding.get("title", f"Finding {i+1}")
                            desc = finding.get("description", "No description available")
                            success_text.append(f"• {title}\n", style="yellow")
                            success_text.append(f"  {desc}\n", style="dim")

                        if len(findings) > 10:
                            success_text.append(f"\n... and {len(findings) - 10} more findings\n", style="dim")

                        return "Native Binary Analysis", success_text
                    else:
                        success_text = Text("Native Binary Analysis completed - No issues found", style="green")
                        return "Native Binary Analysis", success_text
            else:
                # Fallback for unexpected result format
                info_text = Text(f"Native Binary Analysis completed: {str(result)}", style="cyan")
                return "Native Binary Analysis", info_text

        except Exception as analysis_error:
            logger.error(f"Native binary analysis execution failed: {analysis_error}")
            error_text = Text()
            error_text.append("Native Binary Analysis Execution Failed\n", style="red bold")
            error_text.append(f"Error: {str(analysis_error)}\n", style="red")
            return "Native Binary Analysis", error_text

    except ImportError as e:
        logger.error(f"Native binary analysis import failed: {e}")
        error_text = Text(f"Native Binary Analysis Import Error: {str(e)}", style="red")
        return "Native Binary Analysis", error_text
    except Exception as e:
        logger.error(f"Native binary analysis plugin failed: {e}")
        error_text = Text(f"Native Binary Analysis Plugin Error: {str(e)}", style="red")
        return "Native Binary Analysis", error_text


def execute(apk_ctx=None):
    """Alternative entry point for compatibility."""
    return analyze(apk_ctx)


# BasePluginV2 interface
try:
    from .v2_plugin import NativeBinaryAnalysisV2, create_plugin  # noqa: F401

    Plugin = NativeBinaryAnalysisV2
except ImportError:
    pass
