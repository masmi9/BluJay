"""
WebView Security Analysis Plugin Module

This module provides full WebView security analysis for Android applications
with modular architecture, professional confidence calculation, and reliable
vulnerability detection capabilities.
"""

import logging

from .data_structures import (
    WebViewVulnerability,
    WebViewSecurityAnalysis,
    WebViewAnalysisContext,
    WebViewMethodInfo,
    JavaScriptInterfaceInfo,
    XSSTestResult,
    WebViewConfigurationIssue,
    WebViewVulnerabilityType,
    SeverityLevel,
    XSSPayloadType,
    WebViewContextType,
    WebViewConfigurationRisk,
    WebViewSecurityPatterns,
    MAVSControls,
    CWECategories,
)

from .confidence_calculator import WebViewSecurityConfidenceCalculator, calculate_webview_confidence

__version__ = "2.0.0"
__author__ = "AODS Security Team"

# Initialize logger
logger = logging.getLogger(__name__)

# Characteristics for plugin manager discovery
PLUGIN_CHARACTERISTICS = {
    "category": "STATIC_ANALYSIS",
    # WebView checks benefit from resources (XML, assets) and imports
    "decompilation_requirements": ["imports", "res"],
}


class WebViewSecurityAnalyzer:
    """
    WebView Security Analyzer - Main analysis class.

    Provides full WebView security analysis for Android applications
    with professional confidence calculation and vulnerability detection.
    """

    def __init__(self, apk_ctx):
        """Initialize WebView security analyzer."""
        self.apk_ctx = apk_ctx
        self.confidence_calculator = WebViewSecurityConfidenceCalculator()
        self.vulnerabilities = []
        logger.debug("WebView Security Analyzer initialized")

    def analyze(self) -> WebViewSecurityAnalysis:
        """
        Perform WebView security analysis.

        Returns:
            WebViewSecurityAnalysis: Analysis results
        """
        try:
            logger.debug("Starting full WebView security analysis")

            # Initialize analysis components
            from .comprehensive_analyzer import (
                WebViewComprehensiveAnalyzer,
                WebViewStaticAnalyzer,
                WebViewDynamicAnalyzer,
                WebViewXSSTester,
                WebViewConfigurationAnalyzer,
            )

            try:
                from .configuration_analyzer import WebViewConfigurationAnalyzer  # noqa: F811
            except ImportError:
                # Use a basic configuration analyzer if not available
                class WebViewConfigurationAnalyzer:
                    def analyze_configuration(self, apk_ctx, context):
                        return []  # Return empty list to match expected format

            # ROOT CAUSE FIX: Use self.apk_ctx consistently throughout analysis
            # Create analysis context with proper scope handling
            analysis_context = WebViewAnalysisContext(
                apk_path=getattr(self.apk_ctx, "apk_path_str", ""),
                package_name=getattr(self.apk_ctx, "package_name", "unknown"),
                deep_analysis_mode=True,
            )

            # Initialize analyzers
            static_analyzer = WebViewStaticAnalyzer()
            dynamic_analyzer = WebViewDynamicAnalyzer()
            xss_tester = WebViewXSSTester()
            config_analyzer = WebViewConfigurationAnalyzer()
            comprehensive_analyzer = WebViewComprehensiveAnalyzer(
                static_analyzer, dynamic_analyzer, xss_tester, config_analyzer
            )

            # Perform analysis with proper scope
            analysis_result = comprehensive_analyzer.analyze(self.apk_ctx, analysis_context)

            logger.info(
                f"WebView analysis complete: {analysis_result.total_webviews} WebViews analyzed, "
                f"{analysis_result.vulnerable_webviews} vulnerabilities found"
            )

            # Fallback to basic analysis if analysis fails
            if analysis_result.total_webviews == 0:
                logger.warning("Analysis found no WebViews, performing basic fallback analysis")
                analysis_result = self._perform_basic_fallback_analysis(self.apk_ctx)

            logger.debug("WebView security analysis completed")
            return analysis_result

        except Exception as e:
            logger.error(f"WebView security analysis failed: {e}")
            # Return empty results on error
            return WebViewSecurityAnalysis(
                total_webviews=0,
                vulnerable_webviews=0,
                javascript_interfaces=[],
                xss_test_results=[],
                configuration_issues=[],
                vulnerabilities=[],
                risk_score=0,
                security_recommendations=[],
                masvs_compliance={},
            )

    def _perform_basic_fallback_analysis(self, apk_ctx) -> WebViewSecurityAnalysis:
        """Perform basic fallback WebView analysis when analysis fails."""
        try:
            logger.debug("Performing basic WebView analysis")

            # Basic static analysis using APK context
            vulnerabilities = []
            javascript_interfaces = []
            configuration_issues = []

            # Try to find basic WebView usage patterns
            if hasattr(apk_ctx, "decompiled_path") and apk_ctx.decompiled_path:
                import os
                import re  # noqa: F401

                # Look for WebView usage in Java files
                java_files = []
                for root, dirs, files in os.walk(apk_ctx.decompiled_path):
                    for file in files:
                        if file.endswith(".java"):
                            java_files.append(os.path.join(root, file))

                webview_count = 0
                for java_file in java_files[:100]:  # Limit to prevent performance issues
                    try:
                        with open(java_file, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()

                        # Basic WebView detection
                        if "WebView" in content:
                            webview_count += 1

                            # Check for basic security issues
                            if "setJavaScriptEnabled(true)" in content:
                                vulnerabilities.append(
                                    WebViewVulnerability(
                                        vulnerability_type=WebViewVulnerabilityType.JAVASCRIPT_ENABLED_GLOBALLY,
                                        severity=SeverityLevel.MEDIUM,
                                        title="JavaScript Enabled Globally",
                                        description="WebView has JavaScript enabled which may pose security risks",
                                        file_path=java_file,
                                        line_number=1,
                                        code_snippet="setJavaScriptEnabled(true)",
                                        remediation="Only enable JavaScript when necessary and validate all inputs",
                                        masvs_control=MAVSControls.PLATFORM_3,
                                        cwe_category=CWECategories.IMPROPER_INPUT_VALIDATION,
                                        confidence=0.8,
                                        evidence=["JavaScript enabled globally in WebView"],
                                    )
                                )

                            if "addJavascriptInterface" in content:
                                javascript_interfaces.append(
                                    JavaScriptInterfaceInfo(
                                        interface_name="Unknown",
                                        exposed_methods=[],
                                        risk_level=WebViewConfigurationRisk.HIGH,
                                        file_path=java_file,
                                        line_number=1,
                                    )
                                )
                    except Exception as e:
                        logger.debug(f"Error analyzing file {java_file}: {e}")
                        continue

                logger.info(f"Basic analysis found {webview_count} WebView references")

            return WebViewSecurityAnalysis(
                total_webviews=max(webview_count, 1) if "webview_count" in locals() else 1,
                vulnerable_webviews=len(vulnerabilities),
                javascript_interfaces=javascript_interfaces,
                xss_test_results=[],
                configuration_issues=configuration_issues,
                vulnerabilities=vulnerabilities,
                risk_score=min(len(vulnerabilities) * 10, 100),
                security_recommendations=[
                    "Disable JavaScript in WebView unless absolutely necessary",
                    "Validate all data passed to WebView",
                    "Use HTTPS for all WebView content",
                    "Implement proper input validation for JavaScript interfaces",
                ],
                masvs_compliance={MAVSControls.PLATFORM_3: "PARTIAL" if vulnerabilities else "PASS"},
            )

        except Exception as e:
            logger.error(f"Basic fallback analysis failed: {e}")
            return WebViewSecurityAnalysis(
                total_webviews=0,
                vulnerable_webviews=0,
                javascript_interfaces=[],
                xss_test_results=[],
                configuration_issues=[],
                vulnerabilities=[],
                risk_score=0,
                security_recommendations=[],
                masvs_compliance={},
            )


__all__ = [
    # Data structures
    "WebViewVulnerability",
    "WebViewSecurityAnalysis",
    "WebViewAnalysisContext",
    "WebViewMethodInfo",
    "JavaScriptInterfaceInfo",
    "XSSTestResult",
    "WebViewConfigurationIssue",
    # Enums
    "WebViewVulnerabilityType",
    "SeverityLevel",
    "XSSPayloadType",
    "WebViewContextType",
    "WebViewConfigurationRisk",
    "WebViewSecurityPatterns",
    "MAVSControls",
    "CWECategories",
    # Analyzers
    "WebViewSecurityAnalyzer",
    "WebViewSecurityConfidenceCalculator",
    # Utility functions
    "calculate_webview_confidence",
]

# Plugin compatibility functions


def run(apk_ctx=None):
    """
    Main plugin entry point for compatibility with plugin manager.

    CRITICAL FIX: Enhanced variable scope handling to prevent 'apk_ctx' not defined errors.

    BROADER AODS SCOPE CONSIDERATIONS:
    - Maintains consistent plugin interface across AODS framework
    - Provides error handling and graceful degradation
    - Integrates with AODS logging and reporting systems
    - Ensures compatibility with multiple plugin invocation patterns
    """
    try:
        from rich.text import Text

        # AODS COMPATIBILITY: Ensure apk_ctx is properly validated and scoped
        if apk_ctx is None:
            logger.warning("WebView analysis called without APK context - skipping")
            return "WebView Security Analysis", Text(
                "WebView Security Analysis skipped - no APK context", style="yellow"
            )

        # CRITICAL FIX: Validate apk_ctx has required attributes
        if not hasattr(apk_ctx, "package_name"):
            logger.warning("APK context missing required attributes - using fallback analysis")
            # Set default attributes for compatibility
            apk_ctx.package_name = getattr(apk_ctx, "package_name", "unknown")
            apk_ctx.apk_path_str = getattr(apk_ctx, "apk_path", str(apk_ctx))

        # AODS SCOPE: Enhanced error handling with context preservation
        analyzer = WebViewSecurityAnalyzer(apk_ctx)
        result = analyzer.analyze()

        if hasattr(result, "vulnerabilities") and result.vulnerabilities:
            findings_text = Text()
            findings_text.append(
                f"WebView Security Analysis - {len(result.vulnerabilities)} findings\n", style="bold blue"
            )
            for finding in result.vulnerabilities[:10]:
                findings_text.append(f"• {finding.title}\n", style="yellow")
                findings_text.append(f"  {finding.description}\n", style="dim")
        else:
            findings_text = Text("WebView Security Analysis completed - No vulnerabilities found", style="green")

        return "WebView Security Analysis", findings_text

    except Exception as e:
        logger.error(f"WebView security analysis failed: {e}")
        error_text = Text(f"WebView Security Analysis Error: {str(e)}", style="red")
        return "WebView Security Analysis", error_text


# Add plugin entry points for different calling conventions


def analyze(apk_ctx=None):
    """Plugin entry point with optional parameters."""
    return run(apk_ctx)


def run_plugin(apk_ctx=None):
    """
    Standard AODS plugin entry point.

    CRITICAL FIX: This method ensures compatibility with AODS plugin execution
    patterns and prevents 'apk_ctx' not defined errors by providing proper
    variable scope and parameter handling.

    BROADER AODS SCOPE CONSIDERATIONS:
    - Follows AODS standard plugin interface conventions
    - Maintains consistency with other AODS plugins
    - Provides graceful error handling and logging integration
    - Supports multiple plugin invocation patterns used across AODS

    Args:
        apk_ctx: APK context object for analysis

    Returns:
        Tuple of (analysis_title, analysis_results)
    """
    try:
        # Ensure apk_ctx is properly scoped and available throughout execution
        if apk_ctx is None:
            logger.error("WebView security analysis: apk_ctx parameter is None")
            from rich.text import Text

            error_text = Text("WebView Security Analysis Error: APK context not provided", style="red")
            return "WebView Security Analysis", error_text

        # Delegate to the main run function with proper error handling
        return run(apk_ctx)

    except NameError as e:
        if "apk_ctx" in str(e):
            logger.error(f"Variable scope error in WebView analysis: {e}")
            from rich.text import Text

            error_text = Text(f"WebView Security Analysis Error: Variable scope issue - {str(e)}", style="red")
            return "WebView Security Analysis", error_text
        else:
            raise
    except Exception as e:
        logger.error(f"WebView security analysis execution failed: {e}")
        from rich.text import Text

        error_text = Text(f"WebView Security Analysis Error: {str(e)}", style="red")
        return "WebView Security Analysis", error_text


def execute():
    """Plugin entry point without parameters (fallback)."""
    return run(None)


# BasePluginV2 interface
try:
    from .v2_plugin import WebviewSecurityAnalysisV2, create_plugin  # noqa: F401

    Plugin = WebviewSecurityAnalysisV2
except ImportError:
    pass
