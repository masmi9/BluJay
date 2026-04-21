"""
Enhanced Frida Dynamic Analysis Plugin - Modular Architecture.

This package provides full Frida-based dynamic security analysis
with improved maintainability, performance, and error handling.
"""

try:
    from .main import run_plugin, run

    MAIN_MODULE_AVAILABLE = True
except ImportError as e:
    import logging

    logger = logging.getLogger(__name__)
    logger.warning(f"Main module not available: {e}")
    MAIN_MODULE_AVAILABLE = False

    # Fallback implementations
    def run_plugin(*args, **kwargs):
        return {"status": "error", "error": "Main module not available", "findings": []}

    def run(*args, **kwargs):
        return run_plugin(*args, **kwargs)


try:
    from .enhanced_frida_analyzer import EnhancedFridaDynamicAnalyzer

    ENHANCED_ANALYZER_AVAILABLE = True
except ImportError as e:
    import logging

    logger = logging.getLogger(__name__)
    logger.warning(f"Enhanced analyzer not available: {e}")
    ENHANCED_ANALYZER_AVAILABLE = False

    class EnhancedFridaDynamicAnalyzer:
        def __init__(self, *args, **kwargs):
            pass

        def analyze(self, *args, **kwargs):
            return {"status": "error", "error": "Enhanced analyzer not available", "findings": []}


try:
    from .icc_analyzer import ICCSecurityAnalyzer, ICCTestConfiguration

    ICC_ANALYZER_AVAILABLE = True
except ImportError as e:
    import logging

    logger = logging.getLogger(__name__)
    logger.warning(f"ICC analyzer not available: {e}")
    ICC_ANALYZER_AVAILABLE = False

    class ICCSecurityAnalyzer:
        def __init__(self, *args, **kwargs):
            pass

    class ICCTestConfiguration:
        def __init__(self, *args, **kwargs):
            pass


try:
    from .webview_exploitation_module import WebViewExploitationModule, WebViewExploitationConfig

    WEBVIEW_MODULE_AVAILABLE = True
except ImportError as e:
    import logging

    logger = logging.getLogger(__name__)
    logger.warning(f"WebView exploitation module not available: {e}")
    WEBVIEW_MODULE_AVAILABLE = False

    class WebViewExploitationModule:
        def __init__(self, *args, **kwargs):
            pass

    class WebViewExploitationConfig:
        def __init__(self, *args, **kwargs):
            pass


try:
    from .dynamic_execution_module import DynamicExecutionModule, DynamicExecutionConfig

    DYNAMIC_EXECUTION_AVAILABLE = True
except ImportError as e:
    import logging

    logger = logging.getLogger(__name__)
    logger.warning(f"Dynamic execution module not available: {e}")
    DYNAMIC_EXECUTION_AVAILABLE = False

    class DynamicExecutionModule:
        def __init__(self, *args, **kwargs):
            pass

    class DynamicExecutionConfig:
        def __init__(self, *args, **kwargs):
            pass


try:
    from .constants import PLUGIN_CHARACTERISTICS

    CONSTANTS_AVAILABLE = True
except ImportError as e:
    import logging

    logger = logging.getLogger(__name__)
    logger.warning(f"Plugin constants not available: {e}")
    CONSTANTS_AVAILABLE = False

    PLUGIN_CHARACTERISTICS = {"name": "Enhanced Frida Dynamic Analysis", "version": "1.0.0", "status": "fallback"}

try:
    from .data_structures import FridaTestResult, FridaAnalysisConfig, FridaVulnerabilityPattern, FridaTestCache

    DATA_STRUCTURES_AVAILABLE = True
except ImportError as e:
    import logging

    logger = logging.getLogger(__name__)
    logger.warning(f"Data structures not available: {e}")
    DATA_STRUCTURES_AVAILABLE = False

    class FridaTestResult:
        def __init__(self, *args, **kwargs):
            pass

    class FridaAnalysisConfig:
        def __init__(self, *args, **kwargs):
            pass

    class FridaVulnerabilityPattern:
        def __init__(self, *args, **kwargs):
            pass

    class FridaTestCache:
        def __init__(self, *args, **kwargs):
            pass


# Create alias for backward compatibility
analyzer = EnhancedFridaDynamicAnalyzer

# Enhanced __all__ export with availability checking
__all__ = [
    "run_plugin",
    "run",
    "EnhancedFridaDynamicAnalyzer",
    "ICCSecurityAnalyzer",
    "ICCTestConfiguration",
    "WebViewExploitationModule",
    "WebViewExploitationConfig",
    "DynamicExecutionModule",
    "DynamicExecutionConfig",
    "analyzer",
    "PLUGIN_CHARACTERISTICS",
    "FridaTestResult",
    "FridaAnalysisConfig",
    "FridaVulnerabilityPattern",
    "FridaTestCache",
]

# Add entry points for plugin manager compatibility


def analyze(apk_ctx=None):
    """Entry point for dynamic analysis."""
    if MAIN_MODULE_AVAILABLE:
        return run(apk_ctx)
    elif ENHANCED_ANALYZER_AVAILABLE:
        analyzer = EnhancedFridaDynamicAnalyzer()
        return analyzer.analyze(apk_ctx)
    else:
        return {"status": "error", "error": "No analyzers available", "findings": []}


def execute(apk_ctx=None):
    """Alternative entry point for compatibility."""
    return analyze(apk_ctx)


# BasePluginV2 interface
try:
    from .v2_plugin import FridaDynamicAnalysisV2, create_plugin  # noqa: F401

    Plugin = FridaDynamicAnalysisV2
except ImportError:
    pass
