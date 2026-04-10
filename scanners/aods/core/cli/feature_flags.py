"""
core.cli.feature_flags - Gated imports and boolean feature flags (Track 46).

Contains ~28 try-except gated imports that set _AVAILABLE boolean flags,
plus SHUTDOWN_EVENT, CLEANUP_REGISTRY, ADBHelper/FridaHelper stubs,
and the ENHANCED_REPORTING_AVAILABLE flag.

Side effects: Each try-except block logs a status message. This module
MUST be imported AFTER ``configure_structlog()`` has been called in dyna.py.
"""

import importlib.util
import os
import logging
import signal
import threading

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from core.output_manager import get_output_manager

# Lazy loader reference - import from utilities

# System integration fixes - module removed (dead code); flag kept for compat
SYSTEM_INTEGRATION_AVAILABLE = False

# Frida-first dynamic analysis integration (gated by tool availability)
FRIDA_FIRST_AVAILABLE = False
try:
    # Evaluate static-only gate up-front to suppress availability logs in static runs
    _static_gate = os.getenv("AODS_STATIC_ONLY", "0") == "1" or os.getenv("AODS_STATIC_ONLY_HARD", "0") == "1"
    from core.external.unified_tool_executor import check_frida_available as _check_frida_available

    _frida_info = _check_frida_available()
    if _frida_info.get("available"):
        try:
            FRIDA_FIRST_AVAILABLE = not _static_gate
            if not _static_gate:
                logger.info("frida_first_available")
        except ImportError:
            FRIDA_FIRST_AVAILABLE = False
            logger.debug("frida_first_module_unavailable")
    else:
        logger.debug("frida_tool_not_found")
except Exception as e:
    FRIDA_FIRST_AVAILABLE = False
    logger.debug("frida_availability_probe_failed", error=str(e))

# Disable Frida-first in static-only modes to avoid device/tool initialization
try:
    if os.getenv("AODS_STATIC_ONLY", "0") == "1" or os.getenv("AODS_STATIC_ONLY_HARD", "0") == "1":
        if FRIDA_FIRST_AVAILABLE:
            logger.info("frida_first_disabled", reason="static_only_mode")
        FRIDA_FIRST_AVAILABLE = False
except Exception:
    # Be conservative; if env check fails, leave flag as-is
    pass

# Core accuracy pipeline integration
ACCURACY_ENHANCEMENT_AVAILABLE = True


# Gate 4: Business domain detection for context-aware confidence scoring
try:
    from core.app_type_detector import BusinessDomain

    BUSINESS_DOMAIN_DETECTION_AVAILABLE = True
except ImportError:
    BUSINESS_DOMAIN_DETECTION_AVAILABLE = False
    BusinessDomain = None
# Updated to use unified execution framework
# Legacy compatibility import for ExecutionMode
# CONSOLIDATION FIX: Use unified analysis engine instead of deprecated parallel analysis engine
UNIFIED_ANALYSIS_ENGINE_AVAILABLE = importlib.util.find_spec("core.unified_analysis_engine") is not None
if UNIFIED_ANALYSIS_ENGINE_AVAILABLE:
    logger.info("unified_analysis_engine_loaded")
else:
    logger.debug("unified_analysis_engine_unavailable")
# CONSOLIDATION FIX: Use unified plugin management instead of deprecated plugin manager
UNIFIED_PLUGIN_MANAGER_AVAILABLE = importlib.util.find_spec("core.plugins") is not None
if UNIFIED_PLUGIN_MANAGER_AVAILABLE:
    logger.info("unified_plugin_management_loaded")
else:
    logger.debug("unified_plugin_management_unavailable")
# CONSOLIDATION FIX: Use unified reporting framework instead of deprecated report generator
UNIFIED_REPORTING_AVAILABLE = importlib.util.find_spec("core.shared_infrastructure.reporting") is not None
if UNIFIED_REPORTING_AVAILABLE:
    logger.info("unified_reporting_loaded")
else:
    logger.debug("unified_reporting_unavailable")


class ReportGenerator:
    """Fallback report generator when unified reporting is unavailable."""

    def __init__(self, *args, **kwargs):
        pass

    def generate_report(self, *args, **kwargs):
        return {"status": "fallback", "message": "Unified reporting not available"}


# NOTE: lazy_import_vulnerability_classifier_class lives in core.cli.utilities (canonical)

# Enhanced connection framework for better reliability
try:
    from core.enhanced_scan_orchestrator import EnhancedScanOrchestrator  # noqa: F401 - re-export

    # CONSOLIDATION FIX: Use unified network facade instead of deprecated connection framework
    UNIFIED_CONNECTION_MANAGER_AVAILABLE = importlib.util.find_spec("core.unified_connection_manager") is not None
    if UNIFIED_CONNECTION_MANAGER_AVAILABLE:
        logger.info("unified_connection_management_loaded")
    else:
        logger.debug("unified_connection_management_unavailable")
    ROBUST_CONNECTION_AVAILABLE = True
    logger.info("connection_framework_loaded")
except ImportError as e:
    ROBUST_CONNECTION_AVAILABLE = False
    logger.debug("connection_framework_unavailable", error=str(e))
# Centralized scan mode tracking
try:
    from core.scan_mode_tracker import set_global_scan_mode, get_global_scan_mode  # noqa: F401 - re-export

    SCAN_MODE_TRACKER_AVAILABLE = True
except ImportError:
    SCAN_MODE_TRACKER_AVAILABLE = False
    logger.warning("scan_mode_tracker_unavailable")
# Unified execution framework components
SCAN_ORCHESTRATOR_AVAILABLE = importlib.util.find_spec("core.enhanced_scan_orchestrator") is not None

# Legacy parallel window execution manager (disabled)
PARALLEL_WINDOWS_AVAILABLE = False
logger.info("parallel_execution_disabled", reason="pinned_to_canonical_orchestrator")

# Canonical execution integration (supplements imports at top)
ENHANCED_PARALLEL_AVAILABLE = importlib.util.find_spec("core.execution.canonical_orchestrator") is not None
if ENHANCED_PARALLEL_AVAILABLE:
    logger.info("canonical_execution_loaded")
else:
    logger.debug("canonical_execution_unavailable")

logger.info("feature_flags_loaded")

# Unified Threat Intelligence Integration
try:
    from core.unified_threat_intelligence import get_unified_threat_intelligence, initialize_unified_threat_intelligence

    UNIFIED_THREAT_INTEL_AVAILABLE = True
    logger.info("unified_threat_intel_loaded")
except ImportError as e:
    UNIFIED_THREAT_INTEL_AVAILABLE = False
    logger.debug("unified_threat_intel_unavailable", error=str(e))

    def get_unified_threat_intelligence(config=None):
        raise RuntimeError(f"Unified Threat Intelligence unavailable: {e}")  # noqa: F821

    def initialize_unified_threat_intelligence(*a, **kw):
        pass


# Machine learning integration with defensive disable logic
try:
    # Check if ML is disabled globally
    # Phase 9.6: Fix bug where AODS_DISABLE_ML=0 was treated as disabled (string '0' is truthy)
    if os.environ.get("AODS_DISABLE_ML", "").lower() in ("1", "true", "yes"):
        logger.info("ml_integration_disabled", reason="environment_variable")
        raise ImportError("ML disabled via environment variable")

    from core.ml_integration_manager import MLIntegrationManager

    ML_INTEGRATION_AVAILABLE = True
    logger.info("ml_integration_loaded")
except ImportError as e:
    ML_INTEGRATION_AVAILABLE = False
    if "disabled via environment variable" in str(e):
        logger.info("ml_integration_disabled_intentionally")
    else:
        logger.debug("ml_integration_unavailable", error=str(e))

    # Create a dummy class to avoid UnboundLocalError
    class FallbackMLIntegrationManager:
        def __init__(self, *args, **kwargs):
            pass

        def initialize(self):
            return False

    # Assign the fallback class to MLIntegrationManager to prevent UnboundLocalError
    MLIntegrationManager = FallbackMLIntegrationManager

# ADVANCED_INTELLIGENCE_AVAILABLE mirrors UNIFIED_THREAT_INTEL_AVAILABLE (single source)
ADVANCED_INTELLIGENCE_AVAILABLE = UNIFIED_THREAT_INTEL_AVAILABLE

# WebView Security Analysis Integration
WEBVIEW_SECURITY_AVAILABLE = importlib.util.find_spec("core.webview_security_analyzer") is not None
if WEBVIEW_SECURITY_AVAILABLE:
    logger.info("webview_security_loaded")
else:
    logger.debug("webview_security_unavailable")

# ENHANCED_ORCHESTRATOR_AVAILABLE mirrors ROBUST_CONNECTION_AVAILABLE (same import block above)
ENHANCED_ORCHESTRATOR_AVAILABLE = ROBUST_CONNECTION_AVAILABLE

# Unified Payload Manager Integration
try:
    from core.unified_payload_manager import UnifiedPayloadManager, PayloadCategory  # noqa: F401 - re-export

    UNIFIED_PAYLOAD_MANAGER_AVAILABLE = True
    logger.info("unified_payload_manager_loaded")
except ImportError as e:
    UNIFIED_PAYLOAD_MANAGER_AVAILABLE = False
    logger.debug("unified_payload_manager_unavailable", error=str(e))

# Process management for clean termination
PSUTIL_AVAILABLE = importlib.util.find_spec("psutil") is not None
if not PSUTIL_AVAILABLE:
    logger.warning("psutil_unavailable")

# Always define CLEANUP_REGISTRY so signal_cleanup can import it unconditionally
CLEANUP_REGISTRY = []

# Graceful shutdown manager
try:
    from core.graceful_shutdown_manager import (  # noqa: F401 - re-export (reset_shutdown_manager)
        register_cleanup,
        reset_shutdown_manager,
    )

    GRACEFUL_SHUTDOWN_AVAILABLE = True
    logger.info("graceful_shutdown_loaded")

    # Create compatibility event for legacy code
    SHUTDOWN_EVENT = threading.Event()
except ImportError as e:
    GRACEFUL_SHUTDOWN_AVAILABLE = False
    logger.debug("graceful_shutdown_unavailable", error=str(e))

    # Fallback to basic signal handling
    CLEANUP_REGISTRY = []
    SHUTDOWN_EVENT = threading.Event()

    def register_cleanup(func):
        """Register a cleanup function to be called on exit."""
        CLEANUP_REGISTRY.append(func)

    def signal_handler(signum, frame):
        """Basic signal handler for clean shutdown."""
        output_mgr = get_output_manager()
        signal_name = signal.Signals(signum).name
        output_mgr.warning(f"Received {signal_name} signal - initiating clean shutdown...")

        SHUTDOWN_EVENT.set()


# Plugin execution manager for preventing premature termination
# CONSOLIDATION FIX: Use unified plugin manager execution capabilities instead of deprecated reliable execution
ROBUST_PLUGIN_EXECUTION_AVAILABLE = True  # Always available through unified plugin manager

# Unified Threat Intelligence System (replaces legacy engines)
# Gate on actual import success from above
THREAT_INTELLIGENCE_AVAILABLE = UNIFIED_THREAT_INTEL_AVAILABLE

# Cross-platform analysis removed (Track 65) - modules deleted as dead code
CROSS_PLATFORM_ANALYSIS_AVAILABLE = False

# Drozer removed - AODS is Frida-first. Minimal no-op stub retained for import compatibility.


class DrozerHelper:
    """No-op stub. Drozer removed from AODS - use Frida for dynamic analysis."""

    def __init__(self, package_name: str):
        self.package_name = package_name

    def start_drozer(self) -> bool:
        return False

    def check_connection(self) -> bool:
        return False


# Import device helpers only if available
try:
    from core.adb_exploitation_framework import ADBDeviceManager as ADBHelper
except ImportError:
    # Create a minimal fallback ADBHelper class
    class ADBHelper:
        def __init__(self, *args, **kwargs):
            pass

        def __getattr__(self, name):
            def method(*args, **kwargs):
                raise RuntimeError(f"ADBHelper not available: {name} method called")

            return method


# Frida functionality is integrated through existing dynamic analysis framework
FridaHelper = None

# Import dynamic analysis
try:
    from core.dynamic_log_analyzer import DynamicAnalysisResult, create_dynamic_log_analyzer
except ImportError:
    # Create a minimal fallback class for type annotations
    class DynamicAnalysisResult:
        def __init__(self, **kwargs):
            self.status = "unavailable"
            self.data = kwargs

    def create_dynamic_log_analyzer(*args, **kwargs):
        raise RuntimeError("Dynamic log analyzer is not available")


# Enhanced vulnerability reporting
try:
    from core.shared_infrastructure.reporting.unified_facade import (
        UnifiedReportingManager as EnhancedVulnerabilityReportingEngine,
    )  # noqa: F401 - re-export

    ENHANCED_REPORTING_AVAILABLE = True
    logger.info("enhanced_reporting_loaded")
except ImportError as e:
    try:
        from core.enhanced_vulnerability_reporting_engine import (  # noqa: F401 - re-export
            EnhancedVulnerabilityReportingEngine,
        )

        ENHANCED_REPORTING_AVAILABLE = True
        logger.info("enhanced_reporting_loaded", source="fallback")
    except ImportError:
        ENHANCED_REPORTING_AVAILABLE = False
        logger.debug("enhanced_reporting_unavailable", error=str(e))

# Agent Intelligence System (Track 90) - optional, disabled by default
AGENT_AVAILABLE = False
try:
    if os.environ.get("AODS_AGENT_ENABLED", "").lower() in ("1", "true", "yes"):
        _agent_spec = importlib.util.find_spec("core.agent")
        if _agent_spec is not None:
            AGENT_AVAILABLE = True
            logger.info("agent_system_available")
        else:
            logger.debug("agent_system_unavailable", reason="core.agent not found")
    else:
        logger.debug("agent_system_disabled", reason="AODS_AGENT_ENABLED not set")
except Exception as e:
    logger.debug("agent_system_probe_failed", error=str(e))
