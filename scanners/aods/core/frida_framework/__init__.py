#!/usr/bin/env python3
"""
Frida Framework - Modular Dynamic Analysis Framework

modular Frida framework for full Android security testing.
Provides advanced dynamic analysis capabilities with clean architecture.

Components:
- FridaManager: Main orchestrator for dynamic analysis
- FridaConnection: Core connection and device management
- ScriptManager: Script loading and execution management
- FlutterAnalyzer: Flutter-specific analysis capabilities
- AnalysisOrchestrator: High-level analysis workflow coordination

Features:
- Modular architecture with clean separation of concerns
- SSL pinning bypass capabilities
- WebView security testing
- Anti-Frida detection bypass
- Flutter application support
- confidence scoring
- Full result aggregation
- 100% backward compatibility

"""

from .frida_connection import FridaConnection
from .script_manager import ScriptManager
from .flutter_analyzer import FlutterAnalyzer
from .analysis_orchestrator import AnalysisOrchestrator

# Export all components
__all__ = [
    # Core components
    "FridaConnection",
    "ScriptManager",
    "FlutterAnalyzer",
    "AnalysisOrchestrator",
]

# Version information
__version__ = "2.0.0"
__author__ = "AODS Development Team"
__description__ = "Modular Frida Framework for Dynamic Android Security Testing"

# Framework capabilities
FRAMEWORK_CAPABILITIES = [
    "ssl_bypass",
    "webview_security",
    "anti_frida_detection",
    "flutter_analysis",
    "custom_scripts",
    "comprehensive_analysis",
    "targeted_analysis",
    "real_time_monitoring",
]

# Supported script types
SUPPORTED_SCRIPT_TYPES = [
    "ssl_bypass",
    "webview_security",
    "anti_frida",
    "flutter_comprehensive",
    "flutter_architecture",
    "custom",
]
