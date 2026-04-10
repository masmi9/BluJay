#!/usr/bin/env python3
"""
Intent Fuzzing Analysis Plugin - Modular Architecture

This module provides full intent fuzzing and URI manipulation testing
for Android applications implementing MASVS platform security requirements.

Features:
- Intent fuzzing and URI manipulation testing
- MASVS compliance validation
- result enhancement
- Device-based dynamic analysis
- Rich text reporting

Modular Components:
- data_structures.py: Core data classes and enums
- intent_analyzer.py: Intent fuzzing orchestration
- masvs_mapper.py: MASVS control mapping and compliance
- formatter.py: Rich text output formatting

MASVS Controls: MSTG-PLATFORM-01, MSTG-PLATFORM-02, MSTG-PLATFORM-03, MSTG-PLATFORM-04, MSTG-PLATFORM-05, MSTG-CODE-8, MSTG-CODE-9  # noqa: E501

"""

import logging
from typing import Tuple, Union

from rich.text import Text

from core.intent_fuzzer import IntentFuzzer, run_intent_fuzzing_analysis  # noqa: F401

logger = logging.getLogger(__name__)

# Plugin metadata
PLUGIN_METADATA = {
    "name": "Intent Fuzzing Analysis",
    "description": "Full intent fuzzing and URI manipulation testing with modular architecture",
    "version": "2.0.0",
    "author": "AODS Development Team",
    "category": "DYNAMIC_ANALYSIS",
    "priority": "HIGH",
    "timeout": 120,
    "mode": "deep",
    "requires_device": True,
    "requires_network": False,
    "invasive": True,
    "execution_time_estimate": 60,
    "dependencies": [{"name": "adb", "required": True, "command": "adb version"}],
    "modular_architecture": True,
    "components": ["intent_analyzer", "masvs_mapper", "formatter", "data_structures"],
    "masvs_controls": [
        "MSTG-PLATFORM-01",
        "MSTG-PLATFORM-02",
        "MSTG-PLATFORM-03",
        "MSTG-PLATFORM-04",
        "MSTG-PLATFORM-05",
        "MSTG-CODE-8",
        "MSTG-CODE-9",
    ],
    "test_types": ["intent_fuzzing", "uri_manipulation", "exported_component_testing"],
}

PLUGIN_CHARACTERISTICS = {
    "name": "Intent Fuzzing Analysis",
    "description": "Full intent fuzzing and URI manipulation testing for MASVS compliance",
    "version": "2.0.0",
    "author": "AODS Framework",
    "category": "DYNAMIC_ANALYSIS",
    "mode": "deep",
    "masvs_controls": [
        "MSTG-PLATFORM-01",
        "MSTG-PLATFORM-02",
        "MSTG-PLATFORM-03",
        "MSTG-PLATFORM-04",
        "MSTG-PLATFORM-05",
        "MSTG-CODE-8",
        "MSTG-CODE-9",
    ],
    "requires_device": True,
    "requires_network": False,
    "invasive": True,
    "execution_time_estimate": 60,
    "dependencies": [{"name": "adb", "required": True, "command": "adb version"}],
    "targets": ["intent_vulnerabilities", "uri_manipulation", "exported_components"],
    "modular": True,
}


class IntentFuzzingAnalysisPlugin:
    """
    Main Intent Fuzzing Analysis plugin using modular architecture.

    Orchestrates full intent fuzzing analysis through specialized
    components with MASVS compliance validation and professional reporting.
    """

    def __init__(self, apk_ctx):
        """Initialize the intent fuzzing analysis plugin."""
        self.apk_ctx = apk_ctx
        self.logger = logging.getLogger(__name__)

    def analyze(self, deep_mode: bool = False) -> Tuple[str, Union[str, Text]]:
        """
        Perform full intent fuzzing analysis.

        Args:
            deep_mode: Whether to run invasive tests with enhanced MASVS mapping

        Returns:
            Tuple[str, Union[str, Text]]: Analysis results
        """
        try:
            # Check if we have the required package name
            if not hasattr(self.apk_ctx, "package_name") or not self.apk_ctx.package_name:
                return self._create_error_result("Package name not available for intent fuzzing")

            # Run the core intent fuzzing analysis
            title, analysis_result = run_intent_fuzzing_analysis(self.apk_ctx)

            # Enhance results with MASVS control mapping if in deep mode
            if deep_mode and isinstance(analysis_result, Text):
                enhanced_result = self._enhance_with_masvs_mapping(analysis_result)
                return (title, enhanced_result)

            return (title, analysis_result)

        except Exception as e:
            self.logger.error(f"Intent fuzzing analysis failed: {e}", exc_info=True)
            return self._create_error_result(f"Error during analysis: {str(e)}")

    def _create_error_result(self, error_message: str) -> Tuple[str, Text]:
        """Create error result for failed analysis."""
        result = Text()
        result.append("❌ Intent Fuzzing Analysis\n", style="red bold")
        result.append(f"{error_message}\n", style="red")
        return ("Intent Fuzzing Analysis", result)

    def _enhance_with_masvs_mapping(self, base_result: Text) -> Text:
        """
        Enhance intent fuzzing results with MASVS control mappings.

        Args:
            base_result: Base analysis results

        Returns:
            Enhanced results with MASVS mappings
        """
        enhanced = Text()
        enhanced.append_text(base_result)

        # Add MASVS control mapping section
        enhanced.append("\n\n📋 MASVS Control Mapping:\n", style="cyan bold")

        masvs_controls = [
            {
                "id": "MSTG-PLATFORM-01",
                "title": "App Permissions",
                "description": "Intent fuzzing validates proper permission enforcement for exported components",
                "relevance": "HIGH",
            },
            {
                "id": "MSTG-PLATFORM-02",
                "title": "Inter-Process Communication",
                "description": "Tests secure IPC implementation and prevents unauthorized access",
                "relevance": "CRITICAL",
            },
            {
                "id": "MSTG-PLATFORM-03",
                "title": "Custom URL Schemes",
                "description": "Validates URL scheme security and prevents malicious deep linking",
                "relevance": "HIGH",
            },
            {
                "id": "MSTG-PLATFORM-04",
                "title": "Sensitive Functionality Exposure",
                "description": "Identifies exposed sensitive functions through intent analysis",
                "relevance": "CRITICAL",
            },
            {
                "id": "MSTG-PLATFORM-05",
                "title": "WebViews",
                "description": "Tests WebView intent handling for security vulnerabilities",
                "relevance": "MEDIUM",
            },
            {
                "id": "MSTG-CODE-8",
                "title": "Code Quality and Build Settings",
                "description": "Validates secure coding practices in intent handling logic",
                "relevance": "MEDIUM",
            },
            {
                "id": "MSTG-CODE-9",
                "title": "Memory Corruption Bugs",
                "description": "Tests for memory corruption through malformed intent data",
                "relevance": "HIGH",
            },
        ]

        for control in masvs_controls:
            relevance_style = (
                "red" if control["relevance"] == "CRITICAL" else "yellow" if control["relevance"] == "HIGH" else "cyan"
            )
            enhanced.append(f"  • {control['id']}: {control['title']}\n", style=f"bold {relevance_style}")
            enhanced.append(f"    {control['description']}\n", style="white")
            enhanced.append(f"    Relevance: {control['relevance']}\n\n", style=relevance_style)

        # Add security recommendations
        enhanced.append("🛡️ Security Recommendations:\n", style="green bold")
        recommendations = [
            "Validate and sanitize all URI schemes and deep links",
            "Implement proper permission checks for exported components",
            "Avoid exposing sensitive functionality through exported components",
            "Use signature-level permissions for sensitive inter-app communication",
            "Implement proper error handling to prevent information disclosure",
        ]

        for i, rec in enumerate(recommendations, 1):
            enhanced.append(f"  {i}. {rec}\n", style="white")

        # Add tool installation guidance
        enhanced.append("\n🛠️ Tool Requirements:\n", style="blue bold")
        enhanced.append("  • Android Debug Bridge (ADB) - Install Android SDK platform-tools\n", style="white")
        enhanced.append("  • Connected Android device or emulator with USB debugging enabled\n", style="white")
        enhanced.append("  • Target application installed on the test device\n", style="white")

        return enhanced


def run_plugin(apk_ctx, deep_mode: bool = False) -> Tuple[str, Union[str, Text]]:
    """
    Execute intent fuzzing analysis plugin.

    Args:
        apk_ctx: APK context object containing package info and analysis data
        deep_mode: Whether to run invasive tests (requires device connection)

    Returns:
        Tuple of (section_title, formatted_results)
    """
    import os

    # Skip in static-only mode - requires device for intent fuzzing
    if os.getenv("AODS_STATIC_ONLY_HARD", "0") == "1" or os.getenv("AODS_STATIC_ONLY", "0") == "1":
        return "Intent Fuzzing Analysis", Text("⏭️ Skipped in static-only mode (requires device)", style="dim")

    plugin = IntentFuzzingAnalysisPlugin(apk_ctx)
    return plugin.analyze(deep_mode)


def run(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """
    Execute intent fuzzing analysis (compatibility wrapper).

    Args:
        apk_ctx: APK context object

    Returns:
        Tuple of (section_title, formatted_results)
    """
    return run_plugin(apk_ctx, deep_mode=False)


# Export for modular compatibility
__all__ = ["run", "run_plugin", "IntentFuzzingAnalysisPlugin", "PLUGIN_METADATA", "PLUGIN_CHARACTERISTICS"]

# Legacy compatibility export
PLUGIN_INFO = PLUGIN_METADATA

# BasePluginV2 interface
try:
    from .v2_plugin import IntentFuzzingAnalysisV2, create_plugin  # noqa: F401

    Plugin = IntentFuzzingAnalysisV2
except ImportError:
    pass
