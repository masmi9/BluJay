#!/usr/bin/env python3
"""
Emulator Detection Analyzer Plugin (MASVS-RESILIENCE-2)

Detects emulator/root detection patterns as resilience features.
"""

import logging
from typing import Tuple, Union

from rich.text import Text
from core.apk_ctx import APKContext

logger = logging.getLogger(__name__)

PLUGIN_METADATA = {
    "name": "Emulator Detection Analyzer",
    "description": "Detects emulator/root detection patterns as resilience features",
    "version": "2.1.0",
    "author": "AODS Team",
    "category": "RESILIENCE",
    "priority": "MEDIUM",
    "timeout": 120,
    "mode": "safe",
    "requires_device": False,
    "requires_network": False,
    "invasive": False,
    "execution_time_estimate": 30,
    "dependencies": [],
    "security_controls": ["MASVS-RESILIENCE-2"],
    "owasp_categories": ["M8"],
}


def run(apk_ctx: APKContext) -> Tuple[str, Union[str, Text]]:
    """Framework-compatible run function - delegates to v2 plugin."""
    try:
        from .v2_plugin import EmulatorDetectionAnalyzerV2

        plugin = EmulatorDetectionAnalyzerV2()
        result = plugin.execute(apk_ctx)

        output = Text()
        output.append("Emulator Detection Analysis Results\n", style="bold blue")
        output.append("=" * 40 + "\n", style="blue")
        output.append(f"Status: {result.status.value}\n", style="green")
        output.append(f"Findings: {len(result.findings)}\n", style="yellow")

        for finding in result.findings:
            output.append(f"\n[{finding.severity.upper()}] {finding.title}\n", style="bold")
            if finding.file_path:
                output.append(f"  File: {finding.file_path}\n")

        return PLUGIN_METADATA["name"], output

    except Exception as e:
        error_text = Text()
        error_text.append(f"Emulator Detection Analysis Error: {str(e)}", style="red")
        return PLUGIN_METADATA["name"], error_text


def run_plugin(apk_ctx: APKContext) -> Tuple[str, Union[str, Text]]:
    """Plugin interface function for plugin manager."""
    return run(apk_ctx)


# BasePluginV2 interface
try:
    from .v2_plugin import EmulatorDetectionAnalyzerV2, create_plugin  # noqa: F401

    Plugin = EmulatorDetectionAnalyzerV2
except ImportError:
    pass
