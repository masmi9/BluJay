#!/usr/bin/env python3
"""
Semgrep MASTG Analyzer Plugin

Provides OWASP MASTG-aligned security analysis using Semgrep rules.
Runs Semgrep on JADX-decompiled sources and converts findings to
standardized PluginFinding format with proper MSTG→MASVS mapping.

Features:
- Extracts MSTG IDs from Semgrep rule metadata
- Maps MSTG test IDs to MASVS control IDs using taxonomy.yaml
- Graceful degradation when Semgrep CLI or rules are unavailable
- Integrates with AODS normalization and deduplication pipelines
"""

from .v2_plugin import SemgrepMastgAnalyzerV2, create_plugin

# Plugin metadata for discovery
PLUGIN_METADATA = {
    "name": "Semgrep MASTG Analyzer",
    "description": "OWASP MASTG-aligned security analysis using Semgrep rules",
    "version": "1.0.0",
    "author": "AODS Development Team",
    "category": "STATIC_ANALYSIS",
    "priority": "NORMAL",
    "timeout": 300,
    "mode": "static",
    "requires_device": False,
    "requires_network": False,
    "invasive": False,
    "execution_time_estimate": 60,
    "dependencies": ["semgrep"],
    "security_controls": [
        "MASVS-STORAGE",
        "MASVS-CRYPTO",
        "MASVS-AUTH",
        "MASVS-NETWORK",
        "MASVS-PLATFORM",
        "MASVS-CODE",
        "MASVS-RESILIENCE",
    ],
    "owasp_categories": ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10"],
}


def run_plugin(apk_ctx):
    """
    Plugin entry point for legacy discovery.

    Args:
        apk_ctx: APK context with file path and package information

    Returns:
        Tuple of (analysis_type, results)
    """
    plugin = SemgrepMastgAnalyzerV2()
    result = plugin.execute(apk_ctx)

    # Format results for legacy compatibility
    findings_count = len(result.findings) if result.findings else 0

    return "Semgrep MASTG Analysis", {
        "plugin": "semgrep_mastg_analyzer",
        "status": result.status.value if hasattr(result.status, "value") else str(result.status),
        "findings_count": findings_count,
        "findings": [f.__dict__ if hasattr(f, "__dict__") else f for f in (result.findings or [])],
        "metadata": result.metadata or {},
        "execution_time": result.execution_time,
    }


def run(apk_ctx):
    """Alias for run_plugin."""
    return run_plugin(apk_ctx)


# BasePluginV2 interface
Plugin = SemgrepMastgAnalyzerV2

__all__ = ["SemgrepMastgAnalyzerV2", "create_plugin", "run_plugin", "run", "PLUGIN_METADATA", "Plugin"]
