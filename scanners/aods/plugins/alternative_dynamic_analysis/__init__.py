"""
Alternative Dynamic Analysis Plugin

Provides dynamic analysis capabilities without Frida dependency.

This plugin now supports both legacy and BasePluginV2 interfaces:
- Legacy: run_plugin(), run() functions
- BasePluginV2: AlternativeDynamicAnalysisV2 class
"""

from .main import run_plugin, run
from .v2_plugin import AlternativeDynamicAnalysisV2, create_plugin

# BasePluginV2 interface (primary)
Plugin = AlternativeDynamicAnalysisV2

__all__ = ["run_plugin", "run", "AlternativeDynamicAnalysisV2", "create_plugin", "Plugin"]
