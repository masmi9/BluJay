#!/usr/bin/env python3
"""
Shared Execution Components

Zero-duplication core components used by all execution strategies.
"""

from .plugin_executor import PluginExecutor

# Use unified configuration manager (Phase 5 migration)
from core.shared_infrastructure.configuration.unified_config_architecture import UnifiedConfigurationManager as ConfigurationManager  # type: ignore  # noqa: E501

__all__ = [
    "PluginExecutor",
    "ConfigurationManager",
]
