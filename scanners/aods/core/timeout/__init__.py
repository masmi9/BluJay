"""
Timeout Management Package
=========================
🎯 SURGICAL FIX: Clean re-export from canonical source
"""

# Import from the canonical unified timeout manager
from .unified_timeout_manager import UnifiedTimeoutManager, TimeoutType, TimeoutStrategy, TimeoutContext

# Import from plugin timeout registry
from .plugin_timeout_registry import get_timeout_for_plugin

# SURGICAL FIX: Create alias for missing function name
get_optimized_timeout_for_plugin = get_timeout_for_plugin

# Clean export list - single source of truth
__all__ = [
    "UnifiedTimeoutManager",
    "TimeoutType",
    "TimeoutStrategy",
    "TimeoutContext",
    "get_optimized_timeout_for_plugin",
]
