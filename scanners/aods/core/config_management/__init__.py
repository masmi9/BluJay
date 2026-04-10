#!/usr/bin/env python3
"""
Configuration Management Module for AODS Plugin Modularization

Components:
- PatternLoader: Loads and validates security patterns from YAML files
"""

from .pattern_loader import PatternLoader, PatternLoadError


# MIGRATED: ConfigCache replaced with unified infrastructure
def get_config_cache():
    """Get unified cache manager instance for backward compatibility."""
    from core.shared_infrastructure.performance.caching_consolidation import get_unified_cache_manager

    return get_unified_cache_manager()


# Legacy alias for compatibility
ConfigCache = get_config_cache

__all__ = [
    "PatternLoader",
    "PatternLoadError",
    "ConfigCache",
]
