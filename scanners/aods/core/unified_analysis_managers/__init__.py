#!/usr/bin/env python3
"""
Unified Analysis Managers Framework - Public API

Frida-first analysis management framework for AODS.

Components:
- frida_manager.py: Consolidated Frida management with resource coordination
- base_manager.py: Base class for analysis managers

Usage:
    from core.unified_analysis_managers import (
        get_frida_manager, FridaManager
    )

    # Modern Frida manager (RECOMMENDED)
    frida_mgr = get_frida_manager(package_name, strategy="auto")

    # Legacy wrapper
    frida_mgr = FridaManager(package_name)
"""

import logging
from typing import Any, Dict  # noqa: F401

from .base_manager import BaseAnalysisManager, AnalysisManagerConfig  # noqa: F401
from .frida_manager import UnifiedFridaManager, FridaStrategy  # noqa: F401

logger = logging.getLogger(__name__)


# ============================================================================
# Frida Manager Factory
# ============================================================================

_frida_managers: Dict[str, UnifiedFridaManager] = {}


def get_frida_manager(package_name: str = "", strategy: str = "auto") -> UnifiedFridaManager:
    """Get optimized Frida manager for package.

    Args:
        package_name: Package name or APKContext object
        strategy: Strategy selection ("auto", "standard", "flutter_enhanced", "static_fallback")

    Returns:
        Configured UnifiedFridaManager instance
    """
    # Handle APKContext objects passed instead of strings
    if hasattr(package_name, "package_name"):
        actual_package_name = package_name.package_name
    else:
        actual_package_name = str(package_name)

    manager_id = f"frida_{actual_package_name}_{strategy}"

    if manager_id not in _frida_managers:
        config = AnalysisManagerConfig(
            package_name=package_name,
            strategy=strategy,
            enable_monitoring=True,
        )
        _frida_managers[manager_id] = UnifiedFridaManager(config)

    return _frida_managers[manager_id]


# ============================================================================
# Legacy FridaManager Compatibility Wrapper
# ============================================================================


class FridaManager:
    """
    Legacy FridaManager compatibility wrapper.

    Provides backward compatibility for existing code while routing to the
    unified framework.
    """

    def __init__(self, package_name: str = None):
        """Initialize legacy-compatible Frida manager."""
        self.package_name = package_name or ""
        self._unified_manager = get_frida_manager(self.package_name, strategy="auto")

        # Legacy attribute compatibility
        self.device = None
        self.session = None
        self.scripts = {}
        self.analysis_results = {}
        self.is_available = self._unified_manager.check_connection()
        self.connection_timeout = 30
        self.analysis_duration = 60

    def _check_frida_availability(self):
        """Legacy method - delegate to unified manager."""
        return self._unified_manager.check_connection()

    def check_frida_availability(self):
        """Legacy method - delegate to unified manager."""
        available = self._unified_manager.check_connection()
        return available, "Available" if available else "Not available"

    def is_frida_available(self):
        """Legacy method - delegate to unified manager."""
        return self._unified_manager.check_connection()

    def is_app_running(self):
        """Legacy method - delegate to unified manager."""
        return True

    def analyze_flutter_app(self, apk_path: str, package_name: str):
        """Legacy method - delegate to unified manager."""
        return self._unified_manager.execute_analysis({"apk_path": apk_path, "analysis_type": "flutter"})

    def run_comprehensive_analysis(self, duration: int = 60):
        """Legacy method - delegate to unified manager."""
        return self._unified_manager.execute_analysis({"duration": duration, "analysis_type": "full"})


__all__ = [
    "get_frida_manager",
    "FridaManager",
    "UnifiedFridaManager",
    "FridaStrategy",
    "BaseAnalysisManager",
    "AnalysisManagerConfig",
]
