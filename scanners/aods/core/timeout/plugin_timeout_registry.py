#!/usr/bin/env python3
"""
AODS Plugin-Specific Timeout Registry
=====================================

Registry of plugin-specific timeout values based on complexity analysis.
Integrates with the broader AODS system to provide intelligent timeout management.
"""

import logging
from typing import Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Critical analysis plugins that need higher timeout caps on standard profile.
# These produce foundational results consumed by downstream plugins.
_CRITICAL_ANALYSIS_PLUGINS = frozenset({
    "jadx_static_analysis",
    "semgrep_mastg_analyzer",
    "enhanced_static_analysis",
})


@dataclass
class PluginTimeoutProfile:
    """Profile containing timeout configuration for a specific plugin."""

    plugin_name: str
    base_timeout: int
    complexity_level: str
    operations: list
    reasoning: str
    escalation_multiplier: float = 2.0
    max_escalations: int = 3


class PluginTimeoutRegistry:
    """Registry for plugin-specific timeout configurations."""

    def __init__(self):
        """Initialize the plugin timeout registry with complexity-based profiles."""
        self.logger = logging.getLogger(__name__)
        self._registry = {}
        self._initialize_plugin_profiles()

    def _initialize_plugin_profiles(self):
        """Initialize plugin timeout profiles based on complexity analysis."""

        # High-complexity plugins requiring extended timeouts
        profiles = [
            PluginTimeoutProfile(
                plugin_name="library_vulnerability_scanner",
                base_timeout=300,  # 5 minutes
                complexity_level="high",
                operations=["dependency analysis", "CVE matching", "vulnerability correlation"],
                reasoning="Extensive dependency tree analysis and CVE database queries",
            ),
            PluginTimeoutProfile(
                plugin_name="native_binary_analysis",
                base_timeout=420,  # 7 minutes
                complexity_level="very_high",
                operations=["binary disassembly", "native library scanning", "symbol analysis"],
                reasoning="Complex binary analysis requiring disassembly and deep scanning",
            ),
            PluginTimeoutProfile(
                plugin_name="advanced_ssl_tls_analyzer",
                base_timeout=240,  # 4 minutes
                complexity_level="high",
                operations=["certificate validation", "SSL/TLS configuration analysis", "crypto analysis"],
                reasoning="Full SSL/TLS configuration and certificate chain analysis",
            ),
            PluginTimeoutProfile(
                plugin_name="mobile_serialization_security",
                base_timeout=180,  # 3 minutes
                complexity_level="medium",
                operations=["serialization pattern detection", "data flow analysis"],
                reasoning="Deep data flow analysis for serialization vulnerabilities",
            ),
            PluginTimeoutProfile(
                plugin_name="insecure_data_storage",
                base_timeout=210,  # 3.5 minutes
                complexity_level="medium",
                operations=["file system analysis", "database scanning", "preference analysis"],
                reasoning="Thorough file system and database analysis",
            ),
            PluginTimeoutProfile(
                plugin_name="network_communication_tests",
                base_timeout=180,  # 3 minutes
                complexity_level="medium",
                operations=["network traffic analysis", "endpoint discovery", "protocol analysis"],
                reasoning="Network analysis and endpoint discovery",
            ),
            # Note: *_standardized plugins removed in Track 9 cleanup (2026-01-28)
        ]

        # Register profiles
        for profile in profiles:
            self._registry[profile.plugin_name] = profile
            self.logger.debug(f"Registered timeout profile for {profile.plugin_name}: {profile.base_timeout}s")

    def get_timeout_for_plugin(
        self, plugin_name: str, default_timeout: int = 294, scan_profile: Optional[str] = None
    ) -> int:
        """Get timeout value for a specific plugin with optional profile optimization."""

        # Check for exact match
        if plugin_name in self._registry:
            profile = self._registry[plugin_name]
            base_timeout = profile.base_timeout
            self.logger.debug(f"Using plugin-specific timeout for {plugin_name}: {base_timeout}s")
        else:
            # Check for partial matches (for plugins with dynamic names)
            base_timeout = default_timeout
            for registered_name, profile in self._registry.items():
                if registered_name in plugin_name or plugin_name in registered_name:
                    base_timeout = profile.base_timeout
                    self.logger.debug(
                        f"Using partial-match timeout for {plugin_name} (matched {registered_name}): {base_timeout}s"
                    )
                    break
            else:
                self.logger.debug(f"Using default timeout for {plugin_name}: {default_timeout}s")

        # Apply scan profile optimization if provided
        if scan_profile:
            optimized_timeout = self.apply_profile_timeout_optimization(base_timeout, scan_profile, plugin_name)
            return optimized_timeout

        return base_timeout

    def apply_profile_timeout_optimization(self, base_timeout: int, scan_profile: str, plugin_name: str) -> int:
        """
        Apply scan profile-specific timeout optimization.

        Args:
            base_timeout: Base timeout from plugin registry
            scan_profile: Scan profile name (lightning, fast, standard, deep)
            plugin_name: Plugin name for logging

        Returns:
            Optimized timeout in seconds
        """
        profile_lower = scan_profile.lower()

        # Lightning profile: Aggressive timeout reduction for 60s total execution target
        if profile_lower == "lightning":
            # Cap at 60s max, use 50% of base timeout or 30s minimum
            optimized_timeout = min(60, max(30, int(base_timeout * 0.5)))
            self.logger.debug(
                f"Lightning profile optimization for '{plugin_name}': {base_timeout}s -> {optimized_timeout}s"
            )
            return optimized_timeout

        # Fast profile: Moderate timeout reduction for 2-3 minute target
        elif profile_lower == "fast":
            # Cap at 120s max, use 70% of base timeout
            optimized_timeout = min(120, max(60, int(base_timeout * 0.7)))
            self.logger.debug(f"Fast profile optimization for '{plugin_name}': {base_timeout}s -> {optimized_timeout}s")
            return optimized_timeout

        # Standard profile: Light timeout reduction for 5-8 minute target
        elif profile_lower == "standard":
            if plugin_name in _CRITICAL_ANALYSIS_PLUGINS:
                # Critical plugins get a higher cap (240s) to avoid losing findings
                optimized_timeout = min(240, max(120, int(base_timeout * 0.85)))
            else:
                # Cap at 180s max, use 85% of base timeout
                optimized_timeout = min(180, max(90, int(base_timeout * 0.85)))
            self.logger.debug(
                f"Standard profile optimization for '{plugin_name}': {base_timeout}s -> {optimized_timeout}s"
            )
            return optimized_timeout

        # Deep profile: Use full timeout
        else:
            return base_timeout

    def get_plugin_profile(self, plugin_name: str) -> Optional[PluginTimeoutProfile]:
        """Get complete timeout profile for a plugin."""
        return self._registry.get(plugin_name)

    def register_plugin_timeout(
        self, plugin_name: str, timeout: int, complexity_level: str = "medium", reasoning: str = "Custom timeout"
    ):
        """Register a custom timeout for a plugin."""
        profile = PluginTimeoutProfile(
            plugin_name=plugin_name,
            base_timeout=timeout,
            complexity_level=complexity_level,
            operations=["custom operations"],
            reasoning=reasoning,
        )
        self._registry[plugin_name] = profile
        self.logger.info(f"Registered custom timeout for {plugin_name}: {timeout}s")

    def get_all_registered_plugins(self) -> Dict[str, PluginTimeoutProfile]:
        """Get all registered plugin timeout profiles."""
        return self._registry.copy()

    def get_optimization_summary(self) -> Dict[str, any]:
        """Get optimization summary for monitoring and reporting."""
        total_plugins = len(self._registry)
        complexity_breakdown = {}

        for profile in self._registry.values():
            complexity_breakdown[profile.complexity_level] = complexity_breakdown.get(profile.complexity_level, 0) + 1

        avg_timeout = (
            sum(profile.base_timeout for profile in self._registry.values()) / total_plugins if total_plugins > 0 else 0
        )

        return {
            "total_optimized_plugins": total_plugins,
            "complexity_breakdown": complexity_breakdown,
            "average_optimized_timeout": int(avg_timeout),
            "timeout_range": {
                "min": min(profile.base_timeout for profile in self._registry.values()) if total_plugins > 0 else 0,
                "max": max(profile.base_timeout for profile in self._registry.values()) if total_plugins > 0 else 0,
            },
            "optimization_date": "2025-08-27",
        }


# Global registry instance
_global_registry = None


def get_plugin_timeout_registry() -> PluginTimeoutRegistry:
    """Get global plugin timeout registry instance."""
    global _global_registry
    if _global_registry is None:
        _global_registry = PluginTimeoutRegistry()
    return _global_registry


def get_timeout_for_plugin(plugin_name: str, default_timeout: int = 294, scan_profile: Optional[str] = None) -> int:
    """Convenience function to get timeout for a plugin with optional profile optimization."""
    registry = get_plugin_timeout_registry()
    return registry.get_timeout_for_plugin(plugin_name, default_timeout, scan_profile)


# Export public interface
__all__ = ["PluginTimeoutProfile", "PluginTimeoutRegistry", "get_plugin_timeout_registry", "get_timeout_for_plugin"]
