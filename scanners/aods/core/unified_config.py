#!/usr/bin/env python3
"""
Unified Configuration Facade for AODS Canonical Architecture
===========================================================

This facade provides the canonical interface for AODS configuration management,
delegating to the full unified configuration architecture while providing
a clean, simple API for the AODS_CANONICAL execution path.

This module serves as the bridge between the canonical execution path and the
existing configuration system in core/shared_infrastructure/configuration/
"""

import logging
from dataclasses import dataclass
from enum import Enum

# Import from the configuration system
from core.shared_infrastructure.configuration import (
    ConfigurationEnvironment,
    ExecutionConfig as BaseExecutionConfig,
    PluginConfig as BasePluginConfig,
    ReportingConfig as BaseReportingConfig,
    AnalysisConfig as BaseAnalysisConfig,
    get_unified_config_manager,
)

logger = logging.getLogger(__name__)


class ScanProfile(Enum):
    """Scan profile enumeration for canonical configuration."""

    LIGHTNING = "lightning"
    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"


@dataclass(frozen=True)
class UnifiedConfig:
    """
    Unified configuration object for canonical AODS execution.

    This immutable configuration object provides a clean interface for the
    canonical execution path while leveraging the configuration
    system underneath.
    """

    execution_config: BaseExecutionConfig
    plugin_config: BasePluginConfig
    reporting_config: BaseReportingConfig
    analysis_config: BaseAnalysisConfig
    scan_profile: ScanProfile

    @classmethod
    def from_profile(cls, profile: ScanProfile) -> "UnifiedConfig":
        """Create unified configuration from scan profile."""
        config_manager = get_unified_config_manager()

        # Map scan profiles to configuration environments
        profile_mapping = {
            ScanProfile.LIGHTNING: ConfigurationEnvironment.TESTING,
            ScanProfile.FAST: ConfigurationEnvironment.DEVELOPMENT,
            ScanProfile.STANDARD: ConfigurationEnvironment.PRODUCTION,
            ScanProfile.DEEP: ConfigurationEnvironment.PRODUCTION,
        }

        env = profile_mapping.get(profile, ConfigurationEnvironment.PRODUCTION)
        base_config = config_manager.get_configuration(env)

        # Extract specific configurations
        execution_config = base_config.execution
        plugin_config = base_config.plugin
        reporting_config = base_config.reporting
        analysis_config = base_config.analysis

        # Apply profile-specific optimizations
        from dataclasses import replace

        if profile == ScanProfile.LIGHTNING:
            # Lightning: Minimal plugins, fast execution
            plugin_config = replace(plugin_config, max_concurrent_plugins=2, default_timeout_seconds=30)
            execution_config = replace(execution_config, max_workers=2, default_timeout_seconds=60)
        elif profile == ScanProfile.FAST:
            # Fast: Reduced plugin set, optimized execution
            plugin_config = replace(plugin_config, max_concurrent_plugins=4, default_timeout_seconds=60)
            execution_config = replace(execution_config, max_workers=4, default_timeout_seconds=300)
        elif profile == ScanProfile.DEEP:
            # Deep: All plugins, analysis
            plugin_config = replace(plugin_config, max_concurrent_plugins=8, default_timeout_seconds=300)
            execution_config = replace(execution_config, max_workers=8, default_timeout_seconds=1800)

        return cls(
            execution_config=execution_config,
            plugin_config=plugin_config,
            reporting_config=reporting_config,
            analysis_config=analysis_config,
            scan_profile=profile,
        )


class ConfigurationFactory:
    """
    Factory for creating unified configuration objects.

    This factory provides the canonical interface for configuration creation
    while leveraging the configuration management system.
    """

    @staticmethod
    def create_default_config() -> UnifiedConfig:
        """Create default unified configuration."""
        return UnifiedConfig.from_profile(ScanProfile.STANDARD)

    @staticmethod
    def create_from_profile(profile: ScanProfile) -> UnifiedConfig:
        """Create unified configuration from scan profile."""
        return UnifiedConfig.from_profile(profile)

    @staticmethod
    def create_from_environment(environment: str = "production") -> UnifiedConfig:
        """Create unified configuration from environment."""
        env_mapping = {
            "development": ScanProfile.FAST,
            "testing": ScanProfile.LIGHTNING,
            "production": ScanProfile.STANDARD,
            "deep": ScanProfile.DEEP,
        }

        profile = env_mapping.get(environment.lower(), ScanProfile.STANDARD)
        return UnifiedConfig.from_profile(profile)


# Convenience functions for canonical execution path


def create_unified_config(profile: ScanProfile = ScanProfile.STANDARD) -> UnifiedConfig:
    """Create unified configuration with specified profile."""
    return ConfigurationFactory.create_from_profile(profile)


def get_default_config() -> UnifiedConfig:
    """Get default unified configuration."""
    return ConfigurationFactory.create_default_config()


# Export the canonical interface
__all__ = ["UnifiedConfig", "ScanProfile", "ConfigurationFactory", "create_unified_config", "get_default_config"]
