#!/usr/bin/env python3
"""
Unified Configuration Architecture - Consolidation of All AODS Configurations

This module consolidates all AODS configuration systems into a single, coherent architecture:
- ExecutionConfig (execution and plugin management)
- PluginConfig (plugin system configuration)
- ReportingConfig (reporting and output configuration)
- AnalysisConfig (analysis framework configuration)
- SecurityConfig (security and compliance settings)
- PerformanceConfig (performance and resource management)

CONSOLIDATION ACHIEVEMENTS:
- Single point of configuration access across all AODS components
- Type-safe configuration objects with validation
- Environment-specific configuration inheritance
- Hot-reload capabilities for development/production
- Immutable configuration objects for thread safety
- Validation and schema enforcement
"""

import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
from pathlib import Path
import yaml

# MIGRATED: Import unified caching infrastructure
from core.shared_infrastructure.performance.caching_consolidation import get_unified_cache_manager, CacheType
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class ConfigurationScope(Enum):
    """Configuration scope levels."""

    GLOBAL = "global"  # System-wide configuration
    EXECUTION = "execution"  # Execution framework configuration
    PLUGIN = "plugin"  # Plugin system configuration
    REPORTING = "reporting"  # Reporting and output configuration
    ANALYSIS = "analysis"  # Analysis framework configuration
    SECURITY = "security"  # Security and compliance configuration
    PERFORMANCE = "performance"  # Performance and resource configuration


class ConfigurationEnvironment(Enum):
    """Configuration environment types."""

    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"
    DEBUG = "debug"


class ConfigurationPriority(Enum):
    """Configuration priority levels for merging."""

    DEFAULT = 1
    FILE = 2
    ENVIRONMENT = 3
    COMMAND_LINE = 4
    RUNTIME = 5


# ============================================================================
# EXECUTION CONFIGURATION
# ============================================================================


@dataclass(frozen=True)
class ExecutionConfig:
    """Unified execution framework configuration."""

    # Core execution settings
    canonical_mode: bool = False
    max_concurrent_processes: int = 4
    execution_timeout_seconds: int = 3600
    enable_parallel_execution: bool = True
    enable_resource_monitoring: bool = True

    # Analysis modes
    scan_mode: str = "full"  # safe, balanced, deep, full
    vulnerable_app_mode: bool = False
    lightning_mode: bool = False

    # Fallback and recovery
    enable_fallback_strategies: bool = True
    max_retries: int = 3
    retry_delay_seconds: int = 5

    # Execution environments
    enable_sandboxing: bool = True
    isolation_level: str = "standard"  # minimal, standard, strict

    # Workspace and output
    workspace_dir: Optional[str] = None
    temp_dir: Optional[str] = None
    cleanup_temp_files: bool = True

    # Backward-compatibility aliases for attributes used by execution strategies
    def __getattr__(self, name: str):
        _aliases = {
            "max_workers": "max_concurrent_processes",
            "timeout_seconds": "execution_timeout_seconds",
        }
        if name in _aliases:
            return getattr(self, _aliases[name])
        _defaults = {
            "parallel_threshold_plugins": 3,
            "memory_limit_gb": 4.0,
            "enable_performance_monitoring": self.enable_resource_monitoring,
        }
        if name in _defaults:
            return _defaults[name]
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")


# ============================================================================
# PLUGIN CONFIGURATION
# ============================================================================


@dataclass(frozen=True)
class PluginConfig:
    """Unified plugin system configuration."""

    # Plugin discovery and loading
    plugin_directories: List[str] = field(default_factory=lambda: ["plugins/"])
    plugin_patterns: List[str] = field(default_factory=lambda: ["*.py", "__init__.py"])
    enable_plugin_registry: bool = True
    enable_plugin_validation: bool = True

    # Plugin execution
    default_timeout_seconds: int = 300
    max_concurrent_plugins: int = 10
    enable_plugin_isolation: bool = True
    plugin_memory_limit_mb: int = 512

    # Plugin priority and scheduling
    enable_priority_scheduling: bool = True
    enable_adaptive_timeout: bool = True
    enable_resource_management: bool = True

    # Plugin compatibility
    enable_legacy_support: bool = True
    enable_deprecation_warnings: bool = True


# ============================================================================
# REPORTING CONFIGURATION
# ============================================================================


@dataclass(frozen=True)
class ReportingConfig:
    """Unified reporting and output configuration."""

    # Output formats and destinations
    output_formats: List[str] = field(default_factory=lambda: ["json", "html"])
    output_directory: Optional[str] = None
    enable_console_output: bool = True
    enable_file_output: bool = True

    # Report content and structure
    include_metadata: bool = True
    include_evidence: bool = True
    include_recommendations: bool = True
    include_executive_summary: bool = True

    # Report enhancement
    enable_vulnerability_enhancement: bool = True
    enable_confidence_scoring: bool = True
    enable_risk_assessment: bool = True
    enable_compliance_mapping: bool = True

    # Report formatting
    max_report_size_mb: int = 100
    enable_compression: bool = True
    date_format: str = "%Y-%m-%d %H:%M:%S UTC"

    # Privacy and security
    # PERMANENT FIX: Disable redaction to reveal actual secret values per user request
    redact_sensitive_data: bool = False
    include_source_paths: bool = True


# ============================================================================
# ANALYSIS CONFIGURATION
# ============================================================================


@dataclass(frozen=True)
class AnalysisConfig:
    """Unified analysis framework configuration."""

    # Analysis scope and depth
    enable_static_analysis: bool = True
    enable_dynamic_analysis: bool = True
    enable_hybrid_analysis: bool = True
    analysis_depth: str = "full"  # surface, standard, deep, full

    # Decompilation settings
    enable_jadx_decompilation: bool = True
    decompilation_timeout_seconds: int = 600
    decompilation_memory_limit_mb: int = 2048
    enable_decompilation_caching: bool = True

    # Analysis frameworks
    enable_frida_analysis: bool = True
    # Drozer removed from AODS; keep flag for legacy compatibility (disabled)
    enable_drozer_analysis: bool = False
    enable_objection_analysis: bool = True

    # Analysis optimization
    enable_intelligent_filtering: bool = True
    enable_duplicate_detection: bool = True
    enable_false_positive_reduction: bool = True

    # Analysis scope limits
    max_files_per_analysis: Optional[int] = None
    max_analysis_time_seconds: Optional[int] = None
    skip_framework_files: bool = False


# ============================================================================
# SECURITY CONFIGURATION
# ============================================================================


@dataclass(frozen=True)
class SecurityConfig:
    """Unified security and compliance configuration."""

    # Compliance frameworks
    enable_nist_compliance: bool = True
    enable_owasp_compliance: bool = True
    enable_masvs_compliance: bool = True
    compliance_level: str = "standard"  # basic, standard, strict

    # Security validation
    enable_certificate_validation: bool = True
    enable_signature_verification: bool = True
    enable_permission_analysis: bool = True

    # Threat intelligence
    enable_threat_intelligence: bool = True
    threat_intelligence_sources: List[str] = field(default_factory=list)

    # Security constraints
    max_privilege_level: str = "standard"
    enable_secure_defaults: bool = True
    enforce_security_policies: bool = True


# ============================================================================
# PERFORMANCE CONFIGURATION
# ============================================================================


@dataclass(frozen=True)
class PerformanceConfig:
    """Unified performance and resource configuration."""

    # Resource limits
    max_memory_usage_mb: int = 4096
    max_cpu_usage_percent: int = 80
    max_disk_usage_gb: int = 10

    # Performance optimization
    enable_caching: bool = True
    cache_size_mb: int = 1024
    enable_parallel_processing: bool = True
    enable_lazy_loading: bool = True

    # Monitoring and metrics
    enable_performance_monitoring: bool = True
    enable_resource_tracking: bool = True
    performance_sampling_rate: float = 0.1

    # Optimization strategies
    enable_adaptive_optimization: bool = True
    enable_predictive_scaling: bool = False
    optimization_strategy: str = "balanced"  # speed, balanced, memory


# ============================================================================
# UNIFIED CONFIGURATION MANAGER
# ============================================================================


@dataclass(frozen=True)
class UnifiedAODSConfig:
    """Complete unified AODS configuration."""

    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    plugin: PluginConfig = field(default_factory=PluginConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)

    # Metadata
    version: str = "1.0.0"
    environment: ConfigurationEnvironment = ConfigurationEnvironment.DEVELOPMENT
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    config_source: str = "default"


class UnifiedConfigurationManager:
    """
    Unified configuration manager for all AODS configuration needs.

    This manager consolidates all configuration systems and provides:
    - Single point of configuration access
    - Environment-specific configuration loading
    - Configuration validation and type safety
    - Hot-reload capabilities
    - Configuration inheritance and merging
    """

    def __init__(self, config_directory: Optional[Path] = None):
        """Initialize unified configuration manager."""
        self.config_directory = config_directory or Path("config")
        self.logger = logging.getLogger(__name__)

        # MIGRATED: Use unified cache manager; store environment-config objects under namespaced keys
        self.cache_manager = get_unified_cache_manager()
        self._cache_namespace = "unified_config_architecture"
        self._config_cache: Dict[ConfigurationEnvironment, UnifiedAODSConfig] = {}
        self._last_loaded: Dict[ConfigurationEnvironment, datetime] = {}

        # Configuration sources (in priority order)
        self._config_sources = [
            # Note: default config is applied before iterating sources; do not include here to avoid
            # calling with an unexpected 'environment' argument
            self._load_file_config,
            self._load_environment_config,
            self._load_runtime_overrides,
        ]

        self.logger.info("✅ UnifiedConfigurationManager initialized")

    def get_configuration(self, environment: Optional[ConfigurationEnvironment] = None) -> UnifiedAODSConfig:
        """
        Get unified configuration for specified environment.

        Args:
            environment: Configuration environment (defaults to auto-detection)

        Returns:
            Complete unified AODS configuration
        """
        if environment is None:
            environment = self._detect_environment()

        # Check cache and reload if needed
        if self._should_reload_config(environment):
            self._load_configuration(environment)

        # Prefer local in-memory cache first, then unified cache fallback
        config = self._config_cache.get(environment)
        if config is None:
            try:
                cached = self.cache_manager.retrieve(
                    f"{self._cache_namespace}:{environment.value}", CacheType.CONFIGURATION
                )
                if isinstance(cached, UnifiedAODSConfig):
                    config = cached
            except Exception:
                pass
        return config or self._get_default_config()

    def _detect_environment(self) -> ConfigurationEnvironment:
        """Detect current environment from various sources."""
        # Check environment variable first
        env_name = os.getenv("AODS_ENVIRONMENT", "").lower()
        if env_name:
            try:
                return ConfigurationEnvironment(env_name)
            except ValueError:
                pass

        # Check for development indicators
        if os.getenv("AODS_DEBUG") == "1" or os.getenv("DEBUG") == "1":
            return ConfigurationEnvironment.DEBUG

        # Check for testing indicators
        if "test" in sys.argv[0].lower() or os.getenv("TESTING") == "1":
            return ConfigurationEnvironment.TESTING

        # Default to development
        return ConfigurationEnvironment.DEVELOPMENT

    def _should_reload_config(self, environment: ConfigurationEnvironment) -> bool:
        """Check if configuration should be reloaded."""
        if environment not in self._config_cache:
            return True

        # Check file modification times
        config_file = self.config_directory / f"aods_{environment.value}.yaml"
        if config_file.exists():
            file_mtime = datetime.fromtimestamp(config_file.stat().st_mtime)
            cache_time = self._last_loaded.get(environment, datetime.min)
            return file_mtime > cache_time

        return False

    def _load_configuration(self, environment: ConfigurationEnvironment) -> None:
        """Load configuration from all sources with proper precedence."""
        config = self._get_default_config()

        # Apply configuration sources in priority order
        for source_loader in self._config_sources:
            try:
                source_config = source_loader(environment)
                if source_config:
                    config = self._merge_configurations(config, source_config)
            except Exception as e:
                self.logger.warning(f"Failed to load config from source: {e}")

        # Cache the merged configuration (memory + unified)
        self._config_cache[environment] = config
        try:
            self.cache_manager.store(
                f"{self._cache_namespace}:{environment.value}",
                config,
                CacheType.CONFIGURATION,
                ttl_hours=2,
                tags=[self._cache_namespace],
            )
        except Exception:
            pass
        self._last_loaded[environment] = datetime.now(timezone.utc)

        self.logger.info(f"✅ Configuration loaded for environment: {environment.value}")

    def _get_default_config(self) -> UnifiedAODSConfig:
        """Get default configuration with sensible defaults."""
        return UnifiedAODSConfig()

    def _load_file_config(self, environment: ConfigurationEnvironment) -> Optional[UnifiedAODSConfig]:
        """Load configuration from YAML file."""
        config_file = self.config_directory / f"aods_{environment.value}.yaml"

        if not config_file.exists():
            return None

        try:
            with open(config_file, "r") as f:
                config_data = yaml.safe_load(f)

            return self._parse_config_data(config_data, f"file:{config_file}")
        except Exception as e:
            self.logger.error(f"Failed to load config from {config_file}: {e}")
            return None

    def _load_environment_config(self, environment: ConfigurationEnvironment) -> Optional[UnifiedAODSConfig]:
        """Load configuration overrides from environment variables."""
        env_overrides = {}

        # Look for AODS_* environment variables
        for key, value in os.environ.items():
            if key.startswith("AODS_"):
                config_key = key[5:].lower().replace("_", ".")
                env_overrides[config_key] = self._parse_env_value(value)

        if not env_overrides:
            return None

        return self._parse_config_data({"environment_overrides": env_overrides}, "environment")

    def _load_runtime_overrides(self, environment: ConfigurationEnvironment) -> Optional[UnifiedAODSConfig]:
        """Load runtime configuration overrides."""
        # This would be populated by runtime configuration changes
        return None

    def _parse_env_value(self, value: str) -> Any:
        """Parse environment variable value to appropriate type."""
        # Boolean values
        if value.lower() in ("true", "1", "yes", "on"):
            return True
        elif value.lower() in ("false", "0", "no", "off"):
            return False

        # Numeric values
        try:
            if "." in value:
                return float(value)
            else:
                return int(value)
        except ValueError:
            pass

        # String value
        return value

    def _parse_config_data(self, config_data: Dict[str, Any], source: str) -> UnifiedAODSConfig:
        """Parse configuration data into UnifiedAODSConfig object."""
        # Extract configuration sections
        execution_data = config_data.get("execution", {})
        plugin_data = config_data.get("plugin", {})
        reporting_data = config_data.get("reporting", {})
        analysis_data = config_data.get("analysis", {})
        security_data = config_data.get("security", {})
        performance_data = config_data.get("performance", {})

        # Create configuration objects with validation
        return UnifiedAODSConfig(
            execution=self._create_execution_config(execution_data),
            plugin=self._create_plugin_config(plugin_data),
            reporting=self._create_reporting_config(reporting_data),
            analysis=self._create_analysis_config(analysis_data),
            security=self._create_security_config(security_data),
            performance=self._create_performance_config(performance_data),
            config_source=source,
        )

    def _create_execution_config(self, data: Dict[str, Any]) -> ExecutionConfig:
        """Create ExecutionConfig from data with validation."""
        # Extract and validate fields
        return ExecutionConfig(
            canonical_mode=data.get("canonical_mode", False),
            max_concurrent_processes=max(1, data.get("max_concurrent_processes", 4)),
            execution_timeout_seconds=max(60, data.get("execution_timeout_seconds", 3600)),
            enable_parallel_execution=data.get("enable_parallel_execution", True),
            enable_resource_monitoring=data.get("enable_resource_monitoring", True),
            scan_mode=data.get("scan_mode", "full"),
            vulnerable_app_mode=data.get("vulnerable_app_mode", False),
            lightning_mode=data.get("lightning_mode", False),
            enable_fallback_strategies=data.get("enable_fallback_strategies", True),
            max_retries=max(0, data.get("max_retries", 3)),
            retry_delay_seconds=max(1, data.get("retry_delay_seconds", 5)),
            enable_sandboxing=data.get("enable_sandboxing", True),
            isolation_level=data.get("isolation_level", "standard"),
            workspace_dir=data.get("workspace_dir"),
            temp_dir=data.get("temp_dir"),
            cleanup_temp_files=data.get("cleanup_temp_files", True),
        )

    def _create_plugin_config(self, data: Dict[str, Any]) -> PluginConfig:
        """Create PluginConfig from data with validation."""
        return PluginConfig(
            plugin_directories=data.get("plugin_directories", ["plugins/"]),
            plugin_patterns=data.get("plugin_patterns", ["*.py", "__init__.py"]),
            enable_plugin_registry=data.get("enable_plugin_registry", True),
            enable_plugin_validation=data.get("enable_plugin_validation", True),
            default_timeout_seconds=max(30, data.get("default_timeout_seconds", 300)),
            max_concurrent_plugins=max(1, data.get("max_concurrent_plugins", 10)),
            enable_plugin_isolation=data.get("enable_plugin_isolation", True),
            plugin_memory_limit_mb=max(128, data.get("plugin_memory_limit_mb", 512)),
            enable_priority_scheduling=data.get("enable_priority_scheduling", True),
            enable_adaptive_timeout=data.get("enable_adaptive_timeout", True),
            enable_resource_management=data.get("enable_resource_management", True),
            enable_legacy_support=data.get("enable_legacy_support", True),
            enable_deprecation_warnings=data.get("enable_deprecation_warnings", True),
        )

    def _create_reporting_config(self, data: Dict[str, Any]) -> ReportingConfig:
        """Create ReportingConfig from data with validation."""
        return ReportingConfig(
            output_formats=data.get("output_formats", ["json", "html"]),
            output_directory=data.get("output_directory"),
            enable_console_output=data.get("enable_console_output", True),
            enable_file_output=data.get("enable_file_output", True),
            include_metadata=data.get("include_metadata", True),
            include_evidence=data.get("include_evidence", True),
            include_recommendations=data.get("include_recommendations", True),
            include_executive_summary=data.get("include_executive_summary", True),
            enable_vulnerability_enhancement=data.get("enable_vulnerability_enhancement", True),
            enable_confidence_scoring=data.get("enable_confidence_scoring", True),
            enable_risk_assessment=data.get("enable_risk_assessment", True),
            enable_compliance_mapping=data.get("enable_compliance_mapping", True),
            max_report_size_mb=max(10, data.get("max_report_size_mb", 100)),
            enable_compression=data.get("enable_compression", True),
            date_format=data.get("date_format", "%Y-%m-%d %H:%M:%S UTC"),
            # PERMANENT FIX: Disable redaction to reveal actual secret values per user request
            redact_sensitive_data=data.get("redact_sensitive_data", False),
            include_source_paths=data.get("include_source_paths", False),
        )

    def _create_analysis_config(self, data: Dict[str, Any]) -> AnalysisConfig:
        """Create AnalysisConfig from data with validation."""
        return AnalysisConfig(
            enable_static_analysis=data.get("enable_static_analysis", True),
            enable_dynamic_analysis=data.get("enable_dynamic_analysis", True),
            enable_hybrid_analysis=data.get("enable_hybrid_analysis", True),
            analysis_depth=data.get("analysis_depth", "full"),
            enable_jadx_decompilation=data.get("enable_jadx_decompilation", True),
            decompilation_timeout_seconds=max(60, data.get("decompilation_timeout_seconds", 600)),
            decompilation_memory_limit_mb=max(512, data.get("decompilation_memory_limit_mb", 2048)),
            enable_decompilation_caching=data.get("enable_decompilation_caching", True),
            enable_frida_analysis=data.get("enable_frida_analysis", True),
            # Drozer removed: default to False even if not specified
            enable_drozer_analysis=data.get("enable_drozer_analysis", False),
            enable_objection_analysis=data.get("enable_objection_analysis", True),
            enable_intelligent_filtering=data.get("enable_intelligent_filtering", True),
            enable_duplicate_detection=data.get("enable_duplicate_detection", True),
            enable_false_positive_reduction=data.get("enable_false_positive_reduction", True),
            max_files_per_analysis=data.get("max_files_per_analysis"),
            max_analysis_time_seconds=data.get("max_analysis_time_seconds"),
            skip_framework_files=data.get("skip_framework_files", False),
        )

    def _create_security_config(self, data: Dict[str, Any]) -> SecurityConfig:
        """Create SecurityConfig from data with validation."""
        return SecurityConfig(
            enable_nist_compliance=data.get("enable_nist_compliance", True),
            enable_owasp_compliance=data.get("enable_owasp_compliance", True),
            enable_masvs_compliance=data.get("enable_masvs_compliance", True),
            compliance_level=data.get("compliance_level", "standard"),
            enable_certificate_validation=data.get("enable_certificate_validation", True),
            enable_signature_verification=data.get("enable_signature_verification", True),
            enable_permission_analysis=data.get("enable_permission_analysis", True),
            enable_threat_intelligence=data.get("enable_threat_intelligence", True),
            threat_intelligence_sources=data.get("threat_intelligence_sources", []),
            max_privilege_level=data.get("max_privilege_level", "standard"),
            enable_secure_defaults=data.get("enable_secure_defaults", True),
            enforce_security_policies=data.get("enforce_security_policies", True),
        )

    def _create_performance_config(self, data: Dict[str, Any]) -> PerformanceConfig:
        """Create PerformanceConfig from data with validation."""
        return PerformanceConfig(
            max_memory_usage_mb=max(1024, data.get("max_memory_usage_mb", 4096)),
            max_cpu_usage_percent=min(100, max(10, data.get("max_cpu_usage_percent", 80))),
            max_disk_usage_gb=max(1, data.get("max_disk_usage_gb", 10)),
            enable_caching=data.get("enable_caching", True),
            cache_size_mb=max(128, data.get("cache_size_mb", 1024)),
            enable_parallel_processing=data.get("enable_parallel_processing", True),
            enable_lazy_loading=data.get("enable_lazy_loading", True),
            enable_performance_monitoring=data.get("enable_performance_monitoring", True),
            enable_resource_tracking=data.get("enable_resource_tracking", True),
            performance_sampling_rate=min(1.0, max(0.01, data.get("performance_sampling_rate", 0.1))),
            enable_adaptive_optimization=data.get("enable_adaptive_optimization", True),
            enable_predictive_scaling=data.get("enable_predictive_scaling", False),
            optimization_strategy=data.get("optimization_strategy", "balanced"),
        )

    def _merge_configurations(self, base: UnifiedAODSConfig, override: UnifiedAODSConfig) -> UnifiedAODSConfig:
        """Merge two configurations with override taking precedence."""
        # This is a simplified merge - in production would need more sophisticated merging
        return UnifiedAODSConfig(
            execution=override.execution if override.execution != ExecutionConfig() else base.execution,
            plugin=override.plugin if override.plugin != PluginConfig() else base.plugin,
            reporting=override.reporting if override.reporting != ReportingConfig() else base.reporting,
            analysis=override.analysis if override.analysis != AnalysisConfig() else base.analysis,
            security=override.security if override.security != SecurityConfig() else base.security,
            performance=override.performance if override.performance != PerformanceConfig() else base.performance,
            version=override.version,
            environment=override.environment,
            config_source=f"{base.config_source} + {override.config_source}",
        )


# ============================================================================
# GLOBAL CONFIGURATION ACCESS
# ============================================================================

_unified_config_manager: Optional[UnifiedConfigurationManager] = None


def get_unified_config_manager() -> UnifiedConfigurationManager:
    """Get global unified configuration manager instance."""
    global _unified_config_manager
    if _unified_config_manager is None:
        _unified_config_manager = UnifiedConfigurationManager()
    return _unified_config_manager


def get_configuration(environment: Optional[ConfigurationEnvironment] = None) -> UnifiedAODSConfig:
    """Get unified AODS configuration for environment."""
    return get_unified_config_manager().get_configuration(environment)


def get_execution_config(environment: Optional[ConfigurationEnvironment] = None) -> ExecutionConfig:
    """Get execution configuration."""
    return get_configuration(environment).execution


def get_plugin_config(environment: Optional[ConfigurationEnvironment] = None) -> PluginConfig:
    """Get plugin configuration."""
    return get_configuration(environment).plugin


def get_reporting_config(environment: Optional[ConfigurationEnvironment] = None) -> ReportingConfig:
    """Get reporting configuration."""
    return get_configuration(environment).reporting


def get_analysis_config(environment: Optional[ConfigurationEnvironment] = None) -> AnalysisConfig:
    """Get analysis configuration."""
    return get_configuration(environment).analysis


def get_security_config(environment: Optional[ConfigurationEnvironment] = None) -> SecurityConfig:
    """Get security configuration."""
    return get_configuration(environment).security


def get_performance_config(environment: Optional[ConfigurationEnvironment] = None) -> PerformanceConfig:
    """Get performance configuration."""
    return get_configuration(environment).performance
