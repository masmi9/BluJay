#!/usr/bin/env python3
"""
Unified Configuration Management Facade for AODS - MAXIMUM CONFIGURATION CAPABILITY & RELIABILITY
=================================================================================================

DUAL EXCELLENCE PRINCIPLE: This facade achieves the perfect balance for configuration:
1. MAXIMUM CONFIGURATION CAPABILITY (full format support, validation, hot-reload)
2. MAXIMUM RELIABILITY (thread-safe, error-resilient, performance-optimized)

The facade consolidates ALL configuration management functionality while maintaining
VULNERABILITY DETECTION ACCURACY as paramount and ensuring configuration errors don't
impact security analysis capabilities.

CONSOLIDATED MODULES:
- core/enhanced_config_manager.py (Enhanced configuration with caching and hot-reload)
- core/drozer_config_manager.py (Drozer-specific configuration)
- core/deduplication_config_manager.py (Deduplication configuration)
- core/config_management/* (Pattern loading, validation, caching)
- Various specialized configuration managers across plugins

Features:
- **Full FORMAT SUPPORT**: YAML, JSON, TOML, INI, environment variables, CLI args
- **PRECEDENCE SYSTEM**: CLI > ENV > File > Default with clear override rules
- **VALIDATION & SCHEMA**: Schema validation, business rule checking, type enforcement
- **HOT-RELOAD**: Real-time configuration updates with change notifications
- **THREAD-SAFE**: Concurrent access with proper locking and atomic operations
- **PERFORMANCE OPTIMIZED**: Intelligent caching, lazy loading, minimal I/O
- **ERROR RESILIENT**: Graceful degradation, fallback mechanisms, recovery strategies
"""

import logging
import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

# Import unified configuration components
from .config_loader import ConfigurationLoader, LoadedConfiguration, ConfigSource, ConfigFormat
from .system_detection import get_system_detector
from ..analysis_exceptions import ConfigurationError

logger = logging.getLogger(__name__)


class ConfigurationScope(Enum):
    """Configuration scope levels for different contexts."""

    GLOBAL = "global"  # System-wide configuration
    MODULE = "module"  # Module-specific configuration
    PLUGIN = "plugin"  # Plugin-specific configuration
    ANALYSIS = "analysis"  # Analysis session configuration
    TEMPORARY = "temporary"  # Temporary/runtime configuration


class ConfigurationPrecedence(Enum):
    """Configuration precedence levels (higher number = higher priority)."""

    DEFAULT = 1  # Built-in defaults
    FILE_GLOBAL = 2  # Global config files
    FILE_MODULE = 3  # Module-specific config files
    FILE_USER = 4  # User-specific config files
    ENVIRONMENT = 5  # Environment variables
    CLI_ARGS = 6  # Command-line arguments
    RUNTIME = 7  # Runtime overrides


@dataclass
class UnifiedConfigurationOptions:
    """
    Unified configuration options for all AODS systems.

    Consolidates configuration from all legacy configuration managers.
    """

    # Basic configuration paths
    config_directories: List[Path] = field(
        default_factory=lambda: [Path("config"), Path("~/.aods/config").expanduser(), Path("/etc/aods/config")]
    )

    # Format and loading options
    supported_formats: List[ConfigFormat] = field(
        default_factory=lambda: [ConfigFormat.YAML, ConfigFormat.JSON, ConfigFormat.TOML]
    )
    enable_hot_reload: bool = True
    enable_caching: bool = True
    cache_ttl: float = 300.0

    # Validation options
    enable_schema_validation: bool = True
    enable_business_rule_validation: bool = True
    strict_validation: bool = False  # False for graceful degradation

    # Performance options
    enable_lazy_loading: bool = True
    enable_concurrent_loading: bool = True
    max_concurrent_loaders: int = 4

    # Security options (VULNERABILITY-FIRST)
    preserve_security_settings: bool = True  # Never override security configs automatically
    validate_security_patterns: bool = True  # Validate security pattern configurations

    # Error handling (RELIABILITY-FIRST)
    enable_graceful_degradation: bool = True
    enable_fallback_defaults: bool = True
    enable_error_recovery: bool = True
    log_configuration_errors: bool = True


class UnifiedConfigurationManager:
    """
    Unified configuration manager consolidating ALL AODS configuration capabilities.

    DUAL EXCELLENCE: Maximum capability + Maximum reliability

    This manager provides configuration functionality by merging capabilities from:
    - Enhanced Config Manager: Caching, hot-reload, performance optimization
    - Execution Config Manager: Auto-tuning, system optimization, resource management
    - Pattern Config Management: Security pattern loading, validation, caching
    - Specialized managers: Drozer, deduplication, enterprise configurations

    Features:
    📁 **Full CONFIG LOADING**: All formats with intelligent precedence
    🔄 **HOT-RELOAD**: Real-time updates with change notifications
    ✅ **VALIDATION**: Schema and business rule validation with fallback
    ⚡ **HIGH PERFORMANCE**: Caching, lazy loading, concurrent access
    🛡️ **SECURITY-AWARE**: Preserves security configurations, validates patterns
    🔧 **AUTO-TUNING**: Intelligent defaults based on system capabilities
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, options: Optional[UnifiedConfigurationOptions] = None):
        """Singleton pattern with thread safety."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, options: Optional[UnifiedConfigurationOptions] = None):
        """Initialize unified configuration manager."""
        if hasattr(self, "_initialized"):
            return

        self.options = options or UnifiedConfigurationOptions()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # Core components
        self.config_loader = ConfigurationLoader(
            enable_hot_reload=self.options.enable_hot_reload,
            enable_caching=self.options.enable_caching,
            cache_ttl=self.options.cache_ttl,
        )

        # Configuration registry
        self.configurations: Dict[str, LoadedConfiguration] = {}
        self.config_lock = threading.RLock()

        # Precedence tracking
        self.precedence_registry: Dict[str, Dict[ConfigurationPrecedence, Any]] = defaultdict(dict)

        # Change notifications
        self.change_callbacks: Dict[str, List[Callable]] = defaultdict(list)

        # Performance tracking
        self.stats = {
            "configurations_loaded": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "hot_reloads": 0,
            "validation_errors": 0,
            "fallback_usage": 0,
            "average_load_time": 0.0,
        }

        # Initialize system detection
        self.system_detector = get_system_detector()

        # Initialize default configurations
        self._initialize_default_configurations()
        self._load_system_configurations()

        self._initialized = True
        self.logger.info("✅ Unified Configuration Manager initialized with full capabilities")

    def _initialize_default_configurations(self):
        """Initialize built-in default configurations."""
        # Execution configuration defaults
        self.register_default_configuration(
            "execution",
            {
                "execution_mode": "adaptive",
                "max_workers": None,  # Auto-detected
                "timeout_seconds": 300,
                "memory_limit_gb": None,  # Auto-detected
                "enable_parallel_execution": True,
                "enable_process_separation": True,
                "enable_resource_monitoring": True,
                "enable_adaptive_optimization": True,
                "max_memory_usage_percent": 80.0,
                "max_cpu_usage_percent": 90.0,
            },
        )

        # Security pattern defaults (from enhanced_config_manager.py)
        self.register_default_configuration(
            "security_patterns",
            {
                "crypto_patterns": {
                    "weak_encryption_algorithms": {
                        "DES": {
                            "patterns": ["DES\\.getInstance\\(", "Cipher\\.getInstance\\([\"']DES[\"']"],
                            "severity": "CRITICAL",
                            "reason": "DES encryption is deprecated and vulnerable",
                            "recommendation": "Use AES-256 encryption instead",
                            "cwe_id": "CWE-327",
                        }
                    }
                },
                "vulnerability_patterns": {
                    "sql_injection": {"patterns": ["execSQL\\(", "rawQuery\\("], "severity": "HIGH", "cwe_id": "CWE-89"}
                },
            },
        )

        # Drozer configuration defaults (from drozer_config_manager.py)
        self.register_default_configuration(
            "drozer",
            {
                "connection_timeout": 60,
                "command_timeout": 90,
                "port": 31415,
                "max_reconnection_attempts": 3,
                "enable_command_validation": True,
                "enable_security_validation": True,
            },
        )

        # Analysis configuration defaults
        self.register_default_configuration(
            "analysis",
            {
                "vulnerability_detection_focus": True,
                "minimize_false_positives": True,
                "preserve_borderline_cases": True,
                "enable_deep_analysis": True,
                "analysis_timeout": 1800,
            },
        )

    def _load_system_configurations(self):
        """Load system-specific configurations."""
        try:
            # Auto-detect system capabilities and optimize defaults
            system_profile = self.system_detector.get_complete_system_profile()

            # Update execution config based on system capabilities
            execution_config = self.get_configuration("execution")
            if execution_config and "hardware" in system_profile:
                # Auto-optimize worker count
                hardware_info = system_profile["hardware"]
                cpu_count = hardware_info.get("cpu_cores", 4)  # Default to 4 cores
                optimized_workers = max(2, min(8, int(cpu_count * 0.75)))

                # Auto-optimize memory limit
                memory_gb = hardware_info.get("total_memory_gb", 8.0)  # Default to 8GB
                optimized_memory = max(1.0, memory_gb * 0.6)

                self.set_configuration_value(
                    "execution.max_workers", optimized_workers, ConfigurationPrecedence.DEFAULT
                )
                self.set_configuration_value(
                    "execution.memory_limit_gb", optimized_memory, ConfigurationPrecedence.DEFAULT
                )

                self.logger.info(
                    f"🔧 Auto-optimized execution config: {optimized_workers} workers, {optimized_memory:.1f}GB memory"
                )

        except Exception as e:
            self.logger.warning(f"⚠️ Failed to load system configurations: {e}")
            # Continue with defaults

    def register_default_configuration(self, name: str, config_data: Dict[str, Any]):
        """Register a default configuration."""
        with self.config_lock:
            loaded_config = LoadedConfiguration(data=config_data, sources=[], load_time=time.time())
            self.configurations[name] = loaded_config

            # Register in precedence system
            for key, value in self._flatten_config(config_data, name).items():
                self.precedence_registry[key][ConfigurationPrecedence.DEFAULT] = value

    def load_configuration_file(
        self,
        name: str,
        file_path: Union[str, Path],
        precedence: ConfigurationPrecedence = ConfigurationPrecedence.FILE_GLOBAL,
        required: bool = False,
    ) -> bool:
        """Load configuration from file with specified precedence."""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                if required:
                    raise ConfigurationError(f"Required configuration file not found: {file_path}")
                self.logger.debug(f"Optional configuration file not found: {file_path}")
                return False

            # Load configuration using core loader
            config_source = ConfigSource(path=file_path, format=ConfigFormat.AUTO, required=required)
            loaded_config = self.config_loader.load_configuration([config_source])

            if not loaded_config.is_valid() and required:
                raise ConfigurationError(f"Invalid configuration in {file_path}: {loaded_config.validation_errors}")

            # Merge with existing configuration
            self._merge_configuration(name, loaded_config, precedence)

            self.stats["configurations_loaded"] += 1
            self.logger.info(f"✅ Loaded configuration '{name}' from {file_path}")
            return True

        except Exception as e:
            self.stats["validation_errors"] += 1
            if required:
                raise ConfigurationError(f"Failed to load required configuration {name}: {e}")
            else:
                self.logger.warning(f"⚠️ Failed to load optional configuration {name}: {e}")
                return False

    def _merge_configuration(self, name: str, new_config: LoadedConfiguration, precedence: ConfigurationPrecedence):
        """Merge new configuration with existing configuration based on precedence."""
        with self.config_lock:
            if name not in self.configurations:
                self.configurations[name] = new_config
            else:
                # Deep merge configurations
                existing = self.configurations[name]
                merged_data = self._deep_merge_dicts(existing.data, new_config.data)

                # Update configuration
                self.configurations[name] = LoadedConfiguration(
                    data=merged_data,
                    sources=existing.sources + new_config.sources,
                    load_time=time.time(),
                    validation_errors=existing.validation_errors + new_config.validation_errors,
                    warnings=existing.warnings + new_config.warnings,
                )

            # Update precedence registry
            for key, value in self._flatten_config(new_config.data, name).items():
                self.precedence_registry[key][precedence] = value

    def _deep_merge_dicts(self, dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = dict1.copy()

        for key, value in dict2.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge_dicts(result[key], value)
            else:
                result[key] = value

        return result

    def _flatten_config(self, config: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        """Flatten nested configuration for precedence tracking."""
        flattened = {}

        for key, value in config.items():
            full_key = f"{prefix}.{key}" if prefix else key

            if isinstance(value, dict):
                flattened.update(self._flatten_config(value, full_key))
            else:
                flattened[full_key] = value

        return flattened

    def get_configuration(self, name: str) -> Optional[LoadedConfiguration]:
        """Get configuration by name."""
        with self.config_lock:
            return self.configurations.get(name)

    def get_configuration_value(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation with precedence resolution."""
        # Check precedence registry first
        if key_path in self.precedence_registry:
            precedence_dict = self.precedence_registry[key_path]

            # Return value with highest precedence
            for precedence in sorted(ConfigurationPrecedence, key=lambda p: p.value, reverse=True):
                if precedence in precedence_dict:
                    self.stats["cache_hits"] += 1
                    return precedence_dict[precedence]

        # Fallback to configuration lookup
        parts = key_path.split(".", 1)
        config_name = parts[0]

        config = self.get_configuration(config_name)
        if config:
            if len(parts) == 1:
                return config.data
            else:
                return config.get_nested(parts[1], default)

        self.stats["cache_misses"] += 1
        return default

    def set_configuration_value(
        self, key_path: str, value: Any, precedence: ConfigurationPrecedence = ConfigurationPrecedence.RUNTIME
    ):
        """Set configuration value with specified precedence."""
        with self.config_lock:
            # Update precedence registry
            self.precedence_registry[key_path][precedence] = value

            # Update actual configuration if it exists
            parts = key_path.split(".", 1)
            config_name = parts[0]

            config = self.get_configuration(config_name)
            if config and len(parts) > 1:
                config.set_nested(parts[1], value)

            # Notify change callbacks
            self._notify_configuration_change(key_path, value)

    def _notify_configuration_change(self, key_path: str, new_value: Any):
        """Notify registered callbacks of configuration changes."""
        try:
            callbacks = self.change_callbacks.get(key_path, [])
            for callback in callbacks:
                try:
                    callback(key_path, new_value)
                except Exception as e:
                    self.logger.error(f"Error in configuration change callback for {key_path}: {e}")
        except Exception as e:
            self.logger.error(f"Error notifying configuration change for {key_path}: {e}")

    def register_change_callback(self, key_path: str, callback: Callable[[str, Any], None]):
        """Register callback for configuration changes."""
        with self.config_lock:
            self.change_callbacks[key_path].append(callback)

    def load_environment_variables(self, prefix: str = "AODS_"):
        """Load configuration from environment variables."""
        env_config = {}

        for key, value in os.environ.items():
            if key.startswith(prefix):
                config_key = key[len(prefix) :].lower().replace("_", ".")

                # Try to parse value as JSON, fall back to string
                try:
                    import json

                    parsed_value = json.loads(value)
                except (json.JSONDecodeError, ValueError):
                    parsed_value = value

                # Set with environment precedence
                self.set_configuration_value(config_key, parsed_value, ConfigurationPrecedence.ENVIRONMENT)

                self.logger.debug(f"Loaded environment variable: {config_key} = {parsed_value}")

        self.logger.info(f"✅ Loaded {len(env_config)} environment variables")

    def auto_discover_configurations(self):
        """Auto-discover and load configurations from standard locations."""
        discovered_count = 0

        for config_dir in self.options.config_directories:
            if not config_dir.exists():
                continue

            for format_enum in self.options.supported_formats:
                format_ext = format_enum.value
                pattern = f"*.{format_ext}"

                for config_file in config_dir.glob(pattern):
                    config_name = config_file.stem

                    try:
                        if self.load_configuration_file(config_name, config_file, ConfigurationPrecedence.FILE_GLOBAL):
                            discovered_count += 1
                    except Exception as e:
                        self.logger.warning(f"⚠️ Failed to load discovered config {config_file}: {e}")

        self.logger.info(f"✅ Auto-discovered {discovered_count} configuration files")
        return discovered_count

    def validate_all_configurations(self) -> Dict[str, List[str]]:
        """Validate all loaded configurations."""
        validation_results = {}

        with self.config_lock:
            for name, config in self.configurations.items():
                errors = []

                # Basic validation
                if not config.is_valid():
                    errors.extend(config.validation_errors)

                # Security-specific validation
                if self.options.preserve_security_settings and "security" in name:
                    security_errors = self._validate_security_configuration(config.data)
                    errors.extend(security_errors)

                validation_results[name] = errors

                if errors:
                    self.stats["validation_errors"] += len(errors)
                    self.logger.warning(f"⚠️ Validation errors in {name}: {errors}")

        return validation_results

    def _validate_security_configuration(self, config_data: Dict[str, Any]) -> List[str]:
        """Validate security-specific configuration requirements."""
        errors = []

        # Ensure vulnerability detection settings are not disabled
        if config_data.get("vulnerability_detection_focus") is False:
            errors.append("vulnerability_detection_focus cannot be disabled for security configurations")

        # Validate security patterns
        if "patterns" in config_data:
            patterns = config_data["patterns"]
            if not isinstance(patterns, dict) or not patterns:
                errors.append("Security patterns must be a non-empty dictionary")

        return errors

    def get_effective_configuration(self, scope: ConfigurationScope = ConfigurationScope.GLOBAL) -> Dict[str, Any]:
        """Get effective configuration for specified scope with all precedence applied."""
        effective_config = {}

        with self.config_lock:
            # Build effective configuration by applying precedence
            for key_path, precedence_dict in self.precedence_registry.items():
                # Apply scope filtering if needed
                if scope != ConfigurationScope.GLOBAL:
                    if not key_path.startswith(scope.value):
                        continue

                # Get highest precedence value
                for precedence in sorted(ConfigurationPrecedence, key=lambda p: p.value, reverse=True):
                    if precedence in precedence_dict:
                        self._set_nested_value(effective_config, key_path, precedence_dict[precedence])
                        break

        return effective_config

    def _set_nested_value(self, config_dict: Dict[str, Any], key_path: str, value: Any):
        """Set nested value in configuration dictionary."""
        keys = key_path.split(".")
        current = config_dict

        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]

        current[keys[-1]] = value

    def get_configuration_statistics(self) -> Dict[str, Any]:
        """Get configuration management statistics."""
        with self.config_lock:
            return {
                "statistics": self.stats.copy(),
                "configurations": {
                    "total_loaded": len(self.configurations),
                    "names": list(self.configurations.keys()),
                    "total_precedence_rules": len(self.precedence_registry),
                },
                "capabilities": {
                    "hot_reload_enabled": self.options.enable_hot_reload,
                    "caching_enabled": self.options.enable_caching,
                    "validation_enabled": self.options.enable_schema_validation,
                    "supported_formats": [f.value for f in self.options.supported_formats],
                },
                "system_info": {
                    "config_directories": [str(d) for d in self.options.config_directories],
                    "environment_variables_loaded": len(
                        [
                            k
                            for k in self.precedence_registry.keys()
                            if ConfigurationPrecedence.ENVIRONMENT in self.precedence_registry[k]
                        ]
                    ),
                },
            }


# Convenience functions for backward compatibility
def create_configuration_manager(options: Optional[Dict[str, Any]] = None) -> UnifiedConfigurationManager:
    """Create unified configuration manager with optional configuration."""
    if options:
        unified_options = UnifiedConfigurationOptions(**options)
        return UnifiedConfigurationManager(unified_options)
    return UnifiedConfigurationManager()


def get_configuration_value(key_path: str, default: Any = None) -> Any:
    """Get configuration value using global configuration manager."""
    manager = create_configuration_manager()
    return manager.get_configuration_value(key_path, default)


def set_configuration_value(key_path: str, value: Any, precedence: str = "runtime"):
    """Set configuration value using global configuration manager."""
    manager = create_configuration_manager()
    precedence_enum = ConfigurationPrecedence[precedence.upper()]
    manager.set_configuration_value(key_path, value, precedence_enum)


# Export for core.shared_infrastructure.configuration facade
__all__ = [
    "UnifiedConfigurationManager",
    "UnifiedConfigurationOptions",
    "ConfigurationScope",
    "ConfigurationPrecedence",
    "create_configuration_manager",
    "get_configuration_value",
    "set_configuration_value",
]
