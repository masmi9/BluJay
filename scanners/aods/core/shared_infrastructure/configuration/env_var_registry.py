#!/usr/bin/env python3
"""
AODS Environment Variable Registry - Track 3C

Centralized registry of all recognized AODS_* environment variables.
Provides type coercion, validation, default values, and documentation.

Usage:
    from core.shared_infrastructure.configuration.env_var_registry import (
        get_env_var,
        get_all_env_vars,
        ENV_VAR_REGISTRY
    )

    # Get typed value with default
    static_only = get_env_var('AODS_STATIC_ONLY_HARD', as_type=bool)

    # Get all current env var values
    all_vars = get_all_env_vars()
"""

import os
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Type, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class EnvVarCategory(Enum):
    """Categories for environment variables."""

    EXECUTION = "execution"
    ML = "ml"
    SECURITY = "security"
    FRIDA = "frida"
    UI = "ui"
    PERFORMANCE = "performance"
    DEBUG = "debug"
    PLUGIN = "plugin"
    REPORTING = "reporting"
    TESTING = "testing"


@dataclass
class EnvVarDefinition:
    """Definition of an environment variable."""

    name: str
    description: str
    var_type: Type
    default: Any
    category: EnvVarCategory
    config_path: Optional[str] = None  # Path in unified config (e.g., "execution.static_only")
    deprecated: bool = False
    deprecated_replacement: Optional[str] = None
    allowed_values: Optional[List[Any]] = None
    validator: Optional[Callable[[Any], bool]] = None

    def get_value(self) -> Any:
        """Get the current value from environment with type coercion."""
        raw = os.environ.get(self.name)
        if raw is None:
            return self.default

        try:
            if self.var_type == bool:
                # Handle boolean specially
                return raw.lower() in ("1", "true", "yes", "on")
            elif self.var_type == int:
                return int(raw)
            elif self.var_type == float:
                return float(raw)
            elif self.var_type == list:
                # Comma-separated list
                return [x.strip() for x in raw.split(",") if x.strip()]
            else:
                return raw
        except (ValueError, TypeError):
            logger.warning(f"Invalid value for {self.name}: {raw} (expected {self.var_type.__name__}), using default")
            return self.default

    def is_set(self) -> bool:
        """Check if the env var is explicitly set."""
        return self.name in os.environ


# Central registry of all AODS environment variables
ENV_VAR_REGISTRY: Dict[str, EnvVarDefinition] = {}


def _register(var: EnvVarDefinition) -> EnvVarDefinition:
    """Register an environment variable definition."""
    ENV_VAR_REGISTRY[var.name] = var
    return var


# ============================================================================
# EXECUTION CATEGORY
# ============================================================================

_register(
    EnvVarDefinition(
        name="AODS_STATIC_ONLY_HARD",
        description="Force static-only analysis mode (disable all dynamic/Frida analysis)",
        var_type=bool,
        default=False,
        category=EnvVarCategory.EXECUTION,
        config_path="execution.static_only",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_MAX_EXTERNAL_PROCS",
        description="Maximum concurrent external processes (JADX, ADB, etc.)",
        var_type=int,
        default=2,
        category=EnvVarCategory.EXECUTION,
        config_path="execution.max_concurrent_processes",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_TOOL_EXECUTOR_THREADS",
        description="Thread pool size for tool executor",
        var_type=int,
        default=4,
        category=EnvVarCategory.EXECUTION,
        config_path="execution.tool_executor_threads",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_MAX_WORKERS",
        description="Maximum worker threads for parallel execution",
        var_type=int,
        default=4,
        category=EnvVarCategory.EXECUTION,
        config_path="execution.max_workers",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_ENV",
        description="Environment type (development, testing, production, debug)",
        var_type=str,
        default="production",
        category=EnvVarCategory.EXECUTION,
        config_path="environment",
        allowed_values=["development", "testing", "production", "debug"],
    )
)

_register(
    EnvVarDefinition(
        name="AODS_APP_PROFILE",
        description="Application profile (production, vulnerable)",
        var_type=str,
        default="production",
        category=EnvVarCategory.EXECUTION,
        config_path="execution.app_profile",
        allowed_values=["production", "vulnerable"],
    )
)

_register(
    EnvVarDefinition(
        name="AODS_HTTP_MODE",
        description="HTTP allowlist mode (strict, internal)",
        var_type=str,
        default="internal",
        category=EnvVarCategory.EXECUTION,
        config_path="execution.http_mode",
        allowed_values=["strict", "internal"],
    )
)

# ============================================================================
# ML CATEGORY
# ============================================================================

_register(
    EnvVarDefinition(
        name="AODS_DISABLE_ML",
        description="Disable ML features entirely",
        var_type=bool,
        default=False,
        category=EnvVarCategory.ML,
        config_path="ml.enabled",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_ML_FP_THRESHOLD",
        description="ML false-positive filtering threshold",
        var_type=float,
        default=0.15,
        category=EnvVarCategory.ML,
        config_path="ml.fp_threshold",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_ML_ENABLE_CALIBRATION",
        description="Enable probability calibration",
        var_type=bool,
        default=True,
        category=EnvVarCategory.ML,
        config_path="ml.enable_calibration",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_ML_MAX_ECE",
        description="Maximum expected calibration error",
        var_type=float,
        default=0.05,
        category=EnvVarCategory.ML,
        config_path="ml.max_ece",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_ML_MAX_MCE",
        description="Maximum miscalibration error",
        var_type=float,
        default=0.10,
        category=EnvVarCategory.ML,
        config_path="ml.max_mce",
    )
)

# ============================================================================
# SECURITY CATEGORY
# ============================================================================

_register(
    EnvVarDefinition(
        name="AODS_AUTH_DISABLED",
        description="Disable authentication (development only)",
        var_type=bool,
        default=False,
        category=EnvVarCategory.SECURITY,
        config_path="security.auth_disabled",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_ADMIN_PASSWORD",
        description="Admin user password",
        var_type=str,
        default="admin",
        category=EnvVarCategory.SECURITY,
        config_path="security.admin_password",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_ANALYST_PASSWORD",
        description="Analyst user password",
        var_type=str,
        default="analyst",
        category=EnvVarCategory.SECURITY,
        config_path="security.analyst_password",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_VIEWER_PASSWORD",
        description="Viewer user password",
        var_type=str,
        default="viewer",
        category=EnvVarCategory.SECURITY,
        config_path="security.viewer_password",
    )
)

# ============================================================================
# FRIDA CATEGORY
# ============================================================================

_register(
    EnvVarDefinition(
        name="AODS_FRIDA_MODE",
        description="Frida operation mode",
        var_type=str,
        default="standard",
        category=EnvVarCategory.FRIDA,
        config_path="frida.mode",
        allowed_values=["standard", "read_only", "disabled"],
    )
)

_register(
    EnvVarDefinition(
        name="AODS_FRIDA_FORWARD_PORT",
        description="Frida server forward port",
        var_type=int,
        default=27042,
        category=EnvVarCategory.FRIDA,
        config_path="frida.forward_port",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_FRIDA_ANALYZER_ENABLE",
        description="Enable Frida analyzer",
        var_type=bool,
        default=True,
        category=EnvVarCategory.FRIDA,
        config_path="frida.analyzer_enabled",
    )
)

# ============================================================================
# UI CATEGORY
# ============================================================================

_register(
    EnvVarDefinition(
        name="AODS_UI_ORIGIN",
        description="Primary UI origin URL",
        var_type=str,
        default="http://127.0.0.1:5088",
        category=EnvVarCategory.UI,
        config_path="ui.origin",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_UI_ORIGIN_ALT",
        description="Alternative UI origin URL",
        var_type=str,
        default="http://localhost:5088",
        category=EnvVarCategory.UI,
        config_path="ui.origin_alt",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_API_URL",
        description="API base URL",
        var_type=str,
        default="http://127.0.0.1:8088/api",
        category=EnvVarCategory.UI,
        config_path="ui.api_url",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_WEB_BASE_PATH",
        description="Web base path for UI",
        var_type=str,
        default="/ui",
        category=EnvVarCategory.UI,
        config_path="ui.web_base_path",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_APP_TITLE",
        description="Application title",
        var_type=str,
        default="AODS",
        category=EnvVarCategory.UI,
        config_path="ui.app_title",
    )
)

# ============================================================================
# PERFORMANCE CATEGORY
# ============================================================================

_register(
    EnvVarDefinition(
        name="AODS_DEDUP_AGGREGATE",
        description="Enable deduplication aggregation",
        var_type=bool,
        default=False,
        category=EnvVarCategory.PERFORMANCE,
        config_path="performance.dedup_aggregate",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_CACHE_ENABLED",
        description="Enable caching",
        var_type=bool,
        default=True,
        category=EnvVarCategory.PERFORMANCE,
        config_path="performance.cache_enabled",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_CACHE_SIZE_MB",
        description="Maximum cache size in MB",
        var_type=int,
        default=256,
        category=EnvVarCategory.PERFORMANCE,
        config_path="performance.cache_size_mb",
    )
)

# ============================================================================
# PLUGIN CATEGORY
# ============================================================================

_register(
    EnvVarDefinition(
        name="AODS_DISABLE_SEMGREP",
        description="Disable Semgrep MASTG plugin",
        var_type=bool,
        default=False,
        category=EnvVarCategory.PLUGIN,
        config_path="plugin.disable_semgrep",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_SEMGREP_RULES_DIR",
        description="Override Semgrep rules directory path",
        var_type=str,
        default=None,
        category=EnvVarCategory.PLUGIN,
        config_path="plugin.semgrep_rules_dir",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_SEMGREP_EMIT_SARIF",
        description="Emit SARIF output from Semgrep",
        var_type=bool,
        default=False,
        category=EnvVarCategory.PLUGIN,
        config_path="plugin.semgrep_emit_sarif",
    )
)

# ============================================================================
# REPORTING CATEGORY
# ============================================================================

_register(
    EnvVarDefinition(
        name="AODS_REPORT_FORMATS",
        description="Output report formats (comma-separated: json,html,csv,txt)",
        var_type=list,
        default=["json", "html"],
        category=EnvVarCategory.REPORTING,
        config_path="reporting.output_formats",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_REPORT_DIR",
        description="Output directory for reports",
        var_type=str,
        default="reports",
        category=EnvVarCategory.REPORTING,
        config_path="reporting.output_directory",
    )
)

# ============================================================================
# DEBUG CATEGORY
# ============================================================================

_register(
    EnvVarDefinition(
        name="AODS_DEBUG",
        description="Enable debug mode",
        var_type=bool,
        default=False,
        category=EnvVarCategory.DEBUG,
        config_path="debug.enabled",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_LOG_LEVEL",
        description="Logging level",
        var_type=str,
        default="INFO",
        category=EnvVarCategory.DEBUG,
        config_path="debug.log_level",
        allowed_values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
)

_register(
    EnvVarDefinition(
        name="AODS_LOG_FORMAT",
        description="Log format (json, console, auto)",
        var_type=str,
        default="auto",
        category=EnvVarCategory.DEBUG,
        config_path="debug.log_format",
        allowed_values=["json", "console", "auto"],
    )
)

# ============================================================================
# TESTING CATEGORY
# ============================================================================

_register(
    EnvVarDefinition(
        name="AODS_LOCAL_GATES",
        description="Run local MASVS strict gate during pytest integration tests",
        var_type=bool,
        default=False,
        category=EnvVarCategory.TESTING,
        config_path="testing.local_gates",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_WS_DEV_NOAUTH",
        description="Disable WebSocket authentication in dev mode",
        var_type=bool,
        default=False,
        category=EnvVarCategory.TESTING,
        config_path="testing.ws_dev_noauth",
    )
)

_register(
    EnvVarDefinition(
        name="AODS_WS_ORIGIN_ALLOW_ALL",
        description="Allow all WebSocket origins",
        var_type=bool,
        default=False,
        category=EnvVarCategory.TESTING,
        config_path="testing.ws_origin_allow_all",
    )
)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def get_env_var(name: str, as_type: Optional[Type] = None, default: Any = None) -> Any:
    """
    Get an environment variable value with optional type coercion.

    Args:
        name: Environment variable name
        as_type: Optional type to coerce to (bool, int, float, str, list)
        default: Default value if not set and not in registry

    Returns:
        The environment variable value, coerced to the specified type
    """
    if name in ENV_VAR_REGISTRY:
        definition = ENV_VAR_REGISTRY[name]
        if definition.deprecated:
            logger.warning(
                f"Environment variable {name} is deprecated. "
                f"Use {definition.deprecated_replacement or 'unified config'} instead."
            )
        return definition.get_value()

    # Fallback for unregistered variables
    raw = os.environ.get(name)
    if raw is None:
        return default

    if as_type is None:
        return raw

    try:
        if as_type == bool:
            return raw.lower() in ("1", "true", "yes", "on")
        elif as_type == int:
            return int(raw)
        elif as_type == float:
            return float(raw)
        elif as_type == list:
            return [x.strip() for x in raw.split(",") if x.strip()]
        else:
            return raw
    except (ValueError, TypeError):
        return default


def get_all_env_vars(category: Optional[EnvVarCategory] = None) -> Dict[str, Any]:
    """
    Get all environment variable values.

    Args:
        category: Optional category filter

    Returns:
        Dictionary of env var names to their current values
    """
    result = {}
    for name, definition in ENV_VAR_REGISTRY.items():
        if category is None or definition.category == category:
            result[name] = {
                "value": definition.get_value(),
                "is_set": definition.is_set(),
                "default": definition.default,
                "category": definition.category.value,
                "description": definition.description,
            }
    return result


def get_env_var_summary() -> Dict[str, Any]:
    """Get a summary of all environment variables by category."""
    summary = {cat.value: [] for cat in EnvVarCategory}

    for name, definition in ENV_VAR_REGISTRY.items():
        summary[definition.category.value].append(
            {
                "name": name,
                "description": definition.description,
                "type": definition.var_type.__name__,
                "default": definition.default,
                "current": definition.get_value(),
                "is_set": definition.is_set(),
            }
        )

    return summary


def validate_env_vars() -> Dict[str, List[str]]:
    """
    Validate all environment variables.

    Returns:
        Dictionary with 'errors' and 'warnings' lists
    """
    errors = []
    warnings = []

    for name, definition in ENV_VAR_REGISTRY.items():
        if definition.deprecated and definition.is_set():
            warnings.append(f"{name} is deprecated, use {definition.deprecated_replacement or 'unified config'}")

        if definition.allowed_values and definition.is_set():
            value = definition.get_value()
            if value not in definition.allowed_values:
                errors.append(f"{name} has invalid value '{value}', allowed: {definition.allowed_values}")

        if definition.validator and definition.is_set():
            value = definition.get_value()
            if not definition.validator(value):
                errors.append(f"{name} failed custom validation")

    return {"errors": errors, "warnings": warnings}


# Export for convenience
__all__ = [
    "EnvVarCategory",
    "EnvVarDefinition",
    "ENV_VAR_REGISTRY",
    "get_env_var",
    "get_all_env_vars",
    "get_env_var_summary",
    "validate_env_vars",
]
