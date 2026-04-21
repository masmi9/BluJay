#!/usr/bin/env python3
"""
Plugin Deprecation Manager - Legacy Interface Deprecation
=========================================================

Manages the deprecation of legacy plugin interfaces and migration to BasePlugin v2.
Provides warnings, migration guidance, and enforcement of deprecation timeline.

Features:
- 6-month deprecation timeline management
- Legacy plugin usage tracking and warnings
- Migration guidance and automation
- Deprecation policy enforcement
- Compatibility layer management
- Migration progress reporting

Usage:
    from core.plugins.deprecation_manager import DeprecationManager

    # Initialize deprecation manager
    manager = DeprecationManager()

    # Check if plugin is deprecated
    is_deprecated = manager.is_plugin_deprecated(plugin_name)

    # Log deprecation warning
    manager.log_deprecation_warning(plugin_name, "legacy_run_function")
"""

import json
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    from core.logging_config import get_logger
except ImportError:
    import logging as stdlib_logging

    get_logger = stdlib_logging.getLogger

logger = get_logger(__name__)


class DeprecationPhase(Enum):
    """Phases of the deprecation timeline."""

    ANNOUNCEMENT = "announcement"  # Month 0-1: Announce deprecation
    WARNING = "warning"  # Month 1-3: Show warnings
    RESTRICTED = "restricted"  # Month 3-5: Restrict new usage
    REMOVAL = "removal"  # Month 6+: Remove legacy support


class DeprecationSeverity(Enum):
    """Severity levels for deprecation warnings."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class DeprecationItem:
    """Information about a deprecated item."""

    name: str
    type: str  # plugin, interface, function, class
    deprecated_since: str  # ISO date string
    removal_date: str  # ISO date string
    replacement: Optional[str] = None
    migration_guide: Optional[str] = None
    reason: str = ""

    # Usage tracking
    usage_count: int = 0
    last_used: Optional[str] = None
    affected_plugins: Set[str] = field(default_factory=set)


@dataclass
class DeprecationWarning:
    """Deprecation warning information."""

    item_name: str
    plugin_name: str
    warning_type: str
    message: str
    severity: DeprecationSeverity
    timestamp: str
    phase: DeprecationPhase
    migration_suggestion: Optional[str] = None


class DeprecationManager:
    """
    Manages plugin interface deprecation and migration to BasePlugin v2.

    Implements a 6-month deprecation timeline with progressive restrictions
    and full migration support.
    """

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize the deprecation manager.

        Args:
            config_path: Path to deprecation configuration file
        """
        self.config_path = config_path or Path("config/plugin_deprecation.json")
        self.deprecated_items: Dict[str, DeprecationItem] = {}
        self.warnings_log: List[DeprecationWarning] = []
        self.usage_stats: Dict[str, Dict[str, Any]] = {}

        # Load configuration
        self._load_deprecation_config()

        # Set up logging
        self.logger = get_logger(__name__)

        # Track current phase
        self.current_phase = self._determine_current_phase()

    def _load_deprecation_config(self):
        """Load deprecation configuration."""
        if self.config_path.exists():
            try:
                with open(self.config_path, "r") as f:
                    config = json.load(f)

                # Load deprecated items
                for item_data in config.get("deprecated_items", []):
                    item = DeprecationItem(
                        name=item_data["name"],
                        type=item_data["type"],
                        deprecated_since=item_data["deprecated_since"],
                        removal_date=item_data["removal_date"],
                        replacement=item_data.get("replacement"),
                        migration_guide=item_data.get("migration_guide"),
                        reason=item_data.get("reason", ""),
                        usage_count=item_data.get("usage_count", 0),
                        last_used=item_data.get("last_used"),
                        affected_plugins=set(item_data.get("affected_plugins", [])),
                    )
                    self.deprecated_items[item.name] = item

                # Load usage stats
                self.usage_stats = config.get("usage_stats", {})

            except Exception as e:
                self.logger.error(f"Failed to load deprecation config: {e}")
        else:
            # Create default configuration
            self._create_default_config()

    def _create_default_config(self):
        """Create default deprecation configuration."""
        # Calculate dates for 6-month timeline
        announcement_date = datetime.now()
        removal_date = announcement_date + timedelta(days=180)  # 6 months

        # Define deprecated legacy interfaces
        legacy_items = [
            {
                "name": "legacy_run_function",
                "type": "function",
                "deprecated_since": announcement_date.isoformat(),
                "removal_date": removal_date.isoformat(),
                "replacement": "BasePluginV2.execute()",
                "migration_guide": "Migrate to BasePlugin v2 interface with execute() method",
                "reason": "Standardization to BasePlugin v2 interface",
            },
            {
                "name": "legacy_analyze_function",
                "type": "function",
                "deprecated_since": announcement_date.isoformat(),
                "removal_date": removal_date.isoformat(),
                "replacement": "BasePluginV2.execute()",
                "migration_guide": "Migrate to BasePlugin v2 interface with execute() method",
                "reason": "Standardization to BasePlugin v2 interface",
            },
            {
                "name": "ad_hoc_plugin_interface",
                "type": "interface",
                "deprecated_since": announcement_date.isoformat(),
                "removal_date": removal_date.isoformat(),
                "replacement": "BasePluginV2",
                "migration_guide": "Inherit from BasePluginV2 and implement required methods",
                "reason": "Standardization to unified plugin interface",
            },
            {
                "name": "tuple_result_format",
                "type": "format",
                "deprecated_since": announcement_date.isoformat(),
                "removal_date": removal_date.isoformat(),
                "replacement": "PluginResult",
                "migration_guide": "Return PluginResult object instead of tuple",
                "reason": "Standardization to structured result format",
            },
        ]

        # Create deprecated items
        for item_data in legacy_items:
            item = DeprecationItem(**item_data)
            self.deprecated_items[item.name] = item

        # Save configuration
        self._save_deprecation_config()

    def _save_deprecation_config(self):
        """Save deprecation configuration."""
        config = {
            "deprecated_items": [
                {
                    "name": item.name,
                    "type": item.type,
                    "deprecated_since": item.deprecated_since,
                    "removal_date": item.removal_date,
                    "replacement": item.replacement,
                    "migration_guide": item.migration_guide,
                    "reason": item.reason,
                    "usage_count": item.usage_count,
                    "last_used": item.last_used,
                    "affected_plugins": list(item.affected_plugins),
                }
                for item in self.deprecated_items.values()
            ],
            "usage_stats": self.usage_stats,
            "last_updated": datetime.now().isoformat(),
        }

        # Ensure config directory exists
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.config_path, "w") as f:
            json.dump(config, f, indent=2)

    def _determine_current_phase(self) -> DeprecationPhase:
        """Determine current deprecation phase based on timeline."""
        if not self.deprecated_items:
            return DeprecationPhase.ANNOUNCEMENT

        # Use the earliest deprecation date as reference
        earliest_date = min(
            datetime.fromisoformat(item.deprecated_since.replace("Z", "+00:00").replace("+00:00", ""))
            for item in self.deprecated_items.values()
        )

        now = datetime.now()
        days_since_deprecation = (now - earliest_date).days

        if days_since_deprecation < 30:
            return DeprecationPhase.ANNOUNCEMENT
        elif days_since_deprecation < 90:
            return DeprecationPhase.WARNING
        elif days_since_deprecation < 150:
            return DeprecationPhase.RESTRICTED
        else:
            return DeprecationPhase.REMOVAL

    def is_plugin_deprecated(self, plugin_name: str) -> bool:
        """Check if a plugin uses deprecated interfaces."""
        return plugin_name in [plugin for item in self.deprecated_items.values() for plugin in item.affected_plugins]

    def is_interface_deprecated(self, interface_name: str) -> bool:
        """Check if an interface is deprecated."""
        return interface_name in self.deprecated_items

    def log_deprecation_warning(self, plugin_name: str, deprecated_item: str, context: Optional[str] = None):
        """Log usage of deprecated interface."""
        if deprecated_item not in self.deprecated_items:
            return

        item = self.deprecated_items[deprecated_item]

        # Update usage statistics
        item.usage_count += 1
        item.last_used = datetime.now().isoformat()
        item.affected_plugins.add(plugin_name)

        # Determine severity based on phase
        severity_map = {
            DeprecationPhase.ANNOUNCEMENT: DeprecationSeverity.INFO,
            DeprecationPhase.WARNING: DeprecationSeverity.WARNING,
            DeprecationPhase.RESTRICTED: DeprecationSeverity.ERROR,
            DeprecationPhase.REMOVAL: DeprecationSeverity.CRITICAL,
        }
        severity = severity_map[self.current_phase]

        # Create warning message
        message = self._create_warning_message(item, plugin_name, context)

        # Create warning record
        warning = DeprecationWarning(
            item_name=deprecated_item,
            plugin_name=plugin_name,
            warning_type=item.type,
            message=message,
            severity=severity,
            timestamp=datetime.now().isoformat(),
            phase=self.current_phase,
            migration_suggestion=item.migration_guide,
        )

        self.warnings_log.append(warning)

        # Log the warning
        log_method = {
            DeprecationSeverity.INFO: self.logger.info,
            DeprecationSeverity.WARNING: self.logger.warning,
            DeprecationSeverity.ERROR: self.logger.error,
            DeprecationSeverity.CRITICAL: self.logger.critical,
        }[severity]

        log_method(f"DEPRECATION [{severity.value.upper()}]: {message}")

        # Show Python warning for WARNING phase and above
        if severity in [DeprecationSeverity.WARNING, DeprecationSeverity.ERROR]:
            warnings.warn(message, DeprecationWarning, stacklevel=3)

        # Save updated statistics
        self._save_deprecation_config()

    def _create_warning_message(self, item: DeprecationItem, plugin_name: str, context: Optional[str] = None) -> str:
        """Create deprecation warning message."""
        base_message = f"Plugin '{plugin_name}' uses deprecated {item.type} '{item.name}'"

        if context:
            base_message += f" in {context}"

        # Add phase-specific information
        if self.current_phase == DeprecationPhase.ANNOUNCEMENT:
            base_message += f". This {item.type} will be removed on {item.removal_date[:10]}"
        elif self.current_phase == DeprecationPhase.WARNING:
            base_message += f". This {item.type} will be removed soon"
        elif self.current_phase == DeprecationPhase.RESTRICTED:
            base_message += f". This {item.type} is restricted and will be removed soon"
        else:  # REMOVAL
            base_message += f". This {item.type} has been removed"

        # Add replacement information
        if item.replacement:
            base_message += f". Use '{item.replacement}' instead"

        # Add migration guide
        if item.migration_guide:
            base_message += f". Migration: {item.migration_guide}"

        return base_message

    def should_block_deprecated_usage(self, deprecated_item: str) -> bool:
        """Check if deprecated usage should be blocked."""
        if self.current_phase == DeprecationPhase.REMOVAL:
            return True

        # In restricted phase, block new usage (could be implemented with timestamps)
        if self.current_phase == DeprecationPhase.RESTRICTED:
            # For now, allow existing usage but warn heavily
            return False

        return False

    def get_migration_guidance(self, plugin_name: str) -> List[str]:
        """Get migration guidance for a plugin."""
        guidance = []

        for item in self.deprecated_items.values():
            if plugin_name in item.affected_plugins:
                guide = f"• Replace {item.type} '{item.name}'"
                if item.replacement:
                    guide += f" with '{item.replacement}'"
                if item.migration_guide:
                    guide += f": {item.migration_guide}"
                guidance.append(guide)

        return guidance

    def get_deprecation_report(self) -> Dict[str, Any]:
        """Get full deprecation report."""
        report = {
            "current_phase": self.current_phase.value,
            "total_deprecated_items": len(self.deprecated_items),
            "total_warnings": len(self.warnings_log),
            "affected_plugins": len(
                set(plugin for item in self.deprecated_items.values() for plugin in item.affected_plugins)
            ),
            "items": {},
            "usage_summary": {},
            "migration_progress": {},
        }

        # Item details
        for name, item in self.deprecated_items.items():
            report["items"][name] = {
                "type": item.type,
                "deprecated_since": item.deprecated_since,
                "removal_date": item.removal_date,
                "replacement": item.replacement,
                "usage_count": item.usage_count,
                "affected_plugins": list(item.affected_plugins),
                "days_until_removal": self._days_until_removal(item),
            }

        # Usage summary by severity
        severity_counts = {}
        for warning in self.warnings_log:
            severity = warning.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        report["usage_summary"] = severity_counts

        # Migration progress (plugins that have migrated)
        all_affected = set(plugin for item in self.deprecated_items.values() for plugin in item.affected_plugins)

        # This would need integration with plugin registry to determine migration status
        report["migration_progress"] = {
            "total_affected": len(all_affected),
            "migrated": 0,  # Would be calculated based on v2 plugin registrations
            "pending": len(all_affected),
        }

        return report

    def _days_until_removal(self, item: DeprecationItem) -> int:
        """Calculate days until removal."""
        removal_date = datetime.fromisoformat(item.removal_date.replace("Z", "+00:00").replace("+00:00", ""))
        return max(0, (removal_date - datetime.now()).days)

    def export_deprecation_report(self, output_path: Path):
        """Export deprecation report to JSON file."""
        report = self.get_deprecation_report()

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        self.logger.info(f"Deprecation report exported to: {output_path}")

    def check_plugin_for_deprecated_usage(self, plugin_path: Path, plugin_name: str) -> List[str]:
        """Check a plugin for deprecated interface usage."""
        deprecated_usage = []

        try:
            if plugin_path.exists():
                content = plugin_path.read_text(encoding="utf-8", errors="ignore")

                # Check for deprecated patterns
                if "def run(" in content:
                    deprecated_usage.append("legacy_run_function")
                    self.log_deprecation_warning(plugin_name, "legacy_run_function", "function definition")

                if "def analyze(" in content:
                    deprecated_usage.append("legacy_analyze_function")
                    self.log_deprecation_warning(plugin_name, "legacy_analyze_function", "function definition")

                if "return (" in content and "PluginResult" not in content:
                    deprecated_usage.append("tuple_result_format")
                    self.log_deprecation_warning(plugin_name, "tuple_result_format", "return statement")

                if "BasePluginV2" not in content and ("def run(" in content or "def analyze(" in content):
                    deprecated_usage.append("ad_hoc_plugin_interface")
                    self.log_deprecation_warning(plugin_name, "ad_hoc_plugin_interface", "plugin interface")

        except Exception as e:
            self.logger.warning(f"Failed to check plugin {plugin_name} for deprecated usage: {e}")

        return deprecated_usage


# Global deprecation manager instance
deprecation_manager = DeprecationManager()

# Convenience functions


def log_deprecated_usage(plugin_name: str, deprecated_item: str, context: Optional[str] = None):
    """Log deprecated interface usage."""
    deprecation_manager.log_deprecation_warning(plugin_name, deprecated_item, context)


def is_deprecated(interface_name: str) -> bool:
    """Check if an interface is deprecated."""
    return deprecation_manager.is_interface_deprecated(interface_name)


def should_block_usage(deprecated_item: str) -> bool:
    """Check if deprecated usage should be blocked."""
    return deprecation_manager.should_block_deprecated_usage(deprecated_item)


def get_migration_help(plugin_name: str) -> List[str]:
    """Get migration guidance for a plugin."""
    return deprecation_manager.get_migration_guidance(plugin_name)
