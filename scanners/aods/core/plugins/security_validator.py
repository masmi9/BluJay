#!/usr/bin/env python3
"""
Plugin Security Validator - Security Hardening for AODS Plugins
===============================================================

Provides security validation for plugins including integrity
checking, signature verification, capability validation, and security policy
enforcement.

Features:
- Plugin integrity verification using checksums
- Digital signature validation (future enhancement)
- Capability-based security policy enforcement
- Whitelist/blacklist management
- Security risk assessment
- Sandboxing recommendations
- Audit logging and compliance reporting

Usage:
    from core.plugins.security_validator import PluginSecurityValidator

    # Initialize validator
    validator = PluginSecurityValidator()

    # Validate plugin
    result = validator.validate_plugin(plugin_path, plugin_metadata)

    # Check security policy
    allowed = validator.check_security_policy(plugin_metadata)
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import stat

from .base_plugin_v2 import PluginMetadata, PluginCapability

try:
    from core.logging_config import get_logger
except ImportError:
    import logging as stdlib_logging

    get_logger = stdlib_logging.getLogger

logger = get_logger(__name__)


class SecurityLevel(Enum):
    """Security levels for plugins."""

    TRUSTED = "trusted"
    STANDARD = "standard"
    RESTRICTED = "restricted"
    UNTRUSTED = "untrusted"
    BLOCKED = "blocked"


class ValidationResult(Enum):
    """Plugin validation results."""

    APPROVED = "approved"
    APPROVED_WITH_WARNINGS = "approved_with_warnings"
    RESTRICTED = "restricted"
    REJECTED = "rejected"
    BLOCKED = "blocked"


@dataclass
class SecurityIssue:
    """Security issue found during validation."""

    severity: str  # critical, high, medium, low, info
    category: str  # integrity, permissions, capabilities, policy
    description: str
    recommendation: str
    code: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationReport:
    """Full plugin validation report."""

    plugin_id: str
    plugin_path: str
    result: ValidationResult
    security_level: SecurityLevel

    # Validation details
    integrity_verified: bool = False
    signature_verified: bool = False
    policy_compliant: bool = False

    # Issues and recommendations
    issues: List[SecurityIssue] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    # Metadata
    validation_time: float = field(default_factory=time.time)
    validator_version: str = "1.0.0"

    # Computed properties
    @property
    def critical_issues(self) -> List[SecurityIssue]:
        return [issue for issue in self.issues if issue.severity == "critical"]

    @property
    def high_issues(self) -> List[SecurityIssue]:
        return [issue for issue in self.issues if issue.severity == "high"]

    @property
    def has_blocking_issues(self) -> bool:
        return len(self.critical_issues) > 0


@dataclass
class SecurityPolicy:
    """Security policy configuration."""

    # Capability restrictions
    allowed_capabilities: Set[PluginCapability] = field(default_factory=set)
    restricted_capabilities: Set[PluginCapability] = field(default_factory=set)
    blocked_capabilities: Set[PluginCapability] = field(default_factory=set)

    # Resource limits
    max_memory_mb: Optional[int] = None
    max_execution_time: Optional[int] = None
    max_file_size_mb: int = 50

    # Permission requirements
    allow_network_access: bool = True
    allow_filesystem_access: bool = True
    allow_system_access: bool = False
    require_signature: bool = False

    # Security levels
    minimum_security_level: SecurityLevel = SecurityLevel.STANDARD
    default_security_level: SecurityLevel = SecurityLevel.STANDARD

    # Validation settings
    enforce_whitelist: bool = False
    block_unknown_plugins: bool = False
    require_integrity_check: bool = True


class PluginSecurityValidator:
    """
    Full plugin security validator.

    Validates plugins against security policies, checks integrity,
    and provides security recommendations for safe plugin execution.
    """

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize the security validator.

        Args:
            config_path: Path to security configuration file
        """
        # Initialize logger first
        self.logger = get_logger(__name__)

        self.config_path = config_path or Path("config/plugin_security.json")
        self.policy = self._load_security_policy()
        self.whitelist = self._load_whitelist()
        self.blacklist = self._load_blacklist()

        # Known good checksums (for integrity verification)
        self.known_checksums: Dict[str, str] = {}
        self._load_known_checksums()

    def _load_security_policy(self) -> SecurityPolicy:
        """Load security policy from configuration."""
        if self.config_path.exists():
            try:
                with open(self.config_path, "r") as f:
                    config = json.load(f)

                policy_config = config.get("security_policy", {})

                # Convert capability strings to enums
                allowed_caps = set()
                for cap_str in policy_config.get("allowed_capabilities", []):
                    try:
                        allowed_caps.add(PluginCapability(cap_str))
                    except ValueError:
                        self.logger.warning(f"Unknown capability in policy: {cap_str}")

                restricted_caps = set()
                for cap_str in policy_config.get("restricted_capabilities", []):
                    try:
                        restricted_caps.add(PluginCapability(cap_str))
                    except ValueError:
                        self.logger.warning(f"Unknown capability in policy: {cap_str}")

                blocked_caps = set()
                for cap_str in policy_config.get("blocked_capabilities", []):
                    try:
                        blocked_caps.add(PluginCapability(cap_str))
                    except ValueError:
                        self.logger.warning(f"Unknown capability in policy: {cap_str}")

                return SecurityPolicy(
                    allowed_capabilities=allowed_caps,
                    restricted_capabilities=restricted_caps,
                    blocked_capabilities=blocked_caps,
                    max_memory_mb=policy_config.get("max_memory_mb"),
                    max_execution_time=policy_config.get("max_execution_time"),
                    max_file_size_mb=policy_config.get("max_file_size_mb", 50),
                    allow_network_access=policy_config.get("allow_network_access", True),
                    allow_filesystem_access=policy_config.get("allow_filesystem_access", True),
                    allow_system_access=policy_config.get("allow_system_access", False),
                    require_signature=policy_config.get("require_signature", False),
                    minimum_security_level=SecurityLevel(policy_config.get("minimum_security_level", "standard")),
                    default_security_level=SecurityLevel(policy_config.get("default_security_level", "standard")),
                    enforce_whitelist=policy_config.get("enforce_whitelist", False),
                    block_unknown_plugins=policy_config.get("block_unknown_plugins", False),
                    require_integrity_check=policy_config.get("require_integrity_check", True),
                )

            except Exception as e:
                self.logger.error(f"Failed to load security policy: {e}")

        # Return default policy
        return SecurityPolicy()

    def _load_whitelist(self) -> Set[str]:
        """Load plugin whitelist."""
        whitelist_path = self.config_path.parent / "plugin_whitelist.json"
        if whitelist_path.exists():
            try:
                with open(whitelist_path, "r") as f:
                    data = json.load(f)
                    return set(data.get("whitelisted_plugins", []))
            except Exception as e:
                self.logger.error(f"Failed to load whitelist: {e}")
        return set()

    def _load_blacklist(self) -> Set[str]:
        """Load plugin blacklist."""
        blacklist_path = self.config_path.parent / "plugin_blacklist.json"
        if blacklist_path.exists():
            try:
                with open(blacklist_path, "r") as f:
                    data = json.load(f)
                    return set(data.get("blacklisted_plugins", []))
            except Exception as e:
                self.logger.error(f"Failed to load blacklist: {e}")
        return set()

    def _load_known_checksums(self):
        """Load known good plugin checksums."""
        checksums_path = self.config_path.parent / "plugin_checksums.json"
        if checksums_path.exists():
            try:
                with open(checksums_path, "r") as f:
                    self.known_checksums = json.load(f)
            except Exception as e:
                self.logger.error(f"Failed to load checksums: {e}")

    def validate_plugin(self, plugin_path: Path, metadata: PluginMetadata) -> ValidationReport:
        """
        Perform full plugin validation.

        Args:
            plugin_path: Path to the plugin
            metadata: Plugin metadata

        Returns:
            ValidationReport with validation results
        """
        report = ValidationReport(
            plugin_id=metadata.name,
            plugin_path=str(plugin_path),
            result=ValidationResult.APPROVED,
            security_level=self.policy.default_security_level,
        )

        # Check blacklist first
        if metadata.name in self.blacklist:
            report.result = ValidationResult.BLOCKED
            report.security_level = SecurityLevel.BLOCKED
            report.issues.append(
                SecurityIssue(
                    severity="critical",
                    category="policy",
                    description="Plugin is blacklisted",
                    recommendation="Remove plugin from blacklist or use alternative",
                    code="BLACKLISTED_PLUGIN",
                )
            )
            return report

        # Perform validation checks
        self._validate_integrity(plugin_path, metadata, report)
        self._validate_capabilities(metadata, report)
        self._validate_permissions(metadata, report)
        self._validate_resource_limits(metadata, report)
        self._validate_file_security(plugin_path, report)
        self._check_whitelist_compliance(metadata, report)

        # Determine final result
        self._determine_final_result(report)

        return report

    def _validate_integrity(self, plugin_path: Path, metadata: PluginMetadata, report: ValidationReport):
        """Validate plugin integrity."""
        if not self.policy.require_integrity_check:
            return

        try:
            # Calculate file checksum
            checksum = self._calculate_checksum(plugin_path)

            # Check against known good checksums
            known_checksum = self.known_checksums.get(metadata.name)
            if known_checksum:
                if checksum == known_checksum:
                    report.integrity_verified = True
                else:
                    report.issues.append(
                        SecurityIssue(
                            severity="high",
                            category="integrity",
                            description="Plugin checksum does not match known good checksum",
                            recommendation="Verify plugin source and update checksum if legitimate",
                            code="CHECKSUM_MISMATCH",
                            details={"calculated": checksum, "expected": known_checksum},
                        )
                    )
            else:
                # No known checksum - warning only
                report.warnings.append(f"No known checksum for plugin {metadata.name}")
                report.recommendations.append(f"Add checksum for {metadata.name} to known checksums")

        except Exception as e:
            report.issues.append(
                SecurityIssue(
                    severity="medium",
                    category="integrity",
                    description=f"Failed to verify plugin integrity: {e}",
                    recommendation="Manually verify plugin integrity",
                    code="INTEGRITY_CHECK_FAILED",
                )
            )

    def _validate_capabilities(self, metadata: PluginMetadata, report: ValidationReport):
        """Validate plugin capabilities against policy."""
        for capability in metadata.capabilities:
            if capability in self.policy.blocked_capabilities:
                report.issues.append(
                    SecurityIssue(
                        severity="critical",
                        category="capabilities",
                        description=f"Plugin uses blocked capability: {capability.value}",
                        recommendation="Remove blocked capability or update security policy",
                        code="BLOCKED_CAPABILITY",
                        details={"capability": capability.value},
                    )
                )
            elif capability in self.policy.restricted_capabilities:
                report.issues.append(
                    SecurityIssue(
                        severity="medium",
                        category="capabilities",
                        description=f"Plugin uses restricted capability: {capability.value}",
                        recommendation="Review usage of restricted capability",
                        code="RESTRICTED_CAPABILITY",
                        details={"capability": capability.value},
                    )
                )
            elif self.policy.allowed_capabilities and capability not in self.policy.allowed_capabilities:
                report.issues.append(
                    SecurityIssue(
                        severity="low",
                        category="capabilities",
                        description=f"Plugin uses capability not in allowed list: {capability.value}",
                        recommendation="Add capability to allowed list or review plugin",
                        code="UNALLOWED_CAPABILITY",
                        details={"capability": capability.value},
                    )
                )

    def _validate_permissions(self, metadata: PluginMetadata, report: ValidationReport):
        """Validate plugin permission requirements."""
        if metadata.requires_network and not self.policy.allow_network_access:
            report.issues.append(
                SecurityIssue(
                    severity="high",
                    category="permissions",
                    description="Plugin requires network access but policy forbids it",
                    recommendation="Update policy or disable network features",
                    code="NETWORK_ACCESS_DENIED",
                )
            )

        if metadata.requires_root and not self.policy.allow_system_access:
            report.issues.append(
                SecurityIssue(
                    severity="critical",
                    category="permissions",
                    description="Plugin requires root access but policy forbids it",
                    recommendation="Update policy or use alternative plugin",
                    code="ROOT_ACCESS_DENIED",
                )
            )

        # Check data access requirements
        for data_access in metadata.data_access_required:
            if data_access == "filesystem" and not self.policy.allow_filesystem_access:
                report.issues.append(
                    SecurityIssue(
                        severity="high",
                        category="permissions",
                        description="Plugin requires filesystem access but policy forbids it",
                        recommendation="Update policy or disable filesystem features",
                        code="FILESYSTEM_ACCESS_DENIED",
                    )
                )

    def _validate_resource_limits(self, metadata: PluginMetadata, report: ValidationReport):
        """Validate plugin resource limits."""
        if self.policy.max_memory_mb and metadata.memory_limit_mb:
            if metadata.memory_limit_mb > self.policy.max_memory_mb:
                report.issues.append(
                    SecurityIssue(
                        severity="medium",
                        category="resources",
                        description=f"Plugin memory limit ({metadata.memory_limit_mb}MB) exceeds policy limit ({self.policy.max_memory_mb}MB)",  # noqa: E501
                        recommendation="Reduce plugin memory limit or update policy",
                        code="MEMORY_LIMIT_EXCEEDED",
                    )
                )

        if self.policy.max_execution_time and metadata.timeout_seconds:
            if metadata.timeout_seconds > self.policy.max_execution_time:
                report.issues.append(
                    SecurityIssue(
                        severity="low",
                        category="resources",
                        description=f"Plugin timeout ({metadata.timeout_seconds}s) exceeds policy limit ({self.policy.max_execution_time}s)",  # noqa: E501
                        recommendation="Reduce plugin timeout or update policy",
                        code="TIMEOUT_LIMIT_EXCEEDED",
                    )
                )

    def _validate_file_security(self, plugin_path: Path, report: ValidationReport):
        """Validate plugin file security."""
        try:
            # Check file permissions
            file_stat = plugin_path.stat()

            # Check if file is world-writable
            if file_stat.st_mode & stat.S_IWOTH:
                report.issues.append(
                    SecurityIssue(
                        severity="medium",
                        category="permissions",
                        description="Plugin file is world-writable",
                        recommendation="Remove world-write permissions",
                        code="WORLD_WRITABLE_FILE",
                    )
                )

            # Check file size
            file_size_mb = file_stat.st_size / (1024 * 1024)
            if file_size_mb > self.policy.max_file_size_mb:
                report.issues.append(
                    SecurityIssue(
                        severity="low",
                        category="resources",
                        description=f"Plugin file size ({file_size_mb:.1f}MB) exceeds limit ({self.policy.max_file_size_mb}MB)",  # noqa: E501
                        recommendation="Optimize plugin size or update policy",
                        code="FILE_SIZE_EXCEEDED",
                    )
                )

        except Exception as e:
            report.warnings.append(f"Failed to check file security: {e}")

    def _check_whitelist_compliance(self, metadata: PluginMetadata, report: ValidationReport):
        """Check whitelist compliance."""
        if self.policy.enforce_whitelist:
            if metadata.name not in self.whitelist:
                if self.policy.block_unknown_plugins:
                    report.issues.append(
                        SecurityIssue(
                            severity="critical",
                            category="policy",
                            description="Plugin not in whitelist and unknown plugins are blocked",
                            recommendation="Add plugin to whitelist or update policy",
                            code="NOT_WHITELISTED",
                        )
                    )
                else:
                    report.issues.append(
                        SecurityIssue(
                            severity="medium",
                            category="policy",
                            description="Plugin not in whitelist",
                            recommendation="Add plugin to whitelist for full trust",
                            code="NOT_WHITELISTED",
                        )
                    )

    def _determine_final_result(self, report: ValidationReport):
        """Determine final validation result based on issues."""
        if report.critical_issues:
            report.result = ValidationResult.BLOCKED
            report.security_level = SecurityLevel.BLOCKED
        elif report.high_issues:
            report.result = ValidationResult.RESTRICTED
            report.security_level = SecurityLevel.RESTRICTED
        elif any(issue.severity == "medium" for issue in report.issues):
            report.result = ValidationResult.APPROVED_WITH_WARNINGS
            report.security_level = SecurityLevel.STANDARD
        else:
            report.result = ValidationResult.APPROVED
            if report.plugin_id in self.whitelist:
                report.security_level = SecurityLevel.TRUSTED
            else:
                report.security_level = SecurityLevel.STANDARD

    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA-256 checksum of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def check_security_policy(self, metadata: PluginMetadata) -> bool:
        """
        Quick security policy check.

        Args:
            metadata: Plugin metadata

        Returns:
            True if plugin passes basic policy checks
        """
        # Check blacklist
        if metadata.name in self.blacklist:
            return False

        # Check blocked capabilities
        for capability in metadata.capabilities:
            if capability in self.policy.blocked_capabilities:
                return False

        # Check whitelist if enforced
        if self.policy.enforce_whitelist and self.policy.block_unknown_plugins:
            if metadata.name not in self.whitelist:
                return False

        return True

    def export_validation_report(self, report: ValidationReport, output_path: Path):
        """Export validation report to JSON file."""
        report_data = {
            "plugin_id": report.plugin_id,
            "plugin_path": report.plugin_path,
            "result": report.result.value,
            "security_level": report.security_level.value,
            "integrity_verified": report.integrity_verified,
            "signature_verified": report.signature_verified,
            "policy_compliant": report.policy_compliant,
            "validation_time": report.validation_time,
            "validator_version": report.validator_version,
            "issues": [
                {
                    "severity": issue.severity,
                    "category": issue.category,
                    "description": issue.description,
                    "recommendation": issue.recommendation,
                    "code": issue.code,
                    "details": issue.details,
                }
                for issue in report.issues
            ],
            "warnings": report.warnings,
            "recommendations": report.recommendations,
        }

        with open(output_path, "w") as f:
            json.dump(report_data, f, indent=2)

        self.logger.info(f"Validation report exported to: {output_path}")


# Global validator instance
security_validator = PluginSecurityValidator()

# Convenience functions


def validate_plugin_security(plugin_path: Path, metadata: PluginMetadata) -> ValidationReport:
    """Validate plugin security using global validator."""
    return security_validator.validate_plugin(plugin_path, metadata)


def check_plugin_policy(metadata: PluginMetadata) -> bool:
    """Check plugin against security policy using global validator."""
    return security_validator.check_security_policy(metadata)
