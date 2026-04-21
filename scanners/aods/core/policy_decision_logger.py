#!/usr/bin/env python3
"""
Policy Decision Logger

Provides structured audit logging for policy-based decisions including:
- Frida safety checks and enforcement
- Tool execution permissions
- Scan mode enforcement (static-only, etc.)
- Resource limit decisions
- Security boundary enforcement

Logs are written to both the standard logger and a dedicated audit file.
Sensitive values are automatically redacted.
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from enum import Enum


class PolicyDecisionType(Enum):
    """Types of policy decisions that can be audited."""

    FRIDA_SAFETY = "frida_safety"
    TOOL_EXECUTION = "tool_execution"
    SCAN_MODE = "scan_mode"
    RESOURCE_LIMIT = "resource_limit"
    SECURITY_BOUNDARY = "security_boundary"
    PLUGIN_EXECUTION = "plugin_execution"
    NETWORK_ACCESS = "network_access"
    FILE_ACCESS = "file_access"
    ADB_COMMAND = "adb_command"
    DEVICE_ACCESS = "device_access"


class PolicyOutcome(Enum):
    """Possible outcomes of a policy decision."""

    ALLOWED = "allowed"
    DENIED = "denied"
    DEGRADED = "degraded"  # Allowed with reduced capabilities
    WARNED = "warned"  # Allowed but with warning logged
    SKIPPED = "skipped"  # Operation skipped due to policy


# Patterns for sensitive data redaction
SENSITIVE_PATTERNS: List[re.Pattern] = [
    re.compile(r"(password|passwd|pwd)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"(secret|token|key|api_key)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"(auth|bearer)\s+\S+", re.IGNORECASE),
    re.compile(r"--password[=\s]+\S+", re.IGNORECASE),
    re.compile(r"-p\s+\S+"),  # Common password flag
    re.compile(r"[a-zA-Z0-9+/]{40,}={0,2}"),  # Base64 tokens
]

# Keys that should be redacted entirely
SENSITIVE_KEYS: Set[str] = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "key",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "bearer",
    "credential",
    "credentials",
    "private_key",
    "private",
    "cert",
    "certificate",
}


@dataclass
class PolicyContext:
    """Context information for a policy decision."""

    scan_id: Optional[str] = None
    package_name: Optional[str] = None
    apk_path: Optional[str] = None
    plugin_name: Optional[str] = None
    tool_name: Optional[str] = None
    device_id: Optional[str] = None
    environment: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class PolicyDecisionEntry:
    """A single policy decision audit log entry."""

    timestamp: str
    decision_type: str
    outcome: str
    reason: str
    context: Dict[str, Any] = field(default_factory=dict)
    policy_rule: str = ""
    input_data: Dict[str, Any] = field(default_factory=dict)
    enforcement_action: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class PolicyDecisionLogger:
    """
    Centralized policy decision audit logger.

    Usage:
        logger = PolicyDecisionLogger.get_instance()
        logger.log_decision(
            decision_type=PolicyDecisionType.FRIDA_SAFETY,
            outcome=PolicyOutcome.DENIED,
            reason="Static-only mode enabled",
            policy_rule="AODS_STATIC_ONLY=1",
            context=PolicyContext(scan_id="scan_001", package_name="com.example"),
            input_data={"operation": "attach", "pid": 1234}
        )
    """

    _instance: Optional["PolicyDecisionLogger"] = None

    def __init__(self):
        self.logger = logging.getLogger("policy.audit")
        self._audit_file: Optional[Path] = None
        self._enabled = os.environ.get("AODS_POLICY_AUDIT_ENABLED", "1") == "1"
        self._verbose = os.environ.get("AODS_POLICY_AUDIT_VERBOSE", "0") == "1"
        self._setup_audit_file()

    @classmethod
    def get_instance(cls) -> "PolicyDecisionLogger":
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _setup_audit_file(self) -> None:
        """Setup dedicated audit log file."""
        try:
            audit_dir = Path("artifacts/policy_audit")
            audit_dir.mkdir(parents=True, exist_ok=True)
            date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
            self._audit_file = audit_dir / f"policy_decisions_{date_str}.jsonl"
        except Exception as e:
            self.logger.warning(f"Failed to setup policy audit file: {e}")

    def log_decision(
        self,
        decision_type: PolicyDecisionType,
        outcome: PolicyOutcome,
        reason: str,
        policy_rule: str = "",
        context: Optional[PolicyContext] = None,
        input_data: Optional[Dict[str, Any]] = None,
        enforcement_action: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a policy decision for audit purposes.

        Args:
            decision_type: Type of policy decision
            outcome: Result of the policy check
            reason: Human-readable explanation
            policy_rule: The rule or config that triggered this decision
            context: Context about the operation
            input_data: Input data for the decision (will be redacted)
            enforcement_action: Action taken (e.g., "blocked", "degraded_to_static")
            metadata: Additional context metadata
        """
        if not self._enabled:
            return

        entry = PolicyDecisionEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            decision_type=decision_type.value,
            outcome=outcome.value,
            reason=reason,
            context=context.to_dict() if context else {},
            policy_rule=policy_rule,
            input_data=self._redact_sensitive(input_data or {}),
            enforcement_action=enforcement_action,
            metadata=metadata or {},
        )

        # Log to standard logger
        log_msg = (
            f"Policy Decision: {decision_type.value} | "
            f"outcome={outcome.value} | "
            f"rule={policy_rule} | "
            f"reason={reason}"
        )

        if outcome == PolicyOutcome.DENIED:
            self.logger.warning(log_msg)
        elif outcome == PolicyOutcome.WARNED:
            self.logger.warning(log_msg)
        elif self._verbose:
            self.logger.info(log_msg)
        else:
            self.logger.debug(log_msg)

        # Write to audit file
        self._write_audit_entry(entry)

    def _redact_sensitive(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive values from data."""
        redacted = {}
        for key, value in data.items():
            # Check if key is sensitive
            if key.lower() in SENSITIVE_KEYS:
                redacted[key] = "[REDACTED]"
            elif isinstance(value, str):
                # Check for sensitive patterns in string values
                redacted_value = value
                for pattern in SENSITIVE_PATTERNS:
                    redacted_value = pattern.sub("[REDACTED]", redacted_value)
                # Truncate long strings
                if len(redacted_value) > 500:
                    redacted_value = redacted_value[:500] + "...[truncated]"
                redacted[key] = redacted_value
            elif isinstance(value, dict):
                redacted[key] = self._redact_sensitive(value)
            elif isinstance(value, (list, tuple)):
                redacted[key] = [
                    self._redact_sensitive(v) if isinstance(v, dict) else v for v in value[:10]  # Limit list length
                ]
            else:
                redacted[key] = value
        return redacted

    def _write_audit_entry(self, entry: PolicyDecisionEntry) -> None:
        """Write audit entry to file."""
        if self._audit_file is None:
            return
        try:
            with open(self._audit_file, "a", encoding="utf-8") as f:
                f.write(entry.to_json() + "\n")
        except Exception as e:
            self.logger.warning(f"Failed to write policy audit entry: {e}")

    # Convenience methods for common policy decisions

    def log_frida_safety(
        self,
        outcome: PolicyOutcome,
        operation: str,
        reason: str,
        context: Optional[PolicyContext] = None,
        device_id: Optional[str] = None,
        target_pid: Optional[int] = None,
    ) -> None:
        """Log Frida safety policy decision."""
        self.log_decision(
            decision_type=PolicyDecisionType.FRIDA_SAFETY,
            outcome=outcome,
            reason=reason,
            policy_rule="frida_safety_policy",
            context=context,
            input_data={"operation": operation, "device_id": device_id, "target_pid": target_pid},
            enforcement_action="blocked" if outcome == PolicyOutcome.DENIED else "allowed",
        )

    def log_tool_execution(
        self,
        tool_name: str,
        command: str,
        outcome: PolicyOutcome,
        reason: str,
        context: Optional[PolicyContext] = None,
        timeout: Optional[int] = None,
    ) -> None:
        """Log tool execution policy decision."""
        self.log_decision(
            decision_type=PolicyDecisionType.TOOL_EXECUTION,
            outcome=outcome,
            reason=reason,
            policy_rule="tool_execution_policy",
            context=context,
            input_data={"tool": tool_name, "command": command, "timeout": timeout},  # Will be redacted
            enforcement_action="executed" if outcome == PolicyOutcome.ALLOWED else "blocked",
        )

    def log_scan_mode(
        self, requested_mode: str, effective_mode: str, reason: str, context: Optional[PolicyContext] = None
    ) -> None:
        """Log scan mode enforcement decision."""
        outcome = PolicyOutcome.ALLOWED if requested_mode == effective_mode else PolicyOutcome.DEGRADED
        self.log_decision(
            decision_type=PolicyDecisionType.SCAN_MODE,
            outcome=outcome,
            reason=reason,
            policy_rule="scan_mode_enforcement",
            context=context,
            input_data={"requested_mode": requested_mode, "effective_mode": effective_mode},
            enforcement_action=f"mode_set_to_{effective_mode}",
        )

    def log_resource_limit(
        self,
        resource_type: str,
        requested: Any,
        allowed: Any,
        outcome: PolicyOutcome,
        reason: str,
        context: Optional[PolicyContext] = None,
    ) -> None:
        """Log resource limit enforcement decision."""
        self.log_decision(
            decision_type=PolicyDecisionType.RESOURCE_LIMIT,
            outcome=outcome,
            reason=reason,
            policy_rule="resource_limit_policy",
            context=context,
            input_data={"resource_type": resource_type, "requested": requested, "allowed": allowed},
            enforcement_action="limited" if outcome != PolicyOutcome.ALLOWED else "allowed",
        )

    def log_plugin_execution(
        self,
        plugin_name: str,
        outcome: PolicyOutcome,
        reason: str,
        context: Optional[PolicyContext] = None,
        skip_reason: Optional[str] = None,
    ) -> None:
        """Log plugin execution policy decision."""
        self.log_decision(
            decision_type=PolicyDecisionType.PLUGIN_EXECUTION,
            outcome=outcome,
            reason=reason,
            policy_rule="plugin_execution_policy",
            context=context,
            input_data={"plugin_name": plugin_name, "skip_reason": skip_reason},
            enforcement_action="executed" if outcome == PolicyOutcome.ALLOWED else "skipped",
        )

    def log_adb_command(
        self,
        command: str,
        outcome: PolicyOutcome,
        reason: str,
        context: Optional[PolicyContext] = None,
        device_id: Optional[str] = None,
    ) -> None:
        """Log ADB command policy decision."""
        self.log_decision(
            decision_type=PolicyDecisionType.ADB_COMMAND,
            outcome=outcome,
            reason=reason,
            policy_rule="adb_command_policy",
            context=context,
            input_data={"command": command, "device_id": device_id},  # Will be redacted
            enforcement_action="executed" if outcome == PolicyOutcome.ALLOWED else "blocked",
        )


# Module-level convenience function
def get_policy_logger() -> PolicyDecisionLogger:
    """Get the singleton policy decision logger instance."""
    return PolicyDecisionLogger.get_instance()


__all__ = [
    "PolicyDecisionLogger",
    "PolicyDecisionType",
    "PolicyOutcome",
    "PolicyContext",
    "PolicyDecisionEntry",
    "get_policy_logger",
]
