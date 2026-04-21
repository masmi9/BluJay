#!/usr/bin/env python3
"""
External Tool Policy Module

Enforces access control for external tools (ADB, Frida, JADX, etc.)
based on scan mode and configuration.

Usage:
    from core.external.policy import ExternalToolPolicy

    # Check if tool is denied
    if ExternalToolPolicy.is_denied('frida'):
        print(ExternalToolPolicy.denial_reason('frida'))

    # Enable static-only mode programmatically
    ExternalToolPolicy.set_static_only(True)
"""

from __future__ import annotations
import os
from typing import Optional, Any


class ExternalToolPolicy:
    """
    External tools policy gate.

    Enforces tool access based on scan mode:
    - When static-only mode is active, deny dynamic tools (ADB, Frida)
    - Static analysis tools like JADX are always allowed

    Static-only mode can be enabled via:
    - Environment variable: AODS_STATIC_ONLY_HARD=1
    - CLI flag: --static-only (sets env var automatically)
    - Programmatic: ExternalToolPolicy.set_static_only(True)
    """

    # Class-level flag for programmatic control
    _static_only_override: bool = False

    # Dynamic tools that should be blocked in static-only mode
    DYNAMIC_TOOLS = {"adb", "frida", "drozer", "objection"}

    @classmethod
    def set_static_only(cls, enabled: bool) -> None:
        """
        Programmatically enable/disable static-only mode.

        Args:
            enabled: True to block dynamic tools, False to allow them
        """
        cls._static_only_override = enabled
        if enabled:
            os.environ["AODS_STATIC_ONLY"] = "1"
            os.environ["AODS_STATIC_ONLY_HARD"] = "1"
        else:
            os.environ.pop("AODS_STATIC_ONLY", None)
            os.environ.pop("AODS_STATIC_ONLY_HARD", None)

    @classmethod
    def is_static_only(cls) -> bool:
        """Check if static-only mode is currently active."""
        return (
            cls._static_only_override
            or os.environ.get("AODS_STATIC_ONLY_HARD", "0") == "1"
            or os.environ.get("AODS_STATIC_ONLY", "0") == "1"
        )

    @classmethod
    def is_denied(cls, tool_type: Any, run_mode: Optional[str] = None, static_only: Optional[bool] = None) -> bool:
        """
        Check if a tool is denied by policy.

        Args:
            tool_type: Tool name or enum (e.g., 'frida', 'adb', ToolType.FRIDA)
            run_mode: Optional run mode string (deprecated, use static_only)
            static_only: Optional explicit static-only flag

        Returns:
            True if tool is denied, False if allowed
        """
        # Determine if static-only mode is active
        if static_only is not None:
            is_static = static_only
        else:
            is_static = cls.is_static_only()

        if not is_static:
            return False

        # Get tool name (handle enums and strings)
        name = getattr(tool_type, "value", str(tool_type)).lower()

        # Deny dynamic tools in static-only mode
        return name in cls.DYNAMIC_TOOLS

    @classmethod
    def denial_reason(cls, tool_type: Any) -> str:
        """Get human-readable denial reason for a tool."""
        name = getattr(tool_type, "value", str(tool_type))
        return f"Tool '{name}' denied: static-only mode active (dynamic tools blocked)"
