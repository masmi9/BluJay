"""
Core External Tool Integration Package

This package provides unified interfaces for executing external tools
with consistent error handling, resource management, and cleanup.
"""

from .unified_tool_executor import (
    UnifiedToolExecutor,
    ToolType,
    ExecutionStatus,
    ToolConfiguration,
    ExecutionResult,
    execute_adb_command,
    execute_jadx_decompilation,
    execute_frida_script,
    get_global_executor,
)

__all__ = [
    "UnifiedToolExecutor",
    "ToolType",
    "ExecutionStatus",
    "ToolConfiguration",
    "ExecutionResult",
    "execute_adb_command",
    "execute_jadx_decompilation",
    "execute_frida_script",
    "get_global_executor",
]
