"""
core.agent.script_safety - Frida script safety validator (Track 92).

Validates generated Frida scripts before execution using blocklist-based
text scanning. Rejects scripts that attempt file I/O, process spawning,
network access, or other dangerous operations.

Public API:
    validate_frida_script(script) -> tuple[bool, str]
"""

from __future__ import annotations

# Patterns that MUST NOT appear in Frida scripts
BLOCKED_PATTERNS = [
    # File I/O
    "File(",
    "FileOutputStream",
    "FileInputStream",
    "RandomAccessFile",
    "deleteFile",
    "unlink(",
    # Process execution
    "Runtime.getRuntime",
    "exec(",
    "ProcessBuilder",
    "System.exit",
    "android.os.Process.killProcess",
    # Network
    "socket(",
    "ServerSocket(",
    "OkHttpClient",
    "HttpURLConnection",
    "URL(",
    # Dangerous reflection
    "dalvik.system.DexClassLoader",
    "DexFile",
    # Shell commands
    "'/system/bin/sh'",
    '"/system/bin/sh"',
    # JavaScript eval / dynamic code execution
    "eval(",
    "Function(",
    # Frida native API - arbitrary memory access
    "NativeFunction",
    "NativePointer",
    "NativeCallback",
    "Memory.alloc",
    "Memory.write",
    "Memory.read",
    "Memory.copy",
    "Memory.protect",
    # Frida code replacement / module loading
    "Interceptor.replace",
    "Module.load",
    # Frida message passing (can exfiltrate data)
    "recv(",
    "send(",
    # Frida class manipulation - inject new classes
    "Java.openClassFile",
    "Java.registerClass",
]

# Patterns that MUST appear for a valid Frida script
REQUIRED_PATTERNS = ["Java.perform"]

# Maximum allowed script length in characters
MAX_SCRIPT_LENGTH = 5000


def validate_frida_script(script: str) -> tuple:
    """Validate a Frida script for safety before execution.

    Args:
        script: The Frida JavaScript source code.

    Returns:
        Tuple of (is_safe: bool, reason: str).
        If is_safe is True, reason is "ok".
        If is_safe is False, reason explains why.
    """
    if not script or not script.strip():
        return False, "Empty script"

    if len(script) > MAX_SCRIPT_LENGTH:
        return False, f"Script exceeds maximum length ({len(script)} > {MAX_SCRIPT_LENGTH})"

    # Check for blocked patterns (case-sensitive - patterns use correct casing)
    for pattern in BLOCKED_PATTERNS:
        if pattern in script:
            return False, f"Blocked pattern found: {pattern}"

    # Check required patterns
    for pattern in REQUIRED_PATTERNS:
        if pattern not in script:
            return False, f"Required pattern missing: {pattern}"

    return True, "ok"
