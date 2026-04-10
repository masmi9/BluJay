#!/usr/bin/env python3
"""
Objection Utilities
===================

Shared utilities for objection integration across all modules.
Provides consistent objection binary detection and execution.
"""

import subprocess
import sys
import os
from typing import Optional, List

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


def get_objection_binary_path() -> Optional[str]:
    """
    Get the path to objection binary.

    Returns:
        Path to objection binary if found, None otherwise
    """
    # Try full path first (venv installation)
    venv_bin = os.path.dirname(sys.executable)
    objection_path = os.path.join(venv_bin, "objection")

    if os.path.exists(objection_path):
        return objection_path

    # Try PATH
    try:
        result = subprocess.run(["which", "objection"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass

    return None


def check_objection_availability() -> bool:
    """
    Check if objection binary is available and functional.

    Returns:
        True if objection is available, False otherwise
    """
    try:
        objection_path = get_objection_binary_path()
        if not objection_path:
            return False

        result = subprocess.run([objection_path, "--help"], capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except Exception as e:
        logger.debug(f"Objection availability check failed: {e}")
        return False


def run_objection_command(args: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """
    Run objection command with proper binary path.

    Args:
        args: Command arguments (without 'objection')
        timeout: Command timeout in seconds

    Returns:
        CompletedProcess result

    Raises:
        RuntimeError: If objection is not available
    """
    objection_path = get_objection_binary_path()
    if not objection_path:
        raise RuntimeError("Objection binary not available")

    cmd = [objection_path] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
