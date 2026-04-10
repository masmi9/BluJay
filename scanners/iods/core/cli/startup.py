"""
IODS Startup – venv enforcement and early environment setup.
"""
from __future__ import annotations

import os
import sys


def setup_ml_environment_safely() -> None:
    """Disable ML if resource-safe mode is requested."""
    if os.environ.get("IODS_RESOURCE_SAFE", "0") == "1":
        if os.environ.get("IODS_DISABLE_ML", "") not in ("0", "false", "no"):
            os.environ["IODS_DISABLE_ML"] = "1"


def enforce_iods_venv() -> None:
    """Ensure the active virtual environment is named iods_venv."""
    if os.environ.get("IODS_TEST_MODE") == "1":
        return
    if "--help" in sys.argv or "-h" in sys.argv:
        return

    venv = os.environ.get("VIRTUAL_ENV", "")
    venv_name = os.path.basename(venv)
    if venv and venv_name != "iods_venv":
        print(f"WARNING: Active venv is '{venv_name}', expected 'iods_venv'.")
        print("  Create it with: python3 -m venv iods_venv && source iods_venv/bin/activate")


def check_virtual_environment() -> None:
    """Warn if running outside any virtual environment."""
    if os.environ.get("IODS_TEST_MODE") == "1":
        return
    if not os.environ.get("VIRTUAL_ENV"):
        print("WARNING: No active virtual environment detected.")
        print("  Run: source iods_venv/bin/activate")
