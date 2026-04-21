"""
core.cli.startup - Early bootstrap functions (Track 46).

ML environment setup, venv enforcement, virtual env checks.
Must be called before any heavy imports.

NOTE: This module runs BEFORE structlog is configured.
Uses stdlib logging only - do NOT import structlog here.
"""

import sys
import os
import logging as _stdlib_logging

from core.cli import REPO_ROOT

_startup_logger = _stdlib_logging.getLogger(__name__)


def setup_ml_environment_safely():
    """Setup ML environment with defensive error handling - MUST run before imports"""
    try:
        # Check for disable flag in command line arguments
        if "--disable-ml" in sys.argv:
            os.environ["AODS_DISABLE_ML"] = "1"
            _startup_logger.info("ML components disabled via command line flag")
            return

        # Check for environment variable (defensive fallback)
        if os.environ.get("AODS_DISABLE_ML", "").lower() in ("1", "true", "yes"):
            _startup_logger.info("ML components disabled via environment variable")
            return

        # Check if ML dependencies are actually available (defensive validation)
        try:
            import importlib.util

            # Quick availability check without importing
            ml_deps_available = all(
                [
                    importlib.util.find_spec("matplotlib"),
                    importlib.util.find_spec("sklearn"),
                    importlib.util.find_spec("nltk"),
                ]
            )

            if ml_deps_available:
                _startup_logger.info("ML dependencies available, ML components enabled")
            else:
                _startup_logger.warning("ML dependencies missing, ML components automatically disabled")
                os.environ["AODS_DISABLE_ML"] = "1"

        except Exception as e:
            _startup_logger.warning("Error checking ML dependencies, ML components automatically disabled", exc_info=e)
            os.environ["AODS_DISABLE_ML"] = "1"

    except Exception as e:
        _startup_logger.error("Error setting up ML environment, disabling ML as fallback", exc_info=e)
        os.environ["AODS_DISABLE_ML"] = "1"


def enforce_aods_venv():
    """Enforce AODS virtual environment requirement before execution."""
    try:
        from tests.test_venv_preflight import AODSVenvEnforcementIntegration

        if not AODSVenvEnforcementIntegration.enforce_venv_before_scan():
            sys.stderr.write("AODS Virtual Environment enforcement failed.\n")
            sys.stderr.write("Please activate aods_venv and retry.\n")
            sys.exit(1)
    except ImportError:
        # Fallback check if test module not available
        in_venv = hasattr(sys, "real_prefix") or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)
        if not in_venv:
            sys.stderr.write("AODS Virtual Environment Not Active.\n")
            sys.stderr.write("Please activate aods_venv before running scans.\n")
            sys.stderr.write("Run: source aods_venv/bin/activate\n")
            sys.exit(1)


def check_virtual_environment():
    """Check if AODS is running in the proper virtual environment with dependencies."""
    # Check if we're in a virtual environment
    in_venv = hasattr(sys, "real_prefix") or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)

    # Check if aods_venv is available
    venv_path = REPO_ROOT / "aods_venv"
    venv_python = venv_path / "bin" / "python3"

    if not in_venv and venv_path.exists():
        sep = "=" * 50
        msg = (
            f"AODS Virtual Environment Not Active\n"
            f"{sep}\n"
            f"AODS dependencies (cachetools, filetype, nltk, etc.) are installed in aods_venv/\n"
            f"To avoid 'No module named' errors, please run AODS with the virtual environment:\n"
            f"\n"
            f"Linux/Mac:\n"
            f"  source aods_venv/bin/activate\n"
            f"  python3 dyna.py [arguments]\n"
            f"\n"
            f"Or use the direct path:\n"
            f"  {venv_python} dyna.py [arguments]\n"
            f"\n"
            f"Windows:\n"
            f"  .\\aods_venv\\Scripts\\activate\n"
            f"  python dyna.py [arguments]\n"
            f"{sep}\n"
        )
        sys.stderr.write(msg)

        # Try to import critical dependencies to verify they would work in venv
        try:
            # Try using venv python to test imports
            import subprocess

            result = subprocess.run(
                [str(venv_python), "-c", "import cachetools, filetype, nltk"], capture_output=True, timeout=10
            )
            if result.returncode == 0:
                sys.stderr.write("Dependencies are available in aods_venv - please activate it!\n")
            else:
                sys.stderr.write("Dependencies missing in aods_venv - run setup_venv.sh\n")
        except Exception:
            pass

        sys.stderr.write("\n")


# NOTE: check_virtual_environment() is called explicitly from dyna.py,
# NOT at import time here, to avoid duplicate side-effects.
