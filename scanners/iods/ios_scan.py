#!/usr/bin/env python3
"""
IODS (iOS OWASP Dynamic Scan) – Entry Point
============================================
iOS security testing platform for IPA files.

Usage:
  python ios_scan.py --ipa MyApp.ipa --mode safe
  python ios_scan.py --ipa MyApp.ipa --mode deep --profile standard
  python ios_scan.py --batch-targets targets.txt --ci-mode

See README.md for full documentation.
"""

import sys
import os

# ── Path setup ────────────────────────────────────────────────────────────────
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

plugins_dir = os.path.join(project_root, "plugins")
if plugins_dir not in sys.path:
    sys.path.insert(0, plugins_dir)

# ── Early environment setup ───────────────────────────────────────────────────
if "--help" not in sys.argv and "-h" not in sys.argv and os.environ.get("IODS_TEST_MODE") != "1":
    os.environ.setdefault("IODS_PERFORMANCE_MODE", "1")
    os.environ.setdefault("IODS_PARALLEL_WORKERS", "2")
    os.environ.setdefault("IODS_ML_CACHE", "1")

# ── Bootstrap ─────────────────────────────────────────────────────────────────
from core.cli.startup import setup_ml_environment_safely, enforce_iods_venv, check_virtual_environment

setup_ml_environment_safely()
enforce_iods_venv()
check_virtual_environment()

# ── Logging ───────────────────────────────────────────────────────────────────
import logging
from core.logging_config import configure_structlog, get_logger

configure_structlog()
logger = get_logger(__name__)

try:
    from rich.logging import RichHandler
    logging.basicConfig(
        level=logging.INFO,
        handlers=[RichHandler(rich_tracebacks=True, show_path=False, show_level=True)],
    )
except ImportError:
    logging.basicConfig(level=logging.INFO)

# ── Feature flags ─────────────────────────────────────────────────────────────
from core.cli.feature_flags import *  # noqa: F401, F403

# ── CLI ───────────────────────────────────────────────────────────────────────
from core.cli.arg_parser import create_argument_parser


def main() -> int:
    """Parse arguments and delegate to run_main()."""
    parser = create_argument_parser()

    try:
        args = parser.parse_args()
    except SystemExit:
        if len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
            print("ERROR: IPA path must use --ipa flag")
            print(f"  Incorrect: python ios_scan.py {sys.argv[1]}")
            print(f"  Correct:   python ios_scan.py --ipa {sys.argv[1]}")
            print("  For help:  python ios_scan.py --help")
        sys.exit(1)

    from core.cli.execution import run_main
    return run_main(args)


if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv or os.environ.get("IODS_TEST_MODE") == "1":
        print("IODS iOS Security Analysis Framework")
        print("Usage: ios_scan.py [options]")
        print("  --ipa <path>       Path to target IPA file")
        print("  --mode <mode>      safe|deep|agent (default: safe)")
        print("  --profile <name>   lightning|fast|standard|deep (default: standard)")
        print("  --static-only      Static analysis only (no device required)")
        print("  --help             Show this help and exit")
        sys.exit(0)

    print("IODS iOS Security Analysis Starting...")
    print("=" * 60)
    sys.exit(main())
