#!/usr/bin/env python3

# Ensure proper Python path setup for plugin imports
import sys
import os
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Add plugins directory to Python path for plugin imports
plugins_dir = os.path.join(project_root, 'plugins')
if plugins_dir not in sys.path:
    sys.path.insert(0, plugins_dir)

# Defer side-effectful env toggles when invoked with --help or test discovery
if '--help' not in sys.argv and '-h' not in sys.argv and os.environ.get('AODS_TEST_MODE') != '1':
    os.environ['AODS_PERFORMANCE_MODE'] = '1'
    os.environ['AODS_PARALLEL_WORKERS'] = '2'  # Increase from 1 to 2 workers
    os.environ['AODS_ML_CACHE'] = '1'  # Enable ML model caching

"""
AODS (Automated OWASP Dynamic Scan) - Enterprise Mobile Security Testing Framework
"""

# ---------- Early bootstrap (startup.py) ----------
from core.cli.startup import (
    setup_ml_environment_safely,
    enforce_aods_venv,
    check_virtual_environment,
)

# CRITICAL: Call early ML detection before any other imports
# Resource-safe early ML-off: if environment requests resource-safe, disable ML before checks
try:
    if os.environ.get('AODS_RESOURCE_SAFE', '0') == '1' and os.environ.get('AODS_DISABLE_ML', '') not in ('0','false','no'):
        os.environ['AODS_DISABLE_ML'] = '1'
        print("🔧 Resource-safe: ML disabled by default (early)")
except Exception:
    pass
setup_ml_environment_safely()

# CRITICAL: Enforce aods_venv before any imports or execution
enforce_aods_venv()

# Check virtual environment before continuing
check_virtual_environment()

# ---------- Stdlib + structlog (must precede feature_flags) ----------
import logging
import signal
import atexit

from core.logging_config import configure_structlog, get_logger
configure_structlog()
logger = get_logger(__name__)

# ---------- Feature flags (side-effect: ~50 print() statements) ----------
# MUST be imported after configure_structlog() above.
from core.cli.feature_flags import *  # noqa: F403 - backward compat for all flags

# ---------- Signal/cleanup wiring ----------
from core.cli.signal_cleanup import (
    signal_handler_fallback,
    is_shutdown_requested,
    cleanup_processes,
    cleanup_adb_connections,
    cleanup_threads,
    force_exit_after_timeout,
)

# Register signal handlers for clean shutdown
if GRACEFUL_SHUTDOWN_AVAILABLE:  # noqa: F405
    # Use graceful shutdown manager
    signal.signal(signal.SIGINT, lambda s, f: None)  # Disable default handler
    signal.signal(signal.SIGTERM, lambda s, f: None)  # Disable default handler
else:
    # Fallback to basic signal handling
    signal.signal(signal.SIGINT, signal_handler_fallback)
    signal.signal(signal.SIGTERM, signal_handler_fallback)

# Register cleanup at exit
atexit.register(cleanup_processes)

# ---------- logging.basicConfig (side-effect, stays in dyna.py) ----------
from rich.logging import RichHandler
logging.basicConfig(
    level=logging.INFO,
    handlers=[RichHandler(rich_tracebacks=True, show_path=False, show_level=True)],
)

# ---------- Remaining cli imports ----------
# Backward-compat re-exports (see comment block below)
from core.cli.finding_processing import (  # noqa: F401
    _create_canonical_findings,
    _sync_all_containers,
    _parse_vulnerabilities_from_text_report,
)
from core.cli.utilities import (
    run_dynamic_log_analysis,  # noqa: F401 - re-exported for parallel_execution_manager
    _import_heavy_modules,
)
from core.cli.arg_parser import create_argument_parser


# ==========================================================================
# Backward-compatibility re-exports (see Track 46 plan - 5 external consumers)
# ==========================================================================
# 1. tests/unit/test_container_sync.py:
#      from dyna import _create_canonical_findings, _sync_all_containers
#    → re-exported from core.cli.finding_processing above
#
# 2. tests/unit/core/reporting/test_track42_fp_elimination.py:
#      from dyna import _parse_vulnerabilities_from_text_report
#    → re-exported from core.cli.finding_processing above
#
# 3. core/parallel_execution_manager.py:
#      from dyna import run_dynamic_log_analysis
#    → re-exported from core.cli.utilities above
#
# 4. core/performance_optimization/advanced_performance_suite.py:
#      from dyna import main as aods_main
#    → main() is defined below
#
# 5. scripts/cleanup_safety_protocol.py:
#      "import dyna" (string literal validation)
#    → this module is importable
# ==========================================================================


def main():
    """Main entry point - parse arguments and delegate to run_main()."""
    _import_heavy_modules()

    import sys
    import os

    parser = create_argument_parser()

    # Parse arguments with better error handling
    try:
        args = parser.parse_args()
    except SystemExit as e:
        # Check for common user mistakes
        if len(sys.argv) > 1 and not sys.argv[1].startswith('--'):
            print("❌ Error: APK path must use --apk flag")
            print(f"   Incorrect: python dyna.py {sys.argv[1]}")
            print(f"   Correct:   python dyna.py --apk {sys.argv[1]}")
            print("   For help:  python dyna.py --help")
        elif '--report-format' in sys.argv:
            print("❌ Error: Use --output-format instead of --report-format")
            print("   Available formats: json, text, csv, html")
            print("   Example: python dyna.py --apk app.apk --output-format json")
        sys.exit(1)

    from core.cli.execution import run_main  # local import to avoid ordering issues
    return run_main(args)


if __name__ == "__main__":
    # Lightweight help handling for test environments
    if ('--help' in sys.argv) or ('-h' in sys.argv) or (os.environ.get('AODS_TEST_MODE') == '1'):
        print("AODS Dynamic Scan - usage: dyna.py [options]")
        print("  --apk <path>    Path to target APK")
        print("  --pkg <name>    Override package name")
        print("  --safe          Enable safe mode")
        print("  --help          Show this help and exit")
        sys.exit(0)
    # Show scan start
    print("AODS Security Analysis Starting...")
    print("=" * 60)

    # **STARTUP VALIDATION**: Check MITRE mapping integrity
    # PERFORMANCE FIX: Skip for lightning/fast profiles to reduce startup time by ~38 seconds
    skip_mitre_check = os.environ.get('AODS_SKIP_MITRE_CHECK', '0') == '1'
    fast_profile = any(
        arg in sys.argv for arg in ['--profile=lightning', '--profile=fast', '--testing-mode']
    ) or (
        '--profile' in sys.argv and
        sys.argv.index('--profile') + 1 < len(sys.argv) and
        sys.argv[sys.argv.index('--profile') + 1] in ('lightning', 'fast')
    )

    if skip_mitre_check or fast_profile:
        print("MITRE integrity check: SKIPPED (fast profile or AODS_SKIP_MITRE_CHECK=1)")
    else:
        try:
            from core.config.mitre_integrity_checker import startup_mitre_validation
            if not startup_mitre_validation():
                print("WARNING: MITRE mapping integrity validation failed")
                print("Threat intelligence may be inconsistent")
                print("Run: python core/config/mitre_integrity_checker.py for details")
                sys.exit(2)
            else:
                print("MITRE configuration integrity validated")
        except Exception as e:
            print(f"MITRE integrity check failed: {e}")
            sys.exit(2)

    print("=" * 60)

    sys.exit(main())
