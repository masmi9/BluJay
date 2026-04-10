"""
core.cli.execution - Main execution body of dyna.py (Track 46).

Contains ``run_main(args)`` which is the orchestration body extracted
from ``main()`` in dyna.py.
"""

import logging
import os

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


from core.cli.feature_flags import (
    GRACEFUL_SHUTDOWN_AVAILABLE,
)

# Import implementation classes that are only available when their feature flag is True.
# These are used behind if-guards (e.g. if ENHANCED_ORCHESTRATOR_AVAILABLE:) so they
# only need to exist when the corresponding feature loaded successfully.
try:
    pass
except ImportError:
    pass
try:
    pass
except ImportError:
    pass
try:
    pass
except ImportError:
    pass
try:
    from core.cli.feature_flags import reset_shutdown_manager
except ImportError:
    pass


from core.cli.signal_cleanup import (
    cleanup_processes,
    force_exit_after_timeout,
)

# Conditional imports from feature_flags (class-level imports that may not exist)
try:
    from core.cli.feature_flags import set_global_scan_mode, get_global_scan_mode
except ImportError:
    set_global_scan_mode = None
    get_global_scan_mode = None

try:
    from core.cli.feature_flags import EnhancedVulnerabilityReportingEngine
except ImportError:
    EnhancedVulnerabilityReportingEngine = None


def run_main(args):
    """Orchestration body of main() - extracted from dyna.py.

    Args:
        args: Parsed argparse.Namespace from create_argument_parser().

    Returns:
        int or None: Exit code (0 on success).
    """
    # Delegate to extracted modules (Track 50)
    from core.cli.execution_setup import initialize_execution

    ctx = initialize_execution(args)

    try:
        if args.parallel_scan:
            from core.cli.execution_parallel import run_parallel_execution

            return run_parallel_execution(ctx)
        else:
            from core.cli.execution_standard import run_standard_execution

            return run_standard_execution(ctx)

    except KeyboardInterrupt:
        ctx.output_mgr.warning("Analysis interrupted by user")
        return 1
    except Exception as e:
        ctx.output_mgr.error(f"Analysis failed: {e}")
        logging.exception("Analysis error")
        return 1
    finally:
        # Safety net: force exit if non-daemon threads prevent clean shutdown
        force_exit_after_timeout(timeout_seconds=5)

        # Cleanup
        cleanup_processes()

        # Reset shutdown manager to prevent lingering effects between scans
        if GRACEFUL_SHUTDOWN_AVAILABLE:
            try:
                reset_shutdown_manager()
            except Exception:
                pass  # Continue cleanup even if reset fails

        # Ensure a minimal JSON report exists or upgrade placeholder at --output on early termination
        try:
            out_path = None
            try:
                out_path = locals().get("args").output if "args" in locals() else None
            except Exception:
                out_path = os.environ.get("AODS_OUTPUT_PATH")
            if out_path:
                import json as _json
                from pathlib import Path as _Path

                p = _Path(out_path)
                p.parent.mkdir(parents=True, exist_ok=True)
                write_minimal = (not p.exists()) or (p.exists() and p.stat().st_size == 0)
                upgrade_started = False
                if p.exists() and not write_minimal:
                    try:
                        current = _json.loads(p.read_text(encoding="utf-8", errors="ignore") or "{}")
                        status = str(current.get("status", "")).lower()
                        if status in ("started", "running"):
                            upgrade_started = True
                    except Exception:
                        write_minimal = True
                if write_minimal or upgrade_started:
                    minimal = {
                        "status": "aborted",
                        "message": "Scan terminated before report generation",
                        "findings": [],
                        "metadata": {
                            "apk": getattr(args, "apk", ""),
                            "pkg": getattr(args, "pkg", ""),
                            "mode": getattr(args, "mode", ""),
                        },
                    }
                    p.write_text(_json.dumps(minimal, indent=2), encoding="utf-8")
        except Exception:
            pass
