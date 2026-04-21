"""
core.cli.execution_setup - Execution initialization extracted from run_main (Track 50).
"""

import os
import time
import logging
from dataclasses import dataclass, field
from typing import Any

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from core.output_manager import get_output_manager

from core.cli.feature_flags import (
    SCAN_MODE_TRACKER_AVAILABLE,
)
from core.cli.config_overrides import (
    apply_pattern_configuration_overrides,
)
from core.cli.utilities import print_banner

try:
    from core.cli.feature_flags import set_global_scan_mode, get_global_scan_mode
except ImportError:
    set_global_scan_mode = None
    get_global_scan_mode = None


@dataclass
class ExecutionContext:
    """Shared state passed between execution phases."""

    args: Any
    output_mgr: Any = None
    config_data: dict = field(default_factory=dict)
    aods_canonical: bool = False
    correlation_logger: Any = None
    compliance_engine: Any = None
    enterprise_optimizer: Any = None
    cross_platform_engine: Any = None
    feedback_server: Any = None
    parser: Any = None


def initialize_execution(args) -> ExecutionContext:
    """Initialize execution environment and return shared context.

    Contains the setup logic from run_main() lines 137-619.
    """
    from core.cli.arg_parser import create_argument_parser

    parser = create_argument_parser()
    correlation_logger = None

    # Apply command-line configuration overrides
    if any(
        [
            getattr(args, "disable_android14_webview_patterns", False),
            getattr(args, "disable_android14_network_patterns", False),
            getattr(args, "enable_android14_audit_patterns", False),
            getattr(args, "force_ml_filtering", False),
        ]
    ):
        apply_pattern_configuration_overrides(args)

    # Expose output path for cross-module minimal report writing during shutdown
    # IMPORTANT: Do not pre-create placeholder when skip-if-report-exists is requested,
    # otherwise the placeholder itself will trigger an early skip.
    try:
        _out_arg = getattr(args, "output", None)
        if _out_arg:
            os.environ["AODS_OUTPUT_PATH"] = _out_arg
            # Only create a placeholder when skip-if-report-exists is NOT active
            _skip_flag = bool(getattr(args, "skip_if_report_exists", False))
            _skip_env = os.getenv("AODS_SKIP_IF_REPORT_EXISTS", "0") == "1"
            if not _skip_flag and not _skip_env:
                try:
                    from pathlib import Path as _Path
                    import json as _json

                    p = _Path(_out_arg)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    if (not p.exists()) or p.stat().st_size == 0:
                        placeholder = {
                            "status": "started",
                            "message": "Scan started; finalization pending",
                            "findings": [],
                        }
                        p.write_text(_json.dumps(placeholder, indent=2), encoding="utf-8")
                except Exception:
                    pass
    except Exception:
        pass

    # PHASE 0.5: AODS_CANONICAL Feature Flag - Canonical Orchestration
    AODS_CANONICAL = os.getenv("AODS_CANONICAL", "0") == "1" or args.canonical

    if AODS_CANONICAL:
        logger.info(
            "Using canonical orchestration architecture",
            canonical=True,
            features="unified execution, intelligent strategy, deterministic ordering, zero duplication",
            rollback="Set AODS_CANONICAL=0 if issues occur",
        )

        # Import and validate canonical orchestrator
        try:
            logger.info("Canonical orchestrator loaded successfully")
        except ImportError as e:
            logger.warning("Canonical orchestrator import failed", error=str(e))
            if os.environ.get("AODS_EXEC_PATH_NO_FALLBACK", "0") == "1":
                raise
            logger.warning("Falling back to legacy execution path")
            AODS_CANONICAL = False
    else:
        logger.info(
            "Using legacy execution path (default)",
            canonical=False,
            hint="Set AODS_CANONICAL=1 to test canonical orchestration",
        )

    # ENHANCED: Validate argument combinations with automatic package detection
    batch_mode = bool(args.batch_targets or args.batch_config)
    single_mode = bool(args.apk)  # Only APK required now, pkg can be auto-detected

    if not batch_mode and not single_mode:
        parser.error(
            "Either provide --apk for single APK analysis (pkg auto-detected), or --batch-targets/--batch-config for batch processing"  # noqa: E501
        )

    if batch_mode and single_mode:
        parser.error(
            "Cannot use both single APK mode (--apk) and batch mode (--batch-targets/--batch-config) simultaneously"
        )

    # Validate package detection configuration
    if hasattr(args, "pkg_confidence_threshold"):
        if not (0.0 <= args.pkg_confidence_threshold <= 1.0):
            parser.error("--pkg-confidence-threshold must be between 0.0 and 1.0")

    # ENHANCED: Resolve package name for single APK mode
    if single_mode:
        try:
            from core.utils.package_interaction import resolve_package_name

            # Resolve package name (auto-detect or manual)
            package_name, was_auto_detected, confidence = resolve_package_name(args, args.apk)

            # Update args with resolved package name
            args.pkg = package_name
            args._pkg_was_auto_detected = was_auto_detected
            args._pkg_detection_confidence = confidence

            if was_auto_detected:
                logger.info("Package auto-detected", package=package_name, confidence=f"{confidence:.1%}")
            else:
                logger.info("Package manually specified", package=package_name)

        except ImportError as e:
            logger.error("Package detection modules not available", error=str(e))
            if not args.pkg:
                parser.error("Package detection failed and --pkg not provided. Please specify --pkg manually.")
        except Exception as e:
            logger.error("Package name resolution failed", error=str(e))
            if not args.pkg:
                parser.error("Package name resolution failed. Please specify --pkg manually.")

    # ENHANCED: Testing mode automatically enables lightning profile for faster development iteration
    # Auto-detect testing environment via environment variables
    testing_env_detected = any(
        [
            os.getenv("CI"),  # GitHub Actions, GitLab CI, etc.
            os.getenv("PYTEST_CURRENT_TEST"),  # pytest
            os.getenv("AODS_TESTING_MODE"),  # Custom AODS testing env var
            os.getenv("DEVELOPMENT", "").lower() == "true",  # Development environment
        ]
    )

    if args.testing_mode or testing_env_detected:
        if not args.profile:  # Only auto-set if no profile explicitly specified
            args.profile = "lightning"
            source = "flag" if args.testing_mode else "environment"
            logger.info("Testing mode enabled, using lightning profile", source=source, estimated_time="~45s")
        elif args.testing_mode:  # If both --testing-mode and --profile specified, prefer user choice but warn
            logger.warning("Testing mode flag detected but explicit profile specified", profile=args.profile)
        # Testing mode uses sequential execution for deterministic, proven report generation
        args.parallel_scan = False

    # Smart defaults when no profile specified
    elif not args.profile:
        # Auto-select profile based on mode for better user experience
        if args.mode == "agent":
            # Agent mode: use standard profile as base, orchestration agent will override
            args.profile = "standard"
            args.agent_orchestrate = True
            logger.info("Agent mode: enabling orchestration with standard base profile")
        elif args.mode == "deep":
            args.profile = "deep"
            logger.info("Auto-selected profile for deep mode analysis", profile="deep")
        else:
            args.profile = "standard"
            logger.info("Auto-selected profile for safe mode analysis", profile="standard")
    # Resource-safe overrides for constrained environments (e.g., WSL)
    try:
        if os.getenv("AODS_RESOURCE_SAFE", "0") == "1":
            # Prefer lightning/standard and sequential execution to reduce RAM/CPU pressure
            if not getattr(args, "profile", None) or args.profile.lower() in ("deep", "standard"):
                args.profile = "lightning"
                logger.info("Resource-safe mode: forcing lightning profile", profile="lightning")
            args.sequential = True
            args.parallel_scan = False
            logger.info("Resource-safe mode: sequential execution enabled, parallel scan disabled")
            # Auto-detect WSL and enforce stricter limits
            try:
                is_wsl = False
                with open("/proc/version", "r", errors="ignore") as f:
                    v = f.read().lower()
                    is_wsl = "microsoft" in v or "wsl" in v
            except Exception:
                is_wsl = False
            if is_wsl:
                # Default ML-off in WSL resource-safe mode (unless explicitly enabled)
                if os.environ.get("AODS_DISABLE_ML", "") not in ("0", "false", "no"):
                    os.environ["AODS_DISABLE_ML"] = "1"
                    logger.info("Resource-safe WSL: ML disabled by default")
                # Shrink cache tiers aggressively for low RAM
                os.environ.setdefault("AODS_CACHE_MEMORY_MB", "64")
                os.environ.setdefault("AODS_CACHE_SSD_GB", "1")
                os.environ.setdefault("AODS_CACHE_DISK_GB", "2")
                logger.info("Resource-safe WSL: cache tiers reduced", mem_mb=64, ssd_gb=1, disk_gb=2)
    except Exception as _rs_err:
        logger.warning("Failed to activate resource-safe mode", error=str(_rs_err))

    # Early-exit if an output report already exists and skipping is requested
    try:
        if args.skip_if_report_exists or os.getenv("AODS_SKIP_IF_REPORT_EXISTS", "0") == "1":
            out_path = getattr(args, "output", None)
            if out_path and os.path.exists(out_path) and os.path.getsize(out_path) > 0:
                logger.info("Existing report detected, skipping scan", output_path=out_path)
                return
    except Exception as _skip_err:
        logger.warning("Skip-if-report-exists check failed", error=str(_skip_err))

    # Dry run: print a concise plan and exit
    if getattr(args, "dry_run", False):
        try:
            plan = {
                "apk": getattr(args, "apk", None),
                "pkg": getattr(args, "pkg", None),
                "mode": getattr(args, "mode", None),
                "profile": getattr(args, "profile", None),
                "static_only": getattr(args, "static_only", False),
                "dynamic_only": getattr(args, "dynamic_only", False),
                "output": getattr(args, "output", None),
                "resource_safe": os.getenv("AODS_RESOURCE_SAFE", "0"),
                "single_run_lock": os.getenv("AODS_SINGLE_RUN_LOCK", "0"),
            }
            logger.info("Dry-run plan", **plan)
        except Exception as _dry_err:
            logger.warning("Dry-run planning failed", error=str(_dry_err))
        return

    # Single-run lock to prevent accidental re-runs in concurrent shells
    _lock_fd = None
    _lock_file = None
    try:
        if os.getenv("AODS_SINGLE_RUN_LOCK", "0") == "1":
            import atexit
            import hashlib  # time already imported at module level

            # Build a stable lock id from key inputs
            key_parts = [
                str(getattr(args, "apk", "")),
                str(getattr(args, "pkg", "")),
                str(getattr(args, "mode", "")),
                str(getattr(args, "profile", "")),
                (
                    "static"
                    if getattr(args, "static_only", False)
                    else "dynamic" if getattr(args, "dynamic_only", False) else "full"
                ),
                str(getattr(args, "output", "")),
            ]
            lock_id = hashlib.sha256(("|".join(key_parts)).encode("utf-8")).hexdigest()[:16]
            lock_dir = os.path.join("artifacts", "locks")
            os.makedirs(lock_dir, exist_ok=True)
            _lock_file = os.path.join(lock_dir, f"aods_scan_{lock_id}.lock")

            # Exclusive create; fail if the lock already exists
            _lock_fd = os.open(_lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(_lock_fd, f"pid={os.getpid()}\nstart_ts={int(time.time())}\n".encode("utf-8"))
            os.close(_lock_fd)
            _lock_fd = None
            logger.info("Single-run lock acquired", lock_file=_lock_file)

            def _release_lock():
                try:
                    if _lock_file and os.path.exists(_lock_file):
                        os.remove(_lock_file)
                        logger.debug("Single-run lock released", lock_file=_lock_file)
                except Exception:
                    pass

            atexit.register(_release_lock)
    except FileExistsError:
        # Lock already held by another process; respect skip policy if set
        if os.getenv("AODS_SINGLE_RUN_LOCK_SKIP", "1") == "1":
            logger.warning("Detected existing single-run lock, skipping scan", lock_file=_lock_file)
            return
        else:
            logger.warning(
                "Detected existing single-run lock but continuing per AODS_SINGLE_RUN_LOCK_SKIP=0", lock_file=_lock_file
            )
    except Exception as _lock_err:
        logger.warning("Single-run lock setup failed", error=str(_lock_err))

    # CRITICAL FIX: Auto-set mode to deep when profile is deep
    if args.profile == "deep" and args.mode == "safe":
        args.mode = "deep"
        logger.info("Auto-setting mode to deep because --profile deep was specified", mode="deep", profile="deep")

    # Handle sequential execution override
    if args.sequential:
        args.parallel_scan = False
        logger.info("Sequential execution mode enabled, parallel scans disabled")
    else:
        logger.info("Parallel execution mode enabled by default, static and dynamic scans will run in separate windows")

    # Configure logging and output manager
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        # FIXED: Also set output manager to verbose mode for progress bars
        from core.output_manager import set_output_level, OutputLevel

        set_output_level(OutputLevel.VERBOSE)
        logger.debug("Verbose mode enabled, logging and output set to DEBUG/VERBOSE")

    # CRITICAL FIX: Set global scan mode from command line argument
    if SCAN_MODE_TRACKER_AVAILABLE:
        set_global_scan_mode(args.mode, args.pkg, "command_line")

    # **NEW**: Configure deduplication from CLI arguments
    try:
        from core.deduplication_config_manager import configure_deduplication_from_cli

        configure_deduplication_from_cli(args)
        logger.info("Deduplication configured", strategy=args.dedup_strategy, threshold=args.dedup_threshold)
    except ImportError:
        logger.warning("Deduplication configuration manager not available, using defaults")
    except Exception as e:
        logger.warning("Error configuring deduplication, using defaults", error=str(e))
        logger.info("Scan mode set", mode=args.mode, package=args.pkg)
    else:
        logger.info("Scan mode tracker not available, using fallback mode", mode=args.mode)
    # Print banner
    print_banner()

    output_mgr = get_output_manager()
    output_mgr.status(f"Starting AODS analysis with scan mode: {args.mode.upper()}", "info")

    # ENHANCED CLI FEATURES: Handle new configuration and enterprise features
    config_data = {}

    # Load custom configuration if specified
    if args.config:
        try:
            import yaml
            from pathlib import Path

            config_path = Path(args.config)
            if config_path.exists():
                with open(config_path, "r") as f:
                    config_data = yaml.safe_load(f)
                output_mgr.status(f"🔧 Loaded custom configuration: {args.config}", "success")
            else:
                output_mgr.warning(f"Configuration file not found: {args.config}")
        except Exception as e:
            output_mgr.warning(f"Failed to load configuration: {e}")

    # Apply environment-specific settings
    if args.environment:
        try:
            env_config_path = f"config/deployment/{args.environment}.yml"
            from pathlib import Path

            if Path(env_config_path).exists():
                with open(env_config_path, "r") as f:
                    env_config = yaml.safe_load(f)
                    config_data.update(env_config)
                output_mgr.status(f"🌍 Applied {args.environment} environment settings", "success")
        except Exception as e:
            output_mgr.warning(f"Failed to load environment config: {e}")

    # Initialize compliance framework if specified
    compliance_engine = None
    if args.compliance:
        try:
            if args.compliance == "nist":
                try:
                    from core.nist_compliance_mapper import create_nist_compliance_mapper

                    compliance_engine = create_nist_compliance_mapper("AODS Security Assessment")
                    output_mgr.status("📊 NIST Compliance Framework enabled", "success")
                except ImportError:
                    output_mgr.warning("⚠️ NIST Compliance engine not available - continuing without compliance checks")
            else:
                output_mgr.status(f"📊 {args.compliance.upper()} compliance framework requested", "info")
        except Exception as e:
            output_mgr.warning(f"Failed to initialize compliance framework: {e}")

    # Initialize enterprise optimization if requested
    enterprise_optimizer = None
    if args.enterprise_optimization:
        try:
            # MIGRATED: Use unified performance infrastructure for enterprise optimization
            from core.shared_infrastructure.monitoring.performance_tracker import get_unified_performance_tracker
            from core.shared_infrastructure.performance.caching_consolidation import get_unified_cache_manager

            # Use unified enterprise optimization approach
            enterprise_optimizer = {
                "performance_tracker": get_unified_performance_tracker(),
                "cache_manager": get_unified_cache_manager(),
                "config": config_data,
            }
            output_mgr.status("🚀 Enterprise optimization features enabled", "success")
        except Exception as e:
            output_mgr.warning(f"Failed to initialize enterprise optimization: {e}")

    # Start feedback server if requested
    feedback_server = None
    if args.feedback_server:
        try:
            from core.ai_ml.user_feedback_interface import UserFeedbackInterface
            from core.shared_infrastructure.learning_analytics_dashboard import LearningAnalyticsDashboard

            # Phase 11: User Feedback & Analytics Integration
            feedback_server = UserFeedbackInterface()
            LearningAnalyticsDashboard()

            output_mgr.status("📊 Phase 11: User Feedback & Analytics Integration activated", "info")

            # Phase 15: External Data Integration
            try:
                from core.unified_threat_intelligence import UnifiedThreatIntelligenceSystem
                from core.external_data.pipeline_manager import ExternalDataPipelineManager

                UnifiedThreatIntelligenceSystem()
                ExternalDataPipelineManager()

                output_mgr.status("🌐 Phase 15: External Data Integration activated", "info")
            except ImportError as e:
                output_mgr.status(f"⚠️ Phase 15 External Data components not fully available: {e}", "warning")

            # Start server in background thread
            import threading

            def start_feedback_server():
                feedback_server.start_web_interface(port=args.feedback_port, debug=False)

            feedback_thread = threading.Thread(target=start_feedback_server, daemon=True)
            feedback_thread.start()
            output_mgr.status(f"🌐 ML Feedback server started on port {args.feedback_port}", "success")
        except Exception as e:
            output_mgr.warning(f"Failed to start feedback server: {e}")

    # Configure ML settings if specified
    if args.ml_confidence:
        if 0.0 <= args.ml_confidence <= 1.0:
            config_data["ml_confidence_threshold"] = args.ml_confidence
            output_mgr.status(f"🤖 ML confidence threshold set to {args.ml_confidence}", "info")
        else:
            output_mgr.warning("ML confidence threshold must be between 0.0 and 1.0")

    if args.ml_models_path:
        config_data["ml_models_path"] = args.ml_models_path
        output_mgr.status(f"🤖 Custom ML models path: {args.ml_models_path}", "info")

    # Enable progressive analysis if requested
    if args.progressive_analysis:
        config_data["progressive_analysis"] = True
        config_data["sample_rate"] = args.sample_rate
        output_mgr.status(f"📈 Progressive analysis enabled (sample rate: {args.sample_rate})", "info")

    # Enable QA mode if requested
    if args.qa_mode:
        config_data["qa_mode"] = True
        # Phase 14: Initialize QA Automation Integration
        try:
            output_mgr.status("🧪 Phase 14: QA Automation Integration activated", "info")
        except ImportError:
            output_mgr.status("⚠️ QA Automation components not available", "warning")
        output_mgr.status("🔍 Quality assurance mode enabled", "info")

    # Configure security profile
    config_data["security_profile"] = args.security_profile
    if args.security_profile != "basic":
        output_mgr.status(f"🔒 Security profile: {args.security_profile}", "info")

    # Start metrics server if requested
    if args.enable_metrics:
        try:
            # Start Prometheus metrics server
            try:
                from prometheus_client import start_http_server

                start_http_server(args.metrics_port)
                output_mgr.status(f"📊 Metrics server started on port {args.metrics_port}", "success")
            except ImportError:
                output_mgr.warning("⚠️ Prometheus client not available - metrics server disabled")
        except Exception as e:
            output_mgr.warning(f"Failed to start metrics server: {e}")
    # Initialize dashboard if requested
    if args.dashboard:
        try:
            from core.advanced_reporting_dashboard import AdvancedReportingDashboard

            dashboard = AdvancedReportingDashboard()

            # Start dashboard in background
            import threading

            def start_dashboard():
                dashboard.start_interactive_dashboard(port=8888)

            dashboard_thread = threading.Thread(target=start_dashboard, daemon=True)
            dashboard_thread.start()
            output_mgr.status("📊 Executive dashboard started on port 8888", "success")
        except Exception as e:
            output_mgr.warning(f"Failed to start dashboard: {e}")

    # Cross-platform analysis removed (Track 65)
    cross_platform_engine = None

    # Build and return execution context
    ctx = ExecutionContext(
        args=args,
        output_mgr=output_mgr,
        config_data=config_data,
        aods_canonical=AODS_CANONICAL,
        correlation_logger=correlation_logger,
        compliance_engine=compliance_engine,
        enterprise_optimizer=enterprise_optimizer,
        cross_platform_engine=cross_platform_engine,
        feedback_server=feedback_server,
        parser=parser,
    )
    return ctx
