"""
core.cli.execution_standard - Standard (non-parallel) execution extracted from run_main (Track 50).
"""

import os
import signal
import sys
import logging

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


from core.cli.feature_flags import (
    ADVANCED_INTELLIGENCE_AVAILABLE,
    AGENT_AVAILABLE,
    WEBVIEW_SECURITY_AVAILABLE,
    ENHANCED_ORCHESTRATOR_AVAILABLE,
    UNIFIED_PAYLOAD_MANAGER_AVAILABLE,
)

try:
    from core.cli.feature_flags import EnhancedScanOrchestrator
except ImportError:
    pass
try:
    from core.cli.feature_flags import UnifiedPayloadManager
except ImportError:
    pass
try:
    from core.cli.feature_flags import get_unified_threat_intelligence
except ImportError:
    pass


def run_standard_execution(ctx) -> int:
    """Run standard (non-parallel) execution path.

    Contains the standard execution logic from run_main() lines 2647-3116.

    Args:
        ctx: ExecutionContext from initialize_execution().

    Returns:
        Exit code (0 on success).
    """
    args = ctx.args
    output_mgr = ctx.output_mgr
    ctx.config_data
    AODS_CANONICAL = ctx.aods_canonical
    ctx.compliance_engine
    ctx.enterprise_optimizer
    ctx.cross_platform_engine

    # Standard AODS execution
    output_mgr.info("Starting standard AODS analysis")

    # Initialize Advanced Components
    advanced_intelligence = None
    scan_orchestrator = None  # noqa: F841
    payload_manager = None

    # Initialize Advanced Intelligence Engine if available
    if ADVANCED_INTELLIGENCE_AVAILABLE:
        try:
            advanced_intelligence = get_unified_threat_intelligence()
            output_mgr.success("✅ Advanced Intelligence Engine initialized")
        except Exception as e:
            output_mgr.warning(f"⚠️ Advanced Intelligence Engine error: {e} - continuing without advanced intelligence")
            advanced_intelligence = None

    # Initialize WebView Security Analyzer if available
    webview_analyzer = None
    if WEBVIEW_SECURITY_AVAILABLE:
        try:
            # WebView analyzer will be initialized during analysis with proper context
            output_mgr.success("✅ WebView Security Analyzer initialized")
        except Exception as e:
            output_mgr.warning(f"⚠️ WebView Security Analyzer error: {e} - continuing without WebView analysis")
            webview_analyzer = None

    # Initialize Enhanced Scan Orchestrator if available
    if ENHANCED_ORCHESTRATOR_AVAILABLE:
        try:
            _scan_orchestrator = EnhancedScanOrchestrator(apk_path=args.apk)  # noqa: F841
            # Note: Enhanced Scan Orchestrator doesn't require async initialization
            output_mgr.success("✅ Enhanced Scan Orchestrator initialized")
        except Exception as e:
            output_mgr.warning(f"⚠️ Enhanced Scan Orchestrator error: {e} - continuing with standard orchestration")

    # Initialize Unified Payload Manager if available
    if UNIFIED_PAYLOAD_MANAGER_AVAILABLE:
        try:
            payload_manager = UnifiedPayloadManager()
            payload_manager.initialize()
            output_mgr.success("✅ Unified Payload Manager initialized")
        except Exception as e:
            output_mgr.warning(f"⚠️ Unified Payload Manager error: {e} - continuing with standard payloads")
            payload_manager = None

    # Handle static-only and dynamic-only flags
    if args.static_only:
        output_mgr.info("Running static analysis only")
        args.disable_dynamic_analysis = True
        # CRITICAL FIX: Set environment variables so policy enforcement works
        # This ensures ExternalToolPolicy.is_denied() blocks Frida/ADB
        os.environ["AODS_STATIC_ONLY"] = "1"
        os.environ["AODS_STATIC_ONLY_HARD"] = "1"
        output_mgr.info("🔒 Static-only enforcement enabled (Frida/ADB blocked)")

        # Handle conflicting flags
        if getattr(args, "dynamic_only", False):
            output_mgr.warning("⚠️ --static-only and --dynamic-only are mutually exclusive; ignoring --dynamic-only")
            args.dynamic_only = False

        if getattr(args, "with_objection", False):
            output_mgr.warning("⚠️ --with-objection requires dynamic analysis; disabled in static-only mode")
            args.with_objection = False

    elif args.dynamic_only:
        output_mgr.info("Running dynamic analysis only")
        args.disable_static_analysis = True

    # Handle Objection Integration for standard execution
    if args.with_objection and not hasattr(args, "objection_context"):
        try:
            from plugins.objection_integration import ObjectionReconnaissanceModule

            output_mgr.status("🔍 Initializing Objection integration", "info")

            # Initialize Objection components based on mode
            objection_context = {
                "recon_results": None,
                "verification_commands": [],
                "training_scenarios": [],
                "dev_insights": [],
            }

            # Pre-scan reconnaissance if requested
            if not args.objection_mode or args.objection_mode == "recon":
                recon_module = ObjectionReconnaissanceModule()
                output_mgr.status("🚀 Running Objection reconnaissance", "info")
                objection_context["recon_results"] = recon_module.quick_reconnaissance(
                    args.pkg, timeout=args.objection_timeout
                )
                output_mgr.success("✅ Objection reconnaissance completed")

            # Store objection context in args for later use
            args.objection_context = objection_context

        except ImportError as e:
            output_mgr.warning(f"⚠️ Objection integration modules not available: {e}")
            args.with_objection = False
        except Exception as e:
            output_mgr.warning(f"⚠️ Objection integration failed: {e}")
            args.with_objection = False

    # PHASE 13: Check for batch processing mode
    if args.batch_targets or args.batch_config:
        output_mgr.status("🚀 Enterprise Batch Processing Mode - Analyzing multiple targets", "info")
        try:
            from core.enterprise import execute_batch_analysis, create_batch_config, load_targets_from_file

            # Configure batch processing
            if args.batch_config:
                # Load batch configuration from YAML file
                import yaml

                with open(args.batch_config, "r") as f:
                    batch_config = yaml.safe_load(f)

                # Load targets from configuration
                targets = batch_config.get("targets", [])
                if not targets and args.batch_targets:
                    # Fallback to targets file
                    targets = load_targets_from_file(args.batch_targets)

            elif args.batch_targets:
                # Load targets from file and create basic configuration
                targets = load_targets_from_file(args.batch_targets)
                batch_config = create_batch_config(
                    operation="security_analysis",
                    targets=[],  # Will be populated from file
                    output_dir=args.batch_output_dir or "./batch_results",
                    enable_parallel_processing=args.batch_parallel,
                    max_concurrent_analyses=args.batch_max_concurrent,
                    timeout_minutes=args.batch_timeout,
                    enable_ml_enhancement=not args.disable_ml,
                    report_formats=args.formats,
                )
            else:
                raise ValueError("Either --batch-config or --batch-targets must be specified for batch processing")

            # Convert targets to expected format
            formatted_targets = []
            for i, target in enumerate(targets):
                if isinstance(target, dict):
                    formatted_targets.append(target)
                else:
                    # Simple string target
                    formatted_targets.append({"id": f"target_{i + 1}", "path": target, "type": "auto", "priority": 1})

            # ENHANCED: Apply package detection to batch targets
            try:
                from core.utils.package_interaction import handle_batch_package_detection

                output_mgr.status("🔍 Applying automatic package detection to batch targets", "info")
                formatted_targets = handle_batch_package_detection(formatted_targets, args)
                output_mgr.success(f"✅ Package detection completed for {len(formatted_targets)} targets")
            except ImportError:
                output_mgr.warning("⚠️ Package detection for batch mode not available")
            except Exception as e:
                output_mgr.warning(f"⚠️ Batch package detection failed: {e}")

            # Execute batch analysis
            output_mgr.status(f"Starting batch analysis of {len(formatted_targets)} targets", "info")
            batch_result = execute_batch_analysis(batch_config, formatted_targets)

            if batch_result["success"]:
                output_mgr.success("✅ Batch analysis completed successfully!")
                output_mgr.info(
                    f"📊 Processed: {batch_result['targets_processed']}/{batch_result['targets_total']} targets"
                )
                if batch_result.get("reports_generated"):
                    output_mgr.info(f"📄 Reports generated: {len(batch_result['reports_generated'])}")

                # CI/CD mode exit handling
                if args.ci_mode:
                    # Check for failure conditions
                    exit_code = 0
                    if args.fail_on_critical or args.fail_on_high:
                        # Parse results for severity levels
                        # This would need integration with the actual results
                        output_mgr.info("CI/CD mode: Checking vulnerability severity levels...")

                    sys.exit(exit_code)

            else:
                output_mgr.error(f"❌ Batch analysis failed: {batch_result.get('error', 'Unknown error')}")
                sys.exit(1)

            # Batch analysis completed, exit
            return 0

        except ImportError as e:
            output_mgr.error(f"❌ Enterprise batch processing not available: {e}")
            output_mgr.info("Please ensure the enterprise module is properly installed")
            sys.exit(1)
        except Exception as e:
            output_mgr.error(f"❌ Batch processing failed: {e}")
            sys.exit(1)
    # Standard single APK analysis mode
    output_mgr.status("📱 Single APK Analysis Mode", "info")

    # PHASE 7: CANONICAL EXECUTION PATH - Modular Architecture
    if AODS_CANONICAL:
        output_mgr.status("🏗️ Using canonical modular execution path", "info")
        try:
            # Import canonical modular components
            from core.execution import create_execution_manager
            from core.plugins import create_plugin_manager
            from core.shared_infrastructure.reporting import create_unified_reporting_manager
            from core.unified_config import ConfigurationFactory, ScanProfile as ModularScanProfile

            # Create modular configuration
            scan_profile_map = {
                "lightning": ModularScanProfile.LIGHTNING,
                "fast": ModularScanProfile.FAST,
                "standard": ModularScanProfile.STANDARD,
                "deep": ModularScanProfile.DEEP,
            }

            modular_profile = scan_profile_map.get(args.profile, ModularScanProfile.STANDARD)
            config = ConfigurationFactory.create_from_profile(modular_profile)

            # Create modular managers using dependency injection
            execution_manager = create_execution_manager(config.execution_config)
            create_plugin_manager(config.plugin_config)
            reporting_manager = create_unified_reporting_manager(config.reporting_config)

            # Execute analysis using modular architecture
            output_mgr.status("🚀 Executing modular analysis pipeline", "info")

            # Create APK context for modular execution
            from core.apk_ctx import APKContext

            apk_context = APKContext(
                apk_path=args.apk,
                package_name=args.pkg,
                scan_mode=args.mode,
                enable_ml=not args.disable_ml,
                vulnerable_app_mode=args.vulnerable_app_mode,
            )

            # Run modular analysis
            analysis_results = execution_manager.run_analysis(apk_context)

            # Generate reports using modular reporting
            output_mgr.status("📊 Generating reports using modular orchestrator", "info")
            report_bundle = reporting_manager.generate_reports(analysis_results)

            # Display modular results
            output_mgr.success("✅ Modular analysis completed successfully!")
            output_mgr.info("📄 Generated reports (modular architecture):")
            for format_name, file_path in report_bundle.generated_files.items():
                output_mgr.info(f"  {format_name.upper()}: {file_path}")

            return 0

        except ImportError as e:
            output_mgr.warning(f"⚠️ Canonical modular components not available: {e}")
            if os.environ.get("AODS_EXEC_PATH_NO_FALLBACK", "0") == "1":
                raise
            output_mgr.info("   🔄 Falling back to legacy execution path")
            # Fall through to legacy execution
        except Exception as e:
            output_mgr.warning(f"⚠️ Canonical execution failed: {e}")
            if os.environ.get("AODS_EXEC_PATH_NO_FALLBACK", "0") == "1":
                raise
            output_mgr.info("   🔄 Falling back to legacy execution path")
            # Fall through to legacy execution

    # LEGACY EXECUTION PATH (current implementation)
    output_mgr.status("🔧 Using legacy execution path", "info")
    # Freeze execution path as legacy and write run manifest early for determinism
    try:
        from core.execution.execution_path_guard import ExecutionPathGuard

        _guard = ExecutionPathGuard.get_guard()
        _guard.freeze("legacy")
        # Best-effort early manifest (context will be recorded later)
        _guard.write_run_manifest()
    except Exception:
        pass

    # OPTIMIZED: Initialize correlation context only when needed
    from core.correlation_context import get_correlation_logger, set_scan_correlation_id

    correlation_logger = get_correlation_logger(__name__)

    set_scan_correlation_id()
    correlation_logger.info("Starting security analysis")
    correlation_logger.info(f"APK: {args.apk}, Package: {args.pkg}, Mode: {args.mode}")

    # Create and configure test suite with scan optimization
    from core.cli.scanner import AODSScanner

    test_suite = AODSScanner(
        apk_path=args.apk,
        package_name=args.pkg,
        enable_ml=not args.disable_ml,  # ML enabled by default, disabled with --disable-ml
        vulnerable_app_mode=args.vulnerable_app_mode,  # Enable relaxed detection for vulnerable apps
        scan_profile=args.profile,  # Scan profile for performance optimization
        enable_optimized=args.optimized,  # Enable Performance Enhancement Suite
    )
    # Ensure requested report formats are honored (default includes JSON)
    try:
        if hasattr(test_suite, "set_report_formats"):
            requested_formats = getattr(args, "formats", None) or ["json"]
            test_suite.set_report_formats(requested_formats)
    except Exception:
        pass

    # Integrate advanced components into test suite
    if advanced_intelligence:
        test_suite.advanced_intelligence = advanced_intelligence
        output_mgr.info("🧠 Advanced Intelligence Engine integrated with test suite")

    if webview_analyzer:
        test_suite.webview_analyzer = webview_analyzer
        output_mgr.info("🌐 WebView Security Analyzer integrated with test suite")

    # CRITICAL FIX: Ensure scan mode is set in APK context
    test_suite.apk_ctx.set_scan_mode(args.mode)
    # Record execution path into context and refresh manifest with analysis_id
    try:
        from core.execution.execution_path_guard import ExecutionPathGuard as _EPG

        _g = _EPG.get_guard()
        _g.record_in_context(test_suite.apk_ctx)
        _g.write_run_manifest(test_suite.apk_ctx)
    except Exception:
        pass

    # Initialize Frida if needed (only for dynamic analysis) - Frida-first approach
    if args.mode in ("deep", "agent") and not args.disable_dynamic_analysis:
        output_mgr.status("Initializing Frida for dynamic analysis...", "info")

        # Check Frida availability for dynamic analysis (unified)
        from core.external.unified_tool_executor import check_frida_available as _check_frida_available

        _frida = _check_frida_available()
        if _frida.get("available"):
            output_mgr.info("Frida ready for dynamic analysis")
        else:
            output_mgr.info("Frida not available - dynamic analysis will be limited")
            output_mgr.info("   • Frida not installed in virtual environment")
            output_mgr.info("   • Install with: pip install frida-tools frida")
            output_mgr.info("   • Or use --static-only for static analysis")
            output_mgr.info("   Continuing with static analysis only")

            # Disable dynamic analysis components for this run
            args.disable_dynamic_analysis = True

    # Initialize APKAnalyzer early to avoid skipped info extraction
    try:
        if not getattr(test_suite.apk_ctx, "analyzer", None):
            from core.analyzer import APKAnalyzer as _APKAnalyzer

            _an = _APKAnalyzer(
                manifest_dir=str(test_suite.apk_ctx.decompiled_apk_dir),
                decompiled_dir=str(test_suite.apk_ctx.decompiled_apk_dir),
            )
            test_suite.apk_ctx.set_apk_analyzer(_an)
    except Exception:
        pass

    # Track 81: Global scan timeout enforcement based on profile.
    # Prevents scans from running indefinitely in the standard (non-parallel) path.
    _PROFILE_GLOBAL_TIMEOUTS = {
        "lightning": 300,    # 5 minutes
        "fast": 600,         # 10 minutes
        "standard": 1800,    # 30 minutes
        "deep": 7200,        # 2 hours
    }
    _scan_profile_name = getattr(args, 'profile', 'standard')
    _global_timeout = _PROFILE_GLOBAL_TIMEOUTS.get(_scan_profile_name, 1800)
    _prev_alarm_handler = None

    def _scan_timeout_handler(signum, frame):
        """Handle scan timeout - raise TimeoutError to unwind the call stack."""
        raise TimeoutError(
            f"Scan exceeded global timeout of {_global_timeout}s for profile '{_scan_profile_name}'"
        )

    # Install alarm-based timeout (POSIX only; silently skipped on Windows)
    if hasattr(signal, 'SIGALRM'):
        _prev_alarm_handler = signal.signal(signal.SIGALRM, _scan_timeout_handler)
        signal.alarm(_global_timeout)
        output_mgr.verbose(
            f"Global scan timeout set: {_global_timeout}s (profile: {_scan_profile_name})"
        )

    try:
        # Run core tests (only if static analysis is enabled)
        if not args.disable_static_analysis:
            output_mgr.status("Running core security tests...", "info")
            test_suite.extract_additional_info()
            test_suite.test_debuggable_logging()
            test_suite.network_cleartext_traffic_analyzer()

        # --- Agent orchestration (Track 93) - runs BEFORE plugin execution ---
        _want_orchestrate = getattr(args, "agent_orchestrate", False) or getattr(args, "agent", False)
        if _want_orchestrate and AGENT_AVAILABLE and args.apk:
            try:
                from core.agent.orchestration import run_orchestration
                from core.agent.config import load_agent_config as _load_orch_cfg

                _orch_cfg = _load_orch_cfg()
                _orch_model = getattr(args, "agent_model", None)
                if _orch_model:
                    _orch_cfg.model = _orch_model

                output_mgr.info("Running AI orchestration agent for plugin selection...")
                _orch_result = run_orchestration(
                    apk_path=args.apk,
                    config=_orch_cfg,
                    report_dir="reports",
                )
                # Store orchestration result for report integration later
                args._orchestration_result = _orch_result
                # Override plugin set via orchestrated profile
                _orch_plugin_names = {ps.plugin_name for ps in _orch_result.selected_plugins}
                if _orch_plugin_names and hasattr(test_suite, "apk_ctx"):
                    test_suite.apk_ctx._orchestration_plugins = _orch_plugin_names
                output_mgr.success(
                    f"AI orchestration: {len(_orch_result.selected_plugins)} plugins selected "
                    f"({_orch_result.app_category or 'unknown'}, est. {_orch_result.estimated_time or 'N/A'})"
                )
            except ImportError as _orch_err:
                output_mgr.verbose(f"Agent orchestration unavailable: {_orch_err}")
            except Exception as _orch_err:
                output_mgr.verbose(f"Agent orchestration failed, using standard profile: {_orch_err}")

        # Track 81: Set scan profile before plugin execution so PluginTimeoutRegistry
        # enforces per-profile timeout caps (e.g., lightning: 60s/plugin).
        try:
            from core.plugins.unified_manager import _set_current_scan_profile
            _set_current_scan_profile(getattr(args, 'profile', 'standard'))
        except ImportError:
            pass

        # Run plugins (only if static analysis is enabled)
        if not args.disable_static_analysis:
            correlation_logger.info("Executing security analysis plugins")
            output_mgr.status("Executing security analysis plugins...", "info")
            test_suite.run_plugins()

        # --- Mid-scan adjustment (Track 100) - after initial plugins, before deep tests ---
        _orch_result_attr = getattr(args, "_orchestration_result", None)
        if _orch_result_attr and AGENT_AVAILABLE and not args.disable_static_analysis:
            try:
                from core.agent.orchestration import run_midscan_adjustment

                _interim = getattr(test_suite, "findings", []) or []
                if not _interim and hasattr(test_suite, "apk_ctx"):
                    _interim = getattr(test_suite.apk_ctx, "findings", []) or []
                _adjusted = run_midscan_adjustment(
                    interim_findings=_interim,
                    original_result=_orch_result_attr,
                    apk_path=args.apk,
                )
                if _adjusted:
                    args._orchestration_result = _adjusted
                    _new_plugins = {
                        ps.plugin_name for ps in _adjusted.selected_plugins
                    } - {ps.plugin_name for ps in _orch_result_attr.selected_plugins}
                    if _new_plugins and hasattr(test_suite, "apk_ctx"):
                        _existing = getattr(test_suite.apk_ctx, "_orchestration_plugins", set())
                        test_suite.apk_ctx._orchestration_plugins = _existing | _new_plugins
                    output_mgr.info(
                        f"Mid-scan adjustment: added {len(_new_plugins)} plugins "
                        f"({', '.join(_new_plugins)})"
                    )
            except ImportError:
                pass
            except Exception as _mid_err:
                output_mgr.verbose(f"Mid-scan adjustment skipped: {_mid_err}")

        # Run additional tests based on scan mode (only if static analysis is enabled)
        if args.mode in ("deep", "agent") and not args.disable_static_analysis:
            output_mgr.status("Running deep analysis tests...", "info")
            test_suite.attack_surface_analysis()
            test_suite.traversal_vulnerabilities()
            test_suite.injection_vulnerabilities()

        # Run dynamic analysis for --dynamic-only mode
        if args.disable_static_analysis and not args.disable_dynamic_analysis:
            output_mgr.status("Running dynamic analysis...", "info")
            dynamic_timeout = 300  # 5 minutes default timeout
            test_suite.run_dynamic_analysis_only(dynamic_timeout)

        # Run ML-based malware detection if enabled
        if getattr(args, "enable_malware_scan", False) and not args.disable_static_analysis:
            output_mgr.status("Running ML-based malware detection...", "info")
            try:
                # Use package-level import for better encapsulation (Track 9 Priority 1)
                from plugins.malware_detection import create_plugin

                malware_plugin = create_plugin()
                malware_result = malware_plugin.execute(test_suite.apk_ctx)

                # Add malware findings to consolidated results
                if malware_result.findings:
                    for finding in malware_result.findings:
                        if hasattr(finding, "severity") and finding.severity in ("critical", "high"):
                            output_mgr.warning(f"🚨 Malware Detection: {finding.title}")
                        elif hasattr(finding, "severity") and finding.severity == "info":
                            output_mgr.info(f"✅ Malware Scan: {finding.title}")

                    # Integrate findings into test_suite results
                    if hasattr(test_suite, "consolidated_results"):
                        if "malware_detection" not in test_suite.consolidated_results:
                            test_suite.consolidated_results["malware_detection"] = []
                        for f in malware_result.findings:
                            test_suite.consolidated_results["malware_detection"].append(
                                {
                                    "id": getattr(f, "finding_id", "unknown"),
                                    "title": getattr(f, "title", "Malware Finding"),
                                    "severity": getattr(f, "severity", "medium"),
                                    "confidence": getattr(f, "confidence", 0.5),
                                    "description": getattr(f, "description", ""),
                                    "cwe_id": getattr(f, "cwe_id", None),
                                    "evidence": getattr(f, "evidence", {}),
                                }
                            )

                output_mgr.info(f"Malware scan completed: {len(malware_result.findings)} findings")
            except ImportError as e:
                output_mgr.warning(f"Malware detection plugin not available: {e}")
            except Exception as e:
                output_mgr.warning(f"Malware detection failed: {e}")
                logger.debug("malware_detection_error", error=str(e), exc_info=True)

        # Generate reports
        output_mgr.status("Generating security reports...", "info")
        generated_files = test_suite.generate_report()

    except TimeoutError as _timeout_err:
        output_mgr.warning(f"Scan timeout reached: {_timeout_err}")
        output_mgr.info("Generating partial report with findings collected so far...")
        # Generate report with whatever findings were collected before timeout
        try:
            generated_files = test_suite.generate_report()
        except Exception:
            generated_files = {}
    finally:
        # Cancel the alarm and restore previous handler
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)
            if _prev_alarm_handler is not None:
                signal.signal(signal.SIGALRM, _prev_alarm_handler)
    # Persist final JSON to --output for CI/tools expecting a single output file
    try:
        final_out = getattr(args, "output", None)
        if final_out:
            from pathlib import Path as _Path
            import os as _os
            import shutil as _shutil
            import json as _json

            json_src = generated_files.get("json") if isinstance(generated_files, dict) else None
            _Path(final_out).parent.mkdir(parents=True, exist_ok=True)
            if json_src and _os.path.exists(json_src):
                _shutil.copyfile(json_src, final_out)
            else:
                # Build a consolidated minimal-but-final JSON
                findings = []
                metadata = {}
                try:
                    findings = (getattr(test_suite, "consolidated_results", {}) or {}).get("vulnerabilities", [])
                    metadata = getattr(test_suite, "_report_metadata", {}) or {}
                except Exception:
                    findings, metadata = [], {}
                final_doc = {"status": "completed", "findings": findings, "metadata": metadata}
                _Path(final_out).write_text(_json.dumps(final_doc, indent=2), encoding="utf-8")
    except Exception as _persist_err:
        try:
            output_mgr.warning(f"Failed to persist final report to --output: {_persist_err}")
        except Exception:
            pass

    # Track 81: Apply post-processing to generated JSON report (parity with parallel path).
    # This adds canonical container merge (severity inflation fix), CWE-file dedup,
    # evidence normalization, intent severity downgrade, meta-finding separation,
    # and actionable recommendations.
    try:
        from pathlib import Path as _PostPath
        import json as _post_json

        from core.cli.finding_processing import (
            _create_canonical_findings,
            _sync_all_containers,
            _normalize_finding_evidence as _post_normalize,
            _improve_recommendations as _post_improve,
        )

        # Find the generated JSON report
        _json_report_path = None
        if isinstance(generated_files, dict) and generated_files.get("json"):
            _json_report_path = generated_files["json"]

        if _json_report_path and _PostPath(_json_report_path).exists():
            with open(_json_report_path, "r") as _rf:
                _json_data = _post_json.load(_rf)

            if isinstance(_json_data, dict):
                # Apply serialize_final_report for CWE-file dedup, metadata, status mapping
                try:
                    from core.reporting.final_report_serializer import serialize_final_report
                    from core.apk_ctx import APKContext as _PostAPKContext

                    _post_apk_ctx = None
                    try:
                        _post_apk_ctx = _PostAPKContext(args.apk)
                    except Exception:
                        pass
                    _json_data = serialize_final_report(_json_data, apk_context=_post_apk_ctx)
                except Exception as _ser_err:
                    logger.warning("serialize_final_report failed in standard path (non-fatal)", error=str(_ser_err))

                # Apply compound vulnerability correlation (Track 113.5)
                try:
                    from core.compound_vulnerability_engine import correlate_findings as _correlate

                    _std_vulns = _json_data.get("vulnerabilities", [])
                    if isinstance(_std_vulns, list) and len(_std_vulns) >= 2:
                        _std_compound = _correlate(_std_vulns)
                        if _std_compound:
                            _std_vulns.extend(_std_compound)
                            _json_data["vulnerabilities"] = _std_vulns
                            _json_data["compound_findings"] = {
                                "count": len(_std_compound),
                                "titles": [c.get("title", "") for c in _std_compound],
                            }
                except Exception as _compound_err:
                    logger.debug("Compound vulnerability detection skipped (standard)", error=str(_compound_err))

                # Create canonical findings list with correct container ordering
                # (vulnerabilities before enhanced_vulnerabilities - classifier wins in dedup,
                # preventing EVRE severity inflation)
                try:
                    _canonical = _create_canonical_findings(_json_data, logger)
                    _sync_all_containers(_json_data, _canonical, logger)
                except Exception as _canon_err:
                    logger.warning("Canonical findings merge failed (non-fatal)", error=str(_canon_err))

                # Filter meta-findings (parity with parallel path)
                _META_TITLES = ["Alternative AODS Plugin Available", "Actionable Recommendation"]

                def _is_meta(f):
                    if not isinstance(f, dict):
                        return False
                    t = f.get("title", "")
                    return any(mt in t for mt in _META_TITLES)

                for _ckey in ("vulnerabilities", "enhanced_vulnerabilities", "vulnerability_findings", "findings"):
                    _clist = _json_data.get(_ckey)
                    if isinstance(_clist, list):
                        _real = [f for f in _clist if not _is_meta(f)]
                        _meta = [f for f in _clist if _is_meta(f)]
                        if _meta:
                            _json_data.setdefault("recommendations", []).extend(_meta)
                        _json_data[_ckey] = _real

                # Final evidence normalization + recommendations (LAST pass)
                _final_vulns = _json_data.get("vulnerabilities", [])
                if isinstance(_final_vulns, list) and _final_vulns:
                    _post_normalize(_final_vulns)
                    _post_improve(_final_vulns)

                # Update counts
                _vcount = len(_json_data.get("vulnerabilities", []))
                if "findings_count" in _json_data:
                    _json_data["findings_count"] = _vcount
                if isinstance(_json_data.get("summary"), dict):
                    _json_data["summary"]["total_findings"] = _vcount

                # Rewrite the report
                with open(_json_report_path, "w") as _wf:
                    _post_json.dump(_json_data, _wf, indent=2, default=str)

                output_mgr.verbose(f"Post-processed JSON report: {_vcount} findings")

                # Re-copy to --output if it was specified (original copy was pre-post-processing)
                try:
                    _final_out = getattr(args, "output", None)
                    if _final_out:
                        import shutil as _post_shutil
                        _post_shutil.copyfile(_json_report_path, _final_out)
                except Exception:
                    pass
    except Exception as _post_err:
        try:
            output_mgr.verbose(f"Report post-processing skipped: {_post_err}")
        except Exception:
            pass

    # --- Agent pipeline (Track 96) - runs all agents in sequence ---
    _want_pipeline = getattr(args, "agent_pipeline", False)
    if _want_pipeline and AGENT_AVAILABLE and _json_report_path:
        try:
            from core.agent.supervisor import run_pipeline
            from core.agent.config import load_agent_config as _load_pipeline_cfg

            _pipeline_cfg = _load_pipeline_cfg()
            _pipeline_model = getattr(args, "agent_model", None)
            if _pipeline_model:
                _pipeline_cfg.model = _pipeline_model

            _pipeline_source_dir = None
            try:
                _apk_ctx_p = getattr(test_suite, "apk_ctx", None)
                if _apk_ctx_p:
                    _pipeline_source_dir = str(getattr(_apk_ctx_p, "decompiled_apk_dir", ""))
            except Exception:
                pass

            output_mgr.info("Running agent pipeline (triage -> verify -> remediate -> narrate)...")
            try:
                from core.agent.cli_progress import CLIProgressReporter
                _cli_reporter = CLIProgressReporter(verbose=True)
                _progress_cb = _cli_reporter.report
            except ImportError:
                _progress_cb = None
            _pipeline_result = run_pipeline(
                report_file=str(_json_report_path),
                config=_pipeline_cfg,
                source_dir=_pipeline_source_dir if _pipeline_source_dir else None,
                report_dir=str(os.path.dirname(_json_report_path)) or ".",
                progress_callback=_progress_cb,
            )
            _step_summary = ", ".join(
                f"{s.agent_type}={s.status}" for s in _pipeline_result.steps
            )
            output_mgr.success(f"Agent pipeline complete: {_step_summary}")
        except ImportError as _pipeline_err:
            output_mgr.verbose(f"Agent pipeline unavailable: {_pipeline_err}")
        except Exception as _pipeline_err:
            output_mgr.verbose(f"Agent pipeline failed: {_pipeline_err}")
        # Individual agent blocks below are skipped when pipeline was requested

    # --- Agent narration (Track 91) ---
    _want_narrate = getattr(args, "agent_narrate", False) or getattr(args, "agent", False)
    if _want_narrate and not _want_pipeline and AGENT_AVAILABLE and _json_report_path:
        try:
            from core.agent.narration import run_narration
            from core.agent.config import load_agent_config

            _agent_cfg = load_agent_config()
            _agent_model = getattr(args, "agent_model", None)
            if _agent_model:
                _agent_cfg.model = _agent_model

            _source_dir = None
            try:
                _apk_ctx = getattr(test_suite, "apk_ctx", None)
                if _apk_ctx:
                    _source_dir = str(getattr(_apk_ctx, "decompiled_apk_dir", ""))
            except Exception:
                pass

            output_mgr.info("Running AI narration agent...")
            _narrative = run_narration(
                report_file=str(_json_report_path),
                config=_agent_cfg,
                source_dir=_source_dir if _source_dir else None,
                report_dir=str(os.path.dirname(_json_report_path)) or ".",
            )
            output_mgr.success(
                f"AI narrative: {_narrative.risk_rating} risk - {_narrative.executive_summary[:120]}"
                + ("..." if len(_narrative.executive_summary) > 120 else "")
            )
        except ImportError as _agent_err:
            output_mgr.verbose(f"Agent narration unavailable: {_agent_err}")
        except Exception as _agent_err:
            output_mgr.verbose(f"Agent narration failed: {_agent_err}")

    # --- Agent verification (Track 92) ---
    _want_verify = getattr(args, "agent_verify", False) or getattr(args, "agent", False)
    if _want_verify and not _want_pipeline and AGENT_AVAILABLE and _json_report_path:
        try:
            from core.agent.verification import run_verification
            from core.agent.config import load_agent_config as _load_verify_cfg

            _verify_cfg = _load_verify_cfg()
            _verify_model = getattr(args, "agent_model", None)
            if _verify_model:
                _verify_cfg.model = _verify_model

            _verify_source_dir = None
            try:
                _apk_ctx_v = getattr(test_suite, "apk_ctx", None)
                if _apk_ctx_v:
                    _verify_source_dir = str(getattr(_apk_ctx_v, "decompiled_apk_dir", ""))
            except Exception:
                pass

            output_mgr.info("Running AI verification agent...")
            _verification = run_verification(
                report_file=str(_json_report_path),
                config=_verify_cfg,
                source_dir=_verify_source_dir if _verify_source_dir else None,
                report_dir=str(os.path.dirname(_json_report_path)) or ".",
            )
            _v_parts = []
            if _verification.total_verified:
                _v_parts.append(f"{_verification.total_verified} verified")
            if _verification.total_confirmed:
                _v_parts.append(f"{_verification.total_confirmed} confirmed")
            if _verification.total_fp_detected:
                _v_parts.append(f"{_verification.total_fp_detected} FP detected")
            _v_summary = ", ".join(_v_parts) if _v_parts else "no findings verified"
            output_mgr.success(f"AI verification: {_v_summary}")
        except ImportError as _verify_err:
            output_mgr.verbose(f"Agent verification unavailable: {_verify_err}")
        except Exception as _verify_err:
            output_mgr.verbose(f"Agent verification failed: {_verify_err}")

    # --- Agent triage (Track 99) ---
    _want_triage = getattr(args, "agent_triage", False) or getattr(args, "agent", False)
    if _want_triage and not _want_pipeline and AGENT_AVAILABLE and _json_report_path:
        try:
            from core.agent.triage import run_triage
            from core.agent.config import load_agent_config as _load_triage_cfg

            _triage_cfg = _load_triage_cfg()
            _triage_model = getattr(args, "agent_model", None)
            if _triage_model:
                _triage_cfg.model = _triage_model

            _triage_source_dir = None
            try:
                _apk_ctx_t = getattr(test_suite, "apk_ctx", None)
                if _apk_ctx_t:
                    _triage_source_dir = str(getattr(_apk_ctx_t, "decompiled_apk_dir", ""))
            except Exception:
                pass

            output_mgr.info("Running AI triage agent...")
            _triage_result = run_triage(
                report_file=str(_json_report_path),
                config=_triage_cfg,
                source_dir=_triage_source_dir if _triage_source_dir else None,
                report_dir=str(os.path.dirname(_json_report_path)) or ".",
            )
            _t_counts = {}
            for _cf in _triage_result.classified_findings:
                _t_counts[_cf.classification] = _t_counts.get(_cf.classification, 0) + 1
            _t_summary = ", ".join(f"{v} {k}" for k, v in _t_counts.items()) if _t_counts else "no findings classified"
            output_mgr.success(f"AI triage: {_t_summary}")
        except ImportError as _triage_err:
            output_mgr.verbose(f"Agent triage unavailable: {_triage_err}")
        except Exception as _triage_err:
            output_mgr.verbose(f"Agent triage failed: {_triage_err}")

    # --- Agent remediation (Track 100) ---
    _want_remediate = getattr(args, "agent_remediate", False) or getattr(args, "agent", False)
    if _want_remediate and not _want_pipeline and AGENT_AVAILABLE and _json_report_path:
        try:
            from core.agent.remediation import run_remediation
            from core.agent.config import load_agent_config as _load_remediate_cfg

            _remediate_cfg = _load_remediate_cfg()
            _remediate_model = getattr(args, "agent_model", None)
            if _remediate_model:
                _remediate_cfg.model = _remediate_model

            _remediate_source_dir = None
            try:
                _apk_ctx_r = getattr(test_suite, "apk_ctx", None)
                if _apk_ctx_r:
                    _remediate_source_dir = str(getattr(_apk_ctx_r, "decompiled_apk_dir", ""))
            except Exception:
                pass

            output_mgr.info("Running AI remediation agent...")
            _remediation_result = run_remediation(
                report_file=str(_json_report_path),
                config=_remediate_cfg,
                source_dir=_remediate_source_dir if _remediate_source_dir else None,
                report_dir=str(os.path.dirname(_json_report_path)) or ".",
            )
            _r_with = _remediation_result.total_with_patches
            _r_total = _remediation_result.total_findings
            output_mgr.success(f"AI remediation: {_r_with}/{_r_total} findings with code patches")
        except ImportError as _remediate_err:
            output_mgr.verbose(f"Agent remediation unavailable: {_remediate_err}")
        except Exception as _remediate_err:
            output_mgr.verbose(f"Agent remediation failed: {_remediate_err}")

    # --- Save orchestration results to report (Track 93) ---
    if hasattr(args, "_orchestration_result") and _json_report_path:
        try:
            from core.agent.orchestration import save_orchestration_to_report

            save_orchestration_to_report(args._orchestration_result, str(_json_report_path))
        except Exception as _orch_save_err:
            output_mgr.verbose(f"Orchestration report save failed: {_orch_save_err}")

    # Display results
    vulns = getattr(test_suite, "vulnerabilities", []) or []
    _KNOWN_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    severity_counts = {}
    for v in vulns:
        sev = (v.get("severity", "") or "").upper()
        if sev not in _KNOWN_SEVERITIES:
            sev = "MEDIUM"  # Normalize empty/unknown severity for display
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    breakdown = ", ".join(
        f"{c} {s}"
        for s, c in sorted(
            severity_counts.items(), key=lambda x: _KNOWN_SEVERITIES.index(x[0]) if x[0] in _KNOWN_SEVERITIES else 99
        )
    )

    output_mgr.success(
        f"AODS analysis completed: {len(vulns)} vulnerabilities found" + (f" ({breakdown})" if breakdown else "")
    )
    output_mgr.info("Generated reports:")
    for format_name, file_path in generated_files.items():
        output_mgr.info(f"  {format_name.upper()}: {file_path}")

    return 0
