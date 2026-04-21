"""
core.cli.execution_parallel - Parallel scan execution extracted from run_main (Track 50).
"""

import datetime
import os
import time
import json
import logging
import asyncio

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from core.apk_ctx import APKContext

from core.cli import REPO_ROOT
from core.cli.feature_flags import (
    UNIFIED_THREAT_INTEL_AVAILABLE,
    ENHANCED_ORCHESTRATOR_AVAILABLE,
    ENHANCED_PARALLEL_AVAILABLE,
    SCAN_ORCHESTRATOR_AVAILABLE,
    BUSINESS_DOMAIN_DETECTION_AVAILABLE,
    AGENT_AVAILABLE,
)

try:
    from core.cli.feature_flags import EnhancedScanOrchestrator
    from core.enhanced_scan_orchestrator import ScanType as OrchestratorScanType
except ImportError:
    pass
try:
    pass
except ImportError:
    pass
try:
    from core.cli.feature_flags import get_unified_threat_intelligence
except ImportError:
    pass

from core.cli.finding_processing import (
    _is_valid_finding_title,
    _parse_vulnerabilities_from_text_report,
    _create_canonical_findings,
    _sync_all_containers,
    _normalize_finding_evidence,
    _improve_recommendations,
)
from core.cli.utilities import (
    EmergencyPluginManager,
)

_VALID_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})


def _safe_normalize_severity(value) -> str:
    """Normalize severity to uppercase string, tolerating floats, ints, enums, and None."""
    if value is None:
        return "MEDIUM"
    # Handle enums (.value returns the string)
    if hasattr(value, "value"):
        value = value.value
    s = str(value).strip().upper()
    if s in _VALID_SEVERITIES:
        return s
    return "MEDIUM"


# Canonical FP reduction (Track 112 - replaces 7-system coordinator)
try:
    from core.fp_reducer import reduce_false_positives as _reduce_fps

    CANONICAL_FP_AVAILABLE = True
except ImportError:
    CANONICAL_FP_AVAILABLE = False


def _run_agents_on_parallel_report(args, output_file: str, output_mgr) -> None:
    """Run requested agents on the completed parallel scan report.

    Mirrors the agent blocks in execution_standard.py.  All failures are
    caught and logged - agent errors must never block the scan.
    """
    if not AGENT_AVAILABLE or not output_file:
        return

    _want_pipeline = getattr(args, "agent_pipeline", False)
    _want_any = getattr(args, "agent", False)
    _report_dir = os.path.dirname(output_file) or "."

    # --- Pipeline ---
    if _want_pipeline:
        try:
            from core.agent.supervisor import run_pipeline
            from core.agent.config import load_agent_config

            _cfg = load_agent_config()
            _model = getattr(args, "agent_model", None)
            if _model:
                _cfg.model = _model

            output_mgr.info("Running agent pipeline (triage -> verify -> remediate -> narrate)...")
            try:
                from core.agent.cli_progress import CLIProgressReporter
                _cli_rpt = CLIProgressReporter(verbose=True)
                _pcb = _cli_rpt.report
            except ImportError:
                _pcb = None
            _result = run_pipeline(report_file=output_file, config=_cfg, report_dir=_report_dir, progress_callback=_pcb)
            _summary = ", ".join(f"{s.agent_type}={s.status}" for s in _result.steps)
            output_mgr.success(f"Agent pipeline complete: {_summary}")
        except Exception as _err:
            output_mgr.verbose(f"Agent pipeline failed (non-fatal): {_err}")
        return  # pipeline runs all agents - skip individual blocks

    # --- Individual agents ---
    _want_triage = getattr(args, "agent_triage", False) or _want_any
    if _want_triage:
        try:
            from core.agent.triage import run_triage
            from core.agent.config import load_agent_config as _lac

            _cfg = _lac()
            _model = getattr(args, "agent_model", None)
            if _model:
                _cfg.model = _model
            output_mgr.info("Running AI triage agent...")
            _triage = run_triage(report_file=output_file, config=_cfg, report_dir=_report_dir)
            _counts = {}
            for _cf in _triage.classified_findings:
                _counts[_cf.classification] = _counts.get(_cf.classification, 0) + 1
            _ts = ", ".join(f"{v} {k}" for k, v in _counts.items()) if _counts else "no findings classified"
            output_mgr.success(f"AI triage: {_ts}")
        except Exception as _err:
            output_mgr.verbose(f"Agent triage failed (non-fatal): {_err}")

    _want_narrate = getattr(args, "agent_narrate", False) or _want_any
    if _want_narrate:
        try:
            from core.agent.narration import run_narration
            from core.agent.config import load_agent_config as _lac2

            _cfg = _lac2()
            _model = getattr(args, "agent_model", None)
            if _model:
                _cfg.model = _model
            output_mgr.info("Running AI narration agent...")
            _narrative = run_narration(report_file=output_file, config=_cfg, report_dir=_report_dir)
            output_mgr.success(f"AI narrative: {_narrative.risk_rating} risk")
        except Exception as _err:
            output_mgr.verbose(f"Agent narration failed (non-fatal): {_err}")

    _want_remediate = getattr(args, "agent_remediate", False) or _want_any
    if _want_remediate:
        try:
            from core.agent.remediation import run_remediation
            from core.agent.config import load_agent_config as _lac3

            _cfg = _lac3()
            _model = getattr(args, "agent_model", None)
            if _model:
                _cfg.model = _model
            output_mgr.info("Running AI remediation agent...")
            _rem = run_remediation(report_file=output_file, config=_cfg, report_dir=_report_dir)
            output_mgr.success(f"AI remediation: {_rem.total_with_patches}/{_rem.total_findings} with patches")
        except Exception as _err:
            output_mgr.verbose(f"Agent remediation failed (non-fatal): {_err}")


def run_parallel_execution(ctx) -> int:
    """Run parallel scan execution path.

    Contains the parallel scan logic from run_main() lines 622-2645.

    Args:
        ctx: ExecutionContext from initialize_execution().

    Returns:
        Exit code (0 on success).
    """
    args = ctx.args
    output_mgr = ctx.output_mgr
    config_data = ctx.config_data
    AODS_CANONICAL = ctx.aods_canonical

    if args.parallel_scan:
        # CRITICAL FIX: Process scan type flags BEFORE parallel execution
        scan_types_to_run = []

        # Check for dynamic-only and static-only flags
        if args.dynamic_only:
            args.disable_static_analysis = True
            args.mode = "deep"  # Dynamic analysis requires deep mode
            scan_types_to_run = ["dynamic"]
            output_mgr.info("🎯 Parallel Scan Manager: DYNAMIC-ONLY mode activated (deep mode)")
            output_mgr.info("🔧 Auto-setting mode to 'deep' for dynamic analysis")
        elif args.static_only:
            args.disable_dynamic_analysis = True
            scan_types_to_run = ["static"]
            # CRITICAL FIX: Set environment variables so policy enforcement works
            os.environ["AODS_STATIC_ONLY"] = "1"
            os.environ["AODS_STATIC_ONLY_HARD"] = "1"
            output_mgr.info("🎯 Parallel Scan Manager: STATIC-ONLY mode activated")
            output_mgr.info("🔒 Static-only enforcement enabled (Frida/ADB blocked)")
        elif args.disable_static_analysis:
            scan_types_to_run = ["dynamic"]
            output_mgr.info("🎯 Parallel Scan Manager: Dynamic analysis only (static disabled)")
        elif args.disable_dynamic_analysis:
            scan_types_to_run = ["static"]
            output_mgr.info("🎯 Parallel Scan Manager: Static analysis only (dynamic disabled)")
        else:
            scan_types_to_run = ["static", "dynamic"]
            output_mgr.info("🎯 Parallel Scan Manager: Full static + dynamic execution")

        output_mgr.info(f"Using Parallel Scan Manager for separate execution: {', '.join(scan_types_to_run)}")

        try:
            # PERMANENT FIX: Use EnhancedScanOrchestrator for configure_scan method
            if ENHANCED_ORCHESTRATOR_AVAILABLE:
                logger.debug("Using EnhancedScanOrchestrator for unified orchestration")
                orchestrator = EnhancedScanOrchestrator(args.apk)

                # Prepare scan configuration for unified framework
                scan_config = {
                    "package_name": args.pkg,
                    "mode": getattr(args, "mode", "safe"),
                    "profile": getattr(
                        args, "profile", "standard"
                    ),  # CRITICAL: Pass scan profile for plugin optimization
                    "vulnerable_app_mode": getattr(args, "vulnerable_app_mode", False),
                    "static_timeout": getattr(args, "static_timeout", 1800),
                    "dynamic_timeout": getattr(args, "dynamic_timeout", 1800),
                    "consolidate": True,
                    "scan_types": scan_types_to_run,
                    "disable_static_analysis": getattr(args, "disable_static_analysis", False),
                    "disable_dynamic_analysis": getattr(args, "disable_dynamic_analysis", False),
                    "objection_context": getattr(args, "objection_context", None),
                }

                # PERMANENT FIX: Execute through unified orchestrator with error handling
                try:
                    # CRITICAL FIX: Determine scan type based on flags first, then mode
                    if args.dynamic_only or getattr(args, "disable_static_analysis", False):
                        scan_type = OrchestratorScanType.DYNAMIC_ONLY
                        output_mgr.info("🎯 Orchestrator: Using DYNAMIC_ONLY scan type")
                    elif args.static_only or getattr(args, "disable_dynamic_analysis", False):
                        scan_type = OrchestratorScanType.STATIC_ONLY
                        output_mgr.info("🎯 Orchestrator: Using STATIC_ONLY scan type")
                    else:
                        # Use mode-based mapping for full scans
                        scan_type_map = {
                            "lightning": OrchestratorScanType.STATIC_ONLY,
                            "fast": OrchestratorScanType.STATIC_ONLY,
                            "standard": OrchestratorScanType.FULL_SCAN,  # FIXED: Use FULL_SCAN not FULL
                            "deep": OrchestratorScanType.INTELLIGENT,
                        }
                        scan_type = scan_type_map.get(args.mode, OrchestratorScanType.FULL_SCAN)
                        output_mgr.info(f"🎯 Orchestrator: Using {scan_type.value} scan type for mode '{args.mode}'")

                    # Configure the orchestrator
                    # PERFORMANCE FIX: Pass args.profile (lightning/fast/standard/deep) not args.mode (safe/deep)
                    scan_profile = getattr(args, "profile", None) or args.mode
                    if orchestrator.configure_scan(scan_type, scan_config, scan_profile):
                        results = orchestrator.execute_scan()
                        # PERMANENT FIX: Debug logging for orchestration results
                        output_mgr.debug(
                            f"Orchestrator returned: {type(results)} with keys: {list(results.keys()) if isinstance(results, dict) else 'N/A'}"  # noqa: E501
                        )
                        if isinstance(results, dict) and "status" in results:
                            output_mgr.debug(f"Job status: {results.get('status')}, Job ID: {results.get('job_id')}")
                    else:
                        results = {"success": False, "error": "Failed to configure scan"}
                        output_mgr.error("Orchestrator configuration failed")
                except Exception as orchestration_error:
                    # PERMANENT FIX: Enhanced error reporting with debug details
                    import traceback

                    error_details = traceback.format_exc()
                    output_mgr.error(f"Unified orchestration exception: {orchestration_error}")
                    output_mgr.debug(f"Orchestration error traceback: {error_details}")
                    if os.environ.get("AODS_EXEC_PATH_NO_FALLBACK", "0") == "1":
                        raise
                    output_mgr.info("Falling back to legacy implementation...")
                    # Set results to None to trigger fallback
                    results = None

                # PERMANENT FIX: Handle all orchestrator result formats correctly
                if results is not None and isinstance(results, dict):
                    # Check if this is a direct scan result from orchestrator (new format)
                    if "status" in results and "scan_type" in results and "job_id" in results:
                        scan_status = results.get("status")

                        if scan_status == "completed":
                            # Success case - orchestrator returned scan results directly
                            job_id = results.get("job_id")  # Preserve job_id before transformation
                            unified_results = {
                                "static_result": {
                                    "static_analysis": results.get("static_analysis"),
                                    "findings_count": results.get("findings_count"),
                                    "security_score": results.get("security_score"),
                                },
                                "dynamic_result": {
                                    "dynamic_analysis": results.get("dynamic_analysis"),
                                    "coverage": results.get("coverage"),
                                },
                                "consolidated_results": results,  # Use full results as consolidated
                                "success": True,
                                "total_duration": results.get("execution_time", 0),
                                "job_id": job_id,  # Preserve job_id in unified results
                            }
                            results = unified_results
                            output_mgr.success(f"✅ Unified orchestration completed successfully (Job: {job_id})")
                            # PERMANENT FIX: Success case - continue with results, don't trigger fallback
                        else:
                            # Failed case - extract error from scan result
                            error_msg = results.get("error", f"Scan status: {scan_status}")
                            detailed_error = f"Unified scan orchestration failed: {error_msg}"
                            output_mgr.error(detailed_error)
                            # Fall back to legacy implementation
                            raise ImportError("Unified orchestration failed - scan failed")
                    # Check if this is a job status response from orchestrator (legacy format)
                    elif "status" in results and "result" in results:
                        job_status = results.get("status")
                        job_result = results.get("result", {})

                        if job_status == "completed":
                            # Success case - extract results from job result
                            unified_results = {
                                "static_result": job_result.get("static_results"),
                                "dynamic_result": job_result.get("dynamic_results"),
                                "consolidated_results": job_result.get("consolidated_results"),
                                "success": True,
                                "total_duration": job_result.get("execution_time", 0),
                            }
                            results = unified_results
                            # PERMANENT FIX: Success case - continue with results, don't trigger fallback
                        else:
                            # Failed case - extract error from job result
                            error_msg = job_result.get("error", results.get("error", f"Job status: {job_status}"))
                            success_rate = job_result.get("statistics", {}).get("success_rate", 0.0)
                            total_plugins = job_result.get("statistics", {}).get("total_plugins", 0)
                            successful_plugins = job_result.get("statistics", {}).get("successful_plugins", 0)

                            detailed_error = f"Unified scan orchestration failed: {error_msg}"
                            if total_plugins > 0:
                                detailed_error += f" (Success rate: {success_rate:.1%}, {successful_plugins}/{total_plugins} plugins succeeded)"  # noqa: E501

                            output_mgr.error(detailed_error)
                            # Fall back to legacy implementation
                            raise ImportError("Unified orchestration failed - job failed")
                    elif results.get("success"):
                        # Legacy success format
                        unified_results = {
                            "static_result": results.get("static_results"),
                            "dynamic_result": results.get("dynamic_results"),
                            "consolidated_results": results.get("consolidated_results"),
                            "success": True,
                            "total_duration": results.get("execution_time", 0),
                        }
                        results = unified_results
                        # PERMANENT FIX: Success case - continue with results, don't trigger fallback
                    else:
                        # Legacy error format or unrecognized format
                        error_msg = results.get("error", "Unrecognized result format")
                        success_rate = results.get("statistics", {}).get("success_rate", 0.0)
                        total_plugins = results.get("statistics", {}).get("total_plugins", 0)
                        successful_plugins = results.get("statistics", {}).get("successful_plugins", 0)

                        detailed_error = f"Unified scan orchestration failed: {error_msg}"
                        if total_plugins > 0:
                            detailed_error += f" (Success rate: {success_rate:.1%}, {successful_plugins}/{total_plugins} plugins succeeded)"  # noqa: E501

                        output_mgr.error(detailed_error)
                        # Fall back to legacy implementation
                        raise ImportError("Unified orchestration failed - unrecognized format")
                else:
                    # PERMANENT FIX: Handle non-dict results or None results
                    if results is not None:
                        output_mgr.warning(f"Unified orchestration returned unexpected result type: {type(results)}")
                    if os.environ.get("AODS_EXEC_PATH_NO_FALLBACK", "0") == "1":
                        raise RuntimeError(f"Unified orchestration produced invalid result type: {type(results)}")
                    output_mgr.info("Falling back to legacy implementation...")
                    raise ImportError("Unified orchestration failed - invalid result type")

            else:
                # CRITICAL FIX: Use canonical orchestrator instead of legacy fallback
                logger.debug("Using canonical orchestrator fallback")
                from core.execution.canonical_orchestrator import CanonicalOrchestrator

                orchestrator = CanonicalOrchestrator()

                # Execute using canonical orchestrator with analysis
                results = orchestrator.execute_comprehensive_analysis(args)

            # Convert dataclass results (e.g. CanonicalExecutionResult) to dict
            if results is not None and not isinstance(results, dict):
                try:
                    from dataclasses import asdict, fields as _dc_fields

                    _dc_fields(results)  # raises TypeError if not a dataclass
                    results = asdict(results)
                except TypeError:
                    pass

            # CRITICAL FIX: Store unified results for consolidate_results() access
            logger.debug(
                "Results keys after execution",
                keys=list(results.keys()) if isinstance(results, dict) and results else None,
            )

            # Handle result storage based on which execution path was used
            # PERMANENT FIX: Check if orchestrator produced meaningful results using correct structure
            orchestrator_findings_count = 0
            if results and isinstance(results, dict):
                # Count findings in orchestrator results - check multiple possible locations
                findings = results.get("findings", [])  # Direct findings
                if not findings and "static_result" in results:
                    # Check static result findings
                    static_result = results.get("static_result", {})
                    if isinstance(static_result, dict):
                        findings.extend(static_result.get("findings", []))
                        # Also check findings_count field
                        findings_count = static_result.get("findings_count", 0)
                        if findings_count > 0 and not findings:
                            # Use findings_count as indicator if no actual findings list
                            orchestrator_findings_count = findings_count
                if not findings and "consolidated_results" in results:
                    # Check consolidated results
                    consolidated = results.get("consolidated_results", {})
                    if isinstance(consolidated, dict):
                        findings.extend(consolidated.get("findings", []))
                        findings.extend(consolidated.get("vulnerabilities", []))

                # If we found actual findings, use that count
                if findings:
                    orchestrator_findings_count = len(findings)
                # If orchestrator completed successfully, consider it meaningful even without findings
                elif results.get("success") and orchestrator_findings_count == 0:
                    orchestrator_findings_count = 1  # Mark as meaningful to use orchestrator results

            if SCAN_ORCHESTRATOR_AVAILABLE and "manager" not in locals() and orchestrator_findings_count > 0:
                # Using unified orchestrator - results are already consolidated
                logger.debug("Using unified orchestrator results", findings_count=orchestrator_findings_count)
            else:
                # Orchestrator produced no meaningful results - fall back to traditional manager
                if SCAN_ORCHESTRATOR_AVAILABLE and "manager" not in locals():
                    logger.debug("Orchestrator produced no results, creating traditional manager for main AODS flow")
                    # Create traditional plugin manager to enable main AODS plugin system
                    manager = EmergencyPluginManager()
                    # Set scan profile on the manager for traditional AODS flow
                    if hasattr(manager, "set_scan_profile"):
                        # PERMANENT FIX: Import ScanProfile before using it
                        try:
                            from core.scan_profiles import ScanProfile

                            manager.set_scan_profile(ScanProfile.DEEP if args.mode == "deep" else ScanProfile.LIGHTNING)
                        except ImportError:
                            logger.warning("ScanProfile not available, skipping profile setting")

                # Using legacy manager - store results in manager.scan_results
                if "manager" in locals() and hasattr(manager, "scan_results"):
                    manager.scan_results.update(results)
                    logger.debug("Manager scan_results after update", scan_results=manager.scan_results)

            # Save consolidated results
            if args.output:
                output_file = args.output
            else:
                output_file = f"aods_parallel_{args.pkg}_{int(time.time())}.json"

            # CRITICAL FIX: Use consolidated results with infrastructure vs runtime separation
            consolidated_results = None
            try:
                if SCAN_ORCHESTRATOR_AVAILABLE and "manager" not in locals() and orchestrator_findings_count > 0:
                    # Using unified orchestrator - results are already consolidated
                    logger.debug("Using pre-consolidated results from unified orchestrator")
                    consolidated_results = results.get("consolidated_results", results)
                    logger.info(
                        "Using unified orchestrator consolidated results", findings_count=orchestrator_findings_count
                    )
                else:
                    # Using legacy manager - call consolidate_results
                    if hasattr(manager, "consolidate_results"):
                        logger.debug("Calling manager.consolidate_results()")
                        consolidated_results = manager.consolidate_results()
                        logger.info(
                            "Using consolidated results with infrastructure vs runtime separation",
                            total_findings=consolidated_results.get("statistics", {}).get("total_findings", 0),
                        )
                    else:
                        logger.warning("Manager does not have consolidate_results method")
            except Exception as e:
                logger.warning(
                    "Failed to get consolidated results, falling back to individual scan results", error=str(e)
                )

            # THREAT INTELLIGENCE ENRICHMENT
            if UNIFIED_THREAT_INTEL_AVAILABLE:
                try:
                    logger.info("Enriching results with threat intelligence")
                    threat_intel_system = get_unified_threat_intelligence()

                    # Enrich consolidated results with threat intelligence
                    if consolidated_results and "vulnerabilities" in consolidated_results:
                        enriched_vulns = []
                        for vuln in consolidated_results["vulnerabilities"]:
                            # Correlate with threat intelligence (run synchronously for now)
                            try:
                                loop = asyncio.new_event_loop()
                                asyncio.set_event_loop(loop)
                                correlation_result = loop.run_until_complete(
                                    threat_intel_system.correlate_with_vulnerability(vuln)
                                )
                                loop.close()
                            except Exception as corr_e:
                                logger.warning(
                                    "Correlation failed for vulnerability",
                                    vulnerability_id=vuln.get("id", "unknown"),
                                    error=str(corr_e),
                                )
                                # Create empty correlation result
                                from core.unified_threat_intelligence import ThreatCorrelationResult

                                correlation_result = ThreatCorrelationResult(
                                    vulnerability_id=vuln.get("id", "unknown"),
                                    matched_threats=[],
                                    correlation_confidence=0.0,
                                    risk_assessment="UNKNOWN",
                                    recommended_actions=[],
                                    correlation_reasoning="Correlation failed",
                                )

                            # Add threat intelligence data to vulnerability
                            vuln["threat_intelligence"] = {
                                "matched_threats": len(correlation_result.matched_threats),
                                "correlation_confidence": correlation_result.correlation_confidence,
                                "risk_assessment": correlation_result.risk_assessment,
                                "recommended_actions": correlation_result.recommended_actions,
                                "enrichment_data": correlation_result.enrichment_data,
                            }

                            # Update risk score if threat intelligence provides higher score
                            if correlation_result.matched_threats:
                                max_threat_risk = max([t.risk_score for t in correlation_result.matched_threats])
                                current_risk = vuln.get("risk_score", 0)
                                vuln["enhanced_risk_score"] = max(current_risk, max_threat_risk)

                            enriched_vulns.append(vuln)

                        consolidated_results["vulnerabilities"] = enriched_vulns
                        consolidated_results["threat_intelligence_summary"] = {
                            "total_correlations": sum(
                                1
                                for v in enriched_vulns
                                if v.get("threat_intelligence", {}).get("matched_threats", 0) > 0
                            ),
                            "high_risk_threats": sum(
                                1
                                for v in enriched_vulns
                                if v.get("threat_intelligence", {}).get("risk_assessment") in ["HIGH", "CRITICAL"]
                            ),
                            "enrichment_timestamp": datetime.now().isoformat(),
                        }

                        logger.info("Enhanced vulnerabilities with threat intelligence", count=len(enriched_vulns))

                except Exception as e:
                    logger.warning("Threat intelligence enrichment failed", error=str(e))
                    # Continue without enrichment
            # CRITICAL FIX: APPLY ML FALSE POSITIVE REDUCTION
            vulnerabilities_data = []
            logger.debug("Consolidated results info", result_type=str(type(consolidated_results)))
            if consolidated_results:
                logger.debug("Consolidated results keys", keys=list(consolidated_results.keys()))

                # Extract vulnerabilities from plugin_results structure
                vulnerabilities_data = []

                # FIXED: Handle orchestrator result structure correctly
                # For full scans, plugin results are in static_results and dynamic_results
                plugin_results_sources = []

                # Check for direct plugin_results
                if "plugin_results" in consolidated_results:
                    plugin_results_sources.append(("direct", consolidated_results["plugin_results"]))

                # Check for static_results with plugin_results
                if "static_results" in consolidated_results and isinstance(
                    consolidated_results["static_results"], dict
                ):
                    static_plugin_results = consolidated_results["static_results"].get("plugin_results", {})
                    if static_plugin_results:
                        plugin_results_sources.append(("static", static_plugin_results))

                # Check for dynamic_results with plugin_results
                if "dynamic_results" in consolidated_results and isinstance(
                    consolidated_results["dynamic_results"], dict
                ):
                    dynamic_plugin_results = consolidated_results["dynamic_results"].get("plugin_results", {})
                    if dynamic_plugin_results:
                        plugin_results_sources.append(("dynamic", dynamic_plugin_results))

                logger.debug("Found plugin result sources", count=len(plugin_results_sources))

                # Track 42: Track plugins that produced structured findings to skip text fallback
                _plugins_with_structured_findings = set()

                # Process all plugin result sources
                for source_name, plugin_results in plugin_results_sources:
                    logger.debug("Processing plugin_results", source=source_name, plugin_count=len(plugin_results))

                    # Collect all vulnerabilities from all plugin results
                    for plugin_name, plugin_result in plugin_results.items():
                        logger.debug(
                            "Processing plugin",
                            plugin=plugin_name,
                            source=source_name,
                            result_type=str(type(plugin_result)),
                        )
                        if isinstance(plugin_result, (list, tuple)) and len(plugin_result) >= 2:
                            logger.debug(
                                "Plugin result details",
                                plugin=plugin_name,
                                result_1_type=str(type(plugin_result[1])),
                                result_1_length=len(str(plugin_result[1])) if plugin_result[1] else 0,
                            )
                            if isinstance(plugin_result[1], str) and len(plugin_result[1]) > 100:
                                logger.debug("Plugin text preview", plugin=plugin_name, preview=plugin_result[1][:200])

                        # Handle V2 PluginResult objects with .findings attribute
                        if hasattr(plugin_result, "findings") and plugin_result.findings:
                            logger.debug(
                                "Plugin is V2 PluginResult",
                                plugin=plugin_name,
                                findings_count=len(plugin_result.findings),
                            )
                            for finding in plugin_result.findings:
                                # Convert PluginFinding to vulnerability dict
                                vuln = {
                                    "title": getattr(finding, "title", "Security Finding"),
                                    "description": getattr(finding, "description", ""),
                                    "severity": _safe_normalize_severity(getattr(finding, "severity", "medium")),
                                    "confidence": getattr(finding, "confidence", 0.5),
                                    "plugin_source": plugin_name,
                                    "cwe_id": getattr(finding, "cwe_id", None),
                                    "owasp_category": getattr(finding, "owasp_category", None),
                                    "masvs_control": getattr(finding, "masvs_control", None),
                                    "file_path": getattr(finding, "file_path", None),
                                    "line_number": getattr(finding, "line_number", None),
                                    "code_snippet": getattr(finding, "code_snippet", None),
                                    "recommendation": getattr(finding, "recommendation", None),
                                    "evidence": getattr(finding, "evidence", {}),
                                }
                                # Remove None values
                                vuln = {k: v for k, v in vuln.items() if v is not None}
                                vulnerabilities_data.append(vuln)
                            logger.debug(
                                "Converted V2 findings from plugin",
                                plugin=plugin_name,
                                count=len(plugin_result.findings),
                            )
                            _plugins_with_structured_findings.add(plugin_name)  # Track 42
                            continue  # Skip legacy handling for this result

                        if isinstance(plugin_result, (list, tuple)) and len(plugin_result) >= 2:
                            # Handle wrapped PluginResult: ("✅ plugin_name", PluginResult(...))
                            inner = plugin_result[1]
                            if hasattr(inner, "findings") and inner.findings:
                                for finding in inner.findings:
                                    vuln = {
                                        "title": getattr(finding, "title", "Security Finding"),
                                        "description": getattr(finding, "description", ""),
                                        "severity": _safe_normalize_severity(getattr(finding, "severity", "medium")),
                                        "confidence": getattr(finding, "confidence", 0.5),
                                        "plugin_source": plugin_name,
                                        "cwe_id": getattr(finding, "cwe_id", None),
                                        "owasp_category": getattr(finding, "owasp_category", None),
                                        "masvs_control": getattr(finding, "masvs_control", None),
                                        "file_path": getattr(finding, "file_path", None),
                                        "line_number": getattr(finding, "line_number", None),
                                        "code_snippet": getattr(finding, "code_snippet", None),
                                        "recommendation": getattr(finding, "recommendation", None),
                                        "evidence": getattr(finding, "evidence", {}),
                                    }
                                    vuln = {k: v for k, v in vuln.items() if v is not None}
                                    vulnerabilities_data.append(vuln)
                                logger.debug(
                                    "Extracted V2 findings from wrapped PluginResult",
                                    plugin=plugin_name,
                                    count=len(inner.findings),
                                )
                                _plugins_with_structured_findings.add(plugin_name)
                                continue
                            # Format: (plugin_name_string, {vulnerabilities: [...]}) or [plugin_name_string, {vulnerabilities: [...]}]  # noqa: E501
                            elif isinstance(plugin_result[1], dict) and "vulnerabilities" in plugin_result[1]:
                                plugin_vulns = plugin_result[1]["vulnerabilities"]
                                # Ensure plugin_source is set
                                enriched = []
                                for v in plugin_vulns:
                                    if isinstance(v, dict) and "plugin_source" not in v:
                                        v = {**v, "plugin_source": plugin_name}
                                    enriched.append(v)
                                vulnerabilities_data.extend(enriched)
                                _plugins_with_structured_findings.add(plugin_name)  # Track 42
                                logger.debug(
                                    "Found vulnerabilities in plugin",
                                    plugin=plugin_name,
                                    source=source_name,
                                    count=len(enriched),
                                )
                            elif isinstance(plugin_result[1], dict) and (
                                "standardized_vulnerabilities" in plugin_result[1]
                                or "security_issues" in plugin_result[1]
                            ):
                                payload = plugin_result[1]
                                std_vulns = payload.get("standardized_vulnerabilities") or []
                                if std_vulns:
                                    # Ensure plugin_source on standardized vulns
                                    enriched = []
                                    for v in std_vulns:
                                        if isinstance(v, dict) and "plugin_source" not in v:
                                            v = {**v, "plugin_source": plugin_name}
                                        enriched.append(v)
                                    vulnerabilities_data.extend(enriched)
                                    _plugins_with_structured_findings.add(plugin_name)  # Track 42
                                    logger.debug(
                                        "Collected standardized_vulnerabilities from plugin",
                                        plugin=plugin_name,
                                        source=source_name,
                                        count=len(std_vulns),
                                    )
                                sec_issues = payload.get("security_issues") or []
                                if sec_issues:
                                    # Convert security issues to generic vulnerabilities
                                    converted = [
                                        {
                                            "title": f"{issue.get('issue_type', 'Network Issue')}",
                                            "severity": issue.get("severity", "MEDIUM"),
                                            "description": issue.get("description", ""),
                                            "plugin_source": plugin_name,
                                            "type": issue.get("issue_type", "NETWORK_SECURITY"),
                                            "evidence": issue.get("evidence", []),
                                        }
                                        for issue in sec_issues
                                        if isinstance(issue, dict)
                                    ]
                                    vulnerabilities_data.extend(converted)
                                    _plugins_with_structured_findings.add(plugin_name)  # Track 42
                                    logger.debug(
                                        "Converted security_issues to vulnerabilities",
                                        plugin=plugin_name,
                                        source=source_name,
                                        count=len(converted),
                                    )
                            elif isinstance(plugin_result[1], str):
                                # Track 42: Skip text fallback when structured findings already exist
                                if plugin_name in _plugins_with_structured_findings:
                                    continue
                                # AODS text report format: (title, report_text) - parse like orchestrator does
                                report_text = plugin_result[1]
                                parsed_vulns = _parse_vulnerabilities_from_text_report(
                                    report_text, plugin_name, structured_plugin_names=_plugins_with_structured_findings
                                )
                                if parsed_vulns:
                                    vulnerabilities_data.extend(parsed_vulns)
                                    logger.debug(
                                        "Parsed vulnerabilities from text report",
                                        plugin=plugin_name,
                                        source=source_name,
                                        count=len(parsed_vulns),
                                    )
                            elif isinstance(plugin_result[1], (tuple, list)) and len(plugin_result[1]) >= 2:
                                # Nested tuple format: (title, (sub_title, report_text)) - common AODS plugin format
                                logger.debug(
                                    "Plugin nested structure",
                                    plugin=plugin_name,
                                    nested_type=str(type(plugin_result[1][1])),
                                )
                                if isinstance(plugin_result[1][1], dict):
                                    # Handle dict format in nested structure FIRST (before string conversion)
                                    nested_dict = plugin_result[1][1]
                                    logger.debug(
                                        "Plugin has dict in nested structure",
                                        plugin=plugin_name,
                                        keys=list(nested_dict.keys()),
                                    )
                                    if "vulnerabilities" in nested_dict or "findings" in nested_dict:
                                        plugin_vulns = (
                                            nested_dict.get("vulnerabilities") or nested_dict.get("findings", [])
                                        )
                                        enriched = []
                                        for v in plugin_vulns:
                                            if isinstance(v, dict) and "plugin_source" not in v:
                                                v = {**v, "plugin_source": plugin_name}
                                            enriched.append(v)
                                        vulnerabilities_data.extend(enriched)
                                        _plugins_with_structured_findings.add(plugin_name)
                                        logger.debug(
                                            "Found vulnerabilities in nested dict",
                                            plugin=plugin_name,
                                            source=source_name,
                                            count=len(enriched),
                                        )
                                    elif hasattr(nested_dict, "security_findings") or "security_findings" in str(
                                        nested_dict
                                    ):
                                        # Handle structured analysis results (like ManifestAnalysisResult)
                                        logger.debug(
                                            "Plugin has structured analysis result, checking for security findings",
                                            plugin=plugin_name,
                                        )
                                        # Don't create generic vulnerabilities for structured plugins
                                        # The plugin should handle its own vulnerability extraction
                                    elif (
                                        hasattr(nested_dict, "standardized_vulnerabilities")
                                        and getattr(nested_dict, "standardized_vulnerabilities")
                                    ) or (
                                        "standardized_vulnerabilities" in nested_dict
                                        and nested_dict.get("standardized_vulnerabilities")
                                    ):
                                        std_vulns = getattr(
                                            nested_dict, "standardized_vulnerabilities", None
                                        ) or nested_dict.get("standardized_vulnerabilities", [])
                                        enriched = []
                                        for v in std_vulns:
                                            # Convert objects to dicts when possible
                                            if hasattr(v, "to_dict") and callable(getattr(v, "to_dict")):
                                                try:
                                                    v = v.to_dict()
                                                except Exception:
                                                    v = dict(v.__dict__) if hasattr(v, "__dict__") else v
                                            # Ensure dict form and annotate plugin source
                                            if isinstance(v, dict) and "plugin_source" not in v:
                                                v = {**v, "plugin_source": plugin_name}
                                            enriched.append(v)
                                        vulnerabilities_data.extend(enriched)
                                        logger.debug(
                                            "Collected standardized_vulnerabilities from nested dict",
                                            plugin=plugin_name,
                                            source=source_name,
                                            count=len(std_vulns),
                                        )
                                    elif "security_issues" in nested_dict and nested_dict.get("security_issues"):
                                        issues = nested_dict.get("security_issues") or []
                                        converted = [
                                            {
                                                "title": f"{issue.get('issue_type', 'Network Issue')}",
                                                "severity": issue.get("severity", "MEDIUM"),
                                                "description": issue.get("description", ""),
                                                "plugin_source": plugin_name,
                                                "type": issue.get("issue_type", "NETWORK_SECURITY"),
                                                "evidence": issue.get("evidence", []),
                                            }
                                            for issue in issues
                                            if isinstance(issue, dict)
                                        ]
                                        vulnerabilities_data.extend(converted)
                                        logger.debug(
                                            "Converted security_issues from nested dict",
                                            plugin=plugin_name,
                                            source=source_name,
                                            count=len(converted),
                                        )
                                elif isinstance(plugin_result[1][1], str):
                                    report_text = plugin_result[1][1]
                                    logger.debug(
                                        "Plugin report text sample", plugin=plugin_name, preview=report_text[:300]
                                    )
                                    parsed_vulns = _parse_vulnerabilities_from_text_report(
                                        report_text, plugin_name,
                                        structured_plugin_names=_plugins_with_structured_findings,
                                    )
                                    if parsed_vulns:
                                        vulnerabilities_data.extend(parsed_vulns)
                                        logger.debug(
                                            "Parsed vulnerabilities from nested tuple report",
                                            plugin=plugin_name,
                                            source=source_name,
                                            count=len(parsed_vulns),
                                        )
                                    else:
                                        logger.debug(
                                            "No vulnerabilities parsed from nested tuple report", plugin=plugin_name
                                        )
                                elif (
                                    isinstance(plugin_result[1][1], (tuple, list))
                                    and len(plugin_result[1][1]) >= 2
                                    and isinstance(plugin_result[1][1][1], dict)
                                ):
                                    # Handle deeper nested structure: (title, (formatted_report, structured_payload_dict))  # noqa: E501
                                    nested_payload = plugin_result[1][1][1]
                                    if "standardized_vulnerabilities" in nested_payload and nested_payload.get(
                                        "standardized_vulnerabilities"
                                    ):
                                        std_vulns = nested_payload.get("standardized_vulnerabilities") or []
                                        enriched = []
                                        for v in std_vulns:
                                            if hasattr(v, "to_dict") and callable(getattr(v, "to_dict")):
                                                try:
                                                    v = v.to_dict()
                                                except Exception:
                                                    v = dict(v.__dict__) if hasattr(v, "__dict__") else v
                                            if isinstance(v, dict) and "plugin_source" not in v:
                                                v = {**v, "plugin_source": plugin_name}
                                            enriched.append(v)
                                        vulnerabilities_data.extend(enriched)
                                        logger.debug(
                                            "Collected standardized_vulnerabilities from deep nested payload",
                                            plugin=plugin_name,
                                            source=source_name,
                                            count=len(std_vulns),
                                        )
                                    else:
                                        logger.debug(
                                            "No standardized_vulnerabilities in deep nested payload",
                                            plugin=plugin_name,
                                            source=source_name,
                                        )
                                elif hasattr(plugin_result[1][1], "plain") or hasattr(plugin_result[1][1], "__str__"):
                                    # Handle rich.text.Text objects or other objects with string representation
                                    try:
                                        if hasattr(plugin_result[1][1], "plain"):
                                            report_text = plugin_result[1][1].plain
                                        else:
                                            report_text = str(plugin_result[1][1])
                                        logger.debug(
                                            "Plugin converted text sample",
                                            plugin=plugin_name,
                                            preview=report_text[:500],
                                        )
                                        if "Security Findings:" in report_text:
                                            logger.debug(
                                                "Full report for plugin", plugin=plugin_name, report=report_text
                                            )
                                        parsed_vulns = _parse_vulnerabilities_from_text_report(
                                            report_text, plugin_name,
                                            structured_plugin_names=_plugins_with_structured_findings,
                                        )
                                        if parsed_vulns:
                                            vulnerabilities_data.extend(parsed_vulns)
                                            logger.debug(
                                                "Parsed vulnerabilities from rich text report",
                                                plugin=plugin_name,
                                                source=source_name,
                                                count=len(parsed_vulns),
                                            )
                                        else:
                                            logger.debug(
                                                "No vulnerabilities parsed from rich text report", plugin=plugin_name
                                            )
                                    except Exception as e:
                                        logger.debug(
                                            "Failed to convert rich text for plugin", plugin=plugin_name, error=str(e)
                                        )
                        elif isinstance(plugin_result, dict) and "vulnerabilities" in plugin_result:
                            # Direct dict format: {vulnerabilities: [...]}
                            plugin_vulns = plugin_result["vulnerabilities"]
                            vulnerabilities_data.extend(plugin_vulns)
                            logger.debug(
                                "Found vulnerabilities in plugin",
                                plugin=plugin_name,
                                source=source_name,
                                count=len(plugin_vulns),
                            )
                        elif isinstance(plugin_result, str):
                            # Direct string format - parse like orchestrator does
                            parsed_vulns = _parse_vulnerabilities_from_text_report(
                                plugin_result, plugin_name,
                                structured_plugin_names=_plugins_with_structured_findings,
                            )
                            if parsed_vulns:
                                vulnerabilities_data.extend(parsed_vulns)
                                logger.debug(
                                    "Parsed vulnerabilities from string report",
                                    plugin=plugin_name,
                                    source=source_name,
                                    count=len(parsed_vulns),
                                )

                logger.debug("Total vulnerabilities collected", count=len(vulnerabilities_data))

                # Phase 9.6: Apply title validation to filter out plugin summaries
                # This ensures parallel scan path uses same filtering as normal path
                if vulnerabilities_data:
                    pre_filter_count = len(vulnerabilities_data)
                    validated_vulns = []
                    for v in vulnerabilities_data:
                        title = v.get("title", v.get("name", "")) if isinstance(v, dict) else ""
                        if _is_valid_finding_title(title):
                            validated_vulns.append(v)
                        else:
                            logger.debug("Removed invalid/summary title", title=title[:60])
                    vulnerabilities_data = validated_vulns
                    post_filter_count = len(vulnerabilities_data)
                    if pre_filter_count != post_filter_count:
                        logger.info(
                            "Title filter applied",
                            before=pre_filter_count,
                            after=post_filter_count,
                            removed=pre_filter_count - post_filter_count,
                        )

                if len(vulnerabilities_data) == 0:
                    # Extract from optimized_findings (orchestrator format: dict of category -> list of findings)
                    opt_findings = consolidated_results.get("optimized_findings")
                    if isinstance(opt_findings, dict):
                        for category, items in opt_findings.items():
                            if isinstance(items, list):
                                for item in items:
                                    if not isinstance(item, dict):
                                        continue
                                    issue = (
                                        item.get("issue_type")
                                        or item.get("vulnerability_type")
                                        or item.get("type", "Unknown")
                                    )
                                    title = issue.replace("_", " ").title()
                                    vuln = {
                                        "title": title,
                                        "severity": item.get("severity", "MEDIUM"),
                                        "description": f"{title} found in {item.get('file_path', 'unknown')}",
                                        "file_path": item.get("file_path", ""),
                                        "confidence": item.get("confidence", 0.5),
                                        "plugin_source": category,
                                        "type": item.get("type", category),
                                        "category": category.replace("_", " ").title(),
                                    }
                                    # Preserve any extra fields
                                    for k, v in item.items():
                                        if k not in vuln:
                                            vuln[k] = v
                                    vulnerabilities_data.append(vuln)
                        if vulnerabilities_data:
                            logger.debug(
                                "Extracted findings from optimized_findings",
                                findings_count=len(vulnerabilities_data),
                                categories=len(opt_findings),
                            )

                if len(vulnerabilities_data) == 0:
                    # Fallback - try to find any nested vulnerability data
                    logger.debug("No vulnerabilities found in standard structure, trying fallback")
                    for key, value in consolidated_results.items():
                        if isinstance(value, list) and len(value) > 0:
                            logger.debug("Checking key for vulnerabilities", key=key, item_count=len(value))
                            if isinstance(value[0], dict) and any(
                                search_key in str(value[0]).lower()
                                for search_key in ["vulnerability", "finding", "title", "description"]
                            ):
                                vulnerabilities_data = value
                                logger.debug("Fallback selected vulnerabilities data source", key=key)
                                break
            # Ensure extracted vulnerabilities are always written back to consolidated_results
            if vulnerabilities_data:
                consolidated_results["vulnerabilities"] = vulnerabilities_data
                consolidated_results["findings_count"] = len(vulnerabilities_data)

                # Apply canonical FP reduction
                if CANONICAL_FP_AVAILABLE:
                    original_count = len(vulnerabilities_data)
                    try:
                        filtered_data, fp_result = _reduce_fps(vulnerabilities_data)
                        consolidated_results["vulnerabilities"] = filtered_data
                        consolidated_results["findings_count"] = len(filtered_data)
                        consolidated_results["ml_filtering"] = {
                            "applied": True,
                            "original_count": fp_result.original_count,
                            "filtered_count": fp_result.filtered_count,
                            "reduction_percentage": fp_result.reduction_percentage,
                            "stages": fp_result.stages_applied,
                        }
                    except Exception as fp_error:
                        logger.warning("FP reduction failed, proceeding unfiltered", error=str(fp_error))
                        consolidated_results["ml_filtering"] = {
                            "applied": False,
                            "error": str(fp_error),
                            "original_count": original_count,
                        }

                # Apply compound vulnerability correlation (Track 113.5)
                try:
                    from core.compound_vulnerability_engine import correlate_findings as _correlate

                    _vuln_list = consolidated_results.get("vulnerabilities", [])
                    if isinstance(_vuln_list, list) and len(_vuln_list) >= 2:
                        _compound = _correlate(_vuln_list)
                        if _compound:
                            _vuln_list.extend(_compound)
                            consolidated_results["vulnerabilities"] = _vuln_list
                            consolidated_results["findings_count"] = len(_vuln_list)
                            consolidated_results["compound_findings"] = {
                                "count": len(_compound),
                                "titles": [c.get("title", "") for c in _compound],
                            }
                except Exception as _compound_err:
                    logger.debug("Compound vulnerability detection skipped", error=str(_compound_err))

            # Convert ScanResult objects to JSON-serializable format
            json_results = {}
            total_findings = 0
            successful_scans = 0
            # If we have consolidated results, use them for the main structure
            if consolidated_results:
                json_results = consolidated_results
                # PERMANENT FIX: Extract findings count from orchestrator results correctly
                total_findings = (
                    consolidated_results.get("statistics", {}).get("total_findings", 0)  # Legacy format
                    or consolidated_results.get("findings_count", 0)  # Orchestrator format
                    or len(consolidated_results.get("findings", []))  # Direct findings list
                    or len(consolidated_results.get("vulnerabilities", []))  # Vulnerabilities list
                )
                logger.debug("Extracted total_findings from consolidated_results", total_findings=total_findings)

                # Also check if this is a successful orchestrator result
                if consolidated_results.get("status") == "completed" or consolidated_results.get("success"):
                    successful_scans = 1  # Mark orchestrator as successful
                # Add individual scan result details for compatibility
                scan_details = {}
                for scan_type, scan_result in results.items():
                    if hasattr(scan_result, "__dict__"):
                        # **ENHANCED VULNERABILITY INTEGRATION**: Check for enhanced vulnerability report (RESTORED FROM COMMIT e0879e0127b88576afaf9b31497e9ddcd09a3537)  # noqa: E501
                        enhanced_report = getattr(scan_result, "enhanced_report", None)
                        logger.debug("Scan result attributes", scan_type=scan_type, attributes=list(dir(scan_result)))
                        logger.debug("Enhanced report value", scan_type=scan_type, enhanced_report=enhanced_report)

                        # Extract vulnerabilities using enhanced integration logic
                        vulnerabilities = []
                        if enhanced_report and isinstance(enhanced_report, dict):
                            # Use enhanced vulnerability data if available
                            vulnerabilities = enhanced_report.get(
                                "enhanced_vulnerabilities", enhanced_report.get("vulnerabilities", [])
                            )
                            if vulnerabilities:
                                logger.info(
                                    "Using enhanced vulnerability data",
                                    scan_type=scan_type,
                                    findings_count=len(vulnerabilities),
                                )
                            else:
                                logger.warning(
                                    "Enhanced report found but no vulnerabilities",
                                    scan_type=scan_type,
                                    report_keys=list(enhanced_report.keys()),
                                )
                        else:
                            # Fallback to regular findings extraction
                            findings = getattr(scan_result, "findings", [])
                            if isinstance(findings, dict):
                                vulnerabilities = findings.get("vulnerabilities", [])
                            elif isinstance(findings, list):
                                vulnerabilities = findings
                            logger.info(
                                "Using regular findings", scan_type=scan_type, findings_count=len(vulnerabilities)
                            )

                        scan_details[scan_type] = {
                            "success": getattr(scan_result, "success", False),
                            "execution_time": getattr(scan_result, "execution_time", 0),
                            "findings_count": len(getattr(scan_result, "findings", [])),
                            "metadata": getattr(scan_result, "metadata", {}),
                        }
                        if scan_details[scan_type]["success"]:
                            successful_scans += 1

                # Add scan details to consolidated results
                json_results["scan_details"] = scan_details
            else:
                # Fallback to original logic if consolidation fails
                for scan_type, scan_result in results.items():
                    # Initialize findings to ensure it's always defined
                    findings = []
                    if hasattr(scan_result, "__dict__"):
                        findings = getattr(scan_result, "findings", [])

                    # ENHANCED VULNERABILITY INTEGRATION: Check for enhanced vulnerability report
                    enhanced_report = getattr(scan_result, "enhanced_report", None)
                    logger.debug(
                        "Scan result attributes (fallback)", scan_type=scan_type, attributes=list(dir(scan_result))
                    )
                    logger.debug(
                        "Enhanced report value (fallback)", scan_type=scan_type, enhanced_report=enhanced_report
                    )
                    if enhanced_report and isinstance(enhanced_report, dict):
                        # Use enhanced vulnerability data if available
                        vulnerabilities = enhanced_report.get(
                            "enhanced_vulnerabilities", enhanced_report.get("vulnerabilities", [])
                        )
                        if vulnerabilities:
                            logger.info(
                                "Using enhanced vulnerability data",
                                scan_type=scan_type,
                                findings_count=len(vulnerabilities),
                            )
                        else:
                            logger.warning(
                                "Enhanced report found but no vulnerabilities",
                                scan_type=scan_type,
                                report_keys=list(enhanced_report.keys()),
                            )
                    else:
                        # Handle findings properly - it might be a dict with 'vulnerabilities' key or a list
                        if isinstance(findings, dict):
                            vulnerabilities = findings.get("vulnerabilities", [])
                        elif isinstance(findings, list):
                            vulnerabilities = findings
                        else:
                            vulnerabilities = []
                        logger.info("Using raw findings", scan_type=scan_type, findings_count=len(vulnerabilities))

                    # Apply canonical FP reduction (Track 112)
                    original_count = len(vulnerabilities)
                    filtering_applied = False

                    if vulnerabilities and CANONICAL_FP_AVAILABLE:
                        try:
                            vulnerabilities, fp_result = _reduce_fps(vulnerabilities)
                            filtering_applied = True
                            if fp_result.stages_applied:
                                logger.info(
                                    "fp_filtering_completed",
                                    scan_type=scan_type,
                                    original=fp_result.original_count,
                                    filtered=fp_result.filtered_count,
                                    reduction_pct=fp_result.reduction_percentage,
                                    stages=fp_result.stages_applied,
                                )
                        except Exception as e:
                            logger.warning("fp_reduction_failed", scan_type=scan_type, error=str(e))

                    # CLEAN SCANNING: Enhanced JSON results with quality metrics
                    clean_scan_metadata = {
                        "clean_scan_enabled": CANONICAL_FP_AVAILABLE and filtering_applied,
                        "fp_filtering_applied": filtering_applied,
                        "fp_filtering_type": (
                            "canonical_fp_reducer" if (CANONICAL_FP_AVAILABLE and filtering_applied) else "none"
                        ),
                        "analytics": {
                            "feedback_collection_enabled": args.feedback_server if "args" in locals() else False,
                            "analytics_dashboard_active": True,  # Phase 11: Analytics integration
                            "learning_analytics_active": True,  # Phase 11: Learning analytics
                            "user_interaction_tracking": True,  # Phase 11: User interaction analytics
                            "feedback_sessions_supported": ["cli", "web", "api"],  # Phase 11: Multi-interface feedback
                            "real_time_analytics": True,  # Phase 11: Real-time analytics
                        },
                        "external_data": {
                            "cve_nvd_integration": True,  # Phase 15: CVE/NVD integration
                            "threat_intelligence_active": True,  # Phase 15: Threat intelligence
                            "vulnerability_database_sync": True,  # Phase 15: External vulnerability DB
                            "data_pipeline_enabled": True,  # Phase 15: Data synchronization pipeline
                            "threat_intel_sources": ["mitre", "cve", "nvd"],  # Phase 15: Threat intelligence sources
                            "external_enrichment_active": True,  # Phase 15: External data enrichment
                        },
                        "quality_assurance": {
                            "original_findings": original_count,
                            "filtered_findings": len(vulnerabilities),
                            "qa_automation_enabled": config_data.get("qa_mode", False),
                            "user_feedback_enabled": args.feedback_server if "args" in locals() else False,
                            "analytics_dashboard_enabled": True,  # Phase 11: Analytics integration
                            "external_data_integration_enabled": True,  # Phase 15: External data integration
                            "threat_intelligence_enabled": True,  # Phase 15: Threat intelligence
                            "noise_eliminated": original_count - len(vulnerabilities),
                            "reduction_percentage": (
                                ((original_count - len(vulnerabilities)) / original_count * 100)
                                if original_count > 0
                                else 0
                            ),
                            "ml_systems_applied": (
                                len(getattr(fp_result, "stages_applied", []))
                                if "fp_result" in locals()
                                else 0
                            ),
                        },
                    }

                    json_results[scan_type] = {
                        "success": getattr(scan_result, "success", False),
                        "execution_time": getattr(scan_result, "execution_time", 0),
                        "findings_count": len(vulnerabilities),
                        "vulnerabilities": vulnerabilities,  # Now includes clean scanning
                        "metadata": getattr(scan_result, "metadata", {}),
                        "clean_scan_metadata": clean_scan_metadata,
                        "original_findings_count": original_count,
                    }
                    if getattr(scan_result, "success", False):
                        successful_scans += 1
                    total_findings += len(vulnerabilities)
                else:
                    json_results[scan_type] = scan_result

            # Add summary statistics
            json_results["summary"] = {
                "total_findings": total_findings,
                "successful_scans": successful_scans,
                "total_scans": len(results),
                "success_rate": successful_scans / len(results) if results else 0,
            }
            # **ENHANCED VULNERABILITY PROCESSING**: Apply full enhancement pipeline
            # Includes: Recommendations, ML Enhancement, Smart Filtering, and Runtime Evidence
            if not (hasattr(args, "disable_enhancements") and args.disable_enhancements):
                try:
                    # Import enhancement pipeline
                    from core.aods_vulnerability_enhancer import enhance_aods_vulnerabilities

                    enhanced_vulnerabilities = []

                    # CRITICAL DEBUG: Check what's in json_results
                    output_mgr.info(f"🔧 DEBUG: json_results keys: {list(json_results.keys())}")
                    if "vulnerabilities" in json_results:
                        output_mgr.info(
                            f"🔧 DEBUG: Found 'vulnerabilities' key with {len(json_results['vulnerabilities'])} items"
                        )

                    # Handle both old format (nested dicts) and new format (direct lists)
                    vulnerability_sources = [
                        "vulnerabilities",  # Direct vulnerability list
                        "infrastructure_findings",  # Infrastructure findings list
                        "runtime_findings",  # Runtime findings list
                    ]

                    # CRITICAL FIX: Check for direct 'vulnerabilities' key first
                    if "vulnerabilities" in json_results and isinstance(json_results["vulnerabilities"], list):
                        scan_vulns = json_results["vulnerabilities"]
                        scan_type_for_context = "vulnerabilities"
                        output_mgr.info(
                            f"🔧 DEBUG: Processing direct 'vulnerabilities' key with {len(scan_vulns)} items"
                        )

                        # Process the vulnerabilities directly
                        if scan_vulns:
                            # Find decompiled sources path for organic code extraction
                            decompiled_path = None
                            try:
                                import glob

                                # Derive the APK stem to scope to the CURRENT APK's directory
                                _apk_path = getattr(args, "apk", "") if hasattr(args, "apk") else ""
                                _apk_stem = os.path.splitext(os.path.basename(_apk_path))[0]

                                workspace_dir = os.path.join(os.getcwd(), "workspace")
                                if os.path.exists(workspace_dir):
                                    # Prefer APK-stem-scoped directory (e.g. workspace/capcut_83f11896_decompiled)
                                    if _apk_stem:
                                        stem_matches = glob.glob(
                                            os.path.join(workspace_dir, f"{_apk_stem}_*_decompiled")
                                        )
                                        if stem_matches:
                                            decompiled_path = stem_matches[0]
                                            output_mgr.info(f"🔧 Found scoped decompiled sources: {decompiled_path}")

                                    # Fallback: any decompiled directory (only when workspace has exactly one)
                                    if not decompiled_path:
                                        all_matches = glob.glob(os.path.join(workspace_dir, "*_decompiled"))
                                        if len(all_matches) == 1:
                                            decompiled_path = all_matches[0]
                                            output_mgr.info(f"🔧 Found decompiled sources: {decompiled_path}")

                            except Exception as e:
                                output_mgr.warning(f"⚠️ Could not locate decompiled sources: {e}")

                            # Enhance vulnerabilities with AODS enhancement pipeline
                            try:
                                # Build minimal scan context
                                pkg_name = args.pkg if hasattr(args, "pkg") and args.pkg else "unknown"
                                scan_ctx = {
                                    "scan_type": scan_type_for_context,
                                    "package_name": pkg_name,
                                    "scan_mode": getattr(args, "scan_mode", "safe"),
                                }
                                enhanced_batch = enhance_aods_vulnerabilities(
                                    vulnerabilities=scan_vulns,
                                    scan_context=scan_ctx,
                                    disable_ml=getattr(args, "disable_ml", False),
                                    decompiled_path=decompiled_path,
                                )
                                enhanced_vulnerabilities.extend(enhanced_batch)
                                output_mgr.info(
                                    f"✅ Enhanced {len(enhanced_batch)} vulnerabilities from direct 'vulnerabilities' key"  # noqa: E501
                                )
                            except Exception as e:
                                output_mgr.warning(f"⚠️ Enhancement failed for direct vulnerabilities: {e}")
                                # Fallback: add unenhanced vulnerabilities
                                enhanced_vulnerabilities.extend(scan_vulns)

                    # Also process other scan types for backward compatibility
                    for scan_type, scan_data in json_results.items():
                        # Skip the direct 'vulnerabilities' key as we already processed it
                        if scan_type == "vulnerabilities":
                            continue

                        scan_vulns = None
                        scan_type_for_context = scan_type

                        # Handle new format: direct vulnerability lists
                        if scan_type in vulnerability_sources and isinstance(scan_data, list):
                            scan_vulns = scan_data
                        # Handle old format: nested dictionaries with 'vulnerabilities' key (backward compatibility)
                        elif scan_type != "summary" and isinstance(scan_data, dict) and "vulnerabilities" in scan_data:
                            scan_vulns = scan_data["vulnerabilities"]

                        if scan_vulns:
                            # Find decompiled sources path for organic code extraction
                            decompiled_path = None
                            try:
                                import glob

                                _apk_path2 = getattr(args, "apk", "") if hasattr(args, "apk") else ""
                                _apk_stem2 = os.path.splitext(os.path.basename(_apk_path2))[0]
                                workspace_dir = os.path.join(os.getcwd(), "workspace")
                                if os.path.exists(workspace_dir):
                                    # Prefer APK-stem-scoped directory
                                    if _apk_stem2:
                                        stem_matches2 = glob.glob(
                                            os.path.join(workspace_dir, f"{_apk_stem2}_*_decompiled")
                                        )
                                        if stem_matches2:
                                            decompiled_path = stem_matches2[0]
                                            output_mgr.debug(
                                                f"Found scoped decompiled path: {decompiled_path}"
                                            )

                                    # Fallback: single decompiled directory or APKContext
                                    if not decompiled_path:
                                        all_matches2 = glob.glob(os.path.join(workspace_dir, "*_decompiled"))
                                        if len(all_matches2) == 1:
                                            decompiled_path = all_matches2[0]
                                        else:
                                            try:
                                                _apk_ctx = APKContext(args.apk)
                                                if (hasattr(_apk_ctx, "decompiled_apk_dir")
                                                        and _apk_ctx.decompiled_apk_dir):
                                                    ctx_path = str(_apk_ctx.decompiled_apk_dir)
                                                    if os.path.exists(ctx_path) and os.path.isdir(ctx_path):
                                                        decompiled_path = ctx_path
                                            except Exception:
                                                pass
                            except Exception as e:
                                output_mgr.debug(f"Could not find decompiled sources: {e}")

                            # Apply full enhancement pipeline
                            enhanced_scan_vulns = enhance_aods_vulnerabilities(
                                vulnerabilities=scan_vulns,
                                scan_context={
                                    "scan_type": scan_type_for_context,
                                    "package_name": pkg_name,
                                    "scan_mode": args.scan_mode if hasattr(args, "scan_mode") else "safe",
                                },
                                disable_ml=args.disable_ml if hasattr(args, "disable_ml") else False,
                                decompiled_path=decompiled_path,
                            )

                            # Update scan data with enhanced vulnerabilities
                            # **CRITICAL FIX**: Handle both direct lists and nested dictionaries
                            if scan_type in vulnerability_sources and isinstance(json_results[scan_type], list):
                                # Direct list format: Replace the entire list
                                json_results[scan_type] = enhanced_scan_vulns
                                output_mgr.debug(
                                    f"🔧 DEBUG: Updated direct list {scan_type} with {len(enhanced_scan_vulns)} enhanced vulnerabilities"  # noqa: E501
                                )
                            elif (
                                isinstance(json_results[scan_type], dict)
                                and "vulnerabilities" in json_results[scan_type]
                            ):
                                # Nested dictionary format: Update the vulnerabilities key
                                json_results[scan_type]["vulnerabilities"] = enhanced_scan_vulns
                                output_mgr.debug(
                                    f"🔧 DEBUG: Updated nested dict {scan_type}['vulnerabilities'] with {len(enhanced_scan_vulns)} enhanced vulnerabilities"  # noqa: E501
                                )

                            enhanced_vulnerabilities.extend(enhanced_scan_vulns)

                    if enhanced_vulnerabilities:
                        # Promote enhancer evidence into canonical format to improve coverage prior to normalization
                        try:

                            def _promote_evidence(v):
                                if not isinstance(v, dict):
                                    return v
                                ev = v.setdefault("evidence", {}) if isinstance(v.get("evidence"), dict) else {}
                                if "evidence" not in v:
                                    v["evidence"] = ev
                                # Map code_evidence block if present
                                ce = v.get("code_evidence")
                                if isinstance(ce, dict):
                                    if ce.get("file_path") and not ev.get("file_path"):
                                        ev["file_path"] = ce.get("file_path")
                                    if ce.get("line_number") and not ev.get("line_number"):
                                        try:
                                            ev["line_number"] = int(ce.get("line_number"))
                                        except Exception:
                                            pass
                                    if ce.get("extraction_method") and not ev.get("extraction_method"):
                                        ev["extraction_method"] = ce.get("extraction_method")
                                    if ce.get("context_lines") and not ev.get("context_lines"):
                                        ev["context_lines"] = ce.get("context_lines")
                                # Promote top-level aliases
                                if v.get("file_path") and not ev.get("file_path"):
                                    ev["file_path"] = v.get("file_path")
                                if v.get("line_number") and not ev.get("line_number"):
                                    try:
                                        ev["line_number"] = int(v.get("line_number"))
                                    except Exception:
                                        pass
                                if v.get("code_snippet") and not ev.get("code_snippet"):
                                    ev["code_snippet"] = v.get("code_snippet")
                                return v

                            enhanced_vulnerabilities = [_promote_evidence(v) for v in enhanced_vulnerabilities]
                        except Exception as _e:
                            output_mgr.debug(f"Evidence promotion skipped: {_e}")
                        # Replace top-level vulnerabilities list with enhanced set when available
                        try:
                            if isinstance(json_results.get("vulnerabilities"), list) and enhanced_vulnerabilities:
                                json_results["vulnerabilities"] = enhanced_vulnerabilities
                                # Keep findings_count in sync if present
                                if isinstance(json_results.get("findings_count"), int):
                                    json_results["findings_count"] = len(enhanced_vulnerabilities)
                        except Exception as _e2:
                            output_mgr.debug(f"Failed to replace top-level vulnerabilities with enhanced set: {_e2}")
                        output_mgr.info(
                            f"🎯 Enhanced {len(enhanced_vulnerabilities)} vulnerabilities with recommendations, ML analysis, and smart filtering"  # noqa: E501
                        )

                        # Log enhancement quality metrics (with type safety - 2025-08-27)
                        recommendations_count = sum(
                            1 for v in enhanced_vulnerabilities if isinstance(v, dict) and v.get("recommendations")
                        )
                        ml_enhanced_count = sum(
                            1 for v in enhanced_vulnerabilities if isinstance(v, dict) and v.get("ml_enhanced")
                        )
                        evidence_count = sum(
                            1 for v in enhanced_vulnerabilities if isinstance(v, dict) and v.get("evidence")
                        )
                        organic_code_count = sum(
                            1
                            for v in enhanced_vulnerabilities
                            if isinstance(v, dict) and v.get("code_snippet_source") == "organic_extraction"
                        )

                        output_mgr.info("📊 Enhancement Quality:")
                        output_mgr.info(
                            f"   🧬 {organic_code_count}/{len(enhanced_vulnerabilities)} have organic code snippets"
                        )
                        output_mgr.info(
                            f"   💡 {recommendations_count}/{len(enhanced_vulnerabilities)} have recommendations"
                        )
                        output_mgr.info(f"   🤖 {ml_enhanced_count}/{len(enhanced_vulnerabilities)} ML enhanced")
                        output_mgr.info(f"   📋 {evidence_count}/{len(enhanced_vulnerabilities)} have evidence")

                        # **VULNERABILITY CORRELATION ENGINE**: Apply cross-plugin correlation
                        if len(enhanced_vulnerabilities) > 1:
                            try:
                                from core.vulnerability_correlation_engine import (
                                    create_vulnerability_correlation_engine,
                                )

                                correlation_engine = create_vulnerability_correlation_engine()
                                output_mgr.info(
                                    f"🔗 Starting vulnerability correlation analysis for {len(enhanced_vulnerabilities)} findings..."  # noqa: E501
                                )

                                # Convert to plugin results format
                                plugin_results = {"enhanced_scan": enhanced_vulnerabilities}
                                correlation_analysis = correlation_engine.analyze_findings(plugin_results)
                                # Type-safe correlation analysis access (2025-08-27)
                                correlated_findings = (
                                    correlation_analysis.get("correlations", [])
                                    if isinstance(correlation_analysis, dict)
                                    else []
                                )

                                if correlated_findings:
                                    output_mgr.info(
                                        f"🎯 Vulnerability correlation complete: {len(correlated_findings)} correlated risks identified"  # noqa: E501
                                    )

                                    # Calculate correlation statistics
                                    risk_escalations = len(
                                        [
                                            c
                                            for c in correlated_findings
                                            if c.escalated_severity != c.primary_finding.severity
                                        ]
                                    )
                                    compound_threats = len(
                                        [c for c in correlated_findings if len(c.related_findings) > 1]
                                    )
                                    critical_escalations = len(
                                        [
                                            c
                                            for c in correlated_findings
                                            if _safe_normalize_severity(c.escalated_severity) == "CRITICAL"
                                        ]
                                    )
                                    avg_confidence = (
                                        sum(c.correlation_confidence for c in correlated_findings)
                                        / len(correlated_findings)
                                        if correlated_findings
                                        else 0.0
                                    )

                                    # Add correlation metadata to results
                                    correlation_summary = {
                                        "total_correlations": len(correlated_findings),
                                        "risk_escalations": risk_escalations,
                                        "compound_threats": compound_threats,
                                        "critical_escalations": critical_escalations,
                                        "correlation_confidence": round(avg_confidence, 2),
                                    }

                                    # Integrate correlations back into findings
                                    enhanced_vulnerabilities = correlation_engine.integrate_correlations_with_findings(
                                        enhanced_vulnerabilities, correlated_findings
                                    )

                                    output_mgr.info("🔗 Correlation Results:")
                                    output_mgr.info(f"   📈 Risk escalations: {risk_escalations}")
                                    output_mgr.info(f"   🎯 Compound threats: {compound_threats}")
                                    output_mgr.info(f"   🚨 Critical escalations: {critical_escalations}")
                                    output_mgr.info(f"   💯 Avg confidence: {avg_confidence:.2f}")

                                    # Store correlation data for reporting
                                    if "vulnerability_correlations" not in json_results:
                                        json_results["vulnerability_correlations"] = correlation_summary

                                else:
                                    output_mgr.info("🔗 No significant vulnerability correlations found")

                            except ImportError as e:
                                output_mgr.warning(f"⚠️  Vulnerability correlation engine not available: {e}")
                            except Exception as e:
                                output_mgr.warning(f"⚠️  Vulnerability correlation engine failed: {e}")
                                # Continue with uncorrelated findings - this is not a critical failure
                    else:
                        output_mgr.info("No vulnerabilities found for enhancement")

                except ImportError as e:
                    output_mgr.warning(f"⚠️ Enhancement pipeline not available: {e}")
                    output_mgr.info("🔄 Falling back to basic vulnerability processing")

                    # Fallback: Basic vulnerability collection without enhancement
                    enhanced_vulnerabilities = []
                    for scan_type, scan_data in json_results.items():
                        if scan_type != "summary" and isinstance(scan_data, dict) and "vulnerabilities" in scan_data:
                            scan_vulns = scan_data["vulnerabilities"]
                            if scan_vulns:
                                enhanced_vulnerabilities.extend(scan_vulns)

                except Exception as e:
                    output_mgr.error(f"❌ Vulnerability enhancement failed: {e}")
                    output_mgr.info("🔄 Falling back to basic vulnerability processing")

                    # Fallback: Basic vulnerability collection without enhancement
                    enhanced_vulnerabilities = []
                    for scan_type, scan_data in json_results.items():
                        if scan_type != "summary" and isinstance(scan_data, dict) and "vulnerabilities" in scan_data:
                            scan_vulns = scan_data["vulnerabilities"]
                            if scan_vulns:
                                enhanced_vulnerabilities.extend(scan_vulns)
            else:
                # Enhancement disabled - collect vulnerabilities without enhancement
                output_mgr.info("🔧 Vulnerability enhancement disabled - using basic processing")
                enhanced_vulnerabilities = []
                for scan_type, scan_data in json_results.items():
                    if scan_type != "summary" and isinstance(scan_data, dict) and "vulnerabilities" in scan_data:
                        scan_vulns = scan_data["vulnerabilities"]
                        if scan_vulns:
                            enhanced_vulnerabilities.extend(scan_vulns)

            # **ADD ENHANCED VULNERABILITIES TO FINAL OUTPUT**
            if enhanced_vulnerabilities:
                json_results["enhanced_vulnerabilities"] = enhanced_vulnerabilities
                output_mgr.info(f"✅ Added {len(enhanced_vulnerabilities)} enhanced vulnerabilities to final output")

            # **CONTAINER SYNC FIX**: Create canonical findings and sync all containers
            # This ensures len(vulnerabilities) == len(enhanced_vulnerabilities) == len(findings)
            try:
                _sync_logger = logger
                canonical = _create_canonical_findings(json_results, _sync_logger)
                _sync_all_containers(json_results, canonical, _sync_logger)
                output_mgr.info(f"✅ Container sync complete: {len(canonical)} canonical findings")
            except Exception as _sync_err:
                output_mgr.warning(f"⚠️ Container sync failed (non-fatal): {_sync_err}")

            # **FINAL JSON SERIALIZATION FIX**: Clean Rich Text objects before serialization
            def clean_for_json(obj):
                """Convert objects to JSON-serializable format, handling Rich Text objects."""
                # Handle Rich Text objects from plugins
                if hasattr(obj, "__rich_console__") or hasattr(obj, "__rich__"):
                    if hasattr(obj, "plain"):
                        return str(obj.plain)
                    else:
                        return str(obj)
                elif hasattr(obj, "plain") and str(type(obj)).find("rich") != -1:
                    return str(obj.plain)
                elif hasattr(obj, "__dict__"):
                    return obj.__dict__
                elif hasattr(obj, "_asdict"):
                    return obj._asdict()
                elif isinstance(obj, (list, tuple)):
                    return [clean_for_json(item) for item in obj]
                elif isinstance(obj, dict):
                    return {key: clean_for_json(value) for key, value in obj.items()}
                else:
                    return str(obj)

            # **CRITICAL FIX**: Apply integrated normalization BEFORE JSON write
            # This ensures all findings have CWE/OWASP/MASVS/MITRE mappings and evidence
            try:
                from core.integrated_finding_normalizer import (
                    normalize_findings_integrated,
                    compute_masvs_summary_integrated,
                )

                # Collect all vulnerabilities for normalization (nested + top-level)
                # Track processed keys to prevent double-collection (fixes count mismatch)
                all_vulnerabilities = []
                processed_keys = set()
                # Nested structures
                for scan_type, scan_data in json_results.items():
                    if scan_type != "summary" and isinstance(scan_data, dict):
                        vulns = scan_data.get("vulnerabilities", [])
                        if isinstance(vulns, list) and vulns:
                            all_vulnerabilities.extend(vulns)
                            processed_keys.add(scan_type)
                # Top-level structures - only add if NOT already processed via nested iteration
                top_level_vulns = json_results.get("vulnerabilities")
                if isinstance(top_level_vulns, list) and top_level_vulns and "vulnerabilities" not in processed_keys:
                    all_vulnerabilities.extend(top_level_vulns)
                top_level_findings = json_results.get("vulnerability_findings")
                if (
                    isinstance(top_level_findings, list)
                    and top_level_findings
                    and "vulnerability_findings" not in processed_keys
                ):
                    all_vulnerabilities.extend(top_level_findings)

                if all_vulnerabilities:
                    logger.info(
                        "Applying integrated normalization before JSON write", findings_count=len(all_vulnerabilities)
                    )

                    # Apply full normalization with MITRE integration
                    normalized_vulnerabilities = normalize_findings_integrated(
                        all_vulnerabilities,
                        apk_context={
                            "apk_path": getattr(args, "apk", None) or json_results.get("apk_path") or "unknown"
                        },
                    )

                    # Compute MASVS summary from normalized findings
                    masvs_summary = compute_masvs_summary_integrated(normalized_vulnerabilities)

                    # Update json_results with normalized findings (nested + top-level)
                    vuln_index = 0
                    for scan_type, scan_data in json_results.items():
                        if scan_type != "summary" and isinstance(scan_data, dict):
                            vulns = scan_data.get("vulnerabilities", [])
                            if isinstance(vulns, list) and vulns:
                                normalized_count = len(vulns)
                                scan_data["vulnerabilities"] = normalized_vulnerabilities[
                                    vuln_index : vuln_index + normalized_count
                                ]
                                vuln_index += normalized_count
                    # Replace top-level lists if present
                    if isinstance(top_level_vulns, list) and top_level_vulns:
                        json_results["vulnerabilities"] = normalized_vulnerabilities[
                            vuln_index : vuln_index + len(top_level_vulns)
                        ]
                        vuln_index += len(top_level_vulns)
                    if isinstance(top_level_findings, list) and top_level_findings:
                        json_results["vulnerability_findings"] = normalized_vulnerabilities[
                            vuln_index : vuln_index + len(top_level_findings)
                        ]
                        vuln_index += len(top_level_findings)

                    # Add summary with MASVS and integration metrics
                    json_results["masvs_summary"] = masvs_summary
                    json_results["normalization_applied"] = True

                    # **QUALITY GATES**: Validate coverage thresholds
                    from roadmap.Upgrade.validation.integration_coverage_validator import validate_integration_report

                    # Create temporary report for validation
                    temp_report = {"vulnerabilities": normalized_vulnerabilities, "masvs_summary": masvs_summary}

                    # Validate against acceptance criteria
                    coverage_validation = validate_integration_report(temp_report)
                    # Expose under the key expected by the validator
                    json_results["integration_coverage_validation"] = coverage_validation

                    # **EMIT ARTIFACTS**: Save validation results to reports/
                    from datetime import datetime

                    reports_dir = "reports"
                    os.makedirs(reports_dir, exist_ok=True)

                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    validation_file = f"{reports_dir}/scan_validation_{timestamp}.json"

                    with open(validation_file, "w") as f:
                        import json as json_module

                        json_module.dump(coverage_validation, f, indent=2, default=str)

                    # Log quality gate results
                    status = coverage_validation.get("status", "UNKNOWN")
                    coverage_metrics = coverage_validation.get("coverage_validation", {})
                    # Ensure report metadata includes schema_version and apk_path for CI gate
                    json_results.setdefault("metadata", {})
                    try:
                        json_results["metadata"]["schema_version"] = (
                            json_results["metadata"].get("schema_version") or "1.0.0"
                        )
                        # Add APK path for metadata extraction in serializer
                        _apk_path = getattr(args, "apk", None)
                        if _apk_path:
                            json_results["apk_path"] = str(_apk_path)
                            json_results["metadata"]["apk_path"] = str(_apk_path)
                    except Exception:
                        pass

                    # Persist parsed manifest data for attack surface graph
                    try:
                        _apk_path_for_manifest = getattr(args, "apk", None)
                        if _apk_path_for_manifest:
                            _manifest_ctx = APKContext(str(_apk_path_for_manifest))
                            _manifest_p = getattr(_manifest_ctx, "manifest_path", None)
                            if _manifest_p:
                                from core.analysis.attack_surface import extract_manifest_data
                                _mdata = extract_manifest_data(_manifest_p)
                                if _mdata:
                                    json_results["metadata"]["manifest_data"] = _mdata
                                    json_results["manifest_data"] = _mdata
                    except Exception:
                        pass

                    # Gate 4: Add business domain to report metadata (parallel scan path)
                    if BUSINESS_DOMAIN_DETECTION_AVAILABLE:
                        try:
                            from core.apk_ctx import APKContext as _APKContext
                            from core.app_type_detector import detect_business_domain, get_business_domain_info

                            # Create APK context for domain detection
                            apk_path = getattr(args, "apk", None) or json_results.get("apk_path", "")
                            pkg_name = getattr(args, "pkg", None) or json_results.get("package_name", "")
                            if apk_path:
                                _temp_ctx = _APKContext(apk_path_str=str(apk_path), package_name=pkg_name)
                                _business_domain = detect_business_domain(_temp_ctx)
                                _domain_info = get_business_domain_info(_business_domain)
                                domain_value = (
                                    _business_domain.value
                                    if hasattr(_business_domain, "value")
                                    else str(_business_domain)
                                )
                                json_results["metadata"]["business_domain"] = domain_value
                                json_results["metadata"]["business_domain_info"] = {
                                    "name": _domain_info.get("name", domain_value),
                                    "security_level": _domain_info.get("security_level", "MEDIUM"),
                                    "confidence_multiplier": _domain_info.get("confidence_multiplier", 1.0),
                                    "regulatory_requirements": _domain_info.get("regulatory_requirements", []),
                                }
                                logger.info(
                                    "Business domain detected",
                                    domain=_domain_info.get("name", domain_value),
                                    security_level=_domain_info.get("security_level", "MEDIUM"),
                                )
                        except Exception as _bd_err:
                            logger.warning("Business domain detection failed", error=str(_bd_err))

                    logger.info("Integrated normalization complete", findings_enhanced=len(normalized_vulnerabilities))
                    logger.info(
                        "Quality gates result",
                        status=status,
                        taxonomy_coverage=coverage_metrics.get("taxonomy_coverage", "N/A"),
                        code_snippet_coverage=coverage_metrics.get("code_snippet_coverage", "N/A"),
                        line_number_coverage=coverage_metrics.get("line_number_coverage", "N/A"),
                        validation_file=validation_file,
                    )

                    # Warn if quality gates fail
                    if status == "FAIL":
                        logger.warning("Quality gates failed - some coverage thresholds not met")
                    else:
                        logger.info("Quality gates passed - all coverage thresholds met")
                else:
                    json_results["normalization_applied"] = False
                    logger.info("No vulnerabilities found for normalization")

            except Exception as e:
                logger.warning("Integrated normalization failed", error=str(e))
                json_results["normalization_applied"] = False
                json_results["normalization_error"] = str(e)

            # **DIRECT ENRICHMENT CALL**: Ensure enrichment always runs before JSON write
            try:
                from core.integrated_finding_normalizer import normalize_findings_integrated

                # Extract all vulnerabilities from json_results (nested + top-level)
                all_findings = []
                for key, value in json_results.items():
                    if isinstance(value, dict) and "vulnerabilities" in value:
                        vulns = value["vulnerabilities"]
                        if isinstance(vulns, list) and vulns:
                            all_findings.extend(vulns)
                if isinstance(json_results.get("vulnerabilities"), list) and json_results["vulnerabilities"]:
                    all_findings.extend(json_results["vulnerabilities"])
                if (
                    isinstance(json_results.get("vulnerability_findings"), list)
                    and json_results["vulnerability_findings"]
                ):
                    all_findings.extend(json_results["vulnerability_findings"])

                if all_findings:
                    logger.info("Direct enrichment processing", findings_count=len(all_findings))
                    enriched_findings = normalize_findings_integrated(
                        all_findings,
                        apk_context={
                            "apk_path": getattr(args, "apk", None) or json_results.get("apk_path") or "unknown"
                        },
                    )

                    if enriched_findings:
                        # Replace vulnerabilities with enriched versions
                        enriched_idx = 0
                        for key, value in json_results.items():
                            if isinstance(value, dict) and "vulnerabilities" in value:
                                vulns = value["vulnerabilities"]
                                if isinstance(vulns, list) and vulns:
                                    count = len(vulns)
                                    value["vulnerabilities"] = enriched_findings[enriched_idx : enriched_idx + count]
                                    enriched_idx += count
                        # Replace top-level lists as well
                        if isinstance(json_results.get("vulnerabilities"), list) and json_results["vulnerabilities"]:
                            count = len(json_results["vulnerabilities"])
                            json_results["vulnerabilities"] = enriched_findings[enriched_idx : enriched_idx + count]
                            enriched_idx += count
                        if (
                            isinstance(json_results.get("vulnerability_findings"), list)
                            and json_results["vulnerability_findings"]
                        ):
                            count = len(json_results["vulnerability_findings"])
                            json_results["vulnerability_findings"] = enriched_findings[
                                enriched_idx : enriched_idx + count
                            ]
                            enriched_idx += count

                        json_results["mitre_enrichment_applied"] = True
                        logger.info("Direct enrichment complete", findings_enriched=len(enriched_findings))
                    else:
                        json_results["mitre_enrichment_applied"] = False
                        logger.info("Direct enrichment returned no enriched results")
                else:
                    json_results["mitre_enrichment_applied"] = False
                    logger.info("Direct enrichment: no findings found to enrich")

            except Exception as e:
                json_results["mitre_enrichment_applied"] = False
                json_results["mitre_enrichment_error"] = str(e)
                logger.error("Direct enrichment failed", error=str(e))
            # Finalize resource usage and serialize report
            try:
                # Augment resource usage with execution time if available
                if isinstance(json_results, dict):
                    ru = dict(json_results.get("resource_usage") or {})
                    exec_time = json_results.get("execution_time")
                    if isinstance(exec_time, (int, float)) and exec_time >= 0:
                        ru["wall_time_seconds"] = exec_time
                    if ru:
                        json_results["resource_usage"] = ru

                # Apply vulnerable app false-positive filtering just before final serialization
                try:
                    import os as _os

                    if _os.getenv("AODS_DISABLE_RUNTIME_FP_FILTER") == "1":
                        json_results["fp_filtering_applied_runtime"] = False
                        raise RuntimeError("Runtime FP filtering disabled by env")
                    from core.vulnerable_app_coordinator import vulnerable_app_coordinator

                    # Build minimal app context
                    app_ctx = {
                        "apk_path": getattr(args, "apk", None) or json_results.get("apk_path") or "unknown",
                        "package_name": json_results.get("package_name")
                        or json_results.get("metadata", {}).get("app_package", ""),
                    }
                    # Normalize top-level vulnerabilities list(s)

                    def _apply_filter_to_list(vulns):
                        try:
                            return vulnerable_app_coordinator.apply_vulnerable_app_filtering(vulns or [], app_ctx)
                        except Exception:
                            return vulns or []

                    if isinstance(json_results.get("vulnerabilities"), list):
                        json_results["vulnerabilities"] = _apply_filter_to_list(json_results["vulnerabilities"])
                    if isinstance(json_results.get("vulnerability_findings"), list):
                        json_results["vulnerability_findings"] = _apply_filter_to_list(
                            json_results["vulnerability_findings"]
                        )
                    # Nested sections that contain vulnerabilities
                    for key, value in list(json_results.items()):
                        if isinstance(value, dict) and isinstance(value.get("vulnerabilities"), list):
                            value["vulnerabilities"] = _apply_filter_to_list(value["vulnerabilities"])
                    json_results["fp_filtering_applied_runtime"] = True
                except Exception as _fp_err:
                    json_results["fp_filtering_applied_runtime"] = False
                    json_results["fp_filtering_error"] = str(_fp_err)

                # Final report serialization: dedupe, IDs, metadata, status mapping, resource usage
                from core.reporting.final_report_serializer import serialize_final_report

                _apk_ctx = None
                try:
                    _apk_ctx = APKContext(args.apk)
                except Exception:
                    pass
                json_results = serialize_final_report(json_results, apk_context=_apk_ctx)
            except Exception as e:
                logger.warning("Final report serialization failed, writing raw results", error=str(e))

            # Attach Frida telemetry summary if available
            try:
                import json as _json
                from pathlib import Path as _Path

                _telemetry_summary_path = _Path("reports/frida_suggestions/telemetry_summary.json")
                if _telemetry_summary_path.exists():
                    with _telemetry_summary_path.open("r") as _tf:
                        _summary = _json.load(_tf)
                    analytics = json_results.get("analytics") if isinstance(json_results.get("analytics"), dict) else {}
                    analytics["frida_telemetry_summary"] = _summary
                    json_results["analytics"] = analytics
            except Exception:
                pass

            # **FINAL SYNC**: Ensure all finding containers have identical counts before writing
            # This fixes the count mismatch (Track 12) - prioritize enriched containers
            if isinstance(json_results, dict):
                # Find the most complete findings list to use as source
                enhanced = json_results.get("enhanced_vulnerabilities", [])
                vulns = json_results.get("vulnerabilities", [])
                findings = json_results.get("findings", [])
                vuln_findings = json_results.get("vulnerability_findings", [])

                # Helper to check if a list has enriched findings (contains CWE/OWASP data)
                def _has_enrichment(lst):
                    if not lst or not isinstance(lst, list):
                        return False
                    for item in lst[:5]:  # Check first 5 for efficiency
                        if isinstance(item, dict):
                            if item.get("cwe_id") or item.get("owasp_category"):
                                return True
                    return False

                # Prioritize enriched containers over raw size
                # DIRECT ENRICHMENT enriches 'vulnerabilities' and 'vulnerability_findings'
                # so prefer those if they have CWE/OWASP data, even if not the longest
                if _has_enrichment(vulns) and len(vulns) >= len(vuln_findings):
                    canonical = vulns
                elif _has_enrichment(vuln_findings):
                    canonical = vuln_findings
                else:
                    # Fallback to largest list if no enrichment found
                    canonical = max([enhanced, vulns, findings, vuln_findings], key=len, default=[])

                # **FILTER META-FINDINGS**: Remove informational/recommendation items that aren't real vulnerabilities
                # These are added by plugins as helpful suggestions but shouldn't count as vulnerabilities
                # Filter by specific title patterns only (NOT by severity) to avoid filtering real vulnerabilities
                META_FINDING_TITLES = [
                    "Alternative AODS Plugin Available",
                    "Actionable Recommendation",  # Matches "Actionable Recommendation 1", "Actionable Recommendation 2", etc.  # noqa: E501
                ]

                def _is_meta_finding(finding):
                    """Check if a finding is a meta-finding (recommendation, not a real vulnerability)."""
                    if not isinstance(finding, dict):
                        return False
                    title = finding.get("title", "")
                    for meta_title in META_FINDING_TITLES:
                        if meta_title in title:
                            return True
                    return False

                if canonical:
                    # Separate real vulnerabilities from meta-findings
                    real_vulns = [f for f in canonical if not _is_meta_finding(f)]
                    meta_findings = [f for f in canonical if _is_meta_finding(f)]

                    # Store meta-findings separately (not lost, just categorized)
                    if meta_findings:
                        json_results["recommendations"] = meta_findings
                        logger.info("Separated meta-findings into recommendations", count=len(meta_findings))

                    # Use filtered list as canonical
                    canonical = real_vulns

                    json_results["enhanced_vulnerabilities"] = canonical
                    json_results["vulnerabilities"] = canonical
                    json_results["vulnerability_findings"] = canonical
                    json_results["findings"] = canonical

                    # Update counts in summaries to match
                    if "masvs_summary" in json_results and isinstance(json_results["masvs_summary"], dict):
                        json_results["masvs_summary"]["total_findings"] = len(canonical)
                    if "integration_coverage_validation" in json_results and isinstance(
                        json_results["integration_coverage_validation"], dict
                    ):
                        json_results["integration_coverage_validation"]["total_findings"] = len(canonical)
                    if "findings_count" in json_results:
                        json_results["findings_count"] = len(canonical)

            # **FINAL EVIDENCE NORMALIZATION**: Run after ALL enrichment/sync passes
            # to promote evidence.content → code_snippet, set manifest file_path,
            # and replace generic recommendations.  Earlier passes may create fresh
            # dicts that lose fields set inside _create_canonical_findings().
            try:
                final_vulns = json_results.get("vulnerabilities", [])
                if isinstance(final_vulns, list) and final_vulns:
                    _normalize_finding_evidence(final_vulns)
                    _improve_recommendations(final_vulns)
            except Exception as _norm_err:
                logger.warning("Final evidence normalization failed (non-fatal)", error=str(_norm_err))

            try:
                with open(output_file, "w") as f:
                    json.dump(json_results, f, indent=2, default=clean_for_json)
            except Exception as _write_err:
                # Fail-safe minimal report
                _minimal = {
                    "status": (
                        json_results.get("status", "completed") if isinstance(json_results, dict) else "completed"
                    ),
                    "metadata": {
                        "app_package": getattr(args, "pkg", ""),
                        "apk_path": getattr(args, "apk", ""),
                        "error": f"report_write_failed: {_write_err}",
                    },
                    "findings": json_results.get("findings", []) if isinstance(json_results, dict) else [],
                }
                try:
                    with open(output_file, "w") as f:
                        json.dump(_minimal, f, indent=2, default=clean_for_json)
                except Exception:
                    pass

            output_mgr.success(f"Parallel scan completed! Results saved to: {output_file}")

            # Generate additional report formats (HTML, CSV) if requested
            extra_formats = [f for f in getattr(args, "formats", []) if f in ("html", "csv")]
            if extra_formats:
                try:
                    from core.shared_infrastructure.reporting.unified_facade import (
                        create_report_manager,
                    )
                    from core.shared_infrastructure.reporting.data_structures import ReportFormat

                    _rpt_mgr = create_report_manager()
                    _vulns = json_results.get("vulnerabilities", []) if isinstance(json_results, dict) else []
                    _fmt_map = {"html": ReportFormat.HTML, "csv": ReportFormat.CSV}
                    _rpt_formats = [_fmt_map[f] for f in extra_formats if f in _fmt_map]
                    if _rpt_formats and _vulns:
                        _pkg = getattr(args, "pkg", "") or "unknown"
                        _result = _rpt_mgr.generate_security_report(
                            findings=_vulns,
                            metadata={
                                "package_name": _pkg,
                                "apk_path": getattr(args, "apk", ""),
                            },
                            formats=_rpt_formats,
                            output_directory="reports",
                            base_filename=f"{_pkg}_security_report",
                        )
                        if _result and "file_paths" in _result:
                            for _fmt_name, _fpath in _result["file_paths"].items():
                                if isinstance(_fpath, str):
                                    output_mgr.success(f"{_fmt_name.upper()} report saved to: {_fpath}")
                except Exception as _rpt_err:
                    output_mgr.warning(f"Additional report generation failed (non-fatal): {_rpt_err}")

            # --- Agent integration (Track 104) ---
            # Mirrors execution_standard.py: run requested agents on the
            # completed report.  All failures are caught - never blocks scan.
            _run_agents_on_parallel_report(args, output_file, output_mgr)

            # Export Objection verification commands if requested
            if args.export_objection_commands and args.with_objection:
                try:
                    objection_results = results.get("objection")
                    if objection_results and hasattr(objection_results, "findings") and objection_results.findings:
                        findings_data = (
                            objection_results.findings[1]
                            if isinstance(objection_results.findings, tuple)
                            else objection_results.findings
                        )
                        verification_commands = findings_data.get("verification_commands", [])

                        if verification_commands:
                            objection_output_file = f"objection_commands_{args.pkg}_{int(time.time())}.txt"
                            with open(objection_output_file, "w") as f:
                                f.write(f"# Objection Verification Commands for {args.pkg}\n")
                                f.write(f"# Generated by AODS on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                                f.write(f"# Total commands: {len(verification_commands)}\n\n")

                                for i, cmd in enumerate(verification_commands, 1):
                                    f.write(f"# Command {i}: {cmd.get('description', 'Manual verification')}\n")
                                    f.write(f"{cmd.get('command', 'objection -g ' + args.pkg + ' explore')}\n\n")

                            output_mgr.success(f"✅ Objection commands exported to: {objection_output_file}")
                        else:
                            output_mgr.info("ℹ️ No Objection verification commands to export")
                except Exception as e:
                    output_mgr.warning(f"⚠️ Failed to export Objection commands: {e}")
            # Track 75.fix: Use post-dedup count from final report, not pre-dedup total_findings
            final_count = (
                len(json_results.get("vulnerabilities", [])) if isinstance(json_results, dict) else total_findings
            )

            # PERMANENT FIX: Use correct counts for orchestrator vs legacy results
            if consolidated_results and (
                consolidated_results.get("status") == "completed" or consolidated_results.get("success")
            ):
                # Orchestrator case - use orchestrator metrics
                total_scans = 1  # One orchestrator run
                logger.info(
                    "Unified orchestration results summary",
                    status="completed",
                    total_findings=final_count,
                    job_id=consolidated_results.get("job_id", "N/A"),
                    execution_time=round(consolidated_results.get("execution_time", 0), 1),
                )
            else:
                # Legacy parallel scan case
                # FIXED: Use proper success rate calculation based on actual scan execution
                total_scan_attempts = max(len(results), successful_scans)  # At least as many as successful
                rate = (successful_scans / total_scan_attempts) if total_scan_attempts > 0 else 0
                logger.info(
                    "Parallel scan results summary",
                    successful_scans=successful_scans,
                    total_findings=final_count,
                    success_rate=round(rate, 3),
                )

            return 0
        except ImportError:
            output_mgr.warning("Parallel scan manager not available, falling back to standard execution")
        except Exception as e:
            output_mgr.error(f"Parallel scan manager failed: {e}")
            output_mgr.warning("Falling back to standard execution")
    # Check for enhanced parallel execution first
    if ENHANCED_PARALLEL_AVAILABLE and (args.parallel_windows or args.parallel):
        output_mgr.info("Using Enhanced Parallel Execution Architecture")

        # Add parallel execution flags to args
        args.parallel_execution = args.parallel or args.parallel_windows
        args.separate_windows = args.parallel_windows

        # Handle Objection Integration
        objection_context = None
        if args.with_objection:
            try:
                try:
                    from plugins.objection_integration import (
                        ObjectionReconnaissanceModule,
                        ObjectionVerificationAssistant,
                        ObjectionTrainingModule,
                        ObjectionDevelopmentTesting,
                    )
                except ImportError:
                    # Fallback: try direct import without plugins prefix
                    import sys

                    sys.path.insert(0, str(REPO_ROOT / "plugins" / "objection_integration"))
                    try:
                        from main import (  # type: ignore
                            ObjectionReconnaissanceModule,
                            ObjectionVerificationAssistant,
                            ObjectionTrainingModule,
                            ObjectionDevelopmentTesting,
                        )
                    except ImportError:
                        from __init__ import (  # type: ignore  # noqa: F401
                            ObjectionReconnaissanceModule,
                            ObjectionVerificationAssistant,
                            ObjectionTrainingModule,
                            ObjectionDevelopmentTesting,
                        )

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

        # PHASE 0.5: AODS_CANONICAL Feature Flag - Canonical Orchestration
        AODS_CANONICAL = os.getenv("AODS_CANONICAL", "0") == "1"

        if AODS_CANONICAL:
            try:
                output_mgr.info("🚀 AODS_CANONICAL=1: Using canonical orchestration architecture")
                from core.execution.canonical_orchestrator import execute_canonical_analysis

                # Execute analysis using canonical orchestrator
                result = execute_canonical_analysis(args)

                if result.success:
                    output_mgr.success("✅ Canonical orchestration completed successfully")

                    # Display full results
                    output_mgr.info("📊 Canonical Analysis Results:")
                    output_mgr.info(f"   🎯 Strategy Used: {result.strategy_used.value}")
                    output_mgr.info(f"   🔍 Vulnerabilities Found: {result.vulnerabilities_found}")
                    output_mgr.info(f"   ⚡ Execution Time: {result.execution_time:.2f}s")
                    output_mgr.info(f"   📋 Plugins Executed: {result.total_plugins_executed}")
                    output_mgr.info(f"   ✅ Successful: {result.successful_plugins}")
                    output_mgr.info(f"   ❌ Failed: {result.failed_plugins}")

                    # Generate reports (test_suite not available in this path)
                    generated_files = {}

                    output_mgr.success("AODS canonical analysis completed successfully!")
                    output_mgr.info("Generated reports:")
                    for format_name, file_path in generated_files.items():
                        output_mgr.info(f"  {format_name.upper()}: {file_path}")
                    # Mirror latest JSON to artifacts/reports/sysreptor_report.json for UI 'Latest'
                    try:
                        import os as _os
                        import shutil as _shutil
                        from pathlib import Path as _Path

                        repo_root = REPO_ROOT
                        # Prefer a JSON report if present in mapping
                        json_path = None
                        for k, v in (generated_files or {}).items():
                            if str(k).lower().strip() in {"json", "sysreptor_json", "report_json"} or str(
                                v
                            ).lower().endswith(".json"):
                                json_path = v
                                break
                        if json_path and _os.path.exists(json_path):
                            dest_dir = repo_root.parent / "artifacts" / "reports"
                            dest_dir.mkdir(parents=True, exist_ok=True)
                            dest_file = dest_dir / "sysreptor_report.json"
                            _shutil.copyfile(json_path, dest_file)
                            logger.info("Mirrored latest report", dest=str(dest_file))
                    except Exception as e:
                        logger.warning("Failed to mirror latest report", error=str(e))

                    return 0
                else:
                    # Single-path policy: do not fall back mid-run; surface error and exit non-zero
                    msg = result.error_message or "Canonical orchestration reported unsuccessful result"
                    output_mgr.error(f"❌ Canonical orchestration failed: {msg}")
                    return 2
            except Exception as e:
                # Single-path policy: do not fall back mid-run; surface error and exit non-zero
                output_mgr.error(f"❌ Canonical orchestration exception: {e}")
                import traceback

                if output_mgr.verbose:
                    output_mgr.error(f"Canonical orchestration traceback: {traceback.format_exc()}")
                return 2

        return 0
