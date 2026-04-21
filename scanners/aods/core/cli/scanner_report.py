"""
core.cli.scanner_report - Report generation extracted from AODSScanner (Track 50).

Contains the generate_report_impl() function which is the body of
AODSScanner.generate_report(), accepting the scanner instance directly.
"""

import os
import logging
import time
from pathlib import Path
from typing import Dict

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from core.output_manager import get_output_manager
from core.report_validator import ReportValidator

from core.cli.feature_flags import (
    ENHANCED_REPORTING_AVAILABLE,
    ML_INTEGRATION_AVAILABLE,
    THREAT_INTELLIGENCE_AVAILABLE,
    UNIFIED_REPORTING_AVAILABLE,
    MLIntegrationManager,
    get_unified_threat_intelligence,
)

from core.cli.finding_processing import (
    _extract_findings_from_content,
    _is_valid_finding_title,
    _normalize_finding_evidence,
    _improve_recommendations,
)

# Conditional imports matching scanner.py pattern
try:
    from core.cli.feature_flags import EnhancedVulnerabilityReportingEngine
except ImportError:
    EnhancedVulnerabilityReportingEngine = None

if UNIFIED_REPORTING_AVAILABLE:
    try:
        from core.shared_infrastructure.reporting import ReportFormat
    except ImportError:
        ReportFormat = None
else:
    ReportFormat = None


def _truncate_at_word(text: str, max_len: int) -> str:
    """Truncate text at a word boundary to avoid mid-word cuts."""
    if not text or len(text) <= max_len:
        return text
    truncated = text[:max_len]
    last_space = truncated.rfind(" ")
    if last_space > max_len * 0.6:
        truncated = truncated[:last_space]
    return truncated.rstrip(",.;: ") + "..."


def generate_report_impl(scanner) -> Dict[str, str]:
    """
    Generate security reports in multiple formats.

    This is the extracted body of AODSScanner.generate_report().
    The scanner instance is passed directly to preserve access to all attributes.

    Args:
        scanner: AODSScanner instance with all scan state.

    Returns:
        Dict mapping format names to generated file paths.
    """
    # Ensure VulnerabilityClassifier is available in this scope
    from core.vulnerability_classifier import VulnerabilityClassifier

    output_mgr = get_output_manager()

    # FP reduction now handled in execution_parallel.py (Track 112 canonical reducer)
    # No per-report filtering needed - findings are already filtered before report generation

    # CRITICAL FIX: DO NOT override report generator scan mode - it uses centralized tracker
    # The ReportGenerator constructor already uses get_effective_scan_mode() for consistency
    # scanner.report_generator.scan_mode = scanner.apk_ctx.scan_mode  # REMOVED - causes inconsistency

    # Track 11: Build domain metadata dict (applies to both reporting paths)
    domain_metadata = {}
    if hasattr(scanner, "business_domain") and scanner.business_domain:
        domain_value = (
            scanner.business_domain.value if hasattr(scanner.business_domain, "value") else str(scanner.business_domain)
        )
        domain_metadata["business_domain"] = domain_value
        if hasattr(scanner, "business_domain_info") and scanner.business_domain_info:
            domain_metadata["business_domain_info"] = {
                "name": scanner.business_domain_info.get("name", domain_value),
                "security_level": scanner.business_domain_info.get("security_level", "MEDIUM"),
                "confidence_multiplier": scanner.business_domain_info.get("confidence_multiplier", 1.0),
                "regulatory_requirements": scanner.business_domain_info.get("regulatory_requirements", []),
            }

    # Track 60 Fix 10: Inject analysis_duration into report metadata
    scan_start = getattr(scanner, "_scan_start_time", None)
    analysis_duration = round(time.time() - scan_start, 2) if scan_start else 0.0

    # Extract manifest data for attack surface persistence (survives workspace cleanup)
    manifest_data = None
    try:
        manifest_p = getattr(scanner.apk_ctx, "manifest_path", None)
        if manifest_p:
            from core.analysis.attack_surface import extract_manifest_data

            manifest_data = extract_manifest_data(manifest_p)
    except Exception:
        pass  # Non-critical - attack surface will use file fallback if available

    # Handle both unified and legacy reporting systems for metadata
    if hasattr(scanner, "report_generator") and scanner.report_generator is not None:
        # Using legacy reporting system
        scanner.report_generator.add_metadata("apk_path", str(scanner.apk_ctx.apk_path))
        scanner.report_generator.add_metadata("total_tests_run", len(scanner.report_data))
        scanner.report_generator.add_metadata("analysis_duration", analysis_duration)
        scanner.report_generator.add_metadata("workspace_dir", str(scanner.apk_ctx.decompiled_apk_dir))
        if manifest_data:
            scanner.report_generator.add_metadata("manifest_data", manifest_data)
        for k, v in domain_metadata.items():
            scanner.report_generator.add_metadata(k, v)
    elif hasattr(scanner, "report_manager") and scanner.report_manager is not None:
        # Using unified reporting system - store metadata for later use
        if not hasattr(scanner, "_report_metadata"):
            scanner._report_metadata = {}
        scanner._report_metadata["apk_path"] = str(scanner.apk_ctx.apk_path)
        scanner._report_metadata["total_tests_run"] = len(scanner.report_data)
        scanner._report_metadata["analysis_duration"] = analysis_duration
        scanner._report_metadata["workspace_dir"] = str(scanner.apk_ctx.decompiled_apk_dir)
        if manifest_data:
            scanner._report_metadata["manifest_data"] = manifest_data
        scanner._report_metadata.update(domain_metadata)

    # Apply ML-enhanced vulnerability classification with fallback
    output_mgr.status("Applying ML-enhanced vulnerability classification...", "info")

    # Initialize ML Integration Manager with intelligent fallback
    use_ml = False
    ml_manager = None
    # Initialize VulnerabilityClassifier (imported locally above)
    classifier = VulnerabilityClassifier()  # Always initialize fallback classifier

    # Respect the enable_ml setting from command line arguments
    if scanner.enable_ml and ML_INTEGRATION_AVAILABLE:
        try:
            if MLIntegrationManager is not None:
                ml_manager = MLIntegrationManager(enable_ml=True)
                # CRITICAL FIX: Set vulnerable app mode for ML classification
                ml_manager.vulnerable_app_mode = scanner.vulnerable_app_mode
                output_mgr.info(f"🎯 ML classifier configured for vulnerable_app_mode: {scanner.vulnerable_app_mode}")

                # Also configure detection settings based on app type
                if scanner.vulnerable_app_mode:
                    output_mgr.info("🏫 Using training-grade detection settings")
                else:
                    output_mgr.info("🏢 Using production-grade detection settings")

                output_mgr.status("ML Integration Manager initialized", "success")
                use_ml = True
        except Exception as e:
            output_mgr.warning(f"ML Integration Manager failed to initialize: {e}")
            output_mgr.warning("Falling back to organic-only classification...")
            use_ml = False
    elif not scanner.enable_ml:
        output_mgr.status("🤖 ML components disabled via --disable-ml flag", "info")
        output_mgr.status("Using organic-only classification...", "info")
    else:
        output_mgr.warning("ML Integration not available - using organic-only classification...")

    # VULNERABLE APP MODE: Apply relaxed settings for maximum vulnerability detection
    if scanner.vulnerable_app_mode:
        output_mgr.status("VULNERABLE APP MODE ENABLED", "warning")
        output_mgr.status("🔓 Using relaxed detection settings for maximum vulnerability detection", "warning")
        output_mgr.status("   • Confidence threshold: 0.1 (10%) instead of 0.7 (70%)", "info")
        output_mgr.status("   • Similarity threshold: 0.6 (60%) instead of 0.85 (85%)", "info")
        output_mgr.status("   • Severity filtering: INFO+ instead of MEDIUM+", "info")
        output_mgr.status("   • Framework filtering: DISABLED for maximum detection", "info")

        # Create vulnerable app mode configuration
        try:
            from core.vulnerability_filter import VulnerabilitySeverity
            from core.accuracy_integration_pipeline.data_structures import (
                PipelineConfiguration,
                ConfidenceCalculationConfiguration,
            )

            # Create relaxed pipeline configuration for vulnerable apps
            vulnerable_config = PipelineConfiguration(
                vulnerable_app_mode=True,
                min_severity=VulnerabilitySeverity.INFO,
                enable_framework_filtering=False,
                enable_context_filtering=True,
                preserve_high_confidence_low_severity=True,
                similarity_threshold=0.6,
                confidence_config=ConfidenceCalculationConfiguration(
                    min_confidence_threshold=0.1,
                    enable_vulnerability_preservation=True,
                    enable_context_enhancement=True,
                    enable_evidence_aggregation=True,
                ),
            )

            # Apply vulnerable app mode settings
            vulnerable_config.apply_vulnerable_app_mode()

            # Configure classifiers with relaxed settings
            if use_ml and ml_manager:
                # Apply vulnerable config to ML manager if it supports it
                if hasattr(ml_manager, "apply_vulnerable_app_config"):
                    config_applied = ml_manager.apply_vulnerable_app_config(vulnerable_config)
                    if config_applied:
                        output_mgr.status("   • ML configuration applied for vulnerable app mode", "success")
                    else:
                        output_mgr.status("   • ML configuration not applied (method failed)", "warning")
                else:
                    output_mgr.status("   • ML manager doesn't support vulnerable app config", "info")
                output_mgr.status("   • ML + Organic detection with MAXIMUM SENSITIVITY", "info")
            else:
                # Apply vulnerable config to organic classifier if it supports it
                if hasattr(classifier, "apply_vulnerable_app_config"):
                    config_applied = classifier.apply_vulnerable_app_config(vulnerable_config)
                    if config_applied:
                        output_mgr.status("   • Organic classifier configured for vulnerable app mode", "success")
                    else:
                        output_mgr.status(
                            "   • Organic classifier configuration not applied (method failed)", "warning"
                        )
                else:
                    output_mgr.status("   • Organic classifier doesn't support vulnerable app config", "info")
                output_mgr.status("   • Organic-only detection with MAXIMUM SENSITIVITY", "info")

            output_mgr.status("Vulnerable app mode configuration applied", "success")

        except ImportError as e:
            output_mgr.warning(f"Could not apply vulnerable app mode: {e}")
            output_mgr.status("Using standard detection settings instead", "info")
    else:
        output_mgr.status("🏢 Using production-grade detection settings", "info")

    ReportValidator()

    # ENHANCED: Extract findings for classification with detailed vulnerability detection
    all_findings = []
    for title, content in scanner.report_data:
        # Handle PluginResult objects from v2 plugins - extract structured findings
        # before falling through to the generic str(content) path
        if hasattr(content, "findings") and hasattr(content, "status"):
            # PluginResult dataclass: extract each PluginFinding as a proper dict
            plugin_source = title.replace("✅ ", "").replace("❌ ", "").replace("⏰ ", "")
            for pf in content.findings or []:
                child = {
                    "title": getattr(pf, "title", "Security Finding"),
                    "description": _truncate_at_word(getattr(pf, "description", ""), 500),
                    "severity": getattr(pf, "severity", None) or "medium",
                    "confidence": getattr(pf, "confidence", 0.5),
                    "file_path": getattr(pf, "file_path", None),
                    "location": getattr(pf, "file_path", None) or "unknown",
                    "line_number": getattr(pf, "line_number", None),
                    "cwe_id": getattr(pf, "cwe_id", None),
                    "owasp_category": getattr(pf, "owasp_category", None),
                    "masvs_control": getattr(pf, "masvs_control", None),
                    "evidence": getattr(pf, "evidence", {}),
                    "remediation": getattr(pf, "remediation", None),
                    "references": getattr(pf, "references", []),
                    "code_snippet": getattr(pf, "code_snippet", None),
                    "vulnerability_type": getattr(pf, "vulnerability_type", None),
                    "plugin_source": plugin_source,
                    "status": "FAIL",
                    "content": getattr(pf, "description", ""),
                    "result": getattr(pf, "description", ""),
                }
                # Copy remediation → recommendation so downstream pipeline finds it
                if child.get("remediation"):
                    child["recommendation"] = child["remediation"]
                # Remove None values to avoid overriding defaults downstream,
                # but preserve location/file_path with empty string fallback
                # so the HTML formatter can still render them
                child = {
                    k: ("" if k in ("file_path", "location") else None) if v is None else v
                    for k, v in child.items()
                }
                child = {k: v for k, v in child.items() if v is not None}
                all_findings.append(child)
            # Always skip generic str(content) path for PluginResult objects,
            # even when findings is empty (avoids plugin name as finding title)
            continue

        # Basic finding structure
        finding = {
            "title": title,
            "content": str(content),
            "description": _truncate_at_word(str(content), 200),
            "status": scanner._determine_status_from_content(content),
            "result": str(content),
        }

        # ENHANCED: Extract additional vulnerability indicators from structured content
        content_str = str(content).lower()

        # Extract explicit status indicators
        if "status: fail" in content_str or "status: failed" in content_str:
            finding["status"] = "FAIL"
            finding["vulnerability_indicator"] = "explicit_failure"
        elif "risk level: high" in content_str or "risk_level: high" in content_str:
            finding["risk_level"] = "HIGH"
            finding["vulnerability_indicator"] = "high_risk"
        elif "risk level: medium" in content_str or "risk_level: medium" in content_str:
            finding["risk_level"] = "MEDIUM"
            finding["vulnerability_indicator"] = "medium_risk"

        # Extract MASTG compliance failures
        if "failed:" in content_str and "mstg-" in content_str:
            finding["compliance_failure"] = True
            finding["vulnerability_indicator"] = "compliance_failure"

        # Extract network security issues
        if "cleartext traffic enabled" in content_str or 'usescleartexttraffic="true"' in content_str:
            finding["network_security_issue"] = "cleartext_traffic"
            finding["vulnerability_indicator"] = "network_security"
            finding["severity"] = "HIGH"

        # Extract certificate pinning issues
        if "certificate pinning" in content_str and ("missing" in content_str or "not detected" in content_str):
            finding["network_security_issue"] = "missing_cert_pinning"
            finding["vulnerability_indicator"] = "network_security"
            finding["severity"] = "HIGH"

        # Extract security grade failures
        if "security grade: f" in content_str or "overall score: 0.0%" in content_str:
            finding["vulnerability_indicator"] = "security_grade_fail"
            if not finding.get("severity") or finding.get("severity") == "?":
                finding["severity"] = "HIGH"
            finding["status"] = "FAIL"

        # Extract certificate security issues (self-signed, debug certs)
        if "security issues:" in content_str or "priority issues" in content_str:
            finding["vulnerability_indicator"] = "security_issues_present"
            if not finding.get("severity") or finding.get("severity") == "?":
                finding["severity"] = "MEDIUM"

        # Extract debug certificate usage
        if "android debug" in content_str and ("self-signed" in content_str or "certificate" in content_str):
            finding["vulnerability_indicator"] = "debug_certificate"
            finding["vulnerability_type"] = "insecure_certificate"
            if not finding.get("severity") or finding.get("severity") == "?":
                finding["severity"] = "MEDIUM"

        # Extract dangerous permissions
        if "dangerous permission" in content_str:
            finding["vulnerability_indicator"] = "dangerous_permissions"
            if not finding.get("severity") or finding.get("severity") == "?":
                finding["severity"] = "MEDIUM"

        # Enhanced finding extraction from structured content
        has_children = False
        if isinstance(content, dict):
            # Extract structured vulnerability data
            for key in (
                "status",
                "risk_level",
                "evidence",
                "masvs_control",
                "severity",
                "cwe_id",
                "vulnerability_type",
                "confidence",
            ):
                if key in content:
                    finding[key] = content[key]

            # Expand nested vulnerabilities list into individual findings
            if "vulnerabilities" in content and isinstance(content["vulnerabilities"], list):
                for vuln in content["vulnerabilities"]:
                    if not isinstance(vuln, dict):
                        continue
                    child = {
                        "title": vuln.get("title", title),
                        "content": str(vuln),
                        "description": _truncate_at_word(vuln.get("description", str(vuln)), 200),
                        "status": vuln.get("status", "FAIL"),
                        "result": str(vuln),
                    }
                    # Track 72: Copy ALL vuln dict fields (not just a subset)
                    # to preserve line_number, file_path, location, plugin_source, etc.
                    for vkey, vval in vuln.items():
                        if vkey not in child and vval is not None:
                            child[vkey] = vval
                    all_findings.append(child)
                    has_children = True

        # Only add the parent finding when no children were extracted  - 
        # otherwise we'd pollute the classifier with summary-titled entries
        # (e.g., "jadx_static_analysis") that crowd out individual findings.
        if not has_children:
            all_findings.append(finding)

    # Pre-classification: remove plugin summary entries that have plugin-name
    # titles (e.g., "jadx_static_analysis", "APK Information Extraction").
    # These are status summaries, not individual security findings. Keeping them
    # causes the classifier to prefer them (rich text content) over real findings.
    pre_filter_count = len(all_findings)
    all_findings = [f for f in all_findings if _is_valid_finding_title(f.get("title", ""))]
    if pre_filter_count != len(all_findings):
        output_mgr.info(
            f"Pre-classification filter: {pre_filter_count} -> {len(all_findings)} "
            f"({pre_filter_count - len(all_findings)} summaries removed)"
        )

    # Apply ML-enhanced or fallback classification
    classification_results = None  # Initialize to avoid UnboundLocalError

    if use_ml and ml_manager is not None:
        try:
            # Use ML Integration Manager
            output_mgr.status("Running hybrid ML + organic vulnerability detection...", "info")
            classification_results = ml_manager.classify_all_findings(all_findings)

            # Extract ML performance metrics
            ml_metrics = ml_manager.get_performance_metrics()

            # Handle both detailed and simplified metric responses
            if "status" in ml_metrics and ml_metrics["status"] == "No predictions made yet":
                output_mgr.status(
                    f"ML Metrics: 0 predictions made, " f"Mode: ML-enabled (fallback), Status: {ml_metrics['status']}",
                    "info",
                )
            else:
                predictions_made = ml_metrics.get("total_predictions", ml_metrics.get("predictions_made", 0))
                agreement_rate = ml_metrics.get("hybrid_agreement_rate", 0.0)
                ml_enabled = ml_manager.get_ml_status().get("ml_enabled", False)
                output_mgr.status(
                    f"ML Metrics: {predictions_made} predictions, "
                    f"{agreement_rate:.1%} ML-organic agreement, "
                    f"Mode: {'ML-enhanced' if ml_enabled else 'Organic-only'}",
                    "info",
                )
        except Exception as e:
            output_mgr.warning(f"ML classification failed: {e}")
            output_mgr.status("Falling back to organic-only vulnerability detection...", "info")
            classification_results = classifier.classify_all_findings(all_findings)
    else:
        # Fallback to organic-only classification
        output_mgr.status("Running organic-only vulnerability detection...", "info")
        classification_results = classifier.classify_all_findings(all_findings)

    # PHASE 4A INTEGRATION - AI-Enhanced Vulnerability Detection and Performance Optimization
    phase4a_enhanced_detection_enabled = os.getenv("PHASE4A_ENHANCED_DETECTION", "0") == "1"
    phase4a_performance_optimizer_enabled = os.getenv("PHASE4A_PERFORMANCE_OPTIMIZER", "0") == "1"

    if phase4a_enhanced_detection_enabled or phase4a_performance_optimizer_enabled:
        try:
            output_mgr.status("🚀 Phase 4A AI-Enhanced Analysis starting...", "info")

            # Phase 4A.1: Enhanced Vulnerability Detection Engine
            if phase4a_enhanced_detection_enabled:
                try:
                    from core.ai_ml.enhanced_vulnerability_detection_engine import get_enhanced_vulnerability_detector

                    enhanced_detector = get_enhanced_vulnerability_detector()

                    output_mgr.status("🎯 Phase 4A.1: AI-Enhanced Vulnerability Detection active", "info")

                    # Process existing vulnerabilities with enhanced detection
                    enhanced_vulnerabilities = []
                    original_count = len(classification_results.get("vulnerabilities", []))

                    output_mgr.status(
                        f"🔧 Phase 4A.1: Processing {original_count} vulnerabilities with AI enhancement", "info"
                    )

                    # Apply enhanced detection to each existing vulnerability for refinement
                    for i, vuln in enumerate(classification_results.get("vulnerabilities", [])):
                        try:
                            # Handle different vulnerability object types and extract content
                            if isinstance(vuln, dict):
                                content = vuln.get("content", "")
                                title = vuln.get("title", "")
                                file_path = vuln.get("location", "")
                                vuln_dict = vuln  # Already a dictionary
                            elif hasattr(vuln, "explanation"):
                                # DetectionResult object from AI/ML detector
                                content = getattr(vuln, "explanation", "")
                                title = getattr(vuln, "vulnerability_type", "")
                                file_path = ""
                                # Convert DetectionResult dataclass to dictionary format
                                vuln_dict = {
                                    "content": content,
                                    "title": title,
                                    "location": file_path,
                                    "vulnerability_type": getattr(vuln, "vulnerability_type", ""),
                                    "severity": getattr(vuln, "severity", ""),
                                    "confidence": getattr(vuln, "confidence", 0.0),
                                    "explanation": getattr(vuln, "explanation", ""),
                                    "recommendation": getattr(vuln, "recommendation", ""),
                                    "is_vulnerability": getattr(vuln, "is_vulnerability", False),
                                }
                            elif hasattr(vuln, "content"):
                                # Handle other object types with content attribute
                                content = getattr(vuln, "content", "")
                                title = getattr(vuln, "title", "")
                                file_path = getattr(vuln, "location", "")
                                vuln_dict = {"content": content, "title": title, "location": file_path}
                            else:
                                # Handle string or other types
                                content = str(vuln)
                                title = ""
                                file_path = ""
                                vuln_dict = {"content": content, "title": title, "location": file_path}

                            output_mgr.status(
                                f"🔍 Phase 4A.1: Analyzing vulnerability {i + 1}/{original_count} (type: {type(vuln).__name__})",  # noqa: E501
                                "info",
                            )

                            enhanced_result = enhanced_detector.detect_vulnerabilities_enhanced(
                                content=content, title=title, file_path=file_path
                            )

                            output_mgr.status(
                                f"✅ Phase 4A.1: Enhancement result - Type: {type(enhanced_result)}, "
                                f"is_vulnerability: {enhanced_result.is_vulnerability}, "
                                f"confidence: {enhanced_result.confidence:.3f}",
                                "info",
                            )

                            if enhanced_result.is_vulnerability and enhanced_result.confidence > 0.5:
                                # Enhance existing vulnerability with AI insights
                                enhanced_vuln = vuln_dict.copy()
                                enhanced_vuln.update(
                                    {
                                        "ai_enhanced": True,
                                        "enhanced_confidence": enhanced_result.confidence,
                                        "ai_reasoning": enhanced_result.explanation,
                                        "enhanced_severity": enhanced_result.severity,
                                        "false_positive_probability": enhanced_result.false_positive_probability,
                                        "enhanced_description": enhanced_result.explanation,
                                    }
                                )
                                enhanced_vulnerabilities.append(enhanced_vuln)
                            else:
                                # Keep original vulnerability if not enhanced
                                enhanced_vulnerabilities.append(vuln_dict)

                        except Exception as vuln_error:
                            output_mgr.warning(f"Phase 4A.1: Failed to enhance vulnerability {i + 1}: {vuln_error}")
                            # Keep original vulnerability if enhancement fails
                            enhanced_vulnerabilities.append(vuln)

                    # Update classification results with enhanced vulnerabilities
                    if enhanced_vulnerabilities:
                        classification_results["vulnerabilities"] = enhanced_vulnerabilities
                        classification_results["enhanced_by_phase4a"] = True
                        enhanced_count = len(enhanced_vulnerabilities)

                        output_mgr.status(
                            f"✅ Phase 4A.1: Enhanced {original_count}→{enhanced_count} vulnerabilities "
                            f"with AI detection engine",
                            "info",
                        )
                    else:
                        output_mgr.info("No vulnerabilities enhanced - keeping original results")

                except ImportError as import_error:
                    output_mgr.warning(f"Phase 4A.1: Enhanced detection engine not available: {import_error}")
                except Exception as phase4a1_error:
                    output_mgr.warning(f"Phase 4A.1: Enhanced detection failed: {phase4a1_error}")
                    output_mgr.status("Continuing with standard analysis...", "info")

            # Phase 4A.2: Predictive Performance Optimization
            if phase4a_performance_optimizer_enabled:
                # MIGRATED: Use unified performance infrastructure for predictive optimization
                from core.shared_infrastructure.monitoring.performance_tracker import get_unified_performance_tracker

                performance_optimizer = get_unified_performance_tracker()

                output_mgr.status("⚡ Phase 4A.2: Predictive Performance Optimization active", "info")

                # Create analysis context for optimization
                analysis_context = {
                    "apk_name": scanner.apk_ctx.package_name,
                    "vulnerability_count": len(classification_results.get("vulnerabilities", [])),
                    "scan_mode": getattr(scanner.apk_ctx, "scan_mode", "safe"),
                    "ml_enabled": use_ml,
                }

                # Apply performance optimization predictions
                from core.ai_ml.predictive_analysis_performance_optimizer import WorkloadType

                workload_prediction = performance_optimizer.predict_workload_performance(
                    WorkloadType.SINGLE_ANALYSIS, analysis_context
                )

                optimization_result = performance_optimizer.optimize_analysis_performance(
                    workload_prediction, analysis_context
                )

                # Log performance optimization results
                improvement_pct = optimization_result.expected_improvement_percent
                output_mgr.status(
                    f"✅ Phase 4A.2: Predicted {improvement_pct:.1f}% performance improvement "
                    f"through predictive optimization",
                    "info",
                )

                # Add optimization metadata
                classification_results["performance_optimization"] = {
                    "phase4a_optimized": True,
                    "predicted_improvement_percentage": improvement_pct,
                    "optimization_strategies": [str(opt.value) for opt in optimization_result.applied_optimizations],
                }

            output_mgr.status("🎉 Phase 4A AI-Enhanced Analysis complete!", "info")

        except ImportError as e:
            output_mgr.warning(f"Phase 4A components not available: {e}")
        except Exception as e:
            output_mgr.warning(f"Phase 4A enhancement failed: {e}")
            output_mgr.status("Continuing with standard analysis...", "info")
    # ENHANCED VULNERABILITY REPORTING - Add technical details and fix classification issues
    if ENHANCED_REPORTING_AVAILABLE:
        try:
            import logging

            logger = logging.getLogger(__name__)
            logger.info("🔧 Applying Enhanced Vulnerability Reporting...")

            # Initialize enhanced reporting engine
            # **SURGICAL FIX**: Handle both UnifiedReportingManager (no params) and original class (requires params)
            try:
                # Try without parameters first (UnifiedReportingManager alias)
                enhanced_engine = EnhancedVulnerabilityReportingEngine()
            except TypeError as e:
                if "missing 1 required positional argument: 'apk_path'" in str(e):
                    # Fallback: Original class requires parameters
                    enhanced_engine = EnhancedVulnerabilityReportingEngine(
                        apk_path=scanner.apk_ctx.apk_path_str, target_package=scanner.package_name
                    )
                else:
                    # Re-raise unexpected TypeError
                    raise

            # Create app context for enhanced analysis
            app_context = {
                "package_name": scanner.package_name,
                "apk_path": scanner.apk_ctx.apk_path_str,
                "decompiled_path": getattr(scanner.apk_ctx, "decompiled_apk_dir", ""),
                "scan_mode": getattr(scanner.apk_ctx, "scan_mode", "safe"),
            }

            # Get raw findings from classified results
            # ACCURACY FIX: Only enhance true vulnerabilities (exclude informational/PASS)
            raw_findings = list(classification_results.get("vulnerabilities", []))

            logger.info(f"📊 Enhancing {len(raw_findings)} findings with technical details...")

            # Apply enhanced reporting
            enhanced_results = enhanced_engine.enhance_vulnerability_report(raw_findings, app_context)

            # PERMANENT REGRESSION FIX: Ensure enhanced_results is always a dictionary
            if isinstance(enhanced_results, list):
                # Convert list to proper dictionary format
                enhanced_results = {
                    "enhanced_vulnerabilities": enhanced_results,
                    "executive_summary": {"total_vulnerabilities": len(enhanced_results), "severity_breakdown": {}},
                    "technical_summary": {
                        "total_vulnerabilities": len(enhanced_results),
                        "technical_details": "Enhanced reporting converted from list format",
                    },
                    "actionable_recommendations": [],
                    "html_report": None,
                }
                logger.info("Enhanced results converted from list to dictionary format")
            elif not isinstance(enhanced_results, dict) and enhanced_results is not None:
                # Handle other unexpected types
                logger.warning(
                    f"Enhanced results has unexpected type {type(enhanced_results)}, creating empty dictionary"
                )
                enhanced_results = {
                    "enhanced_vulnerabilities": [],
                    "executive_summary": {"total_vulnerabilities": 0, "severity_breakdown": {}},
                    "technical_summary": {"total_vulnerabilities": 0, "technical_details": "Type conversion fallback"},
                    "actionable_recommendations": [],
                    "html_report": None,
                }

            # Update classification results with enhanced data
            if enhanced_results:
                logger.info("✅ Enhanced reporting generated:")
                logger.info(f"   Original findings: {len(raw_findings)}")
                if isinstance(enhanced_results, dict):
                    exec_summary = enhanced_results.get("executive_summary", {})
                    if isinstance(exec_summary, dict):
                        logger.info(f"   Enhanced vulnerabilities: {exec_summary.get('total_vulnerabilities', 0)}")
                        logger.info(f"   Severity breakdown: {exec_summary.get('severity_breakdown', {})}")
                    else:
                        logger.info("   Enhanced vulnerabilities: 0 (summary type error)")
                        logger.info("   Severity breakdown: {} (summary type error)")
                else:
                    logger.info(f"   Enhanced vulnerabilities: 0 (results type error: {type(enhanced_results)})")
                    logger.info("   Severity breakdown: {} (results type error)")

                # Save enhanced HTML report
                if isinstance(enhanced_results, dict) and enhanced_results.get("html_report"):
                    html_filename = f"{scanner.package_name}_enhanced_security_report.html"
                    with open(html_filename, "w", encoding="utf-8") as f:
                        f.write(enhanced_results["html_report"])
                    logger.info(f"📄 Enhanced HTML report saved: {html_filename}")

                # Merge enhanced results back into classification_results - with type checking
                if isinstance(enhanced_results, dict):
                    classification_results.update(
                        {
                            "enhanced_vulnerabilities": enhanced_results.get("enhanced_vulnerabilities", []),
                            "enhanced_executive_summary": enhanced_results.get("executive_summary", {}),
                            "technical_summary": enhanced_results.get(
                                "technical_summary",
                                {
                                    "total_vulnerabilities": len(enhanced_results.get("enhanced_vulnerabilities", [])),
                                    "technical_details": "Enhanced technical summary generated",
                                },
                            ),
                            "actionable_recommendations": enhanced_results.get("actionable_recommendations", []),
                            "enhanced_reporting_applied": True,
                        }
                    )
                else:
                    # Fallback if enhanced_results is not a dictionary
                    classification_results.update(
                        {
                            "enhanced_vulnerabilities": [],
                            "enhanced_executive_summary": {},
                            "technical_summary": {
                                "total_vulnerabilities": 0,
                                "technical_details": "Enhanced reporting type error - using fallback",
                            },
                            "actionable_recommendations": [],
                            "enhanced_reporting_applied": False,
                        }
                    )
                    logger.warning(
                        f"Enhanced results has unexpected type {type(enhanced_results)}, using fallback values"
                    )

                # Fix severity counts in main results - with proper type checking
                if isinstance(enhanced_results, dict):
                    enhanced_summary = enhanced_results.get("executive_summary", {})
                    if isinstance(enhanced_summary, dict):
                        severity_breakdown = enhanced_summary.get("severity_breakdown", {})
                    else:
                        severity_breakdown = {}
                        logger.warning("Enhanced summary is not a dictionary, using empty severity breakdown")
                else:
                    enhanced_summary = {}
                    severity_breakdown = {}
                    logger.warning(
                        f"Enhanced results is not a dictionary (type: {type(enhanced_results)}), using empty summaries"
                    )
                classification_results["vulnerability_summary"] = {
                    "total_vulnerabilities": (
                        enhanced_summary.get("total_vulnerabilities", 0) if isinstance(enhanced_summary, dict) else 0
                    ),
                    "critical_count": severity_breakdown.get("CRITICAL", 0),
                    "high_count": severity_breakdown.get("HIGH", 0),
                    "medium_count": severity_breakdown.get("MEDIUM", 0),
                    "low_count": severity_breakdown.get("LOW", 0),
                }

                # ACCURACY FIX: Do NOT promote informational findings to vulnerabilities
                # Keep classification_results['vulnerabilities'] from the classifier (truth source)
                # Optionally, retain enhanced details separately for later enrichment
                if isinstance(enhanced_results, dict):
                    enhanced_only_vulns = enhanced_results.get("enhanced_vulnerabilities", [])
                    # Filter out items that clearly indicate PASS/secure just in case

                    def _looks_like_pass(item: dict) -> bool:
                        text = (
                            str(item.get("title", ""))
                            + " "
                            + str(item.get("description", ""))
                            + " "
                            + str(item.get("content", ""))
                        ).lower()
                        return (
                            ("status: pass" in text)
                            or ("(pass)" in text)
                            or ("no vulnerabilities" in text)
                            or ("secure" in text and "insecure" not in text)
                        )

                    enhanced_only_vulns = [v for v in enhanced_only_vulns if not _looks_like_pass(v)]
                    # Attach enhanced details for downstream consumers without overwriting classifier output
                    classification_results["enhanced_vulnerabilities"] = enhanced_only_vulns
                    logger.info("🎯 Retained classifier vulnerabilities; stored enhanced details separately")

                logger.info("🎯 Enhanced vulnerability reporting applied successfully")
            else:
                logger.info("No vulnerabilities found for enhancement")

        except Exception as e:
            import logging

            logger = logging.getLogger(__name__)
            logger.error(f"❌ Enhanced reporting failed: {e}")
            logger.info("Continuing with standard reporting...")
    else:
        import logging

        logger = logging.getLogger(__name__)
        logger.info("Standard reporting mode (enhanced engine not available)")

    # PERMANENT FIX: Full vulnerability validation and synchronization
    scanner._validate_and_sync_vulnerabilities(classification_results)

    vulnerabilities = classification_results["vulnerabilities"]
    vuln_summary = classification_results["vulnerability_summary"]

    # Track 81: Confidence scoring consolidated into serialize_final_report().
    # ConfidenceScorer runs as the final authority in final_report_serializer.py,
    # so any confidence values set here would be overwritten. Removed redundant
    # _set_severity_confidence() calls and scanner.confidence_scorer invocation.

    ml_status = "🤖 ML-Enhanced" if use_ml else "🌱 Organic-Only"
    output_mgr.status(
        f"{ml_status} Classification complete: {vuln_summary['total_vulnerabilities']} vulnerabilities identified "
        f"({vuln_summary['critical_count']} Critical, {vuln_summary['high_count']} High, "
        f"{vuln_summary['medium_count']} Medium, {vuln_summary['low_count']} Low)",
        "success",
    )

    # Update report generator with enhanced metadata AND vulnerability results
    # Handle both unified and legacy reporting systems for metadata
    if hasattr(scanner, "report_generator") and scanner.report_generator is not None:
        # Using legacy reporting system
        scanner.report_generator.add_metadata("vulnerabilities_found", vuln_summary["total_vulnerabilities"])
        scanner.report_generator.add_metadata("vulnerability_summary", vuln_summary)
        scanner.report_generator.add_metadata("enhanced_classification", True)
        scanner.report_generator.add_metadata("classifier_version", "2.0")

    # Add ML integration metadata
    # Handle both unified and legacy reporting systems for ML metadata
    if hasattr(scanner, "report_generator") and scanner.report_generator is not None:
        # Using legacy reporting system
        if use_ml and ml_manager is not None:
            try:
                ml_metrics = ml_manager.get_performance_metrics()
                scanner.report_generator.add_metadata("ml_enabled", True)

                # Handle both detailed and simplified metric responses
                if "status" in ml_metrics and ml_metrics["status"] == "No predictions made yet":
                    scanner.report_generator.add_metadata("ml_predictions_made", 0)
                    scanner.report_generator.add_metadata("ml_agreement_rate", 0.0)
                    scanner.report_generator.add_metadata("ml_status", ml_metrics["status"])
                else:
                    scanner.report_generator.add_metadata("ml_predictions_made", ml_metrics.get("total_predictions", 0))
                    scanner.report_generator.add_metadata(
                        "ml_agreement_rate", ml_metrics.get("hybrid_agreement_rate", 0.0)
                    )

                scanner.report_generator.add_metadata("ml_mode", "hybrid")
            except Exception as e:
                output_mgr.warning(f"Failed to get ML metadata: {e}")
                scanner.report_generator.add_metadata("ml_enabled", False)
                scanner.report_generator.add_metadata("ml_mode", "organic_only")
        else:
            scanner.report_generator.add_metadata("ml_enabled", False)
            scanner.report_generator.add_metadata("ml_mode", "organic_only")
    elif hasattr(scanner, "report_manager") and scanner.report_manager is not None:
        # Using unified reporting system - store ML metadata for later use
        if not hasattr(scanner, "_report_metadata"):
            scanner._report_metadata = {}

        if use_ml and ml_manager is not None:
            try:
                ml_metrics = ml_manager.get_performance_metrics()
                scanner._report_metadata["ml_enabled"] = True

                # Handle both detailed and simplified metric responses
                if "status" in ml_metrics and ml_metrics["status"] == "No predictions made yet":
                    scanner._report_metadata["ml_predictions_made"] = 0
                    scanner._report_metadata["ml_agreement_rate"] = 0.0
                    scanner._report_metadata["ml_status"] = ml_metrics["status"]
                else:
                    scanner._report_metadata["ml_predictions_made"] = ml_metrics.get("total_predictions", 0)
                    scanner._report_metadata["ml_agreement_rate"] = ml_metrics.get("hybrid_agreement_rate", 0.0)

                scanner._report_metadata["ml_mode"] = "hybrid"
            except Exception as e:
                output_mgr.warning(f"Failed to get ML metadata: {e}")
                scanner._report_metadata["ml_enabled"] = False
                scanner._report_metadata["ml_mode"] = "organic_only"
        else:
            scanner._report_metadata["ml_enabled"] = False
            scanner._report_metadata["ml_mode"] = "organic_only"

    if hasattr(scanner, "report_manager") and scanner.report_manager is not None:
        # Using unified reporting system - store metadata for later use
        if not hasattr(scanner, "_report_metadata"):
            scanner._report_metadata = {}
        scanner._report_metadata.update(
            {
                "vulnerabilities_found": vuln_summary["total_vulnerabilities"],
                "vulnerability_summary": vuln_summary,
                "enhanced_classification": True,
                "classifier_version": "2.0",
            }
        )

        # Add ML integration metadata
        if use_ml and ml_manager is not None:
            try:
                ml_metrics = ml_manager.get_performance_metrics()
                scanner._report_metadata["ml_enabled"] = True

                # Handle both detailed and simplified metric responses
                if "status" in ml_metrics and ml_metrics["status"] == "No predictions made yet":
                    scanner._report_metadata.update(
                        {"ml_predictions_made": 0, "ml_agreement_rate": 0.0, "ml_status": ml_metrics["status"]}
                    )
                else:
                    scanner._report_metadata.update(
                        {
                            "ml_predictions_made": ml_metrics.get("total_predictions", 0),
                            "ml_agreement_rate": ml_metrics.get("hybrid_agreement_rate", 0.0),
                        }
                    )

                scanner._report_metadata["ml_mode"] = "hybrid"
            except Exception as e:
                output_mgr.warning(f"Failed to get ML metadata: {e}")
                scanner._report_metadata.update({"ml_enabled": False, "ml_mode": "organic_only"})
        else:
            scanner._report_metadata.update({"ml_enabled": False, "ml_mode": "organic_only"})

    # CRITICAL FIX: Pass VulnerabilityClassifier results to ReportGenerator

    # THREAT INTELLIGENCE INTEGRATION: Enhance vulnerabilities with threat intelligence
    threat_enhanced_vulnerabilities = vulnerabilities.copy()
    threat_intelligence_summary = {}

    if THREAT_INTELLIGENCE_AVAILABLE and vulnerabilities:
        try:
            output_mgr.status("Correlating vulnerabilities with threat intelligence...", "info")
            threat_system = get_unified_threat_intelligence()

            # Correlate each vulnerability with threat intelligence
            enhanced_count = 0
            high_risk_correlations = 0

            for i, vulnerability in enumerate(threat_enhanced_vulnerabilities):
                try:
                    # Analyze vulnerability with threat intelligence
                    enhanced_vuln = threat_system.analyze_vulnerability_with_threat_intelligence(vulnerability)

                    # Update the vulnerability with threat intelligence data
                    threat_enhanced_vulnerabilities[i] = enhanced_vuln

                    # Track enhancement statistics
                    if "threat_intelligence" in enhanced_vuln:
                        enhanced_count += 1
                        threat_info = enhanced_vuln["threat_intelligence"]

                        if threat_info.get("risk_assessment") in ["CRITICAL", "HIGH"]:
                            high_risk_correlations += 1

                except Exception as e:
                    output_mgr.debug(f"Failed to enhance vulnerability {i} with threat intelligence: {e}")
                    continue

            # Get threat intelligence engine status (Track 60 Fix 13: wrap in try/except)
            try:
                ti_status = threat_system.get_threat_intelligence_status()
            except AttributeError:
                ti_status = {"engine_status": "unavailable"}

            threat_intelligence_summary = {
                "enabled": True,
                "vulnerabilities_analyzed": len(vulnerabilities),
                "enhanced_vulnerabilities": enhanced_count,
                "high_risk_correlations": high_risk_correlations,
                "threat_feeds_active": ti_status.get("threat_feeds", 0),
                "cached_threats": ti_status.get("cached_threats", 0),
                "engine_status": ti_status.get("engine_status", "unknown"),
            }

            output_mgr.status(
                f"Threat Intelligence: {enhanced_count}/{len(vulnerabilities)} vulnerabilities enhanced, "
                f"{high_risk_correlations} high-risk correlations found",
                "success",
            )

        except Exception as e:
            output_mgr.warning(f"Threat intelligence correlation failed: {e}")
            threat_intelligence_summary = {"enabled": False, "error": str(e), "fallback_mode": True}
    else:
        if not THREAT_INTELLIGENCE_AVAILABLE:
            output_mgr.info("Threat Intelligence Engine not available - continuing without threat correlation")
        else:
            output_mgr.info("No vulnerabilities found for threat intelligence correlation")

        threat_intelligence_summary = {
            "enabled": False,
            "reason": "not_available" if not THREAT_INTELLIGENCE_AVAILABLE else "no_vulnerabilities",
        }

    # Add threat intelligence metadata to report
    # Handle both unified and legacy reporting systems for threat intelligence metadata
    if hasattr(scanner, "report_generator") and scanner.report_generator is not None:
        # Using legacy reporting system
        scanner.report_generator.add_metadata("threat_intelligence", threat_intelligence_summary)
    elif hasattr(scanner, "report_manager") and scanner.report_manager is not None:
        # Using unified reporting system - store metadata for later use
        if not hasattr(scanner, "_report_metadata"):
            scanner._report_metadata = {}
        scanner._report_metadata["threat_intelligence"] = threat_intelligence_summary

    # Use threat-enhanced vulnerabilities for final report
    vulnerabilities = threat_enhanced_vulnerabilities

    # Handle both unified and legacy reporting systems for setting vulnerabilities
    if hasattr(scanner, "report_generator") and scanner.report_generator is not None:
        # Using legacy reporting system
        scanner.report_generator.set_external_vulnerabilities(vulnerabilities)
    elif hasattr(scanner, "report_manager") and scanner.report_manager is not None:
        # Using unified reporting system - store vulnerabilities for later use
        scanner._vulnerabilities = vulnerabilities

    # Cache classified vulnerability data for full technical reporting
    scanner.apk_ctx.set_cache(
        "classified_vulnerabilities",
        {
            "vulnerabilities": vulnerabilities,
            "vulnerability_summary": vuln_summary,
            "classification_metadata": classification_results.get("metadata", {}),
            "statistics": classification_results.get("statistics", {}),
        },
    )
    scanner.apk_ctx.set_cache("vulnerability_summary", vuln_summary)
    scanner.apk_ctx.set_cache("vulnerability_classification_results", classification_results)

    # Update consolidated_results with classification results for report generation
    scanner.consolidated_results.update(classification_results)

    # Track 81: Apply evidence normalization and recommendation improvement to findings
    # before report generation. This ensures BOTH parallel and standard execution paths
    # get intent severity downgrade, workspace path normalization, manifest file_path
    # defaults, confidence floor filtering, and actionable recommendations.
    try:
        for container_key in ("vulnerabilities", "enhanced_vulnerabilities", "vulnerability_findings"):
            container = scanner.consolidated_results.get(container_key)
            if isinstance(container, list) and container:
                _normalize_finding_evidence(container)
                _improve_recommendations(container)
        # Also normalize scanner.vulnerabilities if it exists separately
        if (hasattr(scanner, "vulnerabilities")
                and isinstance(scanner.vulnerabilities, list) and scanner.vulnerabilities):
            _normalize_finding_evidence(scanner.vulnerabilities)
            _improve_recommendations(scanner.vulnerabilities)
    except Exception as _norm_err:
        output_mgr.verbose(f"Pre-report normalization skipped: {_norm_err}")

    generated_files = {}

    # Generate text report (legacy compatibility)
    if "txt" in scanner.report_formats:
        output_mgr.verbose("Generating text report...")
        report_str = "OWASP MASVS Test Report\n"
        report_str += "=========================\n\n"
        for title, content in scanner.report_data:
            report_str += f"## {title}\n"
            if isinstance(content, dict):
                for key, value in content.items():
                    report_str += f"  {key}: {value}\n"
            else:
                report_str += f"  {content}\n"
            report_str += "\n"
        report_filename = f"{scanner.apk_ctx.package_name}_report.txt"
        with open(report_filename, "w") as f:
            f.write(report_str)
        generated_files["txt"] = report_filename
        output_mgr.verbose(f"Text report generated: {report_filename}")

    # CONSOLIDATION FIX: Generate enhanced reports using unified reporting framework
    try:
        if any(fmt in scanner.report_formats for fmt in ["json", "csv", "html", "all"]):
            if UNIFIED_REPORTING_AVAILABLE and scanner.report_manager:
                # Use unified reporting framework
                output_mgr.verbose("Using unified reporting framework...")

                if "all" in scanner.report_formats:
                    output_mgr.verbose("Generating all report formats...")
                    # Generate all formats using unified system
                    output_files = scanner.report_manager.generate_multi_format_report(
                        findings=scanner.consolidated_results.get("vulnerabilities", []),
                        base_output_path=f"{scanner.apk_ctx.package_name}_security_report",
                        formats=["json", "html", "csv"],
                    )
                    for format_name, file_path in output_files.items():
                        generated_files[format_name] = str(file_path)
                        output_mgr.verbose(f"Enhanced {format_name.upper()} report generated: {file_path}")
                else:
                    # Generate specific formats
                    for fmt in scanner.report_formats:
                        if fmt in ["json", "html", "csv"]:
                            output_mgr.verbose(f"Generating {fmt.upper()} report...")
                            output_path = f"{scanner.apk_ctx.package_name}_security_report.{fmt}"

                            # Convert format string to proper ReportFormat enum member
                            if fmt.lower() == "json":
                                report_format = ReportFormat.JSON
                            elif fmt.lower() == "html":
                                report_format = ReportFormat.HTML
                            elif fmt.lower() == "csv":
                                report_format = ReportFormat.CSV
                            elif fmt.lower() == "xml":
                                report_format = ReportFormat.XML
                            elif fmt.lower() == "markdown":
                                report_format = ReportFormat.MARKDOWN
                            elif fmt.lower() == "pdf":
                                report_format = ReportFormat.PDF
                            else:
                                report_format = ReportFormat.JSON  # Default fallback

                            # Use consolidated_results (post-dedup, FP-filtered) as primary source.
                            # This preserves the full quality pipeline (dedup + noise removal).
                            vulnerabilities_for_report = []

                            if scanner.consolidated_results and "vulnerabilities" in scanner.consolidated_results:
                                vulnerabilities_for_report = scanner.consolidated_results["vulnerabilities"]
                            elif classification_results and "vulnerabilities" in classification_results:
                                vulnerabilities_for_report = classification_results["vulnerabilities"]
                            elif hasattr(scanner, "vulnerabilities") and scanner.vulnerabilities:
                                vulnerabilities_for_report = scanner.vulnerabilities
                            elif classification_results and "enhanced_vulnerabilities" in classification_results:
                                vulnerabilities_for_report = classification_results["enhanced_vulnerabilities"]

                            output_mgr.info(
                                f"Report generation using {len(vulnerabilities_for_report)} vulnerabilities"
                            )

                            # NORMALIZATION: align top-level severity + confidence with classifier result and drop non-vulnerabilities  # noqa: E501
                            normalized_findings = []
                            for finding in vulnerabilities_for_report:
                                try:
                                    cls = finding.get("classification", {}) if isinstance(finding, dict) else {}
                                    is_vuln = bool(cls.get("is_vulnerability", True))
                                    if not is_vuln:
                                        continue
                                    sev = cls.get("severity")
                                    cls_conf = cls.get("confidence")
                                    if sev or cls_conf is not None:
                                        # Create a shallow copy to avoid mutating shared structures
                                        f_copy = dict(finding)
                                        if sev:
                                            f_copy["severity"] = str(sev).lower()
                                        if cls_conf is not None and isinstance(cls_conf, (int, float)):
                                            f_copy["confidence"] = float(cls_conf)
                                        normalized_findings.append(f_copy)
                                    else:
                                        normalized_findings.append(finding)
                                except Exception:
                                    normalized_findings.append(finding)

                            # Phase 9.6: Apply title validation to filter out plugin summaries
                            # First, extract nested findings from summaries before discarding them
                            pre_filter = len(normalized_findings)
                            _kept = []
                            for f in normalized_findings:
                                _title = f.get("title", f.get("name", "")) if isinstance(f, dict) else ""
                                if _is_valid_finding_title(_title):
                                    _kept.append(f)
                                elif isinstance(f, dict):
                                    # Extract nested findings from plugin summaries
                                    _nested = _extract_findings_from_content(f, _title)
                                    if _nested:
                                        _kept.extend(_nested)
                                    # No nested findings recovered - drop the summary
                            normalized_findings = _kept
                            post_filter = len(normalized_findings)
                            if pre_filter != post_filter:
                                output_mgr.info(
                                    f"🔧 Phase 9.6 filter: {pre_filter} → {post_filter} findings ({pre_filter - post_filter} summaries removed)"  # noqa: E501
                                )

                            # ENRICHMENT: taxonomy mapping, evidence, CWE/OWASP/MASVS
                            try:
                                from core.integrated_finding_normalizer import get_integrated_normalizer

                                _normalizer = get_integrated_normalizer(
                                    apk_context={
                                        "apk_path": getattr(scanner.apk_ctx, "apk_path_str", "")
                                        or str(getattr(scanner.apk_ctx, "apk_path", ""))
                                    }
                                )
                                _normalizer.enrich_classified_findings(normalized_findings)
                            except Exception as _enrich_err:
                                output_mgr.verbose(f"Finding enrichment skipped: {_enrich_err}")

                            # Evidence enrichment: add line numbers and code snippets
                            try:
                                from core.evidence_enrichment_pipeline import enrich_plugin_findings as _enrich_evidence

                                _enrich_evidence(normalized_findings, apk_context=scanner.apk_ctx)
                            except Exception as _ev_err:
                                output_mgr.verbose(f"Evidence enrichment skipped: {_ev_err}")

                            result = scanner.report_manager.generate_security_report(
                                findings=normalized_findings,
                                metadata={
                                    "target_apk_path": scanner.apk_ctx.apk_path_str,
                                    "package_name": scanner.package_name,
                                    "apk": scanner.apk_ctx.apk_path_str,
                                    **(getattr(scanner, "_report_metadata", {}) or {}),
                                },
                                formats=[report_format],
                                output_directory="reports",
                                base_filename=f"{scanner.apk_ctx.package_name}_security_report",
                            )

                            # CRITICAL FIX: Use new file_paths structure
                            if result and "file_paths" in result and result["file_paths"]:
                                # Extract the actual file path from file_paths
                                format_key = report_format.value.lower()
                                if format_key in result["file_paths"]:
                                    if isinstance(result["file_paths"][format_key], str):
                                        # Successfully saved file
                                        actual_output_path = result["file_paths"][format_key]
                                        generated_files[fmt] = actual_output_path
                                        output_mgr.verbose(f"{fmt.upper()} report saved: {actual_output_path}")
                                    else:
                                        # Error in file saving
                                        error_info = result["file_paths"][format_key]
                                        output_mgr.warning(f"Failed to save {fmt.upper()} report: {error_info}")
                                        generated_files[fmt] = output_path
                                else:
                                    generated_files[fmt] = output_path
                                    output_mgr.verbose(f"{fmt.upper()} report generated: {output_path}")
                            else:
                                output_mgr.warning(f"Failed to generate {fmt.upper()} report - no file paths in result")
            else:
                # Fallback to deprecated system
                output_mgr.warning("Using deprecated report generator (fallback)")
                if "all" in scanner.report_formats:
                    output_files = scanner.report_generator.generate_all_formats()
                    for format_name, file_path in output_files.items():
                        generated_files[format_name] = str(file_path)
                        output_mgr.verbose(f"Enhanced {format_name.upper()} report generated: {file_path}")
                else:
                    if "json" in scanner.report_formats:
                        json_filename = f"{scanner.apk_ctx.package_name}_security_report.json"

                        # PERMANENT FIX: Ensure report generator has vulnerabilities before generating
                        if (
                            not hasattr(scanner.report_generator, "vulnerabilities")
                            or not scanner.report_generator.vulnerabilities
                        ):
                            # Try to get vulnerabilities from multiple sources
                            if "vulnerabilities" in classification_results:
                                scanner.report_generator.vulnerabilities = classification_results["vulnerabilities"]
                            elif "enhanced_vulnerabilities" in classification_results:
                                scanner.report_generator.vulnerabilities = classification_results[
                                    "enhanced_vulnerabilities"
                                ]
                            elif hasattr(scanner, "vulnerabilities") and scanner.vulnerabilities:
                                scanner.report_generator.vulnerabilities = scanner.vulnerabilities

                            output_mgr.info(
                                f"🔧 Fallback report generator now has {len(scanner.report_generator.vulnerabilities or [])} vulnerabilities"  # noqa: E501
                            )

                        scanner.report_generator.generate_json(Path(json_filename))
                        generated_files["json"] = json_filename
                        output_mgr.verbose(f"JSON report generated: {json_filename}")

                    if "csv" in scanner.report_formats:
                        csv_filename = f"{scanner.apk_ctx.package_name}_security_report.csv"
                        scanner.report_generator.generate_csv(Path(csv_filename))
                        generated_files["csv"] = csv_filename
                        output_mgr.verbose(f"CSV report generated: {csv_filename}")
    except Exception as e:
        output_mgr.warning(f"Failed to generate enhanced reports: {e}")
        output_mgr.info("Continuing with available reports...")

    # Return generated files summary
    output_mgr.verbose(f"Report generation complete. Generated files: {generated_files}")
    return generated_files
