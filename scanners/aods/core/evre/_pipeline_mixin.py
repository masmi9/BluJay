"""Main entry point: enhance_vulnerability_report, parallel/sequential processing."""

from typing import Dict, List


class PipelineMixin:
    """Main pipeline: enhance_vulnerability_report entry point + parallel/sequential helpers."""

    def enhance_vulnerability_report(self, findings: List[Dict], app_context: Dict) -> Dict:
        """Enhanced vulnerability reporting with context-aware analysis"""

        # Filter valid vulnerability findings (skip strings and non-dict items)
        valid_findings = []
        for finding in findings:
            if isinstance(finding, dict) and any(
                key in finding for key in ["title", "description", "vulnerability_type", "severity"]
            ):
                valid_findings.append(finding)
            elif isinstance(finding, str):
                # Skip string entries like "dynamic_scan_completed", "static_analysis_finished", etc.
                self.logger.debug("Skipping string finding", finding=finding)
                continue
            else:
                self.logger.debug("Skipping invalid finding type", finding_type=str(type(finding)))
                continue

        self.logger.info("Enhancing vulnerability findings", count=len(valid_findings))
        self.logger.info("ML Enhancement Stage 1: Initializing ML-enhanced vulnerability processing")

        # CRITICAL DEBUG: Check if we have any findings to process
        if not valid_findings:
            self.logger.warning("No valid findings after filtering, returning empty report")
            return {
                "executive_summary": {"total_vulnerabilities": 0, "severity_breakdown": {}},
                "enhanced_vulnerabilities": [],
                "vulnerabilities": [],
                "metadata": {},
                "coordination_metrics": {},
            }

        # INTEGRATION FIX: Apply intelligent global exclusions using existing coordination systems
        if hasattr(self, "global_exclusions") and self.global_exclusions:
            original_count = len(valid_findings)
            filtered_findings, stats = self._apply_global_exclusions(valid_findings)

            filtered_count = len(filtered_findings)
            excluded_count = original_count - filtered_count

            self.logger.info(
                "Intelligent filtering applied",
                original=original_count,
                filtered=filtered_count,
                excluded=excluded_count,
                preserved_vulnerabilities=stats["preserved_vulnerabilities"],
                library_vulns=stats["library_vulns"],
                test_vulns=stats["test_vulns"],
            )
            self.logger.info("ML Enhancement Stage 2: ML-enhanced filtering algorithms applied")

            valid_findings = filtered_findings

        # SPEED OPTIMIZATION: Use parallel processing for large finding sets
        self.logger.info("ML Enhancement Stage 3: Applying ML-enhanced vulnerability classification")
        if len(valid_findings) > 500:
            enhanced_vulnerabilities = self._parallel_enhance_findings(valid_findings)
        else:
            enhanced_vulnerabilities = self._sequential_enhance_findings(valid_findings)
        self.logger.info("ML Enhancement Stage 4: ML-enhanced confidence scoring completed")

        self.logger.debug("After enhancement", count=len(enhanced_vulnerabilities))

        # INTEGRATION FIX: Apply unified deduplication using existing framework
        self.logger.info("ML Enhancement Stage 5: Applying ML-guided deduplication strategies")
        enhanced_vulnerabilities = self._apply_unified_deduplication(enhanced_vulnerabilities)
        # Reporter-level consolidation: collapse overlapping WebView JS-bridge findings
        try:
            enhanced_vulnerabilities = self._dedupe_webview_js_bridge(enhanced_vulnerabilities)
        except Exception:
            pass
        self.logger.debug("After unified deduplication", count=len(enhanced_vulnerabilities))

        # FP reduction handled in execution_parallel.py (Track 112 canonical reducer)
        self.logger.debug("Skipping EVRE-level FP filtering (handled upstream)", count=len(enhanced_vulnerabilities))

        enhanced_vulnerabilities = self._apply_conservative_qa(enhanced_vulnerabilities)  # Use conservative QA
        self.logger.debug("After conservative QA", count=len(enhanced_vulnerabilities))

        enhanced_vulnerabilities = self._apply_result_validation(enhanced_vulnerabilities)
        self.logger.debug("After result validation", count=len(enhanced_vulnerabilities))

        # FINAL VALIDATION: Ensure all coordination fixes have persisted
        coordination_validation = self._validate_coordination_effectiveness(enhanced_vulnerabilities)

        # Generate final report with proper app context
        app_context = getattr(self, "app_context", {})
        final_report = self._finalize_enhanced_report(enhanced_vulnerabilities, app_context)

        # Ensure final_report is a dictionary
        if not isinstance(final_report, dict):
            self.logger.warning(
                "_finalize_enhanced_report returned unexpected type, creating fallback dict",
                return_type=str(type(final_report)),
            )
            final_report = {
                "enhanced_vulnerabilities": enhanced_vulnerabilities,
                "vulnerabilities": enhanced_vulnerabilities,
                "executive_summary": {
                    "total_vulnerabilities": len(enhanced_vulnerabilities),
                    "severity_breakdown": self._get_severity_breakdown(enhanced_vulnerabilities),
                },
                "metadata": app_context,
                "coordination_metrics": {},
            }

        # Add coordination metrics to final report
        final_report["coordination_metrics"] = coordination_validation

        # SCAN STATISTICS INTEGRATION: Add full scan statistics
        self.logger.info("Scan Statistics Stage: Collecting scan statistics")
        try:
            from ..reporting.scan_statistics_collector import ScanStatisticsCollector

            # Create or get existing statistics collector
            if not hasattr(self, "statistics_collector"):
                self.statistics_collector = ScanStatisticsCollector()
                # Record basic scan info if not already started
                package_name = app_context.get("package_name", "Unknown")
                self.statistics_collector.start_scan(package_name, "deep", 0.0)

            # Record vulnerabilities for statistics
            vulnerabilities = final_report.get("vulnerabilities", [])
            self.statistics_collector.record_vulnerabilities(vulnerabilities)

            # End scan and get statistics
            self.statistics_collector.end_scan()
            scan_statistics = self.statistics_collector.get_statistics_summary()

            # Add scan statistics to final report
            final_report["scan_statistics"] = scan_statistics
            self.logger.info("Scan statistics added", total_duration=scan_statistics["scan_overview"]["total_duration"])

        except Exception as e:
            self.logger.warning("Scan statistics collection failed", error=str(e))

        # CODE SNIPPET EXTRACTION: Add vulnerable code snippets to vulnerabilities
        self.logger.info("Code Snippet Extraction Stage: Extracting vulnerable code snippets")
        try:
            from ..vulnerability_code_extractor import VulnerabilityCodeExtractor

            # Create code extractor
            code_extractor = VulnerabilityCodeExtractor(context_lines=7)

            # Extract code snippets for vulnerabilities
            vulnerabilities = final_report.get("vulnerabilities", [])
            code_extraction_stats = {"extracted": 0, "failed": 0, "total_time_ms": 0.0}

            for vulnerability in vulnerabilities:
                extraction_result = code_extractor.extract_code_snippet(vulnerability, app_context.get("apk_context"))

                if extraction_result.success and extraction_result.code_snippet:
                    # Add code snippet to vulnerability
                    vulnerability["code_snippet"] = {
                        "file_path": extraction_result.code_snippet.file_path,
                        "line_number": extraction_result.code_snippet.line_number,
                        "vulnerable_line": extraction_result.code_snippet.vulnerable_line,
                        "context_lines": extraction_result.code_snippet.context_lines,
                        "start_line": extraction_result.code_snippet.start_line,
                        "end_line": extraction_result.code_snippet.end_line,
                        "language": extraction_result.code_snippet.language,
                        "syntax_highlighted": extraction_result.code_snippet.syntax_highlighted,
                        "extraction_method": extraction_result.code_snippet.extraction_method,
                    }
                    code_extraction_stats["extracted"] += 1
                else:
                    vulnerability["code_snippet"] = None
                    code_extraction_stats["failed"] += 1

                code_extraction_stats["total_time_ms"] += extraction_result.extraction_time_ms

            # Clear cache to free memory
            code_extractor.clear_cache()

            extraction_rate = (
                (code_extraction_stats["extracted"] / len(vulnerabilities) * 100) if vulnerabilities else 0
            )
            self.logger.info(
                "Code snippet extraction completed",
                extracted=code_extraction_stats["extracted"],
                total=len(vulnerabilities),
                rate_pct=round(extraction_rate, 1),
            )

        except Exception as e:
            self.logger.warning("Code snippet extraction failed", error=str(e))

        # EVIDENCE COLLECTION: Collect full evidence for vulnerabilities
        self.logger.info("Evidence Collection Stage: Collecting full evidence")
        try:
            from ..evidence_collection_framework import EvidenceCollectionFramework

            # Create evidence collection framework
            evidence_framework = EvidenceCollectionFramework()

            # Collect evidence for all vulnerabilities
            vulnerabilities = final_report.get("vulnerabilities", [])
            evidence_stats = {"collected": 0, "total_evidence_items": 0, "total_size_bytes": 0}

            for vulnerability in vulnerabilities:
                evidence_collection = evidence_framework.collect_evidence_for_vulnerability(
                    vulnerability, app_context.get("apk_context")
                )

                if evidence_collection.evidence_items:
                    # Add evidence collection to vulnerability
                    vulnerability["evidence_collection"] = {
                        "collection_id": evidence_collection.vulnerability_id,
                        "evidence_summary": evidence_collection.evidence_summary,
                        "total_evidence_items": len(evidence_collection.evidence_items),
                        "total_size_bytes": evidence_collection.total_size_bytes,
                        "collection_timestamp": evidence_collection.collection_timestamp,
                        "evidence_items": [
                            {
                                "evidence_id": item.evidence_id,
                                "evidence_type": item.evidence_type.value,
                                "title": item.title,
                                "description": item.description,
                                "data": item.data,
                                "file_path": item.file_path,
                                "timestamp": item.timestamp,
                                "size_bytes": item.size_bytes,
                                "checksum": item.checksum,
                                "metadata": item.metadata,
                            }
                            for item in evidence_collection.evidence_items
                        ],
                    }
                    evidence_stats["collected"] += 1
                    evidence_stats["total_evidence_items"] += len(evidence_collection.evidence_items)
                    evidence_stats["total_size_bytes"] += evidence_collection.total_size_bytes
                else:
                    vulnerability["evidence_collection"] = None

            # Add evidence collection statistics to report
            final_report["evidence_statistics"] = {
                **evidence_framework.get_collection_statistics(),
                "vulnerabilities_with_evidence": evidence_stats["collected"],
                "total_vulnerabilities": len(vulnerabilities),
                "evidence_collection_rate": (
                    (evidence_stats["collected"] / len(vulnerabilities) * 100) if vulnerabilities else 0
                ),
            }

            collection_rate = (evidence_stats["collected"] / len(vulnerabilities) * 100) if vulnerabilities else 0
            self.logger.info(
                "Evidence collection completed",
                collected=evidence_stats["collected"],
                total=len(vulnerabilities),
                rate_pct=round(collection_rate, 1),
                total_evidence_items=evidence_stats["total_evidence_items"],
                total_size_bytes=evidence_stats["total_size_bytes"],
            )

        except Exception as e:
            self.logger.warning("Evidence collection failed", error=str(e))

        # PROOF-OF-CONCEPT GENERATION: Generate safe PoCs for exploitable vulnerabilities
        self.logger.info("Proof-of-Concept Generation Stage: Creating safe educational demonstrations")
        try:
            from ..proof_of_concept_generator import ProofOfConceptGenerator

            # Create PoC generator
            poc_generator = ProofOfConceptGenerator()

            # Generate PoCs for applicable vulnerabilities
            vulnerabilities = final_report.get("vulnerabilities", [])
            poc_stats = {"generated": 0, "applicable": 0, "safety_validated": 0}

            for vulnerability in vulnerabilities:
                # Check if PoC is applicable
                if poc_generator._is_poc_applicable(vulnerability):
                    poc_stats["applicable"] += 1

                    # Generate safe PoC
                    poc = poc_generator.generate_poc_for_vulnerability(vulnerability)

                    if poc:
                        # Add PoC to vulnerability
                        vulnerability["proof_of_concept"] = {
                            "poc_id": poc.poc_id,
                            "poc_type": poc.poc_type.value,
                            "risk_level": poc.risk_level.value,
                            "title": poc.title,
                            "description": poc.description,
                            "impact_assessment": poc.impact_assessment,
                            "business_risk": poc.business_risk,
                            "steps": [
                                {
                                    "step_number": step.step_number,
                                    "title": step.title,
                                    "description": step.description,
                                    "command": step.command,
                                    "expected_result": step.expected_result,
                                    "safety_notes": step.safety_notes,
                                    "is_safe": step.is_safe,
                                }
                                for step in poc.steps
                            ],
                            "mitigation_verification": poc.mitigation_verification,
                            "safety_validation": poc.safety_validation,
                            "timestamp": poc.timestamp,
                            "metadata": poc.metadata,
                        }
                        poc_stats["generated"] += 1

                        # Verify safety validation passed
                        if all(poc.safety_validation.values()):
                            poc_stats["safety_validated"] += 1
                    else:
                        vulnerability["proof_of_concept"] = None
                else:
                    vulnerability["proof_of_concept"] = None

            # Add PoC generation statistics to report
            final_report["poc_statistics"] = {
                **poc_generator.get_generation_statistics(),
                "applicable_vulnerabilities": poc_stats["applicable"],
                "pocs_generated": poc_stats["generated"],
                "safety_validated_pocs": poc_stats["safety_validated"],
                "total_vulnerabilities": len(vulnerabilities),
                "poc_generation_rate": (
                    (poc_stats["generated"] / poc_stats["applicable"] * 100) if poc_stats["applicable"] > 0 else 0
                ),
                "safety_compliance_rate": (
                    (poc_stats["safety_validated"] / poc_stats["generated"] * 100)
                    if poc_stats["generated"] > 0
                    else 100
                ),
            }

            generation_rate = (
                (poc_stats["generated"] / poc_stats["applicable"] * 100) if poc_stats["applicable"] > 0 else 0
            )
            safety_rate = (
                (poc_stats["safety_validated"] / poc_stats["generated"] * 100) if poc_stats["generated"] > 0 else 100
            )
            self.logger.info(
                "PoC generation completed",
                generated=poc_stats["generated"],
                applicable=poc_stats["applicable"],
                generation_rate_pct=round(generation_rate, 1),
                safety_validated=poc_stats["safety_validated"],
                safety_rate_pct=round(safety_rate, 1),
            )

        except Exception as e:
            self.logger.warning("PoC generation failed", error=str(e))

        # REMEDIATION GUIDANCE GENERATION: Generate actionable remediation guidance
        self.logger.info("Remediation Guidance Stage: Generating actionable remediation guidance")
        try:
            from ..remediation_guidance_engine import RemediationGuidanceEngine

            # Create remediation guidance engine
            remediation_engine = RemediationGuidanceEngine()

            # Generate remediation guidance for all vulnerabilities
            vulnerabilities = final_report.get("vulnerabilities", [])
            remediation_stats = {"generated": 0, "total_hours": 0.0, "priority_breakdown": {}}

            for vulnerability in vulnerabilities:
                # Generate remediation guidance
                guidance = remediation_engine.generate_remediation_guidance(vulnerability)

                if guidance:
                    # Add remediation guidance to vulnerability
                    vulnerability["remediation_guidance"] = {
                        "guidance_id": guidance.guidance_id,
                        "priority": guidance.priority.value,
                        "complexity": guidance.overall_complexity.value,
                        "estimated_hours": guidance.estimated_total_hours,
                        "fix_summary": guidance.fix_summary,
                        "detailed_description": guidance.detailed_description,
                        "root_cause_analysis": guidance.root_cause_analysis,
                        "remediation_steps": [
                            {
                                "step_number": step.step_number,
                                "title": step.title,
                                "description": step.description,
                                "code_example": step.code_example,
                                "verification_method": step.verification_method,
                                "estimated_hours": step.estimated_hours,
                                "complexity": step.complexity.value,
                            }
                            for step in guidance.remediation_steps
                        ],
                        "code_examples": guidance.code_examples,
                        "verification_checklist": guidance.verification_checklist,
                        "best_practices": guidance.best_practices,
                        "prevention_measures": guidance.prevention_measures,
                        "references": guidance.references,
                        "timestamp": guidance.timestamp,
                        "metadata": guidance.metadata,
                    }
                    remediation_stats["generated"] += 1
                    remediation_stats["total_hours"] += guidance.estimated_total_hours

                    # Track priority breakdown
                    priority = guidance.priority.value
                    remediation_stats["priority_breakdown"][priority] = (
                        remediation_stats["priority_breakdown"].get(priority, 0) + 1
                    )
                else:
                    vulnerability["remediation_guidance"] = None

            # Generate remediation roadmap for all vulnerabilities
            remediation_roadmap = remediation_engine.generate_remediation_roadmap(vulnerabilities)

            # Add remediation statistics and roadmap to report
            final_report["remediation_statistics"] = {
                **remediation_engine.get_generation_statistics(),
                "vulnerabilities_with_guidance": remediation_stats["generated"],
                "total_vulnerabilities": len(vulnerabilities),
                "guidance_generation_rate": (
                    (remediation_stats["generated"] / len(vulnerabilities) * 100) if vulnerabilities else 0
                ),
                "total_estimated_hours": remediation_stats["total_hours"],
                "priority_breakdown": remediation_stats["priority_breakdown"],
            }

            final_report["remediation_roadmap"] = remediation_roadmap

            generation_rate = (remediation_stats["generated"] / len(vulnerabilities) * 100) if vulnerabilities else 0
            estimated_weeks = remediation_roadmap.get("roadmap_summary", {}).get("estimated_weeks", 0)
            self.logger.info(
                "Remediation guidance completed",
                generated=remediation_stats["generated"],
                total=len(vulnerabilities),
                rate_pct=round(generation_rate, 1),
                total_estimated_hours=round(remediation_stats["total_hours"], 1),
                estimated_weeks=estimated_weeks,
                priority_breakdown=remediation_stats["priority_breakdown"],
            )

        except Exception as e:
            self.logger.warning("Remediation guidance generation failed", error=str(e))

        # BEST PRACTICES INTEGRATION: Generate security best practices
        self.logger.info("Best Practices Integration Stage: Generating security best practices")
        try:
            from ..best_practices_engine import BestPracticesEngine

            # Create best practices engine
            best_practices_engine = BestPracticesEngine()

            # Generate best practices report for the application
            vulnerabilities = final_report.get("vulnerabilities", [])
            best_practices_report = best_practices_engine.generate_best_practices_report(vulnerabilities, app_context)

            # Add best practices to final report
            final_report["best_practices"] = {
                "report_id": best_practices_report.report_id,
                "total_recommendations": best_practices_report.total_recommendations,
                "category_breakdown": best_practices_report.category_breakdown,
                "priority_breakdown": best_practices_report.priority_breakdown,
                "recommendations": [
                    {
                        "recommendation_id": rec.recommendation_id,
                        "title": rec.title,
                        "description": rec.description,
                        "category": rec.category.value,
                        "practice_type": rec.practice_type.value,
                        "priority": rec.priority.value,
                        "implementation_steps": rec.implementation_steps,
                        "code_examples": rec.code_examples,
                        "tools_and_resources": rec.tools_and_resources,
                        "compliance_frameworks": rec.compliance_frameworks,
                        "related_vulnerabilities": rec.related_vulnerabilities,
                        "implementation_effort": rec.implementation_effort,
                        "business_impact": rec.business_impact,
                        "references": rec.references,
                        "timestamp": rec.timestamp,
                    }
                    for rec in best_practices_report.recommendations
                ],
                "implementation_roadmap": best_practices_report.implementation_roadmap,
                "compliance_summary": best_practices_report.compliance_summary,
                "timestamp": best_practices_report.timestamp,
                "metadata": best_practices_report.metadata,
            }

            # Add best practices statistics
            final_report["best_practices_statistics"] = {
                **best_practices_engine.get_generation_statistics(),
                "report_generation_success": True,
                "recommendations_per_vulnerability": (
                    best_practices_report.total_recommendations / len(vulnerabilities) if vulnerabilities else 0
                ),
                "compliance_score": best_practices_report.compliance_summary.get("compliance_score", 0),
            }

            self.logger.info(
                "Best practices integration completed",
                total_recommendations=best_practices_report.total_recommendations,
                category_breakdown=best_practices_report.category_breakdown,
                priority_breakdown=best_practices_report.priority_breakdown,
                implementation_phases=len(best_practices_report.implementation_roadmap),
                compliance_score=round(best_practices_report.compliance_summary.get("compliance_score", 0), 1),
            )

        except Exception as e:
            self.logger.warning("Best practices integration failed", error=str(e))

        # RISK INTELLIGENCE ANALYSIS: Generate advanced risk analytics and intelligence
        self.logger.info("Risk Intelligence Analysis Stage: Analyzing trends and predictive risk")
        try:
            from ..risk_intelligence_engine import RiskIntelligenceEngine

            # Create risk intelligence engine
            risk_intel_engine = RiskIntelligenceEngine()

            # Generate risk intelligence analysis
            risk_intelligence_report = risk_intel_engine.analyze_risk_intelligence(final_report, app_context)

            # Add risk intelligence to final report
            final_report["risk_intelligence"] = {
                "report_id": risk_intelligence_report.report_id,
                "analysis_period": risk_intelligence_report.analysis_period,
                "overall_risk_level": risk_intelligence_report.overall_risk_level.value,
                "risk_score": risk_intelligence_report.risk_score,
                "trend_analysis": [
                    {
                        "category": trend.category,
                        "severity": trend.severity,
                        "count_history": trend.count_history,
                        "timestamps": trend.timestamps,
                        "trend_direction": trend.trend_direction.value,
                        "trend_confidence": trend.trend_confidence,
                        "prediction_next_period": trend.prediction_next_period,
                        "risk_score": trend.risk_score,
                    }
                    for trend in risk_intelligence_report.trend_analysis
                ],
                "risk_patterns": [
                    {
                        "pattern_id": pattern.pattern_id,
                        "pattern_name": pattern.pattern_name,
                        "description": pattern.description,
                        "affected_categories": pattern.affected_categories,
                        "frequency": pattern.frequency,
                        "risk_impact": pattern.risk_impact,
                        "first_observed": pattern.first_observed,
                        "last_observed": pattern.last_observed,
                        "confidence_score": pattern.confidence_score,
                    }
                    for pattern in risk_intelligence_report.risk_patterns
                ],
                "industry_benchmarks": [
                    {
                        "industry_sector": benchmark.industry_sector,
                        "app_category": benchmark.app_category,
                        "benchmark_metrics": benchmark.benchmark_metrics,
                        "percentile_ranking": benchmark.percentile_ranking,
                        "comparison_summary": benchmark.comparison_summary,
                        "improvement_areas": benchmark.improvement_areas,
                    }
                    for benchmark in risk_intelligence_report.industry_benchmarks
                ],
                "threat_intelligence": [
                    {
                        "threat_id": threat.threat_id,
                        "threat_category": threat.threat_category.value,
                        "threat_name": threat.threat_name,
                        "description": threat.description,
                        "severity": threat.severity,
                        "affected_platforms": threat.affected_platforms,
                        "indicators": threat.indicators,
                        "mitigation_strategies": threat.mitigation_strategies,
                        "source": threat.source,
                        "timestamp": threat.timestamp,
                    }
                    for threat in risk_intelligence_report.threat_intelligence
                ],
                "predictive_assessment": risk_intelligence_report.predictive_assessment,
                "recommendations": risk_intelligence_report.recommendations,
                "timestamp": risk_intelligence_report.timestamp,
                "metadata": risk_intelligence_report.metadata,
            }

            # Add risk intelligence statistics
            final_report["risk_intelligence_statistics"] = {
                **risk_intel_engine.get_analysis_statistics(),
                "analysis_success": True,
                "trends_confidence": (
                    sum(trend.trend_confidence for trend in risk_intelligence_report.trend_analysis)
                    / len(risk_intelligence_report.trend_analysis)
                    if risk_intelligence_report.trend_analysis
                    else 0
                ),
                "patterns_risk_score": (
                    sum(pattern.risk_impact for pattern in risk_intelligence_report.risk_patterns)
                    / len(risk_intelligence_report.risk_patterns)
                    if risk_intelligence_report.risk_patterns
                    else 0
                ),
            }

            self.logger.info(
                "Risk intelligence analysis completed",
                risk_level=risk_intelligence_report.overall_risk_level.value,
                risk_score=round(risk_intelligence_report.risk_score, 1),
                trends_analyzed=len(risk_intelligence_report.trend_analysis),
                patterns_detected=len(risk_intelligence_report.risk_patterns),
                industry_benchmarks=len(risk_intelligence_report.industry_benchmarks),
                threat_intelligence=len(risk_intelligence_report.threat_intelligence),
                recommendations=len(risk_intelligence_report.recommendations),
            )

        except Exception as e:
            self.logger.warning("Risk intelligence analysis failed", error=str(e))

        # ML-ENHANCED CONFIDENCE SCORING: Apply advanced ML-based confidence scoring
        self.logger.info("ML Confidence Scoring Stage: Enhancing vulnerability confidence with ML")
        try:
            from ..ml_confidence_scoring_engine import MLConfidenceScoringEngine

            # Create ML confidence scoring engine
            ml_confidence_engine = MLConfidenceScoringEngine()

            # Apply ML confidence scoring to all vulnerabilities
            vulnerabilities = final_report.get("vulnerabilities", [])
            ml_confidence_results = []
            confidence_improvements = 0
            fp_reductions = 0

            for vulnerability in vulnerabilities:
                # Calculate ML-enhanced confidence
                ml_result = ml_confidence_engine.calculate_ml_confidence(vulnerability, app_context)

                # Update vulnerability with ML confidence data
                vulnerability["ml_confidence"] = {
                    "original_confidence": ml_result.original_confidence,
                    "ml_confidence": ml_result.ml_confidence,
                    "adjusted_confidence": ml_result.adjusted_confidence,
                    "confidence_level": ml_result.confidence_level.value,
                    "false_positive_probability": ml_result.false_positive_probability,
                    "explanation": {
                        "confidence_score": ml_result.explanation.confidence_score,
                        "confidence_level": ml_result.explanation.confidence_level.value,
                        "primary_factors": ml_result.explanation.primary_factors,
                        "supporting_evidence": ml_result.explanation.supporting_evidence,
                        "risk_factors": ml_result.explanation.risk_factors,
                        "model_reasoning": ml_result.explanation.model_reasoning,
                        "feature_importance": ml_result.explanation.feature_importance,
                        "calibration_notes": ml_result.explanation.calibration_notes,
                    },
                    "processing_time_ms": ml_result.processing_time_ms,
                    "model_version": ml_result.model_version,
                    "timestamp": ml_result.timestamp,
                }

                # Update the main confidence field with ML-enhanced value
                vulnerability["confidence"] = ml_result.adjusted_confidence

                # Track improvements
                if ml_result.adjusted_confidence > ml_result.original_confidence + 0.05:
                    confidence_improvements += 1

                if ml_result.false_positive_probability < 0.2:
                    fp_reductions += 1

                ml_confidence_results.append(ml_result)

            # Add ML confidence statistics to report
            final_report["ml_confidence_statistics"] = {
                **ml_confidence_engine.get_scoring_statistics(),
                "vulnerabilities_processed": len(vulnerabilities),
                "confidence_improvements": confidence_improvements,
                "fp_reductions": fp_reductions,
                "improvement_rate": (confidence_improvements / len(vulnerabilities) * 100) if vulnerabilities else 0,
                "fp_reduction_rate": (fp_reductions / len(vulnerabilities) * 100) if vulnerabilities else 0,
                "average_confidence_boost": (
                    sum(r.adjusted_confidence - r.original_confidence for r in ml_confidence_results)
                    / len(ml_confidence_results)
                    if ml_confidence_results
                    else 0
                ),
                "average_fp_probability": (
                    sum(r.false_positive_probability for r in ml_confidence_results) / len(ml_confidence_results)
                    if ml_confidence_results
                    else 0
                ),
            }

            improvement_rate = (confidence_improvements / len(vulnerabilities) * 100) if vulnerabilities else 0
            fp_reduction_rate = (fp_reductions / len(vulnerabilities) * 100) if vulnerabilities else 0
            avg_boost = (
                sum(r.adjusted_confidence - r.original_confidence for r in ml_confidence_results)
                / len(ml_confidence_results)
                if ml_confidence_results
                else 0
            )
            avg_fp_prob = (
                sum(r.false_positive_probability for r in ml_confidence_results) / len(ml_confidence_results)
                if ml_confidence_results
                else 0
            )

            self.logger.info(
                "ML confidence scoring completed",
                vulnerabilities_enhanced=len(vulnerabilities),
                confidence_improvements=confidence_improvements,
                improvement_rate_pct=round(improvement_rate, 1),
                fp_reductions=fp_reductions,
                fp_reduction_rate_pct=round(fp_reduction_rate, 1),
                avg_confidence_boost=round(avg_boost, 3),
                avg_fp_probability=round(avg_fp_prob, 3),
            )

        except Exception as e:
            self.logger.warning("ML confidence scoring failed", error=str(e))

        # SECURITY FRAMEWORK COMPLIANCE MAPPING: Add framework mapping
        self.logger.info("Security Framework Mapping Stage: Mapping to compliance frameworks")
        try:
            from ..reporting.security_framework_mapper import SecurityFrameworkMapper

            # Create security framework mapper
            framework_mapper = SecurityFrameworkMapper()

            # Generate compliance report
            vulnerabilities = final_report.get("vulnerabilities", [])
            compliance_report = framework_mapper.generate_compliance_report(vulnerabilities)

            # Add compliance report to final report
            final_report["security_compliance"] = compliance_report

            overall_score = compliance_report.get("compliance_summary", {}).get("overall_score", 0)
            self.logger.info("Security framework mapping added", overall_compliance_pct=overall_score)

        except Exception as e:
            self.logger.warning("Security framework mapping failed", error=str(e))

        # EXECUTIVE SUMMARY INTEGRATION: Add executive summary to report
        self.logger.info("Executive Summary Stage: Generating executive summary")
        try:
            from ..reporting.executive_summary_generator import ExecutiveSummaryGenerator

            # Create executive summary with enhanced scan statistics and compliance data
            exec_generator = ExecutiveSummaryGenerator()
            scan_results = {
                "vulnerabilities": final_report.get("vulnerabilities", []),
                "scan_statistics": final_report.get("scan_statistics", {}),
                "security_compliance": final_report.get("security_compliance", {}),
                "app_package": app_context.get("package_name", "Unknown"),
                "aods_version": "2.1.0",
            }

            executive_summary = exec_generator.generate_summary(scan_results)
            formatted_summary = exec_generator.format_summary_for_report(executive_summary)

            # Add executive summary to final report
            final_report.update(formatted_summary)
            self.logger.info("Executive summary added", risk_level=executive_summary.overall_risk_level)

        except Exception as e:
            self.logger.warning("Executive summary generation failed", error=str(e))

        # PARALLEL SCAN MANAGER INTEGRATION: Add executive summary format expected by ParallelScanManager
        self.logger.info("ML Enhancement Stage 6: Finalizing ML-enhanced vulnerability report")
        vulnerabilities = final_report.get("vulnerabilities", [])
        severity_breakdown = final_report.get("metadata", {}).get("severity_breakdown", {})

        enhanced_report_format = {
            "executive_summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "severity_breakdown": severity_breakdown,
            },
            "enhanced_vulnerabilities": vulnerabilities,
            "vulnerabilities": vulnerabilities,  # For compatibility
            "metadata": final_report.get("metadata", {}),
            "coordination_metrics": coordination_validation,
        }

        self.logger.info("ML Enhancement Complete", vulnerabilities_processed=len(vulnerabilities))
        return enhanced_report_format

    def _parallel_enhance_findings(self, valid_findings):
        """SPEED: Parallel processing for large finding sets (500+)"""
        import multiprocessing as mp
        from concurrent.futures import ProcessPoolExecutor, as_completed
        import time

        self.logger.info("PARALLEL MODE: Processing findings", count=len(valid_findings), cores=mp.cpu_count())
        start_time = time.time()

        # Split findings into batches for parallel processing
        batch_size = max(50, len(valid_findings) // mp.cpu_count())
        batches = [valid_findings[i : i + batch_size] for i in range(0, len(valid_findings), batch_size)]

        enhanced_vulnerabilities = []
        completed_count = 0

        with ProcessPoolExecutor(max_workers=mp.cpu_count()) as executor:
            # Submit all batches
            future_to_batch = {
                executor.submit(self._process_finding_batch, batch, batch_idx): batch_idx
                for batch_idx, batch in enumerate(batches)
            }

            # Process completed batches
            for future in as_completed(future_to_batch):
                batch_idx = future_to_batch[future]
                try:
                    batch_results = future.result()
                    enhanced_vulnerabilities.extend(batch_results)
                    completed_count += len(batch_results)

                    progress_pct = (completed_count / len(valid_findings)) * 100
                    elapsed = time.time() - start_time
                    rate = completed_count / elapsed if elapsed > 0 else 0
                    eta = (len(valid_findings) - completed_count) / rate if rate > 0 else 0

                    self.logger.info(
                        "Parallel enhancement progress",
                        completed=completed_count,
                        total=len(valid_findings),
                        progress_pct=round(progress_pct, 1),
                        rate_per_sec=round(rate, 1),
                        eta_sec=round(eta, 1),
                    )

                except Exception as e:
                    self.logger.error("Batch processing failed", batch_idx=batch_idx, error=str(e))

        elapsed = time.time() - start_time
        self.logger.info(
            "Parallel enhancement completed",
            findings=len(enhanced_vulnerabilities),
            elapsed_sec=round(elapsed, 1),
            rate_per_sec=round(len(valid_findings) / elapsed, 1),
        )
        return enhanced_vulnerabilities

    def _process_finding_batch(self, batch, batch_idx):
        """Process a batch of findings in parallel"""
        batch_results = []
        for finding in batch:
            try:
                enhanced_finding = self._enhance_single_finding(finding)
                if enhanced_finding:
                    batch_results.append(enhanced_finding)
            except Exception:
                # Log error but continue processing
                continue
        return batch_results

    def _sequential_enhance_findings(self, valid_findings):
        """Original sequential processing for smaller finding sets"""
        enhanced_vulnerabilities = []

        for index, finding in enumerate(valid_findings):
            # Progress indication for large finding sets
            if len(valid_findings) > 100 and index % 25 == 0:  # More frequent updates
                progress_pct = (index / len(valid_findings)) * 100
                self.logger.info(
                    "Sequential enhancement progress",
                    completed=index,
                    total=len(valid_findings),
                    progress_pct=round(progress_pct, 1),
                )

            try:
                enhanced_finding = self._enhance_single_finding(finding)
                if enhanced_finding:
                    enhanced_vulnerabilities.append(enhanced_finding)
            except Exception as e:
                self.logger.warning("Error enhancing finding", index=index, error=str(e))
                continue

        return enhanced_vulnerabilities
