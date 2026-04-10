"""Report finalization, interactive report, executive dashboard, plugin metrics."""

import os
from typing import Any, Dict, List


class FinalizeMixin:
    """Report finalization: serialize vulnerabilities, generate interactive report & executive dashboard."""

    def _finalize_enhanced_report(
        self, vulnerabilities: List[Dict[str, Any]], app_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create final enhanced vulnerability report with proper serialization."""
        try:
            self.logger.info("Finalizing enhanced report", count=len(vulnerabilities))

            # Convert vulnerabilities to proper JSON format
            serialized_vulnerabilities = []
            for vuln in vulnerabilities:
                # Ensure vulnerability is in dictionary format
                if hasattr(vuln, "__dict__"):
                    vuln_dict = vuln.__dict__.copy()
                elif hasattr(vuln, "_asdict"):
                    vuln_dict = vuln._asdict()
                elif isinstance(vuln, dict):
                    vuln_dict = vuln.copy()
                else:
                    # Convert unknown object to dict
                    vuln_dict = {}
                    for attr in dir(vuln):
                        if not attr.startswith("_"):
                            try:
                                vuln_dict[attr] = getattr(vuln, attr)
                            except Exception:
                                continue

                # Ensure required fields exist
                required_fields = {
                    "id": vuln_dict.get("id", f"vuln_{hash(str(vuln_dict))}")[:16],
                    "title": vuln_dict.get("title", "Unknown Vulnerability"),
                    "description": vuln_dict.get("description", "No description available"),
                    "severity": vuln_dict.get("severity", "UNKNOWN"),
                    "confidence": vuln_dict.get("confidence", 0.5),
                    "file_path": vuln_dict.get("file_path", "unknown"),
                    "line_number": vuln_dict.get("line_number", 0),
                    "method_name": vuln_dict.get("method_name", ""),
                    "class_name": vuln_dict.get("class_name", ""),
                    "vulnerable_code": vuln_dict.get("vulnerable_code", "[No code available]"),
                    "surrounding_context": vuln_dict.get("surrounding_context", ""),
                    "pattern_matches": vuln_dict.get("pattern_matches", []),
                    "specific_remediation": vuln_dict.get("specific_remediation", "Review and fix this vulnerability"),
                    "code_fix_example": vuln_dict.get("code_fix_example", ""),
                    "api_references": vuln_dict.get("api_references", []),
                    "original_severity": vuln_dict.get("original_severity", vuln_dict.get("severity", "UNKNOWN")),
                    "adjusted_severity": vuln_dict.get("adjusted_severity", vuln_dict.get("severity", "UNKNOWN")),
                    "severity_reasoning": vuln_dict.get("severity_reasoning", "Based on pattern analysis"),
                    "vulnerable_pattern": vuln_dict.get("vulnerable_pattern", "unknown"),
                    "masvs_control": vuln_dict.get("masvs_control", "MASVS-GENERAL"),
                    "owasp_category": vuln_dict.get("owasp_category", "M10: Extraneous Functionality"),
                    "cwe_id": vuln_dict.get("cwe_id", "CWE-200"),
                }

                # Update vulnerability with required fields
                vuln_dict.update(required_fields)

                # Enrich with MSTG references based on MASVS control (best-effort)
                try:
                    _map = {
                        "MASVS-NETWORK-1": ["MASTG-NETWORK-1", "MASTG-TEST-0024"],
                        "MASVS-CRYPTO-1": ["MASTG-CRYPTO-1", "MASTG-TEST-0014"],
                        "MASVS-STORAGE-4": ["MASTG-STORAGE-2", "MASTG-TEST-0031"],
                        "MASVS-AUTH-1": ["MASTG-AUTH-1", "MASTG-TEST-0007"],
                        "MASVS-PRIVACY-1": ["MASTG-PRIVACY-1"],
                    }
                    ctrl = str(vuln_dict.get("masvs_control", "")).strip().upper()
                    if ctrl in _map:
                        vuln_dict["mstg_references"] = _map[ctrl]
                except Exception:
                    pass
                serialized_vulnerabilities.append(vuln_dict)

            # Generate summary statistics
            severity_counts = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
                "INFORMATIONAL": 0,
                "UNKNOWN": 0,
            }
            confidence_stats = {"high": 0, "medium": 0, "low": 0}

            for vuln in serialized_vulnerabilities:
                # Count severities
                severity = vuln.get("severity", "UNKNOWN").upper()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts["UNKNOWN"] += 1

                # Count confidence levels
                confidence = float(vuln.get("confidence", 0.5))
                if confidence >= 0.8:
                    confidence_stats["high"] += 1
                elif confidence >= 0.6:
                    confidence_stats["medium"] += 1
                else:
                    confidence_stats["low"] += 1

            # Create final report structure
            final_report = {
                "success": True,
                "execution_time": 0,  # This will be updated by the calling method
                "findings_count": len(serialized_vulnerabilities),
                "vulnerabilities": serialized_vulnerabilities,
                "metadata": {
                    "app_package": app_context.get("package_name", "unknown"),
                    "app_path": app_context.get("apk_path", "unknown"),
                    "scan_timestamp": app_context.get("scan_timestamp", ""),
                    "target_package": getattr(self, "target_package", "unknown"),
                    "severity_breakdown": severity_counts,
                    "confidence_distribution": confidence_stats,
                    "total_findings": len(serialized_vulnerabilities),
                },
                "fp_filtering_applied": True,
                "fp_filtering_type": "conservative_qa",
                "original_findings_count": app_context.get("original_findings_count", len(serialized_vulnerabilities)),
            }

            self.logger.info(
                "Enhanced report finalized",
                vulnerabilities=len(serialized_vulnerabilities),
                critical=severity_counts["CRITICAL"],
                high=severity_counts["HIGH"],
                medium=severity_counts["MEDIUM"],
                confidence_high=confidence_stats["high"],
                confidence_medium=confidence_stats["medium"],
                confidence_low=confidence_stats["low"],
            )

            # INTERACTIVE REPORT GENERATION: Generate modern interactive HTML report
            self.logger.info("Interactive Report Generation Stage: Creating interactive HTML report")
            try:
                from ..interactive_report_generator import InteractiveReportGenerator, InteractiveReportConfig

                # Create interactive report configuration
                interactive_config = InteractiveReportConfig(
                    title=f"AODS Security Analysis - {app_context.get('package_name', 'Unknown App')}",
                    theme="professional",
                    enable_filtering=True,
                    enable_sorting=True,
                    enable_export=True,
                    show_code_snippets=True,
                    show_remediation=True,
                    show_risk_intelligence=True,
                )

                # Create interactive report generator
                interactive_generator = InteractiveReportGenerator(interactive_config)

                # Generate interactive HTML report
                interactive_report = interactive_generator.generate_interactive_report(final_report)

                # Add interactive report data to final report
                final_report["interactive_report"] = {
                    "report_id": interactive_report.report_id,
                    "title": interactive_report.title,
                    "file_size_bytes": interactive_report.file_size_bytes,
                    "generation_time": interactive_report.generation_time,
                    "html_available": True,
                    "export_formats": ["HTML", "PDF", "CSV", "Excel"],
                    "features": [
                        "Real-time filtering and sorting",
                        "Drill-down analysis",
                        "Interactive vulnerability details",
                        "Export capabilities",
                        "Professional presentation",
                    ],
                }

                # Save interactive HTML report if output directory is available
                output_dir = getattr(self, "output_directory", None)
                if output_dir and os.path.exists(output_dir):
                    html_output_path = os.path.join(
                        output_dir, f"interactive_report_{interactive_report.report_id}.html"
                    )
                    csv_output_path = os.path.join(output_dir, f"vulnerabilities_{interactive_report.report_id}.csv")

                    # Save HTML report
                    html_saved = interactive_generator.save_report(interactive_report, html_output_path)

                    # Export CSV
                    csv_saved = interactive_generator.export_csv(interactive_report, csv_output_path)

                    if html_saved:
                        final_report["interactive_report"]["html_file_path"] = html_output_path
                        self.logger.info("Interactive HTML report saved", path=html_output_path)

                    if csv_saved:
                        final_report["interactive_report"]["csv_file_path"] = csv_output_path
                        self.logger.info("CSV export saved", path=csv_output_path)

                # Add interactive report statistics
                interactive_stats = interactive_generator.get_generation_statistics()
                final_report["interactive_report_statistics"] = {
                    **interactive_stats,
                    "report_generation_success": True,
                    "html_size_kb": interactive_report.file_size_bytes / 1024,
                    "vulnerabilities_included": len(final_report.get("vulnerabilities", [])),
                    "interactive_features_enabled": len(interactive_config.__dict__),
                }

                file_size_kb = interactive_report.file_size_bytes / 1024
                self.logger.info(
                    "Interactive report generation completed",
                    title=interactive_report.title,
                    html_size_kb=round(file_size_kb, 1),
                    generation_time_ms=round(interactive_stats.get("average_generation_time_ms", 0), 1),
                )

            except Exception as e:
                self.logger.warning("Interactive report generation failed", error=str(e))
                # Add fallback interactive report info
                final_report["interactive_report"] = {
                    "report_id": "fallback",
                    "title": "Interactive Report (Generation Failed)",
                    "html_available": False,
                    "error": str(e),
                }

            # EXECUTIVE DASHBOARD GENERATION: Generate executive-level security dashboard
            # Check CLI flags for executive dashboard control
            generate_executive_dashboard = True
            executive_dashboard_output_dir = output_dir

            # Check for CLI arguments (if available in context)
            if hasattr(self, "args") and self.args:
                if hasattr(self.args, "no_executive_dashboard") and self.args.no_executive_dashboard:
                    generate_executive_dashboard = False
                    self.logger.info("Executive Dashboard Generation: Disabled via --no-executive-dashboard flag")
                elif hasattr(self.args, "executive_dashboard_out") and self.args.executive_dashboard_out:
                    executive_dashboard_output_dir = self.args.executive_dashboard_out
                    self.logger.info(
                        "Executive Dashboard Output: Using custom directory", directory=executive_dashboard_output_dir
                    )

            if generate_executive_dashboard:
                self.logger.info("Executive Dashboard Generation Stage: Creating executive security dashboard")
                try:
                    from ..executive_dashboard_generator import ExecutiveDashboardGenerator

                    # Create executive dashboard generator
                    executive_generator = ExecutiveDashboardGenerator()

                    # Try to get monitoring dashboard instance for KPI integration
                    monitoring_dashboard = None
                    try:
                        # Check if monitoring is available in the ML system
                        if hasattr(self, "ml_reducer") and hasattr(self.ml_reducer, "monitoring_dashboard"):
                            monitoring_dashboard = self.ml_reducer.monitoring_dashboard
                            self.logger.info("Integrating enterprise monitoring KPIs into executive dashboard")
                    except Exception as e:
                        self.logger.warning("Could not integrate monitoring KPIs", error=str(e))

                    # Integrate learning analytics summary
                    learning_analytics_summary = None
                    try:
                        from ..shared_infrastructure.learning_analytics_dashboard import (
                            generate_executive_summary_for_dashboard,
                            LearningAnalyticsDashboard,
                            AnalyticsTimeframe,
                        )

                        # Create learning analytics dashboard instance
                        learning_dashboard = LearningAnalyticsDashboard()

                        # Generate executive summary from learning analytics
                        learning_analytics_summary = generate_executive_summary_for_dashboard(
                            learning_dashboard, AnalyticsTimeframe.LAST_MONTH
                        )

                        # Add learning analytics to final report for dashboard integration
                        final_report["learning_analytics_summary"] = learning_analytics_summary
                        self.logger.info("Integrated learning analytics summary into executive dashboard")

                    except Exception as e:
                        self.logger.warning("Could not integrate learning analytics", error=str(e))

                    # Integrate plugin execution metrics
                    try:
                        # Get plugin execution metrics from unified manager
                        plugin_metrics = self._extract_plugin_execution_metrics(final_report)
                        final_report["plugin_execution_metrics"] = plugin_metrics
                        self.logger.info("Integrated plugin execution metrics", plugins_tracked=len(plugin_metrics))
                    except Exception as e:
                        self.logger.warning("Could not integrate plugin metrics", error=str(e))

                    # Generate executive dashboard with monitoring integration
                    executive_dashboard = executive_generator.generate_executive_dashboard(
                        final_report, monitoring_dashboard=monitoring_dashboard
                    )

                    # Add executive dashboard data to final report
                    final_report["executive_dashboard"] = {
                        "dashboard_id": executive_dashboard.dashboard_id,
                        "title": executive_dashboard.title,
                        "file_size_bytes": executive_dashboard.file_size_bytes,
                        "generation_time": executive_dashboard.generation_time,
                        "dashboard_available": True,
                        "executive_summary": {
                            "overall_risk_level": executive_dashboard.executive_summary.overall_risk_level.value,
                            "security_posture_score": executive_dashboard.executive_summary.security_posture_score,
                            "key_findings": executive_dashboard.executive_summary.key_findings,
                            "strategic_recommendations": executive_dashboard.executive_summary.strategic_recommendations,  # noqa: E501
                            "immediate_actions": executive_dashboard.executive_summary.immediate_actions,
                            "investment_priorities": executive_dashboard.executive_summary.investment_priorities,
                        },
                        "kpi_metrics": [
                            {
                                "name": kpi.name,
                                "value": kpi.value,
                                "unit": kpi.unit,
                                "target": kpi.target,
                                "status": kpi.status,
                                "trend": kpi.trend,
                                "description": kpi.description,
                            }
                            for kpi in executive_dashboard.kpi_metrics
                        ],
                        "risk_visualizations": [
                            {
                                "chart_type": viz.chart_type,
                                "title": viz.title,
                                "description": viz.description,
                                "insights": viz.insights,
                            }
                            for viz in executive_dashboard.risk_visualizations
                        ],
                        "compliance_overview": [
                            {
                                "framework": comp.framework,
                                "status": comp.status.value,
                                "coverage_percentage": comp.coverage_percentage,
                                "gaps": comp.gaps,
                                "recommendations": comp.recommendations,
                            }
                            for comp in executive_dashboard.compliance_overview
                        ],
                    }

                    # Save executive dashboard if output directory is available
                    if executive_dashboard_output_dir and os.path.exists(executive_dashboard_output_dir):
                        dashboard_output_path = os.path.join(
                            executive_dashboard_output_dir,
                            f"executive_dashboard_{executive_dashboard.dashboard_id}.html",
                        )

                        # Save dashboard
                        dashboard_saved = executive_generator.save_dashboard(executive_dashboard, dashboard_output_path)

                        if dashboard_saved:
                            final_report["executive_dashboard"]["dashboard_file_path"] = dashboard_output_path
                            final_report["executive_dashboard"][
                                "dashboard_url"
                            ] = f"file://{os.path.abspath(dashboard_output_path)}"

                            # Add dashboard link to main report artifacts
                            if "report_artifacts" not in final_report:
                                final_report["report_artifacts"] = []

                            final_report["report_artifacts"].append(
                                {
                                    "type": "executive_dashboard",
                                    "name": "Executive Security Dashboard",
                                    "path": dashboard_output_path,
                                    "url": final_report["executive_dashboard"]["dashboard_url"],
                                    "description": "High-level executive security dashboard with KPIs and strategic insights",  # noqa: E501
                                    "size_bytes": executive_dashboard.file_size_bytes,
                                    "format": "HTML",
                                }
                            )

                            self.logger.info("Executive dashboard saved", path=dashboard_output_path)

                    # Add executive dashboard statistics
                    executive_stats = executive_generator.get_generation_statistics()
                    final_report["executive_dashboard_statistics"] = {
                        **executive_stats,
                        "dashboard_generation_success": True,
                        "dashboard_size_kb": executive_dashboard.file_size_bytes / 1024,
                        "kpi_metrics_count": len(executive_dashboard.kpi_metrics),
                        "visualizations_count": len(executive_dashboard.risk_visualizations),
                        "compliance_frameworks_count": len(executive_dashboard.compliance_overview),
                    }

                    dashboard_size_kb = executive_dashboard.file_size_bytes / 1024
                    self.logger.info(
                        "Executive dashboard generation completed",
                        title=executive_dashboard.title,
                        dashboard_size_kb=round(dashboard_size_kb, 1),
                        kpi_metrics=len(executive_dashboard.kpi_metrics),
                        risk_visualizations=len(executive_dashboard.risk_visualizations),
                        compliance_frameworks=len(executive_dashboard.compliance_overview),
                        security_score=round(executive_dashboard.executive_summary.security_posture_score, 1),
                        generation_time_ms=round(executive_stats.get("average_generation_time_ms", 0), 1),
                    )

                except Exception as e:
                    self.logger.error("Executive dashboard generation failed", error=str(e), exc_info=True)

                    # Try to generate a minimal fallback dashboard
                    try:
                        fallback_dashboard = executive_generator._generate_fallback_dashboard(final_report, str(e))
                        final_report["executive_dashboard"] = {
                            "dashboard_id": fallback_dashboard.dashboard_id,
                            "title": fallback_dashboard.title,
                            "dashboard_available": True,
                            "fallback_mode": True,
                            "original_error": str(e),
                            "executive_summary": {
                                "overall_risk_level": fallback_dashboard.executive_summary.overall_risk_level.value,
                                "security_posture_score": fallback_dashboard.executive_summary.security_posture_score,
                                "key_findings": fallback_dashboard.executive_summary.key_findings,
                                "strategic_recommendations": fallback_dashboard.executive_summary.strategic_recommendations,  # noqa: E501
                            },
                        }
                        self.logger.info("Generated fallback executive dashboard")
                    except Exception as fallback_error:
                        self.logger.error("Fallback dashboard generation also failed", error=str(fallback_error))
                        # Add minimal fallback dashboard info
                        final_report["executive_dashboard"] = {
                            "dashboard_id": "fallback",
                            "title": "Executive Dashboard (Generation Failed)",
                            "dashboard_available": False,
                            "error": str(e),
                            "fallback_error": str(fallback_error),
                        }
            else:
                # Executive dashboard disabled via CLI flag
                final_report["executive_dashboard"] = {
                    "dashboard_id": "disabled",
                    "title": "Executive Dashboard (Disabled)",
                    "dashboard_available": False,
                    "disabled_reason": "Disabled via --no-executive-dashboard CLI flag",
                }

            return final_report

        except Exception as e:
            self.logger.error("Enhanced report finalization failed", error=str(e))
            # Return basic structure to prevent complete failure
            return {
                "success": False,
                "execution_time": 0,
                "findings_count": 0,
                "vulnerabilities": [],
                "metadata": {"error": str(e)},
                "fp_filtering_applied": False,
                "fp_filtering_type": "none",
                "original_findings_count": 0,
            }

    def _extract_plugin_execution_metrics(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract plugin execution metrics for executive dashboard integration.

        Args:
            report_data: Complete report data

        Returns:
            Dictionary containing plugin execution metrics
        """
        try:
            plugin_metrics = {
                "total_plugins_executed": 0,
                "successful_plugins": 0,
                "failed_plugins": 0,
                "average_execution_time": 0.0,
                "total_execution_time": 0.0,
                "plugin_performance": {},
                "plugin_success_rate": 0.0,
                "findings_per_plugin": {},
                "top_performing_plugins": [],
            }

            # Extract from scan statistics if available
            scan_stats = report_data.get("scan_statistics", {})
            if "plugins_executed" in scan_stats:
                plugin_metrics["total_plugins_executed"] = scan_stats["plugins_executed"]

            if "execution_time" in scan_stats:
                plugin_metrics["total_execution_time"] = scan_stats["execution_time"]

            # Extract from vulnerabilities to calculate findings per plugin
            vulnerabilities = report_data.get("vulnerabilities", [])
            plugin_findings = {}

            for vuln in vulnerabilities:
                if isinstance(vuln, dict):
                    plugin_name = vuln.get("plugin", "unknown")
                    if plugin_name not in plugin_findings:
                        plugin_findings[plugin_name] = 0
                    plugin_findings[plugin_name] += 1

            plugin_metrics["findings_per_plugin"] = plugin_findings

            # Calculate top performing plugins (by findings)
            if plugin_findings:
                sorted_plugins = sorted(plugin_findings.items(), key=lambda x: x[1], reverse=True)
                plugin_metrics["top_performing_plugins"] = [
                    {"plugin": name, "findings": count} for name, count in sorted_plugins[:5]
                ]

            # Calculate success rate (assume all executed plugins succeeded if we have findings)
            if plugin_metrics["total_plugins_executed"] > 0:
                plugin_metrics["successful_plugins"] = len(plugin_findings)
                plugin_metrics["plugin_success_rate"] = (
                    plugin_metrics["successful_plugins"] / plugin_metrics["total_plugins_executed"]
                ) * 100

            # Calculate average execution time
            if plugin_metrics["total_plugins_executed"] > 0 and plugin_metrics["total_execution_time"] > 0:
                plugin_metrics["average_execution_time"] = (
                    plugin_metrics["total_execution_time"] / plugin_metrics["total_plugins_executed"]
                )

            return plugin_metrics

        except Exception as e:
            self.logger.error(f"Failed to extract plugin execution metrics: {e}")
            return {
                "total_plugins_executed": 0,
                "successful_plugins": 0,
                "failed_plugins": 0,
                "average_execution_time": 0.0,
                "plugin_success_rate": 0.0,
                "error": str(e),
            }
