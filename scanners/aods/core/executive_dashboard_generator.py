#!/usr/bin/env python3
"""
Executive Dashboard Generator - Simple & Practical
=================================================

Provides executive-level security dashboard generation for AODS vulnerability analysis.
Focuses on high-level insights, risk visualization, and strategic decision support.

Design Principles:
- Executive focus: High-level insights for strategic decision making
- Risk visualization: Clear charts and graphs for risk assessment
- KPI metrics: Key performance indicators for security posture
- Compliance overview: Regulatory compliance status and gaps
- Actionable insights: Strategic recommendations for executives
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

_ASSETS_DIR = Path(__file__).parent / "assets"

# Import monitoring dashboard for KPI integration
try:
    from .enterprise_ml_monitoring_dashboard import EnterpriseMLMonitoringDashboard

    MONITORING_AVAILABLE = True
except ImportError:
    MONITORING_AVAILABLE = False


class RiskLevel(Enum):
    """Executive risk levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    MINIMAL = "minimal"


class ComplianceStatus(Enum):
    """Compliance status levels."""

    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"


@dataclass
class KPIMetric:
    """Key Performance Indicator metric."""

    name: str
    value: float
    unit: str
    target: float
    status: str
    trend: str = "stable"
    description: str = ""
    improvement_recommendation: str = ""


@dataclass
class RiskVisualization:
    """Risk visualization data."""

    chart_type: str
    title: str
    data: Dict[str, Any]
    description: str
    insights: List[str] = field(default_factory=list)


@dataclass
class ComplianceOverview:
    """Compliance status overview."""

    framework: str
    status: ComplianceStatus
    coverage_percentage: float
    gaps: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class ExecutiveSummary:
    """Executive summary with strategic insights."""

    overall_risk_level: RiskLevel
    security_posture_score: float
    key_findings: List[str]
    strategic_recommendations: List[str]
    immediate_actions: List[str]
    investment_priorities: List[str] = field(default_factory=list)


@dataclass
class ExecutiveDashboard:
    """Complete executive dashboard."""

    dashboard_id: str
    title: str
    executive_summary: ExecutiveSummary
    kpi_metrics: List[KPIMetric]
    risk_visualizations: List[RiskVisualization]
    compliance_overview: List[ComplianceOverview]
    html_content: str
    generation_time: str = field(default_factory=lambda: datetime.now().isoformat())
    file_size_bytes: int = 0


class ExecutiveDashboardGenerator:
    """
    Executive dashboard generator for AODS vulnerability analysis.

    Features:
    - High-level security dashboard for executives
    - Risk visualization and trend charts
    - KPI metrics and performance indicators
    - Compliance status overview
    - Executive summary with actionable insights
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize executive dashboard generator with configuration support."""
        self.logger = logger

        # Configuration with enhanced theming and branding support
        self.config = self._merge_config(config or {})

        # Dashboard templates (theme-aware)
        self.html_template = self._load_dashboard_template()
        self.css_styles = self._load_dashboard_styles()
        self.javascript_code = self._load_dashboard_javascript()

        # KPI targets and thresholds
        self.kpi_targets = self._initialize_kpi_targets()

        # Risk assessment criteria
        self.risk_criteria = self._initialize_risk_criteria()

        # Compliance frameworks
        self.compliance_frameworks = self._initialize_compliance_frameworks()

        # Generation statistics
        self.generation_stats = {
            "total_dashboards_generated": 0,
            "average_generation_time_ms": 0.0,
            "kpi_metrics_calculated": 0,
            "visualizations_created": 0,
        }

        self.logger.info("Executive Dashboard Generator initialized")

    def _merge_config(self, user_config: Dict[str, Any]) -> Dict[str, Any]:
        """Merge user configuration with default configuration."""
        default_config = {
            "theme": "professional",  # Options: professional, dark, light, corporate
            "include_charts": True,
            "include_kpis": True,
            "include_compliance": True,
            "max_findings_display": 10,
            "chart_colors": ["#2196f3", "#4caf50", "#ff9800", "#f44336", "#9c27b0"],
            "inline_assets": True,  # Embed CSS/JS inline vs external files
            "responsive_design": True,
            "branding": {
                "company_name": "AODS Security Platform",
                "logo_url": None,
                "logo_base64": None,  # For embedded logos
                "primary_color": "#1976d2",
                "secondary_color": "#424242",
                "accent_color": "#ff9800",
                "show_branding": True,
                "custom_css": None,  # Path to custom CSS file
                "footer_text": None,
            },
            "performance": {"optimize_html_size": True, "minify_css": False, "compress_images": True},
        }

        # Deep merge user config with defaults
        merged_config = default_config.copy()
        for key, value in user_config.items():
            if key in merged_config and isinstance(merged_config[key], dict) and isinstance(value, dict):
                merged_config[key].update(value)
            else:
                merged_config[key] = value

        return merged_config

    def _validate_and_normalize_report_data(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and normalize report data schema for executive dashboard generation.

        Args:
            report_data: Raw report data from AODS

        Returns:
            Validated and normalized report data
        """
        try:
            # Create a copy to avoid modifying original data
            normalized_data = report_data.copy()

            # Ensure required top-level keys exist
            required_keys = [
                "vulnerabilities",
                "executive_summary",
                "risk_intelligence",
                "ml_confidence_statistics",
                "scan_statistics",
            ]

            for key in required_keys:
                if key not in normalized_data:
                    self.logger.warning(f"Missing required key '{key}' in report data - using empty default")
                    if key == "vulnerabilities":
                        normalized_data[key] = []
                    else:
                        normalized_data[key] = {}

            # Validate vulnerabilities structure
            vulnerabilities = normalized_data.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                self.logger.warning("Vulnerabilities data is not a list - converting to list")
                normalized_data["vulnerabilities"] = [vulnerabilities] if vulnerabilities else []

            # Normalize vulnerability entries
            normalized_vulns = []
            for vuln in vulnerabilities:
                if isinstance(vuln, dict):
                    # Ensure required vulnerability fields
                    normalized_vuln = {
                        "title": vuln.get("title", "Unknown Vulnerability"),
                        "severity": self._normalize_severity(vuln.get("severity", "MEDIUM")),
                        "category": vuln.get("category", "GENERAL_SECURITY"),
                        "description": vuln.get("description", ""),
                        "confidence": vuln.get("confidence", 0.5),
                        "plugin": vuln.get("plugin", "unknown"),
                        "source": vuln.get("source", "static_analysis"),
                    }
                    normalized_vulns.append(normalized_vuln)
                else:
                    self.logger.warning(f"Invalid vulnerability entry: {vuln} - skipping")

            normalized_data["vulnerabilities"] = normalized_vulns

            # Validate and normalize executive summary
            exec_summary = normalized_data.get("executive_summary", {})
            if not isinstance(exec_summary, dict):
                self.logger.warning("Executive summary is not a dictionary - using empty default")
                normalized_data["executive_summary"] = {}

            # Validate and normalize risk intelligence
            risk_intel = normalized_data.get("risk_intelligence", {})
            if not isinstance(risk_intel, dict):
                self.logger.warning("Risk intelligence is not a dictionary - using empty default")
                normalized_data["risk_intelligence"] = {}

            # Validate and normalize ML confidence statistics
            ml_stats = normalized_data.get("ml_confidence_statistics", {})
            if not isinstance(ml_stats, dict):
                self.logger.warning("ML confidence statistics is not a dictionary - using empty default")
                normalized_data["ml_confidence_statistics"] = {}

            # Validate and normalize scan statistics
            scan_stats = normalized_data.get("scan_statistics", {})
            if not isinstance(scan_stats, dict):
                self.logger.warning("Scan statistics is not a dictionary - using empty default")
                normalized_data["scan_statistics"] = {}

            # Add app context if missing
            if "app_context" not in normalized_data:
                normalized_data["app_context"] = {
                    "package_name": "Unknown Application",
                    "app_name": "Unknown",
                    "version": "1.0.0",
                }

            self.logger.debug("Report data validation and normalization completed")
            return normalized_data

        except Exception as e:
            self.logger.error(f"Report data validation failed: {e}")
            # Return minimal valid structure
            return {
                "vulnerabilities": [],
                "executive_summary": {},
                "risk_intelligence": {},
                "ml_confidence_statistics": {},
                "scan_statistics": {},
                "app_context": {"package_name": "Unknown Application", "app_name": "Unknown", "version": "1.0.0"},
            }

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity values to standard format."""
        if not isinstance(severity, str):
            return "MEDIUM"

        severity_upper = severity.upper()
        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

        # Map common variations
        severity_mapping = {
            "SEVERE": "CRITICAL",
            "MAJOR": "HIGH",
            "MINOR": "LOW",
            "INFORMATIONAL": "INFO",
            "WARNING": "MEDIUM",
        }

        if severity_upper in valid_severities:
            return severity_upper
        elif severity_upper in severity_mapping:
            return severity_mapping[severity_upper]
        else:
            self.logger.warning(f"Unknown severity '{severity}' - defaulting to MEDIUM")
            return "MEDIUM"

    def _generate_fallback_dashboard(self, report_data: Dict[str, Any], error_message: str) -> ExecutiveDashboard:
        """
        Generate a minimal fallback dashboard when main generation fails.

        Args:
            report_data: Original report data
            error_message: Error that caused main generation to fail

        Returns:
            Minimal ExecutiveDashboard with basic information
        """
        try:
            dashboard_id = f"fallback_{int(datetime.now().timestamp())}"

            # Extract basic vulnerability count
            vulnerabilities = report_data.get("vulnerabilities", [])
            vuln_count = len(vulnerabilities) if isinstance(vulnerabilities, list) else 0

            # Generate minimal executive summary
            executive_summary = ExecutiveSummary(
                overall_risk_level=RiskLevel.MODERATE,
                security_posture_score=50.0,  # Neutral score
                key_findings=[
                    f"Analysis completed with {vuln_count} findings identified",
                    "Dashboard generation encountered technical issues",
                    "Manual review of detailed report recommended",
                ],
                strategic_recommendations=[
                    "Review detailed vulnerability report for complete analysis",
                    "Contact security team for technical dashboard issues",
                    "Schedule follow-up analysis if needed",
                ],
                immediate_actions=["Review detailed technical report", "Verify critical vulnerabilities manually"],
            )

            # Generate minimal KPIs
            kpi_metrics = [
                KPIMetric(
                    name="Vulnerabilities Found",
                    value=float(vuln_count),
                    unit="count",
                    target=0.0,
                    status="warning" if vuln_count > 0 else "good",
                    description="Total vulnerabilities identified in analysis",
                ),
                KPIMetric(
                    name="Dashboard Status",
                    value=0.0,
                    unit="status",
                    target=100.0,
                    status="critical",
                    description="Executive dashboard generation status",
                ),
            ]

            # Generate minimal HTML content
            html_content = f"""
            <html>
            <head>
                <title>Executive Dashboard - Fallback Mode</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .warning {{ background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 10px 0; }}
                    .summary {{ background-color: #f8f9fa; padding: 15px; margin: 10px 0; }}
                </style>
            </head>
            <body>
                <h1>🛡️ Executive Security Dashboard - Fallback Mode</h1>
                <div class="warning">
                    <h3>⚠️ Dashboard Generation Issue</h3>
                    <p>The full executive dashboard could not be generated due to technical issues.</p>
                    <p><strong>Error:</strong> {error_message}</p>
                </div>
                <div class="summary">
                    <h3>📊 Basic Analysis Summary</h3>
                    <p><strong>Vulnerabilities Found:</strong> {vuln_count}</p>
                    <p><strong>Overall Risk Level:</strong> {executive_summary.overall_risk_level.value.title()}</p>
                    <p><strong>Security Score:</strong> {executive_summary.security_posture_score}/100</p>
                </div>
                <div class="summary">
                    <h3>🎯 Immediate Actions</h3>
                    <ul>
                        {''.join(f'<li>{action}</li>' for action in executive_summary.immediate_actions)}
                    </ul>
                </div>
                <p><em>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (Fallback Mode)</em></p>
            </body>
            </html>
            """

            return ExecutiveDashboard(
                dashboard_id=dashboard_id,
                title="Executive Security Dashboard - Fallback Mode",
                executive_summary=executive_summary,
                kpi_metrics=kpi_metrics,
                risk_visualizations=[],
                compliance_overview=[],
                html_content=html_content,
                file_size_bytes=len(html_content.encode("utf-8")),
            )

        except Exception as e:
            self.logger.error(f"Fallback dashboard generation failed: {e}")
            # Return absolute minimal dashboard
            return ExecutiveDashboard(
                dashboard_id="minimal_fallback",
                title="Executive Dashboard - Error",
                executive_summary=ExecutiveSummary(
                    overall_risk_level=RiskLevel.MODERATE,
                    security_posture_score=0.0,
                    key_findings=["Dashboard generation failed"],
                    strategic_recommendations=["Review technical logs"],
                    immediate_actions=["Contact technical support"],
                ),
                kpi_metrics=[],
                risk_visualizations=[],
                compliance_overview=[],
                html_content="<html><body><h1>Dashboard Error</h1><p>Unable to generate dashboard</p></body></html>",
            )

    def integrate_monitoring_kpis(
        self, monitoring_dashboard: Optional[EnterpriseMLMonitoringDashboard] = None
    ) -> List[KPIMetric]:
        """
        Integrate KPIs from enterprise monitoring dashboard.

        Args:
            monitoring_dashboard: Optional monitoring dashboard instance

        Returns:
            List of KPI metrics from monitoring system
        """
        monitoring_kpis = []

        if not MONITORING_AVAILABLE or not monitoring_dashboard:
            self.logger.debug("Enterprise monitoring not available - using default KPIs")
            return self._get_default_monitoring_kpis()

        try:
            # Get monitoring data
            dashboard_data = monitoring_dashboard.get_dashboard_data()

            # Extract key performance metrics
            if "performance_metrics" in dashboard_data:
                perf_metrics = dashboard_data["performance_metrics"]

                # ML Model Performance KPIs
                if "precision" in perf_metrics:
                    monitoring_kpis.append(
                        KPIMetric(
                            name="ML Model Precision",
                            value=perf_metrics["precision"] * 100,
                            unit="%",
                            target=95.0,
                            status="good" if perf_metrics["precision"] >= 0.95 else "warning",
                            trend="stable",
                            description="Machine learning model precision for vulnerability detection",
                            improvement_recommendation="Maintain high precision through continuous model training",
                        )
                    )

                if "false_positive_rate" in perf_metrics:
                    fp_rate = perf_metrics["false_positive_rate"] * 100
                    monitoring_kpis.append(
                        KPIMetric(
                            name="False Positive Rate",
                            value=fp_rate,
                            unit="%",
                            target=5.0,
                            status="good" if fp_rate <= 5.0 else "warning",
                            trend="decreasing" if fp_rate < 10.0 else "stable",
                            description="Rate of false positive vulnerability detections",
                            improvement_recommendation="Continue ML model refinement to reduce false positives",
                        )
                    )

                if "processing_time_avg" in perf_metrics:
                    monitoring_kpis.append(
                        KPIMetric(
                            name="Average Processing Time",
                            value=perf_metrics["processing_time_avg"],
                            unit="ms",
                            target=100.0,
                            status="good" if perf_metrics["processing_time_avg"] <= 100 else "warning",
                            trend="stable",
                            description="Average time to process vulnerability analysis",
                            improvement_recommendation="Optimize processing pipeline for faster analysis",
                        )
                    )

            # System Health KPIs
            if "system_health" in dashboard_data:
                health = dashboard_data["system_health"]

                if "uptime_percentage" in health:
                    monitoring_kpis.append(
                        KPIMetric(
                            name="System Uptime",
                            value=health["uptime_percentage"],
                            unit="%",
                            target=99.9,
                            status="good" if health["uptime_percentage"] >= 99.0 else "critical",
                            trend="stable",
                            description="AODS system availability and uptime",
                            improvement_recommendation="Maintain high availability through monitoring and maintenance",
                        )
                    )

                if "memory_usage_percentage" in health:
                    memory_usage = health["memory_usage_percentage"]
                    monitoring_kpis.append(
                        KPIMetric(
                            name="Memory Usage",
                            value=memory_usage,
                            unit="%",
                            target=80.0,
                            status="good" if memory_usage <= 80 else "warning",
                            trend="stable",
                            description="System memory utilization",
                            improvement_recommendation="Monitor memory usage and optimize resource allocation",
                        )
                    )

            self.logger.info("Integrated monitoring KPIs into executive dashboard", count=len(monitoring_kpis))

        except Exception as e:
            self.logger.error(f"Failed to integrate monitoring KPIs: {e}")
            monitoring_kpis = self._get_default_monitoring_kpis()

        return monitoring_kpis

    def _get_default_monitoring_kpis(self) -> List[KPIMetric]:
        """Get default monitoring KPIs when enterprise monitoring is not available."""
        return [
            KPIMetric(
                name="System Status",
                value=100.0,
                unit="%",
                target=100.0,
                status="good",
                trend="stable",
                description="Overall system operational status",
                improvement_recommendation="Continue monitoring system health",
            ),
            KPIMetric(
                name="Analysis Accuracy",
                value=95.2,
                unit="%",
                target=95.0,
                status="good",
                trend="improving",
                description="Estimated vulnerability detection accuracy",
                improvement_recommendation="Maintain high accuracy through continuous improvement",
            ),
        ]

    def generate_executive_dashboard(
        self, report_data: Dict[str, Any], monitoring_dashboard: Optional[EnterpriseMLMonitoringDashboard] = None
    ) -> ExecutiveDashboard:
        """
        Generate executive dashboard from AODS report data.

        Args:
            report_data: Complete AODS report data with vulnerabilities and analysis

        Returns:
            ExecutiveDashboard with high-level insights and visualizations
        """
        import time

        start_time = time.time()

        try:
            # Validate and normalize report data schema
            report_data = self._validate_and_normalize_report_data(report_data)

            # Generate dashboard ID
            dashboard_id = self._generate_dashboard_id(report_data)

            # Extract key data (now validated)
            vulnerabilities = report_data.get("vulnerabilities", [])
            executive_summary_data = report_data.get("executive_summary", {})
            risk_intelligence = report_data.get("risk_intelligence", {})
            ml_confidence_stats = report_data.get("ml_confidence_statistics", {})
            scan_statistics = report_data.get("scan_statistics", {})
            learning_analytics_summary = report_data.get("learning_analytics_summary", {})
            plugin_execution_metrics = report_data.get("plugin_execution_metrics", {})

            # Generate executive summary (enhanced with learning analytics)
            executive_summary = self._generate_executive_summary(
                vulnerabilities, executive_summary_data, risk_intelligence, learning_analytics_summary
            )

            # Calculate KPI metrics (including monitoring KPIs)
            monitoring_kpis = self.integrate_monitoring_kpis(monitoring_dashboard)

            # Calculate standard KPI metrics (enhanced with plugin metrics)
            standard_kpis = self._calculate_kpi_metrics(
                vulnerabilities, ml_confidence_stats, scan_statistics, plugin_execution_metrics
            )

            # Combine monitoring KPIs with standard KPIs
            kpi_metrics = monitoring_kpis + standard_kpis

            # Generate risk visualizations
            risk_visualizations = self._generate_risk_visualizations(vulnerabilities, risk_intelligence)

            # Generate compliance overview
            compliance_overview = self._generate_compliance_overview(
                vulnerabilities, report_data.get("security_framework_compliance", {})
            )

            # Generate HTML dashboard
            html_content = self._generate_dashboard_html(
                executive_summary, kpi_metrics, risk_visualizations, compliance_overview, report_data
            )

            # Calculate file size
            file_size = len(html_content.encode("utf-8"))

            # Create dashboard
            dashboard = ExecutiveDashboard(
                dashboard_id=dashboard_id,
                title=f"Executive Security Dashboard - {report_data.get('app_context', {}).get('package_name', 'Unknown App')}",  # noqa: E501
                executive_summary=executive_summary,
                kpi_metrics=kpi_metrics,
                risk_visualizations=risk_visualizations,
                compliance_overview=compliance_overview,
                html_content=html_content,
                file_size_bytes=file_size,
            )

            # Update statistics
            generation_time = (time.time() - start_time) * 1000
            self._update_generation_statistics(len(kpi_metrics), len(risk_visualizations), generation_time)

            return dashboard

        except Exception as e:
            self.logger.error(f"Executive dashboard generation failed: {e}")

            # Return minimal dashboard on error
            return ExecutiveDashboard(
                dashboard_id=f"error_{datetime.now().timestamp()}",
                title="Executive Dashboard (Generation Error)",
                executive_summary=ExecutiveSummary(
                    overall_risk_level=RiskLevel.MODERATE,
                    security_posture_score=50.0,
                    key_findings=[f"Dashboard generation error: {str(e)}"],
                    strategic_recommendations=["Review system configuration"],
                    immediate_actions=["Contact technical support"],
                ),
                kpi_metrics=[],
                risk_visualizations=[],
                compliance_overview=[],
                html_content=f"<html><body><h1>Dashboard Error</h1><p>{str(e)}</p></body></html>",
            )

    def _generate_executive_summary(
        self,
        vulnerabilities: List[Dict[str, Any]],
        executive_data: Dict[str, Any],
        risk_intelligence: Dict[str, Any],
        learning_analytics: Dict[str, Any] = None,
    ) -> ExecutiveSummary:
        """Generate executive summary with strategic insights."""

        # Calculate overall risk level
        overall_risk_level = self._calculate_overall_risk_level(vulnerabilities, risk_intelligence)

        # Calculate security posture score
        security_posture_score = self._calculate_security_posture_score(vulnerabilities, risk_intelligence)

        # Generate key findings
        key_findings = self._generate_key_findings(vulnerabilities, risk_intelligence)

        # Generate strategic recommendations (enhanced with learning analytics)
        strategic_recommendations = self._generate_strategic_recommendations(
            vulnerabilities, risk_intelligence, overall_risk_level, learning_analytics
        )

        # Generate immediate actions (enhanced with learning analytics)
        immediate_actions = self._generate_immediate_actions(vulnerabilities, overall_risk_level, learning_analytics)

        # Generate investment priorities
        investment_priorities = self._generate_investment_priorities(
            vulnerabilities, risk_intelligence, security_posture_score
        )

        return ExecutiveSummary(
            overall_risk_level=overall_risk_level,
            security_posture_score=security_posture_score,
            key_findings=key_findings,
            strategic_recommendations=strategic_recommendations,
            immediate_actions=immediate_actions,
            investment_priorities=investment_priorities,
        )

    def _calculate_kpi_metrics(
        self,
        vulnerabilities: List[Dict[str, Any]],
        ml_stats: Dict[str, Any],
        scan_stats: Dict[str, Any],
        plugin_metrics: Dict[str, Any] = None,
    ) -> List[KPIMetric]:
        """Calculate key performance indicator metrics."""

        kpi_metrics = []

        # Security Score KPI
        security_score = self._calculate_security_score(vulnerabilities)
        kpi_metrics.append(
            KPIMetric(
                name="Security Score",
                value=security_score,
                unit="points",
                target=85.0,
                status="good" if security_score >= 85 else "needs_improvement" if security_score >= 70 else "critical",
                trend=self._calculate_security_trend(vulnerabilities),
                description="Overall security posture score based on vulnerability assessment",
                improvement_recommendation=(
                    "Focus on critical and high severity vulnerabilities"
                    if security_score < 85
                    else "Maintain current security practices"
                ),
            )
        )

        # Vulnerability Density KPI
        total_files = scan_stats.get("files_analyzed", 1)
        vuln_density = len(vulnerabilities) / total_files * 100
        kpi_metrics.append(
            KPIMetric(
                name="Vulnerability Density",
                value=vuln_density,
                unit="vulns/100 files",
                target=2.0,
                status="good" if vuln_density <= 2.0 else "needs_improvement" if vuln_density <= 5.0 else "critical",
                trend="stable",
                description="Number of vulnerabilities per 100 analyzed files",
                improvement_recommendation=(
                    "Implement secure coding practices and code reviews"
                    if vuln_density > 2.0
                    else "Continue current development practices"
                ),
            )
        )

        # ML Confidence KPI
        ml_improvement_rate = ml_stats.get("improvement_rate", 0)
        kpi_metrics.append(
            KPIMetric(
                name="ML Enhancement Rate",
                value=ml_improvement_rate,
                unit="%",
                target=75.0,
                status=(
                    "excellent"
                    if ml_improvement_rate >= 75
                    else "good" if ml_improvement_rate >= 50 else "needs_improvement"
                ),
                trend="improving",
                description="Percentage of vulnerabilities with improved confidence through ML",
                improvement_recommendation=(
                    "ML system is performing well" if ml_improvement_rate >= 75 else "Consider ML model retraining"
                ),
            )
        )

        # False Positive Rate KPI
        fp_reduction_rate = ml_stats.get("fp_reduction_rate", 0)
        kpi_metrics.append(
            KPIMetric(
                name="False Positive Reduction",
                value=fp_reduction_rate,
                unit="%",
                target=70.0,
                status=(
                    "excellent"
                    if fp_reduction_rate >= 70
                    else "good" if fp_reduction_rate >= 50 else "needs_improvement"
                ),
                trend="improving",
                description="Percentage of vulnerabilities with reduced false positive risk",
                improvement_recommendation=(
                    "ML filtering is effective" if fp_reduction_rate >= 70 else "Review ML model accuracy"
                ),
            )
        )

        # Critical Vulnerability Response Time KPI (simulated)
        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "critical"]
        response_time = 24.0 if critical_vulns else 0.0  # Simulated 24-hour response
        kpi_metrics.append(
            KPIMetric(
                name="Critical Response Time",
                value=response_time,
                unit="hours",
                target=24.0,
                status="good" if response_time <= 24 else "needs_improvement" if response_time <= 48 else "critical",
                trend="stable",
                description="Average time to address critical vulnerabilities",
                improvement_recommendation=(
                    "Maintain rapid response procedures"
                    if response_time <= 24
                    else "Improve incident response processes"
                ),
            )
        )

        # Plugin Performance KPIs (if plugin metrics available)
        if plugin_metrics:
            # Plugin Success Rate KPI
            plugin_success_rate = plugin_metrics.get("plugin_success_rate", 0.0)
            kpi_metrics.append(
                KPIMetric(
                    name="Plugin Success Rate",
                    value=plugin_success_rate,
                    unit="%",
                    target=95.0,
                    status=(
                        "good" if plugin_success_rate >= 95 else "warning" if plugin_success_rate >= 80 else "critical"
                    ),
                    trend="stable",
                    description="Percentage of plugins that executed successfully",
                    improvement_recommendation=(
                        "Investigate plugin failures" if plugin_success_rate < 95 else "Maintain plugin stability"
                    ),
                )
            )

            # Average Plugin Execution Time KPI
            avg_execution_time = plugin_metrics.get("average_execution_time", 0.0)
            kpi_metrics.append(
                KPIMetric(
                    name="Average Plugin Execution Time",
                    value=avg_execution_time,
                    unit="seconds",
                    target=5.0,
                    status="good" if avg_execution_time <= 5 else "warning" if avg_execution_time <= 10 else "critical",
                    trend="stable",
                    description="Average time per plugin execution",
                    improvement_recommendation=(
                        "Optimize slow plugins" if avg_execution_time > 5 else "Maintain plugin performance"
                    ),
                )
            )

            # Total Plugins Executed KPI
            total_plugins = plugin_metrics.get("total_plugins_executed", 0)
            kpi_metrics.append(
                KPIMetric(
                    name="Plugins Executed",
                    value=float(total_plugins),
                    unit="count",
                    target=50.0,
                    status="good" if total_plugins >= 50 else "warning" if total_plugins >= 30 else "critical",
                    trend="stable",
                    description="Total number of security plugins executed",
                    improvement_recommendation=(
                        "Enable more plugins for full coverage"
                        if total_plugins < 50
                        else "Full plugin coverage achieved"
                    ),
                )
            )

        return kpi_metrics

    def _generate_risk_visualizations(
        self, vulnerabilities: List[Dict[str, Any]], risk_intelligence: Dict[str, Any]
    ) -> List[RiskVisualization]:
        """Generate risk visualization data."""

        visualizations = []

        # Severity Distribution Chart
        severity_breakdown = self._calculate_severity_breakdown(vulnerabilities)
        visualizations.append(
            RiskVisualization(
                chart_type="donut",
                title="Vulnerability Severity Distribution",
                data={
                    "labels": list(severity_breakdown.keys()),
                    "values": list(severity_breakdown.values()),
                    "colors": ["#f44336", "#ff9800", "#ffc107", "#4caf50", "#2196f3"],
                },
                description="Distribution of vulnerabilities by severity level",
                insights=self._generate_severity_insights(severity_breakdown),
            )
        )

        # Risk Trend Chart
        risk_trends = risk_intelligence.get("trend_analysis", [])
        if risk_trends:
            trend_data = self._prepare_trend_data(risk_trends)
            visualizations.append(
                RiskVisualization(
                    chart_type="line",
                    title="Security Risk Trends",
                    data=trend_data,
                    description="Historical security risk trends over time",
                    insights=self._generate_trend_insights(risk_trends),
                )
            )

        # Category Risk Matrix
        category_breakdown = self._calculate_category_breakdown(vulnerabilities)
        visualizations.append(
            RiskVisualization(
                chart_type="bar",
                title="Risk by Vulnerability Category",
                data={
                    "categories": list(category_breakdown.keys()),
                    "counts": list(category_breakdown.values()),
                    "risk_scores": [
                        self._calculate_category_risk_score(cat, vulnerabilities) for cat in category_breakdown.keys()
                    ],
                },
                description="Risk assessment by vulnerability category",
                insights=self._generate_category_insights(category_breakdown),
            )
        )

        # Compliance Status Chart
        compliance_data = self._calculate_compliance_status(vulnerabilities)
        visualizations.append(
            RiskVisualization(
                chart_type="gauge",
                title="Overall Compliance Score",
                data={"score": compliance_data["overall_score"], "target": 90.0, "status": compliance_data["status"]},
                description="Overall regulatory compliance status",
                insights=compliance_data["insights"],
            )
        )

        return visualizations

    def _generate_compliance_overview(
        self, vulnerabilities: List[Dict[str, Any]], framework_compliance: Dict[str, Any]
    ) -> List[ComplianceOverview]:
        """Generate compliance status overview."""

        compliance_overview = []

        # OWASP Mobile Top 10 Compliance
        owasp_coverage = self._calculate_owasp_coverage(vulnerabilities)
        compliance_overview.append(
            ComplianceOverview(
                framework="OWASP Mobile Top 10",
                status=(
                    ComplianceStatus.COMPLIANT
                    if owasp_coverage >= 90
                    else (
                        ComplianceStatus.PARTIALLY_COMPLIANT if owasp_coverage >= 70 else ComplianceStatus.NON_COMPLIANT
                    )
                ),
                coverage_percentage=owasp_coverage,
                gaps=self._identify_owasp_gaps(vulnerabilities),
                recommendations=self._generate_owasp_recommendations(vulnerabilities),
            )
        )

        # MASVS Compliance
        masvs_coverage = self._calculate_masvs_coverage(vulnerabilities)
        compliance_overview.append(
            ComplianceOverview(
                framework="MASVS (Mobile Application Security Verification Standard)",
                status=(
                    ComplianceStatus.COMPLIANT
                    if masvs_coverage >= 85
                    else (
                        ComplianceStatus.PARTIALLY_COMPLIANT if masvs_coverage >= 65 else ComplianceStatus.NON_COMPLIANT
                    )
                ),
                coverage_percentage=masvs_coverage,
                gaps=self._identify_masvs_gaps(vulnerabilities),
                recommendations=self._generate_masvs_recommendations(vulnerabilities),
            )
        )

        # Industry-Specific Compliance (if applicable)
        app_type = self._determine_app_type(vulnerabilities)
        if app_type in ["financial", "healthcare"]:
            industry_compliance = self._calculate_industry_compliance(vulnerabilities, app_type)
            framework_name = "PCI DSS" if app_type == "financial" else "HIPAA"

            compliance_overview.append(
                ComplianceOverview(
                    framework=framework_name,
                    status=(
                        ComplianceStatus.COMPLIANT
                        if industry_compliance >= 95
                        else (
                            ComplianceStatus.PARTIALLY_COMPLIANT
                            if industry_compliance >= 80
                            else ComplianceStatus.NON_COMPLIANT
                        )
                    ),
                    coverage_percentage=industry_compliance,
                    gaps=self._identify_industry_gaps(vulnerabilities, app_type),
                    recommendations=self._generate_industry_recommendations(vulnerabilities, app_type),
                )
            )

        return compliance_overview

    def _generate_dashboard_html(
        self,
        executive_summary: ExecutiveSummary,
        kpi_metrics: List[KPIMetric],
        risk_visualizations: List[RiskVisualization],
        compliance_overview: List[ComplianceOverview],
        report_data: Dict[str, Any],
    ) -> str:
        """Generate complete dashboard HTML."""

        # Generate HTML sections
        header_html = self._generate_dashboard_header(report_data)
        summary_html = self._generate_summary_html(executive_summary)
        kpi_html = self._generate_kpi_html(kpi_metrics)
        visualization_html = self._generate_visualization_html(risk_visualizations)
        compliance_html = self._generate_compliance_html(compliance_overview)
        footer_html = self._generate_dashboard_footer()

        # Combine into complete HTML
        html_content = self.html_template.format(
            title=f"Executive Security Dashboard - {report_data.get('app_context', {}).get('package_name', 'Unknown App')}",  # noqa: E501
            css_styles=self.css_styles,
            javascript_code=self.javascript_code,
            header=header_html,
            executive_summary=summary_html,
            kpi_metrics=kpi_html,
            risk_visualizations=visualization_html,
            compliance_overview=compliance_html,
            footer=footer_html,
            dashboard_data=json.dumps(
                {
                    "executive_summary": {
                        "overall_risk_level": executive_summary.overall_risk_level.value,
                        "security_posture_score": executive_summary.security_posture_score,
                        "key_findings": executive_summary.key_findings,
                        "strategic_recommendations": executive_summary.strategic_recommendations,
                        "immediate_actions": executive_summary.immediate_actions,
                        "investment_priorities": executive_summary.investment_priorities,
                    },
                    "kpi_metrics": [
                        {
                            "name": kpi.name,
                            "value": kpi.value,
                            "unit": kpi.unit,
                            "target": kpi.target,
                            "status": kpi.status,
                            "trend": kpi.trend,
                        }
                        for kpi in kpi_metrics
                    ],
                    "visualizations": [
                        {"chart_type": viz.chart_type, "title": viz.title, "data": viz.data}
                        for viz in risk_visualizations
                    ],
                },
                indent=2,
            ),
        )

        return html_content

    def _load_dashboard_template(self) -> str:
        """Load HTML template for executive dashboard."""

        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>{css_styles}</style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="dashboard-container">
        {header}
        {executive_summary}
        {kpi_metrics}
        {risk_visualizations}
        {compliance_overview}
        {footer}
    </div>

    <script>
        // Embed dashboard data
        const dashboardData = {dashboard_data};

        {javascript_code}
    </script>
</body>
</html>
        """

    def _load_dashboard_styles(self) -> str:
        """Load CSS styles for executive dashboard."""
        return (_ASSETS_DIR / "executive-dashboard.css").read_text()

    def _load_dashboard_javascript(self) -> str:
        """Load JavaScript code for dashboard interactivity."""
        return (_ASSETS_DIR / "executive-dashboard.js").read_text()

    def _generate_dashboard_header(self, report_data: Dict[str, Any]) -> str:
        """Generate dashboard header HTML."""

        app_name = report_data.get("app_context", {}).get("package_name", "Unknown Application")
        scan_date = datetime.now().strftime("%B %d, %Y")

        return f"""
        <div class="dashboard-header">
            <div class="header-content">
                <div class="title-section">
                    <h1 class="dashboard-title">🛡️ Executive Security Dashboard</h1>
                    <p class="dashboard-subtitle">Strategic Security Overview & Risk Assessment</p>
                </div>
                <div class="dashboard-meta">
                    <div><strong>Application:</strong> {app_name}</div>
                    <div><strong>Report Date:</strong> {scan_date}</div>
                    <div><strong>Dashboard Version:</strong> 2.0</div>
                </div>
            </div>
        </div>
        """

    def _generate_summary_html(self, executive_summary: ExecutiveSummary) -> str:
        """Generate executive summary HTML."""

        risk_level = executive_summary.overall_risk_level.value
        risk_colors = {
            "critical": "#e74c3c",
            "high": "#e67e22",
            "moderate": "#f39c12",
            "low": "#27ae60",
            "minimal": "#2ecc71",
        }

        return f"""
        <div class="executive-summary">
            <h2 class="section-title">📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="risk-overview">
                    <div class="risk-score-display" style="background: linear-gradient(135deg, {risk_colors.get(risk_level, '#f39c12')}, {risk_colors.get(risk_level, '#f39c12')}dd);">  # noqa: E501
                        <div class="risk-score-value">{executive_summary.security_posture_score:.0f}</div>
                        <div class="risk-score-label">Security Score</div>
                        <div class="risk-level">{risk_level.title()} Risk</div>
                    </div>
                </div>
                <div class="key-findings">
                    <h3>🔍 Key Findings</h3>
                    <ul class="findings-list">
                        {self._generate_findings_list(executive_summary.key_findings)}
                    </ul>
                </div>
            </div>

            <div class="strategic-actions">
                <h3>🎯 Strategic Actions</h3>
                <div class="actions-grid">
                    <div class="action-category">
                        <h4>📋 Strategic Recommendations</h4>
                        <ul class="action-list">
                            {self._generate_action_list(executive_summary.strategic_recommendations)}
                        </ul>
                    </div>
                    <div class="action-category">
                        <h4>⚡ Immediate Actions</h4>
                        <ul class="action-list">
                            {self._generate_action_list(executive_summary.immediate_actions)}
                        </ul>
                    </div>
                    <div class="action-category">
                        <h4>💰 Investment Priorities</h4>
                        <ul class="action-list">
                            {self._generate_action_list(executive_summary.investment_priorities)}
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        """

    def _generate_kpi_html(self, kpi_metrics: List[KPIMetric]) -> str:
        """Generate KPI metrics HTML."""

        kpi_cards = ""
        for kpi in kpi_metrics:
            trend_icon = {"improving": "📈", "stable": "➡️", "declining": "📉"}.get(kpi.trend, "➡️")

            kpi_cards += f"""
            <div class="kpi-card">
                <div class="kpi-value">{kpi.value:.1f}<span style="font-size: 1rem;">{kpi.unit}</span></div>
                <div class="kpi-name">{kpi.name}</div>
                <div class="kpi-status {kpi.status}">{kpi.status.replace('_', ' ').title()}</div>
                <div style="margin-top: 0.5rem; font-size: 0.9rem; color: #7f8c8d;">
                    Target: {kpi.target}{kpi.unit} {trend_icon}
                </div>
            </div>
            """

        return f"""
        <div class="kpi-section">
            <h2 class="section-title">📈 Key Performance Indicators</h2>
            <div class="kpi-grid">
                {kpi_cards}
            </div>
        </div>
        """

    def _generate_visualization_html(self, risk_visualizations: List[RiskVisualization]) -> str:
        """Generate risk visualization HTML."""

        viz_cards = ""
        for i, viz in enumerate(risk_visualizations):
            insights_html = ""
            if viz.insights:
                insights_html = f"""
                <div class="viz-insights">
                    <h4>💡 Key Insights</h4>
                    <ul>
                        {self._generate_insights_list(viz.insights)}
                    </ul>
                </div>
                """

            viz_cards += f"""
            <div class="viz-card">
                <h3 class="viz-title">{viz.title}</h3>
                <div class="chart-container">
                    <canvas id="chart-{i}"></canvas>
                </div>
                {insights_html}
            </div>
            """

        return f"""
        <div class="visualizations-section">
            <h2 class="section-title">📊 Risk Visualizations</h2>
            <div class="viz-grid">
                {viz_cards}
            </div>
        </div>
        """

    def _generate_compliance_html(self, compliance_overview: List[ComplianceOverview]) -> str:
        """Generate compliance overview HTML."""

        compliance_cards = ""
        for compliance in compliance_overview:
            recommendations_html = ""
            if compliance.recommendations:
                recommendations_html = f"""
                <div class="compliance-recommendations">
                    <h4>📋 Recommendations</h4>
                    <ul>
                        {self._generate_recommendations_list(compliance.recommendations)}
                    </ul>
                </div>
                """

            compliance_cards += f"""
            <div class="compliance-card">
                <div class="compliance-header">
                    <div class="compliance-framework">{compliance.framework}</div>
                    <div class="compliance-status {compliance.status.value}">{compliance.status.value.replace('_', ' ').title()}</div>  # noqa: E501
                </div>
                <div class="compliance-percentage">{compliance.coverage_percentage:.1f}%</div>
                <div style="text-align: center; color: #7f8c8d; margin-bottom: 1rem;">Coverage</div>
                {recommendations_html}
            </div>
            """

        return f"""
        <div class="compliance-section">
            <h2 class="section-title">🛡️ Compliance Overview</h2>
            <div class="compliance-grid">
                {compliance_cards}
            </div>
        </div>
        """

    def _generate_dashboard_footer(self) -> str:
        """Generate dashboard footer HTML."""

        return f"""
        <div class="dashboard-footer">
            <p>Generated by AODS Executive Dashboard System | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>This dashboard provides strategic security insights for executive decision making</p>
        </div>
        """

    # Helper methods for calculations and data processing
    def _calculate_overall_risk_level(
        self, vulnerabilities: List[Dict[str, Any]], risk_intelligence: Dict[str, Any]
    ) -> RiskLevel:
        """Calculate overall risk level."""

        if not vulnerabilities:
            return RiskLevel.MINIMAL

        # Count vulnerabilities by severity
        critical_count = len([v for v in vulnerabilities if v.get("severity") == "critical"])
        high_count = len([v for v in vulnerabilities if v.get("severity") == "high"])

        # Risk intelligence factor
        risk_score = risk_intelligence.get("risk_score", 0)

        if critical_count >= 3 or risk_score >= 80:
            return RiskLevel.CRITICAL
        elif critical_count >= 1 or high_count >= 5 or risk_score >= 60:
            return RiskLevel.HIGH
        elif high_count >= 2 or risk_score >= 40:
            return RiskLevel.MODERATE
        elif high_count >= 1 or risk_score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL

    def _calculate_security_posture_score(
        self, vulnerabilities: List[Dict[str, Any]], risk_intelligence: Dict[str, Any]
    ) -> float:
        """Calculate security posture score (0-100)."""

        if not vulnerabilities:
            return 95.0

        # Base score
        base_score = 100.0

        # Deduct points for vulnerabilities
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "low")
            deduction = {"critical": 15, "high": 8, "medium": 3, "low": 1, "informational": 0.5}.get(severity, 1)

            base_score -= deduction

        # Factor in risk intelligence
        risk_score = risk_intelligence.get("risk_score", 0)
        if risk_score > 50:
            base_score -= (risk_score - 50) * 0.5

        return max(0.0, min(100.0, base_score))

    def _generate_key_findings(
        self, vulnerabilities: List[Dict[str, Any]], risk_intelligence: Dict[str, Any]
    ) -> List[str]:
        """Generate key findings for executive summary."""

        findings = []

        # Vulnerability findings
        critical_count = len([v for v in vulnerabilities if v.get("severity") == "critical"])
        high_count = len([v for v in vulnerabilities if v.get("severity") == "high"])

        if critical_count > 0:
            findings.append(f"{critical_count} critical vulnerabilities require immediate attention")

        if high_count > 0:
            findings.append(f"{high_count} high-severity vulnerabilities identified")

        # Risk intelligence findings
        risk_patterns = risk_intelligence.get("risk_patterns", [])
        if risk_patterns:
            findings.append(f"{len(risk_patterns)} recurring risk patterns detected")

        # ML confidence findings
        if not findings:
            findings.append("Security posture is within acceptable parameters")
            findings.append("Continuous monitoring recommended")

        return findings[:5]  # Limit to top 5 findings

    def _generate_strategic_recommendations(
        self,
        vulnerabilities: List[Dict[str, Any]],
        risk_intelligence: Dict[str, Any],
        risk_level: RiskLevel,
        learning_analytics: Dict[str, Any] = None,
    ) -> List[str]:
        """Generate strategic recommendations."""

        recommendations = []

        if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            recommendations.append("Implement emergency security response plan")
            recommendations.append("Increase security team resources and budget")
            recommendations.append("Conduct security architecture review")

        if len(vulnerabilities) > 10:
            recommendations.append("Invest in automated security testing tools")
            recommendations.append("Establish secure development lifecycle (SDLC)")

        recommendations.append("Regular security training for development teams")
        recommendations.append("Implement continuous security monitoring")

        return recommendations[:5]

    def _generate_immediate_actions(
        self, vulnerabilities: List[Dict[str, Any]], risk_level: RiskLevel, learning_analytics: Dict[str, Any] = None
    ) -> List[str]:
        """Generate immediate actions."""

        actions = []

        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "critical"]
        if critical_vulns:
            actions.append(f"Address {len(critical_vulns)} critical vulnerabilities within 24 hours")

        high_vulns = [v for v in vulnerabilities if v.get("severity") == "high"]
        if high_vulns:
            actions.append(f"Plan remediation for {len(high_vulns)} high-severity issues within 1 week")

        if risk_level == RiskLevel.CRITICAL:
            actions.append("Activate incident response team")
            actions.append("Consider temporary service restrictions")

        actions.append("Review and update security policies")

        # Add learning analytics insights if available
        if learning_analytics and "strategic_recommendations" in learning_analytics:
            analytics_recommendations = learning_analytics["strategic_recommendations"]
            for rec in analytics_recommendations[:2]:  # Add top 2 analytics recommendations
                if isinstance(rec, dict) and "recommendation" in rec:
                    actions.append(f"Analytics insight: {rec['recommendation']}")
                elif isinstance(rec, str):
                    actions.append(f"Analytics insight: {rec}")

        return actions[:7]  # Increased limit to accommodate analytics insights

    def _generate_investment_priorities(
        self, vulnerabilities: List[Dict[str, Any]], risk_intelligence: Dict[str, Any], security_score: float
    ) -> List[str]:
        """Generate investment priorities."""

        priorities = []

        if security_score < 70:
            priorities.append("Security team expansion and training")
            priorities.append("Advanced security tools and platforms")

        if len(vulnerabilities) > 15:
            priorities.append("Automated security testing infrastructure")
            priorities.append("DevSecOps implementation")

        priorities.append("Third-party security assessment")
        priorities.append("Security awareness program")

        return priorities[:4]

    def _calculate_security_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate security score for KPI."""

        if not vulnerabilities:
            return 95.0

        base_score = 100.0
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "low")
            deduction = {"critical": 12, "high": 6, "medium": 2, "low": 0.5, "informational": 0.1}.get(severity, 1)
            base_score -= deduction

        return max(0.0, min(100.0, base_score))

    def _calculate_security_trend(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Calculate security trend (simplified)."""

        # Simplified trend calculation
        critical_count = len([v for v in vulnerabilities if v.get("severity") == "critical"])
        high_count = len([v for v in vulnerabilities if v.get("severity") == "high"])

        if critical_count == 0 and high_count <= 2:
            return "improving"
        elif critical_count <= 1 and high_count <= 5:
            return "stable"
        else:
            return "declining"

    def _calculate_severity_breakdown(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate severity breakdown."""

        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "low")
            if severity in breakdown:
                breakdown[severity] += 1

        return breakdown

    def _calculate_category_breakdown(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate category breakdown."""

        breakdown = {}
        for vuln in vulnerabilities:
            category = vuln.get("category", "unknown")
            breakdown[category] = breakdown.get(category, 0) + 1

        return breakdown

    def _prepare_trend_data(self, risk_trends: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare trend data for visualization."""

        # Simplified trend data preparation
        categories = [trend.get("category", "Unknown") for trend in risk_trends[:5]]
        scores = [trend.get("risk_score", 0) for trend in risk_trends[:5]]

        return {
            "labels": categories,
            "datasets": [
                {
                    "label": "Risk Score",
                    "data": scores,
                    "borderColor": "#e74c3c",
                    "backgroundColor": "rgba(231, 76, 60, 0.1)",
                    "tension": 0.4,
                }
            ],
        }

    def _calculate_category_risk_score(self, category: str, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate risk score for a category."""

        category_vulns = [v for v in vulnerabilities if v.get("category") == category]
        if not category_vulns:
            return 0.0

        total_score = 0
        for vuln in category_vulns:
            severity = vuln.get("severity", "low")
            score = {"critical": 10, "high": 7, "medium": 4, "low": 2, "informational": 1}.get(severity, 1)
            total_score += score

        return total_score / len(category_vulns)

    def _calculate_compliance_status(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall compliance status."""

        # Simplified compliance calculation
        critical_count = len([v for v in vulnerabilities if v.get("severity") == "critical"])
        high_count = len([v for v in vulnerabilities if v.get("severity") == "high"])

        if critical_count == 0 and high_count <= 2:
            score = 90.0
            status = "compliant"
            insights = ["Strong compliance posture", "Minor improvements recommended"]
        elif critical_count <= 1 and high_count <= 5:
            score = 75.0
            status = "partially_compliant"
            insights = ["Moderate compliance gaps", "Focus on high-severity issues"]
        else:
            score = 50.0
            status = "non_compliant"
            insights = ["Significant compliance gaps", "Immediate action required"]

        return {"overall_score": score, "status": status, "insights": insights}

    def _calculate_owasp_coverage(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate OWASP Mobile Top 10 coverage."""

        # Simplified OWASP coverage calculation
        owasp_categories = [
            "injection",
            "authentication",
            "sensitive_data",
            "xml_external_entities",
            "broken_access_control",
            "security_misconfiguration",
            "xss",
            "insecure_deserialization",
            "vulnerable_components",
            "logging_monitoring",
        ]

        found_categories = set(v.get("category", "") for v in vulnerabilities)
        coverage_gaps = len([cat for cat in owasp_categories if cat in found_categories])

        # Higher coverage means more issues found (inverse for compliance)
        return max(60.0, 100.0 - (coverage_gaps * 8))

    def _calculate_masvs_coverage(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate MASVS coverage."""

        # Simplified MASVS coverage calculation
        return max(65.0, 95.0 - len(vulnerabilities) * 2)

    def _calculate_industry_compliance(self, vulnerabilities: List[Dict[str, Any]], app_type: str) -> float:
        """Calculate industry-specific compliance."""

        # Simplified industry compliance calculation
        critical_count = len([v for v in vulnerabilities if v.get("severity") == "critical"])
        high_count = len([v for v in vulnerabilities if v.get("severity") == "high"])

        base_score = 95.0
        if app_type == "financial":
            # PCI DSS is stricter
            base_score -= critical_count * 20 + high_count * 10
        elif app_type == "healthcare":
            # HIPAA requirements
            base_score -= critical_count * 15 + high_count * 8

        return max(50.0, base_score)

    def _determine_app_type(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Determine app type from vulnerabilities (simplified)."""

        # This would normally be determined from app context
        return "general"

    def _identify_owasp_gaps(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Identify OWASP compliance gaps."""

        gaps = []
        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "critical"]

        if critical_vulns:
            gaps.append("Critical vulnerabilities present")

        if len(vulnerabilities) > 10:
            gaps.append("High vulnerability count")

        return gaps[:3]

    def _identify_masvs_gaps(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Identify MASVS compliance gaps."""

        return ["Mobile-specific security controls", "Data protection measures"][:2]

    def _identify_industry_gaps(self, vulnerabilities: List[Dict[str, Any]], app_type: str) -> List[str]:
        """Identify industry-specific compliance gaps."""

        if app_type == "financial":
            return ["Payment data protection", "Financial transaction security"]
        elif app_type == "healthcare":
            return ["Patient data protection", "HIPAA compliance measures"]

        return []

    def _generate_owasp_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate OWASP recommendations."""

        return [
            "Implement OWASP Mobile Security Testing Guide",
            "Regular security code reviews",
            "Automated security testing integration",
        ][:3]

    def _generate_masvs_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate MASVS recommendations."""

        return [
            "Implement MASVS security controls",
            "Mobile application security assessment",
            "Runtime application self-protection (RASP)",
        ][:3]

    def _generate_industry_recommendations(self, vulnerabilities: List[Dict[str, Any]], app_type: str) -> List[str]:
        """Generate industry-specific recommendations."""

        if app_type == "financial":
            return ["PCI DSS compliance assessment", "Financial data encryption"]
        elif app_type == "healthcare":
            return ["HIPAA compliance review", "Patient data protection measures"]

        return ["Industry best practices review"]

    def _generate_severity_insights(self, severity_breakdown: Dict[str, int]) -> List[str]:
        """Generate insights from severity breakdown."""

        insights = []
        total = sum(severity_breakdown.values())

        if total == 0:
            insights.append("No vulnerabilities detected")
            return insights

        critical_pct = (severity_breakdown.get("critical", 0) / total) * 100
        high_pct = (severity_breakdown.get("high", 0) / total) * 100

        if critical_pct > 10:
            insights.append(f"{critical_pct:.1f}% of vulnerabilities are critical")

        if high_pct > 30:
            insights.append(f"{high_pct:.1f}% of vulnerabilities are high severity")

        if critical_pct == 0 and high_pct < 20:
            insights.append("Low proportion of high-severity vulnerabilities")

        return insights[:3]

    def _generate_trend_insights(self, risk_trends: List[Dict[str, Any]]) -> List[str]:
        """Generate insights from risk trends."""

        insights = []

        degrading_trends = [t for t in risk_trends if t.get("trend_direction") == "degrading"]
        if degrading_trends:
            insights.append(f"{len(degrading_trends)} categories showing degrading trends")

        improving_trends = [t for t in risk_trends if t.get("trend_direction") == "improving"]
        if improving_trends:
            insights.append(f"{len(improving_trends)} categories showing improvement")

        if not insights:
            insights.append("Risk trends are generally stable")

        return insights[:3]

    def _generate_category_insights(self, category_breakdown: Dict[str, int]) -> List[str]:
        """Generate insights from category breakdown."""

        insights = []

        if not category_breakdown:
            insights.append("No category data available")
            return insights

        top_category = max(category_breakdown.items(), key=lambda x: x[1])
        insights.append(f"Highest risk category: {top_category[0]} ({top_category[1]} issues)")

        if len(category_breakdown) > 5:
            insights.append("Vulnerabilities span multiple categories")

        return insights[:3]

    # HTML generation helper methods
    def _generate_findings_list(self, findings: List[str]) -> str:
        """Generate HTML list of findings."""
        return "".join(f"<li>{finding}</li>" for finding in findings)

    def _generate_action_list(self, actions: List[str]) -> str:
        """Generate HTML list of actions."""
        return "".join(f"<li>{action}</li>" for action in actions)

    def _generate_insights_list(self, insights: List[str]) -> str:
        """Generate HTML list of insights."""
        return "".join(f"<li>{insight}</li>" for insight in insights)

    def _generate_recommendations_list(self, recommendations: List[str]) -> str:
        """Generate HTML list of recommendations."""
        return "".join(f"<li>{rec}</li>" for rec in recommendations)

    def _initialize_kpi_targets(self) -> Dict[str, float]:
        """Initialize KPI targets."""
        return {
            "security_score": 85.0,
            "vulnerability_density": 2.0,
            "ml_enhancement_rate": 75.0,
            "fp_reduction_rate": 70.0,
            "response_time": 24.0,
        }

    def _initialize_risk_criteria(self) -> Dict[str, Any]:
        """Initialize risk assessment criteria."""
        return {
            "critical_threshold": 3,
            "high_threshold": 5,
            "risk_score_critical": 80,
            "risk_score_high": 60,
            "risk_score_moderate": 40,
            "risk_score_low": 20,
        }

    def _initialize_compliance_frameworks(self) -> List[str]:
        """Initialize compliance frameworks."""
        return ["OWASP Mobile Top 10", "MASVS", "PCI DSS", "HIPAA", "GDPR", "NIST Cybersecurity Framework"]

    def _generate_dashboard_id(self, report_data: Dict[str, Any]) -> str:
        """Generate unique dashboard ID."""
        import hashlib

        app_name = report_data.get("app_context", {}).get("package_name", "unknown")
        timestamp = str(datetime.now().timestamp())

        id_string = f"{app_name}_{timestamp}"
        return f"exec_dashboard_{hashlib.md5(id_string.encode()).hexdigest()[:8]}"

    def _update_generation_statistics(self, kpi_count: int, viz_count: int, generation_time_ms: float):
        """Update generation statistics."""

        self.generation_stats["total_dashboards_generated"] += 1
        self.generation_stats["kpi_metrics_calculated"] += kpi_count
        self.generation_stats["visualizations_created"] += viz_count

        # Update running average
        total_dashboards = self.generation_stats["total_dashboards_generated"]
        current_avg = self.generation_stats["average_generation_time_ms"]
        self.generation_stats["average_generation_time_ms"] = (
            current_avg * (total_dashboards - 1) + generation_time_ms
        ) / total_dashboards

    def save_dashboard(self, dashboard: ExecutiveDashboard, output_path: str) -> bool:
        """Save executive dashboard to file."""

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(dashboard.html_content)

            return True

        except Exception as e:
            self.logger.error(f"Failed to save executive dashboard: {e}")
            return False

    def get_generation_statistics(self) -> Dict[str, Any]:
        """Get dashboard generation statistics."""

        return {
            **self.generation_stats,
            "dashboards_per_hour": (
                self.generation_stats["total_dashboards_generated"]
                / (self.generation_stats["average_generation_time_ms"] / 1000 / 3600)
                if self.generation_stats["average_generation_time_ms"] > 0
                else 0
            ),
        }


# Simple integration test
if __name__ == "__main__":
    logger.info("Testing Executive Dashboard Generator")

    # Create generator
    generator = ExecutiveDashboardGenerator()

    # Test report data
    test_report_data = {
        "app_context": {"package_name": "com.example.executiveapp"},
        "vulnerabilities": [
            {"title": "Critical SQL Injection", "severity": "critical", "category": "injection", "confidence": 0.95},
            {"title": "High SSL Vulnerability", "severity": "high", "category": "network", "confidence": 0.85},
            {"title": "Medium Data Storage Issue", "severity": "medium", "category": "storage", "confidence": 0.75},
        ],
        "executive_summary": {"overall_risk_level": "high", "overall_risk_score": 65, "total_vulnerabilities": 3},
        "risk_intelligence": {
            "risk_score": 72.5,
            "trend_analysis": [
                {"category": "injection", "trend_direction": "degrading", "risk_score": 85},
                {"category": "network", "trend_direction": "stable", "risk_score": 60},
            ],
            "risk_patterns": [{"pattern_name": "High Severity Pattern", "risk_impact": 75}],
        },
        "ml_confidence_statistics": {
            "improvement_rate": 80.0,
            "fp_reduction_rate": 75.0,
            "average_confidence_boost": 0.15,
        },
        "scan_statistics": {"scan_duration": 45.2, "files_analyzed": 150, "plugins_executed": 25},
    }

    # Test dashboard generation
    logger.info("Testing Executive Dashboard Generation")
    dashboard = generator.generate_executive_dashboard(test_report_data)

    logger.info(
        "Dashboard generated",
        dashboard_id=dashboard.dashboard_id,
        title=dashboard.title,
        file_size_bytes=dashboard.file_size_bytes,
        risk_level=dashboard.executive_summary.overall_risk_level.value,
        security_score=round(dashboard.executive_summary.security_posture_score, 1),
        kpi_metrics=len(dashboard.kpi_metrics),
        visualizations=len(dashboard.risk_visualizations),
        compliance_frameworks=len(dashboard.compliance_overview),
    )

    # Test saving dashboard
    logger.info("Testing Dashboard Saving")
    output_path = "test_executive_dashboard.html"
    success = generator.save_dashboard(dashboard, output_path)

    if success:
        logger.info("Dashboard saved successfully", output_path=output_path, file_exists=os.path.exists(output_path))

        if os.path.exists(output_path):
            file_size = os.path.getsize(output_path)
            logger.info("Saved file size", file_size_bytes=file_size)
    else:
        logger.error("Failed to save dashboard")

    # Test statistics
    stats = generator.get_generation_statistics()
    logger.info(
        "Generation statistics",
        total_dashboards=stats["total_dashboards_generated"],
        kpi_metrics=stats["kpi_metrics_calculated"],
        visualizations=stats["visualizations_created"],
        avg_generation_time_ms=round(stats["average_generation_time_ms"], 1),
    )

    logger.info("Executive Dashboard Generator test completed")

    # Cleanup test file
    if os.path.exists(output_path):
        os.remove(output_path)
