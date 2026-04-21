#!/usr/bin/env python3
"""
Interactive Report Generator - Simple & Practical
================================================

Provides interactive HTML report generation for AODS vulnerability analysis.
Focuses on user-friendly presentation, dynamic content, and enhanced usability.

Design Principles:
- Interactive HTML: Modern web-based reports with dynamic content
- Real-time filtering: Instant vulnerability filtering and sorting
- Drill-down analysis: Expandable sections for detailed analysis
- Export capabilities: Multiple formats (PDF, Excel, CSV)
- User experience: Intuitive navigation and professional presentation
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import csv

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

_ASSETS_DIR = Path(__file__).parent / "assets"


@dataclass
class InteractiveReportConfig:
    """Configuration for interactive report generation."""

    title: str = "AODS Security Analysis Report"
    theme: str = "professional"
    enable_filtering: bool = True
    enable_sorting: bool = True
    enable_export: bool = True
    show_code_snippets: bool = True
    show_remediation: bool = True
    show_risk_intelligence: bool = True
    max_vulnerabilities_per_page: int = 50


@dataclass
class InteractiveReport:
    """Interactive HTML report structure."""

    report_id: str
    title: str
    html_content: str
    css_styles: str
    javascript_code: str
    export_data: Dict[str, Any] = field(default_factory=dict)
    generation_time: str = field(default_factory=lambda: datetime.now().isoformat())
    file_size_bytes: int = 0


class InteractiveReportGenerator:
    """
    Advanced interactive HTML report generator for AODS vulnerability analysis.

    Features:
    - Interactive HTML reports with dynamic content
    - Real-time vulnerability filtering and sorting
    - Drill-down analysis with expandable sections
    - Multiple export formats (PDF, Excel, CSV)
    - Enhanced user experience and navigation
    """

    def __init__(self, config: Optional[InteractiveReportConfig] = None):
        """Initialize interactive report generator."""
        self.logger = logger

        # Configuration
        self.config = config or InteractiveReportConfig()

        # Report templates
        self.html_template = self._load_html_template()
        self.css_styles = self._load_css_styles()
        self.javascript_code = self._load_javascript_code()

        # Generation statistics
        self.generation_stats = {
            "total_reports_generated": 0,
            "total_vulnerabilities_processed": 0,
            "average_generation_time_ms": 0.0,
            "export_formats_generated": 0,
        }

        self.logger.info("Interactive Report Generator initialized")

    def generate_interactive_report(self, report_data: Dict[str, Any]) -> InteractiveReport:
        """
        Generate interactive HTML report from AODS report data.

        Args:
            report_data: Complete AODS report data with vulnerabilities and analysis

        Returns:
            InteractiveReport with HTML content and export capabilities
        """
        import time

        start_time = time.time()

        try:
            # Generate report ID
            report_id = self._generate_report_id(report_data)

            # Extract report components - map actual AODS report keys
            vulnerabilities = report_data.get("vulnerabilities", [])

            # Build executive summary from actual report data
            executive_summary = report_data.get("executive_summary") or {}
            if not executive_summary:
                sev_counts = {}
                for v in vulnerabilities:
                    s = (v.get("severity") or "MEDIUM").upper()
                    sev_counts[s] = sev_counts.get(s, 0) + 1
                # Derive risk level from highest severity
                if sev_counts.get("CRITICAL", 0) > 0:
                    risk_level = "critical"
                elif sev_counts.get("HIGH", 0) > 0:
                    risk_level = "high"
                elif sev_counts.get("MEDIUM", 0) > 0:
                    risk_level = "medium"
                else:
                    risk_level = "low"
                executive_summary = {
                    "overall_risk_level": risk_level,
                    "overall_risk_score": report_data.get("security_score", 0),
                    "total_vulnerabilities": len(vulnerabilities),
                    "severity_breakdown": sev_counts,
                }

            # Build scan statistics from execution_stats
            scan_statistics = report_data.get("scan_statistics") or {}
            if not scan_statistics:
                exec_stats = report_data.get("execution_stats") or {}
                scan_statistics = {
                    "scan_duration": exec_stats.get("scan_duration_seconds", report_data.get("execution_time", 0)),
                    "files_analyzed": exec_stats.get("files_analyzed", 0),
                    "plugins_executed": exec_stats.get("total_plugins") or exec_stats.get("successful_plugins", 0),
                }

            risk_intelligence = report_data.get("risk_intelligence", {})

            # Build ML stats from ml_filtering (actual keys from execution_parallel.py)
            ml_confidence_stats = report_data.get("ml_confidence_statistics") or {}
            if not ml_confidence_stats:
                ml_filt = report_data.get("ml_filtering") or {}
                original = ml_filt.get("original_count", 0)
                filtered = ml_filt.get("filtered_count", 0)
                ml_confidence_stats = {
                    "applied": ml_filt.get("applied", False),
                    "strategy": ml_filt.get("strategy", "none"),
                    "app_type": ml_filt.get("app_type", "unknown"),
                    "original_count": original,
                    "filtered_count": filtered,
                    "reduction_percentage": ml_filt.get("reduction_percentage", 0),
                    "false_positive_rate": ml_filt.get("false_positive_rate", 0),
                }

            # Generate HTML sections
            html_header = self._generate_html_header(report_data)
            html_executive_summary = self._generate_executive_summary_html(executive_summary)
            html_vulnerability_overview = self._generate_vulnerability_overview_html(vulnerabilities)
            html_vulnerability_details = self._generate_vulnerability_details_html(vulnerabilities)
            html_risk_intelligence = self._generate_risk_intelligence_html(risk_intelligence)
            html_scan_statistics = self._generate_scan_statistics_html(scan_statistics, ml_confidence_stats)
            html_footer = self._generate_html_footer()

            # Combine HTML content
            html_content = self.html_template.format(
                title=self.config.title,
                css_styles=self.css_styles,
                javascript_code=self.javascript_code,
                header=html_header,
                executive_summary=html_executive_summary,
                vulnerability_overview=html_vulnerability_overview,
                vulnerability_details=html_vulnerability_details,
                risk_intelligence=html_risk_intelligence,
                scan_statistics=html_scan_statistics,
                footer=html_footer,
                vulnerability_data=json.dumps(vulnerabilities, indent=2),
                report_data=json.dumps(
                    {
                        "executive_summary": executive_summary,
                        "scan_statistics": scan_statistics,
                        "risk_intelligence": risk_intelligence,
                        "ml_confidence_stats": ml_confidence_stats,
                    },
                    indent=2,
                ),
            )

            # Prepare export data
            export_data = self._prepare_export_data(report_data)

            # Calculate file size
            file_size = len(html_content.encode("utf-8"))

            # Create interactive report
            report = InteractiveReport(
                report_id=report_id,
                title=self.config.title,
                html_content=html_content,
                css_styles=self.css_styles,
                javascript_code=self.javascript_code,
                export_data=export_data,
                file_size_bytes=file_size,
            )

            # Update statistics
            generation_time = (time.time() - start_time) * 1000
            self._update_generation_statistics(len(vulnerabilities), generation_time)

            return report

        except Exception as e:
            self.logger.error(f"Interactive report generation failed: {e}")

            # Return minimal report on error
            return InteractiveReport(
                report_id=f"error_{datetime.now().timestamp()}",
                title="Error Report",
                html_content=f"<html><body><h1>Report Generation Error</h1><p>{str(e)}</p></body></html>",
                css_styles="",
                javascript_code="",
            )

    def _generate_html_header(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML header section."""

        apk_info = report_data.get("apk_info") or {}
        app_name = (
            apk_info.get("app_name")
            or apk_info.get("package_name")
            or report_data.get("app_context", {}).get("package_name")
            or "Unknown Application"
        )
        scan_date = datetime.now().strftime("%B %d, %Y at %I:%M %p")

        return f"""
        <div class="report-header">
            <div class="header-content">
                <div class="logo-section">
                    <h1 class="report-title">🛡️ AODS Security Analysis</h1>
                    <p class="report-subtitle">Automated OWASP Dynamic Security Scan</p>
                </div>
                <div class="app-info">
                    <h2 class="app-name">{app_name}</h2>
                    <p class="scan-date">Generated on {scan_date}</p>
                </div>
            </div>
            <div class="header-controls">
                <button class="btn btn-primary" onclick="exportToPDF()">📄 Export PDF</button>
                <button class="btn btn-secondary" onclick="exportToExcel()">📊 Export Excel</button>
                <button class="btn btn-tertiary" onclick="exportToCSV()">📋 Export CSV</button>
            </div>
        </div>
        """

    def _generate_executive_summary_html(self, executive_summary: Dict[str, Any]) -> str:
        """Generate executive summary HTML section."""

        if not executive_summary:
            return "<div class='section'><h2>Executive Summary</h2><p>No executive summary available.</p></div>"

        risk_level = executive_summary.get("overall_risk_level", "Unknown")
        risk_score = executive_summary.get("overall_risk_score", 0)
        total_vulns = executive_summary.get("total_vulnerabilities", 0)
        severity_breakdown = executive_summary.get("severity_breakdown", {})

        # Risk level styling
        risk_class = {
            "critical": "risk-critical",
            "high": "risk-high",
            "medium": "risk-medium",
            "low": "risk-low",
            "very_low": "risk-very-low",
        }.get(risk_level.lower(), "risk-medium")

        # Severity breakdown chart
        severity_chart = self._generate_severity_chart(severity_breakdown)

        return f"""
        <div class="section executive-summary">
            <h2 class="section-title">📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="risk-overview">
                    <div class="risk-score {risk_class}">
                        <div class="risk-value">{risk_score}</div>
                        <div class="risk-label">Risk Score</div>
                        <div class="risk-level">{risk_level.title()} Risk</div>
                    </div>
                </div>
                <div class="vulnerability-stats">
                    <div class="stat-item">
                        <div class="stat-value">{total_vulns}</div>
                        <div class="stat-label">Total Vulnerabilities</div>
                    </div>
                    {self._generate_severity_stats(severity_breakdown)}
                </div>
                <div class="severity-chart">
                    {severity_chart}
                </div>
            </div>
        </div>
        """

    def _generate_vulnerability_overview_html(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate vulnerability overview HTML section."""

        if not vulnerabilities:
            return "<div class='section'><h2>Vulnerabilities</h2><p>No vulnerabilities detected.</p></div>"

        # Filter controls
        filter_controls = self._generate_filter_controls(vulnerabilities)

        # Vulnerability summary table
        summary_table = self._generate_vulnerability_summary_table(vulnerabilities)

        return f"""
        <div class="section vulnerability-overview">
            <h2 class="section-title">🔍 Vulnerability Overview</h2>
            <div class="overview-content">
                {filter_controls}
                {summary_table}
            </div>
        </div>
        """

    def _generate_vulnerability_details_html(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate detailed vulnerability HTML section."""

        if not vulnerabilities:
            return ""

        details_html = """
        <div class="section vulnerability-details">
            <h2 class="section-title">🔬 Detailed Analysis</h2>
            <div class="vulnerability-list" id="vulnerabilityList">
        """

        for i, vuln in enumerate(vulnerabilities):
            details_html += self._generate_single_vulnerability_html(vuln, i)

        details_html += """
            </div>
        </div>
        """

        return details_html

    def _generate_single_vulnerability_html(self, vulnerability: Dict[str, Any], index: int) -> str:
        """Generate HTML for a single vulnerability."""

        title = vulnerability.get("title", "Unknown Vulnerability")
        severity = vulnerability.get("severity", "medium")
        category = vulnerability.get("category", "unknown")
        confidence = vulnerability.get("confidence", 0.5)
        confidence_level = vulnerability.get("confidence_level", "")
        if not confidence_level:
            if confidence >= 0.9:
                confidence_level = "HIGH"
            elif confidence >= 0.7:
                confidence_level = "MEDIUM"
            elif confidence >= 0.5:
                confidence_level = "LOW"
            else:
                confidence_level = "VERY_LOW"
        description = vulnerability.get("description", "No description available")
        cwe_id = vulnerability.get("cwe_id", "")
        file_path = vulnerability.get("file_path", "")
        line_number = vulnerability.get("line_number")
        references = vulnerability.get("references", [])

        # Build location string from file_path + line_number
        location = vulnerability.get("location", "")
        if not location and file_path:
            location = file_path
            if line_number:
                location += f":{line_number}"
        elif not location:
            location = "N/A"

        # ML confidence data
        ml_confidence = vulnerability.get("ml_confidence", {})

        # Code snippet
        code_snippet = self._extract_code_snippet(vulnerability)

        # Remediation guidance
        remediation = self._extract_remediation_guidance(vulnerability)

        # MITRE ATT&CK section
        mitre_html = self._generate_mitre_section_html(vulnerability)

        # Severity styling
        severity_class = f"severity-{severity.lower()}"

        # CWE badge
        cwe_badge = f'<span class="cwe-badge">{cwe_id}</span>' if cwe_id else ""

        # Verified badge - shown when verification agent confirmed the finding
        verified_badge = ""
        if vulnerability.get("verified") or vulnerability.get("dynamically_confirmed"):
            verified_badge = (
                '<span class="verified-badge" style="background:#27ae60;color:#fff;'
                'padding:2px 8px;border-radius:3px;font-size:0.8em;margin-left:6px;"'
                ' data-testid="verified-badge">'
                'Verified</span>'
            )

        # OWASP badge (extracted to avoid long template line)
        owasp_cat = vulnerability.get("owasp_category", "")
        owasp_html = (
            f'<div class="info-item"><strong>OWASP:</strong> {owasp_cat}</div>'
            if owasp_cat else ""
        )

        # References links
        refs_html = ""
        if references:
            refs_items = "".join(
                f'<li><a href="{self._escape_html(ref)}" target="_blank"'
                f' rel="noopener">{self._escape_html(ref)}</a></li>'
                for ref in references[:5]
            )
            refs_html = f"""
                    <div class="references-section">
                        <h4>References</h4>
                        <ul class="reference-list">{refs_items}</ul>
                    </div>"""

        return f"""
        <div class="vulnerability-item {severity_class}" data-severity="{severity}" data-category="{category}" data-title="{title}" data-confidence="{confidence:.4f}">
            <div class="vulnerability-header" onclick="toggleVulnerability({index})">
                <div class="vulnerability-title">
                    <span class="severity-badge {severity_class}">{severity.upper()}</span>
                    {cwe_badge}
                    {verified_badge}
                    <h3>{title}</h3>
                </div>
                <div class="vulnerability-meta">
                    <span class="confidence-score">Confidence: {confidence:.2f} ({confidence_level})</span>
                    <span class="toggle-icon">▼</span>
                </div>
            </div>
            <div class="vulnerability-content" id="vuln-content-{index}" style="display: none;">
                <div class="vulnerability-info">
                    <div class="info-grid">
                        <div class="info-item">
                            <strong>Category:</strong> {category}
                        </div>
                        <div class="info-item">
                            <strong>Location:</strong> {location}
                        </div>
                        <div class="info-item">
                            <strong>Confidence:</strong> {confidence:.2f} ({confidence_level})
                        </div>
                        {f'<div class="info-item"><strong>CWE:</strong> {cwe_id}</div>' if cwe_id else ''}
                        {owasp_html}
                    </div>
                    <div class="description">
                        <h4>Description</h4>
                        <p>{description}</p>
                    </div>
                    {self._generate_ml_confidence_html(ml_confidence)}
                    {self._generate_evidence_collection_html(vulnerability, index)}
                    {code_snippet}
                    {remediation}
                    {mitre_html}
                    {refs_html}
                    {self._generate_risk_intelligence_section_html(vulnerability)}
                </div>
            </div>
        </div>
        """

    def _generate_risk_intelligence_html(self, risk_intelligence: Dict[str, Any]) -> str:
        """Generate risk intelligence HTML section."""

        if not risk_intelligence:
            return ""

        risk_score = risk_intelligence.get("risk_score", 0)
        risk_level = risk_intelligence.get("overall_risk_level", "medium")
        trends = risk_intelligence.get("trend_analysis", [])
        patterns = risk_intelligence.get("risk_patterns", [])
        threats = risk_intelligence.get("threat_intelligence", [])

        return f"""
        <div class="section risk-intelligence">
            <h2 class="section-title">📈 Risk Intelligence</h2>
            <div class="risk-content">
                <div class="risk-overview">
                    <div class="risk-score-display">
                        <div class="score-value">{risk_score:.1f}</div>
                        <div class="score-label">Risk Score</div>
                        <div class="score-level">{risk_level.title()}</div>
                    </div>
                </div>
                {self._generate_trends_html(trends)}
                {self._generate_patterns_html(patterns)}
                {self._generate_threats_html(threats)}
            </div>
        </div>
        """

    def _generate_evidence_collection_html(self, vulnerability: Dict[str, Any], index: int) -> str:
        """Generate evidence collection drill-down HTML."""

        evidence_collection = vulnerability.get("evidence_collection")
        if not evidence_collection:
            return ""

        evidence_items = evidence_collection.get("evidence_items", [])
        total_items = evidence_collection.get("total_evidence_items", len(evidence_items))

        if not evidence_items:
            return ""

        evidence_html = f"""
        <div class="evidence-section">
            <div class="evidence-header" onclick="toggleEvidence({index})">
                <h4>🔍 Evidence Collection ({total_items} items)</h4>
                <span class="toggle-btn" id="evidence-toggle-{index}">▼</span>
            </div>
            <div class="evidence-content" id="evidence-content-{index}" style="display: none;">
                <div class="evidence-summary">
                    <p>Full evidence collected to support this vulnerability finding.</p>
                </div>
                <div class="evidence-items">
        """

        for i, evidence_item in enumerate(evidence_items):
            evidence_type = evidence_item.get("evidence_type", "unknown")
            title = evidence_item.get("title", "Evidence Item")
            description = evidence_item.get("description", "No description available")
            data = evidence_item.get("data", {})

            # Evidence type icon mapping
            type_icons = {
                "code_snippet": "💻",
                "network_traffic": "🌐",
                "file_system": "📁",
                "binary_analysis": "🔧",
                "configuration": "⚙️",
                "log_entry": "📝",
                "metadata": "📊",
                "screenshot": "📸",
            }

            icon = type_icons.get(evidence_type, "📋")

            evidence_html += f"""
                <div class="evidence-item" onclick="toggleEvidenceItem({index}, {i})">
                    <div class="evidence-item-header">
                        <span class="evidence-icon">{icon}</span>
                        <span class="evidence-title">{title}</span>
                        <span class="evidence-type">{evidence_type}</span>
                        <span class="evidence-toggle" id="evidence-item-toggle-{index}-{i}">▶</span>
                    </div>
                    <div class="evidence-item-content" id="evidence-item-content-{index}-{i}" style="display: none;">
                        <p class="evidence-description">{description}</p>
                        {self._format_evidence_data(evidence_type, data)}
                    </div>
                </div>
            """

        evidence_html += """
                </div>
            </div>
        </div>
        """

        return evidence_html

    def _generate_mitre_section_html(self, vulnerability: Dict[str, Any]) -> str:
        """Generate MITRE ATT&CK section from threat_analysis data."""

        threat_analysis = vulnerability.get("threat_analysis")
        if not threat_analysis or not isinstance(threat_analysis, dict):
            # Fallback: show flat mitre_techniques list if available
            techniques = vulnerability.get("mitre_techniques", [])
            tactics = vulnerability.get("mitre_tactics", [])
            if not techniques and not tactics:
                return ""
            items = "".join(f"<li>{self._escape_html(t)}</li>" for t in techniques)
            tactic_str = ", ".join(tactics) if tactics else "N/A"
            return f"""
                    <div class="mitre-section">
                        <h4>MITRE ATT&CK</h4>
                        <p><strong>Tactics:</strong> {self._escape_html(tactic_str)}</p>
                        <ul>{items}</ul>
                    </div>"""

        mitre_techniques = threat_analysis.get("mitre_techniques", [])
        if not mitre_techniques:
            return ""

        rows = ""
        for tech in mitre_techniques[:5]:
            tid = tech.get("technique_id", "")
            name = tech.get("name", "")
            tactic = tech.get("tactic", "")
            desc = tech.get("description", "")
            mitigations = tech.get("mitigations", [])
            mit_str = ", ".join(mitigations[:3]) if mitigations else "N/A"
            rows += f"""
                        <tr>
                            <td><strong>{self._escape_html(tid)}</strong></td>
                            <td>{self._escape_html(name)}</td>
                            <td>{self._escape_html(tactic)}</td>
                            <td title="{self._escape_html(desc)}">{self._escape_html(desc[:120])}</td>
                            <td>{self._escape_html(mit_str)}</td>
                        </tr>"""

        risk_score = threat_analysis.get("risk_score", 0)
        exploit_score = threat_analysis.get("exploitability_score", 0)

        return f"""
                    <div class="mitre-section">
                        <h4>MITRE ATT&CK Analysis</h4>
                        <div class="mitre-scores">
                            <span><strong>Risk Score:</strong> {risk_score:.2f}</span>
                            <span><strong>Exploitability:</strong> {exploit_score:.2f}</span>
                        </div>
                        <table class="mitre-table">
                            <thead>
                                <tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Description</th><th>Mitigations</th></tr>
                            </thead>
                            <tbody>{rows}</tbody>
                        </table>
                    </div>"""

    def _generate_risk_intelligence_section_html(self, vulnerability: Dict[str, Any]) -> str:
        """Generate risk intelligence section for individual vulnerability."""

        risk_intelligence = vulnerability.get("risk_intelligence")
        if not risk_intelligence:
            return ""

        exploitability = risk_intelligence.get("exploitability", "unknown")
        impact = risk_intelligence.get("impact", "unknown")
        likelihood = risk_intelligence.get("likelihood", "unknown")
        business_impact = risk_intelligence.get("business_impact", "Not specified")
        technical_impact = risk_intelligence.get("technical_impact", "Not specified")

        return f"""
        <div class="risk-intelligence-section">
            <div class="risk-header" onclick="toggleRiskIntelligence({vulnerability.get('id', 'unknown')})">
                <h4>📈 Risk Intelligence</h4>
                <span class="toggle-btn" id="risk-toggle-{vulnerability.get('id', 'unknown')}">▼</span>
            </div>
            <div class="risk-content" id="risk-content-{vulnerability.get('id', 'unknown')}" style="display: none;">
                <div class="risk-metrics">
                    <div class="risk-metric">
                        <strong>Exploitability:</strong>
                        <span class="risk-level risk-{exploitability.lower()}">{exploitability.title()}</span>
                    </div>
                    <div class="risk-metric">
                        <strong>Impact:</strong>
                        <span class="risk-level risk-{impact.lower()}">{impact.title()}</span>
                    </div>
                    <div class="risk-metric">
                        <strong>Likelihood:</strong>
                        <span class="risk-level risk-{likelihood.lower()}">{likelihood.title()}</span>
                    </div>
                </div>
                <div class="impact-analysis">
                    <div class="impact-item">
                        <h5>Business Impact</h5>
                        <p>{business_impact}</p>
                    </div>
                    <div class="impact-item">
                        <h5>Technical Impact</h5>
                        <p>{technical_impact}</p>
                    </div>
                </div>
            </div>
        </div>
        """

    def _format_evidence_data(self, evidence_type: str, data: Dict[str, Any]) -> str:
        """Format evidence data based on type."""

        if evidence_type == "code_snippet":
            file_path = data.get("file_path", "Unknown file")
            line_number = data.get("line_number", 0)
            vulnerable_line = data.get("vulnerable_line", "")

            return f"""
            <div class="evidence-data code-evidence">
                <div class="code-info">
                    <strong>File:</strong> {file_path}<br>
                    <strong>Line:</strong> {line_number}
                </div>
                <div class="code-snippet">
                    <pre><code>{vulnerable_line}</code></pre>
                </div>
            </div>
            """

        elif evidence_type == "network_traffic":
            protocol = data.get("protocol", "Unknown")
            endpoints = data.get("endpoints", [])

            return f"""
            <div class="evidence-data network-evidence">
                <div class="network-info">
                    <strong>Protocol:</strong> {protocol}<br>
                    <strong>Endpoints:</strong> {', '.join(endpoints) if endpoints else 'None specified'}
                </div>
            </div>
            """

        elif evidence_type == "file_system":
            storage_location = data.get("storage_location", "Unknown")
            affected_files = data.get("affected_files", [])

            return f"""
            <div class="evidence-data filesystem-evidence">
                <div class="filesystem-info">
                    <strong>Storage Location:</strong> {storage_location}<br>
                    <strong>Affected Files:</strong> {len(affected_files)} files
                </div>
            </div>
            """

        elif evidence_type == "configuration":
            config_entries = data.get("config_entries", 0)
            permissions = data.get("permissions", 0)

            return f"""
            <div class="evidence-data config-evidence">
                <div class="config-info">
                    <strong>Configuration Entries:</strong> {config_entries}<br>
                    <strong>Permissions:</strong> {permissions}
                </div>
            </div>
            """

        elif evidence_type == "log_entry":
            log_level = data.get("log_level", "Unknown")
            entry_count = data.get("entry_count", 0)

            return f"""
            <div class="evidence-data log-evidence">
                <div class="log-info">
                    <strong>Log Level:</strong> {log_level}<br>
                    <strong>Entries:</strong> {entry_count}
                </div>
            </div>
            """

        else:
            # Generic data display
            data_items = []
            for key, value in data.items():
                if isinstance(value, (str, int, float, bool)):
                    data_items.append(f"<strong>{key.replace('_', ' ').title()}:</strong> {value}")

            return f"""
            <div class="evidence-data generic-evidence">
                <div class="generic-info">
                    {'<br>'.join(data_items)}
                </div>
            </div>
            """

    def _generate_scan_statistics_html(self, scan_stats: Dict[str, Any], ml_stats: Dict[str, Any]) -> str:
        """Generate scan statistics HTML section."""
        ml_strategy = str(ml_stats.get('strategy', 'none')).replace('_', ' ').title()

        return f"""
        <div class="section scan-statistics">
            <h2 class="section-title">📊 Scan Statistics</h2>
            <div class="stats-grid">
                <div class="stat-group">
                    <h3>Scan Performance</h3>
                    <div class="stat-item">
                        <span class="stat-label">Duration:</span>
                        <span class="stat-value">{scan_stats.get('scan_duration', 0):.1f}s</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Files Analyzed:</span>
                        <span class="stat-value">{scan_stats.get('files_analyzed', 0)}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Plugins Executed:</span>
                        <span class="stat-value">{scan_stats.get('plugins_executed', 0)}</span>
                    </div>
                </div>
                <div class="stat-group">
                    <h3>ML Filtering</h3>
                    <div class="stat-item">
                        <span class="stat-label">Strategy:</span>
                        <span class="stat-value">{ml_strategy}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Findings Analyzed:</span>
                        <span class="stat-value">{ml_stats.get('original_count', 0)}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">After Filtering:</span>
                        <span class="stat-value">{ml_stats.get('filtered_count', 0)}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">FP Reduction:</span>
                        <span class="stat-value">{ml_stats.get('reduction_percentage', 0):.1f}%</span>
                    </div>
                </div>
            </div>
        </div>
        """

    def _generate_html_footer(self) -> str:
        """Generate HTML footer section."""

        return f"""
        <div class="report-footer">
            <div class="footer-content">
                <p>Generated by AODS (Automated OWASP Dynamic Security Scanner)</p>
                <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>
        """

    def _load_html_template(self) -> str:
        """Load HTML template for interactive reports."""

        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>{css_styles}</style>
</head>
<body>
    <div class="report-container">
        {header}
        {executive_summary}
        {vulnerability_overview}
        {vulnerability_details}
        {risk_intelligence}
        {scan_statistics}
        {footer}
    </div>

    <script>
        // Embed vulnerability data
        const vulnerabilityData = {vulnerability_data};
        const reportData = {report_data};

        {javascript_code}
    </script>
</body>
</html>
        """

    def _load_css_styles(self) -> str:
        """Load CSS styles for interactive reports."""
        return (_ASSETS_DIR / "interactive-report.css").read_text()

    def _load_javascript_code(self) -> str:
        """Load JavaScript code for interactive functionality."""
        return (_ASSETS_DIR / "interactive-report.js").read_text()

    def _generate_severity_chart(self, severity_breakdown: Dict[str, int]) -> str:
        """Generate severity breakdown chart."""

        if not severity_breakdown:
            return "<div class='chart-placeholder'>No data available</div>"

        total = sum(severity_breakdown.values())
        if total == 0:
            return "<div class='chart-placeholder'>No vulnerabilities</div>"

        chart_html = "<div class='severity-chart-container'>"

        for severity, count in severity_breakdown.items():
            percentage = (count / total) * 100
            chart_html += f"""
            <div class='chart-bar'>
                <div class='bar-label'>{severity.title()}</div>
                <div class='bar-container'>
                    <div class='bar-fill severity-{severity}' style='width: {percentage}%'></div>
                    <div class='bar-value'>{count}</div>
                </div>
            </div>
            """

        chart_html += "</div>"
        return chart_html

    def _generate_severity_stats(self, severity_breakdown: Dict[str, int]) -> str:
        """Generate severity statistics HTML."""

        stats_html = ""
        for severity, count in severity_breakdown.items():
            stats_html += f"""
            <div class="stat-item">
                <div class="stat-value severity-{severity}">{count}</div>
                <div class="stat-label">{severity.title()}</div>
            </div>
            """

        return stats_html

    def _generate_filter_controls(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate filter controls HTML."""

        # Extract unique values for filters
        severities = sorted(set(v.get("severity", "unknown") for v in vulnerabilities))
        categories = sorted(set(v.get("category", "unknown") for v in vulnerabilities))

        return f"""
        <div class="filter-controls">
            <div class="filter-row">
                <div class="filter-group">
                    <label for="severityFilter">Severity:</label>
                    <select id="severityFilter" class="filter-select">
                        <option value="all">All Severities</option>
                        {self._generate_filter_options(severities)}
                    </select>
                </div>
                <div class="filter-group">
                    <label for="categoryFilter">Category:</label>
                    <select id="categoryFilter" class="filter-select">
                        <option value="all">All Categories</option>
                        {self._generate_filter_options(categories)}
                    </select>
                </div>
                <div class="filter-group">
                    <label for="searchFilter">Search:</label>
                    <input type="text" id="searchFilter" class="filter-input" placeholder="Search vulnerabilities...">
                </div>
                <div class="filter-group">
                    <button class="btn btn-secondary" onclick="expandAll()">Expand All</button>
                    <button class="btn btn-tertiary" onclick="collapseAll()">Collapse All</button>
                </div>
            </div>
            <div class="filter-summary">
                <span id="vulnerabilityCount">{len(vulnerabilities)} vulnerabilities</span>
            </div>
        </div>
        """

    def _generate_filter_options(self, values: List[str]) -> str:
        """Generate filter option HTML."""

        return "".join(f'<option value="{value}">{value.title()}</option>' for value in values)

    def _generate_vulnerability_summary_table(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate vulnerability summary table."""

        return """
        <div class="summary-table">
            <div class="table-header">
                <div class="table-controls">
                    <button class="sort-btn" data-field="severity">Sort by Severity</button>
                    <button class="sort-btn" data-field="confidence">Sort by Confidence</button>
                    <button class="sort-btn" data-field="title">Sort by Title</button>
                </div>
            </div>
        </div>
        """

    def _extract_code_snippet(self, vulnerability: Dict[str, Any]) -> str:
        """Extract and format code snippet from vulnerability."""

        code_snippet = vulnerability.get("code_snippet")
        if not code_snippet:
            return ""

        # Handle different code snippet formats
        if isinstance(code_snippet, dict):
            code = code_snippet.get("vulnerable_line", "") or code_snippet.get("code", "")
            language = code_snippet.get("language", "text")
        else:
            code = str(code_snippet)
            language = "text"

        if not code:
            return ""

        return f"""
        <div class="code-snippet">
            <h4>Code Snippet ({language})</h4>
            <pre><code>{self._escape_html(code)}</code></pre>
        </div>
        """

    def _extract_remediation_guidance(self, vulnerability: Dict[str, Any]) -> str:
        """Extract and format remediation guidance."""

        # Try structured remediation_guidance first, then flat recommendation field
        remediation = vulnerability.get("remediation_guidance")
        recommendation = vulnerability.get("recommendation", "")

        if not remediation and not recommendation:
            return ""

        if isinstance(remediation, dict):
            summary = remediation.get("fix_summary", "") or recommendation
            steps = remediation.get("remediation_steps", [])
        elif remediation:
            summary = str(remediation)
            steps = []
        else:
            summary = recommendation
            steps = []

        # Also pull recommendations from threat_analysis if available
        threat_recs = []
        threat_analysis = vulnerability.get("threat_analysis", {})
        if isinstance(threat_analysis, dict):
            threat_recs = threat_analysis.get("recommendations", [])

        html = f"""
        <div class="remediation-guidance">
            <h4>Remediation Guidance</h4>
            <p>{self._escape_html(summary)}</p>
        """

        if steps:
            html += "<ol class='remediation-steps'>"
            for step in steps[:5]:
                if isinstance(step, dict):
                    title = step.get("title", "")
                    description = step.get("description", "")
                    html += f"<li><strong>{self._escape_html(title)}</strong>: {self._escape_html(description)}</li>"
                else:
                    html += f"<li>{self._escape_html(str(step))}</li>"
            html += "</ol>"

        if threat_recs and not steps:
            html += "<h5>Recommended Mitigations</h5><ul>"
            for rec in threat_recs[:5]:
                html += f"<li>{self._escape_html(str(rec))}</li>"
            html += "</ul>"

        html += "</div>"
        return html

    def _generate_ml_confidence_html(self, ml_confidence: Dict[str, Any]) -> str:
        """Generate ML confidence information HTML."""

        if not ml_confidence:
            return ""

        original = ml_confidence.get("original_confidence", 0)
        adjusted = ml_confidence.get("adjusted_confidence", 0)
        level = ml_confidence.get("confidence_level", "medium")
        fp_prob = ml_confidence.get("false_positive_probability", 0)

        explanation = ml_confidence.get("explanation", {})
        reasoning = explanation.get("model_reasoning", "")

        return f"""
        <div class="ml-confidence">
            <h4>🤖 ML Confidence Analysis</h4>
            <div class="confidence-grid">
                <div class="confidence-item">
                    <strong>Original:</strong> {original:.3f}
                </div>
                <div class="confidence-item">
                    <strong>ML Enhanced:</strong> {adjusted:.3f}
                </div>
                <div class="confidence-item">
                    <strong>Level:</strong> {level.title()}
                </div>
                <div class="confidence-item">
                    <strong>FP Risk:</strong> {fp_prob:.3f}
                </div>
            </div>
            {f'<p><strong>Reasoning:</strong> {reasoning}</p>' if reasoning else ''}
        </div>
        """

    def _generate_trends_html(self, trends: List[Dict[str, Any]]) -> str:
        """Generate trends analysis HTML."""

        if not trends:
            return ""

        html = """
        <div class="trends-section">
            <h3>📈 Vulnerability Trends</h3>
            <div class="trends-grid">
        """

        for trend in trends[:5]:  # Show top 5 trends
            category = trend.get("category", "Unknown")
            direction = trend.get("trend_direction", "stable")
            confidence = trend.get("trend_confidence", 0)

            direction_icon = {"improving": "📈", "stable": "➡️", "degrading": "📉", "critical": "🚨"}.get(
                direction, "➡️"
            )

            html += f"""
            <div class="trend-item">
                <div class="trend-header">
                    <span class="trend-icon">{direction_icon}</span>
                    <span class="trend-category">{category}</span>
                </div>
                <div class="trend-details">
                    <div>Direction: {direction.title()}</div>
                    <div>Confidence: {confidence:.2f}</div>
                </div>
            </div>
            """

        html += """
            </div>
        </div>
        """

        return html

    def _generate_patterns_html(self, patterns: List[Dict[str, Any]]) -> str:
        """Generate risk patterns HTML."""

        if not patterns:
            return ""

        html = """
        <div class="patterns-section">
            <h3>🔍 Risk Patterns</h3>
            <div class="patterns-list">
        """

        for pattern in patterns:
            name = pattern.get("pattern_name", "Unknown Pattern")
            description = pattern.get("description", "")
            impact = pattern.get("risk_impact", 0)

            html += f"""
            <div class="pattern-item">
                <h4>{name}</h4>
                <p>{description}</p>
                <div class="pattern-impact">Risk Impact: {impact:.1f}</div>
            </div>
            """

        html += """
            </div>
        </div>
        """

        return html

    def _generate_threats_html(self, threats: List[Dict[str, Any]]) -> str:
        """Generate threat intelligence HTML."""

        if not threats:
            return ""

        html = """
        <div class="threats-section">
            <h3>🚨 Threat Intelligence</h3>
            <div class="threats-list">
        """

        for threat in threats[:3]:  # Show top 3 threats
            name = threat.get("threat_name", "Unknown Threat")
            severity = threat.get("severity", "medium")
            description = threat.get("description", "")

            html += f"""
            <div class="threat-item">
                <div class="threat-header">
                    <h4>{name}</h4>
                    <span class="severity-badge severity-{severity}">{severity.upper()}</span>
                </div>
                <p>{description}</p>
            </div>
            """

        html += """
            </div>
        </div>
        """

        return html

    def _prepare_export_data(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for export in various formats."""

        vulnerabilities = report_data.get("vulnerabilities", [])

        # Prepare CSV data
        csv_data = []
        for vuln in vulnerabilities:
            csv_data.append(
                {
                    "Title": vuln.get("title", ""),
                    "Severity": vuln.get("severity", ""),
                    "Category": vuln.get("category", ""),
                    "Confidence": vuln.get("confidence", ""),
                    "Location": vuln.get("location", ""),
                    "Description": vuln.get("description", ""),
                    "ML_Confidence": vuln.get("ml_confidence", {}).get("adjusted_confidence", ""),
                    "FP_Probability": vuln.get("ml_confidence", {}).get("false_positive_probability", ""),
                }
            )

        return {
            "csv_data": csv_data,
            "json_data": report_data,
            "summary_stats": {
                "total_vulnerabilities": len(vulnerabilities),
                "severity_breakdown": self._calculate_severity_breakdown(vulnerabilities),
                "category_breakdown": self._calculate_category_breakdown(vulnerabilities),
            },
        }

    def _calculate_severity_breakdown(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate severity breakdown."""

        breakdown = {}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown")
            breakdown[severity] = breakdown.get(severity, 0) + 1

        return breakdown

    def _calculate_category_breakdown(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate category breakdown."""

        breakdown = {}
        for vuln in vulnerabilities:
            category = vuln.get("category", "unknown")
            breakdown[category] = breakdown.get(category, 0) + 1

        return breakdown

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""

        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )

    def _generate_report_id(self, report_data: Dict[str, Any]) -> str:
        """Generate unique report ID."""

        import hashlib

        app_name = report_data.get("app_context", {}).get("package_name", "unknown")
        timestamp = str(datetime.now().timestamp())

        id_string = f"{app_name}_{timestamp}"
        return f"interactive_{hashlib.md5(id_string.encode()).hexdigest()[:8]}"

    def _update_generation_statistics(self, vulnerability_count: int, generation_time_ms: float):
        """Update generation statistics."""

        self.generation_stats["total_reports_generated"] += 1
        self.generation_stats["total_vulnerabilities_processed"] += vulnerability_count

        # Update running average
        total_reports = self.generation_stats["total_reports_generated"]
        current_avg = self.generation_stats["average_generation_time_ms"]
        self.generation_stats["average_generation_time_ms"] = (
            current_avg * (total_reports - 1) + generation_time_ms
        ) / total_reports

    def save_report(self, report: InteractiveReport, output_path: str) -> bool:
        """Save interactive report to file."""

        try:
            # HTML content is already complete with CSS and JavaScript
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report.html_content)

            return True

        except Exception as e:
            self.logger.error(f"Failed to save interactive report: {e}")
            return False

    def export_csv(self, report: InteractiveReport, output_path: str) -> bool:
        """Export report data as CSV."""

        try:
            csv_data = report.export_data.get("csv_data", [])

            if not csv_data:
                return False

            with open(output_path, "w", newline="", encoding="utf-8") as f:
                if csv_data:
                    writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
                    writer.writeheader()
                    writer.writerows(csv_data)

            return True

        except Exception as e:
            self.logger.error(f"Failed to export CSV: {e}")
            return False

    def get_generation_statistics(self) -> Dict[str, Any]:
        """Get report generation statistics."""

        return {
            **self.generation_stats,
            "reports_per_hour": (
                self.generation_stats["total_reports_generated"]
                / (self.generation_stats["average_generation_time_ms"] / 1000 / 3600)
                if self.generation_stats["average_generation_time_ms"] > 0
                else 0
            ),
        }


# Simple integration test
if __name__ == "__main__":
    logger.info("Testing Interactive Report Generator")

    # Create generator
    config = InteractiveReportConfig(
        title="AODS Security Analysis Report",
        theme="professional",
        enable_filtering=True,
        enable_sorting=True,
        enable_export=True,
    )

    generator = InteractiveReportGenerator(config)

    # Test report data
    test_report_data = {
        "app_context": {"package_name": "com.example.testapp"},
        "vulnerabilities": [
            {
                "title": "SQL Injection in Login Form",
                "severity": "critical",
                "category": "injection",
                "confidence": 0.95,
                "location": "LoginActivity.java:67",
                "description": "User input directly concatenated into SQL query",
                "ml_confidence": {
                    "original_confidence": 0.7,
                    "adjusted_confidence": 0.95,
                    "confidence_level": "very_high",
                    "false_positive_probability": 0.02,
                    "explanation": {"model_reasoning": "High confidence due to strong pattern matching"},
                },
            },
            {
                "title": "Weak SSL Configuration",
                "severity": "high",
                "category": "network",
                "confidence": 0.85,
                "location": "NetworkManager.java:134",
                "description": "SSL certificate validation disabled",
                "ml_confidence": {
                    "original_confidence": 0.6,
                    "adjusted_confidence": 0.85,
                    "confidence_level": "high",
                    "false_positive_probability": 0.08,
                },
            },
        ],
        "executive_summary": {
            "overall_risk_level": "high",
            "overall_risk_score": 75,
            "total_vulnerabilities": 2,
            "severity_breakdown": {"critical": 1, "high": 1},
        },
        "scan_statistics": {"scan_duration": 45.2, "files_analyzed": 150, "plugins_executed": 25},
        "ml_confidence_statistics": {
            "improvement_rate": 80.0,
            "fp_reduction_rate": 75.0,
            "average_confidence_boost": 0.2,
        },
    }

    # Test interactive report generation
    logger.info("Testing Interactive Report Generation")
    report = generator.generate_interactive_report(test_report_data)

    logger.info(
        "Report generated",
        report_id=report.report_id,
        title=report.title,
        file_size_bytes=report.file_size_bytes,
        generation_time=report.generation_time,
    )

    # Test saving report
    logger.info("Testing Report Saving")
    output_path = "test_interactive_report.html"
    success = generator.save_report(report, output_path)

    if success:
        logger.info("Report saved successfully", output_path=output_path, file_exists=os.path.exists(output_path))

        # Check file size
        if os.path.exists(output_path):
            file_size = os.path.getsize(output_path)
            logger.info("Saved file size", file_size_bytes=file_size)
    else:
        logger.error("Failed to save report")

    # Test CSV export
    logger.info("Testing CSV Export")
    csv_path = "test_vulnerabilities.csv"
    csv_success = generator.export_csv(report, csv_path)

    if csv_success:
        logger.info("CSV exported successfully", csv_path=csv_path, file_exists=os.path.exists(csv_path))
    else:
        logger.error("Failed to export CSV")

    # Test statistics
    stats = generator.get_generation_statistics()
    logger.info(
        "Generation statistics",
        total_reports=stats["total_reports_generated"],
        total_vulnerabilities=stats["total_vulnerabilities_processed"],
        avg_generation_time_ms=round(stats["average_generation_time_ms"], 1),
    )

    logger.info("Interactive Report Generator test completed")

    # Cleanup test files
    for file_path in [output_path, csv_path]:
        if os.path.exists(file_path):
            os.remove(file_path)
