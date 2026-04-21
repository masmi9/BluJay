"""Executive summary, technical summary, HTML report generation."""

from typing import Dict, List

from core.evre._dataclasses import EnhancedVulnerabilityReport


class ReportGenMixin:
    """Report generation methods: executive summary, technical summary, HTML."""

    def _generate_executive_summary(self, vulnerabilities: List[EnhancedVulnerabilityReport]) -> Dict:
        """Generate executive summary"""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for vuln in vulnerabilities:
            if hasattr(vuln, "severity"):
                severity = vuln.severity
            elif hasattr(vuln, "adjusted_severity"):
                severity = vuln.adjusted_severity
            elif isinstance(vuln, dict):
                severity = vuln.get("severity", vuln.get("adjusted_severity", "MEDIUM"))
            else:
                severity = "MEDIUM"

            if not isinstance(severity, str):
                if hasattr(severity, "value"):
                    severity = severity.value
                elif hasattr(severity, "level"):
                    severity = severity.level
                else:
                    severity = str(severity) if severity else "MEDIUM"

            severity = severity.upper() if isinstance(severity, str) else "MEDIUM"
            severity_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "INFO"}
            severity = severity_map.get(severity, "MEDIUM")

            severity_counts[severity] += 1

        return {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_breakdown": severity_counts,
            "vulnerabilities_with_code_evidence": len([v for v in vulnerabilities if v.vulnerable_code]),
            "files_analyzed": len(set(v.file_path for v in vulnerabilities if v.file_path != "unknown")),
            "consistency_validated": True,
        }

    def _generate_technical_summary(self, vulnerabilities: List[EnhancedVulnerabilityReport]) -> Dict:
        """Generate technical summary"""
        return {
            "vulnerability_patterns_detected": len(set(v.vulnerable_pattern for v in vulnerabilities)),
            "masvs_controls_affected": len(set(v.masvs_control for v in vulnerabilities)),
            "cwe_categories": len(set(v.cwe_id for v in vulnerabilities)),
            "source_files_with_issues": len(set(v.file_path for v in vulnerabilities if v.file_path != "unknown")),
        }

    def _generate_actionable_recommendations(self, vulnerabilities: List[EnhancedVulnerabilityReport]) -> List[Dict]:
        """Generate actionable recommendations"""
        recommendations = []

        pattern_groups = {}
        for vuln in vulnerabilities:
            pattern = vuln.vulnerable_pattern
            if pattern not in pattern_groups:
                pattern_groups[pattern] = []
            pattern_groups[pattern].append(vuln)

        for pattern, vulns in pattern_groups.items():
            if vulns:
                recommendations.append(
                    {
                        "pattern": pattern,
                        "count": len(vulns),
                        "severity": vulns[0].severity,
                        "action": vulns[0].specific_remediation,
                        "affected_files": list(set(v.file_path for v in vulns if v.file_path != "unknown")),
                    }
                )

        return sorted(
            recommendations,
            key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x["severity"], 0),
            reverse=True,
        )

    def _generate_html_report(
        self, vulnerabilities: List[EnhancedVulnerabilityReport], summary: Dict, app_context: Dict
    ) -> str:
        """Generate rich HTML report"""
        app_name = app_context.get("package_name", "Application")

        vuln_cards = []
        for vuln in vulnerabilities:
            severity_class = vuln.severity.lower()

            code_section = ""
            if vuln.vulnerable_code:
                code_section = f"""
                <button class="collapsible">Evidence</button>
                <div class="collapsible-content">
                    <div class="file-path">{vuln.file_path}</div>
                    <div class="code-snippet">{vuln.surrounding_context}</div>
                </div>
                """

            remediation_section = ""
            if vuln.code_fix_example:
                remediation_section = f"""
                <button class="collapsible">Remediation</button>
                <div class="collapsible-content">
                    <div class="remediation">
                        <h4>Specific Action:</h4>
                        <p>{vuln.specific_remediation}</p>
                        <h4>Code Fix Example:</h4>
                        <div class="code-snippet">{vuln.code_fix_example}</div>
                    </div>
                </div>
                """

            # "Verified" badge for findings confirmed by verification agent
            verified_badge = ""
            if getattr(vuln, "verified", False) or getattr(vuln, "dynamically_confirmed", False):
                verified_badge = (
                    ' <span class="badge" style="background:#27ae60;color:#fff;'
                    'padding:2px 8px;border-radius:3px;font-size:0.8em;">'
                    'Verified</span>'
                )

            vuln_card = f"""
            <div class="vulnerability-card {severity_class}">
                <h3>{vuln.title} <span class="severity-{severity_class}">{vuln.severity}</span>{verified_badge}</h3>
                <p><strong>File:</strong> {vuln.file_path}</p>
                <p><strong>Line:</strong> {vuln.line_number}</p>
                <p><strong>CWE:</strong> <span class="badge">{vuln.cwe_id}</span></p>
                <p><strong>MASVS:</strong> <span class="badge">{vuln.masvs_control}</span></p>
                <p><strong>Description:</strong> {vuln.description}</p>
                {code_section}
                {remediation_section}
            </div>
            """
            vuln_cards.append(vuln_card)

        severity_counts = summary["severity_breakdown"]
        dashboard = f"""
        <div class="summary-box">
            <h2>Executive Summary</h2>
            <p>Total Vulnerabilities: <strong>{summary['total_vulnerabilities']}</strong></p>
            <p>Files with Code Evidence: <strong>{summary['vulnerabilities_with_code_evidence']}</strong></p>
            <p>Source Files Analyzed: <strong>{summary['files_analyzed']}</strong></p>
        </div>

        <div class="dashboard">
            <div class="dashboard-card">
                <h3>Critical</h3>
                <div class="number" style="color: #e74c3c;">{severity_counts['CRITICAL']}</div>
            </div>
            <div class="dashboard-card">
                <h3>High</h3>
                <div class="number" style="color: #f39c12;">{severity_counts['HIGH']}</div>
            </div>
            <div class="dashboard-card">
                <h3>Medium</h3>
                <div class="number" style="color: #f1c40f;">{severity_counts['MEDIUM']}</div>
            </div>
            <div class="dashboard-card">
                <h3>Low</h3>
                <div class="number" style="color: #3498db;">{severity_counts['LOW']}</div>
            </div>
        </div>
        """

        content = f"""
        <h1>{app_name} Enhanced Security Report</h1>
        {dashboard}
        <h2>Detailed Vulnerabilities</h2>
        {''.join(vuln_cards)}
        """

        return self.html_template.format(app_name=app_name, content=content)
