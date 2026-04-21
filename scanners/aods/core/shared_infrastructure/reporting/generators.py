#!/usr/bin/env python3
"""
Report Generators for AODS Unified Reporting Framework

Full report generation engines for different report types and formats.
Provides standardized generation logic with customizable templates and formatting.

Features:
- Multiple report type generators
- Executive summary generation
- Technical detail reports
- Compliance assessment reports
- Custom report generation
- Template-based rendering
- Performance optimization
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

from .data_structures import (
    SecurityFinding,
    ReportSection,
    ReportConfiguration,
    ExecutiveSummary,
    TechnicalReport,
    ComplianceAssessment,
    ReportType,
    ReportFormat,
    SeverityLevel,
    ComplianceFramework,
    calculate_risk_score,
    group_findings_by_severity,
    group_findings_by_category,
    create_default_metadata,
    DynamicCoordinationAnalysisResult,
    ComponentAnalysisResult,
    RuntimePatternResult,
    CorrelationAnalysisResult,
)

logger = logging.getLogger(__name__)


def _assess_security_posture(risk_score: float, n_critical: int, n_high: int) -> str:
    """Determine security posture from risk score and critical/high finding counts.

    The risk score alone can understate risk when a few critical findings are
    mixed with many low/info findings.  Count-based floors ensure the posture
    never understates the presence of severe vulnerabilities.
    """
    # Score-based baseline
    if risk_score >= 80:
        posture = "High Risk - Immediate attention required"
    elif risk_score >= 60:
        posture = "Medium Risk - Security improvements needed"
    elif risk_score >= 40:
        posture = "Low-Medium Risk - Some vulnerabilities present"
    elif risk_score >= 20:
        posture = "Low Risk - Minor security issues"
    else:
        posture = "Good Security Posture - Few issues identified"

    # Count-based floor: critical/high findings guarantee minimum posture
    if n_critical >= 3 or (n_critical >= 1 and n_high >= 5):
        floor = "High Risk - Immediate attention required"
    elif n_critical >= 1 or n_high >= 5:
        floor = "Medium Risk - Security improvements needed"
    elif n_high >= 2:
        floor = "Low-Medium Risk - Some vulnerabilities present"
    else:
        floor = posture  # no floor override

    # Return the more severe of score-based and count-based assessments
    severity_order = [
        "Good Security Posture - Few issues identified",
        "Low Risk - Minor security issues",
        "Low-Medium Risk - Some vulnerabilities present",
        "Medium Risk - Security improvements needed",
        "High Risk - Immediate attention required",
    ]
    score_idx = severity_order.index(posture) if posture in severity_order else 0
    floor_idx = severity_order.index(floor) if floor in severity_order else 0
    return severity_order[max(score_idx, floor_idx)]


# Shared CWE→recommendation mapping (used by both unified_facade and generators)
CWE_RECOMMENDATIONS: Dict[str, str] = {
    "CWE-200": "Remove sensitive information from logs and error messages.",
    "CWE-276": 'Set android:exported="false" or protect with a signature-level permission using android:permission.',
    "CWE-295": "Implement certificate pinning and proper TLS certificate validation. Use TLS 1.2+ with strong cipher suites.",  # noqa: E501
    "CWE-312": "Encrypt sensitive data at rest using Android Keystore or EncryptedSharedPreferences.",
    "CWE-327": "Use AES/GCM/NoPadding instead of ECB or DES. Ensure proper key management with Android Keystore.",
    "CWE-328": "Replace MD5/SHA1 with SHA-256 or stronger. Use bcrypt/scrypt/Argon2 for password hashing.",
    "CWE-330": "Use SecureRandom instead of Random for security-sensitive operations.",
    "CWE-434": "Validate file types and use encrypted storage for sensitive files.",
    "CWE-489": 'Set android:debuggable="false" in the release build. Use build variants to enable debugging only in debug builds.',  # noqa: E501
    "CWE-502": "Avoid deserializing untrusted data or use safe serialization alternatives.",
    "CWE-693": "Implement proper security controls. Disable debug mode in production and restrict backup capabilities.",
    "CWE-798": "Remove hardcoded secrets from source code. Use Android Keystore, encrypted SharedPreferences, or a secrets manager.",  # noqa: E501
    "CWE-862": "Validate all incoming Intent data. Use explicit intents where possible and verify the calling package.",
    "CWE-921": "Use internal storage (getFilesDir()) for sensitive data. External storage is world-readable on older Android versions.",  # noqa: E501
    "CWE-922": "Use internal storage (getFilesDir()) for sensitive data. External storage is world-readable on older Android versions.",  # noqa: E501
    "CWE-926": 'Add android:exported="false" or protect with intent filters and explicit permissions.',
    "CWE-927": "Validate all incoming Intent data including extras and URIs. Use explicit intents and verify the calling package.",  # noqa: E501
    "CWE-1104": "Update targetSdkVersion and minSdkVersion to the latest stable Android API level.",
}

# Title keyword→recommendation fallback (used when CWE not available or not in map)
TITLE_RECOMMENDATIONS: Dict[str, str] = {
    "exported activities": 'Add android:exported="false" or protect with a signature-level permission using android:permission.',  # noqa: E501
    "exported services": 'Add android:exported="false" or protect with a signature-level permission using android:permission.',  # noqa: E501
    "exported receivers": 'Add android:exported="false" or protect with a signature-level permission using android:permission.',  # noqa: E501
    "exported providers": 'Add android:exported="false" or protect with android:permission and android:readPermission/writePermission.',  # noqa: E501
    "world-accessible": 'Remove android:exported="true" or add strict permission controls. Use FileProvider for content sharing.',  # noqa: E501
    "dangerous permission": "Review if this permission is necessary. Request at runtime with clear user justification.",
    "deprecated permission": "Migrate to scoped storage APIs (MediaStore, SAF) instead of broad storage permissions.",
    "grant uri": 'Restrict URI permissions to specific paths. Avoid android:grantUriPermissions="true" on the entire provider.',  # noqa: E501
    "backup enabled": 'Set android:allowBackup="false" or implement a custom BackupAgent that excludes sensitive data.',
    "sql injection": "Use parameterized queries or ContentProvider query builders instead of string concatenation for SQL.",  # noqa: E501
    "insecure cipher": "Use AES/GCM/NoPadding instead of ECB mode. ECB does not provide semantic security.",
    "insecure temporary": "Use Context.getCacheDir() for temp files. Set restrictive permissions and delete files when no longer needed.",  # noqa: E501
    "insecure file perm": "Use MODE_PRIVATE for file creation. Never use MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE.",
    "no padding": "Specify a secure padding scheme (e.g., PKCS7Padding or OAEP) to prevent padding oracle attacks.",
    "shared preferences": "Use EncryptedSharedPreferences from the Jetpack Security library for sensitive data.",
    "sensitive data stored": "Encrypt sensitive data before storing. Use EncryptedSharedPreferences or Android Keystore.",  # noqa: E501
}


def get_cwe_recommendation(cwe_id: str, title: str = "") -> str:
    """Get actionable recommendation for a CWE/finding, shared across report paths."""
    rec = CWE_RECOMMENDATIONS.get(cwe_id)
    if rec:
        return rec
    # Fallback: match title keywords
    title_l = title.lower()
    for pattern, fallback_rec in TITLE_RECOMMENDATIONS.items():
        if pattern in title_l:
            return fallback_rec
    return f"Review and remediate {cwe_id} vulnerability." if cwe_id else ""


class BaseReportGenerator:
    """Base class for all report generators."""

    def __init__(
        self, configuration: Optional[ReportConfiguration] = None, quality_level: Optional[str] = None, **kwargs
    ):
        self.config = configuration or ReportConfiguration(
            output_format=ReportFormat.JSON, report_type=ReportType.SECURITY_ANALYSIS
        )
        # Store quality_level for potential use by subclasses
        self.quality_level = quality_level
        # Filter out any additional parameters that shouldn't be passed to parent
        self.logger = logging.getLogger(self.__class__.__name__)

    def generate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate report from input data."""
        raise NotImplementedError("Subclasses must implement generate method")

    def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate input data structure."""
        required_fields = ["findings", "metadata"]
        return all(field in data for field in required_fields)

    def apply_filters(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Apply configured filters to findings."""
        filtered = findings

        # Filter by severity
        if self.config.filter_by_severity:
            filtered = [f for f in filtered if f.severity in self.config.filter_by_severity]

        # Filter by category
        if self.config.filter_by_category:
            filtered = [f for f in filtered if f.category in self.config.filter_by_category]

        # Filter by confidence threshold
        if self.config.confidence_threshold > 0:
            filtered = [f for f in filtered if f.confidence >= self.config.confidence_threshold]

        # Filter false positives if configured
        if not self.config.include_false_positives:
            filtered = [f for f in filtered if f.false_positive_probability < 0.5]

        return filtered

    def sort_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Sort findings according to configuration."""
        sort_key = self.config.sort_findings_by

        if sort_key == "severity":
            severity_order = {
                SeverityLevel.CRITICAL: 5,
                SeverityLevel.HIGH: 4,
                SeverityLevel.MEDIUM: 3,
                SeverityLevel.LOW: 2,
                SeverityLevel.INFO: 1,
            }
            return sorted(findings, key=lambda f: severity_order.get(f.severity, 0), reverse=True)
        elif sort_key == "confidence":
            return sorted(findings, key=lambda f: f.confidence, reverse=True)
        elif sort_key == "category":
            return sorted(findings, key=lambda f: f.category)
        elif sort_key == "risk_score":
            return sorted(findings, key=lambda f: f.risk_score, reverse=True)

        return findings

    def _asdict_with_enum_values(self, dataclass_obj: Any) -> Dict[str, Any]:
        """
        Convert dataclass to dict with Enums properly serialized to their values.

        CRITICAL FIX: Prevents invalid JSON from Enum object representations
        """
        from dataclasses import asdict, is_dataclass

        if not is_dataclass(dataclass_obj):
            return dataclass_obj

        # Convert to dict first
        result = asdict(dataclass_obj)

        # Recursively fix all Enum values
        return self._fix_enum_values(result)

    def _fix_enum_values(self, obj: Any) -> Any:
        """Recursively convert Enum objects to their values in nested structures."""
        from enum import Enum

        if isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, dict):
            return {key: self._fix_enum_values(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._fix_enum_values(item) for item in obj]
        else:
            return obj

    def _convert_dict_to_security_finding(self, finding_dict: Dict[str, Any]) -> SecurityFinding:
        """Convert AODS finding dictionary to SecurityFinding object with proper field mapping."""
        import time

        # Map AODS fields to SecurityFinding fields
        finding_id = finding_dict.get("id", f"finding_{int(time.time())}")
        title = finding_dict.get("title", finding_dict.get("content", "Unknown Security Finding"))
        description = finding_dict.get("description", finding_dict.get("content", title))

        # Convert severity string to SeverityLevel enum
        severity_str = finding_dict.get("severity", "medium").lower()
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        severity = severity_map.get(severity_str, SeverityLevel.MEDIUM)

        # Preserve enrichment fields when present in dict input
        exploitability = str(finding_dict.get("exploitability", "") or "").lower() or "unknown"
        impact = str(finding_dict.get("impact", "") or "").lower() or "unknown"
        remediation_effort = str(finding_dict.get("remediation_effort", "") or "").lower() or "unknown"
        plugin_source = finding_dict.get("plugin_source", "") or ""
        risk_score = float(finding_dict.get("risk_score", 0.0) or 0.0)

        # Derive exploitability/impact from severity when they would otherwise be "unknown"
        if exploitability == "unknown" or impact == "unknown":
            _sev_derivation = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "low"}
            derived = _sev_derivation.get(severity_str, "medium")
            if exploitability == "unknown":
                exploitability = derived
            if impact == "unknown":
                impact = derived

        # Derive file_path from evidence or location when not provided
        file_path = finding_dict.get("file_path", "")
        if not file_path:
            evidence = finding_dict.get("evidence", {})
            if isinstance(evidence, dict):
                file_path = evidence.get("file_path", "") or evidence.get("location", "")

            # Only infer file_path if not in strict mode (respects AODS_REPORT_STRICT_LOCATIONS)
            import os

            strict_mode = os.environ.get("AODS_REPORT_STRICT_LOCATIONS", "0") == "1"
            if not file_path and not strict_mode:
                # Infer file_path from finding context
                title_lower = title.lower()
                description.lower() if description else ""

                # Manifest-related findings (only for specific security findings, not generic)
                manifest_title_keywords = [
                    "exported",
                    "permission",
                    "backup",
                    "debuggable",
                    "min sdk",
                    "target sdk",
                    "debug mode enabled",
                    "sdk version",
                    "content provider",
                    "intent action",
                    "manifest analysis",
                ]
                if any(kw in title_lower for kw in manifest_title_keywords):
                    file_path = "AndroidManifest.xml"

                # Certificate/signing analysis
                if not file_path and (
                    "certificate" in title_lower or "signing" in title_lower or "apk sign" in title_lower
                ):
                    file_path = "META-INF/CERT.RSA"

                # APK-level analysis
                if not file_path and ("apk information" in title_lower or "apk extraction" in title_lower):
                    file_path = "APK Package"

                # Storage analysis
                if not file_path and (
                    "storage" in title_lower or "data storage" in title_lower or "file storage" in title_lower
                ):
                    file_path = "Application Data Storage"

                # Platform usage
                if not file_path and ("platform usage" in title_lower or "improper platform" in title_lower):
                    file_path = "AndroidManifest.xml"

        # Derive recommendation from CWE database when not provided
        recommendation = finding_dict.get("recommendation", "")
        if not recommendation:
            cwe_id = finding_dict.get("cwe_id", "")
            if cwe_id:
                recommendation = self._get_cwe_recommendation(cwe_id, title)

        return SecurityFinding(
            id=finding_id,
            title=title,
            description=description,
            severity=severity,
            confidence=finding_dict.get("confidence", 0.8),
            category=finding_dict.get("category", "security"),
            location=finding_dict.get("location", "unknown"),
            file_path=file_path,
            line_number=finding_dict.get("line_number", None),
            evidence=finding_dict.get("evidence", ""),
            recommendation=recommendation,
            references=finding_dict.get("references", []),
            cwe_id=finding_dict.get("cwe_id", None),
            owasp_category=finding_dict.get("owasp_category", ""),
            masvs_control=finding_dict.get("masvs_control", ""),
            nist_control=finding_dict.get("nist_control", ""),
            risk_score=risk_score,
            exploitability=exploitability,
            impact=impact,
            remediation_effort=remediation_effort,
            plugin_source=plugin_source,
            code_snippet=finding_dict.get("code_snippet", ""),
        )

    def _get_cwe_recommendation(self, cwe_id: str, title: str) -> str:
        """Get recommendation from CWE database or derive from finding context."""
        return get_cwe_recommendation(cwe_id, title)


class SecurityAnalysisReportGenerator(BaseReportGenerator):
    """Generator for security analysis reports."""

    def generate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate security analysis report."""
        if not self.validate_input(data):
            raise ValueError("Invalid input data structure")

        findings = [self._convert_dict_to_security_finding(f) if isinstance(f, dict) else f for f in data["findings"]]
        context = data.get("context", {})

        # Apply filters and sorting
        filtered_findings = self.apply_filters(findings)
        sorted_findings = self.sort_findings(filtered_findings)

        # Create report metadata
        metadata = create_default_metadata(ReportType.SECURITY_ANALYSIS, self.config.output_format)
        metadata.total_findings = len(sorted_findings)
        metadata.risk_score = calculate_risk_score(sorted_findings)

        # Populate target_application from context or metadata (check multiple possible keys)
        report_metadata = data.get("metadata", {})
        metadata.target_application = (
            context.get("target_apk_path", "")
            or report_metadata.get("target_apk_path", "")
            or context.get("apk_path", "")
            or report_metadata.get("apk_path", "")
            or context.get("package_name", "")
            or report_metadata.get("package_name", "")
            or context.get("target_application", "")
            or report_metadata.get("target_application", "")
        )

        # Calculate unique vulnerabilities (deduplicated by title)
        metadata.unique_vulnerabilities = len(set(f.title for f in sorted_findings))

        # Set compliance frameworks based on findings
        if any(f.masvs_control for f in sorted_findings):
            metadata.compliance_frameworks.append(ComplianceFramework.MASVS)
        if any(f.cwe_id for f in sorted_findings):
            metadata.compliance_frameworks.append(ComplianceFramework.CWE)
        if any(f.owasp_category for f in sorted_findings):
            metadata.compliance_frameworks.append(ComplianceFramework.OWASP_TOP_10)

        # Build report sections
        # NOTE: Executive summary stats grid is rendered separately via report["executive_summary"].
        # The text-based _create_executive_summary_section and _create_vulnerability_overview_section
        # are NOT added here to avoid duplicate/redundant content in the HTML output.
        sections = []

        sections.append(self._create_detailed_findings_section(sorted_findings))

        if self.config.include_remediation_guidance:
            sections.append(self._create_remediation_section(sorted_findings))

        if self.config.include_compliance_mapping:
            sections.append(self._create_compliance_section(sorted_findings))

        # Prepare a compatibility "findings" summary for JSON consumers
        # Normalize severity strings to uppercase for JSON summary to align with tests
        def _norm(fs: SecurityFinding) -> Dict[str, Any]:
            d = self._asdict_with_enum_values(fs)
            try:
                if "severity" in d and isinstance(d["severity"], str):
                    d["severity"] = d["severity"].upper()
            except Exception:
                pass
            return d

        findings_summary = [_norm(f) for f in sorted_findings]

        # Generate report structure
        report = {
            "metadata": self._asdict_with_enum_values(metadata),
            "executive_summary": self._asdict_with_enum_values(self._generate_executive_summary(sorted_findings)),
            "sections": [self._asdict_with_enum_values(section) for section in sections],
            "statistics": self._asdict_with_enum_values(self._calculate_statistics(sorted_findings)),
            "context": self._asdict_with_enum_values(context) if context else {},
            "generated_at": datetime.now().isoformat(),
            # Backward-compatible top-level findings list for JSON parsing in tests/tools
            "findings": findings_summary,
        }

        return report

    def _create_executive_summary_section(self, findings: List[SecurityFinding]) -> ReportSection:
        """Create executive summary section with a brief intro (detailed stats in stats grid)."""
        risk_score = calculate_risk_score(findings)

        summary_content = (
            f"The analysis identified {len(findings)} security findings "
            f"with an overall risk score of {risk_score:.1f}/100."
        )

        return ReportSection(
            id="executive_summary", title="Executive Summary", content=summary_content, order=1
        )

    def _create_vulnerability_overview_section(self, findings: List[SecurityFinding]) -> ReportSection:
        """Create vulnerability overview section."""
        category_groups = group_findings_by_category(findings)

        overview_content = "Vulnerability Distribution by Category:\n"
        for category, category_findings in sorted(category_groups.items()):
            overview_content += f"- {category}: {len(category_findings)} findings\n"

        section = ReportSection(
            id="vulnerability_overview", title="Vulnerability Overview", content=overview_content, order=2
        )

        # Add chart data for visualization
        if self.config.include_charts:
            section.charts.append(
                {
                    "type": "pie",
                    "title": "Findings by Category",
                    "data": {cat: len(findings) for cat, findings in category_groups.items()},
                }
            )

        return section

    def _create_detailed_findings_section(self, findings: List[SecurityFinding]) -> ReportSection:
        """Create detailed findings section."""
        section = ReportSection(
            id="detailed_findings",
            title="Detailed Security Findings",
            content="Analysis of identified security vulnerabilities",
            order=3,
        )

        # Group findings by severity for organized presentation
        severity_groups = group_findings_by_severity(findings)

        all_severities = [
            SeverityLevel.CRITICAL, SeverityLevel.HIGH,
            SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO,
        ]
        for severity in all_severities:
            severity_findings = severity_groups.get(severity, [])
            if not severity_findings:
                continue

            # Apply max findings per section limit
            if self.config.max_findings_per_section > 0:
                severity_findings = severity_findings[: self.config.max_findings_per_section]

            count = len(severity_findings)
            # INFO findings are observations, not vulnerabilities
            if severity == SeverityLevel.INFO:
                noun = "finding" if count == 1 else "findings"
            else:
                noun = "vulnerability" if count == 1 else "vulnerabilities"
            subsection = ReportSection(
                id=f"findings_{severity.value}",
                title=f"{severity.value.title()} Severity Findings",
                content=f"{count} {severity.value} severity {noun} identified",
                findings=severity_findings,
                order=len(section.subsections) + 1,
            )

            section.add_subsection(subsection)

        return section

    def _create_remediation_section(self, findings: List[SecurityFinding]) -> ReportSection:
        """Create remediation guidance section."""
        # Collect unique recommendations
        recommendations = set()
        for finding in findings:
            if finding.recommendation:
                recommendations.add(finding.recommendation)

        # Dedup near-duplicate recommendations (e.g., same first 60 chars but different last word)
        seen_prefixes = set()
        deduped = []
        for rec in sorted(recommendations):
            # Normalize: lowercase, first 60 chars
            prefix = rec[:60].lower().strip()
            if prefix not in seen_prefixes:
                seen_prefixes.add(prefix)
                deduped.append(rec)

        remediation_content = "Recommended Remediation Actions:\n"
        for i, recommendation in enumerate(deduped, 1):
            remediation_content += f"{i}. {recommendation}\n"

        return ReportSection(
            id="remediation_guidance", title="Remediation Guidance", content=remediation_content, order=4
        )

    def _create_compliance_section(self, findings: List[SecurityFinding]) -> ReportSection:
        """Create compliance mapping section."""
        # Group findings by compliance frameworks
        masvs_findings = [f for f in findings if f.masvs_control]
        nist_findings = [f for f in findings if f.nist_control]
        cwe_findings = [f for f in findings if f.cwe_id]

        masvs_count = len(set(f.masvs_control for f in masvs_findings))
        nist_count = len(set(f.nist_control for f in nist_findings))
        cwe_count = len(set(f.cwe_id for f in cwe_findings))

        items = []
        if masvs_count:
            items.append(f"MASVS Controls: {masvs_count} controls affected")
        if nist_count:
            items.append(f"NIST Controls: {nist_count} controls affected")
        if cwe_count:
            items.append(f"CWE Categories: {cwe_count} categories identified")
        compliance_content = "\n".join(items) if items else "No compliance mappings available"

        return ReportSection(
            id="compliance_mapping", title="Compliance Framework Mapping", content=compliance_content, order=5
        )

    def _generate_executive_summary(self, findings: List[SecurityFinding]) -> ExecutiveSummary:
        """Generate executive summary data."""
        severity_counts = self._count_by_severity(findings)
        category_counts = self._count_by_category(findings)

        # Top vulnerability categories (with percentage)
        top_categories = sorted(
            [
                {
                    "category": cat,
                    "count": count,
                    "percentage": (count / len(findings) * 100) if findings else 0,
                }
                for cat, count in category_counts.items()
            ],
            key=lambda x: x["count"],
            reverse=True,
        )[:5]

        # Security posture assessment
        risk_score = calculate_risk_score(findings)
        n_critical = severity_counts.get(SeverityLevel.CRITICAL.value, 0)
        n_high = severity_counts.get(SeverityLevel.HIGH.value, 0)
        security_posture = _assess_security_posture(risk_score, n_critical, n_high)

        # Key recommendations
        key_recommendations = [
            "Implement secure coding practices",
            "Regular security testing and code review",
            "Update to latest security libraries",
            "Enable additional security controls",
        ]

        return ExecutiveSummary(
            overall_risk_score=risk_score,
            total_vulnerabilities=len(findings),
            critical_vulnerabilities=n_critical,
            high_vulnerabilities=n_high,
            medium_vulnerabilities=severity_counts.get(SeverityLevel.MEDIUM.value, 0),
            low_vulnerabilities=severity_counts.get(SeverityLevel.LOW.value, 0),
            info_vulnerabilities=severity_counts.get(SeverityLevel.INFO.value, 0),
            top_vulnerability_categories=top_categories,
            compliance_assessments=[],
            key_recommendations=key_recommendations,
            security_posture=security_posture,
        )

    def _calculate_statistics(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Calculate statistics."""
        return {
            "total_findings": len(findings),
            "by_severity": self._count_by_severity(findings),
            "by_category": self._count_by_category(findings),
            "average_confidence": sum(f.confidence for f in findings) / len(findings) if findings else 0,
            "risk_score": calculate_risk_score(findings),
            "unique_locations": len(set(f.location for f in findings)),
            "unique_files": len(set(f.file_path for f in findings if f.file_path)),
        }

    def _count_by_severity(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = {}
        for severity in SeverityLevel:
            # CRITICAL FIX: Use enum.value as key to prevent massive enum serialization in JSON
            counts[severity.value] = len([f for f in findings if f.severity == severity])
        return counts

    # Normalize raw category names to clean display names
    _CATEGORY_NORMALIZE = {
        "security": "Security",
        "cryptography": "Cryptography",
        "network_security": "Network Security",
        "network security": "Network Security",
        "insecure data storage": "Data Storage",
        "insecure_data_storage": "Data Storage",
        "code quality": "Code Quality",
        "code_quality": "Code Quality",
        "platform usage": "Platform Usage",
        "platform_usage": "Platform Usage",
        "improper_platform_usage": "Platform Usage",
        "improper platform usage": "Platform Usage",
        "privacy": "Privacy",
        "authentication": "Authentication",
        "resilience": "Resilience",
        # MASVS control categories
        "masvs-platform": "Platform Security",
        "masvs-auth": "Authentication",
        "masvs-storage": "Data Storage",
        "masvs-network": "Network Security",
        "masvs-crypto": "Cryptography",
        "masvs-code": "Code Quality",
        "masvs-resilience": "Resilience",
        "masvs-privacy": "Privacy",
        # OWASP Mobile Top 10 codes → clean display names
        "m01-improper-credential-usage": "Credential Usage",
        "m02-insecure-data-storage": "Data Storage",
        "m03-insecure-authentication": "Authentication",
        "m04-insufficient-input-output-validation": "Input Validation",
        "m05-insecure-communication": "Network Security",
        "m06-inadequate-privacy-controls": "Privacy",
        "m07-client-code-quality": "Code Quality",
        "m08-code-tampering": "Code Tampering",
        "m09-reverse-engineering": "Reverse Engineering",
        "m10-extraneous-functionality": "Extraneous Functionality",
    }

    def _count_by_category(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """Count findings by category with normalized names."""
        counts: Dict[str, int] = {}
        for finding in findings:
            cat = finding.category.strip()
            cat = self._CATEGORY_NORMALIZE.get(cat.lower(), cat.title() if cat.islower() else cat)
            counts[cat] = counts.get(cat, 0) + 1
        return counts


class ExecutiveSummaryGenerator(BaseReportGenerator):
    """Generator for executive summary reports."""

    def generate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary report."""
        findings = [SecurityFinding(**f) if isinstance(f, dict) else f for f in data["findings"]]

        # Apply filters
        filtered_findings = self.apply_filters(findings)

        # Generate executive summary
        exec_summary = self._create_executive_summary(filtered_findings)

        # Create metadata
        metadata = create_default_metadata(ReportType.EXECUTIVE_SUMMARY, self.config.output_format)
        metadata.total_findings = len(filtered_findings)
        metadata.risk_score = exec_summary.overall_risk_score

        return {
            "metadata": self._asdict_with_enum_values(metadata),
            "executive_summary": self._asdict_with_enum_values(exec_summary),
            "key_metrics": self._calculate_key_metrics(filtered_findings),
            "generated_at": datetime.now().isoformat(),
        }

    def _create_executive_summary(self, findings: List[SecurityFinding]) -> ExecutiveSummary:
        """Create full executive summary."""
        severity_counts = {}
        for severity in SeverityLevel:
            severity_counts[severity] = len([f for f in findings if f.severity == severity])

        # Top categories
        category_counts = {}
        for finding in findings:
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1

        top_categories = sorted(
            [
                {"category": cat, "count": count, "percentage": (count / len(findings) * 100) if findings else 0}
                for cat, count in category_counts.items()
            ],
            key=lambda x: x["count"],
            reverse=True,
        )[:5]

        # Security posture assessment
        risk_score = calculate_risk_score(findings)
        n_critical = severity_counts.get(SeverityLevel.CRITICAL, 0)
        n_high = severity_counts.get(SeverityLevel.HIGH, 0)
        security_posture = _assess_security_posture(risk_score, n_critical, n_high)

        return ExecutiveSummary(
            overall_risk_score=risk_score,
            total_vulnerabilities=len(findings),
            critical_vulnerabilities=n_critical,
            high_vulnerabilities=n_high,
            medium_vulnerabilities=severity_counts.get(SeverityLevel.MEDIUM, 0),
            low_vulnerabilities=severity_counts.get(SeverityLevel.LOW, 0),
            info_vulnerabilities=severity_counts.get(SeverityLevel.INFO, 0),
            top_vulnerability_categories=top_categories,
            compliance_assessments=[],
            key_recommendations=self._generate_executive_recommendations(findings),
            security_posture=security_posture,
        )

    def _generate_executive_recommendations(self, findings: List[SecurityFinding]) -> List[str]:
        """Generate executive-level recommendations."""
        recommendations = []

        severity_counts = {}
        for severity in SeverityLevel:
            severity_counts[severity] = len([f for f in findings if f.severity == severity])

        if severity_counts.get(SeverityLevel.CRITICAL, 0) > 0:
            recommendations.append(
                "Address critical vulnerabilities immediately to prevent potential security breaches"
            )

        if severity_counts.get(SeverityLevel.HIGH, 0) > 0:
            recommendations.append(
                "Prioritize remediation of high severity vulnerabilities in the next development cycle"
            )

        if len(findings) > 20:
            recommendations.append(
                "Implement security testing processes to prevent future vulnerabilities"
            )

        recommendations.extend(
            [
                "Establish regular security review processes",
                "Invest in security training for development teams",
                "Consider third-party security assessments",
            ]
        )

        return recommendations[:5]  # Limit to top 5 recommendations

    def _calculate_key_metrics(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Calculate key executive metrics."""
        if not findings:
            return {"total_findings": 0, "risk_score": 0, "critical_issues": 0}

        return {
            "total_findings": len(findings),
            "risk_score": calculate_risk_score(findings),
            "critical_issues": len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
            "high_priority_issues": len(
                [f for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
            ),
            "average_confidence": sum(f.confidence for f in findings) / len(findings),
            "most_common_category": (
                max(set(f.category for f in findings), key=lambda cat: len([f for f in findings if f.category == cat]))
                if findings
                else "None"
            ),
        }


class TechnicalReportGenerator(BaseReportGenerator):
    """Generator for detailed technical reports."""

    def generate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed technical report."""
        findings = [SecurityFinding(**f) if isinstance(f, dict) else f for f in data["findings"]]
        context = data.get("context", {})

        # Apply filters and sorting
        filtered_findings = self.apply_filters(findings)
        sorted_findings = self.sort_findings(filtered_findings)

        # Create technical report
        technical_report = TechnicalReport(
            methodology="OWASP MASVS-based static and dynamic analysis",
            tools_used=["AODS Framework", "Static Analysis", "Dynamic Analysis"],
            analysis_scope={
                "total_files_analyzed": context.get("files_analyzed", 0),
                "analysis_duration": context.get("analysis_duration", 0),
                "plugins_executed": context.get("plugins_executed", []),
            },
            detailed_findings=sorted_findings,
            technical_recommendations=self._generate_technical_recommendations(sorted_findings),
            false_positive_analysis=self._analyze_false_positives(sorted_findings),
            performance_analysis=context.get("performance_metrics", {}),
        )

        # Create metadata
        metadata = create_default_metadata(ReportType.TECHNICAL_DETAILS, self.config.output_format)
        metadata.total_findings = len(sorted_findings)
        metadata.risk_score = calculate_risk_score(sorted_findings)

        return {
            "metadata": self._asdict_with_enum_values(metadata),
            "technical_report": self._asdict_with_enum_values(technical_report),
            "detailed_analysis": self._create_detailed_analysis(sorted_findings),
            "generated_at": datetime.now().isoformat(),
        }

    def _generate_technical_recommendations(self, findings: List[SecurityFinding]) -> List[str]:
        """Generate technical recommendations."""
        recommendations = []

        # Category-specific recommendations
        categories = set(f.category for f in findings)

        if "Cryptography" in categories:
            recommendations.append("Implement strong cryptographic algorithms (AES-256, SHA-256)")

        if "Data Storage" in categories:
            recommendations.append("Use encrypted storage mechanisms for sensitive data")

        if "Network Security" in categories:
            recommendations.append("Implement certificate pinning and network security configuration")

        if "Code Quality" in categories:
            recommendations.append("Implement static code analysis in CI/CD pipeline")

        return recommendations

    def _analyze_false_positives(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Analyze false positive patterns."""
        fp_candidates = [f for f in findings if f.false_positive_probability > 0.3]

        return {
            "total_findings": len(findings),
            "potential_false_positives": len(fp_candidates),
            "false_positive_rate": len(fp_candidates) / len(findings) if findings else 0,
            "confidence_distribution": {
                "high": len([f for f in findings if f.confidence >= 0.8]),
                "medium": len([f for f in findings if 0.5 <= f.confidence < 0.8]),
                "low": len([f for f in findings if f.confidence < 0.5]),
            },
        }

    def _create_detailed_analysis(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Create detailed technical analysis."""
        return {
            "vulnerability_patterns": self._analyze_vulnerability_patterns(findings),
            "code_coverage": self._analyze_code_coverage(findings),
            "security_hotspots": self._identify_security_hotspots(findings),
            "risk_assessment": self._detailed_risk_assessment(findings),
        }

    def _analyze_vulnerability_patterns(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Analyze patterns in vulnerabilities."""
        patterns = {}

        # File extension patterns
        file_extensions = {}
        for finding in findings:
            if finding.file_path:
                ext = Path(finding.file_path).suffix
                file_extensions[ext] = file_extensions.get(ext, 0) + 1

        patterns["file_extensions"] = file_extensions

        # Location patterns
        location_patterns = {}
        for finding in findings:
            location_type = finding.location.split(":")[0] if ":" in finding.location else finding.location
            location_patterns[location_type] = location_patterns.get(location_type, 0) + 1

        patterns["location_types"] = location_patterns

        return patterns

    def _analyze_code_coverage(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Analyze code coverage of security findings."""
        unique_files = set(f.file_path for f in findings if f.file_path)
        unique_locations = set(f.location for f in findings)

        return {
            "files_with_findings": len(unique_files),
            "unique_locations": len(unique_locations),
            "findings_per_file": len(findings) / len(unique_files) if unique_files else 0,
        }

    def _identify_security_hotspots(self, findings: List[SecurityFinding]) -> List[Dict[str, Any]]:
        """Identify security hotspots (areas with multiple vulnerabilities)."""
        hotspots = {}

        for finding in findings:
            key = finding.file_path or finding.location
            if key not in hotspots:
                hotspots[key] = []
            hotspots[key].append(finding)

        # Sort by number of findings
        sorted_hotspots = sorted(
            [
                {"location": loc, "finding_count": len(findings), "risk_score": calculate_risk_score(findings)}
                for loc, findings in hotspots.items()
            ],
            key=lambda x: x["finding_count"],
            reverse=True,
        )

        return sorted_hotspots[:10]  # Top 10 hotspots

    def _detailed_risk_assessment(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Perform detailed risk assessment."""
        return {
            "overall_risk_score": calculate_risk_score(findings),
            "risk_distribution": {
                "critical_risk": len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
                "high_risk": len([f for f in findings if f.severity == SeverityLevel.HIGH]),
                "medium_risk": len([f for f in findings if f.severity == SeverityLevel.MEDIUM]),
                "low_risk": len([f for f in findings if f.severity == SeverityLevel.LOW]),
            },
            "exploitability_assessment": {
                "easily_exploitable": len([f for f in findings if f.exploitability == "high"]),
                "moderately_exploitable": len([f for f in findings if f.exploitability == "medium"]),
                "difficult_to_exploit": len([f for f in findings if f.exploitability == "low"]),
            },
        }


class ComplianceReportGenerator(BaseReportGenerator):
    """Generator for compliance framework reports."""

    def __init__(self, framework: str = "MASVS", **kwargs):
        super().__init__(**kwargs)
        self.framework = ComplianceFramework(framework) if isinstance(framework, str) else framework

    def generate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance assessment report."""
        findings = [SecurityFinding(**f) if isinstance(f, dict) else f for f in data["findings"]]

        # Apply filters
        filtered_findings = self.apply_filters(findings)

        # Generate compliance assessment
        compliance_assessment = self._assess_compliance(filtered_findings)

        # Create metadata
        metadata = create_default_metadata(ReportType.COMPLIANCE_ASSESSMENT, self.config.output_format)
        metadata.total_findings = len(filtered_findings)
        metadata.compliance_frameworks = [self.framework]

        return {
            "metadata": self._asdict_with_enum_values(metadata),
            "compliance_assessment": self._asdict_with_enum_values(compliance_assessment),
            "detailed_mapping": self._create_detailed_mapping(filtered_findings),
            "recommendations": self._generate_compliance_recommendations(compliance_assessment),
            "generated_at": datetime.now().isoformat(),
        }

    def _assess_compliance(self, findings: List[SecurityFinding]) -> ComplianceAssessment:
        """Assess compliance with the specified framework."""
        if self.framework == ComplianceFramework.MASVS:
            return self._assess_masvs_compliance(findings)
        elif self.framework == ComplianceFramework.NIST:
            return self._assess_nist_compliance(findings)
        else:
            return self._assess_generic_compliance(findings)

    def _assess_masvs_compliance(self, findings: List[SecurityFinding]) -> ComplianceAssessment:
        """Assess MASVS compliance."""
        # MASVS controls mapping
        masvs_controls = {
            "MASVS-STORAGE": "Data Storage and Privacy",
            "MASVS-CRYPTO": "Cryptography",
            "MASVS-AUTH": "Authentication and Session Management",
            "MASVS-NETWORK": "Network Communication",
            "MASVS-PLATFORM": "Platform Interaction",
            "MASVS-CODE": "Code Quality and Build Settings",
            "MASVS-RESILIENCE": "Resilience Against Reverse Engineering",
        }

        # Map findings to controls
        findings_by_control = {}
        for finding in findings:
            if finding.masvs_control:
                control_category = finding.masvs_control.split("-")[0] + "-" + finding.masvs_control.split("-")[1]
                if control_category not in findings_by_control:
                    findings_by_control[control_category] = []
                findings_by_control[control_category].append(finding)

        total_controls = len(masvs_controls)
        tested_controls = len(findings_by_control)
        failed_controls = len([ctrl for ctrl, findings in findings_by_control.items() if findings])
        passed_controls = tested_controls - failed_controls

        assessment = ComplianceAssessment(
            framework=ComplianceFramework.MASVS,
            total_controls=total_controls,
            tested_controls=tested_controls,
            passed_controls=passed_controls,
            failed_controls=failed_controls,
            not_applicable_controls=total_controls - tested_controls,
            compliance_percentage=0.0,
            risk_score=calculate_risk_score(findings),
            findings_by_control=findings_by_control,
        )

        assessment.compliance_percentage = assessment.calculate_compliance_percentage()
        return assessment

    def _assess_nist_compliance(self, findings: List[SecurityFinding]) -> ComplianceAssessment:
        """Assess NIST compliance."""
        # Simplified NIST assessment
        nist_findings = [f for f in findings if f.nist_control]

        return ComplianceAssessment(
            framework=ComplianceFramework.NIST,
            total_controls=100,  # Approximate
            tested_controls=len(set(f.nist_control for f in nist_findings)),
            passed_controls=0,  # Would need actual compliance logic
            failed_controls=len(set(f.nist_control for f in nist_findings)),
            not_applicable_controls=0,
            compliance_percentage=0.0,
            risk_score=calculate_risk_score(findings),
            findings_by_control={},
        )

    def _assess_generic_compliance(self, findings: List[SecurityFinding]) -> ComplianceAssessment:
        """Generic compliance assessment."""
        return ComplianceAssessment(
            framework=self.framework,
            total_controls=50,
            tested_controls=len(findings),
            passed_controls=0,
            failed_controls=len(findings),
            not_applicable_controls=0,
            compliance_percentage=0.0,
            risk_score=calculate_risk_score(findings),
            findings_by_control={},
        )

    def _create_detailed_mapping(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Create detailed compliance mapping."""
        mapping = {
            "framework": self.framework.value,
            "control_coverage": {},
            "finding_distribution": {},
            "compliance_gaps": [],
        }

        # Add framework-specific mapping details
        if self.framework == ComplianceFramework.MASVS:
            mapping["masvs_version"] = "2.0"
            mapping["control_categories"] = [
                "MASVS-STORAGE",
                "MASVS-CRYPTO",
                "MASVS-AUTH",
                "MASVS-NETWORK",
                "MASVS-PLATFORM",
                "MASVS-CODE",
                "MASVS-RESILIENCE",
            ]

        return mapping

    def _generate_compliance_recommendations(self, assessment: ComplianceAssessment) -> List[str]:
        """Generate compliance-specific recommendations."""
        recommendations = []

        if assessment.compliance_percentage < 50:
            recommendations.append("Significant compliance improvements needed across multiple controls")
        elif assessment.compliance_percentage < 80:
            recommendations.append("Address remaining compliance gaps to achieve better security posture")

        if assessment.failed_controls > 0:
            recommendations.append(
                f"Focus on {assessment.failed_controls} failed controls for immediate compliance improvement"
            )

        recommendations.extend(
            [
                "Implement continuous compliance monitoring",
                "Regular compliance assessments and audits",
                "Staff training on compliance requirements",
            ]
        )

        return recommendations


class CustomReportGenerator(BaseReportGenerator):
    """Generator for custom report structures."""

    def __init__(self, template_config: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.template_config = template_config

    def generate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate custom report based on template configuration."""
        findings = [SecurityFinding(**f) if isinstance(f, dict) else f for f in data["findings"]]

        # Apply filters
        filtered_findings = self.apply_filters(findings)

        # Create custom sections based on template
        sections = []
        for section_config in self.template_config.get("sections", []):
            section = self._create_custom_section(section_config, filtered_findings)
            sections.append(section)

        # Create metadata
        metadata = create_default_metadata(ReportType.CUSTOM, self.config.output_format)
        metadata.title = self.template_config.get("title", "Custom Security Report")
        metadata.total_findings = len(filtered_findings)

        return {
            "metadata": self._asdict_with_enum_values(metadata),
            "sections": [self._asdict_with_enum_values(section) for section in sections],
            "template_config": self.template_config,
            "generated_at": datetime.now().isoformat(),
        }

    def _create_custom_section(self, section_config: Dict[str, Any], findings: List[SecurityFinding]) -> ReportSection:
        """Create custom section based on configuration."""
        section_id = section_config.get("id", "custom_section")
        title = section_config.get("title", "Custom Section")

        # Filter findings for this section
        section_findings = findings
        if "filters" in section_config:
            section_findings = self._apply_section_filters(findings, section_config["filters"])

        content = section_config.get("content", f"Custom section with {len(section_findings)} findings")

        section = ReportSection(
            id=section_id, title=title, content=content, findings=section_findings, order=section_config.get("order", 0)
        )

        return section

    def _apply_section_filters(self, findings: List[SecurityFinding], filters: Dict[str, Any]) -> List[SecurityFinding]:
        """Apply section-specific filters."""
        filtered = findings

        if "severity" in filters:
            target_severities = [SeverityLevel(s) for s in filters["severity"]]
            filtered = [f for f in filtered if f.severity in target_severities]

        if "category" in filters:
            filtered = [f for f in filtered if f.category in filters["category"]]

        if "min_confidence" in filters:
            filtered = [f for f in filtered if f.confidence >= filters["min_confidence"]]

        return filtered


class DynamicCoordinationReportGenerator(BaseReportGenerator):
    """Generator for coordinated dynamic analysis reports."""

    def generate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate full dynamic coordination analysis report."""
        if not self.validate_input(data):
            raise ValueError("Invalid input data structure for dynamic coordination analysis")

        # Extract coordination result
        coordination_result = data.get("coordination_result")
        if isinstance(coordination_result, dict):
            # Convert dict to DynamicCoordinationAnalysisResult if needed
            coordination_result = self._dict_to_coordination_result(coordination_result)

        context = data.get("context", {})

        # Create report metadata
        metadata = create_default_metadata(ReportType.DYNAMIC_COORDINATION_ANALYSIS, self.config.output_format)
        metadata.target_application = coordination_result.package_name
        metadata.total_findings = coordination_result.total_findings

        # Calculate duration if available
        duration = coordination_result.get_analysis_duration()
        if duration:
            metadata.analysis_duration = duration.total_seconds()

        # Build report sections
        sections = []

        # Executive summary
        sections.append(self._create_coordination_summary_section(coordination_result))

        # Component analysis section
        sections.append(self._create_component_analysis_section(coordination_result.component_results))

        # Runtime pattern detection section
        if coordination_result.runtime_patterns:
            sections.append(self._create_runtime_patterns_section(coordination_result.runtime_patterns))

        # Correlation analysis section
        if coordination_result.correlated_findings:
            sections.append(self._create_correlation_analysis_section(coordination_result.correlated_findings))

        # Performance and infrastructure section
        sections.append(self._create_performance_section(coordination_result))

        # Detailed findings section
        all_findings = self._collect_all_findings(coordination_result)
        if all_findings:
            sections.append(self._create_detailed_findings_section(all_findings))

        # Recommendations section
        sections.append(self._create_coordination_recommendations_section(coordination_result))

        # Generate report structure
        report = {
            "metadata": self._asdict_with_enum_values(metadata),
            "coordination_summary": self._generate_coordination_executive_summary(coordination_result),
            "sections": [self._asdict_with_enum_values(section) for section in sections],
            "statistics": self._calculate_coordination_statistics(coordination_result),
            "context": context,
            "generated_at": datetime.now().isoformat(),
        }

        return report

    def _dict_to_coordination_result(self, data: Dict[str, Any]) -> DynamicCoordinationAnalysisResult:
        """Convert dictionary data to DynamicCoordinationAnalysisResult."""
        # This is a simplified conversion - in practice you'd want more reliable handling
        return DynamicCoordinationAnalysisResult(
            coordination_id=data.get("coordination_id", "unknown"),
            analysis_profile=data.get("analysis_profile", "unknown"),
            package_name=data.get("package_name", "unknown"),
            start_time=datetime.now(),
            total_findings=data.get("total_findings", 0),
            correlation_rate=data.get("correlation_rate", 0.0),
            frida_enabled=data.get("frida_enabled", False),
            runtime_patterns_enabled=data.get("runtime_patterns_enabled", False),
            correlation_enabled=data.get("correlation_enabled", False),
        )

    def _create_coordination_summary_section(self, result: DynamicCoordinationAnalysisResult) -> ReportSection:
        """Create coordination analysis summary section."""
        summary_content = f"""
        Coordinated Dynamic Analysis Summary

        Analysis Profile: {result.analysis_profile}
        Target Package: {result.package_name}
        Total Findings: {result.total_findings}
        Correlation Rate: {result.correlation_rate:.1%}
        Cross-Component Validations: {result.cross_component_validations}

        Infrastructure Status:
        • Enhanced Frida: {'✅ Enabled' if result.frida_enabled else '❌ Disabled'}
        • Runtime Patterns: {'✅ Enabled' if result.runtime_patterns_enabled else '❌ Disabled'}
        • Correlation Engine: {'✅ Enabled' if result.correlation_enabled else '❌ Disabled'}
        """

        return ReportSection(
            id="coordination_summary", title="Coordination Analysis Summary", content=summary_content.strip(), order=1
        )

    def _create_component_analysis_section(self, components: List[ComponentAnalysisResult]) -> ReportSection:
        """Create component analysis section."""
        content = "Component Analysis Results:\n\n"

        for component in components:
            content += f"🔧 {component.component_name} ({component.component_type})\n"
            content += f"   Status: {component.status}\n"
            content += f"   Findings: {component.findings_count}\n"
            content += f"   Execution Time: {component.execution_time:.2f}s\n"
            if component.error_message:
                content += f"   Error: {component.error_message}\n"
            content += "\n"

        section = ReportSection(id="component_analysis", title="Component Analysis Results", content=content, order=2)

        return section

    def _create_runtime_patterns_section(self, patterns: List[RuntimePatternResult]) -> ReportSection:
        """Create runtime vulnerability patterns section."""
        content = f"Runtime Vulnerability Pattern Detection Results ({len(patterns)} patterns detected):\n\n"

        # Group by severity
        severity_groups = {}
        for pattern in patterns:
            if pattern.severity not in severity_groups:
                severity_groups[pattern.severity] = []
            severity_groups[pattern.severity].append(pattern)

        for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW]:
            if severity in severity_groups:
                content += f"🚨 {severity.value.upper()} Severity ({len(severity_groups[severity])} patterns):\n"
                for pattern in severity_groups[severity]:
                    content += f"   • {pattern.pattern_name} (confidence: {pattern.confidence:.2f})\n"
                    if pattern.cwe_id:
                        content += f"     CWE: {pattern.cwe_id}\n"
                    if pattern.evidence_count > 0:
                        content += f"     Evidence: {pattern.evidence_count} items\n"
                content += "\n"

        return ReportSection(id="runtime_patterns", title="Runtime Vulnerability Patterns", content=content, order=3)

    def _create_correlation_analysis_section(self, correlations: List[CorrelationAnalysisResult]) -> ReportSection:
        """Create correlation analysis section."""
        content = f"Test Result Correlation Analysis ({len(correlations)} correlations found):\n\n"

        # Group by correlation strategy
        strategy_groups = {}
        for corr in correlations:
            if corr.correlation_strategy not in strategy_groups:
                strategy_groups[corr.correlation_strategy] = []
            strategy_groups[corr.correlation_strategy].append(corr)

        for strategy, correlations_list in strategy_groups.items():
            content += f"🔗 {strategy.title()} Correlation ({len(correlations_list)} findings):\n"
            for corr in correlations_list:
                content += f"   • Primary: {corr.primary_finding.title}\n"
                content += f"     Supporting: {len(corr.supporting_findings)} findings\n"
                content += f"     Sources: {', '.join(corr.component_sources)}\n"
                content += f"     Confidence: {corr.correlation_confidence:.2f}\n"
                if corr.false_positive_indicators:
                    content += f"     FP Indicators: {', '.join(corr.false_positive_indicators)}\n"
            content += "\n"

        return ReportSection(
            id="correlation_analysis", title="Cross-Component Correlation Analysis", content=content, order=4
        )

    def _create_performance_section(self, result: DynamicCoordinationAnalysisResult) -> ReportSection:
        """Create performance and infrastructure section."""
        content = f"""
        Performance Metrics:

        Coordination Overhead: {result.coordination_overhead:.2f}s
        Shared Resource Efficiency: {result.shared_resource_efficiency:.1%}
        False Positive Rate: {result.false_positive_rate:.1%}

        Infrastructure Utilization:
        • Enhanced Frida Infrastructure: {'Active' if result.frida_enabled else 'Inactive'}
        • Runtime Pattern Detection: {'Active' if result.runtime_patterns_enabled else 'Inactive'}
        • Advanced Correlation Engine: {'Active' if result.correlation_enabled else 'Inactive'}
        """

        return ReportSection(
            id="performance_metrics", title="Performance & Infrastructure Analysis", content=content.strip(), order=5
        )

    def _create_detailed_findings_section(self, findings: List[SecurityFinding]) -> ReportSection:
        """Create detailed findings section."""
        content = f"Detailed Security Findings ({len(findings)} total):\n\n"

        # Group by severity and show top findings
        severity_groups = group_findings_by_severity(findings)

        for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM]:
            if severity in severity_groups and severity_groups[severity]:
                content += f"🔥 {severity.value.upper()} Severity Findings:\n"
                for finding in severity_groups[severity][:5]:  # Show top 5
                    content += f"   • {finding.title}\n"
                    content += f"     Location: {finding.location}\n"
                    content += f"     Confidence: {finding.confidence:.2f}\n"
                    if finding.cwe_id:
                        content += f"     CWE: {finding.cwe_id}\n"
                content += "\n"

        return ReportSection(id="detailed_findings", title="Detailed Security Findings", content=content, order=6)

    def _create_coordination_recommendations_section(self, result: DynamicCoordinationAnalysisResult) -> ReportSection:
        """Create recommendations section."""
        recommendations = []

        # Infrastructure recommendations
        if not result.frida_enabled:
            recommendations.append(
                "Consider enabling Enhanced Frida infrastructure for deeper dynamic analysis capabilities"
            )

        if not result.runtime_patterns_enabled:
            recommendations.append("Enable runtime vulnerability pattern detection for real-time security monitoring")

        if not result.correlation_enabled:
            recommendations.append("Activate correlation engine to improve finding accuracy and reduce false positives")

        # Analysis recommendations based on findings
        if result.correlation_rate < 0.5:
            recommendations.append("Low correlation rate detected - consider running longer analysis duration")

        if result.false_positive_rate > 0.3:
            recommendations.append("High false positive rate - review and tune detection patterns")

        if len(result.component_results) < 3:
            recommendations.append("Consider enabling additional analysis components for full coverage")

        content = "Coordination Analysis Recommendations:\n\n"
        for i, rec in enumerate(recommendations, 1):
            content += f"{i}. {rec}\n"

        if not recommendations:
            content += "No specific recommendations - analysis configuration appears optimal.\n"

        return ReportSection(
            id="recommendations", title="Analysis Optimization Recommendations", content=content, order=7
        )

    def _collect_all_findings(self, result: DynamicCoordinationAnalysisResult) -> List[SecurityFinding]:
        """Collect all findings from different sources."""
        all_findings = []

        # Collect from components
        for component in result.component_results:
            all_findings.extend(component.findings)

        # Collect from correlations
        for corr in result.correlated_findings:
            all_findings.append(corr.primary_finding)
            all_findings.extend(corr.supporting_findings)

        # Add uncorrelated findings
        all_findings.extend(result.uncorrelated_findings)

        return all_findings

    def _generate_coordination_executive_summary(self, result: DynamicCoordinationAnalysisResult) -> Dict[str, Any]:
        """Generate executive summary for coordination analysis."""
        return {
            "analysis_profile": result.analysis_profile,
            "total_findings": result.total_findings,
            "components_active": len(result.component_results),
            "correlation_rate": result.correlation_rate,
            "infrastructure_health": {
                "frida": result.frida_enabled,
                "patterns": result.runtime_patterns_enabled,
                "correlation": result.correlation_enabled,
            },
            "severity_distribution": result.get_severity_distribution(),
            "component_summary": result.get_component_summary(),
        }

    def _calculate_coordination_statistics(self, result: DynamicCoordinationAnalysisResult) -> Dict[str, Any]:
        """Calculate full coordination statistics."""
        return {
            "coordination_metrics": {
                "total_findings": result.total_findings,
                "correlation_rate": result.correlation_rate,
                "cross_validations": result.cross_component_validations,
                "false_positive_rate": result.false_positive_rate,
            },
            "performance_metrics": {
                "coordination_overhead": result.coordination_overhead,
                "resource_efficiency": result.shared_resource_efficiency,
            },
            "component_metrics": {
                "components_executed": len(result.component_results),
                "successful_components": len([c for c in result.component_results if c.status == "completed"]),
                "failed_components": len([c for c in result.component_results if c.status == "failed"]),
            },
            "pattern_metrics": {
                "runtime_patterns_detected": len(result.runtime_patterns),
                "pattern_severities": {
                    severity.value: len([p for p in result.runtime_patterns if p.severity == severity])
                    for severity in SeverityLevel
                },
            },
        }


# Main report generator factory
class ReportGenerator:
    """Main factory for creating report generators."""

    @staticmethod
    def create_generator(report_type: ReportType, **kwargs) -> BaseReportGenerator:
        """Create appropriate generator based on report type."""
        if report_type == ReportType.SECURITY_ANALYSIS:
            return SecurityAnalysisReportGenerator(**kwargs)
        elif report_type == ReportType.EXECUTIVE_SUMMARY:
            return ExecutiveSummaryGenerator(**kwargs)
        elif report_type == ReportType.TECHNICAL_DETAILS:
            return TechnicalReportGenerator(**kwargs)
        elif report_type == ReportType.COMPLIANCE_ASSESSMENT:
            return ComplianceReportGenerator(**kwargs)
        elif report_type == ReportType.DYNAMIC_COORDINATION_ANALYSIS:
            return DynamicCoordinationReportGenerator(**kwargs)
        elif report_type == ReportType.CUSTOM:
            return CustomReportGenerator(**kwargs)
        else:
            return SecurityAnalysisReportGenerator(**kwargs)
