#!/usr/bin/env python3
"""
Finding Normalization Utilities - Convert Legacy Formats to Canonical Schema
===========================================================================

This module provides utilities to normalize various existing vulnerability
finding formats across AODS plugins into the canonical schema v1.

Features:
- Automatic detection of source finding format
- Intelligent field mapping and conversion
- Evidence preservation and enhancement
- Taxonomy mapping and enrichment
- Confidence score normalization
- Metadata preservation

Version: 1.0
Author: AODS Development Team
Date: 2025-01-04
"""

import logging
from typing import Dict, List, Any, Optional, Union
from datetime import datetime

from .canonical_schema_v1 import (
    CanonicalFinding,
    VulnerabilityEvidence,
    EvidenceLocation,
    SecurityTaxonomy,
    RemediationGuidance,
    SeverityLevel,
    VulnerabilityCategory,
    DetectionMethod,
)

logger = logging.getLogger(__name__)


class FindingNormalizer:
    """
    Main normalizer class that converts various finding formats to canonical schema.
    """

    def __init__(self):
        """Initialize the normalizer with format mappings."""
        self.severity_mappings = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
            "information": SeverityLevel.INFO,
            "informational": SeverityLevel.INFO,
            "warning": SeverityLevel.LOW,
            "error": SeverityLevel.MEDIUM,
            "severe": SeverityLevel.HIGH,
        }

        self.category_mappings = {
            # Legacy category mappings
            "api_security": VulnerabilityCategory.API_SECURITY,
            "cloud_misconfig": VulnerabilityCategory.CLOUD_MISCONFIG,
            "modern_auth": VulnerabilityCategory.MODERN_AUTH,
            "supply_chain": VulnerabilityCategory.SUPPLY_CHAIN,
            "privacy_compliance": VulnerabilityCategory.PRIVACY_COMPLIANCE,
            "network_security": VulnerabilityCategory.NETWORK_SECURITY,
            "injection_vulnerabilities": VulnerabilityCategory.INJECTION_VULNERABILITIES,
            "anti_tampering": VulnerabilityCategory.ANTI_TAMPERING,
            "webview_security": VulnerabilityCategory.WEBVIEW_SECURITY,
            "ipc_security": VulnerabilityCategory.IPC_SECURITY,
            "library_vulnerabilities": VulnerabilityCategory.LIBRARY_VULNERABILITIES,
            # OWASP Mobile Top 10 mappings
            "improper_platform_usage": VulnerabilityCategory.IMPROPER_PLATFORM_USAGE,
            "insecure_data_storage": VulnerabilityCategory.INSECURE_DATA_STORAGE,
            "insecure_communication": VulnerabilityCategory.INSECURE_COMMUNICATION,
            "insecure_authentication": VulnerabilityCategory.INSECURE_AUTHENTICATION,
            "insufficient_cryptography": VulnerabilityCategory.INSUFFICIENT_CRYPTOGRAPHY,
            "insecure_authorization": VulnerabilityCategory.INSECURE_AUTHORIZATION,
            "client_code_quality": VulnerabilityCategory.CLIENT_CODE_QUALITY,
            "code_tampering": VulnerabilityCategory.CODE_TAMPERING,
            "reverse_engineering": VulnerabilityCategory.REVERSE_ENGINEERING,
            "extraneous_functionality": VulnerabilityCategory.EXTRANEOUS_FUNCTIONALITY,
            # Common alternative names
            "data_storage": VulnerabilityCategory.INSECURE_DATA_STORAGE,
            "communication": VulnerabilityCategory.INSECURE_COMMUNICATION,
            "authentication": VulnerabilityCategory.INSECURE_AUTHENTICATION,
            "authorization": VulnerabilityCategory.INSECURE_AUTHORIZATION,
            "cryptography": VulnerabilityCategory.INSUFFICIENT_CRYPTOGRAPHY,
            "code_quality": VulnerabilityCategory.CLIENT_CODE_QUALITY,
            "tampering": VulnerabilityCategory.CODE_TAMPERING,
            "reverse_eng": VulnerabilityCategory.REVERSE_ENGINEERING,
        }

        self.detection_method_mappings = {
            "static": DetectionMethod.STATIC_ANALYSIS,
            "dynamic": DetectionMethod.DYNAMIC_ANALYSIS,
            "manifest": DetectionMethod.MANIFEST_ANALYSIS,
            "binary": DetectionMethod.BINARY_ANALYSIS,
            "behavioral": DetectionMethod.BEHAVIORAL_ANALYSIS,
            "pattern": DetectionMethod.PATTERN_MATCHING,
            "ml": DetectionMethod.ML_DETECTION,
            "heuristic": DetectionMethod.HEURISTIC_ANALYSIS,
            "signature": DetectionMethod.SIGNATURE_BASED,
            "hybrid": DetectionMethod.HYBRID_ANALYSIS,
            "regex": DetectionMethod.PATTERN_MATCHING,
            "machine_learning": DetectionMethod.ML_DETECTION,
        }

    def normalize_finding(
        self, finding_data: Union[Dict[str, Any], Any], source_format: Optional[str] = None
    ) -> CanonicalFinding:
        """
        Normalize a finding from any format to canonical schema.

        Args:
            finding_data: The finding data (dict or object)
            source_format: Optional hint about the source format

        Returns:
            CanonicalFinding: Normalized finding in canonical format
        """
        try:
            # Auto-detect format if not specified
            if source_format is None:
                source_format = self._detect_format(finding_data)

            # Route to appropriate normalizer
            if source_format == "base_vulnerability":
                return self._normalize_base_vulnerability(finding_data)
            elif source_format == "security_finding":
                return self._normalize_security_finding(finding_data)
            elif source_format == "vulnerability_finding":
                return self._normalize_vulnerability_finding(finding_data)
            elif source_format == "plugin_finding":
                return self._normalize_plugin_finding(finding_data)
            elif source_format == "anti_tampering_vulnerability":
                return self._normalize_anti_tampering_vulnerability(finding_data)
            elif source_format == "dict":
                return self._normalize_dict(finding_data)
            else:
                # Generic normalization for unknown formats
                return self._normalize_generic(finding_data)

        except Exception as e:
            logger.error(f"Failed to normalize finding: {e}")
            # Return a basic finding with error information
            return CanonicalFinding(
                title=f"Normalization Error: {str(e)}",
                description="Failed to normalize finding from legacy format",
                category=VulnerabilityCategory.CLIENT_CODE_QUALITY,
                severity=SeverityLevel.INFO,
                confidence=0.1,
            )

    def _detect_format(self, finding_data: Union[Dict[str, Any], Any]) -> str:
        """Auto-detect the format of the finding data."""
        if isinstance(finding_data, dict):
            # Check for specific field combinations to identify format
            if "vulnerability_type" in finding_data:
                return "base_vulnerability"
            elif "matches" in finding_data and "plugin_name" in finding_data:
                return "base_vulnerability"
            elif "security_impact" in finding_data and "business_impact" in finding_data:
                return "security_finding"
            elif "plugin_source" in finding_data and "technical_details" in finding_data:
                return "security_finding"
            elif "finding_id" in finding_data and "evidence" in finding_data:
                return "vulnerability_finding"
            else:
                return "dict"
        else:
            # Check object type and attributes
            class_name = finding_data.__class__.__name__.lower()
            if "basevulnerability" in class_name:
                return "base_vulnerability"
            elif "securityfinding" in class_name:
                return "security_finding"
            elif "vulnerabilityfinding" in class_name:
                return "vulnerability_finding"
            elif "pluginfinding" in class_name:
                return "plugin_finding"
            elif "antitamperingvulnerability" in class_name:
                return "anti_tampering_vulnerability"
            else:
                return "generic"

    def _normalize_base_vulnerability(self, finding: Any) -> CanonicalFinding:
        """Normalize BaseVulnerability format."""
        # Handle both dict and object formats
        if isinstance(finding, dict):

            def get_attr(obj, key, default=None):
                return obj.get(key, default)

        else:

            def get_attr(obj, key, default=None):
                return getattr(obj, key, default)

        # Extract core fields
        title = get_attr(finding, "title", "Unknown Vulnerability")
        description = get_attr(finding, "description", "")

        # Map severity
        severity_str = str(get_attr(finding, "severity", "MEDIUM")).lower()
        severity = self.severity_mappings.get(severity_str, SeverityLevel.MEDIUM)

        # Map category
        vuln_type = get_attr(finding, "vulnerability_type", None)
        if vuln_type:
            category_str = str(vuln_type).lower().replace("vulnerabilitytype.", "")
            category = self.category_mappings.get(category_str, VulnerabilityCategory.CLIENT_CODE_QUALITY)
        else:
            category = VulnerabilityCategory.CLIENT_CODE_QUALITY

        # Extract confidence
        confidence = float(get_attr(finding, "confidence", 0.5))

        # Create evidence from matches
        evidence_list = []
        matches = get_attr(finding, "matches", [])
        for match in matches:
            # Handle both dict and object formats for match
            if isinstance(match, dict):

                def get_match_attr(obj, key, default=None):
                    return obj.get(key, default)

            else:

                def get_match_attr(obj, key, default=None):
                    return getattr(obj, key, default)

            evidence = VulnerabilityEvidence(
                evidence_type="code_snippet",
                content=get_match_attr(match, "matched_text", ""),
                location=(
                    EvidenceLocation(
                        file_path=get_match_attr(match, "file_path", ""),
                        line_number=get_match_attr(match, "line_number", None),
                        function_name=get_match_attr(match, "function_name", None),
                    )
                    if get_match_attr(match, "file_path")
                    else None
                ),
                confidence=get_match_attr(match, "confidence", 1.0),
                source_plugin=get_attr(finding, "plugin_name", ""),
            )
            evidence_list.append(evidence)

        # Create taxonomy
        taxonomy = SecurityTaxonomy(
            cwe_ids=[get_attr(finding, "cwe_id", "")] if get_attr(finding, "cwe_id", None) else [],
            owasp_categories=(
                [get_attr(finding, "owasp_category", "")] if get_attr(finding, "owasp_category", None) else []
            ),
            masvs_controls=get_attr(finding, "masvs_controls", []),
            cvss_score=get_attr(finding, "cvss_score", None),
        )

        # Create remediation
        remediation = RemediationGuidance(
            summary=get_attr(finding, "remediation", ""),
            detailed_steps=get_attr(finding, "recommendations", []),
            priority=get_attr(finding, "remediation_priority", "MEDIUM"),
        )

        # Create canonical finding
        finding_id = get_attr(finding, "vulnerability_id", None)
        canonical_kwargs = {
            "title": title,
            "description": description,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence_list,
            "taxonomy": taxonomy,
            "remediation": remediation,
            "detector_name": get_attr(finding, "plugin_name", ""),
            "detection_timestamp": get_attr(finding, "analysis_timestamp", datetime.now().isoformat()),
            "tags": set(get_attr(finding, "tags", [])),
            "metadata": get_attr(finding, "metadata", {}),
        }

        # Only set finding_id if it's provided, otherwise let the default factory generate it
        if finding_id:
            canonical_kwargs["finding_id"] = finding_id

        canonical = CanonicalFinding(**canonical_kwargs)

        return canonical

    def _normalize_security_finding(self, finding: Any) -> CanonicalFinding:
        """Normalize SecurityFinding format."""
        # Handle both dict and object formats
        if isinstance(finding, dict):

            def get_attr(obj, key, default=None):
                return obj.get(key, default)

        else:

            def get_attr(obj, key, default=None):
                return getattr(obj, key, default)

        # Extract core fields
        title = get_attr(finding, "title", "Unknown Security Finding")
        description = get_attr(finding, "description", "")

        # Map severity
        severity_str = str(get_attr(finding, "severity", "MEDIUM")).lower()
        severity = self.severity_mappings.get(severity_str, SeverityLevel.MEDIUM)

        # Map category
        category_str = str(get_attr(finding, "category", "client_code_quality")).lower()
        category = self.category_mappings.get(category_str, VulnerabilityCategory.CLIENT_CODE_QUALITY)

        # Extract confidence
        confidence = float(get_attr(finding, "confidence", 0.5))

        # Create evidence
        evidence_content = get_attr(finding, "evidence", "")
        if isinstance(evidence_content, dict):
            # Rich evidence format
            evidence_list = []
            for key, value in evidence_content.items():
                evidence = VulnerabilityEvidence(
                    evidence_type=key, content=str(value), source_plugin=get_attr(finding, "plugin_source", "")
                )
                evidence_list.append(evidence)
        else:
            # Simple string evidence
            evidence_list = (
                [
                    VulnerabilityEvidence(
                        evidence_type="text",
                        content=str(evidence_content),
                        location=(
                            EvidenceLocation(
                                file_path=get_attr(finding, "file_path", ""),
                                line_number=get_attr(finding, "line_number", None),
                            )
                            if get_attr(finding, "file_path")
                            else None
                        ),
                        source_plugin=get_attr(finding, "plugin_source", ""),
                    )
                ]
                if evidence_content
                else []
            )

        # Create taxonomy
        taxonomy = SecurityTaxonomy(
            cwe_ids=[get_attr(finding, "cwe_id", "")] if get_attr(finding, "cwe_id") else [],
            owasp_categories=[get_attr(finding, "owasp_category", "")] if get_attr(finding, "owasp_category") else [],
            masvs_controls=[get_attr(finding, "masvs_control", "")] if get_attr(finding, "masvs_control") else [],
            nist_controls=[get_attr(finding, "nist_control", "")] if get_attr(finding, "nist_control") else [],
        )

        # Create remediation
        remediation = RemediationGuidance(
            summary=get_attr(finding, "recommendation", ""),
            remediation_effort=get_attr(finding, "remediation_effort", "MEDIUM"),
        )

        # Create canonical finding
        canonical = CanonicalFinding(
            finding_id=get_attr(finding, "id", ""),
            title=title,
            description=description,
            category=category,
            severity=severity,
            confidence=confidence,
            evidence=evidence_list,
            taxonomy=taxonomy,
            remediation=remediation,
            detector_name=get_attr(finding, "plugin_source", ""),
            metadata=get_attr(finding, "technical_details", {}) or {},
        )

        return canonical

    def _normalize_vulnerability_finding(self, finding: Any) -> CanonicalFinding:
        """Normalize VulnerabilityFinding format."""
        # Handle both dict and object formats
        if isinstance(finding, dict):

            def get_attr(obj, key, default=None):
                return obj.get(key, default)

        else:

            def get_attr(obj, key, default=None):
                return getattr(obj, key, default)

        # Extract core fields
        title = get_attr(finding, "title", "Unknown Vulnerability")
        description = get_attr(finding, "description", "")

        # Map severity
        severity_str = str(get_attr(finding, "severity", "MEDIUM")).lower()
        severity = self.severity_mappings.get(severity_str, SeverityLevel.MEDIUM)

        # Map category
        category_str = str(get_attr(finding, "category", "client_code_quality")).lower()
        category = self.category_mappings.get(category_str, VulnerabilityCategory.CLIENT_CODE_QUALITY)

        # Extract confidence
        confidence = float(get_attr(finding, "confidence", 0.5))

        # Create evidence from evidence list
        evidence_list = []
        evidence_data = get_attr(finding, "evidence", [])
        if isinstance(evidence_data, list):
            for evidence_item in evidence_data:
                evidence = VulnerabilityEvidence(
                    evidence_type="text",
                    content=str(evidence_item),
                    source_plugin=get_attr(finding, "detector_name", ""),
                )
                evidence_list.append(evidence)
        elif evidence_data:
            evidence_list = [
                VulnerabilityEvidence(
                    evidence_type="text",
                    content=str(evidence_data),
                    source_plugin=get_attr(finding, "detector_name", ""),
                )
            ]

        # Create taxonomy
        taxonomy = SecurityTaxonomy(
            cwe_ids=get_attr(finding, "cwe_ids", []),
            owasp_categories=get_attr(finding, "owasp_refs", []),
            masvs_controls=get_attr(finding, "masvs_refs", []),
        )

        # Create remediation
        remediation = RemediationGuidance(
            summary=get_attr(finding, "security_impact", ""),
            detailed_steps=get_attr(finding, "recommendations", []),
            remediation_effort=get_attr(finding, "remediation_effort", "MEDIUM"),
            priority=get_attr(finding, "remediation_priority", "MEDIUM"),
        )

        # Create canonical finding
        canonical = CanonicalFinding(
            finding_id=get_attr(finding, "finding_id", ""),
            title=title,
            description=description,
            category=category,
            subcategory=get_attr(finding, "subcategory", ""),
            severity=severity,
            confidence=confidence,
            evidence=evidence_list,
            taxonomy=taxonomy,
            remediation=remediation,
            detector_name=get_attr(finding, "detector_name", ""),
            detection_timestamp=get_attr(finding, "timestamp", datetime.now().isoformat()),
            affected_components=get_attr(finding, "affected_components", []),
            tags=set(get_attr(finding, "tags", [])),
        )

        return canonical

    def _normalize_plugin_finding(self, finding: Any) -> CanonicalFinding:
        """Normalize PluginFinding format."""
        # Handle both dict and object formats
        if isinstance(finding, dict):

            def get_attr(obj, key, default=None):
                return obj.get(key, default)

        else:

            def get_attr(obj, key, default=None):
                return getattr(obj, key, default)

        # Extract core fields
        title = get_attr(finding, "title", "Plugin Finding")
        description = get_attr(finding, "description", "")

        # Map severity
        severity_str = str(get_attr(finding, "severity", "MEDIUM")).lower()
        severity = self.severity_mappings.get(severity_str, SeverityLevel.MEDIUM)

        # Extract confidence
        confidence = float(get_attr(finding, "confidence", 0.5))

        # Create evidence
        evidence_data = get_attr(finding, "evidence", "")
        evidence_list = (
            [
                VulnerabilityEvidence(
                    evidence_type="plugin_output",
                    content=str(evidence_data),
                    location=(
                        EvidenceLocation(
                            file_path=get_attr(finding, "file_path", ""),
                            line_number=get_attr(finding, "line_number", None),
                        )
                        if get_attr(finding, "file_path")
                        else None
                    ),
                    source_plugin=get_attr(finding, "plugin_name", ""),
                )
            ]
            if evidence_data
            else []
        )

        # Create canonical finding
        canonical = CanonicalFinding(
            finding_id=get_attr(finding, "finding_id", ""),
            title=title,
            description=description,
            category=VulnerabilityCategory.CLIENT_CODE_QUALITY,  # Default for plugin findings
            severity=severity,
            confidence=confidence,
            evidence=evidence_list,
            detector_name=get_attr(finding, "plugin_name", ""),
            metadata=get_attr(finding, "metadata", {}) or {},
        )

        return canonical

    def _normalize_anti_tampering_vulnerability(self, finding: Any) -> CanonicalFinding:
        """Normalize AntiTamperingVulnerability format."""
        # Handle both dict and object formats
        if isinstance(finding, dict):

            def get_attr(obj, key, default=None):
                return obj.get(key, default)

        else:

            def get_attr(obj, key, default=None):
                return getattr(obj, key, default)

        # Extract core fields
        title = get_attr(finding, "title", "Anti-Tampering Vulnerability")
        description = get_attr(finding, "description", "")

        # Map severity
        severity_str = str(get_attr(finding, "severity", "MEDIUM")).lower()
        severity = self.severity_mappings.get(severity_str, SeverityLevel.MEDIUM)

        # Extract confidence
        confidence = float(get_attr(finding, "confidence", 0.5))

        # Create evidence
        evidence_content = get_attr(finding, "evidence", "")
        evidence_list = (
            [
                VulnerabilityEvidence(
                    evidence_type="anti_tampering_analysis",
                    content=str(evidence_content),
                    location=(
                        EvidenceLocation(
                            file_path=get_attr(finding, "file_path", ""),
                            line_number=get_attr(finding, "line_number", None),
                        )
                        if get_attr(finding, "file_path")
                        else None
                    ),
                    source_plugin="anti_tampering_analysis",
                )
            ]
            if evidence_content
            else []
        )

        # Create taxonomy
        taxonomy = SecurityTaxonomy(
            cwe_ids=[get_attr(finding, "cwe_id", "")] if get_attr(finding, "cwe_id") else [],
            masvs_controls=get_attr(finding, "masvs_refs", []),
        )

        # Create remediation
        remediation = RemediationGuidance(
            summary=get_attr(finding, "remediation", ""),
            business_justification=get_attr(finding, "business_impact", ""),
        )

        # Create canonical finding
        canonical = CanonicalFinding(
            finding_id=get_attr(finding, "vulnerability_id", ""),
            title=title,
            description=description,
            category=VulnerabilityCategory.ANTI_TAMPERING,
            severity=severity,
            confidence=confidence,
            evidence=evidence_list,
            taxonomy=taxonomy,
            remediation=remediation,
            detector_name="anti_tampering_analysis",
            tags=set(get_attr(finding, "tags", [])),
        )

        return canonical

    def _normalize_dict(self, finding: Dict[str, Any]) -> CanonicalFinding:
        """Normalize generic dictionary format."""
        return self._normalize_generic(finding)

    def _normalize_generic(self, finding: Any) -> CanonicalFinding:
        """Generic normalization for unknown formats."""
        # Handle both dict and object formats
        if isinstance(finding, dict):

            def get_attr(obj, key, default=None):
                return obj.get(key, default)

        else:

            def get_attr(obj, key, default=None):
                return getattr(obj, key, default)

        # Extract basic fields with multiple possible names
        title = (
            get_attr(finding, "title")
            or get_attr(finding, "name")
            or get_attr(finding, "vulnerability_name")
            or "Unknown Finding"
        )

        description = (
            get_attr(finding, "description") or get_attr(finding, "details") or get_attr(finding, "message") or ""
        )

        # Map severity with multiple possible names
        severity_value = (
            get_attr(finding, "severity") or get_attr(finding, "priority") or get_attr(finding, "risk") or "MEDIUM"
        )
        severity_str = str(severity_value).lower()
        severity = self.severity_mappings.get(severity_str, SeverityLevel.MEDIUM)

        # Extract confidence with multiple possible names
        confidence_value = (
            get_attr(finding, "confidence") or get_attr(finding, "certainty") or get_attr(finding, "probability") or 0.5
        )
        confidence = float(confidence_value)

        # Create basic evidence
        evidence_content = (
            get_attr(finding, "evidence") or get_attr(finding, "proof") or get_attr(finding, "details") or ""
        )
        evidence_list = (
            [VulnerabilityEvidence(evidence_type="generic", content=str(evidence_content), source_plugin="unknown")]
            if evidence_content
            else []
        )

        # Map category with multiple possible names
        category_value = (
            get_attr(finding, "category")
            or get_attr(finding, "type")
            or get_attr(finding, "vulnerability_category")
            or "client_code_quality"
        )
        category_str = str(category_value).lower()
        category = self.category_mappings.get(category_str, VulnerabilityCategory.CLIENT_CODE_QUALITY)

        # Create canonical finding with defaults
        canonical = CanonicalFinding(
            title=title,
            description=description,
            category=category,
            severity=severity,
            confidence=confidence,
            evidence=evidence_list,
            detector_name=get_attr(finding, "source") or "unknown",
        )

        return canonical

    def normalize_batch(self, findings: List[Union[Dict[str, Any], Any]]) -> List[CanonicalFinding]:
        """Normalize a batch of findings."""
        normalized_findings = []

        for finding in findings:
            try:
                normalized = self.normalize_finding(finding)
                normalized_findings.append(normalized)
            except Exception as e:
                logger.error(f"Failed to normalize finding in batch: {e}")
                # Continue with other findings
                continue

        return normalized_findings


# Convenience functions for common use cases
def normalize_finding(
    finding_data: Union[Dict[str, Any], Any], source_format: Optional[str] = None
) -> CanonicalFinding:
    """Convenience function to normalize a single finding."""
    normalizer = FindingNormalizer()
    return normalizer.normalize_finding(finding_data, source_format)


def normalize_findings_batch(findings: List[Union[Dict[str, Any], Any]]) -> List[CanonicalFinding]:
    """Convenience function to normalize a batch of findings."""
    normalizer = FindingNormalizer()
    return normalizer.normalize_batch(findings)


# Export the main components
__all__ = ["FindingNormalizer", "normalize_finding", "normalize_findings_batch"]
