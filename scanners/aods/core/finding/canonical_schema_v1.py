#!/usr/bin/env python3
"""
Canonical Finding Schema v1 - Unified Vulnerability Data Structure
================================================================

This module provides the canonical, unified data structure for all vulnerability
findings across AODS plugins. It consolidates multiple existing schemas into
a single, full format that supports:

- Cross-plugin compatibility and normalization
- Rich evidence preservation and aggregation
- Security taxonomy mapping
- Advanced deduplication and correlation
Reporting and compliance features

Version: 1.0
Author: AODS Development Team
Date: 2025-01-04
"""

import logging
import uuid
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set

logger = logging.getLogger(__name__)


class SeverityLevel(Enum):
    """Standardized severity levels across all AODS plugins."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ConfidenceLevel(Enum):
    """Confidence level categories for findings."""

    VERY_HIGH = "VERY_HIGH"  # 0.9-1.0
    HIGH = "HIGH"  # 0.7-0.89
    MEDIUM = "MEDIUM"  # 0.5-0.69
    LOW = "LOW"  # 0.3-0.49
    VERY_LOW = "VERY_LOW"  # 0.0-0.29


class VulnerabilityCategory(Enum):
    """Primary vulnerability categories following OWASP and industry standards."""

    # Core OWASP Mobile Top 10
    IMPROPER_PLATFORM_USAGE = "improper_platform_usage"
    INSECURE_DATA_STORAGE = "insecure_data_storage"
    INSECURE_COMMUNICATION = "insecure_communication"
    INSECURE_AUTHENTICATION = "insecure_authentication"
    INSUFFICIENT_CRYPTOGRAPHY = "insufficient_cryptography"
    INSECURE_AUTHORIZATION = "insecure_authorization"
    CLIENT_CODE_QUALITY = "client_code_quality"
    CODE_TAMPERING = "code_tampering"
    REVERSE_ENGINEERING = "reverse_engineering"
    EXTRANEOUS_FUNCTIONALITY = "extraneous_functionality"

    # Extended categories for full coverage
    API_SECURITY = "api_security"
    CLOUD_MISCONFIG = "cloud_misconfig"
    MODERN_AUTH = "modern_auth"
    SUPPLY_CHAIN = "supply_chain"
    PRIVACY_COMPLIANCE = "privacy_compliance"
    NETWORK_SECURITY = "network_security"
    INJECTION_VULNERABILITIES = "injection_vulnerabilities"
    ANTI_TAMPERING = "anti_tampering"
    WEBVIEW_SECURITY = "webview_security"
    IPC_SECURITY = "ipc_security"
    LIBRARY_VULNERABILITIES = "library_vulnerabilities"


class DetectionMethod(Enum):
    """Methods used to detect vulnerabilities."""

    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    MANIFEST_ANALYSIS = "manifest_analysis"
    BINARY_ANALYSIS = "binary_analysis"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    PATTERN_MATCHING = "pattern_matching"
    ML_DETECTION = "ml_detection"
    HEURISTIC_ANALYSIS = "heuristic_analysis"
    SIGNATURE_BASED = "signature_based"
    HYBRID_ANALYSIS = "hybrid_analysis"


@dataclass
class EvidenceLocation:
    """Precise location information for vulnerability evidence."""

    file_path: str
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    component_name: Optional[str] = None

    def __str__(self) -> str:
        """Human-readable location string."""
        parts = [self.file_path]
        if self.line_number:
            parts.append(f"line {self.line_number}")
        if self.function_name:
            parts.append(f"in {self.function_name}()")
        return ":".join(parts)


@dataclass
class VulnerabilityEvidence:
    """Rich evidence data with context and metadata."""

    # Core evidence
    evidence_type: str  # code_snippet, log_entry, network_trace, etc.
    content: str
    location: Optional[EvidenceLocation] = None

    # Context information
    context_before: str = ""
    context_after: str = ""

    # Evidence metadata
    confidence: float = 1.0
    source_plugin: str = ""
    collection_method: DetectionMethod = DetectionMethod.STATIC_ANALYSIS
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)


@dataclass
class SecurityTaxonomy:
    """Security taxonomy mapping."""

    # Primary classifications
    cwe_ids: List[str] = field(default_factory=list)
    owasp_categories: List[str] = field(default_factory=list)
    masvs_controls: List[str] = field(default_factory=list)
    mstg_references: List[str] = field(default_factory=list)

    # Compliance frameworks
    nist_controls: List[str] = field(default_factory=list)
    iso27001_controls: List[str] = field(default_factory=list)
    pci_dss_requirements: List[str] = field(default_factory=list)
    gdpr_articles: List[str] = field(default_factory=list)
    hipaa_safeguards: List[str] = field(default_factory=list)

    # Risk assessment
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    attack_complexity: str = "UNKNOWN"
    attack_vector: str = "UNKNOWN"
    privileges_required: str = "UNKNOWN"
    user_interaction: str = "UNKNOWN"

    # Business impact
    confidentiality_impact: str = "UNKNOWN"
    integrity_impact: str = "UNKNOWN"
    availability_impact: str = "UNKNOWN"


@dataclass
class RemediationGuidance:
    """Full remediation guidance."""

    # Core remediation
    summary: str = ""
    detailed_steps: List[str] = field(default_factory=list)
    code_examples: List[str] = field(default_factory=list)

    # Effort estimation
    remediation_effort: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    estimated_hours: Optional[float] = None
    complexity_level: str = "MEDIUM"

    # Priority and urgency
    priority: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW
    urgency: str = "MEDIUM"
    business_justification: str = ""

    # Resources and references
    references: List[str] = field(default_factory=list)
    tools_required: List[str] = field(default_factory=list)
    skills_required: List[str] = field(default_factory=list)

    # Validation
    verification_steps: List[str] = field(default_factory=list)
    test_cases: List[str] = field(default_factory=list)


@dataclass
class CanonicalFinding:
    """
    Canonical Finding Schema v1 - The unified vulnerability data structure.

    This is the authoritative format for all vulnerability findings in AODS.
    All plugins must normalize their findings to this schema for consistent
    processing, deduplication, and reporting.
    """

    # === CORE IDENTIFICATION ===
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""

    # === CLASSIFICATION ===
    category: VulnerabilityCategory = VulnerabilityCategory.CLIENT_CODE_QUALITY
    subcategory: str = ""
    severity: SeverityLevel = SeverityLevel.MEDIUM
    confidence: float = 0.5
    confidence_level: ConfidenceLevel = field(default=ConfidenceLevel.MEDIUM, init=False)
    ml_enhanced: bool = False

    # === EVIDENCE AND LOCATION ===
    evidence: List[VulnerabilityEvidence] = field(default_factory=list)
    primary_location: Optional[EvidenceLocation] = None
    affected_components: List[str] = field(default_factory=list)

    # === SECURITY TAXONOMY ===
    taxonomy: SecurityTaxonomy = field(default_factory=SecurityTaxonomy)

    # === REMEDIATION ===
    remediation: RemediationGuidance = field(default_factory=RemediationGuidance)

    # === DETECTION METADATA ===
    detection_method: DetectionMethod = DetectionMethod.STATIC_ANALYSIS
    detector_name: str = ""
    detector_version: str = ""
    detection_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    # === ANALYSIS CONTEXT ===
    analysis_session_id: str = ""
    package_name: str = ""
    app_version: str = ""
    target_sdk_version: Optional[int] = None
    min_sdk_version: Optional[int] = None

    # === CORRELATION AND DEDUPLICATION ===
    correlation_key: str = field(default="", init=False)
    fingerprint: str = field(default="", init=False)
    related_findings: List[str] = field(default_factory=list)
    duplicate_of: Optional[str] = None

    # === QUALITY METRICS ===
    evidence_quality_score: float = 0.0
    actionability_score: float = 0.0
    false_positive_probability: float = 0.0

    # === METADATA ===
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    custom_fields: Dict[str, Any] = field(default_factory=dict)

    # === LIFECYCLE ===
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    version: int = 1

    def __post_init__(self):
        """Post-initialization validation and derived field calculation."""
        # Validate confidence range
        if not (0.0 <= self.confidence <= 1.0):
            logger.warning(f"Invalid confidence {self.confidence}, clamping to [0.0, 1.0]")
            self.confidence = max(0.0, min(1.0, self.confidence))

        # Set confidence level based on numeric confidence
        if self.confidence >= 0.9:
            self.confidence_level = ConfidenceLevel.VERY_HIGH
        elif self.confidence >= 0.7:
            self.confidence_level = ConfidenceLevel.HIGH
        elif self.confidence >= 0.5:
            self.confidence_level = ConfidenceLevel.MEDIUM
        elif self.confidence >= 0.3:
            self.confidence_level = ConfidenceLevel.LOW
        else:
            self.confidence_level = ConfidenceLevel.VERY_LOW

        # Generate correlation key for deduplication
        self.correlation_key = self._generate_correlation_key()

        # Generate fingerprint for exact matching
        self.fingerprint = self._generate_fingerprint()

        # Set primary location from evidence if not specified
        if not self.primary_location and self.evidence:
            for evidence in self.evidence:
                if evidence.location:
                    self.primary_location = evidence.location
                    break

        # Validate required fields
        if not self.title:
            logger.warning(f"Finding {self.finding_id} has no title")
        if not self.description:
            logger.warning(f"Finding {self.finding_id} has no description")

    def _generate_correlation_key(self) -> str:
        """Generate correlation key for deduplication."""
        # Use category, location, and normalized title for correlation
        location_key = ""
        if self.primary_location:
            location_key = f"{self.primary_location.file_path}:{self.primary_location.line_number or 0}"

        # Normalize title for correlation (remove dynamic content)
        normalized_title = self.title.lower().strip()

        return f"{self.category.value}:{location_key}:{hash(normalized_title) % 1000000}"

    def _generate_fingerprint(self) -> str:
        """Generate exact fingerprint for duplicate detection."""
        # Use more specific fields for exact matching
        fingerprint_data = [
            self.category.value,
            self.subcategory,
            self.title,
            str(self.primary_location) if self.primary_location else "",
            self.detector_name,
        ]

        fingerprint_str = "|".join(fingerprint_data)
        return str(hash(fingerprint_str) % 10000000)

    def add_evidence(self, evidence: VulnerabilityEvidence) -> None:
        """Add evidence to the finding."""
        self.evidence.append(evidence)
        self.updated_at = datetime.now()

        # Update primary location if not set
        if not self.primary_location and evidence.location:
            self.primary_location = evidence.location

    def merge_with(self, other: "CanonicalFinding") -> "CanonicalFinding":
        """Merge this finding with another finding (for deduplication)."""
        # Use higher confidence finding as base
        if other.confidence > self.confidence:
            base_finding = other
            merge_finding = self
        else:
            base_finding = self
            merge_finding = other

        # Create merged finding
        # Determine higher severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)
        severity_order = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1,
        }
        higher_severity = max(base_finding.severity, merge_finding.severity, key=lambda x: severity_order.get(x, 0))

        merged = CanonicalFinding(
            finding_id=base_finding.finding_id,
            title=base_finding.title,
            description=base_finding.description,
            category=base_finding.category,
            subcategory=base_finding.subcategory,
            severity=higher_severity,
            confidence=max(base_finding.confidence, merge_finding.confidence),
            primary_location=base_finding.primary_location,
            taxonomy=base_finding.taxonomy,
            remediation=base_finding.remediation,
            detection_method=base_finding.detection_method,
            detector_name=f"{base_finding.detector_name}+{merge_finding.detector_name}",
            package_name=base_finding.package_name,
            analysis_session_id=base_finding.analysis_session_id,
        )

        # Merge evidence
        merged.evidence = base_finding.evidence + merge_finding.evidence

        # Merge affected components
        merged.affected_components = list(set(base_finding.affected_components + merge_finding.affected_components))

        # Merge tags
        merged.tags = base_finding.tags.union(merge_finding.tags)

        # Add correlation info
        merged.related_findings = [merge_finding.finding_id]

        return merged

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "category": self.category.value,
            "subcategory": self.subcategory,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "confidence_level": self.confidence_level.value,
            "ml_enhanced": self.ml_enhanced,
            "evidence": [
                {
                    "evidence_type": e.evidence_type,
                    "content": e.content,
                    "location": (
                        {
                            "file_path": e.location.file_path,
                            "line_number": e.location.line_number,
                            "function_name": e.location.function_name,
                        }
                        if e.location
                        else None
                    ),
                    "confidence": e.confidence,
                    "source_plugin": e.source_plugin,
                }
                for e in self.evidence
            ],
            "primary_location": (
                {
                    "file_path": self.primary_location.file_path,
                    "line_number": self.primary_location.line_number,
                    "function_name": self.primary_location.function_name,
                }
                if self.primary_location
                else None
            ),
            "taxonomy": {
                "cwe_ids": self.taxonomy.cwe_ids,
                "owasp_categories": self.taxonomy.owasp_categories,
                "masvs_controls": self.taxonomy.masvs_controls,
                "cvss_score": self.taxonomy.cvss_score,
            },
            "remediation": {
                "summary": self.remediation.summary,
                "detailed_steps": self.remediation.detailed_steps,
                "effort": self.remediation.remediation_effort,
                "priority": self.remediation.priority,
            },
            "detection_metadata": {
                "method": self.detection_method.value,
                "detector": self.detector_name,
                "timestamp": self.detection_timestamp,
            },
            "correlation": {
                "correlation_key": self.correlation_key,
                "fingerprint": self.fingerprint,
                "related_findings": self.related_findings,
            },
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CanonicalFinding":
        """Create finding from dictionary."""
        # This would be implemented for deserialization
        # For now, return a basic implementation
        finding = cls(
            finding_id=data.get("finding_id", str(uuid.uuid4())),
            title=data.get("title", ""),
            description=data.get("description", ""),
            category=VulnerabilityCategory(data.get("category", "client_code_quality")),
            severity=SeverityLevel(data.get("severity", "MEDIUM")),
            confidence=data.get("confidence", 0.5),
        )
        return finding


# Export the canonical schema components
__all__ = [
    "CanonicalFinding",
    "VulnerabilityEvidence",
    "EvidenceLocation",
    "SecurityTaxonomy",
    "RemediationGuidance",
    "SeverityLevel",
    "ConfidenceLevel",
    "VulnerabilityCategory",
    "DetectionMethod",
]
