"""
Enhanced Network Security Analysis Data Structures

This module contains all data structures, dataclasses, and enums used
throughout the enhanced network security analysis plugin components.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any
from enum import Enum


class NetworkVulnerabilityType(Enum):
    """Types of network security vulnerabilities."""

    INSECURE_HTTP = "insecure_http"
    WEAK_SSL_CONTEXT = "weak_ssl_context"
    TRUST_ALL_CERTS = "trust_all_certs"
    HOSTNAME_VERIFICATION_DISABLED = "hostname_verification_disabled"
    PLAINTEXT_CREDENTIALS = "plaintext_credentials"
    SSL_CONFIG_ISSUES = "ssl_config_issues"
    CERTIFICATE_VALIDATION_BYPASS = "certificate_validation_bypass"
    NETWORK_CONFIG_ISSUES = "network_config_issues"
    CREDENTIAL_HANDLING_ISSUES = "credential_handling_issues"
    TLS_VERSION_ISSUES = "tls_version_issues"
    CIPHER_SUITE_ISSUES = "cipher_suite_issues"


class SeverityLevel(Enum):
    """Severity levels for network vulnerabilities."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class NetworkContextType(Enum):
    """Context types for network security analysis."""

    PRODUCTION_APP = "production_app"
    DEVELOPMENT_APP = "development_app"
    FRAMEWORK_CODE = "framework_code"
    TEST_CODE = "test_code"
    CONFIGURATION_FILE = "configuration_file"
    MANIFEST_FILE = "manifest_file"
    NATIVE_CODE = "native_code"
    THIRD_PARTY_LIB = "third_party_lib"
    GENERATED_CODE = "generated_code"
    UNKNOWN_CONTEXT = "unknown_context"


class SSLConfigurationRisk(Enum):
    """Risk levels for SSL configurations."""

    SAFE = "safe"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    CRITICAL_RISK = "critical_risk"


class TLSVersion(Enum):
    """TLS/SSL version enumeration."""

    SSL_V2 = "SSLv2"
    SSL_V3 = "SSLv3"
    TLS_V1 = "TLSv1"
    TLS_V1_1 = "TLSv1.1"
    TLS_V1_2 = "TLSv1.2"
    TLS_V1_3 = "TLSv1.3"


@dataclass
class NetworkSecurityIssue:
    """Represents a network security issue."""

    issue_type: str
    severity: str
    description: str
    file_path: str
    line_number: int
    class_name: str
    method_name: str
    code_example: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "issue_type": self.issue_type,
            "severity": self.severity,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "class_name": self.class_name,
            "method_name": self.method_name,
            "code_example": self.code_example,
            "remediation": self.remediation,
        }


@dataclass
class SSLConfigurationIssue:
    """SSL/TLS configuration security issue."""

    configuration_type: str
    current_value: str
    recommended_value: str
    risk_level: str
    description: str
    file_path: str
    line_number: int
    method_name: str
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "configuration_type": self.configuration_type,
            "current_value": self.current_value,
            "recommended_value": self.recommended_value,
            "risk_level": self.risk_level,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "method_name": self.method_name,
            "remediation": self.remediation,
        }


@dataclass
class CertificateValidationIssue:
    """Certificate validation security issue."""

    validation_type: str
    bypass_method: str
    security_impact: str
    file_path: str
    line_number: int
    class_name: str
    method_name: str
    code_example: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "validation_type": self.validation_type,
            "bypass_method": self.bypass_method,
            "security_impact": self.security_impact,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "class_name": self.class_name,
            "method_name": self.method_name,
            "code_example": self.code_example,
            "remediation": self.remediation,
        }


@dataclass
class CredentialHandlingIssue:
    """Credential handling security issue."""

    credential_type: str
    exposure_method: str
    severity: str
    file_path: str
    line_number: int
    class_name: str
    method_name: str
    code_example: str = ""
    security_impact: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "credential_type": self.credential_type,
            "exposure_method": self.exposure_method,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "class_name": self.class_name,
            "method_name": self.method_name,
            "code_example": self.code_example,
            "security_impact": self.security_impact,
            "remediation": self.remediation,
        }


@dataclass
class NetworkSecurityVulnerability:
    """Full network security vulnerability."""

    vulnerability_id: str
    vulnerability_type: str
    severity: str
    confidence: float
    title: str
    description: str
    file_path: str
    line_number: int
    class_name: str
    method_name: str
    code_example: str = ""
    security_impact: str = ""
    remediation: str = ""
    cwe_id: str = ""
    masvs_refs: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "vulnerability_id": self.vulnerability_id,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "class_name": self.class_name,
            "method_name": self.method_name,
            "code_example": self.code_example,
            "security_impact": self.security_impact,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "masvs_refs": self.masvs_refs,
            "references": self.references,
            "evidence": self.evidence,
        }


@dataclass
@dataclass
class NetworkAnalysisContext:
    """Context information for network security analysis."""

    apk_path: str
    package_name: str
    target_sdk: int = 0
    min_sdk: int = 0
    has_internet_permission: bool = False
    has_network_state_permission: bool = False
    deep_analysis_mode: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "apk_path": self.apk_path,
            "package_name": self.package_name,
            "target_sdk": self.target_sdk,
            "min_sdk": self.min_sdk,
            "has_internet_permission": self.has_internet_permission,
            "has_network_state_permission": self.has_network_state_permission,
            "deep_analysis_mode": self.deep_analysis_mode,
        }


class NetworkSecurityPatterns:
    """Network security pattern types for configuration."""

    INSECURE_HTTP = "insecure_http"
    WEAK_SSL_CONTEXT = "weak_ssl_context"
    TRUST_ALL_CERTS = "trust_all_certs"
    HOSTNAME_VERIFICATION_DISABLED = "hostname_verification_disabled"
    PLAINTEXT_CREDENTIALS = "plaintext_credentials"
    SSL_CONFIG_ISSUES = "ssl_config_issues"
    CERTIFICATE_VALIDATION_BYPASS = "certificate_validation_bypass"
    NETWORK_CONFIG_ISSUES = "network_config_issues"
    CREDENTIAL_HANDLING_ISSUES = "credential_handling_issues"
    TLS_VERSION_ISSUES = "tls_version_issues"
    CIPHER_SUITE_ISSUES = "cipher_suite_issues"


class MAVSNetworkControls:
    """MASVS control mappings for network security."""

    NETWORK_1 = "MSTG-NETWORK-01"  # Secure network communication
    NETWORK_2 = "MSTG-NETWORK-02"  # TLS settings verification
    NETWORK_3 = "MSTG-NETWORK-03"  # Certificate validation
    NETWORK_4 = "MSTG-NETWORK-04"  # Certificate pinning


# Backward-compatible alias with correct acronym spelling
MASVSNetworkControls = MAVSNetworkControls


class CWENetworkCategories:
    """Common Weakness Enumeration categories for network vulnerabilities."""

    WEAK_CRYPTO = "CWE-326"  # Inadequate Encryption Strength
    IMPROPER_CERT_VALIDATION = "CWE-295"  # Improper Certificate Validation
    CLEARTEXT_TRANSMISSION = "CWE-319"  # Cleartext Transmission of Sensitive Information
    MISSING_ENCRYPTION = "CWE-311"  # Missing Encryption of Sensitive Data
    WEAK_SSL_TLS = "CWE-327"  # Use of a Broken or Risky Cryptographic Algorithm
    IMPROPER_INPUT_VALIDATION = "CWE-20"  # Improper Input Validation
    TRUST_BOUNDARY_VIOLATION = "CWE-501"  # Trust Boundary Violation


@dataclass
class NetworkSecurityAnalysis:
    """Main analysis container for network security analysis results."""

    network_security_issues: List[NetworkSecurityIssue] = field(default_factory=list)
    ssl_configuration_issues: List[SSLConfigurationIssue] = field(default_factory=list)
    certificate_validation_issues: List[CertificateValidationIssue] = field(default_factory=list)
    credential_handling_issues: List[CredentialHandlingIssue] = field(default_factory=list)
    total_issues: int = 0
    analysis_confidence: float = 0.0
    recommendations: List[str] = field(default_factory=list)

    def __init__(self, **kwargs):
        """Initialize NetworkSecurityAnalysis, ignoring unexpected keyword arguments."""
        # Filter out unexpected arguments to prevent constructor errors
        valid_fields = {
            "network_security_issues",
            "ssl_configuration_issues",
            "certificate_validation_issues",
            "credential_handling_issues",
            "total_issues",
            "analysis_confidence",
            "recommendations",
        }

        filtered_kwargs = {k: v for k, v in kwargs.items() if k in valid_fields}

        # Set defaults
        self.network_security_issues = filtered_kwargs.get("network_security_issues", [])
        self.ssl_configuration_issues = filtered_kwargs.get("ssl_configuration_issues", [])
        self.certificate_validation_issues = filtered_kwargs.get("certificate_validation_issues", [])
        self.credential_handling_issues = filtered_kwargs.get("credential_handling_issues", [])
        self.total_issues = filtered_kwargs.get("total_issues", 0)
        self.analysis_confidence = filtered_kwargs.get("analysis_confidence", 0.0)
        self.recommendations = filtered_kwargs.get("recommendations", [])
