#!/usr/bin/env python3
"""
Crypto Analysis Interfaces - Modular Architecture
=================================================

Clean interface definitions for cryptographic analysis following SOLID principles.
Enables pluggable crypto analysis strategies with dependency injection and testability.

This module migrates and enhances crypto analysis capabilities from the deprecated
CryptographicSecurityAnalyzer (1960 lines) while maintaining modular architecture principles.
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Union


class CryptoAnalysisType(Enum):
    """Types of cryptographic analysis."""

    CIPHER_ANALYSIS = "cipher_analysis"
    HASH_ANALYSIS = "hash_analysis"
    KEY_MANAGEMENT = "key_management"
    SSL_TLS_ANALYSIS = "ssl_tls_analysis"
    RANDOMNESS_ANALYSIS = "randomness_analysis"
    SECRET_DETECTION = "secret_detection"
    CERTIFICATE_VALIDATION = "certificate_validation"
    CUSTOM_CRYPTO = "custom_crypto"


class CryptoVulnerabilityType(Enum):
    """Types of cryptographic vulnerabilities."""

    WEAK_CIPHER = "weak_cipher"
    WEAK_HASH = "weak_hash"
    WEAK_KEY = "weak_key"
    INSECURE_SSL = "insecure_ssl"
    POOR_RANDOMNESS = "poor_randomness"
    HARDCODED_SECRET = "hardcoded_secret"
    CERTIFICATE_ISSUE = "certificate_issue"
    CUSTOM_CRYPTO_FLAW = "custom_crypto_flaw"
    CIPHER_MODE_ISSUE = "cipher_mode_issue"
    KEY_DERIVATION_ISSUE = "key_derivation_issue"
    PADDING_VULNERABILITY = "padding_vulnerability"


class CryptoSeverityLevel(Enum):
    """Severity levels for crypto vulnerabilities."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CryptoContext:
    """Context information for crypto analysis."""

    file_path: str = ""
    content: str = ""
    language: str = "java"
    framework: str = "android"
    analysis_depth: str = "full"
    custom_patterns: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CryptoFinding:
    """Cryptographic security finding."""

    vulnerability_type: CryptoVulnerabilityType
    title: str
    description: str
    severity: CryptoSeverityLevel
    confidence: float
    file_path: str = ""
    line_number: int = 0
    code_snippet: str = ""
    algorithm: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary format."""
        return {
            "vulnerability_type": self.vulnerability_type.value,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "algorithm": self.algorithm,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }


@dataclass
class CryptoAnalysisResult:
    """Result of crypto analysis."""

    analysis_type: CryptoAnalysisType
    findings: List[CryptoFinding] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    processing_time: float = 0.0
    files_analyzed: int = 0
    patterns_matched: int = 0

    def add_finding(self, finding: CryptoFinding):
        """Add a finding to the result."""
        self.findings.append(finding)
        self.patterns_matched += 1


@dataclass
class CryptoPattern:
    """Cryptographic pattern definition."""

    name: str
    pattern: Union[str, re.Pattern]
    vulnerability_type: CryptoVulnerabilityType
    severity: CryptoSeverityLevel
    description: str
    recommendation: str
    confidence_base: float = 0.8
    context_required: bool = True

    def compile_pattern(self) -> re.Pattern:
        """Compile pattern if it's a string."""
        if isinstance(self.pattern, str):
            return re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        return self.pattern


# Exceptions


class CryptoAnalysisException(Exception):
    """Base exception for crypto analysis operations."""


class PatternCompilationError(CryptoAnalysisException):
    """Raised when pattern compilation fails."""


class AnalysisConfigurationError(CryptoAnalysisException):
    """Raised when analysis configuration is invalid."""


# Core Interfaces


class ICryptoAnalysisStrategy(ABC):
    """Interface for cryptographic analysis strategies."""

    @property
    @abstractmethod
    def analysis_type(self) -> CryptoAnalysisType:
        """Get the type of analysis this strategy performs."""

    @property
    @abstractmethod
    def supported_patterns(self) -> List[CryptoPattern]:
        """Get the patterns this strategy can analyze."""

    @abstractmethod
    def analyze(self, context: CryptoContext) -> CryptoAnalysisResult:
        """Perform cryptographic analysis on the given context.

        Args:
            context: Analysis context with content and metadata

        Returns:
            CryptoAnalysisResult: Analysis results with findings

        Raises:
            CryptoAnalysisException: If analysis fails
        """

    @abstractmethod
    def validate_context(self, context: CryptoContext) -> bool:
        """Validate that the context is suitable for this analysis.

        Args:
            context: Analysis context to validate

        Returns:
            bool: True if context is valid for this analysis
        """


class ICryptoPatternMatcher(ABC):
    """Interface for crypto pattern matching."""

    @abstractmethod
    def match_patterns(self, content: str, patterns: List[CryptoPattern]) -> List[Tuple[CryptoPattern, re.Match]]:
        """Match patterns against content.

        Args:
            content: Content to analyze
            patterns: Patterns to match

        Returns:
            List[Tuple[CryptoPattern, re.Match]]: Matched patterns with match objects
        """

    @abstractmethod
    def extract_context(self, content: str, match: re.Match, lines_before: int = 2, lines_after: int = 2) -> str:
        """Extract context around a match.

        Args:
            content: Full content
            match: Match object
            lines_before: Lines to include before match
            lines_after: Lines to include after match

        Returns:
            str: Context around the match
        """


class ICryptoVulnerabilityAssessor(ABC):
    """Interface for assessing crypto vulnerability severity and confidence."""

    @abstractmethod
    def assess_vulnerability(
        self, pattern: CryptoPattern, match: re.Match, context: str, full_content: str
    ) -> Tuple[CryptoSeverityLevel, float]:
        """Assess vulnerability severity and confidence.

        Args:
            pattern: Matched pattern
            match: Match object
            context: Context around match
            full_content: Full file content

        Returns:
            Tuple[CryptoSeverityLevel, float]: Severity level and confidence score
        """

    @abstractmethod
    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """Calculate confidence score based on evidence.

        Args:
            evidence: Evidence dictionary

        Returns:
            float: Confidence score (0.0 to 1.0)
        """


class ICryptoFindingEnricher(ABC):
    """Interface for enriching crypto findings with additional information."""

    @abstractmethod
    def enrich_finding(self, finding: CryptoFinding, context: CryptoContext) -> CryptoFinding:
        """Enrich finding with additional metadata and recommendations.

        Args:
            finding: Base finding to enrich
            context: Analysis context

        Returns:
            CryptoFinding: Enriched finding
        """

    @abstractmethod
    def add_remediation_guidance(self, finding: CryptoFinding) -> CryptoFinding:
        """Add remediation guidance to finding.

        Args:
            finding: Finding to add guidance to

        Returns:
            CryptoFinding: Finding with remediation guidance
        """


class ICryptoAnalysisManager(ABC):
    """Interface for managing crypto analysis operations."""

    @abstractmethod
    def register_strategy(self, strategy: ICryptoAnalysisStrategy) -> None:
        """Register a crypto analysis strategy.

        Args:
            strategy: Strategy to register
        """

    @abstractmethod
    def analyze_comprehensive(self, context: CryptoContext) -> List[CryptoAnalysisResult]:
        """Perform full crypto analysis using all registered strategies.

        Args:
            context: Analysis context

        Returns:
            List[CryptoAnalysisResult]: Results from all strategies
        """

    @abstractmethod
    def analyze_specific(
        self, context: CryptoContext, analysis_types: List[CryptoAnalysisType]
    ) -> List[CryptoAnalysisResult]:
        """Perform specific types of crypto analysis.

        Args:
            context: Analysis context
            analysis_types: Types of analysis to perform

        Returns:
            List[CryptoAnalysisResult]: Results from specified analyses
        """

    @abstractmethod
    def get_analysis_metrics(self) -> Dict[str, Any]:
        """Get overall analysis metrics.

        Returns:
            Dict[str, Any]: Analysis metrics and statistics
        """


class ICryptoAnalysisFactory(ABC):
    """Factory interface for creating crypto analysis components."""

    @abstractmethod
    def create_strategy(self, analysis_type: CryptoAnalysisType) -> ICryptoAnalysisStrategy:
        """Create analysis strategy for specified type.

        Args:
            analysis_type: Type of analysis strategy to create

        Returns:
            ICryptoAnalysisStrategy: Analysis strategy instance
        """

    @abstractmethod
    def create_pattern_matcher(self) -> ICryptoPatternMatcher:
        """Create pattern matcher instance.

        Returns:
            ICryptoPatternMatcher: Pattern matcher instance
        """

    @abstractmethod
    def create_vulnerability_assessor(self) -> ICryptoVulnerabilityAssessor:
        """Create vulnerability assessor instance.

        Returns:
            ICryptoVulnerabilityAssessor: Vulnerability assessor instance
        """

    @abstractmethod
    def create_finding_enricher(self) -> ICryptoFindingEnricher:
        """Create finding enricher instance.

        Returns:
            ICryptoFindingEnricher: Finding enricher instance
        """


# Protocol for dependency injection


class CryptoAnalysisServiceProvider:
    """Protocol for crypto analysis service providers."""

    def get_analysis_factory(self) -> ICryptoAnalysisFactory:
        """Get crypto analysis factory."""
        ...

    def get_analysis_manager(self) -> ICryptoAnalysisManager:
        """Get crypto analysis manager."""
        ...

    def get_pattern_matcher(self) -> ICryptoPatternMatcher:
        """Get pattern matcher."""
        ...

    def get_vulnerability_assessor(self) -> ICryptoVulnerabilityAssessor:
        """Get vulnerability assessor."""
        ...
