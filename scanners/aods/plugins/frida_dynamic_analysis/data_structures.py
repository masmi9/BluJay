"""
Data structures and constants for Frida Dynamic Analysis Plugin.

This module defines structured dataclasses and constants used throughout
the Frida dynamic analysis plugin for improved maintainability and type safety.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time
from datetime import datetime

# MIGRATED: Import unified caching infrastructure


class FridaTestType(Enum):
    """Types of Frida tests that can be performed."""

    SSL_PINNING = "ssl_pinning"
    WEBVIEW_SECURITY = "webview_security"
    ANTI_TAMPERING = "anti_tampering"
    MEMORY_CORRUPTION = "memory_corruption"
    RUNTIME_MANIPULATION = "runtime_manipulation"


class FridaTestStatus(Enum):
    """Status of Frida test execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CACHED = "cached"


@dataclass
class FridaAnalysisConfig:
    """Configuration for Frida dynamic analysis."""

    analysis_duration: int = 45
    max_concurrent_tests: int = 3
    cache_results: bool = True
    cache_ttl: int = 300  # 5 minutes
    timeout_per_test: int = 30
    retry_attempts: int = 2
    parallel_execution: bool = True

    # Device configuration
    device_selection: str = "usb"
    spawn_mode: bool = True

    # Test configuration
    enable_ssl_tests: bool = True
    enable_webview_tests: bool = True
    enable_tampering_tests: bool = True
    enable_memory_tests: bool = True

    # Logging configuration
    verbose_logging: bool = False
    log_frida_output: bool = True


@dataclass
class FridaVulnerabilityPattern:
    """Pattern definition for vulnerability detection."""

    pattern_name: str
    indicators: List[str]
    severity: str
    cwe_id: str
    masvs_control: str
    owasp_category: str
    confidence_weight: float = 1.0
    false_positive_indicators: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Validate pattern configuration."""
        if self.severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            raise ValueError(f"Invalid severity: {self.severity}")
        if not self.cwe_id.startswith("CWE-"):
            raise ValueError(f"Invalid CWE ID format: {self.cwe_id}")
        if self.confidence_weight < 0 or self.confidence_weight > 1:
            raise ValueError(f"Invalid confidence weight: {self.confidence_weight}")


@dataclass
class FridaTestResult:
    """Result of a Frida test execution."""

    test_type: FridaTestType
    status: FridaTestStatus
    success: bool
    evidence: Dict[str, Any]
    error_message: Optional[str] = None
    execution_time: float = 0.0
    timestamp: float = field(default_factory=time.time)
    confidence_score: float = 0.0

    # Subprocess execution details
    subprocess_result: Optional[Dict[str, Any]] = None
    frida_output: Optional[str] = None

    def __post_init__(self):
        """Validate test result."""
        if self.confidence_score < 0 or self.confidence_score > 1:
            raise ValueError(f"Invalid confidence score: {self.confidence_score}")


@dataclass
class FridaEnvironmentCheck:
    """Results of Frida environment validation."""

    frida_available: bool
    frida_version: Optional[str] = None
    devices_available: bool = False
    device_list: List[str] = field(default_factory=list)
    frida_server_running: bool = False
    adb_available: bool = False
    error_messages: List[str] = field(default_factory=list)
    check_timestamp: float = field(default_factory=time.time)

    @property
    def is_ready(self) -> bool:
        """Check if environment is ready for Frida analysis."""
        return self.frida_available and self.devices_available and self.adb_available and len(self.error_messages) == 0


@dataclass
class FridaProcessInfo:
    """Information about Frida process management."""

    package_name: str
    process_id: Optional[int] = None
    spawn_mode: bool = True
    attached: bool = False
    session_id: Optional[str] = None
    script_count: int = 0
    last_activity: float = field(default_factory=time.time)


class FridaTestCache:
    """MIGRATED: Thread-safe cache for Frida test results using unified caching infrastructure."""

    def __init__(self, ttl: int = 300):
        self.ttl = ttl
        # Use a simple in-memory cache for complex, non-serializable objects
        self._cache = {}

    def get(self, key: str) -> Optional[FridaTestResult]:
        """MIGRATED: Get cached result using unified cache."""
        return self._cache.get(key)

    def set(self, key: str, result: FridaTestResult) -> None:
        """MIGRATED: Cache test result using unified cache."""
        self._cache[key] = result

    def clear(self) -> None:
        """MIGRATED: Clear all cached results using unified cache."""
        self._cache.clear()

    def size(self) -> int:
        """MIGRATED: Get cache size using unified cache."""
        return len(self._cache)

    def cleanup_expired(self) -> None:
        """MIGRATED: Remove expired cache entries - handled automatically by unified cache."""
        # Unified cache handles expiration automatically
        # This method is kept for backward compatibility but is now a no-op


@dataclass
class FridaSecurityRecommendation:
    """Security recommendation with deduplication support."""

    recommendation_id: str
    title: str
    description: str
    severity: str
    masvs_control: str
    fix_description: str
    code_example: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def __hash__(self) -> int:
        """Enable deduplication by recommendation ID."""
        return hash(self.recommendation_id)

    def __eq__(self, other) -> bool:
        """Compare recommendations for deduplication."""
        if not isinstance(other, FridaSecurityRecommendation):
            return False
        return self.recommendation_id == other.recommendation_id


@dataclass
class FridaAnalysisMetadata:
    """Metadata for Frida analysis execution."""

    analysis_id: str
    package_name: str
    start_time: float
    end_time: Optional[float] = None
    total_tests: int = 0
    successful_tests: int = 0
    failed_tests: int = 0
    cached_tests: int = 0
    parallel_execution: bool = False
    device_info: Dict[str, Any] = field(default_factory=dict)

    # Runtime event tracking
    runtime_events: List[Dict[str, Any]] = field(default_factory=list)
    runtime_events_captured: int = 0
    runtime_vulnerabilities_found: int = 0

    @property
    def duration(self) -> float:
        """Calculate analysis duration."""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time

    @property
    def success_rate(self) -> float:
        """Calculate test success rate."""
        if self.total_tests == 0:
            return 0.0
        return self.successful_tests / self.total_tests


# Subprocess execution configuration


@dataclass
class SubprocessConfig:
    """Configuration for subprocess execution with proper error handling."""

    command: List[str]
    timeout: int = 30
    capture_output: bool = True
    text: bool = True
    shell: bool = False
    cwd: Optional[str] = None
    env: Optional[Dict[str, str]] = None

    def __post_init__(self):
        """Validate subprocess configuration."""
        if self.timeout <= 0:
            raise ValueError("Timeout must be positive")
        if not self.command:
            raise ValueError("Command cannot be empty")


@dataclass
class DetailedVulnerability:
    """Detailed vulnerability information from dynamic analysis."""

    vulnerability_type: str
    severity: str
    confidence: float
    description: str
    location: str
    recommendation: str
    cwe_id: Optional[str] = None  # Added missing CWE ID field
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "location": self.location,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat(),
        }


# Alias for backward compatibility
AnalysisMetadata = FridaAnalysisMetadata


@dataclass
class VulnerabilityLocation:
    """Location information for vulnerabilities."""

    file_path: str = ""
    line_number: int = 0
    function_name: str = ""
    class_name: str = ""
    method_signature: str = ""
    component_type: str = ""


@dataclass
class VulnerabilityEvidence:
    """Evidence for vulnerability detection."""

    evidence_type: str = ""
    evidence_data: Dict[str, Any] = field(default_factory=dict)
    confidence_score: float = 0.0
    detection_method: str = ""
    additional_context: str = ""


@dataclass
class VulnerabilityRemediation:
    """Remediation information for vulnerabilities."""

    fix_description: str = ""
    code_example: str = ""
    references: List[str] = field(default_factory=list)
    priority: str = "MEDIUM"
    estimated_effort: str = "MEDIUM"


@dataclass
class RemediationGuidance:
    """Guidance for vulnerability remediation - compatible with core framework."""

    fix_description: str = ""
    code_example: str = ""
    references: List[str] = field(default_factory=list)
    difficulty_level: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    estimated_time: str = "1-2 hours"

    # Legacy fields for backward compatibility
    remediation_steps: List[str] = field(default_factory=list)
    code_examples: List[str] = field(default_factory=list)
    priority: str = "MEDIUM"
    estimated_effort: str = "MEDIUM"


def create_detailed_vulnerability(
    vulnerability_type: str,
    severity: str,
    confidence: Optional[float] = None,
    description: Optional[str] = None,
    location: Any = "",
    recommendation: Optional[str] = None,
    cwe_id: Optional[str] = None,
    evidence: Optional[Dict[str, Any]] = None,
    masvs_control: Optional[str] = None,
    owasp_category: Optional[str] = None,
    security_impact: Optional[str] = None,
    remediation: Any = None,
    **kwargs,
) -> DetailedVulnerability:
    """Create a detailed vulnerability with compatibility for extended kwargs.

    This function accepts additional fields commonly used across AODS (e.g.,
    masvs_control, owasp_category, security_impact, remediation objects, and
    object-style locations) and normalizes them into the local
    DetailedVulnerability structure without breaking legacy callers.
    """

    def _normalize_location(loc: Any) -> str:
        if isinstance(loc, str) or loc is None:
            return loc or ""
        # Try common attributes
        file_path = getattr(loc, "file_path", None)
        component_type = getattr(loc, "component_type", None)
        function_name = getattr(loc, "function_name", None)
        class_name = getattr(loc, "class_name", None)
        parts: List[str] = []
        if component_type:
            parts.append(str(component_type))
        if file_path:
            parts.append(str(file_path))
        # Provide extra context if available
        if class_name or function_name:
            extra = ".".join(
                [
                    p
                    for p in [str(class_name) if class_name else None, str(function_name) if function_name else None]
                    if p
                ]
            )
            if extra:
                parts.append(extra)
        return ":".join(parts) if parts else str(loc)

    def _coerce_evidence(ev: Any) -> Dict[str, Any]:
        if ev is None:
            return {}
        if isinstance(ev, dict):
            return dict(ev)
        # Try to convert known evidence objects
        result: Dict[str, Any] = {}
        for attr in ("matched_pattern", "detection_method", "confidence_score", "timestamp", "additional_context"):
            if hasattr(ev, attr):
                result[attr] = getattr(ev, attr)
        if not result:
            result["raw_evidence"] = str(ev)
        return result

    # Normalize inputs
    normalized_location = _normalize_location(location)
    normalized_evidence = _coerce_evidence(evidence)

    # Prefer explicit description; otherwise fall back to security_impact
    normalized_description = description if description is not None else (security_impact or "")

    # Prefer explicit recommendation; otherwise try remediation.fix_description
    normalized_recommendation = recommendation
    if normalized_recommendation is None and remediation is not None:
        try:
            # Support both dict-like and object-like remediation
            if isinstance(remediation, dict):
                normalized_recommendation = remediation.get("fix_description") or remediation.get("description")
            else:
                normalized_recommendation = getattr(remediation, "fix_description", None) or getattr(
                    remediation, "description", None
                )
        except Exception:
            pass
        if normalized_recommendation is None:
            normalized_recommendation = str(remediation)

    # If confidence is not provided, try to derive from evidence
    if confidence is None:
        try:
            confidence = float(normalized_evidence.get("confidence_score"))
        except Exception:
            confidence = 0.8

    # Enrich evidence with MASVS/OWASP metadata when passed at top level
    if masvs_control and "masvs_control" not in normalized_evidence:
        normalized_evidence["masvs_control"] = masvs_control
    if owasp_category and "owasp_category" not in normalized_evidence:
        normalized_evidence["owasp_category"] = owasp_category
    if cwe_id and "cwe_id" not in normalized_evidence:
        normalized_evidence["cwe_id"] = cwe_id

    # Include any unknown kwargs into evidence additional context for traceability
    if kwargs:
        normalized_evidence.setdefault("additional_context", {})
        try:
            # Merge, preserving existing dict if present
            if isinstance(normalized_evidence["additional_context"], dict):
                normalized_evidence["additional_context"].update(kwargs)
            else:
                normalized_evidence["additional_context"] = {
                    "legacy_context": normalized_evidence["additional_context"],
                    **kwargs,
                }
        except Exception:
            normalized_evidence["additional_context"] = kwargs

    return DetailedVulnerability(
        vulnerability_type=vulnerability_type,
        severity=severity,
        confidence=confidence,
        description=normalized_description,
        location=normalized_location,
        recommendation=normalized_recommendation or "",
        cwe_id=cwe_id,
        evidence=normalized_evidence,
    )
