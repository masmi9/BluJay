"""
BasePluginIOS – Standardized plugin interface for IODS.

Mirrors AODS BasePluginV2 with iOS-specific additions:
  - BINARY_ANALYSIS capability (Mach-O analysis)
  - ENTITLEMENTS_ANALYSIS capability
  - PLIST_ANALYSIS capability
  - iOS library path prefix filtering (Pods/, Frameworks/, Swift stdlib)
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from core.logging_config import get_logger

logger = get_logger(__name__)


class PluginCapability(Enum):
    """iOS plugin capability classifications."""
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    NETWORK_ANALYSIS = "network_analysis"
    CRYPTOGRAPHIC_ANALYSIS = "crypto_analysis"
    BINARY_ANALYSIS = "binary_analysis"
    PLIST_ANALYSIS = "plist_analysis"
    ENTITLEMENTS_ANALYSIS = "entitlements_analysis"
    RESOURCE_ANALYSIS = "resource_analysis"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    VULNERABILITY_DETECTION = "vulnerability_detection"
    COMPLIANCE_CHECKING = "compliance_checking"


class PluginStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    PARTIAL_SUCCESS = "partial_success"
    DEPENDENCY_MISSING = "dependency_missing"
    CONFIGURATION_ERROR = "configuration_error"


class PluginPriority(Enum):
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


@dataclass
class PluginDependency:
    name: str
    version_min: Optional[str] = None
    version_max: Optional[str] = None
    optional: bool = False
    install_command: Optional[str] = None
    description: str = ""


@dataclass
class PluginMetadata:
    name: str
    version: str
    capabilities: List[PluginCapability]
    dependencies: List[Union[str, PluginDependency]] = field(default_factory=list)

    description: str = ""
    author: str = ""
    priority: PluginPriority = PluginPriority.NORMAL
    timeout_seconds: int = 300
    memory_limit_mb: Optional[int] = None
    requires_network: bool = False
    requires_device: bool = False  # True = needs jailbroken device + Frida

    min_iods_version: Optional[str] = None
    supported_platforms: List[str] = field(default_factory=lambda: ["linux", "windows", "macos"])

    tags: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    masvs_control: Optional[str] = None
    security_level: str = "standard"


@dataclass
class PluginFinding:
    finding_id: str
    title: str
    description: str
    severity: str          # critical, high, medium, low, info
    confidence: float      # 0.0 – 1.0

    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None

    vulnerability_type: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    masvs_control: Optional[str] = None

    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    detected_at: float = field(default_factory=time.time)
    plugin_version: Optional[str] = None


@dataclass
class PluginResult:
    status: PluginStatus
    findings: List[PluginFinding] = field(default_factory=list)

    execution_time: float = 0.0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None

    error_message: Optional[str] = None
    warning_messages: List[str] = field(default_factory=list)
    info_messages: List[str] = field(default_factory=list)

    metadata: Dict[str, Any] = field(default_factory=dict)
    performance_metrics: Dict[str, float] = field(default_factory=dict)

    memory_used_mb: Optional[float] = None
    cpu_time_seconds: Optional[float] = None


@dataclass
class PluginConfiguration:
    enabled: bool = True
    timeout_override: Optional[int] = None
    settings: Dict[str, Any] = field(default_factory=dict)
    skip_conditions: List[str] = field(default_factory=list)


class BasePluginIOS(ABC):
    """
    Base class for all IODS plugins.

    Subclass this and implement `get_metadata()` and `execute()`.
    Use `create_finding()` and `create_result()` for standardized output.
    """

    # iOS-specific library/framework path prefixes to filter out of findings
    _LIBRARY_PATH_PREFIXES = (
        "Pods/",
        "Frameworks/",
        "SwiftSupport/",
        "Swift/",
        # Common third-party Pods
        "Pods/Alamofire/",
        "Pods/AFNetworking/",
        "Pods/Firebase/",
        "Pods/GoogleAnalytics/",
        "Pods/Crashlytics/",
        "Pods/Fabric/",
        "Pods/RxSwift/",
        # System frameworks (should not be flagged as app code)
        "usr/lib/swift/",
        "/System/Library/",
        "/usr/lib/",
    )

    @classmethod
    def _is_library_code(cls, rel_path: str) -> bool:
        """Return True if the path belongs to third-party/system code."""
        normalized = rel_path.replace("\\", "/")
        return any(normalized.startswith(p) or f"/{p}" in normalized for p in cls._LIBRARY_PATH_PREFIXES)

    def __init__(self, config: Optional[PluginConfiguration] = None) -> None:
        self.config = config or PluginConfiguration()
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        self._metadata_cache: Optional[PluginMetadata] = None
        self._execution_start_time: Optional[float] = None

    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Declare plugin capabilities and metadata."""

    @abstractmethod
    def execute(self, ipa_ctx) -> PluginResult:
        """Perform analysis against the IPA context."""

    def setup(self, ipa_ctx) -> bool:
        self._execution_start_time = time.time()
        return True

    def cleanup(self, ipa_ctx) -> None:
        pass

    def get_cached_metadata(self) -> PluginMetadata:
        if self._metadata_cache is None:
            self._metadata_cache = self.get_metadata()
        return self._metadata_cache

    def can_execute(self, ipa_ctx) -> tuple:
        if not self.config.enabled:
            return False, "Plugin disabled"
        return True, None

    def create_finding(
        self,
        finding_id: str,
        title: str,
        description: str,
        severity: str,
        confidence: float = 1.0,
        **kwargs,
    ) -> PluginFinding:
        meta = self.get_cached_metadata()
        return PluginFinding(
            finding_id=finding_id,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            plugin_version=meta.version,
            **kwargs,
        )

    def create_result(
        self,
        status: PluginStatus,
        findings: Optional[List[PluginFinding]] = None,
        **kwargs,
    ) -> PluginResult:
        end_time = time.time()
        execution_time = (end_time - self._execution_start_time) if self._execution_start_time else 0.0
        return PluginResult(
            status=status,
            findings=findings or [],
            execution_time=execution_time,
            start_time=self._execution_start_time or end_time,
            end_time=end_time,
            **kwargs,
        )
