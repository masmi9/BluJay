#!/usr/bin/env python3
"""
BasePlugin v2 - Standardized Plugin Interface for AODS
=====================================================

Provides a standardized, modern plugin interface with metadata,
capability declaration, and lifecycle management. Designed to replace the
current ad-hoc plugin system with a consistent, maintainable architecture.

Features:
- Standardized plugin interface with clear contracts
- Capability-based plugin classification
- Metadata and dependency management
- Lifecycle hooks for setup and cleanup
- Result standardization and validation
- Performance monitoring integration
- Security and validation support
- Backward compatibility with legacy plugins

Usage:
    from core.plugins.base_plugin_v2 import BasePluginV2, PluginCapability

    class MyAnalysisPlugin(BasePluginV2):
        def get_metadata(self) -> PluginMetadata:
            return PluginMetadata(
                name="my_analysis",
                version="1.0.0",
                capabilities=[PluginCapability.STATIC_ANALYSIS],
                dependencies=["jadx"]
            )

        def execute(self, apk_ctx: APKContext) -> PluginResult:
            # Perform analysis
            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=[...],
                metadata={"execution_time": 1.23}
            )
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union

# Import correlation context if available
try:
    from core.correlation_context import get_correlation_logger

    CORRELATION_AVAILABLE = True
except ImportError:
    CORRELATION_AVAILABLE = False

# Import optional dependencies manager if available
try:
    from core.optional_dependencies import optional_deps

    OPTIONAL_DEPS_AVAILABLE = True
except ImportError:
    OPTIONAL_DEPS_AVAILABLE = False

# Import structured logging
from core.logging_config import get_logger

logger = get_logger(__name__)


class PluginCapability(Enum):
    """Plugin capability classifications."""

    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    NETWORK_ANALYSIS = "network_analysis"
    CRYPTOGRAPHIC_ANALYSIS = "crypto_analysis"
    MANIFEST_ANALYSIS = "manifest_analysis"
    RESOURCE_ANALYSIS = "resource_analysis"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    VULNERABILITY_DETECTION = "vulnerability_detection"
    COMPLIANCE_CHECKING = "compliance_checking"
    PERFORMANCE_ANALYSIS = "performance_analysis"


class PluginStatus(Enum):
    """Plugin execution status."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    PARTIAL_SUCCESS = "partial_success"
    DEPENDENCY_MISSING = "dependency_missing"
    CONFIGURATION_ERROR = "configuration_error"


class PluginPriority(Enum):
    """Plugin execution priority."""

    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


@dataclass
class PluginDependency:
    """Plugin dependency specification."""

    name: str
    version_min: Optional[str] = None
    version_max: Optional[str] = None
    optional: bool = False
    install_command: Optional[str] = None
    description: str = ""


@dataclass
class PluginMetadata:
    """Full plugin metadata."""

    name: str
    version: str
    capabilities: List[PluginCapability]
    dependencies: List[Union[str, PluginDependency]] = field(default_factory=list)

    # Plugin information
    description: str = ""
    author: str = ""
    license: str = ""
    homepage: str = ""

    # Execution characteristics
    priority: PluginPriority = PluginPriority.NORMAL
    timeout_seconds: int = 300
    memory_limit_mb: Optional[int] = None
    requires_network: bool = False
    requires_root: bool = False

    # Compatibility
    min_aods_version: Optional[str] = None
    supported_platforms: List[str] = field(default_factory=lambda: ["linux", "windows", "macos"])

    # Classification
    tags: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    # Decompilation requirements for policy elevation: res, assets, imports, debug
    decompilation_requirements: List[str] = field(default_factory=list)

    # Security
    security_level: str = "standard"  # standard, elevated, restricted
    data_access_required: List[str] = field(default_factory=list)  # filesystem, network, system

    # CRITICAL FIX: Add is_legacy field for adapter compatibility
    is_legacy: bool = False


@dataclass
class PluginFinding:
    """Standardized plugin finding/vulnerability."""

    finding_id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    confidence: float  # 0.0 - 1.0

    # Location information
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None

    # Classification
    vulnerability_type: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    masvs_control: Optional[str] = None

    # Evidence and context
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    # Metadata
    detected_at: float = field(default_factory=time.time)
    plugin_version: Optional[str] = None


@dataclass
class PluginResult:
    """Standardized plugin execution result."""

    status: PluginStatus
    findings: List[PluginFinding] = field(default_factory=list)

    # Execution information
    execution_time: float = 0.0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None

    # Status details
    error_message: Optional[str] = None
    warning_messages: List[str] = field(default_factory=list)
    info_messages: List[str] = field(default_factory=list)

    # Metrics and metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    performance_metrics: Dict[str, float] = field(default_factory=dict)

    # Resource usage
    memory_used_mb: Optional[float] = None
    cpu_time_seconds: Optional[float] = None

    # Compatibility with legacy systems
    legacy_result: Optional[Any] = None


@dataclass
class PluginConfiguration:
    """Plugin configuration and settings."""

    enabled: bool = True
    timeout_override: Optional[int] = None
    priority_override: Optional[PluginPriority] = None

    # Plugin-specific settings
    settings: Dict[str, Any] = field(default_factory=dict)

    # Execution control
    skip_conditions: List[str] = field(default_factory=list)
    required_capabilities: List[PluginCapability] = field(default_factory=list)

    # Environment
    environment_variables: Dict[str, str] = field(default_factory=dict)
    working_directory: Optional[str] = None


class BasePluginV2(ABC):
    """
    Base class for all AODS plugins v2.

    Provides a standardized interface with metadata,
    lifecycle management, and result standardization.
    """

    # Shared library/SDK path prefixes for filtering third-party code.
    # Subclasses may override to customize.  Paths use forward-slash
    # Java package convention (e.g. "com/google/").
    _LIBRARY_PATH_PREFIXES = (
        "android/", "androidx/",
        "com/google/",
        "com/android/internal/", "com/android/support/", "com/android/tools/",
        "kotlin/", "kotlinx/",
        "com/squareup/", "io/reactivex/",
        "org/apache/", "com/facebook/",
        "com/bumptech/", "com/fasterxml/",
        "org/jetbrains/", "javax/", "java/",
        "okhttp3/", "retrofit2/",
        "com/airbnb/", "dagger/", "butterknife/",
        "org/greenrobot/", "com/tencent/", "com/bytedance/",
        # Ad / attribution SDKs
        "com/applovin/", "com/appsflyer/",
        "com/ironsource/", "com/mbridge/", "com/mintegral/",
        "com/unity3d/", "com/chartboost/", "com/vungle/",
        "com/inmobi/", "com/smaato/", "com/adjust/",
        "com/amazon/device/ads/",
        # ByteDance internal SDKs (bundled in TikTok, CapCut, etc.)
        "com/ttnet/", "com/lynx/", "com/pgl/", "com/bef/",
        # I/O libraries
        "okio/",
    )

    @classmethod
    def _is_library_code(cls, rel_path: str) -> bool:
        """Check if a file path belongs to third-party library/SDK code.

        Works with both relative paths (``sources/com/google/Foo.java``)
        and absolute paths (``/tmp/.../sources/com/google/Foo.java``).
        """
        normalized = rel_path.replace("\\", "/")
        # Strip common leading prefixes to reach Java package root
        for prefix in ("sources/", "src/main/java/", "src/"):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
                break
        # Handle absolute paths containing /sources/ or /src/
        for marker in ("/sources/", "/src/main/java/", "/src/"):
            idx = normalized.rfind(marker)
            if idx >= 0:
                normalized = normalized[idx + len(marker):]
                break
        return any(normalized.startswith(p) for p in cls._LIBRARY_PATH_PREFIXES)

    def __init__(self, config: Optional[PluginConfiguration] = None):
        """Initialize the plugin with optional configuration."""
        self.config = config or PluginConfiguration()
        self.logger = self._get_logger()
        self._metadata_cache: Optional[PluginMetadata] = None
        self._execution_start_time: Optional[float] = None

    def _get_logger(self):
        """Get a logger for this plugin."""
        if CORRELATION_AVAILABLE:
            return get_correlation_logger(f"{__name__}.{self.__class__.__name__}")
        else:
            return get_logger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """
        Get plugin metadata.

        Returns:
            PluginMetadata with full plugin information
        """

    @abstractmethod
    def execute(self, apk_ctx) -> PluginResult:
        """
        Execute the plugin analysis.

        Args:
            apk_ctx: APK context object with analysis data

        Returns:
            PluginResult with findings and execution information
        """

    def validate_dependencies(self) -> Dict[str, bool]:
        """
        Validate plugin dependencies.

        Returns:
            Dict mapping dependency names to availability status
        """
        metadata = self.get_metadata()
        dependency_status = {}

        for dep in metadata.dependencies:
            if isinstance(dep, str):
                dep_name = dep
            else:
                dep_name = dep.name

            # Check using optional dependencies manager if available
            if OPTIONAL_DEPS_AVAILABLE:
                dependency_status[dep_name] = optional_deps.is_available(dep_name)
            else:
                # Fallback: try to import
                try:
                    __import__(dep_name)
                    dependency_status[dep_name] = True
                except ImportError:
                    dependency_status[dep_name] = False

        return dependency_status

    def can_execute(self, apk_ctx) -> tuple[bool, Optional[str]]:
        """
        Check if the plugin can execute in the current context.

        Args:
            apk_ctx: APK context object

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        # Check if plugin is enabled
        if not self.config.enabled:
            return False, "Plugin is disabled in configuration"

        # Check dependencies
        dep_status = self.validate_dependencies()
        missing_deps = [name for name, available in dep_status.items() if not available]

        if missing_deps:
            metadata = self.get_metadata()
            # Check if any missing dependencies are required (not optional)
            required_missing = []
            for dep in metadata.dependencies:
                if isinstance(dep, str):
                    if dep in missing_deps:
                        required_missing.append(dep)
                elif isinstance(dep, PluginDependency):
                    if dep.name in missing_deps and not dep.optional:
                        required_missing.append(dep.name)

            if required_missing:
                return False, f"Missing required dependencies: {', '.join(required_missing)}"

        # Check skip conditions
        for condition in self.config.skip_conditions:
            if self._evaluate_skip_condition(condition, apk_ctx):
                return False, f"Skip condition met: {condition}"

        return True, None

    def _evaluate_skip_condition(self, condition: str, apk_ctx) -> bool:
        """Evaluate a skip condition."""
        # Simple condition evaluation - can be extended
        if condition == "no_apk":
            return apk_ctx is None
        elif condition == "no_manifest":
            return not hasattr(apk_ctx, "manifest_path") or not apk_ctx.manifest_path
        # Add more conditions as needed
        return False

    def setup(self, apk_ctx) -> bool:
        """
        Optional setup before execution.

        Args:
            apk_ctx: APK context object

        Returns:
            True if setup successful, False otherwise
        """
        self._execution_start_time = time.time()
        self.logger.info(f"Setting up plugin: {self.get_metadata().name}")
        return True

    def cleanup(self, apk_ctx) -> None:
        """
        Optional cleanup after execution.

        Args:
            apk_ctx: APK context object
        """
        metadata = self.get_metadata()
        if self._execution_start_time:
            execution_time = time.time() - self._execution_start_time
            self.logger.info(f"Plugin {metadata.name} cleanup completed (total time: {execution_time:.2f}s)")
        else:
            self.logger.info(f"Plugin {metadata.name} cleanup completed")

    def get_cached_metadata(self) -> PluginMetadata:
        """Get cached metadata to avoid repeated calls."""
        if self._metadata_cache is None:
            self._metadata_cache = self.get_metadata()
        return self._metadata_cache

    def create_finding(
        self, finding_id: str, title: str, description: str, severity: str, confidence: float = 1.0, **kwargs
    ) -> PluginFinding:
        """
        Convenience method to create a standardized finding.

        Args:
            finding_id: Unique identifier for the finding
            title: Short title/summary
            description: Detailed description
            severity: Severity level (critical, high, medium, low, info)
            confidence: Confidence score (0.0 - 1.0)
            **kwargs: Additional finding attributes

        Returns:
            PluginFinding instance
        """
        metadata = self.get_cached_metadata()

        finding = PluginFinding(
            finding_id=finding_id,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            plugin_version=metadata.version,
            **kwargs,
        )

        return finding

    def create_result(
        self, status: PluginStatus, findings: Optional[List[PluginFinding]] = None, **kwargs
    ) -> PluginResult:
        """
        Convenience method to create a standardized result.

        Args:
            status: Plugin execution status
            findings: List of findings (optional)
            **kwargs: Additional result attributes

        Returns:
            PluginResult instance
        """
        end_time = time.time()
        execution_time = 0.0

        if self._execution_start_time:
            execution_time = end_time - self._execution_start_time

        result = PluginResult(
            status=status,
            findings=findings or [],
            execution_time=execution_time,
            start_time=self._execution_start_time or end_time,
            end_time=end_time,
            **kwargs,
        )
        # Emit MSTG coverage trace events for any findings that carry MSTG identifiers
        try:
            self._trace_mstg_from_findings(result.findings)
        except Exception:
            # Tracing must never interfere with plugin results
            pass

        return result

    def _trace_mstg_from_findings(self, findings: List[Any]) -> None:
        """Emit MSTG tracer events for findings that reference MSTG/MASVS controls.
        Accepts both `PluginFinding` instances and plain dicts.
        """
        if not findings:
            return
        try:
            from core.compliance.mstg_tracer import get_tracer
        except Exception:
            return
        tracer = get_tracer()
        # If tracing is disabled, get_tracer() returns an instance but it will no-op
        for f in findings:
            try:
                # Extract control identifiers
                ctrl = None
                if hasattr(f, "masvs_control"):
                    ctrl = getattr(f, "masvs_control")
                elif isinstance(f, dict):
                    ctrl = f.get("masvs_control") or f.get("mstg_id")
                # Support list of controls
                controls = ctrl if isinstance(ctrl, list) else ([ctrl] if ctrl else [])
                for cid in controls:
                    if not cid:
                        continue
                    tracer.start_check(str(cid))
                    tracer.end_check(str(cid), "PASS")
            except Exception:
                # Never propagate tracing errors
                continue

    @staticmethod
    def _extract_line_number(item) -> Optional[int]:
        """Extract line_number from a legacy finding dict or object.

        Checks: dict keys (line_number, line, lineno), nested evidence dict,
        object attributes, and trailing ':line' in location strings.
        """
        import re as _re

        ln = None
        if isinstance(item, dict):
            ln = item.get("line_number") or item.get("line") or item.get("lineno")
            # Check nested evidence dict
            if not ln:
                ev = item.get("evidence")
                if isinstance(ev, dict):
                    ln = ev.get("line_number") or ev.get("line")
            # Parse trailing :line from location (e.g. "File.java:123")
            if not ln:
                loc = item.get("location") or item.get("file_path") or ""
                if isinstance(loc, str) and ":" in loc:
                    m = _re.search(r":(\d+)(?::\d+)?$", loc)
                    if m and loc[: m.start()].rstrip().endswith((".java", ".kt", ".xml", ".smali", ".py", ".json")):
                        ln = m.group(1)
        else:
            ln = getattr(item, "line_number", None) or getattr(item, "line", None)

        if ln is not None:
            try:
                ln = int(ln)
                return ln if ln > 0 else None
            except (ValueError, TypeError):
                pass
        return None


class LegacyPluginAdapter(BasePluginV2):
    """
    Adapter to wrap legacy plugins in the BasePlugin v2 interface.

    Provides backward compatibility while migrating to the new interface.
    """

    def __init__(self, legacy_plugin_module, plugin_name: str, config: Optional[PluginConfiguration] = None):
        """
        Initialize adapter with legacy plugin module.

        Args:
            legacy_plugin_module: The legacy plugin module
            plugin_name: Name of the plugin
            config: Optional plugin configuration
        """
        super().__init__(config)
        self.legacy_module = legacy_plugin_module
        self.plugin_name = plugin_name

    def get_metadata(self) -> PluginMetadata:
        """Generate metadata for legacy plugin."""
        # Try to extract metadata from legacy plugin
        version = getattr(self.legacy_module, "__version__", "1.0.0")
        description = getattr(self.legacy_module, "__doc__", "") or f"Legacy plugin: {self.plugin_name}"

        # Infer capabilities based on plugin name/module
        capabilities = self._infer_capabilities()

        return PluginMetadata(
            name=self.plugin_name,
            version=version,
            capabilities=capabilities,
            description=description.strip(),
            tags=["legacy"],
            security_level="standard",
        )

    def _infer_capabilities(self) -> List[PluginCapability]:
        """Infer capabilities from plugin name/module."""
        capabilities = []
        name_lower = self.plugin_name.lower()

        if any(keyword in name_lower for keyword in ["static", "manifest", "resource"]):
            capabilities.append(PluginCapability.STATIC_ANALYSIS)
        if any(keyword in name_lower for keyword in ["dynamic", "frida", "runtime"]):
            capabilities.append(PluginCapability.DYNAMIC_ANALYSIS)
        if any(keyword in name_lower for keyword in ["network", "traffic", "ssl", "tls"]):
            capabilities.append(PluginCapability.NETWORK_ANALYSIS)
        if any(keyword in name_lower for keyword in ["crypto", "encryption", "key"]):
            capabilities.append(PluginCapability.CRYPTOGRAPHIC_ANALYSIS)

        # Default to vulnerability detection if no specific capability inferred
        if not capabilities:
            capabilities.append(PluginCapability.VULNERABILITY_DETECTION)

        return capabilities

    def execute(self, apk_ctx) -> PluginResult:
        """Execute legacy plugin and adapt result."""
        try:
            # Try different legacy plugin entry points
            if hasattr(self.legacy_module, "run"):
                legacy_result = self.legacy_module.run(apk_ctx)
            elif hasattr(self.legacy_module, "analyze"):
                legacy_result = self.legacy_module.analyze(apk_ctx)
            elif hasattr(self.legacy_module, "execute"):
                legacy_result = self.legacy_module.execute(apk_ctx)
            else:
                return self.create_result(
                    status=PluginStatus.CONFIGURATION_ERROR,
                    error_message=f"Legacy plugin {self.plugin_name} has no recognized entry point",
                )

            # Adapt legacy result to new format
            return self._adapt_legacy_result(legacy_result)

        except Exception as e:
            self.logger.error(f"Legacy plugin {self.plugin_name} execution failed: {e}")
            return self.create_result(status=PluginStatus.FAILURE, error_message=str(e), legacy_result=None)

    def _adapt_legacy_result(self, legacy_result) -> PluginResult:
        """Adapt legacy plugin result to new format."""
        # Handle different legacy result formats
        if isinstance(legacy_result, tuple) and len(legacy_result) == 2:
            title, content = legacy_result

            # Create a basic finding from legacy result
            finding = self.create_finding(
                finding_id=f"{self.plugin_name}_legacy_finding",
                title=str(title),
                description=str(content),
                severity="medium",  # Default severity for legacy findings
                confidence=0.8,  # Lower confidence for legacy findings
            )

            return self.create_result(status=PluginStatus.SUCCESS, findings=[finding], legacy_result=legacy_result)

        elif isinstance(legacy_result, str):
            # Simple string result
            finding = self.create_finding(
                finding_id=f"{self.plugin_name}_legacy_result",
                title=f"{self.plugin_name} Analysis",
                description=legacy_result,
                severity="info",
                confidence=0.8,
            )

            return self.create_result(status=PluginStatus.SUCCESS, findings=[finding], legacy_result=legacy_result)

        else:
            # Unknown format - store as metadata
            return self.create_result(
                status=PluginStatus.SUCCESS,
                findings=[],
                legacy_result=legacy_result,
                metadata={"legacy_result_type": type(legacy_result).__name__},
            )


def create_legacy_adapter(plugin_module, plugin_name: str) -> LegacyPluginAdapter:
    """
    Create a legacy plugin adapter.

    Args:
        plugin_module: The legacy plugin module
        plugin_name: Name of the plugin

    Returns:
        LegacyPluginAdapter instance
    """
    return LegacyPluginAdapter(plugin_module, plugin_name, None)
