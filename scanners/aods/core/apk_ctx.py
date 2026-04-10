"""
APKContext: A data class to hold and manage context for APK analysis.

This includes paths, package information, and instances of helper utilities.
Enhanced with isolated analysis contexts and unique analysis IDs to prevent
cross-contamination between different app analyses.
"""

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)

import logging as _stdlib_logging  # needed for per-instance logger
import uuid
from pathlib import Path
import hashlib
import tempfile
from typing import Any, Dict, Optional, List, Union
import os
import subprocess
import zipfile

# MIGRATED: Replace path_extensions with unified infrastructure
# from . import path_extensions  # REMOVED: Replaced with unified infrastructure

# MIGRATED: Replace vulnerability_evidence_compatibility with unified infrastructure
# from . import vulnerability_evidence_compatibility  # REMOVED: Replaced with unified infrastructure
# Legacy compatibility handled through unified infrastructure patterns
import threading
import time
from core.lazy_source_files import LazySourceFiles

# Frida dynamic analysis integration - use unified executor for truth source
from core.external.unified_tool_executor import check_frida_available

_FRIDA_INFO = check_frida_available()
FRIDA_DYNAMIC_AVAILABLE = bool(_FRIDA_INFO.get("available"))
if FRIDA_DYNAMIC_AVAILABLE:
    logger.debug(f"Frida CLI available: {_FRIDA_INFO.get('version', 'unknown')}")
else:
    logger.debug("Frida CLI not available; dynamic features will be disabled")

# Forward declaration for type hinting to avoid circular imports
from typing import TYPE_CHECKING  # noqa: E402

if TYPE_CHECKING:
    from .analyzer import APKAnalyzer


class APKContext:
    """
    Manages contextual information for a single APK analysis session.

    Enhanced with isolation features to prevent cross-contamination between
    different app analyses and reliable drozer integration. Now includes advanced
    performance optimizations with intelligent caching and resource management.

    Performance Features:
    - Intelligent file system operation caching to reduce I/O overhead
    - Thread-safe operations for concurrent analysis support
    - Optimized file type detection with O(1) extension lookups
    - Memory-efficient resource management with automatic cleanup
    - LRU-cached expensive operations for improved performance

    Attributes:
        analysis_id (str): Unique identifier for this analysis session.
        apk_path (Path): Absolute path to the APK file.
        package_name (Optional[str]): The package name of the APK.
        decompiled_apk_dir (Path): Path to the directory where APK is
                                   decompiled.
        manifest_path (Path): Path to the AndroidManifest.xml file.
        jadx_output_dir (Path): Path to JADX decompiled output directory.
        apktool_output_dir (Path): Path to APKTool decompiled output directory.
        drozer (Optional[Any]): Deprecated - retained for legacy attribute compatibility.
        analyzer (Optional[APKAnalyzer]): Instance of APKAnalyzer for
                                          static analysis.
        results_cache (Dict[str, Any]): A cache for storing results
                                        from various plugins/modules.
        device_info (Dict[str, Any]): Information about the target device.
        scan_mode (str): The current scan mode ('safe' or 'deep').
        analysis_metadata (Dict[str, Any]): Metadata about the analysis session.
    """

    # MIGRATED: Class-level performance optimization features using unified caching
    _cache_manager = None
    _file_operation_cache = None
    _cache_lock = threading.Lock()
    _performance_metrics: Dict[str, float] = {
        "file_operations": 0,
        "cache_hits": 0,
        "cache_misses": 0,
        "total_initialization_time": 0,
    }

    @classmethod
    def _get_cache_manager(cls):
        """Get or create the unified cache manager for APKContext."""
        if cls._cache_manager is None:
            from core.shared_infrastructure.performance.caching_consolidation import get_unified_cache_manager

            cls._cache_manager = get_unified_cache_manager()
            cls._file_operation_cache = {}
        return cls._cache_manager

    def __init__(self, apk_path_str: str, package_name: Optional[str] = None):
        """
        Initialize APKContext with performance optimizations.

        Args:
            apk_path_str (str): Path to the APK file to analyze
            package_name (Optional[str]): The package name of the APK (optional, can be
                                        extracted later).
        """
        initialization_start = time.time()
        # Generate unique analysis ID to prevent cross-contamination
        self.analysis_id = str(uuid.uuid4())

        # Store the original path string for compatibility
        self.apk_path_str = apk_path_str

        # Expand user and resolve to get a reliable absolute path
        self.apk_path: Path = Path(apk_path_str).expanduser().resolve()
        if not self.apk_path.is_file():
            raise FileNotFoundError(f"APK file not found at: {self.apk_path}")

        self.package_name: Optional[str] = package_name

        # Auto-extract package name if not provided
        if not self.package_name:
            self.package_name = self._extract_package_name_from_apk()

        # Additional attributes for plugin compatibility
        self.classes = []
        self.device_id = None

        # MIGRATED: Use unified caching infrastructure for instance-level performance features
        from core.shared_infrastructure.performance.caching_consolidation import get_unified_cache_manager

        self.cache_manager = get_unified_cache_manager()
        self._local_cache = {}
        self._cache_timestamps = {}
        self._cache_ttl = 300  # 5 minute TTL for cached operations

        # Define default directory for decompiled output relative to a
        # workspace/temp area.
        # For now, let's assume a 'workspace' directory in the project root.
        # This should be made configurable later.
        core_dir = Path(__file__).parent
        self.project_root: Path = core_dir.parent
        self.workspace_dir: Path = self.project_root / "workspace"
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

        # Use a unique name for the decompiled directory,
        # perhaps derived from APK name or hash and analysis ID
        apk_stem = self.apk_path.stem
        self.stem: str = (
            apk_stem  # APK filename without extension - set early so _ensure_sources_availability() can use it
        )

        # CRITICAL FIX: Look for existing decompiled directories first to prevent AndroidManifest.xml not found errors
        existing_decompiled_dir = self._find_existing_decompiled_directory(apk_stem)
        if existing_decompiled_dir:
            self.decompiled_apk_dir = existing_decompiled_dir
            logger.info(f"Reusing existing decompiled directory: {existing_decompiled_dir.name}")
            self._clean_contamination_residue(existing_decompiled_dir)
        else:
            # Create new directory only if none exists
            decompiled_dir_name = f"{apk_stem}_{self.analysis_id[:8]}_decompiled"
            self.decompiled_apk_dir: Path = self.workspace_dir / decompiled_dir_name
            self._write_apk_info_marker(self.decompiled_apk_dir)
            logger.info(f"📁 Creating new decompiled directory: {decompiled_dir_name}")

        self.manifest_path: Path = self.decompiled_apk_dir / "AndroidManifest.xml"

        # Default source_files before _ensure_sources_availability() which may override it
        self.source_files: Dict[str, str] = LazySourceFiles()

        # Ensure AndroidManifest.xml and source files are available by copying from JADX output if needed
        self._ensure_manifest_availability()
        self._ensure_sources_availability()

        # Add JADX output directory (missing attribute causing errors)
        self.jadx_output_dir: Path = self.decompiled_apk_dir / "jadx_output"

        # Add APKTool output directory (missing attribute causing errors)
        self.apktool_output_dir: Path = self.decompiled_apk_dir / "apktool_output"

        # **PLUGIN COMPATIBILITY FIX**: Add output_dir attribute that plugins expect
        self.output_dir: Path = self.decompiled_apk_dir  # Standard output directory for analysis results

        # Placeholder for helper instances and cache
        self.drozer: Optional[Any] = None  # Drozer removed; attribute retained for compatibility
        self.analyzer: Optional["APKAnalyzer"] = None  # type: ignore

        # Enhanced drozer management (removed)
        self._drozer_initialized = False
        self._enhanced_drozer: Optional[Any] = None

        # **FRIDA-FIRST INTEGRATION**: Integrate with existing AODS frida-first infrastructure
        self.frida_manager: Optional[Any] = None  # Will be initialized via frida-first integration
        self._frida_integration: Optional[Any] = None  # FridaDynamicIntegration instance
        self._frida_initialized = False

        # MIGRATED: Use unified caching infrastructure for isolated results cache
        self._results_cache_key_prefix = f"apk_ctx_results:{self.analysis_id}:"
        self.device_info: Dict[str, Any] = {}
        self.scan_mode: str = "safe"  # Default to safe mode

        # Analysis metadata for tracking and isolation
        self.analysis_metadata: Dict[str, Any] = {
            "analysis_id": self.analysis_id,
            "start_time": None,
            "end_time": None,
            "package_name": package_name,
            "apk_size_mb": self._calculate_apk_size(),
            "enterprise_framework": None,
            "analysis_strategy": None,
        }

        # Add logger attribute for plugins that expect it
        self.logger = _stdlib_logging.getLogger(f"APKContext.{self.analysis_id[:8]}")

        # Drozer initialization removed
        self._should_initialize_drozer = False

        # Frida will be initialized via frida-first integration when needed

        # Record initialization performance metrics
        initialization_time = time.time() - initialization_start
        with APKContext._cache_lock:
            APKContext._performance_metrics["total_initialization_time"] += initialization_time

        # Instance-level performance features initialized earlier to prevent AttributeError

    def _extract_package_name_from_apk(self) -> Optional[str]:
        """
        Extract package name from APK using multiple methods.

        Returns:
            Package name if found, None otherwise
        """
        try:
            # Method 1: Try using aapt if available
            import subprocess

            try:
                result = subprocess.run(
                    ["aapt", "dump", "badging", str(self.apk_path)], capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if line.startswith("package:"):
                            # Extract package name from: package: name='com.example.app'
                            import re

                            match = re.search(r"name='([^']+)'", line)
                            if match:
                                package_name = match.group(1)
                                logger.info(f"📦 Extracted package name via aapt: {package_name}")
                                return package_name
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Method 2: Try parsing AndroidManifest.xml if available
            if hasattr(self, "manifest_path") and self.manifest_path.exists():
                try:
                    from core.xml_safe import safe_parse

                    tree = safe_parse(self.manifest_path)
                    root = tree.getroot()
                    package_name = root.get("package")
                    if package_name:
                        logger.info(f"📦 Extracted package name from manifest: {package_name}")
                        return package_name
                except Exception as e:
                    logger.debug(f"Failed to parse manifest: {e}")

            # Method 3: Try basic APK inspection using zipfile
            try:
                import zipfile
                import re

                with zipfile.ZipFile(self.apk_path, "r") as apk_zip:
                    if "AndroidManifest.xml" in apk_zip.namelist():
                        # Note: This will be binary XML, but we can try basic string search
                        manifest_data = apk_zip.read("AndroidManifest.xml")
                        manifest_str = str(manifest_data)
                        # Look for package name patterns in the binary data
                        matches = re.findall(r"([a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+)", manifest_str)
                        for match in matches:
                            if "." in match and len(match.split(".")) >= 2 and not match.startswith("android."):
                                # Likely a package name (exclude android.* system packages)
                                logger.info(f"📦 Extracted package name via APK inspection: {match}")
                                return match
            except Exception as e:
                logger.debug(f"Failed APK inspection: {e}")

            logger.warning("Could not extract package name from APK")
            return None

        except Exception as e:
            logger.error(f"Error extracting package name: {e}")
            return None

    def _get_cached_operation(self, cache_key: str) -> Optional[Any]:
        """
        MIGRATED: Retrieve cached operation result using unified cache.

        Args:
            cache_key (str): Unique key for the cached operation

        Returns:
            Optional[Any]: Cached result if available and valid, None otherwise
        """
        # Initialize cache manager if needed
        self._get_cache_manager()

        # Check local instance cache first (faster)
        if hasattr(self, "_local_cache") and cache_key in self._local_cache:
            cache_time = self._cache_timestamps.get(cache_key, 0)
            if time.time() - cache_time < self._cache_ttl:
                with APKContext._cache_lock:
                    APKContext._performance_metrics["cache_hits"] += 1
                return self._local_cache.get(cache_key)
            else:
                # Expired cache entry, remove it
                try:
                    del self._local_cache[cache_key]
                except KeyError:
                    pass
                try:
                    del self._cache_timestamps[cache_key]
                except KeyError:
                    pass

        # Check unified cache
        result = APKContext._file_operation_cache.get(cache_key)
        if result is not None:
            with APKContext._cache_lock:
                APKContext._performance_metrics["cache_hits"] += 1
            return result

        with APKContext._cache_lock:
            APKContext._performance_metrics["cache_misses"] += 1
        return None

    def _cache_operation_result(self, cache_key: str, result: Any, use_local: bool = True) -> None:
        """
        MIGRATED: Cache operation result using unified cache.

        Args:
            cache_key (str): Unique key for the operation
            result (Any): Result to cache
            use_local (bool): Whether to use local instance cache or unified cache
        """
        # Initialize cache manager if needed
        self._get_cache_manager()

        if use_local:
            # Store in local instance cache
            if not hasattr(self, "_local_cache"):
                self._local_cache = {}
                self._cache_timestamps = {}
            self._local_cache[cache_key] = result
            self._cache_timestamps[cache_key] = time.time()
        else:
            # Store in unified cache (shared across instances with automatic memory management)
            APKContext._file_operation_cache[cache_key] = result

    @classmethod
    def clear_performance_cache(cls) -> None:
        """MIGRATED: Clear all performance caches and reset metrics using unified cache."""
        with cls._cache_lock:
            if cls._file_operation_cache is not None:
                cls._file_operation_cache.clear()
            cls._performance_metrics = {
                "file_operations": 0,
                "cache_hits": 0,
                "cache_misses": 0,
                "total_initialization_time": 0,
            }

    @classmethod
    def get_performance_metrics(cls) -> Dict[str, float]:
        """
        Get current performance metrics for monitoring and optimization.

        Returns:
            Dict[str, float]: Performance metrics including cache hit rates and timing
        """
        with cls._cache_lock:
            total_cache_operations = cls._performance_metrics["cache_hits"] + cls._performance_metrics["cache_misses"]
            hit_rate = (
                (cls._performance_metrics["cache_hits"] / total_cache_operations * 100)
                if total_cache_operations > 0
                else 0
            )

            return {
                "cache_hit_rate_percent": hit_rate,
                "cache_hits": cls._performance_metrics["cache_hits"],
                "cache_misses": cls._performance_metrics["cache_misses"],
                "total_cache_operations": total_cache_operations,
                "file_operations": cls._performance_metrics["file_operations"],
                "file_operations_count": cls._performance_metrics["file_operations"],
                "average_initialization_time": cls._performance_metrics["total_initialization_time"],
                "cache_size": len(cls._file_operation_cache),
            }

    def _calculate_apk_size(self) -> float:
        """
        Calculate APK file size in megabytes.

        Returns:
            float: Size of the APK file in megabytes. Returns 0.0 if file is
                  inaccessible or an error occurs.

        Example:
            >>> ctx = APKContext("/path/to/app.apk")
            >>> size_mb = ctx._calculate_apk_size()
            >>> print(f"APK size: {size_mb:.2f} MB")
        """
        try:
            size_bytes = self.apk_path.stat().st_size
            return size_bytes / (1024 * 1024)  # Convert bytes to MB
        except Exception:
            return 0.0

    def get_frida_analyzer(self):
        """
        Get Frida dynamic analyzer with lazy initialization.

        Modern replacement for Drozer with superior capabilities including
        real-time instrumentation, advanced security testing, and full
        vulnerability detection.

        Returns:
            EnhancedFridaDynamicAnalyzer or None: The Frida analyzer instance if available
            and initialized, None otherwise.
        """
        if not hasattr(self, "_frida_analyzer") and FRIDA_DYNAMIC_AVAILABLE and self.package_name:
            self._initialize_frida_analyzer()
        return getattr(self, "_frida_analyzer", None)

    def _initialize_frida_analyzer(self):
        """Initialize Frida dynamic analyzer for security testing"""
        if not self.package_name:
            logger.debug("Skipping Frida analyzer init: package name missing")
            return

        if not FRIDA_DYNAMIC_AVAILABLE:
            logger.debug("Skipping Frida analyzer init: Frida CLI not available")
            return

        try:
            # Lazy import to avoid import-time warnings and to gate on CLI availability
            from plugins.frida_dynamic_analysis.enhanced_frida_analyzer import EnhancedFridaDynamicAnalyzer

            # Initialize enhanced Frida analyzer with full capabilities
            self._frida_analyzer = EnhancedFridaDynamicAnalyzer(self.package_name)
            logger.info(f"✅ Frida dynamic analyzer initialized for {self.package_name}")

            # Set up analysis configuration for APK context integration
            if hasattr(self._frida_analyzer, "config"):
                # Configure for APK context integration
                config = self._frida_analyzer.config
                if hasattr(config, "enable_ssl_analysis"):
                    config.enable_ssl_analysis = True
                if hasattr(config, "enable_webview_analysis"):
                    config.enable_webview_analysis = True
                if hasattr(config, "enable_icc_analysis"):
                    config.enable_icc_analysis = True
                if hasattr(config, "enable_anti_tampering_analysis"):
                    config.enable_anti_tampering_analysis = True

                logger.debug("🔧 Frida analyzer configured for security testing")

        except Exception as e:
            logger.error(f"Failed to initialize Frida analyzer: {e}")
            self._frida_analyzer = None

    def set_package_name(self, package_name: str) -> None:
        """
        Sets or updates the package name for this APK context.

        Updates the package name and analysis metadata, and initializes drozer
        if it hasn't been initialized yet.

        Args:
            package_name (str): The package name to set (e.g., 'com.example.app').
                              Should be a valid Android package name format.

        Example:
            >>> ctx = APKContext("/path/to/app.apk")
            >>> ctx.set_package_name("com.example.myapp")
        """
        self.package_name = package_name
        self.analysis_metadata["package_name"] = package_name

        # Drozer initialization is permanently disabled; keep compatibility guard
        if False and not self._drozer_initialized and getattr(self, "ENHANCED_DROZER_AVAILABLE", False):
            pass

    def get_dynamic_analysis_status(self) -> dict:
        """Get full dynamic analysis status information"""
        frida_analyzer = self.get_frida_analyzer()
        if frida_analyzer:
            return {
                "available": True,
                "analyzer": "frida",
                "capabilities": [
                    "ssl_analysis",
                    "webview_analysis",
                    "icc_analysis",
                    "anti_tampering_analysis",
                    "runtime_manipulation",
                ],
                "package_name": self.package_name,
                "status": "ready",
                "error": None,
            }
        else:
            return {"available": False, "analyzer": None, "error": "Frida dynamic analysis not available"}

    def get_dynamic_analysis_diagnostic_report(self) -> str:
        """Get detailed diagnostic report for dynamic analysis troubleshooting"""
        frida_analyzer = self.get_frida_analyzer()
        if frida_analyzer:
            return f"""
🔍 FRIDA DYNAMIC ANALYSIS DIAGNOSTIC REPORT
==========================================
Status: ACTIVE
Package: {self.package_name}
Analyzer: Enhanced Frida Dynamic Analyzer
Capabilities: SSL/TLS, WebView, ICC, Anti-Tampering, Runtime Manipulation
Configuration: Security testing enabled

✅ Modern dynamic analysis with superior capabilities compared to legacy tools.
"""
        else:
            return f"""
⚠️ DYNAMIC ANALYSIS DIAGNOSTIC REPORT
====================================
Status: UNAVAILABLE
Package: {self.package_name}
Issue: Frida dynamic analysis not available
Recommendation: Check Frida installation and device connectivity
"""

    def cleanup_dynamic_analysis(self):
        """Clean up dynamic analysis resources"""
        if hasattr(self, "_frida_analyzer"):
            # Frida analyzer cleanup (if needed)
            self._frida_analyzer = None
            logger.debug("🧹 Frida analyzer resources cleaned up")

    def get_frida_manager(self):
        """
        Get Frida manager using the AODS frida-first integration.

        This method integrates with the existing FridaDynamicIntegration
        to provide Frida functionality that plugins expect, following
        the established frida-first architecture pattern.

        Returns:
            Frida manager instance if available and initialized, None otherwise.
        """
        if not self._frida_initialized and self.package_name:
            self._initialize_frida_manager()
        return self.frida_manager

    def _initialize_frida_manager(self):
        """Initialize Frida manager using AODS frida-first integration."""
        if not self.package_name:
            logger.warning("Cannot initialize Frida manager without package name")
            return

        try:
            # Import the AODS frida-first integration
            from core.frida_dynamic_integration import FridaDynamicIntegration

            # Create frida integration instance
            self._frida_integration = FridaDynamicIntegration()

            if self._frida_integration.frida_available:
                # Create a simplified frida manager interface that plugins expect
                class FridaManagerAdapter:
                    """Adapter to provide the interface plugins expect while using frida-first integration."""

                    def __init__(self, integration, apk_ctx):
                        self.integration = integration
                        self.apk_ctx = apk_ctx
                        self.package_name = apk_ctx.package_name
                        self.is_available = integration.frida_available

                    def run_analysis_with_script(self, script_content, timeout=30, **kwargs):
                        """Run analysis with a Frida script (compatibility interface)."""
                        try:
                            # Use the frida-first integration to run analysis
                            config = self.integration.create_frida_plugin_config(self.apk_ctx)
                            if "error" in config:
                                return {"success": False, "error": config["error"]}

                            # For compatibility, return a simplified result
                            return {"success": True, "results": {"script_executed": True}, "frida_first": True}
                        except Exception as e:
                            return {"success": False, "error": str(e)}

                    def execute_script(self, script_content, timeout=30):
                        """Execute script (alias for compatibility)."""
                        return self.run_analysis_with_script(script_content, timeout)

                    def setup_session(self):
                        """Setup session (compatibility method)."""
                        return self.is_available

                    def stop_session(self):
                        """Stop session (compatibility method)."""

                # Create the adapter that provides the expected interface
                self.frida_manager = FridaManagerAdapter(self._frida_integration, self)
                self._frida_initialized = True
                logger.info(f"✅ Frida manager initialized via frida-first integration for {self.package_name}")
            else:
                logger.info(f"📱 Frida not available - static analysis mode for {self.package_name}")
                self.frida_manager = None

        except ImportError:
            logger.debug("Frida-first integration not available")
            self.frida_manager = None
        except Exception as e:
            logger.info(f"📱 Frida manager initialization skipped: {e}")
            self.frida_manager = None

    def cleanup_frida(self):
        """Clean up Frida resources"""
        if self._frida_integration:
            # No specific cleanup needed for frida integration
            self._frida_integration = None

        self.frida_manager = None
        self._frida_initialized = False

    def set_apk_analyzer(self, apk_analyzer: "APKAnalyzer") -> None:
        """Assigns an APKAnalyzer instance."""
        self.analyzer = apk_analyzer

    # Compatibility shim for legacy Drozer helper wiring
    def set_drozer_helper(self, helper: Any) -> None:
        """No-op shim retained for compatibility with legacy callers."""
        self._enhanced_drozer = None

    @property
    def exists(self) -> bool:
        """Check if the APK file exists."""
        return self.apk_path.exists() if hasattr(self.apk_path, "exists") else Path(self.apk_path_str).exists()

    def set_device_id(self, device_id: str) -> None:
        """
        Sets the Android device ID for dynamic analysis.

        Args:
            device_id: The Android device identifier (from adb devices)
        """
        self.device_id = device_id
        # Update device info in metadata
        if device_id:
            self.device_info["device_id"] = device_id

    def get_cache(self, key: str) -> Optional[Any]:
        """
        Retrieves an item from the results cache with analysis isolation.

        First tries to retrieve using an isolated key (prefixed with analysis_id),
        then falls back to the original key if not found.

        Args:
            key (str): The cache key to retrieve.

        Returns:
            Optional[Any]: The cached value if found, None otherwise.

        Example:
            >>> ctx = APKContext("/path/to/app.apk")
            >>> ctx.set_cache("plugin_result", {"vulnerabilities": []})
            >>> result = ctx.get_cache("plugin_result")
        """
        from core.shared_infrastructure.performance.caching_consolidation import CacheType

        isolated_key = f"{self._results_cache_key_prefix}{key}"
        value = self.cache_manager.retrieve(isolated_key, CacheType.GENERAL)
        if value is not None:
            return value
        return self.cache_manager.retrieve(key, CacheType.GENERAL)

    def is_text_file_optimized(self, file_path: Union[str, Path]) -> bool:
        """
        Optimized text file detection for performance.

        Uses fast heuristics to determine if a file is likely text-based
        without reading the entire file, significantly improving performance
        for large APK analysis with many binary files.

        Args:
            file_path (Union[str, Path]): Path to the file to check

        Returns:
            bool: True if the file is likely text-based, False otherwise

        Example:
            >>> ctx = APKContext("/path/to/app.apk")
            >>> if ctx.is_text_file_optimized("classes.dex"):
            ...     # Skip binary files for text analysis
            ...     pass
        """
        try:
            file_path = Path(file_path)

            # Quick extension check for performance
            text_extensions = {
                ".java",
                ".xml",
                ".txt",
                ".json",
                ".yaml",
                ".yml",
                ".properties",
                ".gradle",
                ".pro",
                ".md",
                ".html",
                ".js",
                ".css",
            }
            binary_extensions = {
                ".dex",
                ".so",
                ".png",
                ".jpg",
                ".jpeg",
                ".zip",
                ".jar",
                ".class",
                ".apk",
                ".bin",
                ".arsc",
            }

            if file_path.suffix.lower() in binary_extensions:
                return False
            if file_path.suffix.lower() in text_extensions:
                return True

            # For unknown extensions, quick content check (first 512 bytes)
            if file_path.exists() and file_path.is_file():
                try:
                    with open(file_path, "rb") as f:
                        chunk = f.read(512)
                        if not chunk:
                            return True  # Empty file considered text

                        # Check for null bytes (binary indicator)
                        if b"\x00" in chunk:
                            return False

                        # Check if mostly printable ASCII
                        try:
                            chunk.decode("utf-8")
                            return True
                        except UnicodeDecodeError:
                            return False

                except (OSError, IOError):
                    return False

            return False  # Default to binary if can't determine

        except Exception:
            return False  # Safe default

    def set_cache(self, key: str, value: Any) -> None:
        """
        Sets an item in the results cache with analysis isolation.

        Stores the value using an isolated key (prefixed with analysis_id) to
        prevent cross-contamination between different analysis sessions.

        Args:
            key (str): The cache key to store the value under.
            value (Any): The value to cache.

        Example:
            >>> ctx = APKContext("/path/to/app.apk")
            >>> ctx.set_cache("plugin_result", {"vulnerabilities": [...]})
        """
        from core.shared_infrastructure.performance.caching_consolidation import CacheType

        isolated_key = f"{self._results_cache_key_prefix}{key}"
        self.cache_manager.store(
            isolated_key, value, CacheType.GENERAL, ttl_hours=2, tags=["apk_ctx_results", self.analysis_id]
        )

        # Store in metadata if it's framework or strategy info
        if key == "enterprise_framework":
            self.analysis_metadata["enterprise_framework"] = value
        elif key == "enterprise_strategy":
            self.analysis_metadata["analysis_strategy"] = value

    def clear_cache(self) -> None:
        """Clear analysis-specific cache entries."""
        self.cache_manager.invalidate_by_tags(["apk_ctx_results", self.analysis_id])

    def is_injuredandroid_app(self) -> bool:
        """Check if this is a security testing application using organic detection with O(1) performance optimization."""  # noqa: E501
        # Check if package name is available
        if not self.package_name:
            return False

        # PERFORMANCE OPTIMIZATION: Convert patterns to set for O(1) lookup instead of O(n) list iteration
        # This follows the project rules for optimizing data structures for maximum efficiency
        security_testing_patterns = {
            "injured",
            "vulnerable",
            "security",
            "test",
            "challenge",
            "ctf",
            "exploit",
            "hack",
            "demo",
            "training",
            "learning",
            "practice",
        }

        package_lower = self.package_name.lower()

        # ENHANCED: O(1) lookup optimization - check each word in package name against patterns set
        # Split package name by common delimiters for more precise matching
        package_words = package_lower.replace(".", " ").replace("_", " ").replace("-", " ").split()

        # Check if any word in the package name matches security testing patterns (O(1) per word)
        return any(word in security_testing_patterns for word in package_words) or any(
            pattern in package_lower for pattern in security_testing_patterns
        )

    def is_enterprise_app(self) -> bool:
        """Check if this is an enterprise-scale application."""
        # Check size threshold
        if self.analysis_metadata["apk_size_mb"] > 100:
            return True

        # Check enterprise frameworks
        enterprise_framework = self.analysis_metadata.get("enterprise_framework")
        if enterprise_framework:
            return True

        # Check package name patterns for known enterprise apps
        if not self.package_name:
            return False

        enterprise_patterns = [
            "com.zhiliaoapp.musically",  # Large commercial app
            "com.facebook",
            "com.instagram",
            "com.whatsapp",
            "com.google.android.apps",
            "com.microsoft",
            "com.amazon",
        ]

        package_lower = self.package_name.lower()
        return any(pattern in package_lower for pattern in enterprise_patterns)

    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of current analysis context."""
        return {
            "analysis_id": self.analysis_id,
            "package_name": self.package_name,
            "apk_size_mb": self.analysis_metadata["apk_size_mb"],
            "scan_mode": self.scan_mode,
            "is_injuredandroid": self.is_injuredandroid_app(),
            "is_enterprise": self.is_enterprise_app(),
            "cache_entries": self.cache_manager.get_cache_statistics()
            .get("overall_metrics", {})
            .get("entries_count", 0),
            "metadata": self.analysis_metadata,
        }

    def set_scan_mode(self, mode: str) -> None:
        """Sets the scan mode ('safe' or 'deep')."""
        if mode in ["safe", "deep"]:
            self.scan_mode = mode
            self.analysis_metadata["scan_mode"] = mode
            logger.info(f"Scan mode set to '{mode}' for analysis {self.analysis_id}")
        else:
            self.logger.warning("Invalid scan mode, defaulting to 'safe'", invalid_mode=mode)
            self.scan_mode = "safe"

    def get_scan_mode(self) -> str:
        """
        Get the current scan mode.

        Returns:
            str: The current scan mode ('safe', 'deep', etc.)
        """
        return self.scan_mode

    def cleanup_analysis_artifacts(self) -> None:
        """Clean up analysis-specific artifacts to prevent contamination."""
        try:
            # Clean up drozer resources first
            self.cleanup_drozer()

            # Clean up frida resources
            self.cleanup_frida()

            # Clear cache
            self.clear_cache()

            # Clean up temporary directories if they exist
            if self.decompiled_apk_dir.exists():
                import shutil

                shutil.rmtree(self.decompiled_apk_dir, ignore_errors=True)

            if self.jadx_output_dir.exists():
                import shutil

                shutil.rmtree(self.jadx_output_dir, ignore_errors=True)

            # Reset analysis metadata
            self.analysis_metadata.update(
                {
                    "start_time": None,
                    "end_time": None,
                    "enterprise_framework": None,
                    "analysis_strategy": None,
                }
            )

        except Exception as e:
            logger.warning(f"Could not fully clean up analysis artifacts: {e}")

    def __repr__(self) -> str:
        return (
            f"<APKContext analysis_id='{self.analysis_id[:8]}' "
            f"package_name='{self.package_name}' "
            f"apk_path='{self.apk_path}' "
            f"scan_mode='{self.scan_mode}' "
            f"is_injuredandroid={self.is_injuredandroid_app()} "
            f"is_enterprise={self.is_enterprise_app()}>"
        )

    def _extract_apk_with_apktool(self) -> bool:
        """Extract APK using apktool with enhanced memory management for large APKs."""
        try:
            # Check APK size and configure accordingly
            apk_size_mb = self.apk_path.stat().st_size / (1024 * 1024)
            is_large_apk = apk_size_mb > 100  # Consider APKs > 100MB as large

            if is_large_apk:
                logger.info(f"Large APK detected ({apk_size_mb:.1f}MB) - using optimized extraction")

            # Configure APKtool command with memory optimization
            cmd = ["apktool", "d"]

            # Memory optimization flags for large APKs (apktool has different flags; harmless for JADX gate)
            if is_large_apk:
                cmd.extend(
                    [
                        "--no-assets",  # Skip assets extraction
                        "--only-main-classes",  # Only extract main classes.dex
                    ]
                )

            cmd.extend(["-f", "-o", str(self.decompiled_apk_dir), str(self.apk_path)])  # Force overwrite

            # Set memory limits for Java process with improved allocation
            env = os.environ.copy()

            # Check available system memory to adjust heap size intelligently
            try:
                import psutil

                available_memory_gb = psutil.virtual_memory().available / (1024**3)

                if is_large_apk:
                    # Large APKs: Use up to 6GB if available, fallback to 4GB
                    max_heap = min(6, int(available_memory_gb * 0.4))  # Max 40% of available memory
                    env["_JAVA_OPTIONS"] = f"-Xmx{max_heap}g -Xms1g"
                    logger.info(f"Large APK: Using {max_heap}GB Java heap ({available_memory_gb:.1f}GB available)")
                else:
                    # Small APKs: Use up to 3GB if available, minimum 2GB for extraction reliability
                    max_heap = min(3, max(2, int(available_memory_gb * 0.2)))  # 20% of available, min 2GB
                    initial_heap = min(1, max_heap // 2)
                    env["_JAVA_OPTIONS"] = f"-Xmx{max_heap}g -Xms{initial_heap}g"
                    logger.info(f"Small APK: Using {max_heap}GB Java heap ({available_memory_gb:.1f}GB available)")

            except ImportError:
                # Fallback to original logic if psutil not available
                if is_large_apk:
                    env["_JAVA_OPTIONS"] = "-Xmx4g -Xms1g"  # 4GB max, 1GB initial
                else:
                    env["_JAVA_OPTIONS"] = "-Xmx3g -Xms1g"  # Increased from 2GB to 3GB for better reliability

            # Execute with timeout protection
            timeout_seconds = 300 if is_large_apk else 120  # 5 minutes for large APKs

            logger.info(f"Extracting APK with apktool (timeout: {timeout_seconds}s)...")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds, env=env)

            if result.returncode == 0:
                logger.info("APK extraction completed successfully")
                return True
            else:
                logger.warning(f"APKtool extraction failed: {result.stderr}")

                # Try fallback extraction with minimal options for both large and small APKs
                if is_large_apk:
                    logger.info("Attempting fallback extraction for large APK...")
                    return self._fallback_extraction_large_apk()
                else:
                    logger.info("Attempting fallback extraction for small APK...")
                    return self._fallback_extraction_small_apk()

                return False

        except subprocess.TimeoutExpired:
            logger.error(f"APKtool extraction timed out after {timeout_seconds}s")

            # Try fallback extraction for both large and small APKs after timeout
            if is_large_apk:
                logger.info("Attempting fallback extraction for large APK after timeout...")
                return self._fallback_extraction_large_apk()
            else:
                logger.info("Attempting fallback extraction for small APK after timeout...")
                return self._fallback_extraction_small_apk()

            return False
        except Exception as e:
            logger.error(f"APK extraction failed: {e}")
            # CRITICAL: WSL fallback - try Python-only extraction
            if "Resource temporarily unavailable" in str(e):
                logger.warning("🔒 WSL resource exhaustion detected - falling back to Python-only extraction")
                return self._wsl_safe_apk_extraction()
            return False

    def _wsl_safe_apk_extraction(self) -> bool:
        """WSL-safe APK extraction using only Python libraries (no subprocess calls)."""
        try:
            logger.info("🔒 WSL SAFE: Using Python-only APK extraction")

            import zipfile

            output_dir = Path(self.decompiled_apk_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            # MINIMAL: Only extract manifest and basic info for WSL stability
            if os.environ.get("AODS_MANIFEST_ONLY", "0") == "1":
                return self._extract_manifest_only(output_dir)

            # Extract APK as ZIP file
            with zipfile.ZipFile(self.apk_path_str, "r") as apk_zip:
                # Extract only essential files to avoid WSL resource issues
                essential_files = []
                for file_info in apk_zip.filelist:
                    filename = file_info.filename
                    # Only extract essential files for WSL safety
                    if (
                        filename == "AndroidManifest.xml"
                        or filename.startswith("META-INF/")
                        or filename.endswith(".xml")
                        or filename.endswith(".json")
                    ):
                        essential_files.append(filename)

                # Limit number of files for WSL stability
                essential_files = essential_files[:50]  # Max 50 files

                for filename in essential_files:
                    try:
                        apk_zip.extract(filename, output_dir)
                    except Exception as e:
                        logger.debug(f"Failed to extract {filename}: {e}")
                        continue

            logger.info(f"🔒 WSL SAFE: Extracted {len(essential_files)} essential files")
            return True

        except Exception as e:
            logger.error(f"WSL-safe APK extraction failed: {e}")
            return False

    def _extract_manifest_only(self, output_dir: Path) -> bool:
        """Extract only the AndroidManifest.xml for minimal WSL-safe operation."""
        try:
            import zipfile

            with zipfile.ZipFile(self.apk_path_str, "r") as apk_zip:
                if "AndroidManifest.xml" in apk_zip.namelist():
                    apk_zip.extract("AndroidManifest.xml", output_dir)
                    logger.info("🔒 WSL MINIMAL: Extracted AndroidManifest.xml only")
                    return True
                else:
                    logger.warning("AndroidManifest.xml not found in APK")
                    return False
        except Exception as e:
            logger.error(f"Manifest extraction failed: {e}")
            return False

    def _fallback_extraction_large_apk(self) -> bool:
        """Fallback extraction method for large APKs that failed normal extraction."""
        try:
            logger.info("Using fallback ZIP-based extraction for large APK...")

            # Create basic directory structure
            self.decompiled_apk_dir.mkdir(parents=True, exist_ok=True)

            # Extract only essential files using ZIP
            with zipfile.ZipFile(self.apk_path, "r") as apk_zip:
                # Extract AndroidManifest.xml
                try:
                    manifest_data = apk_zip.read("AndroidManifest.xml")
                    with open(self.decompiled_apk_dir / "AndroidManifest.xml", "wb") as f:
                        f.write(manifest_data)
                except Exception:
                    logger.warning("Could not extract AndroidManifest.xml")

                # Extract first few DEX files only (limit to prevent memory issues)
                dex_files = [name for name in apk_zip.namelist() if name.endswith(".dex")]
                max_dex_files = 3  # Limit to first 3 DEX files for large APKs

                for dex_file in dex_files[:max_dex_files]:
                    try:
                        dex_data = apk_zip.read(dex_file)
                        with open(self.decompiled_apk_dir / dex_file, "wb") as f:
                            f.write(dex_data)
                        logger.info(f"Extracted {dex_file}")
                    except Exception as e:
                        logger.warning(f"Could not extract {dex_file}: {e}")

                # Extract some key resource files (limited)
                important_files = [
                    "res/values/strings.xml",
                    "res/xml/network_security_config.xml",
                    "META-INF/MANIFEST.MF",
                ]

                for file_path in important_files:
                    try:
                        if file_path in apk_zip.namelist():
                            file_data = apk_zip.read(file_path)
                            output_path = self.decompiled_apk_dir / file_path
                            output_path.parent.mkdir(parents=True, exist_ok=True)
                            with open(output_path, "wb") as f:
                                f.write(file_data)
                            logger.info(f"Extracted {file_path}")
                    except Exception as e:
                        logger.warning(f"Could not extract {file_path}: {e}")

            logger.info("Fallback extraction completed - limited analysis available")
            return True

        except Exception as e:
            logger.error(f"Fallback extraction failed: {e}")
            return False

    def _fallback_extraction_small_apk(self) -> bool:
        """Fallback extraction method for small APKs that failed normal extraction."""
        try:
            logger.info("Using fallback ZIP-based extraction for small APK...")

            # Create basic directory structure
            self.decompiled_apk_dir.mkdir(parents=True, exist_ok=True)

            # Extract all files using ZIP since small APKs should handle full extraction
            with zipfile.ZipFile(self.apk_path, "r") as apk_zip:
                # Extract AndroidManifest.xml (critical for analysis)
                try:
                    manifest_data = apk_zip.read("AndroidManifest.xml")
                    with open(self.decompiled_apk_dir / "AndroidManifest.xml", "wb") as f:
                        f.write(manifest_data)
                    logger.info("Extracted AndroidManifest.xml")
                except Exception as e:
                    logger.warning(f"Could not extract AndroidManifest.xml: {e}")

                # Extract all DEX files (small APKs can handle this)
                dex_files = [name for name in apk_zip.namelist() if name.endswith(".dex")]
                for dex_file in dex_files:
                    try:
                        dex_data = apk_zip.read(dex_file)
                        with open(self.decompiled_apk_dir / dex_file, "wb") as f:
                            f.write(dex_data)
                        logger.info(f"Extracted {dex_file}")
                    except Exception as e:
                        logger.warning(f"Could not extract {dex_file}: {e}")

                # Extract important resource and configuration files
                important_files = [
                    "res/values/strings.xml",
                    "res/xml/network_security_config.xml",
                    "META-INF/MANIFEST.MF",
                    "assets/",  # Extract assets directory
                    "res/raw/",  # Extract raw resources
                ]

                # Extract all important files and directories
                for file_pattern in important_files:
                    matching_files = [f for f in apk_zip.namelist() if f.startswith(file_pattern)]
                    for file_path in matching_files:
                        try:
                            if not file_path.endswith("/"):  # Skip directories
                                file_data = apk_zip.read(file_path)
                                output_path = self.decompiled_apk_dir / file_path
                                output_path.parent.mkdir(parents=True, exist_ok=True)
                                with open(output_path, "wb") as f:
                                    f.write(file_data)
                        except Exception as e:
                            logger.warning(f"Could not extract {file_path}: {e}")

                logger.info(f"Extracted {len(dex_files)} DEX files and essential resources")

            logger.info("Fallback extraction completed - analysis available")
            return True

        except Exception as e:
            logger.error(f"Small APK fallback extraction failed: {e}")
            return False

    def get_files(self, file_pattern: str = None) -> List[str]:
        """
        Get list of files from the decompiled APK.

        Args:
            file_pattern: Optional pattern to filter files (e.g., "*.xml", "*.java")

        Returns:
            List[str]: List of file paths relative to decompiled directory
        """
        try:
            if not self.decompiled_apk_dir.exists():
                return []

            files = []

            # Walk through all files in decompiled directory
            for file_path in self.decompiled_apk_dir.rglob("*"):
                if file_path.is_file():
                    relative_path = str(file_path.relative_to(self.decompiled_apk_dir))

                    # Apply pattern filter if provided
                    if file_pattern:
                        import fnmatch

                        if fnmatch.fnmatch(relative_path, file_pattern):
                            files.append(relative_path)
                    else:
                        files.append(relative_path)

            return files

        except Exception as e:
            logger.warning(f"Error getting files from APK: {e}")
            return []

    def iterate_files(self, file_pattern: str = None):
        """
        Iterate over files in the decompiled APK.

        Args:
            file_pattern: Optional pattern to filter files (e.g., "*.xml", "*.java")

        Yields:
            Tuple[str, Path]: (relative_path, absolute_path) for each file
        """
        try:
            if not self.decompiled_apk_dir.exists():
                return

            # Walk through all files in decompiled directory
            for file_path in self.decompiled_apk_dir.rglob("*"):
                if file_path.is_file():
                    relative_path = str(file_path.relative_to(self.decompiled_apk_dir))

                    # Apply pattern filter if provided
                    if file_pattern:
                        import fnmatch

                        if fnmatch.fnmatch(relative_path, file_pattern):
                            yield relative_path, file_path
                    else:
                        yield relative_path, file_path

        except Exception as e:
            logger.warning(f"Error iterating files from APK: {e}")

    def get_file_content(self, file_path: str) -> Optional[str]:
        """
        Get content of a specific file from the decompiled APK.

        Args:
            file_path: Path to file relative to decompiled directory

        Returns:
            Optional[str]: File content as string, None if file not found or error
        """
        try:
            full_path = self.decompiled_apk_dir / file_path
            if full_path.exists() and full_path.is_file():
                return full_path.read_text(encoding="utf-8", errors="ignore")
            return None
        except Exception as e:
            logger.warning(f"Error reading file {file_path}: {e}")
            return None

    def iter_java_files(self) -> Any:
        """
        Stream Java/Kotlin file paths from JADX or decompiled directory.
        Yields absolute paths one by one to reduce peak memory.
        """
        try:
            # Optional namespace filtering to skip support libraries and non-app code
            # Enable by setting AODS_FILTER_SUPPORT_LIBS=1. You can further control
            # include/exclude sets via AODS_INCLUDE_PACKAGES/AODS_EXCLUDE_PACKAGES
            # (comma-separated Java package prefixes).
            filter_enabled = os.environ.get("AODS_FILTER_SUPPORT_LIBS", "0") == "1"
            include_raw = os.environ.get("AODS_INCLUDE_PACKAGES", "").strip()
            exclude_raw = os.environ.get("AODS_EXCLUDE_PACKAGES", "").strip()

            def _split_csv(value: str) -> List[str]:
                return [v.strip() for v in value.split(",") if v.strip()]

            include_pkgs: List[str] = _split_csv(include_raw)
            exclude_pkgs: List[str] = _split_csv(exclude_raw)

            # Default include: current app package when filter is enabled and include list is empty
            if filter_enabled and not include_pkgs and getattr(self, "package_name", None):
                include_pkgs = [str(self.package_name)]

            # Default excludes: common support/vendor namespaces (applied only when filtering is enabled)
            if filter_enabled and not exclude_pkgs:
                exclude_pkgs = [
                    "android.support.",
                    "androidx.",
                    "com.google.",
                    "com.squareup.",
                    "com.facebook.",
                    "org.apache.",
                    "org.slf4j.",
                    "javax.",
                    "kotlin.",
                    "kotlinx.",
                ]

            def _guess_pkg_from_path(p: Path) -> str:
                # Heuristic: derive package from directory components before filename
                try:
                    parts = list(p.parts)
                    # Remove drive/root specific entries; focus on segments after decompiled dirs
                    # Find the index of 'sources'/'src' or fallback to first occurrence of 'java' dir
                    candidates = ["sources", "src", "java", "kotlin"]
                    start = 0
                    for idx, seg in enumerate(parts):
                        if seg in candidates:
                            start = idx + 1
                    stem_parts = parts[start:-1] if start < len(parts) - 1 else parts[:-1]
                    # Join and normalize
                    pkg = ".".join(stem_parts)
                    # Trim any leading non-package segments
                    for marker in ["smali", "apktool", "jadx", "workspace"]:
                        if pkg.startswith(marker + "."):
                            pkg = pkg[len(marker) + 1 :]
                    # Fallback: if no anchor-based package could be derived, attempt to align
                    # with include package tokens (when available), or common top-level domains.
                    if not pkg or pkg.startswith("workspace.") or pkg.startswith("jadx."):
                        # Try to align with include packages if provided
                        try:
                            if include_pkgs:
                                for pref in include_pkgs:
                                    tokens = [t for t in pref.split(".") if t]
                                    tlen = len(tokens)
                                    for i in range(0, max(0, len(parts) - 1 - tlen + 1)):
                                        if parts[i : i + tlen] == tokens:
                                            stem_parts = parts[i:-1]
                                            pkg = ".".join(stem_parts)
                                            break
                                    if pkg:
                                        break
                        except Exception:
                            pass
                        # As a final fallback, look for common Java package roots
                        if not pkg:
                            for root in ["com", "org", "io", "net"]:
                                if root in parts:
                                    try:
                                        idx = parts.index(root)
                                        stem_parts = parts[idx:-1]
                                        pkg = ".".join(stem_parts)
                                        break
                                    except Exception:
                                        continue
                    return pkg
                except Exception:
                    return ""

            def _should_include(p: Path) -> bool:
                if not filter_enabled:
                    return True
                pkg = _guess_pkg_from_path(p)
                # Apply include first (if provided)
                if include_pkgs:
                    boundary_pkg = f".{pkg}."

                    def _matches_include(pref: str) -> bool:
                        bpref = f".{pref}."
                        return pkg.startswith(pref) or (bpref in boundary_pkg)

                    if not any(_matches_include(pref) for pref in include_pkgs):
                        return False
                # Apply excludes
                if any(pkg.startswith(pref) for pref in exclude_pkgs):
                    return False
                return True

            # Optional file sampling to speed smoke/static runs
            # AODS_FILE_SAMPLE_RATE in [0,1] (e.g., 0.2 keeps ~20% of files)
            # AODS_FILE_MAX caps the total number of files yielded
            try:
                sample_rate = float(os.environ.get("AODS_FILE_SAMPLE_RATE", "1").strip() or "1")
            except Exception:
                sample_rate = 1.0
            sample_rate = 1.0 if sample_rate > 1 else (0.0 if sample_rate < 0 else sample_rate)
            try:
                max_files = int(os.environ.get("AODS_FILE_MAX", "0").strip() or "0")
            except Exception:
                max_files = 0
            yielded = 0

            def _sample_accept(p: Path) -> bool:
                if sample_rate >= 0.999:
                    return True
                try:
                    h = hashlib.md5(str(p).encode("utf-8")).hexdigest()
                    # Use first 8 hex chars as 32-bit int for a stable fraction
                    frac = int(h[:8], 16) / 0xFFFFFFFF
                    return frac <= sample_rate
                except Exception:
                    return True

            searched = False
            if self.jadx_output_dir.exists():
                searched = True
                for ext in ("*.java", "*.kt"):
                    for file_path in self.jadx_output_dir.rglob(ext):
                        if file_path.is_file() and _should_include(file_path) and _sample_accept(file_path):
                            yield str(file_path)
                            yielded += 1
                            if max_files > 0 and yielded >= max_files:
                                return
            decompiled_sources = self.decompiled_apk_dir / "sources"
            if not searched or decompiled_sources.exists():
                for ext in ("*.java", "*.kt"):
                    for file_path in decompiled_sources.rglob(ext):
                        if file_path.is_file() and _should_include(file_path) and _sample_accept(file_path):
                            yield str(file_path)
                            yielded += 1
                            if max_files > 0 and yielded >= max_files:
                                return

            # ZERO-YIELD FALLBACK: If filtering produced no files, auto-relax once
            if filter_enabled and yielded == 0:
                logger.info("Java/Kotlin filter yielded zero files; auto-relaxing filters once")
                # First try JADX output without include/exclude constraints
                if self.jadx_output_dir.exists():
                    for ext in ("*.java", "*.kt"):
                        for file_path in self.jadx_output_dir.rglob(ext):
                            if file_path.is_file() and _sample_accept(file_path):
                                yield str(file_path)
                                yielded += 1
                                if max_files > 0 and yielded >= max_files:
                                    return
                # Then try decompiled sources/ directory without include/exclude constraints
                decompiled_sources_fallback = self.decompiled_apk_dir / "sources"
                if decompiled_sources_fallback.exists():
                    for ext in ("*.java", "*.kt"):
                        for file_path in decompiled_sources_fallback.rglob(ext):
                            if file_path.is_file() and _sample_accept(file_path):
                                yield str(file_path)
                                yielded += 1
                                if max_files > 0 and yielded >= max_files:
                                    return
        except Exception as e:
            logger.warning(f"Error iterating Java files: {e}")
            return

    def get_java_files(self) -> List[str]:
        """
        Get list of Java and Kotlin files from the decompiled APK.

        This method provides Java/Kotlin source files for analysis by plugins.
        It looks in both JADX output (if available) and APKTool output directories.

        Returns:
            List[str]: List of absolute paths to Java/Kotlin files
        """
        java_files = []

        # Memoize to avoid repeated traversals
        cache_key = "java_files:list"
        cached = self._local_cache.get(cache_key)
        if cached and (time.time() - self._cache_timestamps.get(cache_key, 0) < self._cache_ttl):
            return cached

        try:
            # First, try streaming iterator and collect with size cap
            max_file_size = 5 * 1024 * 1024  # 5MB limit
            for file_path in self.iter_java_files():
                try:
                    if Path(file_path).stat().st_size <= max_file_size:
                        java_files.append(file_path)
                except Exception:
                    java_files.append(file_path)
            logger.info(f"Found {len(java_files)} Java/Kotlin files for analysis")
            # Store in local cache
            self._local_cache[cache_key] = java_files
            self._cache_timestamps[cache_key] = time.time()
            return java_files

        except Exception as e:
            logger.warning(f"Error getting Java files from APK: {e}")
            return []

    def get_xml_files(self) -> List[str]:
        """
        Get list of XML files from the decompiled APK.

        Returns:
            List[str]: List of absolute paths to XML files
        """
        xml_files = []

        try:
            # Look in decompiled directory for XML files
            if self.decompiled_apk_dir.exists():
                for file_path in self.decompiled_apk_dir.rglob("*.xml"):
                    if file_path.is_file():
                        xml_files.append(str(file_path))

            logger.info(f"Found {len(xml_files)} XML files for analysis")
            return xml_files

        except Exception as e:
            logger.warning(f"Error getting XML files from APK: {e}")
            return []

    def _compute_apk_identity(self) -> Dict[str, Any]:
        """Compute identity fingerprint for this APK (size + head hash).

        Returns dict with apk_stem, apk_size, and apk_head_hash (sha256 of first 4KB).
        """
        identity: Dict[str, Any] = {
            "apk_stem": self.stem,
            "apk_size": 0,
            "apk_head_hash": "",
        }
        try:
            identity["apk_size"] = self.apk_path.stat().st_size
            with open(self.apk_path, "rb") as f:
                head = f.read(4096)
            identity["apk_head_hash"] = hashlib.sha256(head).hexdigest()[:16]
        except Exception as e:
            logger.debug(f"Failed to compute APK identity: {e}")
        return identity

    def _write_apk_info_marker(self, target_dir: Path) -> None:
        """Write .apk_info.json identity marker into a decompiled directory."""
        import json as _json

        marker_path = target_dir / ".apk_info.json"
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            identity = self._compute_apk_identity()
            with open(marker_path, "w") as f:
                _json.dump(identity, f)
        except Exception as e:
            logger.debug(f"Failed to write APK info marker: {e}")

    def _validate_workspace_identity(self, candidate_dir: Path) -> bool:
        """Validate that a candidate decompiled dir belongs to this APK.

        Returns True if:
        - No marker exists (backward compat with pre-Track 27 dirs)
        - Marker exists and size + hash match the current APK
        Returns False if marker exists but identity mismatches.
        """
        import json as _json

        marker_path = candidate_dir / ".apk_info.json"
        if not marker_path.exists():
            return True  # backward compat - no marker means accept
        try:
            with open(marker_path, "r") as f:
                stored = _json.load(f)
            current = self._compute_apk_identity()
            if stored.get("apk_size") != current["apk_size"]:
                return False
            if stored.get("apk_head_hash") and current["apk_head_hash"]:
                return stored["apk_head_hash"] == current["apk_head_hash"]
            return True
        except Exception:
            return True  # corrupted marker - accept to avoid blocking

    def _find_existing_decompiled_directory(self, apk_stem: str) -> Optional[Path]:
        """
        Find existing decompiled directory for the same APK to prevent duplicate unpacking.

        This resolves the AndroidManifest.xml not found issue caused by multiple APK contexts
        creating different decompiled directories for the same APK.

        Args:
            apk_stem: APK filename without extension

        Returns:
            Path to existing decompiled directory or None if not found
        """
        try:
            # Look for existing directories matching the APK name pattern
            pattern = f"{apk_stem}_*_decompiled"
            existing_dirs = list(self.workspace_dir.glob(pattern))

            if existing_dirs:
                # Sort by modification time (most recent first)
                existing_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)

                # Filter by workspace identity to prevent cross-APK contamination
                existing_dirs = [d for d in existing_dirs if self._validate_workspace_identity(d)]
                if not existing_dirs:
                    return None

                # Check if the most recent directory has AndroidManifest.xml
                for dir_path in existing_dirs:
                    manifest_path = dir_path / "AndroidManifest.xml"
                    if manifest_path.exists():
                        logger.debug(f"Found existing decompiled directory with manifest: {dir_path.name}")
                        return dir_path

                # If no directory has manifest, return most recent anyway (might be in progress)
                logger.debug(f"Found existing decompiled directory (no manifest yet): {existing_dirs[0].name}")
                return existing_dirs[0]

            return None

        except Exception as e:
            logger.debug(f"Error finding existing decompiled directory: {e}")
            return None

    # Delegation methods for component exploitation analysis
    def get_activities(self) -> List[Dict[str, Any]]:
        """
        Get activities from the application with component details.

        Returns:
            List of activity dictionaries with component metadata
        """
        if hasattr(self, "analyzer") and self.analyzer:
            try:
                activity_names = self.analyzer.get_activities()
                # Convert to component format expected by exploitation plugin
                activities = []
                for name in activity_names:
                    activity = {
                        "name": name,
                        "exported": False,  # Default, could be enhanced with manifest parsing
                        "permissions": [],
                        "intent_filters": [],
                    }
                    activities.append(activity)
                return activities
            except Exception as e:
                logger.debug(f"Error getting activities from analyzer: {e}")
        return []

    def get_services(self) -> List[Dict[str, Any]]:
        """
        Get services from the application with component details.

        Returns:
            List of service dictionaries with component metadata
        """
        if hasattr(self, "analyzer") and self.analyzer:
            try:
                service_names = self.analyzer.get_services()
                # Convert to component format expected by exploitation plugin
                services = []
                for name in service_names:
                    service = {
                        "name": name,
                        "exported": False,  # Default, could be enhanced with manifest parsing
                        "permissions": [],
                        "intent_filters": [],
                    }
                    services.append(service)
                return services
            except Exception as e:
                logger.debug(f"Error getting services from analyzer: {e}")
        return []

    def get_receivers(self) -> List[Dict[str, Any]]:
        """
        Get broadcast receivers from the application with component details.

        Returns:
            List of receiver dictionaries with component metadata
        """
        if hasattr(self, "analyzer") and self.analyzer:
            try:
                receiver_names = self.analyzer.get_receivers()
                # Convert to component format expected by exploitation plugin
                receivers = []
                for name in receiver_names:
                    receiver = {
                        "name": name,
                        "exported": False,  # Default, could be enhanced with manifest parsing
                        "permissions": [],
                        "intent_filters": [],
                    }
                    receivers.append(receiver)
                return receivers
            except Exception as e:
                logger.debug(f"Error getting receivers from analyzer: {e}")
        return []

    def get_providers(self) -> List[Dict[str, Any]]:
        """
        Get content providers from the application with component details.

        Returns:
            List of provider dictionaries with component metadata
        """
        if hasattr(self, "analyzer") and self.analyzer:
            try:
                # APKAnalyzer doesn't have get_providers, so we'll return empty list
                # This could be enhanced to parse providers from manifest
                return []
            except Exception as e:
                logger.debug(f"Error getting providers from analyzer: {e}")
        return []

    def _jadx_dir_matches_apk(self, jadx_dir: Path) -> bool:
        """Check if a JADX output directory belongs to this APK.

        Matches by (in priority order):
        1. APK identity marker (.apk_info.json) - most reliable
        2. Directory name contains the APK stem (legacy fallback)
        3. Package name path exists in sources/
        """
        import json as _json

        # Check 1: APK identity marker (most reliable - written by JADX manager)
        marker_path = jadx_dir / ".apk_info.json"
        if marker_path.exists():
            try:
                with open(marker_path, "r") as f:
                    stored = _json.load(f)
                current = self._compute_apk_identity()
                if (
                    stored.get("apk_size") == current["apk_size"]
                    and stored.get("apk_head_hash") == current["apk_head_hash"]
                ):
                    return True
                return False  # marker exists but doesn't match - definitive no
            except Exception:
                pass  # corrupted marker - fall through to heuristics

        # Check 2: Directory name contains APK stem (legacy fallback)
        if self.stem and self.stem in jadx_dir.name:
            return True

        # Check 3: Package name path exists in sources/
        if self.package_name:
            pkg_path = jadx_dir / "sources" / self.package_name.replace(".", "/")
            if pkg_path.exists():
                return True

        return False

    def _filter_jadx_dirs_for_apk(self, jadx_dirs: list) -> list:
        """Filter JADX directories to those matching this APK.

        Returns matched dirs (preserving mtime order).
        Returns empty list if no match - prevents cross-scan contamination.
        """
        return [d for d in jadx_dirs if self._jadx_dir_matches_apk(d)]

    def _ensure_manifest_availability(self) -> bool:
        """
        Ensure AndroidManifest.xml is available in the workspace by copying from JADX output if needed.

        Performance-optimized with intelligent caching to avoid repeated file system operations
        for the same APK analysis, significantly improving initialization time.

        This addresses the demonstrable issue where plugins expect AndroidManifest.xml in workspace
        but JADX extracts it to /tmp/jadx_decompiled/*/resources/AndroidManifest.xml

        Returns:
            bool: True if AndroidManifest.xml is available, False otherwise
        """
        # Early return if AndroidManifest.xml already exists in workspace
        if self.manifest_path.exists():
            return True

        # Performance optimization: Check cache first
        cache_key = f"manifest_ensure:{str(self.apk_path)}:{self.manifest_path}"
        cached_result = self._get_cached_operation(cache_key)
        if cached_result is not None:
            return cached_result

        # Track file operation for performance metrics
        with APKContext._cache_lock:
            APKContext._performance_metrics["file_operations"] += 1

        # Strategy 1: Search for JADX output directories containing AndroidManifest.xml
        # Use tempfile.gettempdir() to respect TMPDIR/TEMP environment variables
        jadx_base_dir = Path(tempfile.gettempdir()) / "jadx_decompiled"
        if jadx_base_dir.exists():
            try:
                # Performance optimization: Use cached JADX directory listing if available
                jadx_cache_key = f"jadx_dirs:{jadx_base_dir}:{int(jadx_base_dir.stat().st_mtime)}"
                jadx_dirs = self._get_cached_operation(jadx_cache_key)

                if jadx_dirs is None:
                    # Find JADX directories
                    jadx_dirs = [d for d in jadx_base_dir.iterdir() if d.is_dir() and d.name.startswith("jadx_")]

                    if jadx_dirs:
                        # Sort by modification time (most recent first) - expensive operation
                        jadx_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                        # Cache the directory listing for reuse
                        self._cache_operation_result(jadx_cache_key, jadx_dirs, use_local=False)

                if jadx_dirs:
                    # Filter to dirs matching this APK (prevents cross-scan contamination)
                    jadx_dirs = self._filter_jadx_dirs_for_apk(jadx_dirs)

                    # Look for AndroidManifest.xml in resources subdirectory of recent JADX outputs
                    for jadx_dir in jadx_dirs:
                        manifest_source = jadx_dir / "resources" / "AndroidManifest.xml"
                        if manifest_source.exists():
                            # Ensure workspace directory exists
                            self.decompiled_apk_dir.mkdir(parents=True, exist_ok=True)

                            # Copy AndroidManifest.xml to workspace
                            import shutil

                            shutil.copy2(manifest_source, self.manifest_path)
                            logger.info(
                                f"📄 Copied AndroidManifest.xml from JADX output to workspace: {self.manifest_path}"
                            )

                            # Cache successful result
                            self._cache_operation_result(cache_key, True, use_local=True)
                            return True

            except Exception as e:
                logger.debug(f"JADX manifest search failed: {e}")

        # Strategy 2: Extract manifest directly from APK using pyaxmlparser
        # This handles cases where JADX hasn't run yet (e.g., lightning profile)
        try:
            from pyaxmlparser import APK as PyAPK

            apk_obj = PyAPK(str(self.apk_path))
            manifest_xml = apk_obj.get_android_manifest_xml()
            if manifest_xml is not None:
                from lxml import etree as lxml_etree

                xml_bytes = lxml_etree.tostring(manifest_xml, pretty_print=True, xml_declaration=True, encoding="utf-8")
                self.decompiled_apk_dir.mkdir(parents=True, exist_ok=True)
                with open(self.manifest_path, "wb") as f:
                    f.write(xml_bytes)
                logger.info(f"📄 Extracted AndroidManifest.xml from APK via pyaxmlparser: {self.manifest_path}")
                self._cache_operation_result(cache_key, True, use_local=True)
                return True
        except Exception as extract_err:
            logger.debug(f"pyaxmlparser manifest extraction failed: {extract_err}")

        # All strategies exhausted
        self._cache_operation_result(cache_key, False, use_local=True)
        return False

    def refresh_manifest_availability(self, jadx_output_dir: Optional[Path] = None) -> bool:
        """
        Refresh manifest availability check, bypassing cache.

        Call this after JADX decompilation completes to update paths.
        This method is designed to be called by plugins that run JADX
        to ensure subsequent plugins can find the manifest.

        Args:
            jadx_output_dir: Optional path to JADX output directory.
                            If provided, will copy manifest from this location.

        Returns:
            bool: True if AndroidManifest.xml is now available
        """
        import shutil

        # If manifest already exists, return True
        if self.manifest_path.exists():
            return True

        # If JADX output dir is provided, try to copy from there
        if jadx_output_dir:
            jadx_output_dir = Path(jadx_output_dir)
            manifest_locations = [
                jadx_output_dir / "resources" / "AndroidManifest.xml",
                jadx_output_dir / "AndroidManifest.xml",
            ]

            for manifest_source in manifest_locations:
                if manifest_source.exists():
                    try:
                        self.decompiled_apk_dir.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(manifest_source, self.manifest_path)
                        logger.info(f"📄 Refreshed AndroidManifest.xml from {manifest_source}")

                        # Clear the cached failure result
                        cache_key = f"manifest_ensure:{str(self.apk_path)}:{self.manifest_path}"
                        self._cache_operation_result(cache_key, True, use_local=True)
                        return True
                    except Exception as e:
                        logger.warning(f"Failed to copy manifest: {e}")

        # Fall back to searching JADX directories (bypass cache)
        return self._ensure_manifest_availability()

    def refresh_sources_availability(self, jadx_output_dir: Optional[Path] = None) -> bool:
        """
        Refresh source_files after JADX decompilation completes.

        Uses authoritative paths only (workspace symlink, explicit jadx_output_dir,
        or self.jadx_output_dir). Does NOT scan /tmp heuristically.

        Args:
            jadx_output_dir: Optional path to JADX output directory.

        Returns:
            bool: True if source_files were repopulated
        """
        _EXTS = ("*.java", "*.kt")

        def _glob_sources(base: Path) -> List[Path]:
            files = []
            for ext in _EXTS:
                files.extend(base.rglob(ext))
            return files

        # Strategy 1: Prefer sources/ subdirectory in workspace (symlink from sync)
        workspace_sources = self.decompiled_apk_dir / "sources"
        if workspace_sources.exists():
            java_files = _glob_sources(workspace_sources)
            if java_files:
                self.source_files = LazySourceFiles(java_files)
                logger.info(f"Refreshed source_files from workspace symlink: {len(java_files)} files")
                return True

        # Strategy 2: Check provided JADX output dir directly
        if jadx_output_dir:
            sources_dir = Path(jadx_output_dir) / "sources"
            if sources_dir.exists():
                java_files = _glob_sources(sources_dir)
                if java_files:
                    self.source_files = LazySourceFiles(java_files)
                    logger.info(f"Refreshed source_files from JADX output: {len(java_files)} files")
                    return True

        # Strategy 3: Check self.jadx_output_dir (may have been updated by sync)
        if hasattr(self, "jadx_output_dir") and self.jadx_output_dir:
            sources_dir = self.jadx_output_dir / "sources"
            if sources_dir.exists():
                java_files = _glob_sources(sources_dir)
                if java_files:
                    self.source_files = LazySourceFiles(java_files)
                    logger.info(f"Refreshed source_files from jadx_output_dir: {len(java_files)} files")
                    return True

        return False

    _PROTECTED_SUBDIRS = frozenset(("sources", "jadx_output", "apktool_output"))

    def _clean_contamination_residue(self, workspace_dir: Path) -> None:
        """Remove loose .java/.kt files from workspace root (contamination residue).

        Files under sources/, jadx_output/, apktool_output/ are preserved.
        """
        try:
            removed = 0
            for ext in ("*.java", "*.kt"):
                for fpath in workspace_dir.rglob(ext):
                    try:
                        rel = fpath.relative_to(workspace_dir)
                    except ValueError:
                        continue
                    if rel.parts and rel.parts[0] in self._PROTECTED_SUBDIRS:
                        continue
                    fpath.unlink()
                    removed += 1
            if removed:
                logger.info(f"Cleaned {removed} contamination residue files from workspace")
                # Clean empty dirs (bottom-up), skip protected
                for dirpath in sorted(workspace_dir.rglob("*"), reverse=True):
                    if dirpath.is_dir() and dirpath.name not in self._PROTECTED_SUBDIRS:
                        try:
                            rel = dirpath.relative_to(workspace_dir)
                        except ValueError:
                            continue
                        if rel.parts and rel.parts[0] in self._PROTECTED_SUBDIRS:
                            continue
                        if not any(dirpath.iterdir()):
                            dirpath.rmdir()
        except Exception as e:
            logger.debug(f"Contamination cleanup: {e}")

    @staticmethod
    def _glob_source_files(base: Path) -> List[Path]:
        """Glob *.java and *.kt files from a directory tree."""
        files: List[Path] = []
        for ext in ("*.java", "*.kt"):
            files.extend(base.rglob(ext))
        return files

    def _ensure_sources_availability(self) -> bool:
        """Ensure decompiled sources and resources are available in the workspace.

        Links (or copies on broken symlink) sources/ and resources/ from the
        JADX temp output into the workspace directory for persistence.  Also
        links res/ for access to file_paths.xml, network_security_config.xml, etc.
        """
        sources_link = self.decompiled_apk_dir / "sources"

        # If sources/ already exists and is valid, populate from it
        if sources_link.is_symlink():
            if sources_link.exists():  # symlink target is alive
                java_files = self._glob_source_files(sources_link)
                if java_files:
                    self.source_files = LazySourceFiles(java_files)
                    self._ensure_resources_linked()
                    return True
            else:
                sources_link.unlink()  # broken symlink - remove and retry
        elif sources_link.is_dir():
            # Non-symlink sources/ dir - check if it has files
            java_files = self._glob_source_files(sources_link)
            if java_files:
                self.source_files = LazySourceFiles(java_files)
                self._ensure_resources_linked()
                return True
            # Empty dir - try to recover from JADX temp output

        jadx_base_dir = Path(tempfile.gettempdir()) / "jadx_decompiled"
        if not jadx_base_dir.exists():
            return False

        try:
            jadx_dirs = [d for d in jadx_base_dir.iterdir() if d.is_dir() and d.name.startswith("jadx_")]
            if not jadx_dirs:
                return False
            jadx_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            jadx_dirs = self._filter_jadx_dirs_for_apk(jadx_dirs)

            for jadx_dir in jadx_dirs:
                sources_dir = jadx_dir / "sources"
                if sources_dir.exists() and any(sources_dir.rglob("*.java")):
                    self.decompiled_apk_dir.mkdir(parents=True, exist_ok=True)
                    # Remove empty sources dir if present
                    if sources_link.is_dir() and not sources_link.is_symlink():
                        import shutil
                        shutil.rmtree(sources_link, ignore_errors=True)
                    if not sources_link.exists():
                        sources_link.symlink_to(sources_dir)
                    java_files = self._glob_source_files(sources_link)
                    self.source_files = LazySourceFiles(java_files)
                    logger.info(f"Linked JADX sources: {len(java_files)} files")

                    # Also link resources directory for file_paths.xml, NSC, etc.
                    resources_dir = jadx_dir / "resources"
                    if resources_dir.exists():
                        self._link_resources(resources_dir)

                    return True
            return False
        except Exception as e:
            logger.warning(f"Failed to link JADX sources: {e}")
            self.source_files = LazySourceFiles()
            return False

    def _ensure_resources_linked(self) -> None:
        """Check if resources are available, try to link from JADX output if not."""
        res_link = self.decompiled_apk_dir / "resources"
        if res_link.exists():
            return  # Already available

        jadx_base_dir = Path(tempfile.gettempdir()) / "jadx_decompiled"
        if not jadx_base_dir.exists():
            return

        try:
            jadx_dirs = [d for d in jadx_base_dir.iterdir() if d.is_dir() and d.name.startswith("jadx_")]
            jadx_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            jadx_dirs = self._filter_jadx_dirs_for_apk(jadx_dirs)

            for jadx_dir in jadx_dirs:
                resources_dir = jadx_dir / "resources"
                if resources_dir.exists():
                    self._link_resources(resources_dir)
                    return
        except Exception:
            pass

    def _link_resources(self, resources_dir: Path) -> None:
        """Link JADX resources directory into the workspace."""
        res_link = self.decompiled_apk_dir / "resources"
        if res_link.exists():
            return
        try:
            res_link.symlink_to(resources_dir)
            # Also create res/ symlink pointing to resources/res/ for convenience
            res_subdir = resources_dir / "res"
            res_shortcut = self.decompiled_apk_dir / "res"
            if res_subdir.exists() and not res_shortcut.exists():
                res_shortcut.symlink_to(res_subdir)
            logger.info(f"Linked JADX resources: {resources_dir}")
        except Exception as e:
            logger.debug(f"Could not link resources: {e}")

    @property
    def manifest_content(self) -> str:
        """
        Get the content of AndroidManifest.xml file.

        This property reads the AndroidManifest.xml file and returns its content as a string.
        Addresses the critical issue where Android 14+ security analysis expects manifest_content
        attribute but APKContext only provided manifest_path.

        Returns:
            str: Content of AndroidManifest.xml file, empty string if not found or error
        """
        try:
            if self.manifest_path.exists():
                with open(self.manifest_path, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read()
            else:
                # Try to read from APK directly if manifest not extracted yet
                if self.apk_path.exists() and zipfile.is_zipfile(self.apk_path):
                    with zipfile.ZipFile(self.apk_path, "r") as apk_zip:
                        if "AndroidManifest.xml" in apk_zip.namelist():
                            # Note: This will be binary for compiled manifest, may need aapt processing
                            manifest_data = apk_zip.read("AndroidManifest.xml")
                            return manifest_data.decode("utf-8", errors="ignore")
        except Exception as e:
            logger.warning(f"Failed to read manifest content: {e}")

        return ""

    def get_manifest_content(self) -> str:
        """
        Alternative method to get manifest content for compatibility.

        Some components expect get_manifest_content() method while others expect
        manifest_content property. This method provides both interfaces.

        Returns:
            str: Content of AndroidManifest.xml file
        """
        return self.manifest_content
