#!/usr/bin/env python3
"""
Optional Dependencies Management for AODS
=========================================

Provides standardized handling of optional dependencies with lazy loading,
graceful fallbacks, and consistent error handling across the entire AODS system.

Features:
- Lazy import pattern for optional dependencies
- Graceful degradation when dependencies are missing
- Consistent error handling and logging
- Performance optimization through import caching
- Feature availability detection
- Standardized fallback mechanisms

Usage:
    from core.optional_dependencies import OptionalDependencyManager

    # Register optional dependency
    odm = OptionalDependencyManager()
    frida_available = odm.is_available('frida')

    # Get module with fallback
    frida = odm.get_module('frida', fallback=None)

    # Lazy import with context
    with odm.lazy_import_context('frida') as frida:
        if frida:
            # Use frida functionality
            pass
"""

import importlib
import importlib.util
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from packaging.version import parse as parse_version, InvalidVersion
import importlib.metadata as importlib_metadata

# MIGRATED: Import unified caching infrastructure
from core.shared_infrastructure.performance.caching_consolidation import CacheType

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


@dataclass
class OptionalDependency:
    """Configuration for an optional dependency."""

    name: str
    import_path: str
    fallback_available: bool = False
    fallback_module: Optional[Any] = None
    feature_description: str = ""
    performance_impact: str = "low"  # low, medium, high
    lazy_load: bool = True
    min_version: Optional[str] = None
    install_command: Optional[str] = None

    # Runtime state
    is_available: Optional[bool] = field(default=None, init=False)
    module: Optional[Any] = field(default=None, init=False)
    load_time: Optional[float] = field(default=None, init=False)
    error_message: Optional[str] = field(default=None, init=False)
    version: Optional[str] = field(default=None, init=False)


class OptionalDependencyManager:
    """
    Centralized manager for optional dependencies in AODS.

    Provides lazy loading, caching, and graceful fallback handling
    for all optional dependencies across the system.

    Version policy and negative caching
    ----------------------------------
    - When `min_version` is defined for a dependency, `is_supported(name)` verifies that
      the detected version satisfies the minimum using `packaging.version.parse`.
    - Version detection uses `importlib.metadata.version(<top-level-package>)` when available,
      falling back to `module.__version__` or `module.VERSION`.
    - Results of availability and version support checks are cached via the unified cache
      (CONFIGURATION tier) to prevent repeated import/version lookups (negative caching included).
    - On indeterminate version (cannot detect), support is treated as False to avoid false positives.
    """

    def __init__(self):
        self._dependencies: Dict[str, OptionalDependency] = {}
        # MIGRATED: Use unified caching infrastructure
        from core.shared_infrastructure.performance.caching_consolidation import get_unified_cache_manager

        self.cache_manager = get_unified_cache_manager()
        # Optional: performance tracker for telemetry (lazy to avoid heavy imports)
        try:
            from core.shared_infrastructure.monitoring.performance_tracker import get_unified_performance_tracker  # type: ignore  # noqa: E501

            self._perf = get_unified_performance_tracker()
        except Exception:
            self._perf = None
        # Hour-based TTL for availability results (env override)
        try:
            self._avail_ttl_hours = int(os.getenv("AODS_OPTIONAL_DEPS_AVAIL_TTL_HOURS", "6"))
        except Exception:
            self._avail_ttl_hours = 6
        self._lock = threading.RLock()

        # Register standard AODS optional dependencies
        self._register_standard_dependencies()

    def _register_standard_dependencies(self):
        """Register standard AODS optional dependencies."""

        # Frida for dynamic analysis
        self.register_dependency(
            OptionalDependency(
                name="frida",
                import_path="frida",
                feature_description="Dynamic analysis and runtime instrumentation",
                performance_impact="high",
                install_command="pip install frida-tools frida",
            )
        )

        # Frida detailed vulnerability structures
        self.register_dependency(
            OptionalDependency(
                name="frida_detailed_vulnerability",
                import_path="plugins.frida_dynamic_analysis.data_structures.DetailedVulnerability",
                feature_description="Frida vulnerability data structures",
                performance_impact="medium",
            )
        )

        # Advanced ML components
        self.register_dependency(
            OptionalDependency(
                name="sklearn",
                import_path="sklearn",
                feature_description="Machine learning enhanced analysis",
                performance_impact="medium",
                install_command="pip install scikit-learn",
            )
        )

        # Enterprise performance optimization
        self.register_dependency(
            OptionalDependency(
                name="enterprise_performance",
                import_path="utilities.enterprise_performance_optimization",
                feature_description="Enterprise performance optimization suite",
                performance_impact="low",
            )
        )

        # Enterprise integration
        self.register_dependency(
            OptionalDependency(
                name="enterprise_integration",
                import_path="utilities.ENTERPRISE_PERFORMANCE_INTEGRATION",
                feature_description="Enterprise integration management",
                performance_impact="low",
            )
        )

        # Advanced threat intelligence
        self.register_dependency(
            OptionalDependency(
                name="threat_intelligence",
                import_path="core.threat_intelligence_engine",
                feature_description="Advanced threat intelligence analysis",
                performance_impact="medium",
            )
        )

        # WebView security analysis
        self.register_dependency(
            OptionalDependency(
                name="webview_security",
                import_path="plugins.webview_security_analysis",
                feature_description="WebView security vulnerability analysis",
                performance_impact="low",
            )
        )

        # Advanced static analysis
        self.register_dependency(
            OptionalDependency(
                name="jadx",
                import_path="jadx",
                feature_description="JADX decompiler integration",
                performance_impact="high",
                install_command="Download JADX from GitHub releases",
            )
        )

    def register_dependency(self, dependency: OptionalDependency):
        """Register an optional dependency."""
        with self._lock:
            self._dependencies[dependency.name] = dependency
            logger.debug(f"Registered optional dependency: {dependency.name}")

    def is_available(self, name: str) -> bool:
        """Check if an optional dependency is available."""
        with self._lock:
            # MIGRATED: Check unified cache first (store only booleans, never modules)
            avail_key = f"optional_deps:avail:{name}"
            cached = self.cache_manager.retrieve(avail_key, CacheType.CONFIGURATION)
            if isinstance(cached, bool):
                # Telemetry: cache hit for availability
                try:
                    if self._perf:
                        self._perf.record_metric(
                            name="optional_deps.availability.cache_hit", value=1, tags={"dep": name}
                        )
                except Exception:
                    pass
                return cached

            if name not in self._dependencies:
                logger.warning(f"Unknown optional dependency: {name}")
                return False

            dependency = self._dependencies[name]

            # Try to import the dependency
            try:
                start_time = time.time()

                if "." in dependency.import_path:
                    # Handle module.submodule imports
                    module = importlib.import_module(dependency.import_path)
                else:
                    # Handle simple imports
                    module = importlib.import_module(dependency.import_path)

                load_time = time.time() - start_time
                # Detect version (best-effort)
                try:
                    detected_version = self._detect_version(name, dependency, module)
                except Exception:
                    detected_version = None

                # MIGRATED: Cache the availability using unified cache (do not persist module objects)
                dependency.is_available = True
                dependency.module = module  # process-local via sys.modules; not persisted in unified cache
                dependency.load_time = load_time
                dependency.version = detected_version
                self.cache_manager.store(
                    key=avail_key,
                    value=True,
                    cache_type=CacheType.CONFIGURATION,
                    ttl_hours=self._avail_ttl_hours,
                    tags=["optional_deps", "imports", f"optdep:{name}"],
                )
                if detected_version:
                    try:
                        self.cache_manager.store(
                            key=f"optional_deps:version:{name}",
                            value=detected_version,
                            cache_type=CacheType.CONFIGURATION,
                            ttl_hours=self._avail_ttl_hours,
                            tags=["optional_deps", "versions", f"optdep:{name}"],
                        )
                    except Exception:
                        pass
                # Telemetry: availability success + cache store
                try:
                    if self._perf:
                        self._perf.record_metric(
                            name="optional_deps.availability.check", value=1, tags={"dep": name, "status": "available"}
                        )
                        self._perf.record_metric(
                            name="optional_deps.availability.cache_store", value=1, tags={"dep": name, "result": "true"}
                        )
                except Exception:
                    pass

                logger.debug(f"Optional dependency '{name}' available (loaded in {load_time:.3f}s)")
                return True

            except ImportError as e:
                dependency.is_available = False
                dependency.error_message = str(e)
                # Negative cache to avoid repeated import attempts within TTL
                self.cache_manager.store(
                    key=avail_key,
                    value=False,
                    cache_type=CacheType.CONFIGURATION,
                    ttl_hours=self._avail_ttl_hours,
                    tags=["optional_deps", "imports", f"optdep:{name}"],
                )
                try:
                    if self._perf:
                        self._perf.record_metric(
                            name="optional_deps.availability.check", value=1, tags={"dep": name, "status": "missing"}
                        )
                        self._perf.record_metric(
                            name="optional_deps.availability.cache_store",
                            value=1,
                            tags={"dep": name, "result": "false"},
                        )
                except Exception:
                    pass

                logger.debug(f"Optional dependency '{name}' not available: {e}")
                return False
            except Exception as e:
                dependency.is_available = False
                dependency.error_message = f"Unexpected error: {e}"
                self.cache_manager.store(
                    key=avail_key,
                    value=False,
                    cache_type=CacheType.CONFIGURATION,
                    ttl_hours=self._avail_ttl_hours,
                    tags=["optional_deps", "imports", f"optdep:{name}"],
                )
                try:
                    if self._perf:
                        self._perf.record_metric(
                            name="optional_deps.availability.check", value=1, tags={"dep": name, "status": "error"}
                        )
                        self._perf.record_metric(
                            name="optional_deps.availability.cache_store",
                            value=1,
                            tags={"dep": name, "result": "false"},
                        )
                except Exception:
                    pass

                logger.warning(f"Error checking optional dependency '{name}': {e}")
                return False

    def _detect_version(self, name: str, dependency: OptionalDependency, module: Any) -> Optional[str]:
        """Best-effort detection of a dependency's version string.
        Prefers importlib.metadata and falls back to module attributes.
        """
        # Try importlib.metadata with the top-level package name
        top_level_pkg = dependency.import_path.split(".")[0] if dependency.import_path else name
        try:
            v = importlib_metadata.version(top_level_pkg)
            return str(v)
        except importlib_metadata.PackageNotFoundError:
            pass
        except Exception:
            pass
        # Try common module attributes
        try:
            v = getattr(module, "__version__", None) or getattr(module, "VERSION", None)
            return str(v) if v is not None else None
        except Exception:
            return None

    def is_supported(self, name: str) -> bool:
        """Check whether the dependency is installed and satisfies min_version if specified."""
        with self._lock:
            if name not in self._dependencies:
                logger.warning(f"Unknown optional dependency: {name}")
                return False
            dependency = self._dependencies[name]
            if not self.is_available(name):
                return False
            if not dependency.min_version:
                return True
            # Compare versions safely
            try:
                current_version = dependency.version
                if not current_version:
                    # Attempt to detect again lazily
                    try:
                        module = dependency.module or importlib.import_module(dependency.import_path or name)
                    except Exception:
                        module = None
                    if module is not None:
                        current_version = self._detect_version(name, dependency, module)
                        dependency.version = current_version
                if not current_version:
                    # If we cannot determine version, treat as unsupported; negative cache
                    self.cache_manager.store(
                        key=f"optional_deps:supported:{name}",
                        value=False,
                        cache_type=CacheType.CONFIGURATION,
                        ttl_hours=self._avail_ttl_hours,
                        tags=["optional_deps", "versions", f"optdep:{name}"],
                    )
                    return False
                supported = parse_version(current_version) >= parse_version(dependency.min_version)
                try:
                    self.cache_manager.store(
                        key=f"optional_deps:supported:{name}",
                        value=bool(supported),
                        cache_type=CacheType.CONFIGURATION,
                        ttl_hours=self._avail_ttl_hours,
                        tags=["optional_deps", "versions", f"optdep:{name}"],
                    )
                except Exception:
                    pass
                return bool(supported)
            except InvalidVersion:
                logger.warning(
                    f"Invalid version string for '{name}': current='{dependency.version}', min='{dependency.min_version}'"  # noqa: E501
                )
                try:
                    self.cache_manager.store(
                        key=f"optional_deps:supported:{name}",
                        value=False,
                        cache_type=CacheType.CONFIGURATION,
                        ttl_hours=self._avail_ttl_hours,
                        tags=["optional_deps", "versions", f"optdep:{name}"],
                    )
                except Exception:
                    pass
                return False

    def get_module(self, name: str, fallback: Any = None) -> Any:
        """Get an optional dependency module with fallback."""
        with self._lock:
            # Check availability first (uses unified cache under the hood)
            if not self.is_available(name):
                dependency = self._dependencies.get(name)
                if dependency and dependency.fallback_available:
                    return dependency.fallback_module
                return fallback
            # Import on demand; relies on Python's sys.modules cache; we do not persist module objects in unified cache
            try:
                dep = self._dependencies.get(name)
                import_path = dep.import_path if dep else name
                return importlib.import_module(import_path)
            except Exception:
                dependency = self._dependencies.get(name)
                if dependency and dependency.fallback_available:
                    return dependency.fallback_module
                return fallback

    @contextmanager
    def lazy_import_context(self, name: str):
        """Context manager for lazy importing optional dependencies."""
        module = None
        try:
            if self.is_available(name):
                module = self.get_module(name)
            yield module
        except Exception as e:
            logger.error(f"Error in lazy import context for '{name}': {e}")
            yield None

    def get_feature_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all optional dependencies."""
        status: Dict[str, Dict[str, Any]] = {}
        now_iso: Optional[str] = None
        try:
            # Avoid import cycle by lazy import of API util; fallback to time-based
            from datetime import datetime, timezone

            now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            now_iso = None

        for name, dependency in self._dependencies.items():
            available = self.is_available(name)
            # Compute support status only when min_version is specified; else mirror availability
            supported = self.is_supported(name) if dependency.min_version else available
            status[name] = {
                "available": available,
                "feature_description": dependency.feature_description,
                "performance_impact": dependency.performance_impact,
                "load_time": dependency.load_time,
                "error_message": dependency.error_message if not available else None,
                "install_command": dependency.install_command if not available else None,
                "version": dependency.version,
                "min_version": dependency.min_version,
                "supported": supported,
                "last_checked": now_iso,
            }

        return status

    def get_missing_dependencies(self) -> List[Dict[str, Any]]:
        """Get list of missing optional dependencies with installation info."""
        missing = []

        for name, dependency in self._dependencies.items():
            if not self.is_available(name):
                missing.append(
                    {
                        "name": name,
                        "feature_description": dependency.feature_description,
                        "install_command": dependency.install_command,
                        "performance_impact": dependency.performance_impact,
                        "error_message": dependency.error_message,
                    }
                )

        return missing

    def invalidate_cache(self, name: Optional[str] = None):
        """MIGRATED: Invalidate import cache for a specific dependency or all using unified cache."""
        with self._lock:

            def _reset_dep(dep_name: str) -> None:
                dep = self._dependencies.get(dep_name)
                if dep:
                    dep.is_available = None
                    dep.module = None
                    dep.load_time = None
                    dep.error_message = None
                    dep.version = None
                avail_key = f"optional_deps:avail:{dep_name}"
                try:
                    self.cache_manager.invalidate(avail_key, CacheType.CONFIGURATION, all_tiers=True)
                except Exception:
                    pass
                try:
                    self.cache_manager.invalidate(
                        f"optional_deps:version:{dep_name}", CacheType.CONFIGURATION, all_tiers=True
                    )
                except Exception:
                    pass
                try:
                    self.cache_manager.invalidate(
                        f"optional_deps:supported:{dep_name}", CacheType.CONFIGURATION, all_tiers=True
                    )
                except Exception:
                    pass

            if name:
                _reset_dep(name)
            else:
                for dep_name in list(self._dependencies.keys()):
                    _reset_dep(dep_name)

    def print_status_report(self):
        """Log a full status report of optional dependencies."""
        available_deps = []
        missing_deps = []

        for name, status in self.get_feature_status().items():
            if status["available"]:
                available_deps.append((name, status))
            else:
                missing_deps.append((name, status))

        logger.info("AODS Optional Dependencies Status Report")

        for name, status in available_deps:
            logger.info(
                "Available dependency", name=name, feature=status["feature_description"], load_time=status["load_time"]
            )

        for name, status in missing_deps:
            logger.warning(
                "Missing dependency",
                name=name,
                feature=status["feature_description"],
                install_command=status["install_command"],
                error_message=status["error_message"],
            )

        if missing_deps:
            high_impact = [dep for dep, status in missing_deps if status["performance_impact"] == "high"]
            medium_impact = [dep for dep, status in missing_deps if status["performance_impact"] == "medium"]

            if high_impact:
                logger.warning("High impact missing dependencies", dependencies=", ".join(high_impact))
            if medium_impact:
                logger.warning("Medium impact missing dependencies", dependencies=", ".join(medium_impact))

        logger.info("Dependency status report complete", available=len(available_deps), missing=len(missing_deps))


# Global instance for easy access
optional_deps = OptionalDependencyManager()

# Convenience functions for common usage patterns


def is_frida_available() -> bool:
    """Check if Frida is available for dynamic analysis."""
    return optional_deps.is_available("frida")


def get_frida_module():
    """Get Frida module if available."""
    return optional_deps.get_module("frida")


def is_sklearn_available() -> bool:
    """Check if scikit-learn is available for ML features."""
    return optional_deps.is_available("sklearn")


def get_sklearn_module():
    """Get scikit-learn module if available."""
    return optional_deps.get_module("sklearn")


@contextmanager
def frida_context():
    """Context manager for Frida operations."""
    with optional_deps.lazy_import_context("frida") as frida:
        yield frida


@contextmanager
def sklearn_context():
    """Context manager for scikit-learn operations."""
    with optional_deps.lazy_import_context("sklearn") as sklearn:
        yield sklearn


def print_dependency_status():
    """Print status of all optional dependencies."""
    optional_deps.print_status_report()
