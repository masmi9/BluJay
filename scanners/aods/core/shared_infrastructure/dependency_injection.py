"""
AODS Dependency Injection Framework

Provides a reliable dependency injection pattern for clean component instantiation,
improved testability, and maintainable architecture across all AODS plugins.

Features:
- Constructor injection pattern for all dependencies
- Component factory with automatic dependency resolution
- Service locator for shared components
- Mock-friendly architecture for testing
- Lifecycle management for resource cleanup
"""

import logging as _stdlib_logging  # kept for per-instance loggers
from typing import Dict, Any, Optional, TypeVar, Callable, List
from dataclasses import dataclass, field
from pathlib import Path
import threading
from contextlib import contextmanager

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    logger = _stdlib_logging.getLogger(__name__)

from ..shared_analyzers.universal_confidence_calculator import UniversalConfidenceCalculator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..shared_analyzers.universal_pattern_analyzer import UniversalPatternAnalyzer
from ..config_management.pattern_loader import PatternLoader
from ..timeout import UnifiedTimeoutManager, TimeoutType

# Type variables for generic dependency injection
T = TypeVar("T")
ServiceFactory = Callable[["AnalysisContext"], Any]


@dataclass
class ComponentLifecycle:
    """Manages component lifecycle and cleanup."""

    instances: Dict[str, Any] = field(default_factory=dict)
    cleanup_handlers: Dict[str, List[Callable]] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def register_cleanup(self, component_name: str, cleanup_fn: Callable):
        """Register cleanup function for a component."""
        with self._lock:
            if component_name not in self.cleanup_handlers:
                self.cleanup_handlers[component_name] = []
            self.cleanup_handlers[component_name].append(cleanup_fn)

    def cleanup_component(self, component_name: str):
        """Clean up a specific component."""
        with self._lock:
            # Run cleanup handlers
            if component_name in self.cleanup_handlers:
                for cleanup_fn in self.cleanup_handlers[component_name]:
                    try:
                        cleanup_fn()
                    except Exception as e:
                        logger.error(f"Error in cleanup handler for {component_name}: {e}")
                del self.cleanup_handlers[component_name]

            # Remove instance
            if component_name in self.instances:
                del self.instances[component_name]

    def cleanup_all(self):
        """Clean up all registered components."""
        with self._lock:
            for component_name in list(self.cleanup_handlers.keys()):
                self.cleanup_component(component_name)


@dataclass
class AnalysisContext:
    """
    Centralized analysis context containing all dependencies for AODS analysis.

    Provides dependency injection for all analysis components including:
    - APK context and file paths
    - Shared analyzers and pattern engines
    - Configuration and pattern loaders
    - Logging and error handling
    - Performance monitoring and metrics
    """

    # Core analysis context
    apk_path: Path
    decompiled_path: Optional[Path] = None
    output_path: Optional[Path] = None

    # Shared analyzers (injected dependencies)
    confidence_calculator: Optional[UniversalConfidenceCalculator] = None
    pattern_analyzer: Optional["UniversalPatternAnalyzer"] = None
    pattern_loader: Optional[PatternLoader] = None

    # Configuration and settings
    config: Dict[str, Any] = field(default_factory=dict)
    debug_mode: bool = False
    max_analysis_time: int = 300  # seconds
    parallel_processing: bool = True

    # Logging and monitoring
    logger: Optional[_stdlib_logging.Logger] = None
    performance_metrics: Dict[str, Any] = field(default_factory=dict)

    # Component lifecycle management
    lifecycle: ComponentLifecycle = field(default_factory=ComponentLifecycle)

    # Thread safety
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def __post_init__(self):
        """Initialize context after creation."""
        if self.logger is None:
            self.logger = _stdlib_logging.getLogger(f"aods.context.{self.apk_path.stem}")

        # Initialize timeout manager for component operations
        self.timeout_manager = UnifiedTimeoutManager()

        # Validate required paths (relaxed for test environments)
        if not self.apk_path.exists():
            try:
                import os as _os

                if _os.getenv("AODS_STRICT_APK_VALIDATION", "") == "1":
                    raise ValueError(f"APK path does not exist: {self.apk_path}")
                # Relax validation under pytest or non-strict runs
                self.logger.warning(f"APK path does not exist: {self.apk_path} - continuing (non-strict mode)")
            except Exception:
                # Fallback to raising if anything unexpected occurs
                raise

    def get_component(self, component_name: str, factory: Optional[ServiceFactory] = None) -> Any:
        """
        Get or create a component with dependency injection.

        Args:
            component_name: Name of the component to retrieve
            factory: Optional factory function to create the component

        Returns:
            Component instance
        """
        with self._lock:
            # Check if component already exists
            if component_name in self.lifecycle.instances:
                return self.lifecycle.instances[component_name]

            # Determine which factory to use
            factory_to_use = factory

            # If no explicit factory provided, check global injector's factory registry
            if factory_to_use is None:
                global_injector = get_injector()
                if component_name in global_injector.factory.factories:
                    factory_to_use = global_injector.factory.factories[component_name]
                    self.logger.debug(f"Using registered factory for component: {component_name}")

            # Create component using factory with timeout protection
            if factory_to_use:
                with self.timeout_manager.timeout_context(
                    operation_name=f"create_component_{component_name}",
                    timeout_type=TimeoutType.PLUGIN,
                    timeout_seconds=60,
                ):
                    try:
                        instance = factory_to_use(self)
                        self.lifecycle.instances[component_name] = instance
                        self.logger.debug(f"Created component: {component_name}")
                        return instance
                    except Exception as e:
                        self.logger.error(f"Error creating component {component_name}: {e}")
                        raise

            raise ValueError(f"No factory provided for component: {component_name}")

    def register_cleanup(self, component_name: str, cleanup_fn: Callable):
        """Register cleanup function for a component."""
        self.lifecycle.register_cleanup(component_name, cleanup_fn)

    def create_child_context(self, **overrides) -> "AnalysisContext":
        """Create a child context with specific overrides."""
        child_data = {
            "apk_path": self.apk_path,
            "decompiled_path": self.decompiled_path,
            "output_path": self.output_path,
            "confidence_calculator": self.confidence_calculator,
            "pattern_analyzer": self.pattern_analyzer,
            "pattern_loader": self.pattern_loader,
            "config": self.config.copy(),
            "debug_mode": self.debug_mode,
            "max_analysis_time": self.max_analysis_time,
            "parallel_processing": self.parallel_processing,
            "logger": self.logger,
            "performance_metrics": self.performance_metrics.copy(),
        }

        # Apply overrides
        child_data.update(overrides)

        return AnalysisContext(**child_data)

    def cleanup(self):
        """Clean up all resources."""
        self.lifecycle.cleanup_all()
        self.logger.debug("Analysis context cleaned up")


class ComponentFactory:
    """
    Component factory for creating and managing AODS analysis components.

    Provides automatic dependency resolution and manages component lifecycle
    with proper cleanup and resource management.
    """

    def __init__(self):
        self.factories: Dict[str, ServiceFactory] = {}
        self.singletons: Dict[str, Any] = {}
        self._lock = threading.RLock()
        self.logger = _stdlib_logging.getLogger(__name__)

        # Register default factories
        self._register_default_factories()

    def _register_default_factories(self):
        """Register default component factories."""
        self.register_factory("confidence_calculator", self._create_confidence_calculator)
        self.register_factory("pattern_analyzer", self._create_pattern_analyzer)
        self.register_factory("pattern_loader", self._create_pattern_loader)

    def register_factory(self, component_name: str, factory: ServiceFactory):
        """Register a factory function for a component."""
        with self._lock:
            self.factories[component_name] = factory
            self.logger.debug(f"Registered factory for: {component_name}")

    def create_component(self, component_name: str, context: AnalysisContext) -> Any:
        """Create a component using registered factory."""
        with self._lock:
            if component_name not in self.factories:
                raise ValueError(f"No factory registered for: {component_name}")

            factory = self.factories[component_name]
            try:
                instance = factory(context)
                self.logger.debug(f"Created component: {component_name}")
                return instance
            except Exception as e:
                self.logger.error(f"Error creating component {component_name}: {e}")
                raise

    def get_singleton(self, component_name: str, context: AnalysisContext) -> Any:
        """Get or create a singleton component."""
        with self._lock:
            if component_name not in self.singletons:
                self.singletons[component_name] = self.create_component(component_name, context)
            return self.singletons[component_name]

    def _create_confidence_calculator(self, context: AnalysisContext) -> UniversalConfidenceCalculator:
        """Factory for confidence calculator."""
        from ..shared_analyzers.universal_confidence_calculator import ConfidenceConfiguration

        # Create proper configuration object
        config = ConfidenceConfiguration(
            plugin_type="general", evidence_weights={}, context_factors={}, reliability_database={}
        )

        calculator = UniversalConfidenceCalculator(config)

        # Register cleanup if needed
        context.register_cleanup("confidence_calculator", lambda: None)

        return calculator

    def _create_pattern_analyzer(self, context: AnalysisContext) -> "UniversalPatternAnalyzer":
        """Factory for pattern analyzer."""
        # Get configuration values with defaults
        pattern_config = context.config.get("patterns", {})
        # Local import to avoid circular import during module initialization
        from ..shared_analyzers.universal_pattern_analyzer import UniversalPatternAnalyzer

        analyzer = UniversalPatternAnalyzer(
            max_workers=pattern_config.get("max_workers", 4),
            enable_caching=pattern_config.get("enable_caching", True),
            cache_ttl=pattern_config.get("cache_ttl", 3600),
        )

        # Register cleanup if needed
        context.register_cleanup("pattern_analyzer", lambda: None)

        return analyzer

    def _create_pattern_loader(self, context: AnalysisContext) -> PatternLoader:
        """Factory for pattern loader."""
        # Get configuration values with defaults
        loader_config = context.config.get("pattern_loader", {})

        loader = PatternLoader(
            cache_enabled=loader_config.get("cache_enabled", True),
            validate_patterns=loader_config.get("validate_patterns", True),
            strict_mode=loader_config.get("strict_mode", False),
        )

        # Register cleanup
        context.register_cleanup("pattern_loader", loader.cleanup if hasattr(loader, "cleanup") else lambda: None)

        return loader


class DependencyInjector:
    """
    Main dependency injector for AODS framework.

    Provides service locator pattern and manages component lifecycle
    across the entire analysis session.
    """

    def __init__(self):
        self.factory = ComponentFactory()
        self.contexts: Dict[str, AnalysisContext] = {}
        self._lock = threading.RLock()
        self.logger = _stdlib_logging.getLogger(__name__)

        # Initialize unified timeout manager for DI operations
        self.timeout_manager = UnifiedTimeoutManager()
        self.logger.info("DependencyInjector initialized with timeout protection")
        try:
            import os as _os

            self._di_debug = _os.getenv("AODS_DI_DEBUG", "0") == "1"
        except Exception:
            self._di_debug = False

    def create_context(self, apk_path: Path, context_id: Optional[str] = None, **kwargs) -> AnalysisContext:
        """
        Create a new analysis context with dependency injection.

        Args:
            apk_path: Path to the APK file
            context_id: Optional unique identifier for the context
            **kwargs: Additional context parameters

        Returns:
            Configured AnalysisContext with all dependencies injected
        """
        if context_id is None:
            context_id = f"context_{apk_path.stem}_{id(apk_path)}"

        # Wrap entire context creation with timeout protection
        with self.timeout_manager.timeout_context(
            operation_name="create_analysis_context", timeout_type=TimeoutType.CRITICAL, timeout_seconds=30
        ):
            with self._lock:
                if self._di_debug:
                    self.logger.debug(f"[DI] Creating context {context_id} for {apk_path}")
                # Create base context
                context = AnalysisContext(apk_path=apk_path, **kwargs)

                # Inject dependencies with individual timeouts
                context.confidence_calculator = self._inject_with_timeout(
                    "confidence_calculator", context, timeout_seconds=10
                )
                context.pattern_analyzer = self._inject_with_timeout("pattern_analyzer", context, timeout_seconds=10)
                context.pattern_loader = self._inject_with_timeout("pattern_loader", context, timeout_seconds=10)

                # Store context
                self.contexts[context_id] = context

                if self._di_debug:
                    self.logger.debug(
                        f"[DI] Context {context_id} created; components: confidence_calculator, pattern_analyzer, pattern_loader"  # noqa: E501
                    )
                self.logger.info(f"Created analysis context: {context_id}")
                return context

    def _inject_with_timeout(self, component_name: str, context: "AnalysisContext", timeout_seconds: int = 10) -> Any:
        """Inject a component with timeout protection."""
        with self.timeout_manager.timeout_context(
            operation_name=f"inject_{component_name}", timeout_type=TimeoutType.PLUGIN, timeout_seconds=timeout_seconds
        ):
            if getattr(self, "_di_debug", False):
                self.logger.debug(f"[DI] Injecting component {component_name}")
            return self.factory.get_singleton(component_name, context)

    def get_context(self, context_id: str) -> Optional[AnalysisContext]:
        """Get an existing analysis context."""
        with self._lock:
            return self.contexts.get(context_id)

    def cleanup_context(self, context_id: str):
        """Clean up a specific analysis context."""
        with self._lock:
            if context_id in self.contexts:
                context = self.contexts[context_id]
                context.cleanup()
                del self.contexts[context_id]
                self.logger.info(f"Cleaned up analysis context: {context_id}")

    def cleanup_all(self):
        """Clean up all analysis contexts."""
        with self._lock:
            for context_id in list(self.contexts.keys()):
                self.cleanup_context(context_id)

    @contextmanager
    def analysis_session(self, apk_path: Path, **kwargs):
        """
        Context manager for analysis session with automatic cleanup.

        Args:
            apk_path: Path to the APK file
            **kwargs: Additional context parameters

        Yields:
            AnalysisContext: Configured analysis context
        """
        context_id = f"session_{apk_path.stem}_{id(apk_path)}"
        context = None

        try:
            context = self.create_context(apk_path, context_id, **kwargs)
            yield context
        except Exception as e:
            self.logger.error(f"Error in analysis session: {e}")
            raise
        finally:
            if context:
                self.cleanup_context(context_id)


# Global dependency injector instance
_injector = DependencyInjector()


def get_injector() -> DependencyInjector:
    """Get the global dependency injector instance."""
    return _injector


def create_analysis_context(apk_path: Path, **kwargs) -> AnalysisContext:
    """
    Convenience function to create an analysis context with dependency injection.

    Args:
        apk_path: Path to the APK file
        **kwargs: Additional context parameters

    Returns:
        Configured AnalysisContext with all dependencies injected
    """
    return _injector.create_context(apk_path, **kwargs)


@contextmanager
def analysis_session(apk_path: Path, **kwargs):
    """
    Context manager for analysis session with automatic cleanup.

    Args:
        apk_path: Path to the APK file
        **kwargs: Additional context parameters

    Yields:
        AnalysisContext: Configured analysis context
    """
    with _injector.analysis_session(apk_path, **kwargs) as context:
        yield context
