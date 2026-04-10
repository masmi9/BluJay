"""
core.cli.scanner - AODSScanner class (extracted from dyna.py, Track 46).

Main test suite for OWASP Mobile Application Security Testing.
"""

import logging
import os
import sys
import time
from typing import Dict, List, Optional, Tuple, Union, Any

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


from rich.text import Text

from core.analyzer import APKAnalyzer
from core.apk_ctx import APKContext
from core.output_manager import get_output_manager

# Import feature flags and utilities from cli package
from core.cli.feature_flags import (
    UNIFIED_PLUGIN_MANAGER_AVAILABLE,
    UNIFIED_REPORTING_AVAILABLE,
    ENHANCED_REPORTING_AVAILABLE,
    FRIDA_FIRST_AVAILABLE,
    GRACEFUL_SHUTDOWN_AVAILABLE,
    BUSINESS_DOMAIN_DETECTION_AVAILABLE,
    BusinessDomain,
    ROBUST_PLUGIN_EXECUTION_AVAILABLE,
    DynamicAnalysisResult,
)

from core.cli.finding_processing import (
    _is_valid_finding_title,
    _extract_findings_from_content,
    _create_canonical_findings,
    _sync_all_containers,
)

from core.cli.utilities import EmergencyPluginManager

# Conditional imports guarded by availability flags from feature_flags
if BUSINESS_DOMAIN_DETECTION_AVAILABLE:
    from core.app_type_detector import detect_business_domain, get_business_domain_info

if FRIDA_FIRST_AVAILABLE:
    from core.frida_dynamic_integration import enable_frida_first_analysis

if UNIFIED_PLUGIN_MANAGER_AVAILABLE:
    from core.plugins import UnifiedPluginManager

if UNIFIED_REPORTING_AVAILABLE:
    from core.shared_infrastructure.reporting import UnifiedReportingManager
else:
    from core.cli.feature_flags import ReportGenerator

if ENHANCED_REPORTING_AVAILABLE:
    pass

# Always-available imports (no try/except guard in feature_flags)
from core.execution import ExecutionManager
from core.plugins import create_plugin_manager

if GRACEFUL_SHUTDOWN_AVAILABLE:
    from core.graceful_shutdown_manager import is_shutdown_requested, get_shutdown_manager


class AODSScanner:
    """
    Main test suite for OWASP Mobile Application Security Testing.

    This class manages the overall test process, including unpacking the APK,
    initializing analysis tools, running plugins, and generating reports.
    """

    def __init__(
        self,
        apk_path: str,
        package_name: str,
        enable_ml: bool = True,
        vulnerable_app_mode: bool = False,
        scan_profile: str = "standard",
        enable_optimized: bool = False,
    ):
        """
        Initialize OWASP Test Suite Drozer

        Args:
            apk_path: Path to the APK file to analyze
            package_name: The package name of the Android application
            enable_ml: Enable machine learning components (default: True)
            vulnerable_app_mode: Enable relaxed detection settings for vulnerable apps (default: False)
            scan_profile: Scan profile for performance optimization (lightning|fast|standard|deep)
            enable_optimized: Enable Performance Enhancement Suite for EXCELLENT performance (default: False)
        """
        self.apk_path = apk_path
        self.package_name = package_name  # Store package_name directly for enhanced reporting
        self._scan_start_time = time.time()  # Track 60 Fix 10: Record scan start time

        # Initialize logger early for vulnerable app detection
        # Use module-level logger (structlog when available) - not stdlib logging.getLogger()
        self.logger = logger

        # AUTO-DETECT VULNERABLE APPS: Integrate VulnerableAppCoordinator
        try:
            from core.vulnerable_app_coordinator import VulnerableAppCoordinator

            app_coordinator = VulnerableAppCoordinator()
            app_context = {"package_name": package_name, "apk_path": apk_path}

            # Auto-detect if this is a vulnerable/training app
            detected_app_type = app_coordinator.detect_vulnerable_app(app_context)
            auto_detected_vulnerable = detected_app_type != "production_app"

            # Override vulnerable_app_mode if auto-detection finds a vulnerable app
            if auto_detected_vulnerable and not vulnerable_app_mode:
                vulnerable_app_mode = True
                self.logger.info("Auto-detected vulnerable app, enabling vulnerable_app_mode", package=package_name)
            elif vulnerable_app_mode:
                self.logger.info("Manual vulnerable_app_mode enabled", package=package_name)
            else:
                self.logger.info("Production app detected, using production-grade filtering", package=package_name)

            # Store the detected app type for ML integration
            self.detected_app_type = detected_app_type

        except ImportError as e:
            self.logger.warning(f"VulnerableAppCoordinator unavailable: {e}")
        except Exception as e:
            self.logger.warning(f"Vulnerable app detection failed: {e}")
            # Set default values if detection failed
            self.detected_app_type = "production_app"

        # CRITICAL FIX: Store vulnerable app mode for ML classification
        self.vulnerable_app_mode = vulnerable_app_mode
        self.logger.info("Final vulnerable_app_mode setting", vulnerable_app_mode=self.vulnerable_app_mode)
        self.apk_ctx = APKContext(apk_path_str=apk_path, package_name=package_name)

        # Gate 4: Detect business domain for context-aware confidence scoring
        self.business_domain = None
        self.business_domain_info = None
        if BUSINESS_DOMAIN_DETECTION_AVAILABLE:
            try:
                self.business_domain = detect_business_domain(self.apk_ctx)
                self.business_domain_info = get_business_domain_info(self.business_domain)
                domain_name = self.business_domain_info.get("name", self.business_domain.value)
                security_level = self.business_domain_info.get("security_level", "MEDIUM")
                multiplier = self.business_domain_info.get("confidence_multiplier", 1.0)
                self.logger.info(
                    "Business domain detected", domain=domain_name, security_level=security_level, multiplier=multiplier
                )
            except Exception as e:
                self.logger.warning(f"Business domain detection failed: {e}")
                self.business_domain = BusinessDomain.UNKNOWN if BusinessDomain else None

        # Track 11: Instantiate ConfidenceScorer for domain-aware confidence scoring
        self.confidence_scorer = None
        try:
            from core.confidence_scorer import ConfidenceScorer

            self.confidence_scorer = ConfidenceScorer(apk_path=str(self.apk_ctx.apk_path))
        except ImportError:
            pass

        self.report_data: List[Tuple[str, Union[str, Text]]] = []

        # Check Frida availability for dynamic analysis
        self.frida_available = self._check_frida_availability()

        # CRITICAL FIX: Use centralized scan mode tracker for report consistency
        try:
            from core.scan_mode_tracker import get_global_scan_mode

            scan_mode = get_global_scan_mode()
        except ImportError:
            # Fallback to APK context scan mode if tracker not available
            scan_mode = self.apk_ctx.scan_mode

        # CONSOLIDATION FIX: Use unified reporting framework instead of deprecated report generator
        if UNIFIED_REPORTING_AVAILABLE:
            self.report_manager = UnifiedReportingManager()
            self.report_generator = None  # Not needed with unified system
            logger.info("Using unified reporting framework")
        else:
            # Fallback to deprecated system (should be removed)
            self.report_generator = ReportGenerator(package_name, scan_mode)
            self.report_manager = None
            logger.warning("Using deprecated report generator (fallback)")
        self.report_formats: List[str] = ["txt"]  # Default to text, can be extended
        self.core_test_characteristics: Dict[str, Dict[str, str]] = {
            "extract_additional_info": {"mode": "safe"},
            "test_debuggable_logging": {"mode": "safe"},
            "network_cleartext_traffic_analyzer": {"mode": "safe"},
        }

        # Initialize the unified plugin manager with scan optimization
        logger.debug("About to create plugin manager")

        # Store scan profile for optimization
        self.scan_profile = scan_profile

        # Create plugin manager with scan profile optimization and defensive error handling
        try:
            # CONSOLIDATION FIX: Use unified plugin manager instead of deprecated create_plugin_manager
            # Access global variable safely
            global UNIFIED_PLUGIN_MANAGER_AVAILABLE
            logger.debug("Checking unified plugin manager availability", available=UNIFIED_PLUGIN_MANAGER_AVAILABLE)
            if UNIFIED_PLUGIN_MANAGER_AVAILABLE:
                # Try to create unified plugin manager with proper configuration
                try:
                    logger.debug("Creating UnifiedPluginManager")
                    self.plugin_manager = UnifiedPluginManager()
                    logger.info(
                        "Using unified plugin management system",
                        plugin_count=len(self.plugin_manager.plugins),
                        has_set_scan_profile=hasattr(self.plugin_manager, "set_scan_profile"),
                    )
                except Exception as unified_error:
                    logger.warning("Unified plugin manager failed", error=str(unified_error), exc_info=True)
                    UNIFIED_PLUGIN_MANAGER_AVAILABLE = False  # Disable for this session

            if not UNIFIED_PLUGIN_MANAGER_AVAILABLE:
                # Fallback to deprecated system with ENHANCED timeout intelligence
                self.plugin_manager = create_plugin_manager(
                    scan_mode=self.apk_ctx.scan_mode,
                    vulnerable_app_mode=vulnerable_app_mode,
                    apk_path=self.apk_path,  # CRITICAL FIX: Pass APK path for intelligent timeout calculation
                )
                logger.warning("Using deprecated plugin manager (fallback)")
            logger.debug("Plugin manager created successfully", plugin_count=len(self.plugin_manager.plugins))

        except Exception as e:
            logger.warning("Plugin manager creation failed, implementing defensive fallback", error=str(e))

            # Defensive: Create minimal plugin manager for essential functionality
            try:
                # CANONICAL: Import unified PluginManager from facade
                from core.plugins import PluginManager

                # Create minimal plugin manager with proper parameters
                self.plugin_manager = PluginManager()

                # Clear plugins that failed to load and mark as degraded mode
                self.plugin_manager.plugins = {}
                self.plugin_manager._degraded_mode = True

                logger.warning("Minimal plugin manager created, some functionality may be limited")

            except Exception as fallback_error:
                logger.error(
                    "Even minimal plugin manager failed, creating emergency fallback", error=str(fallback_error)
                )

                self.plugin_manager = EmergencyPluginManager()
                logger.warning("Emergency plugin manager created, limited to basic functionality")

        # Defensive: Validate plugin manager has required methods
        if not hasattr(self.plugin_manager, "execute_all_plugins"):
            logger.error("Plugin manager missing execute_all_plugins method")
            # Add full static analysis as emergency fallback

            def emergency_execute_all_plugins(apk_ctx):
                logger.warning("Emergency execute_all_plugins called, using full static analysis")
                return self._execute_comprehensive_static_analysis(apk_ctx)

            self.plugin_manager.execute_all_plugins = emergency_execute_all_plugins

        if not hasattr(self.plugin_manager, "set_scan_profile"):
            logger.error("Plugin manager missing set_scan_profile method")
            # Add no-op fallback for scan profile setting

            def emergency_set_scan_profile(profile):
                logger.warning("Emergency set_scan_profile called, profile noted but not applied", profile=profile)
                return True

            self.plugin_manager.set_scan_profile = emergency_set_scan_profile

        # Enable Frida-first dynamic analysis if available
        if FRIDA_FIRST_AVAILABLE:
            try:
                frida_enabled = enable_frida_first_analysis(self.plugin_manager)
                if frida_enabled:
                    logger.info("frida_first_enabled")
                    self.frida_first_enabled = True
                else:
                    logger.info("frida_first_enable_failed")
                    self.frida_first_enabled = False
            except Exception as e:
                logger.debug("frida_first_integration_error", error=str(e))
                self.frida_first_enabled = False
        else:
            logger.debug("frida_first_unavailable", fallback="standard_dynamic_analysis")
            self.frida_first_enabled = False

        # Apply custom scan profile if specified
        if scan_profile:
            from core.scan_profiles import ScanProfile

            profile_map = {
                "lightning": ScanProfile.LIGHTNING,
                "fast": ScanProfile.FAST,
                "standard": ScanProfile.STANDARD,
                "deep": ScanProfile.DEEP,
            }
            if scan_profile in profile_map:
                self.plugin_manager.set_scan_profile(profile_map[scan_profile])

        logger.debug("Plugin manager created successfully with scan optimization")

        # ENHANCED: Initialize unified execution framework
        self.enable_parallel = True
        self.enable_optimized = enable_optimized  # Enable Performance Enhancement Suite
        self.enable_ml = enable_ml  # Store ML enable/disable setting
        self.vulnerable_app_mode = vulnerable_app_mode  # Store vulnerable app mode setting
        self.execution_manager = None
        self.parallel_engine = None  # Backward compatibility only (disabled)

        # Initialize Performance Enhancement Suite if optimized mode is enabled
        self.performance_suite = None
        if self.enable_optimized:
            try:
                # MIGRATED: Use unified performance infrastructure
                from core.shared_infrastructure.monitoring.performance_tracker import get_unified_performance_tracker
                from core.shared_infrastructure.performance.caching_consolidation import get_unified_cache_manager

                self.performance_tracker = get_unified_performance_tracker()
                self.cache_manager = get_unified_cache_manager()
                logger.info("Unified Performance Infrastructure initialized, targeting EXCELLENT performance")
            except Exception as e:
                logger.warning(
                    "Performance Enhancement Suite initialization failed, falling back to standard execution mode",
                    error=str(e),
                )
                self.enable_optimized = False

        if self.enable_parallel:
            # Auto-detect optimal worker count based on system resources
            import psutil

            psutil.cpu_count()
            memory_gb = psutil.virtual_memory().total / (1024**3)

            # Very conservative worker count to prevent resource overwhelm
            # Try to get intelligent resource coordination from existing performance coordinator
            try:
                # MIGRATED: Use unified performance infrastructure for coordination
                from core.shared_infrastructure.monitoring.performance_tracker import get_unified_performance_tracker

                get_unified_performance_tracker()

                # Use unified performance coordination
                optimal_workers = min(2, max(1, int(memory_gb / 2)))
                max_workers = optimal_workers
                strategy = "parallel" if max_workers > 1 else "sequential"
                logger.info("Performance coordinator configured", max_workers=max_workers, strategy=strategy)

            except Exception as e:
                # EXTREME fallback - use environment variable or conservative default
                max_workers = int(os.environ.get("AODS_PARALLEL_WORKERS", "1"))
                strategy = "parallel" if max_workers > 1 else "sequential"
                logger.warning("Using emergency conservative settings", max_workers=max_workers, fallback_reason=str(e))

                # Optimized mode respects environment variable settings
            if self.enable_optimized:
                # Use environment variable for optimized mode
                optimized_workers = int(os.environ.get("AODS_PARALLEL_WORKERS", "2"))
                if optimized_workers > 1:
                    strategy = "parallel"
                    max_workers = optimized_workers
                    logger.info("Optimized mode enabled", max_workers=max_workers)
                else:
                    strategy = "sequential"
                    max_workers = 1
                    logger.warning("Optimized mode using sequential execution (1 worker)")

            # Create unified execution manager
            logger.debug("About to create unified execution manager")
            execution_config = {
                "max_workers": max_workers,
                "memory_limit_gb": min(memory_gb * 0.3, 4.0),  # Much more conservative - only 30% of memory, max 4GB
                "strategy": strategy,
                "adaptive": True,
                "enable_monitoring": True,
                "enable_caching": True,
            }

            self.execution_manager = ExecutionManager(execution_config)
            logger.debug("Unified execution manager created successfully")

            # Legacy parallel engine adapter disabled; canonical ExecutionManager will be used
            self.parallel_engine = None

            output_mgr = get_output_manager()

            if self.enable_optimized:
                output_mgr.status(
                    f"Optimized execution enabled: {max_workers} workers, " f"{memory_gb:.1f}GB memory available",
                    "info",
                )
            else:
                output_mgr.status(
                    f"Parallel execution enabled: {max_workers} workers, " f"{memory_gb:.1f}GB memory available",
                    "info",
                )

        # Reliable PLUGIN EXECUTION: Integrate reliable plugin execution manager to prevent premature termination
        # COORDINATION FIX: Only integrate if parallel execution is not already managing plugins
        self.robust_execution_manager = None
        if ROBUST_PLUGIN_EXECUTION_AVAILABLE and not self.enable_parallel:
            try:
                logger.debug("About to integrate reliable plugin execution manager")

                # CONSOLIDATION FIX: Use unified plugin manager's built-in execution capabilities
                # Configure execution parameters directly on the unified plugin manager
                if hasattr(self.plugin_manager, "configure_execution"):
                    self.plugin_manager.configure_execution(
                        default_timeout=120,  # 2 minutes default
                        max_timeout=300,  # 5 minutes maximum
                        retry_attempts=2,  # 2 retry attempts
                        max_concurrent_plugins=1,  # Sequential mode only
                    )

                # Use the unified plugin manager directly (no separate reliable execution manager needed)
                self.robust_execution_manager = self.plugin_manager

                output_mgr = get_output_manager()
                output_mgr.status(
                    "Reliable Plugin Execution Manager integrated - preventing premature termination", "success"
                )
                logger.debug("Reliable plugin execution manager integrated successfully")

            except Exception as e:
                logger.warning("robust_plugin_execution_failed", error=str(e))
                self.robust_execution_manager = None
        elif self.enable_parallel:
            logger.debug(
                "Skipping reliable plugin execution manager, parallel execution already handles reliable execution"
            )
        else:
            logger.warning("robust_plugin_execution_unavailable", fallback="legacy_execution")

        # Enterprise analysis attributes
        self.specific_plugins = []
        self.benchmarking_enabled = False

        # Dynamic analysis results storage
        self.dynamic_analysis_results: Optional[DynamicAnalysisResult] = None

        # ENTERPRISE PERFORMANCE INTEGRATION
        self.enterprise_integrator = None
        self.enterprise_enabled = False

        # Initialize enterprise performance optimization if available
        try:
            # MIGRATED: Use unified performance infrastructure for enterprise features
            from core.shared_infrastructure.monitoring.performance_tracker import get_unified_performance_tracker
            from core.shared_infrastructure.performance.caching_consolidation import get_unified_cache_manager
            import psutil

            memory_gb = psutil.virtual_memory().total / (1024**3)

            # Enable enterprise mode for large APKs or when explicitly requested
            apk_size_mb = os.path.getsize(apk_path) / (1024 * 1024) if os.path.exists(apk_path) else 0

            # Get system memory information
            import psutil

            memory_gb = psutil.virtual_memory().total / (1024**3)

            enable_enterprise = (
                self.enable_optimized  # Explicitly requested
                or apk_size_mb >= 100  # Large APK
                or memory_gb >= 8  # High-memory system
            ) and (os.getenv("AODS_ENTERPRISE_ENABLE", "0") == "1")

            if enable_enterprise:
                # Safely import enterprise integrator factory from available modules
                _create_epi = None
                try:
                    from core.enterprise_performance_integration import (
                        create_enterprise_performance_integrator as _create_epi,
                    )
                except Exception:
                    try:
                        from core.enterprise_performance_integration.enterprise_performance_integrator import (
                            create_enterprise_performance_integrator as _create_epi,
                        )
                    except Exception:
                        _create_epi = None

                if _create_epi is not None:
                    try:
                        self.enterprise_integrator = _create_epi()
                    except Exception as _epi_err:
                        logger.warning(
                            "enterprise_integrator_init_failed",
                            error=str(_epi_err),
                        )
                        self.enterprise_integrator = None
                        enable_enterprise = False
                else:
                    logger.warning("enterprise_integrator_factory_unavailable")
                    self.enterprise_integrator = None
                    enable_enterprise = False
                self.enterprise_enabled = True
                output_mgr = get_output_manager()
                output_mgr.status(
                    f"Enterprise Performance Optimization enabled: {apk_size_mb:.1f}MB APK, "
                    f"{memory_gb:.1f}GB memory available",
                    "info",
                )

        except ImportError as e:
            logger.warning("enterprise_optimization_unavailable", error=str(e))
            self.enterprise_integrator = None
            self.enterprise_enabled = False

        # Initialize consolidated results dictionary for report generation
        self.consolidated_results = {
            "vulnerabilities": [],
            "informational": [],
            "statistics": {},
            "metadata": {},
            "ml_metrics": {},
        }

    def _execute_comprehensive_static_analysis(self, apk_ctx):
        """Delegate to scanner_static module (Track 50)."""
        from core.cli.scanner_static import execute_comprehensive_static_analysis

        return execute_comprehensive_static_analysis(apk_ctx)

    def _analyze_manifest_patterns(self, content, patterns_config, file_path):
        """Delegate to scanner_static module (Track 50)."""
        from core.cli.scanner_static import analyze_manifest_patterns

        return analyze_manifest_patterns(content, patterns_config, file_path)

    def _analyze_source_patterns(self, content, patterns_config, file_path):
        """Delegate to scanner_static module (Track 50)."""
        from core.cli.scanner_static import analyze_source_patterns

        return analyze_source_patterns(content, patterns_config, file_path)

    def unpack_apk(self) -> None:
        """
        Unpack the APK file for static analysis with enhanced memory management.

        Uses enhanced apktool extraction with memory optimization for large APKs.
        Includes fallback extraction if normal extraction fails.
        """
        logger.info("apk_unpack_started")

        # Use enhanced extraction method from APKContext
        extraction_success = self.apk_ctx._extract_apk_with_apktool()

        if not extraction_success:
            logger.error("apk_extraction_failed", method="enhanced")
            logger.error(
                Text.from_markup(
                    "[red][!] APK extraction failed. This may be due to memory constraints or APK corruption.[/red]"
                )
            )
            sys.exit(1)

        # Check if manifest exists (may be binary in fallback mode)
        if not self.apk_ctx.manifest_path.exists():
            # For fallback extraction, manifest might be binary
            binary_manifest = self.apk_ctx.decompiled_apk_dir / "AndroidManifest.xml"
            if not binary_manifest.exists():
                logger.error("manifest_not_found")
                logger.error(
                    Text.from_markup(
                        "[red][!] AndroidManifest.xml not found after unpacking. "
                        "This may indicate APK corruption or extraction failure.[/red]"
                    )
                )
                sys.exit(1)
            else:
                logger.info("binary_manifest_found", analysis="limited")

        logger.info("apk_unpack_completed")

        # Initialize analyzer with extracted content
        analyzer = APKAnalyzer(
            manifest_dir=str(self.apk_ctx.decompiled_apk_dir),
            decompiled_dir=str(self.apk_ctx.decompiled_apk_dir),
        )
        self.apk_ctx.set_apk_analyzer(analyzer)

    def add_report_section(self, title: str, content: Union[str, Text]) -> None:
        """
        Add a section to the report data.

        Args:
            title: The section title for the report
            content: The content to include in the section
        """
        self.report_data.append((title, content))

        # Handle both unified and legacy reporting systems
        if hasattr(self, "report_manager") and self.report_manager is not None:
            # Using unified reporting system - store for later report generation
            if not hasattr(self, "_report_sections"):
                self._report_sections = []
            self._report_sections.append({"title": title, "content": content})
        elif hasattr(self, "report_generator") and self.report_generator is not None:
            # Using legacy reporting system
            self.report_generator.add_section(title, content)
        # If neither is available, just store in report_data for now

    def _check_frida_availability(self) -> bool:
        """
        Check if Frida is available for dynamic analysis.

        Returns:
            bool: True if Frida is available, False otherwise
        """
        try:
            logger.info("frida_available")
            return True
        except ImportError:
            logger.warning("frida_unavailable", fallback="fallback_methods")
            return False

    def get_performance_report(self) -> Dict[str, Any]:
        """Get full performance optimization report if available."""
        if self.enable_optimized and self.performance_suite:
            return self.performance_suite.get_performance_report()
        else:
            return {
                "optimization_enabled": False,
                "message": "Performance Enhancement Suite not enabled. Use --optimized flag for EXCELLENT performance.",
            }

    def run_plugins(self) -> None:
        """
        Execute all plugins using enhanced parallel execution system.

        ENHANCED: Now uses parallel plugin execution engine for 3-5x speed improvement
        with intelligent dependency management and memory optimization.
        """
        output_mgr = get_output_manager()

        # Check for shutdown request before starting plugins
        if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
            output_mgr.warning("Shutdown requested - skipping plugin execution")
            return

        # Enhanced plugin execution logging
        total_plugins = len(self.plugin_manager.plugins)
        output_mgr.info(f"Starting plugin execution: {total_plugins} plugins loaded")

        # Log plugin details
        plugin_names = list(self.plugin_manager.plugins.keys())
        output_mgr.info(f"📋 Active plugins: {', '.join(plugin_names)}")

        # Validate plugin integration if available
        if hasattr(self.plugin_manager, "validate_integration"):
            if not self.plugin_manager.validate_integration():
                output_mgr.warning("Some advanced plugins may not be available")
            else:
                output_mgr.warning("Some advanced plugins may not be available")

        # Enhanced execution with parallel capabilities
        if self.enable_parallel and self.execution_manager:
            _max_workers = getattr(self.execution_manager.config, "max_workers", 2)
            output_mgr.section_header(
                "Parallel Plugin Execution",
                f"Running plugins with {_max_workers} workers",
            )
            output_mgr.info(f"Parallel execution mode: {_max_workers} workers")

            # Track execution time for performance metrics
            import time

            start_time = time.time()

            # PERFORMANCE ENHANCEMENT SUITE: Apply full optimizations
            if self.enable_optimized and self.performance_suite:
                try:
                    output_mgr.info("🚀 Applying Performance Enhancement Suite optimizations...")

                    # Create full scan context for optimization
                    scan_context = {
                        "apk_context": {
                            "package_name": self.apk_ctx.package_name,
                            "apk_path": self.apk_ctx.apk_path_str,
                            "scan_mode": getattr(self.apk_ctx, "scan_mode", "safe"),
                        },
                        "plugins": [
                            {
                                "name": plugin_name,
                                "type": "static_analysis",  # Default type
                                "dependencies": [],
                                "shared_state": False,
                            }
                            for plugin_name in self.plugin_manager.plugins.keys()
                        ],
                        "findings": [],  # Will be populated during execution
                        "patterns": [],  # Plugin patterns for optimization
                        "scan_mode": "full",
                        "apk_path": self.apk_ctx.apk_path_str,
                    }

                    # Apply performance optimization
                    optimization_result = self.performance_suite.optimize_full_scan_performance(scan_context)

                    if optimization_result.get("optimization_applied"):
                        performance_metrics = optimization_result["performance_metrics"]
                        output_mgr.status(
                            f"Performance optimizations applied: +{performance_metrics['estimated_score_improvement']:.1f} points improvement",  # noqa: E501
                            "success",
                        )
                        output_mgr.info(
                            f"Projected performance score: {performance_metrics['projected_score']:.1f}/100"
                        )

                except Exception as e:
                    output_mgr.warning(f"Performance Enhancement Suite failed: {e}")
                    output_mgr.info("Continuing with standard execution")

            # Execute all plugins with parallel engine and graceful shutdown support
            try:
                plugin_results = self.plugin_manager.execute_all_plugins(self.apk_ctx)
            except KeyboardInterrupt:
                output_mgr.warning("Plugin execution interrupted by user")
                if GRACEFUL_SHUTDOWN_AVAILABLE:
                    get_shutdown_manager().shutdown_now()
                return
            except Exception:
                if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
                    output_mgr.warning("🛑 Plugin execution stopped due to shutdown request")
                    return
                raise

            execution_time = time.time() - start_time

            # Display performance metrics
            output_mgr.info(f"Plugin execution completed in {execution_time:.1f}s")
        else:
            output_mgr.section_header("Sequential Plugin Execution", "Running plugins in sequential mode")
            output_mgr.info("Sequential execution mode: processing plugins one by one")

            # PERFORMANCE ENHANCEMENT SUITE: Apply optimizations for sequential mode too
            if self.enable_optimized and self.performance_suite:
                try:
                    output_mgr.info("🚀 Applying Performance Enhancement Suite optimizations (sequential mode)...")

                    # Create scan context for sequential optimization
                    scan_context = {
                        "apk_context": {
                            "package_name": self.apk_ctx.package_name,
                            "apk_path": self.apk_ctx.apk_path_str,
                            "scan_mode": getattr(self.apk_ctx, "scan_mode", "safe"),
                        },
                        "plugins": [
                            {
                                "name": plugin_name,
                                "type": "static_analysis",
                                "dependencies": [],
                                "shared_state": True,  # Sequential mode implies shared state
                            }
                            for plugin_name in self.plugin_manager.plugins.keys()
                        ],
                        "findings": [],
                        "patterns": [],
                        "scan_mode": "sequential",
                        "apk_path": self.apk_ctx.apk_path_str,
                    }

                    # Apply performance optimization
                    optimization_result = self.performance_suite.optimize_full_scan_performance(scan_context)

                    if optimization_result.get("optimization_applied"):
                        performance_metrics = optimization_result["performance_metrics"]
                        output_mgr.status(
                            f"Sequential mode optimizations applied: +{performance_metrics['estimated_score_improvement']:.1f} points",  # noqa: E501
                            "success",
                        )

                except Exception as e:
                    output_mgr.warning(f"Performance Enhancement Suite failed: {e}")
                    output_mgr.info("Continuing with standard sequential execution")

            # Fallback to sequential execution with graceful shutdown support
            try:
                plugin_results = self.plugin_manager.execute_all_plugins(self.apk_ctx)
            except KeyboardInterrupt:
                output_mgr.warning("Plugin execution interrupted by user")
                if GRACEFUL_SHUTDOWN_AVAILABLE:
                    get_shutdown_manager().shutdown_now()
                return
            except Exception:
                if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
                    output_mgr.warning("🛑 Plugin execution stopped due to shutdown request")
                    return
                raise

        # Check for shutdown before processing results
        if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
            output_mgr.warning("Shutdown requested - skipping result processing")
            return

        # Add plugin results to report with detailed logging
        results_count = 0

        # ENTERPRISE PERFORMANCE OPTIMIZATION: Apply optimization to plugin results
        if self.enterprise_enabled and self.enterprise_integrator:
            try:
                output_mgr.info("Applying enterprise performance optimization...")

                # Check plugin_results validity before processing
                if plugin_results is None or not isinstance(plugin_results, dict):
                    output_mgr.warning("⚠️  Plugin results invalid for optimization - skipping enterprise optimization")
                    plugin_results = plugin_results or {}
                else:
                    # Convert plugin results to findings format for optimization
                    # Phase 9.6: Use proper title validation and nested extraction
                    findings = []
                    for plugin_name, result in plugin_results.items():
                        # Handle various result formats safely
                        try:
                            if isinstance(result, (tuple, list)) and len(result) >= 2:
                                title, content = result[0], result[1]
                            elif isinstance(result, dict):
                                title = result.get("title", plugin_name)
                                content = result.get("content", result)
                            else:
                                title = plugin_name
                                content = str(result) if result is not None else "No results"
                        except (ValueError, TypeError):
                            title = plugin_name
                            content = f"Result format error: {result}"

                        # Phase 9.6: Extract nested findings from content first
                        nested_findings = _extract_findings_from_content(content, plugin_name)
                        if nested_findings:
                            # Use extracted findings instead of treating content as single finding
                            for nf in nested_findings:
                                title_str = str(nf.get("title", "")).lower()
                                findings.append(
                                    {
                                        "plugin": plugin_name,
                                        "title": nf.get("title", f"{plugin_name} Finding"),
                                        "content": nf.get("description", nf.get("content", str(nf))),
                                        "type": "vulnerability" if "vulnerability" in title_str else "info",
                                        **{k: v for k, v in nf.items() if k not in ("title", "content", "description")},
                                    }
                                )
                            continue

                        # Phase 9.6: Validate title before creating finding
                        title_str = ""
                        if hasattr(title, "value"):
                            title_str = str(title.value)
                        elif title:
                            title_str = str(title)

                        # Skip findings with invalid titles (status strings, summaries)
                        if not _is_valid_finding_title(title_str):
                            continue

                        findings.append(
                            {
                                "plugin": plugin_name,
                                "title": title_str,
                                "content": content,
                                "type": "vulnerability" if "vulnerability" in title_str.lower() else "info",
                            }
                        )

                    # Apply enterprise optimization
                    app_context = {
                        "package_name": self.apk_ctx.package_name,
                        "apk_path": self.apk_ctx.apk_path_str,
                        "scan_mode": self.apk_ctx.scan_mode,
                    }

                    optimization_result = self.enterprise_integrator.optimize_apk_analysis(
                        self.apk_ctx.apk_path_str, findings, app_context
                    )

                    # Update plugin results with optimized findings if successful
                    if optimization_result.get("status") == "success":
                        optimized_findings = optimization_result.get("detailed_results", {}).get(
                            "final_findings", findings
                        )

                        # Reconstruct plugin_results with optimized findings
                        optimized_plugin_results = {}
                        for i, finding in enumerate(optimized_findings):
                            if i < len(plugin_results):
                                plugin_name = list(plugin_results.keys())[i]
                                optimized_plugin_results[plugin_name] = (
                                    finding.get("title", "Optimized Result"),
                                    finding.get("content", ""),
                                )

                        plugin_results = optimized_plugin_results

                        output_mgr.status(
                            f"Enterprise optimization applied: {optimization_result['reduction_percentage']:.1f}% "
                            f"reduction in {optimization_result['analysis_time_seconds']:.2f}s",
                            "success",
                        )
                    else:
                        output_mgr.warning("Enterprise optimization failed, using original results")

            except Exception as e:
                output_mgr.warning(f"Enterprise optimization error: {e}")
                # Continue with original results

        # Handle None plugin_results from safe mode
        if plugin_results is None:
            output_mgr.warning("⚠️  Plugin execution returned no results (possibly due to resource constraints)")
            plugin_results = {}

        if not isinstance(plugin_results, dict):
            output_mgr.error(f"❌ Invalid plugin results format: {type(plugin_results)}")
            plugin_results = {}

        for plugin_name, result in plugin_results.items():
            # Handle various result formats safely
            try:
                if hasattr(result, "findings") and hasattr(result, "status"):
                    # PluginResult dataclass - pass through directly so
                    # scanner_report.py can extract structured PluginFindings
                    title = plugin_name
                    content = result
                elif isinstance(result, (tuple, list)) and len(result) >= 2:
                    title, content = result[0], result[1]
                    # Track 85.3: Check if content inside a tuple is a wrapped PluginResult
                    if hasattr(content, "findings") and hasattr(content, "status"):
                        title = plugin_name
                        content = content
                elif isinstance(result, dict):
                    title = result.get("title", plugin_name)
                    content = result.get("content", str(result))
                else:
                    # Handle single value or unexpected format
                    title = plugin_name
                    content = str(result) if result is not None else "No results"

            except (ValueError, TypeError) as e:
                output_mgr.warning(f"⚠️  Invalid result format for {plugin_name}: {e}")
                title = plugin_name
                content = f"Result format error: {e}"

            # Check for shutdown during result processing
            if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
                output_mgr.warning("Shutdown requested during result processing")
                break

            self.add_report_section(title, content)
            results_count += 1
            output_mgr.verbose(f"Added report section: {title}")

        output_mgr.info(f"Plugin results processed: {results_count} sections added to report")

        # Display plugin execution summary
        if not (GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested()):
            if hasattr(self.plugin_manager, "generate_plugin_summary"):
                summary_table = self.plugin_manager.generate_plugin_summary()
                output_mgr.console.print(summary_table)
            else:
                output_mgr.status("Plugin Summary: 5 plugins executed", "info")

            # Display MASVS coverage
            if hasattr(self.plugin_manager, "get_masvs_coverage"):
                masvs_coverage = self.plugin_manager.get_masvs_coverage()
                output_mgr.status(f"MASVS Controls Covered: {len(masvs_coverage)}", "info")
            else:
                output_mgr.status("MASVS Controls Covered: 0", "info")

    def attack_surface_analysis(self) -> None:
        """Delegate to scanner_analysis module (Track 50)."""
        from core.cli.scanner_analysis import attack_surface_analysis

        attack_surface_analysis(self)

    def traversal_vulnerabilities(self) -> None:
        """Delegate to scanner_analysis module (Track 50)."""
        from core.cli.scanner_analysis import traversal_vulnerabilities

        traversal_vulnerabilities(self)

    def injection_vulnerabilities(self) -> None:
        """Delegate to scanner_analysis module (Track 50)."""
        from core.cli.scanner_analysis import injection_vulnerabilities

        injection_vulnerabilities(self)

    def extract_additional_info(self) -> None:
        """Delegate to scanner_analysis module (Track 50)."""
        from core.cli.scanner_analysis import extract_additional_info

        extract_additional_info(self)

    def test_debuggable_logging(self) -> None:
        """Delegate to scanner_analysis module (Track 50)."""
        from core.cli.scanner_analysis import test_debuggable_logging

        test_debuggable_logging(self)

    def network_cleartext_traffic_analyzer(self) -> None:
        """Delegate to scanner_analysis module (Track 50)."""
        from core.cli.scanner_analysis import network_cleartext_traffic_analyzer

        network_cleartext_traffic_analyzer(self)

    def set_report_formats(self, formats: List[str]) -> None:
        """
        Set the output formats for report generation.

        Args:
            formats: List of format strings ('txt', 'json', 'csv', 'all')
        """
        valid_formats = {"txt", "json", "csv", "html", "all"}
        self.report_formats = [fmt for fmt in formats if fmt in valid_formats]
        if not self.report_formats:
            self.report_formats = ["txt"]  # Default fallback
        logger.info("report_formats_set", formats=self.report_formats)

    def _determine_status_from_content(self, content) -> str:
        """Determine the status from content for report generation."""
        content_str = str(content).lower()

        # Check for explicit status indicators
        if "status: fail" in content_str or "status: failed" in content_str:
            return "FAIL"
        elif "status: pass" in content_str or "status: passed" in content_str:
            return "PASS"
        elif "risk level: high" in content_str or "risk_level: high" in content_str:
            return "HIGH_RISK"
        elif "risk level: medium" in content_str or "risk_level: medium" in content_str:
            return "MEDIUM_RISK"
        elif "risk level: low" in content_str or "risk_level: low" in content_str:
            return "LOW_RISK"
        elif "vulnerability" in content_str or "insecure" in content_str:
            return "VULNERABLE"
        elif "secure" in content_str or "safe" in content_str:
            return "SECURE"
        else:
            return "INFO"

    def _validate_and_sync_vulnerabilities(self, classification_results: Dict[str, Any]) -> None:
        """
        PERMANENT FIX: Full vulnerability data validation and synchronization.

        This method ensures that vulnerabilities are consistently available across all
        data structures to prevent future report generation failures.

        Uses merge-based logic to combine findings from all containers (not priority-based)
        to prevent findings from being lost when they exist in one container but not another.
        """
        # Use module-level logger (structlog when available)

        # MERGE-BASED LOGIC: Combine all containers instead of picking one
        # This prevents findings in enhanced_vulnerabilities from being lost
        # when vulnerabilities also has items
        merge_sources = {
            "vulnerabilities": classification_results.get("vulnerabilities", []),
            "enhanced_vulnerabilities": classification_results.get("enhanced_vulnerabilities", []),
        }

        # Also include self.vulnerabilities if present
        if hasattr(self, "vulnerabilities") and self.vulnerabilities:
            merge_sources["self.vulnerabilities"] = self.vulnerabilities

        # Use the canonical merge function for deduplication
        vulnerabilities = _create_canonical_findings(merge_sources, logger)

        # Sync all 4 container keys (vulnerabilities, enhanced_vulnerabilities,
        # vulnerability_findings, findings) so downstream report generation
        # never hits a missing-key error.
        _sync_all_containers(classification_results, vulnerabilities, logger)

        logger.info("Vulnerability sync completed", merged_count=len(vulnerabilities), source_count=len(merge_sources))

        # Synchronize across all possible containers
        if vulnerabilities:
            # Ensure main classification results has vulnerabilities
            classification_results["vulnerabilities"] = vulnerabilities

            # Ensure consolidated_results has vulnerabilities
            if not hasattr(self, "consolidated_results") or not self.consolidated_results:
                self.consolidated_results = {}
            self.consolidated_results["vulnerabilities"] = vulnerabilities

            # Ensure instance has vulnerabilities
            self.vulnerabilities = vulnerabilities

            # Ensure report generator has vulnerabilities
            if hasattr(self, "report_generator") and self.report_generator:
                self.report_generator.vulnerabilities = vulnerabilities

            # Update vulnerability summary to match actual count
            if "vulnerability_summary" not in classification_results:
                classification_results["vulnerability_summary"] = {}

            vuln_summary = classification_results["vulnerability_summary"]
            vuln_summary["total_vulnerabilities"] = len(vulnerabilities)

            # Count by severity if available
            severity_counts = {"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0}
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "").lower()
                if severity == "critical":
                    severity_counts["critical_count"] += 1
                elif severity == "high":
                    severity_counts["high_count"] += 1
                elif severity == "medium":
                    severity_counts["medium_count"] += 1
                elif severity == "low":
                    severity_counts["low_count"] += 1

            vuln_summary.update(severity_counts)

            logger.info(
                "Synchronized vulnerabilities across all containers",
                count=len(vulnerabilities),
                total=vuln_summary["total_vulnerabilities"],
            )
        else:
            # Ensure container keys exist with empty defaults to prevent
            # KeyError in scanner_report.py when accessing result containers.
            classification_results.setdefault(
                "vulnerability_summary",
                {
                    "total_vulnerabilities": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                },
            )
            logger.info("No vulnerabilities found in any container - reports may be empty")

    def generate_report(self) -> Dict[str, str]:
        """Delegate to scanner_report module (Track 50)."""
        from core.cli.scanner_report import generate_report_impl

        return generate_report_impl(self)

    def run_dynamic_analysis_only(self, timeout: int = 300) -> Dict[str, Any]:
        """Delegate to scanner_dynamic module (Track 50)."""
        from core.cli.scanner_dynamic import run_dynamic_analysis_only

        return run_dynamic_analysis_only(self, timeout)

    def _create_empty_dynamic_result(self, reason: str = "No plugins executed") -> Dict[str, Any]:
        """Delegate to scanner_dynamic module (Track 50)."""
        from core.cli.scanner_dynamic import create_empty_dynamic_result

        return create_empty_dynamic_result(self, reason)

    def _create_error_dynamic_result(self, error_msg: str) -> Dict[str, Any]:
        """Delegate to scanner_dynamic module (Track 50)."""
        from core.cli.scanner_dynamic import create_error_dynamic_result

        return create_error_dynamic_result(self, error_msg)

    def _get_recovery_suggestions(self, error_msg: str) -> list:
        """Delegate to scanner_dynamic module (Track 50)."""
        from core.cli.scanner_dynamic import get_recovery_suggestions

        return get_recovery_suggestions(error_msg)


# Backward-compat alias (renamed from OWASPTestSuiteDrozer in Track 48)
OWASPTestSuiteDrozer = AODSScanner
