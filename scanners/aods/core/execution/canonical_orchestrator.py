#!/usr/bin/env python3
"""
Canonical AODS Execution Orchestrator
====================================

Single source of truth for all AODS execution orchestration, consolidating:
- core/enhanced_scan_orchestrator.py (1,667 lines)
- core/execution/unified_manager.py (568 lines)
- core/plugin_manager.py (1,587 lines)
- Multiple parallel execution systems

This canonical orchestrator provides:
1. Single execution entry point (AODS_CANONICAL=1)
2. Unified configuration and strategy selection
3. Full backward compatibility
4. Deterministic execution ordering
5. Enhanced error handling and recovery
6. Performance optimization and monitoring

Usage:
    from core.execution.canonical_orchestrator import CanonicalOrchestrator

    orchestrator = CanonicalOrchestrator()
    result = orchestrator.execute_comprehensive_analysis(args)
"""

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum
from pathlib import Path

# Import unified execution components
from .unified_manager import UnifiedExecutionManager, ExecutionMode
from .execution_path_guard import ExecutionPathGuard

# Import unified configuration system
try:
    from core.shared_infrastructure.configuration import UnifiedConfigurationManager

    UNIFIED_CONFIG_AVAILABLE = True
except ImportError:
    UNIFIED_CONFIG_AVAILABLE = False

# Import multi-tenant boundary management
try:
    from core.tenant import TenantContext, create_boundary_manager

    MULTI_TENANT_AVAILABLE = True
except ImportError:
    MULTI_TENANT_AVAILABLE = False

# Import enhanced orchestrator components for backward compatibility
try:
    from ..enhanced_scan_orchestrator import EnhancedScanOrchestrator, ScanJob

    ENHANCED_ORCHESTRATOR_AVAILABLE = True
except ImportError:
    ENHANCED_ORCHESTRATOR_AVAILABLE = False

# Import legacy plugin manager for compatibility
try:
    from ..plugin_manager import PluginManager

    LEGACY_PLUGIN_MANAGER_AVAILABLE = True
except ImportError:
    LEGACY_PLUGIN_MANAGER_AVAILABLE = False

# Import unified plugin manager for canonical plugin discovery
try:
    from ..plugins import UnifiedPluginManager

    UNIFIED_PLUGIN_MANAGER_AVAILABLE = True
except ImportError:
    UNIFIED_PLUGIN_MANAGER_AVAILABLE = False

# Import APK context
try:
    from ..apk_ctx import APKContext

    APK_CONTEXT_AVAILABLE = True
except ImportError:
    APK_CONTEXT_AVAILABLE = False

logger = logging.getLogger(__name__)


class OrchestrationStrategy(Enum):
    """Orchestration strategies for different execution modes."""

    CANONICAL = "canonical"  # New unified approach (AODS_CANONICAL=1)
    ENHANCED = "enhanced"  # Enhanced scan orchestrator
    LEGACY = "legacy"  # Legacy plugin manager
    UNIFIED = "unified"  # Unified execution manager
    AUTO = "auto"  # Automatic strategy selection


@dataclass
class CanonicalExecutionConfig:
    """Configuration for canonical orchestration."""

    strategy: OrchestrationStrategy = OrchestrationStrategy.AUTO
    enable_parallel: bool = True
    enable_ml_enhancement: bool = True
    ml_enhancement_level: str = "standard"  # disabled, basic, standard, advanced, maximum
    enable_performance_monitoring: bool = True
    max_concurrent_plugins: int = 4
    timeout_seconds: int = 1800
    enable_deterministic_ordering: bool = True
    enable_backward_compatibility: bool = True

    # Environment-based overrides
    force_canonical: bool = field(default_factory=lambda: os.getenv("AODS_CANONICAL", "0") == "1")
    disable_ml: bool = field(default_factory=lambda: os.getenv("AODS_DISABLE_ML", "0") == "1")


@dataclass
class CanonicalExecutionResult:
    """Result from canonical orchestration."""

    strategy_used: OrchestrationStrategy
    execution_time: float
    total_plugins_executed: int
    successful_plugins: int
    failed_plugins: int
    vulnerabilities_found: int
    analysis_results: Dict[str, Any]
    performance_metrics: Dict[str, Any]
    success: bool
    error_message: Optional[str] = None
    compatibility_warnings: List[str] = field(default_factory=list)


class CanonicalOrchestrator:
    """
    Canonical AODS execution orchestrator providing unified entry point.

    This orchestrator eliminates the dual orchestration path problem by:
    1. Providing single canonical entry point
    2. Intelligently routing to appropriate execution strategy
    3. Maintaining full backward compatibility
    4. Ensuring deterministic execution ordering
    5. Error handling and recovery
    """

    def __init__(self, config: Optional[CanonicalExecutionConfig] = None):
        """Initialize canonical orchestrator."""
        self.config = config or CanonicalExecutionConfig()
        self.logger = logging.getLogger(__name__)

        # Initialize unified configuration manager
        self.unified_config_manager = None
        if UNIFIED_CONFIG_AVAILABLE:
            try:
                self.unified_config_manager = UnifiedConfigurationManager()
                self.logger.info("✅ Unified Configuration Manager integrated")
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to initialize unified configuration: {e}")

        # Initialize execution managers
        self._unified_manager: Optional[UnifiedExecutionManager] = None
        self._enhanced_orchestrator: Optional[EnhancedScanOrchestrator] = None
        self._legacy_plugin_manager: Optional[PluginManager] = None

        # Initialize multi-tenant boundary manager
        self.boundary_manager = None
        if MULTI_TENANT_AVAILABLE:
            try:
                self.boundary_manager = create_boundary_manager()
                self.logger.info("✅ Multi-Tenant Boundary Manager initialized")
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to initialize multi-tenant boundary manager: {e}")
                self.boundary_manager = None

        # Execution state
        self._current_strategy: Optional[OrchestrationStrategy] = None
        self._execution_history: List[CanonicalExecutionResult] = []

        # Performance monitoring
        self._performance_metrics = {
            "total_executions": 0,
            "successful_executions": 0,
            "average_execution_time": 0.0,
            "strategy_usage": {},
        }

        self.logger.info("Canonical orchestrator initialized")

    def execute_comprehensive_analysis(
        self, args, tenant_context: Optional[TenantContext] = None
    ) -> CanonicalExecutionResult:
        """
        Execute full AODS analysis using canonical orchestration.

        This is the main entry point for AODS_CANONICAL=1 execution mode.

        Args:
            args: Command line arguments and configuration
            tenant_context: Optional tenant context for multi-tenant execution

        Returns:
            CanonicalExecutionResult with analysis results
        """
        start_time = time.time()

        try:
            self.logger.info("🚀 Starting canonical analysis")

            # Handle multi-tenant context
            if tenant_context and self.boundary_manager:
                # Validate tenant access
                if not self.boundary_manager.validate_tenant_access(
                    tenant_context, "scan_apk", getattr(args, "apk_path", None)
                ):
                    raise PermissionError(f"Tenant {tenant_context.tenant_id} does not have access to perform scan")

                # Apply tenant-specific configuration
                args = self._apply_tenant_configuration(args, tenant_context)

                self.logger.info(f"🏢 Executing analysis for tenant: {tenant_context.tenant_id}")

            # Determine optimal orchestration strategy (freeze via guard)
            strategy = self._determine_orchestration_strategy(args)
            self._current_strategy = strategy
            # Freeze path as 'canonical' here and validate downstream callers
            _ = ExecutionPathGuard.get_guard().freeze("canonical")

            self.logger.info(f"📋 Using orchestration strategy: {strategy.value}")

            # Execute using selected strategy
            if strategy == OrchestrationStrategy.CANONICAL:
                result = self._execute_canonical_strategy(args)
            elif strategy == OrchestrationStrategy.UNIFIED:
                result = self._execute_unified_strategy(args)
            elif strategy == OrchestrationStrategy.ENHANCED:
                result = self._execute_enhanced_strategy(args)
            elif strategy == OrchestrationStrategy.LEGACY:
                result = self._execute_legacy_strategy(args)
            else:
                raise ValueError(f"Unknown orchestration strategy: {strategy}")

            # Apply tenant isolation to findings if needed
            if tenant_context and "findings" in result:
                result["findings"] = self._isolate_findings_for_tenant(result["findings"], tenant_context)

            # Enhance result with canonical metadata
            canonical_result = self._create_canonical_result(strategy, result, time.time() - start_time, tenant_context)

            # Update performance metrics
            self._update_performance_metrics(canonical_result)

            # Store in execution history
            self._execution_history.append(canonical_result)

            self.logger.info(f"✅ Canonical analysis completed in {canonical_result.execution_time:.2f}s")

            return canonical_result

        except Exception as e:
            self.logger.error(f"❌ Canonical analysis failed: {e}")

            # Create error result
            error_result = CanonicalExecutionResult(
                strategy_used=self._current_strategy or OrchestrationStrategy.AUTO,
                execution_time=time.time() - start_time,
                total_plugins_executed=0,
                successful_plugins=0,
                failed_plugins=0,
                vulnerabilities_found=0,
                analysis_results={},
                performance_metrics={},
                success=False,
                error_message=str(e),
            )

            self._execution_history.append(error_result)
            return error_result

    def _determine_orchestration_strategy(self, args) -> OrchestrationStrategy:
        """Determine optimal orchestration strategy based on configuration and environment."""

        # Force canonical if environment variable set
        if self.config.force_canonical:
            self.logger.info("🎯 AODS_CANONICAL=1: Using canonical strategy")
            return OrchestrationStrategy.CANONICAL

        # Check for explicit strategy in args
        if hasattr(args, "orchestration_strategy"):
            strategy_name = args.orchestration_strategy.lower()
            for strategy in OrchestrationStrategy:
                if strategy.value == strategy_name:
                    return strategy

        # Auto-select based on available components and requirements
        if self.config.strategy == OrchestrationStrategy.AUTO:
            return self._auto_select_strategy(args)

        return self.config.strategy

    def _auto_select_strategy(self, args) -> OrchestrationStrategy:
        """Automatically select best orchestration strategy."""

        # Prefer canonical for new installations
        if self._is_new_installation():
            return OrchestrationStrategy.CANONICAL

        # Use unified for standard operations
        if UNIFIED_EXECUTION_AVAILABLE:
            return OrchestrationStrategy.UNIFIED

        # Fall back to enhanced if available
        if ENHANCED_ORCHESTRATOR_AVAILABLE:
            return OrchestrationStrategy.ENHANCED

        # Last resort: legacy
        if LEGACY_PLUGIN_MANAGER_AVAILABLE:
            return OrchestrationStrategy.LEGACY

        # Default to canonical
        return OrchestrationStrategy.CANONICAL

    def _is_new_installation(self) -> bool:
        """Check if this is a new AODS installation."""
        # Simple heuristic: check for legacy configuration files
        legacy_indicators = ["config/legacy_plugin_config.yaml", "config/old_execution_config.yaml"]

        project_root = Path(__file__).parent.parent.parent
        for indicator in legacy_indicators:
            if (project_root / indicator).exists():
                return False

        return True

    def _execute_canonical_strategy(self, args) -> Dict[str, Any]:
        """Execute using canonical strategy (new unified approach)."""
        self.logger.info("🎯 Executing canonical strategy")

        # PERFORMANCE FIX: Get scan profile for timeout optimization
        scan_profile_str = getattr(args, "profile", None) or getattr(args, "scan_profile", None)

        # Profile-based total scan timeout (prevents indefinite execution)
        profile_total_timeouts = {
            "lightning": 120,  # 2 minutes max (expected ~30s)
            "fast": 300,  # 5 minutes max (expected ~2-3min)
            "standard": 900,  # 15 minutes max (expected ~5-8min)
            "deep": 3600,  # 60 minutes max (expected ~15+min)
        }
        total_scan_timeout = profile_total_timeouts.get((scan_profile_str or "").lower(), self.config.timeout_seconds)
        self.logger.info(f"📋 Scan profile: {scan_profile_str or 'default'}, total timeout: {total_scan_timeout}s")

        # Initialize unified execution manager if not already done
        if not self._unified_manager:
            self._unified_manager = UnifiedExecutionManager()

        # Create APK context
        apk_ctx = self._create_apk_context(args)

        # Get plugins to execute
        plugins = self._get_plugins_for_execution(args)

        # Execute using unified manager with profile-based timeout
        execution_mode = ExecutionMode.PARALLEL if self.config.enable_parallel else ExecutionMode.SEQUENTIAL
        result = self._unified_manager.execute(plugins, apk_ctx, execution_mode, scan_profile=scan_profile_str)

        return {
            "strategy": "canonical",
            "execution_result": result,
            "plugins_executed": len(plugins),
            "success": result.success,
            "scan_profile": scan_profile_str,
            "total_timeout": total_scan_timeout,
        }

    def _execute_unified_strategy(self, args) -> Dict[str, Any]:
        """Execute using unified execution manager."""
        self.logger.info("🎯 Executing unified strategy")

        # Initialize unified manager if needed
        if not self._unified_manager:
            self._unified_manager = UnifiedExecutionManager()

        # Use unified manager's analysis
        return self._unified_manager.run_comprehensive_analysis(args)

    def _execute_enhanced_strategy(self, args) -> Dict[str, Any]:
        """Execute using enhanced scan orchestrator."""
        self.logger.info("🎯 Executing enhanced strategy")

        if not ENHANCED_ORCHESTRATOR_AVAILABLE:
            raise RuntimeError("Enhanced orchestrator not available")

        # Initialize enhanced orchestrator if needed
        if not self._enhanced_orchestrator:
            apk_path = getattr(args, "apk", "")
            self._enhanced_orchestrator = EnhancedScanOrchestrator(apk_path)

        # Create scan job and execute
        scan_job = ScanJob(
            job_id=f"canonical_{int(time.time())}",
            apk_path=getattr(args, "apk", ""),
            scan_type="full",
            priority=1,
        )

        return self._enhanced_orchestrator.execute_scan_job(scan_job)

    def _execute_legacy_strategy(self, args) -> Dict[str, Any]:
        """Execute using legacy plugin manager."""
        self.logger.info("🎯 Executing legacy strategy")

        if not LEGACY_PLUGIN_MANAGER_AVAILABLE:
            raise RuntimeError("Legacy plugin manager not available")

        # Initialize legacy manager if needed
        if not self._legacy_plugin_manager:
            self._legacy_plugin_manager = PluginManager()

        # Execute using legacy interface
        apk_ctx = self._create_apk_context(args)
        plugins = self._get_plugins_for_execution(args)

        return self._legacy_plugin_manager.execute_plugins(plugins, apk_ctx)

    def _create_apk_context(self, args) -> Any:
        """Create APK context from arguments."""
        if not APK_CONTEXT_AVAILABLE:
            # Return minimal context if APKContext not available
            return type(
                "APKContext",
                (),
                {"apk_path": getattr(args, "apk", ""), "package_name": getattr(args, "package_name", ""), "args": args},
            )()

        apk_path = getattr(args, "apk", "")
        if apk_path:
            ctx = APKContext(apk_path)
            try:
                ExecutionPathGuard.get_guard().record_in_context(ctx)
                ExecutionPathGuard.get_guard().write_run_manifest(ctx)
            except Exception:
                pass
            return ctx

        # Create minimal context
        return APKContext.create_minimal_context(args)

    def _get_plugins_for_execution(self, args) -> List[Any]:
        """
        Get list of plugins to execute based on arguments.

        Uses UnifiedPluginManager for real plugin discovery with scan profile filtering.
        Implements fail-fast when 0 plugins discovered to prevent silent no-op.

        Args:
            args: Command line arguments (may contain profile, plugin filters, etc.)

        Returns:
            List of plugin metadata objects for execution

        Raises:
            RuntimeError: When 0 plugins discovered and no fallback available
        """
        if not UNIFIED_PLUGIN_MANAGER_AVAILABLE:
            self.logger.warning("⚠️ UnifiedPluginManager not available - cannot discover plugins")
            # Fail-fast: raise error instead of silently returning empty list
            raise RuntimeError(
                "Canonical orchestration requires UnifiedPluginManager. "
                "Either install required dependencies or use a different orchestration strategy."
            )

        try:
            # Create plugin manager and discover plugins
            plugin_manager = UnifiedPluginManager()
            plugin_count = plugin_manager.discover_plugins()

            self.logger.info(f"🔍 Plugin discovery: {plugin_count} plugins found")

            # Get all discovered plugins
            plugins = list(plugin_manager.plugins.values())

            # Apply scan profile filtering if specified
            scan_profile = getattr(args, "profile", None) or getattr(args, "scan_profile", None)
            if scan_profile:
                try:
                    from ..scan_profiles import ScanProfile

                    # Map string to enum if needed
                    if isinstance(scan_profile, str):
                        profile_map = {
                            "lightning": ScanProfile.LIGHTNING,
                            "fast": ScanProfile.FAST,
                            "standard": ScanProfile.STANDARD,
                            "deep": ScanProfile.DEEP,
                        }
                        scan_profile = profile_map.get(scan_profile.lower(), ScanProfile.STANDARD)

                    plugin_manager.set_scan_profile(scan_profile)
                    # Refresh plugins after profile application
                    plugins = list(plugin_manager.plugins.values())
                    self.logger.info(f"📋 Applied scan profile '{scan_profile}': {len(plugins)} plugins selected")
                except Exception as e:
                    self.logger.warning(f"⚠️ Failed to apply scan profile: {e}")

            # Fail-fast: prevent silent no-op when 0 plugins discovered
            if not plugins:
                error_msg = (
                    "Canonical orchestration discovered 0 plugins. "
                    "This would result in a no-op scan. Check plugin directories and discovery configuration."
                )
                self.logger.error(f"❌ {error_msg}")
                raise RuntimeError(error_msg)

            self.logger.info(f"✅ Returning {len(plugins)} plugins for canonical execution")
            return plugins

        except RuntimeError:
            # Re-raise RuntimeError (our fail-fast errors)
            raise
        except Exception as e:
            self.logger.error(f"❌ Plugin discovery failed: {e}")
            raise RuntimeError(f"Canonical plugin discovery failed: {e}")

    def _apply_tenant_configuration(self, args, tenant_context: TenantContext):
        """Apply tenant-specific configuration to execution arguments."""
        if not self.boundary_manager:
            return args

        tenant_id = tenant_context.tenant_id
        config = self.boundary_manager.tenant_configs.get(tenant_id)

        if not config:
            return args

        # Apply resource limits
        quota = config.resource_quota

        # Set tenant-specific paths
        if hasattr(args, "output_dir"):
            args.output_dir = str(tenant_context.output_path)
        if hasattr(args, "temp_dir"):
            args.temp_dir = str(tenant_context.temp_path)
        if hasattr(args, "cache_dir"):
            args.cache_dir = str(tenant_context.cache_path)

        # Apply resource constraints
        if hasattr(args, "max_scan_time"):
            args.max_scan_time = min(
                getattr(args, "max_scan_time", quota.max_scan_duration_minutes * 60),
                quota.max_scan_duration_minutes * 60,
            )

        if hasattr(args, "max_memory"):
            args.max_memory = min(getattr(args, "max_memory", quota.max_memory_mb), quota.max_memory_mb)

        # Add tenant metadata
        args.tenant_id = tenant_id
        args.tenant_name = config.tenant_name
        args.isolation_level = config.isolation_level.value

        return args

    def _isolate_findings_for_tenant(self, findings: List, tenant_context: TenantContext) -> List:
        """Apply tenant isolation to findings."""
        if not self.boundary_manager or not tenant_context:
            return findings

        try:
            # Use boundary manager to isolate findings
            isolated_findings = self.boundary_manager.isolate_findings(tenant_context, findings)
            return isolated_findings
        except Exception as e:
            self.logger.warning(f"Failed to isolate findings for tenant {tenant_context.tenant_id}: {e}")
            return findings

    def _create_canonical_result(
        self,
        strategy: OrchestrationStrategy,
        execution_result: Dict[str, Any],
        execution_time: float,
        tenant_context: Optional[TenantContext] = None,
    ) -> CanonicalExecutionResult:
        """Create canonical result from execution result."""

        # Extract metrics from execution result
        total_plugins = execution_result.get("plugins_executed", 0)
        successful_plugins = execution_result.get("successful_plugins", 0)
        failed_plugins = total_plugins - successful_plugins
        vulnerabilities = execution_result.get("vulnerabilities_found", 0)

        # Extract performance metrics
        performance_metrics = execution_result.get("performance_metrics", {})
        performance_metrics.update(
            {"execution_time": execution_time, "strategy_used": strategy.value, "timestamp": time.time()}
        )

        return CanonicalExecutionResult(
            strategy_used=strategy,
            execution_time=execution_time,
            total_plugins_executed=total_plugins,
            successful_plugins=successful_plugins,
            failed_plugins=failed_plugins,
            vulnerabilities_found=vulnerabilities,
            analysis_results=execution_result,
            performance_metrics=performance_metrics,
            success=execution_result.get("success", False),
        )

    def _update_performance_metrics(self, result: CanonicalExecutionResult):
        """Update internal performance metrics."""
        self._performance_metrics["total_executions"] += 1

        if result.success:
            self._performance_metrics["successful_executions"] += 1

        # Update average execution time
        total_time = (
            self._performance_metrics["average_execution_time"] * (self._performance_metrics["total_executions"] - 1)
            + result.execution_time
        )
        self._performance_metrics["average_execution_time"] = total_time / self._performance_metrics["total_executions"]

        # Update strategy usage
        strategy_name = result.strategy_used.value
        if strategy_name not in self._performance_metrics["strategy_usage"]:
            self._performance_metrics["strategy_usage"][strategy_name] = 0
        self._performance_metrics["strategy_usage"][strategy_name] += 1

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics."""
        return self._performance_metrics.copy()

    def get_execution_history(self) -> List[CanonicalExecutionResult]:
        """Get execution history."""
        return self._execution_history.copy()

    def get_configuration_value(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value from unified configuration system.

        Args:
            key: Configuration key (e.g., 'execution.max_workers', 'ml.enhancement_level')
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        if self.unified_config_manager:
            try:
                return self.unified_config_manager.get_configuration_value(key, default)
            except Exception as e:
                self.logger.warning(f"Failed to get config value '{key}': {e}")

        return default

    def update_configuration(self, updates: Dict[str, Any]) -> bool:
        """
        Update configuration values in unified system.

        Args:
            updates: Dictionary of configuration updates

        Returns:
            True if successful, False otherwise
        """
        if self.unified_config_manager:
            try:
                for key, value in updates.items():
                    self.unified_config_manager.set_configuration_value(key, value)
                self.logger.info(f"Updated {len(updates)} configuration values")
                return True
            except Exception as e:
                self.logger.error(f"Failed to update configuration: {e}")

        return False

    def set_orchestration_strategy(self, strategy: OrchestrationStrategy):
        """Set orchestration strategy."""
        self.config.strategy = strategy
        self.logger.info(f"Orchestration strategy set to: {strategy.value}")


# Backward compatibility functions
def create_canonical_orchestrator(config: Optional[Dict[str, Any]] = None) -> CanonicalOrchestrator:
    """Create canonical orchestrator with optional configuration."""
    if config:
        canonical_config = CanonicalExecutionConfig(**config)
    else:
        canonical_config = CanonicalExecutionConfig()

    return CanonicalOrchestrator(canonical_config)


def execute_canonical_analysis(args) -> CanonicalExecutionResult:
    """Execute canonical analysis (convenience function)."""
    orchestrator = create_canonical_orchestrator()
    return orchestrator.execute_comprehensive_analysis(args)


# Check component availability
try:
    from .unified_manager import UnifiedExecutionManager  # noqa: F811

    UNIFIED_EXECUTION_AVAILABLE = True
except ImportError:
    UNIFIED_EXECUTION_AVAILABLE = False

# Export main interface
__all__ = [
    "CanonicalOrchestrator",
    "CanonicalExecutionConfig",
    "CanonicalExecutionResult",
    "OrchestrationStrategy",
    "create_canonical_orchestrator",
    "execute_canonical_analysis",
]
