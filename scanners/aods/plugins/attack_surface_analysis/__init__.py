"""
Attack Surface Analysis Plugin Module

This module provides full attack surface analysis for Android applications
with modular architecture, evidence-based confidence calculation, and scalable
security assessment capabilities.
"""

import logging

logger = logging.getLogger(__name__)

# Interface migration flag - StandardizedVulnerability interface not yet implemented
# Setting to False prevents NameError when checking migration availability
INTERFACE_MIGRATION_AVAILABLE = False


from .data_structures import (  # noqa: E402
    AttackSurfaceVulnerability,
    AttackVector,
    ComponentSurface,
    AttackSurfaceAnalysis,
    AnalysisContext,
    ComponentType,
    SeverityLevel,
    ExposureLevel,
    AttackComplexity,
    PermissionLevel,
    PatternType,
)

from .confidence_calculator import AttackSurfaceConfidenceCalculator, calculate_attack_surface_confidence  # noqa: E402

from .manifest_analyzer import ManifestAnalyzer  # noqa: E402

from .plugin import AttackSurfaceAnalysisPlugin, create_attack_surface_plugin  # noqa: E402

__version__ = "2.0.0"
__author__ = "AODS Security Team"

__all__ = [
    # Main plugin class
    "AttackSurfaceAnalysisPlugin",
    # Data structures
    "AttackSurfaceVulnerability",
    "AttackVector",
    "ComponentSurface",
    "AttackSurfaceAnalysis",
    "AnalysisContext",
    # Enums
    "ComponentType",
    "SeverityLevel",
    "ExposureLevel",
    "AttackComplexity",
    "PermissionLevel",
    "PatternType",
    # Analyzers
    "AttackSurfaceConfidenceCalculator",
    "ManifestAnalyzer",
    # Factory functions
    "create_attack_surface_plugin",
    "calculate_attack_surface_confidence",
]


class AttackSurfaceAnalyzer:
    """Attack Surface Analyzer for AODS integration."""

    def __init__(self, apk_ctx):
        """Initialize the attack surface analyzer."""
        self.apk_ctx = apk_ctx

    def analyze(self):
        """Perform attack surface analysis."""
        # Import the correct data structure class
        from .data_structures import AttackSurfaceAnalysis, AttackVector, ComponentSurface  # noqa: F401

        # Create properly structured result with all required fields
        # This is a placeholder implementation that can be enhanced later
        try:
            result = AttackSurfaceAnalysis(
                total_components=0,
                exported_components=0,
                high_risk_components=0,
                attack_vectors=[],
                component_surfaces=[],
                ipc_channels={},
                deep_link_schemes=set(),
                permission_boundaries={},
                overall_risk_score=0,
                attack_complexity="unknown",
            )
            return result
        except Exception as e:
            # Graceful error handling - return a structured error instead of crashing
            logger.error(f"Failed to create AttackSurfaceAnalysis result: {e}")
            # Return a minimal result structure that won't break the plugin system
            return {
                "error": f"AttackSurfaceAnalysis initialization failed: {e}",
                "analyzer": "attack_surface_analysis",
                "version": "1.0.0",
                "status": "failed",
            }


# Plugin compatibility functions


def run(apk_ctx):
    """Run attack surface analysis.

    NOTE: This plugin is currently a placeholder implementation.
    It returns a warning instead of falsely reporting "No issues found".
    """
    try:
        from rich.text import Text

        # Check if we have a real implementation or just placeholder
        analyzer = AttackSurfaceAnalyzer(apk_ctx)
        result = analyzer.analyze()

        # Check if the result is a real analysis or placeholder zeros
        is_placeholder = (
            hasattr(result, "total_components")
            and result.total_components == 0
            and hasattr(result, "attack_vectors")
            and len(result.attack_vectors) == 0
        )

        if is_placeholder:
            # Return warning instead of false "No issues found"
            warning_text = Text()
            warning_text.append("⚠️ Attack Surface Analysis: ", style="yellow bold")
            warning_text.append("Not yet implemented\n", style="yellow")
            warning_text.append("This plugin is a placeholder. ", style="dim")
            warning_text.append("No actual analysis was performed.\n", style="dim")
            return "Attack Surface Analysis", warning_text

        if hasattr(result, "findings") and result.findings:
            findings_text = Text(f"Attack Surface Analysis - {len(result.findings)} findings\n", style="bold blue")
            for finding in result.findings[:10]:
                findings_text.append(f"• {finding.title}\n", style="yellow")
        else:
            findings_text = Text("Attack Surface Analysis completed - No issues found", style="green")

        return "Attack Surface Analysis", findings_text
    except Exception as e:
        error_text = Text(f"Attack Surface Analysis Error: {str(e)}", style="red")
        return "Attack Surface Analysis", error_text


def run_plugin(apk_ctx):
    return run(apk_ctx)


def migrate_to_standardized_vulnerabilities(attack_surface_vulnerabilities: list) -> list:
    """
    Migrate AttackSurfaceVulnerability instances to StandardizedVulnerability.

    This function provides interface standardization for the attack surface analysis
    plugin, ensuring compatibility with the unified AODS vulnerability interface
    while maintaining backward compatibility.

    Args:
        attack_surface_vulnerabilities: List of AttackSurfaceVulnerability instances

    Returns:
        List of StandardizedVulnerability instances (or original if migration unavailable)
    """
    if not INTERFACE_MIGRATION_AVAILABLE:
        logger.warning("Interface migration not available, returning original vulnerabilities")
        return attack_surface_vulnerabilities

    try:
        # Filter and migrate only AttackSurfaceVulnerability instances
        attack_surface_vulns = [v for v in attack_surface_vulnerabilities if isinstance(v, AttackSurfaceVulnerability)]
        other_vulns = [v for v in attack_surface_vulnerabilities if not isinstance(v, AttackSurfaceVulnerability)]

        if attack_surface_vulns:
            standardized_vulns = migrate_attack_surface_vulnerabilities(attack_surface_vulns)  # noqa: F821
            logger.info(
                f"Migrated {len(standardized_vulns)} AttackSurfaceVulnerability instances to StandardizedVulnerability"
            )

            # Combine standardized and other vulnerabilities
            return standardized_vulns + other_vulns
        else:
            return attack_surface_vulnerabilities

    except Exception as e:
        logger.error(f"Failed to migrate AttackSurfaceVulnerability instances: {e}")
        return attack_surface_vulnerabilities


def get_standardized_vulnerability_interface():
    """
    Get information about the standardized vulnerability interface support.

    Returns:
        Dictionary with interface standardization information
    """
    return {
        "migration_available": INTERFACE_MIGRATION_AVAILABLE,
        "source_interface": "AttackSurfaceVulnerability",
        "target_interface": "StandardizedVulnerability",
        "backward_compatible": True,
        "migration_adapter": "AttackSurfaceVulnerabilityMigrationAdapter",
        "plugin_name": "attack_surface_analysis",
    }


__all__.extend(
    ["run", "run_plugin", "migrate_to_standardized_vulnerabilities", "get_standardized_vulnerability_interface"]
)

# BasePluginV2 interface
try:
    from .v2_plugin import AttackSurfaceAnalysisV2, create_plugin  # noqa: F401

    Plugin = AttackSurfaceAnalysisV2
except ImportError:
    pass
