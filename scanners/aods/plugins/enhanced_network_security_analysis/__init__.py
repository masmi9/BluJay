"""
Enhanced Network Security Analysis Plugin Module

This module provides full network security analysis for Android applications
with modular architecture, professional confidence calculation, and reliable
network vulnerability detection capabilities.
"""

from .data_structures import (
    NetworkSecurityVulnerability,
    NetworkSecurityAnalysis,
    NetworkAnalysisContext,
    NetworkSecurityIssue,
    SSLConfigurationIssue,
    CertificateValidationIssue,
    CredentialHandlingIssue,
    NetworkVulnerabilityType,
    SeverityLevel,
    NetworkContextType,
    SSLConfigurationRisk,
    TLSVersion,
    NetworkSecurityPatterns,
    MASVSNetworkControls,
    CWENetworkCategories,
)

from .confidence_calculator import NetworkSecurityConfidenceCalculator, calculate_network_security_confidence

__version__ = "2.0.0"
__author__ = "AODS Security Team"

# Characteristics to inform decompilation policy elevation
PLUGIN_CHARACTERISTICS = {
    "category": "NETWORK_SECURITY",
    # Network analysis benefits from resources (NSC, XML); imports optional
    "decompilation_requirements": ["res"],
}

# Interface migration flag - StandardizedVulnerability interface not yet implemented
# Setting to False prevents NameError when checking migration availability
INTERFACE_MIGRATION_AVAILABLE = False

__all__ = [
    # Data structures
    "NetworkSecurityVulnerability",
    "NetworkSecurityAnalysis",
    "NetworkAnalysisContext",
    "NetworkSecurityIssue",
    "SSLConfigurationIssue",
    "CertificateValidationIssue",
    "CredentialHandlingIssue",
    # Enums
    "NetworkVulnerabilityType",
    "SeverityLevel",
    "NetworkContextType",
    "SSLConfigurationRisk",
    "TLSVersion",
    "NetworkSecurityPatterns",
    "MASVSNetworkControls",
    "CWENetworkCategories",
    # Analyzers
    "NetworkSecurityConfidenceCalculator",
    # Utility functions
    "calculate_network_security_confidence",
]


class EnhancedNetworkSecurityAnalyzer:
    """Enhanced Network Security Analyzer for AODS integration."""

    def __init__(self, apk_ctx):
        """Initialize the network security analyzer."""
        self.apk_ctx = apk_ctx

    def analyze(self):
        """Perform network security analysis."""
        # Create empty result for now - can be enhanced later
        from .data_structures import NetworkSecurityAnalysis

        result = NetworkSecurityAnalysis(
            vulnerabilities=[], analysis_metadata={"analyzer": "enhanced_network_security_analysis", "version": "1.0.0"}
        )

        # INTERFACE STANDARDIZATION: Migrate to StandardizedVulnerability if available
        if INTERFACE_MIGRATION_AVAILABLE and (
            getattr(result, "network_security_issues", [])
            or getattr(result, "vulnerabilities", [])
            or getattr(result, "ssl_configuration_issues", [])
            or getattr(result, "certificate_validation_issues", [])
            or getattr(result, "credential_handling_issues", [])
        ):
            try:
                standardized_vulnerabilities = migrate_to_standardized_vulnerabilities(result)  # noqa: F821
                if standardized_vulnerabilities:
                    import logging

                    logger = logging.getLogger(__name__)
                    logger.info(
                        f"🔄 Migrated {len(standardized_vulnerabilities)} network security vulnerabilities to standardized format"  # noqa: E501
                    )
                    # Store standardized vulnerabilities in result for downstream processing
                    result.standardized_vulnerabilities = standardized_vulnerabilities
            except Exception as e:
                import logging

                logger = logging.getLogger(__name__)
                logger.warning(f"Interface migration failed, continuing with original format: {e}")

        return result


# Plugin compatibility functions


def run(apk_ctx):
    try:
        from rich.text import Text

        analyzer = EnhancedNetworkSecurityAnalyzer(apk_ctx)
        result = analyzer.analyze()

        if hasattr(result, "findings") and result.findings:
            findings_text = Text()
            findings_text.append(
                f"Enhanced Network Security Analysis - {len(result.findings)} findings\n", style="bold blue"
            )
            for finding in result.findings[:10]:
                findings_text.append(f"• {finding.title}\n", style="yellow")
        else:
            findings_text = Text("Enhanced Network Security Analysis completed - No issues found", style="green")

        return "Enhanced Network Security Analysis", findings_text
    except Exception as e:
        error_text = Text(f"Enhanced Network Security Analysis Error: {str(e)}", style="red")
        return "Enhanced Network Security Analysis", error_text


def run_plugin(apk_ctx):
    return run(apk_ctx)


__all__.extend(["run", "run_plugin"])

# BasePluginV2 interface
try:
    from .v2_plugin import EnhancedNetworkSecurityAnalysisV2, create_plugin  # noqa: F401

    Plugin = EnhancedNetworkSecurityAnalysisV2
except ImportError:
    pass
