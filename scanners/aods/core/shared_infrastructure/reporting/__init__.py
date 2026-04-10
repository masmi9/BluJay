#!/usr/bin/env python3
"""
AODS Unified Reporting Framework

Full reporting framework supporting multiple output formats (JSON, HTML, PDF, XML)
with standardized templates, generators, and formatting utilities.

Features:
- Multiple format support (JSON, HTML, PDF, XML)
- Template-based report generation
- Standardized report structures
- Rich formatting and styling
- Interactive elements support
- Performance-optimized generation
- Plugin-specific report customization
- Executive summary generation
- Compliance reporting support
- Export and sharing capabilities

This framework provides unified reporting capabilities for all AODS components,
ensuring consistent, professional, and security analysis reports.
"""

# Core report structures and types
from .data_structures import (  # noqa: F401
    ReportFormat,
    ReportType,
    ReportSection,
    ReportMetadata,
    SecurityFinding,
    ReportConfiguration,
    ReportTemplate,
    ReportContext,
    DynamicCoordinationAnalysisResult,
    ComponentAnalysisResult,
    RuntimePatternResult,
    CorrelationAnalysisResult,
)

# Format-specific generators
from .formatters import JSONFormatter, HTMLFormatter, PDFFormatter, XMLFormatter, MarkdownFormatter

# Report generation orchestration
from .generators import (  # noqa: F401
    ReportGenerator,
    ExecutiveSummaryGenerator,
    TechnicalReportGenerator,
    ComplianceReportGenerator,
    CustomReportGenerator,
    DynamicCoordinationReportGenerator,
)

# Template management - temporarily disabled
# from .templates import (
#     TemplateManager,
#     DefaultTemplates,
#     CustomTemplateLoader,
#     TemplateRenderer
# )

# Report utilities - temporarily disabled
# from .utilities import (
#     ReportValidator,
#     ReportMerger,
#     ReportExporter,
#     ReportMetrics,
#     ChartGenerator,
#     TableGenerator
# )

# Main report orchestrator
from .report_orchestrator import UnifiedReportOrchestrator

# Unified reporting facade - PHASE 4 CONSOLIDATION
from .unified_facade import (
    UnifiedReportingManager,
    UnifiedReportConfig,
    ReportQuality,
    create_report_manager,
    generate_security_report,
)

# Export all public interfaces
__all__ = [
    # Core data structures
    "ReportFormat",
    "ReportType",
    "ReportSection",
    "ReportMetadata",
    "SecurityFinding",
    "ReportConfiguration",
    "ReportTemplate",
    "ReportContext",
    # Formatters
    "JSONFormatter",
    "HTMLFormatter",
    "PDFFormatter",
    "XMLFormatter",
    "MarkdownFormatter",
    # Generators
    "ReportGenerator",
    "ExecutiveSummaryGenerator",
    "TechnicalReportGenerator",
    "ComplianceReportGenerator",
    "CustomReportGenerator",
    # Template system - temporarily disabled
    # 'TemplateManager',
    # 'DefaultTemplates',
    # 'CustomTemplateLoader',
    # 'TemplateRenderer',
    # Utilities - temporarily disabled
    # 'ReportValidator',
    # 'ReportMerger',
    # 'ReportExporter',
    # 'ReportMetrics',
    # 'ChartGenerator',
    # 'TableGenerator',
    # Main orchestrator
    "UnifiedReportOrchestrator",
    # Unified reporting facade (Phase 4 consolidation)
    "UnifiedReportingManager",
    "UnifiedReportConfig",
    "ReportQuality",
    "create_report_manager",
    "generate_security_report",
]

# Package metadata
__version__ = "2.0.0"
__author__ = "AODS Development Team"
__description__ = "Unified reporting framework with multi-format support"
__category__ = "SHARED_INFRASTRUCTURE"

# Convenience functions for easy access - ENHANCED WITH PHASE 4 CONSOLIDATION


def create_report_generator(format_type: str = "json", **kwargs):
    """
    Create a unified report manager for full reporting.

    ENHANCED IN PHASE 4: Now returns UnifiedReportingManager with full capabilities

    Args:
        format_type: Primary output format (json, html, pdf, xml, markdown)
        **kwargs: Additional configuration parameters

    Returns:
        UnifiedReportingManager: Full reporting manager
    """
    # Convert format to ReportFormat enum
    try:
        from .data_structures import ReportFormat

        primary_format = ReportFormat(format_type.upper())

        # Create configuration with specified format
        config = UnifiedReportConfig(output_formats=[primary_format], **kwargs)
        return UnifiedReportingManager(config)
    except (ValueError, AttributeError):
        # Fallback to default configuration
        return create_report_manager(kwargs)


def create_legacy_report_generator(format_type: str = "json", **kwargs):
    """
    LEGACY FUNCTION: Create a report generator using legacy orchestrator.

    ⚠️ DEPRECATED: Use create_report_manager() for enhanced capabilities
    """
    import warnings

    warnings.warn(
        "create_legacy_report_generator is deprecated. Use create_report_manager() for enhanced reporting capabilities.",  # noqa: E501
        DeprecationWarning,
        stacklevel=2,
    )
    orchestrator = UnifiedReportOrchestrator()
    return orchestrator.create_generator(format_type, **kwargs)


def generate_executive_summary(analysis_results: dict, **kwargs) -> dict:
    """
    Generate an executive summary report using unified reporting system.

    ENHANCED IN PHASE 4: Now uses UnifiedReportingManager for superior quality

    Args:
        analysis_results: Complete analysis results
        **kwargs: Additional configuration

    Returns:
        dict: Executive summary report
    """
    findings = analysis_results.get("findings", [])
    metadata = {k: v for k, v in analysis_results.items() if k != "findings"}

    # Create unified manager with executive configuration
    manager = create_report_manager(
        {
            "quality_level": "executive",
            "include_technical_details": False,
            "include_charts": True,
            "include_risk_dashboard": True,
            **kwargs,
        }
    )

    return manager.generate_executive_summary(findings, metadata=metadata)


def generate_compliance_report(findings: list, framework: str = "OWASP", **kwargs) -> dict:
    """
    Generate a compliance framework report using unified reporting system.

    ENHANCED IN PHASE 4: Now uses UnifiedReportingManager with full compliance features

    Args:
        findings: List of security findings
        framework: Compliance framework (OWASP, NIST, etc.)
        **kwargs: Additional configuration

    Returns:
        dict: Compliance report
    """
    # Create unified manager with compliance configuration
    manager = create_report_manager(
        {
            "quality_level": "compliance",
            "include_compliance_section": True,
            "include_remediation_guidance": True,
            **kwargs,
        }
    )

    return manager.generate_compliance_report(findings, framework=framework)


# Available formatters registry
AVAILABLE_FORMATTERS = {
    "json": JSONFormatter,
    "html": HTMLFormatter,
    "pdf": PDFFormatter,
    "xml": XMLFormatter,
    "markdown": MarkdownFormatter,
}

# Available report types
AVAILABLE_REPORT_TYPES = {
    "security": "Security analysis report",
    "executive": "Executive summary report",
    "technical": "Detailed technical analysis report",
    "compliance": "Compliance framework assessment report",
    "custom": "Custom report with user-defined structure",
}


def get_supported_formats() -> list:
    """Get list of supported output formats."""
    return list(AVAILABLE_FORMATTERS.keys())


def get_supported_report_types() -> dict:
    """Get dictionary of supported report types."""
    return AVAILABLE_REPORT_TYPES.copy()


# Canonical factory functions for AODS_CANONICAL execution path


def create_unified_reporting_manager(config=None):
    """
    Canonical factory function for creating unified reporting manager.

    This function provides the canonical interface expected by the AODS_CANONICAL
    execution path while delegating to the existing unified reporting system.

    Args:
        config: Optional configuration object or dictionary

    Returns:
        UnifiedReportingManager: Configured reporting manager
    """
    from .unified_facade import create_report_manager

    # Handle dataclass configuration objects (fix for UnboundLocalError)
    if config and hasattr(config, "__dataclass_fields__"):
        # Convert dataclass to dictionary with proper Enum handling
        from dataclasses import asdict
        from enum import Enum

        def fix_enum_values(obj):
            """Convert Enum objects to their values recursively."""
            if isinstance(obj, Enum):
                return obj.value
            elif isinstance(obj, dict):
                return {key: fix_enum_values(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [fix_enum_values(item) for item in obj]
            return obj

        config_dict = fix_enum_values(asdict(config))
        return create_report_manager(config_dict)

    return create_report_manager(config)
