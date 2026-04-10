"""
Token Replay Analysis Plugin Module

This module provides full token security analysis for Android applications
with modular architecture, professional confidence calculation, and reliable
token vulnerability detection capabilities.
"""

from .data_structures import (
    TokenInfo,
    JWTAnalysis,
    SessionAnalysis,
    TokenReplayVulnerability,
    TokenExpiryIssue,
    WeakTokenIssue,
    TokenSecurityAnalysisResult,
    TokenAnalysisContext,
    TokenType,
    TokenStrength,
    TokenVulnerabilityType,
    SessionSecurityLevel,
    JWTVulnerabilityType,
    TokenPatterns,
    MAVSAuthControls,
    CWEAuthCategories,
    TokenWeaknessPatterns,
)

from .confidence_calculator import TokenSecurityConfidenceCalculator, calculate_token_security_confidence

__version__ = "2.0.0"
__author__ = "AODS Security Team"

__all__ = [
    # Data structures
    "TokenInfo",
    "JWTAnalysis",
    "SessionAnalysis",
    "TokenReplayVulnerability",
    "TokenExpiryIssue",
    "WeakTokenIssue",
    "TokenSecurityAnalysisResult",
    "TokenAnalysisContext",
    # Enums
    "TokenType",
    "TokenStrength",
    "TokenVulnerabilityType",
    "SessionSecurityLevel",
    "JWTVulnerabilityType",
    "TokenPatterns",
    "MAVSAuthControls",
    "CWEAuthCategories",
    "TokenWeaknessPatterns",
    # Analyzers
    "TokenSecurityConfidenceCalculator",
    # Utility functions
    "calculate_token_security_confidence",
]

# Plugin compatibility functions


def run(apk_ctx):
    """Main plugin entry point for compatibility with plugin manager."""
    try:
        from rich.text import Text
        from .v2_plugin import TokenReplayAnalysisV2

        plugin = TokenReplayAnalysisV2()
        result = plugin.execute(apk_ctx)

        findings = getattr(result, "findings", []) if result else []
        if findings:
            findings_text = Text()
            findings_text.append(f"Token Replay Analysis - {len(findings)} findings\n", style="bold blue")
            for finding in findings[:10]:
                title = getattr(finding, "title", str(finding))
                findings_text.append(f"• {title}\n", style="yellow")
        else:
            findings_text = Text("Token Replay Analysis completed - No issues found", style="green")

        return "Token Replay Analysis", findings_text
    except Exception as e:
        from rich.text import Text

        error_text = Text(f"Token Replay Analysis Error: {str(e)}", style="red")
        return "Token Replay Analysis", error_text


def run_plugin(apk_ctx):
    return run(apk_ctx)


__all__.extend(["run", "run_plugin"])

# BasePluginV2 interface
try:
    from .v2_plugin import TokenReplayAnalysisV2, create_plugin  # noqa: F401

    Plugin = TokenReplayAnalysisV2
except ImportError:
    pass
