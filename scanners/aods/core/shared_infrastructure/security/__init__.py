#!/usr/bin/env python3
"""
AODS Unified Security Framework

Security management system providing:
- Unified security analysis and vulnerability detection
- Advanced cryptographic security assessment
- Enterprise authentication and authorization
- Threat intelligence and risk scoring
- Secret detection and management
- Multi-tenant security isolation

Features:
- Maximum vulnerability detection (zero false negatives)
- Advanced cryptographic analysis with algorithm strength assessment
- Strong authentication (LDAP, SAML, OAuth, MFA)
- Real-time threat intelligence feeds and IOC matching
- Full secret detection and secure management
- Multi-tenant security isolation and data separation
- Performance-optimized analysis with intelligent caching
- Zero security regressions during consolidation

This framework consolidates ALL AODS security capabilities into a unified,
high-performance, and reliability-focused security management system.
"""

# Unified security facade - PHASE 6 CONSOLIDATION + PHASE 9 WEBVIEW INTEGRATION
from .unified_facade import (
    UnifiedSecurityManager,
    UnifiedSecurityOptions,
    SecurityScope,
    SecurityPolicy,
    create_security_manager,
    perform_security_analysis,
)

# Security analysis components
from .security_analyzers import (
    UnifiedSecurityAnalyzer,
    SecurityAnalysisConfig,
    SecurityFinding,
    ThreatSeverity,
    VulnerabilityCategory,
    AnalysisContext,
)

# WebView security analysis components - PHASE 9 INTEGRATION
from .webview_security_analyzer import (
    WebViewSecurityAnalyzer,
    WebViewSecurityConfig,
    WebViewSecurityFinding,
    WebViewAnalysisResult,
    WebViewVulnerabilityType,
    WebViewSettingsSeverity,
    create_webview_security_analyzer,
    analyze_webview_security,
)

# AI/ML security analysis components - PHASE 10 INTEGRATION
from .ml_security_analyzer import (
    MLSecurityAnalyzer,
    MLSecurityConfig,
    MLSecurityFinding,
    MLAnalysisResult,
    MLModelType,
    MLAnalysisType,
    MLConfidenceLevel,
    MLFeatures,
    MLPrediction,
    create_ml_security_analyzer,
    analyze_ml_security,
)

# Cryptographic analysis: REMOVED - UnifiedCryptoAnalyzer was dead code (never called during scans).
# Active crypto analysis lives in core/execution/crypto/ (strategy pattern).

# Authentication and authorization components
from .authentication_manager import (
    UnifiedAuthenticationManager,
    AuthenticationConfig,
    AuthenticationResult,
    UserSession,
    AuthenticationMethod,
    UserRole,
)

# Threat intelligence components
from .threat_intelligence import (
    UnifiedThreatIntelligence,
    ThreatIntelligenceConfig,
    ThreatIndicator,
    ThreatLevel,
    IOCType,
    ThreatContext,
)

# Secret management components
from .secret_management import (
    UnifiedSecretManager,
    SecretManagementConfig,
    SecretFinding,
    SecretType,
    SecretSeverity,
    SecretContext,
)

# Version information
__version__ = "1.0.0"
__author__ = "AODS Development Team"
__description__ = "Unified Security Framework for AODS Shared Infrastructure"

# Public API exports
__all__ = [
    # Unified Security Facade (Phase 6 consolidation)
    "UnifiedSecurityManager",
    "UnifiedSecurityOptions",
    "SecurityScope",
    "SecurityPolicy",
    "create_security_manager",
    "perform_security_analysis",
    # Security Analysis
    "UnifiedSecurityAnalyzer",
    "SecurityAnalysisConfig",
    "SecurityFinding",
    "ThreatSeverity",
    "VulnerabilityCategory",
    "AnalysisContext",
    # WebView Security Analysis (Phase 9 integration)
    "WebViewSecurityAnalyzer",
    "WebViewSecurityConfig",
    "WebViewSecurityFinding",
    "WebViewAnalysisResult",
    "WebViewVulnerabilityType",
    "WebViewSettingsSeverity",
    "create_webview_security_analyzer",
    "analyze_webview_security",
    # AI/ML Security Analysis (Phase 10 integration)
    "MLSecurityAnalyzer",
    "MLSecurityConfig",
    "MLSecurityFinding",
    "MLAnalysisResult",
    "MLModelType",
    "MLAnalysisType",
    "MLConfidenceLevel",
    "MLFeatures",
    "MLPrediction",
    "create_ml_security_analyzer",
    "analyze_ml_security",
    # Cryptographic Analysis - REMOVED (dead code, see core/execution/crypto/)
    # Authentication & Authorization
    "UnifiedAuthenticationManager",
    "AuthenticationConfig",
    "AuthenticationResult",
    "UserSession",
    "AuthenticationMethod",
    "UserRole",
    # Threat Intelligence
    "UnifiedThreatIntelligence",
    "ThreatIntelligenceConfig",
    "ThreatIndicator",
    "ThreatLevel",
    "IOCType",
    "ThreatContext",
    # Secret Management
    "UnifiedSecretManager",
    "SecretManagementConfig",
    "SecretFinding",
    "SecretType",
    "SecretSeverity",
    "SecretContext",
]

# Convenience functions for common operations


def quick_security_scan(target_path: str, **options) -> dict:
    """
    Quickly perform security scan with default settings.

    Args:
        target_path: Path to APK or source code to analyze
        **options: Additional security analysis options

    Returns:
        Security analysis results
    """
    manager = create_security_manager(options)
    return manager.perform_comprehensive_security_analysis(target_path)


def analyze_cryptography(target_path: str, **options) -> dict:
    """Stub - use core.execution.crypto for active crypto analysis."""
    return {"crypto_findings": []}


def detect_secrets(target_path: str, **options) -> dict:
    """
    Perform focused secret detection analysis.

    Args:
        target_path: Path to analyze for secrets
        **options: Secret detection options

    Returns:
        Secret detection results
    """
    config = {"enable_secret_detection": True, "enable_comprehensive_analysis": False}
    config.update(options)

    manager = create_security_manager(config)
    results = manager.perform_comprehensive_security_analysis(target_path)
    return {"secret_findings": results.get("secret_findings", [])}


# Package metadata
__category__ = "SHARED_INFRASTRUCTURE"
__status__ = "Production"
__maintainer__ = "AODS Security Team"
