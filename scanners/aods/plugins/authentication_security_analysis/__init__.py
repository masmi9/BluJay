"""
Authentication Security Analysis Plugin - Modular Implementation
Authentication and authorization security testing following MASTG guidelines.

This module orchestrates all authentication security analysis components:
- Biometric authentication analysis (MASTG-TEST-0018)
- Credential confirmation analysis (MASTG-TEST-0017)
- Session management security
- Hardcoded secrets detection
- Authentication bypass detection
- Android Keystore usage analysis
"""

import logging
from typing import List, Tuple, Union

from rich.text import Text

from core.apk_ctx import APKContext
from .data_structures import AuthenticationVulnerability, AuthenticationAnalysisResult

from .biometric_analyzer import BiometricAnalyzer
from .credential_analyzer import CredentialAnalyzer
from .session_analyzer import SessionAnalyzer
from .secrets_analyzer import SecretsAnalyzer
from .bypass_analyzer import BypassAnalyzer
from .keystore_analyzer import KeystoreAnalyzer
from .formatters import AuthenticationAnalysisFormatter

logger = logging.getLogger(__name__)

# Interface migration flag - StandardizedVulnerability interface not yet implemented
# Setting to False prevents NameError when checking migration availability
INTERFACE_MIGRATION_AVAILABLE = False


class AuthenticationSecurityAnalyzer:
    """
    Main authentication security analyzer that orchestrates all analysis components.

    This class provides a unified interface for authentication security
    analysis while maintaining clean separation of concerns through specialized analyzers.
    """

    def __init__(self):
        """Initialize all analysis components with dependency injection."""
        self.vulnerabilities = []

        # Initialize specialized analyzers
        self.biometric_analyzer = BiometricAnalyzer()
        self.credential_analyzer = CredentialAnalyzer()
        self.session_analyzer = SessionAnalyzer()
        self.secrets_analyzer = SecretsAnalyzer()
        self.bypass_analyzer = BypassAnalyzer()
        self.keystore_analyzer = KeystoreAnalyzer()

        # Initialize formatter
        self.formatter = AuthenticationAnalysisFormatter()

        logger.debug("Authentication security analyzer initialized with all components")

    def analyze_authentication_security(self, apk_ctx: APKContext) -> List[AuthenticationVulnerability]:
        """
        Main analysis method that coordinates all authentication security checks.

        Args:
            apk_ctx: APK context containing source files and metadata

        Returns:
            List of authentication vulnerabilities found
        """
        logger.debug("Starting authentication security analysis")

        self.vulnerabilities = []

        try:
            # Run all analysis components
            self.vulnerabilities.extend(self._analyze_biometric_implementation(apk_ctx))
            self.vulnerabilities.extend(self._analyze_credential_confirmation(apk_ctx))
            self.vulnerabilities.extend(self._analyze_session_management(apk_ctx))
            self.vulnerabilities.extend(self._analyze_hardcoded_secrets(apk_ctx))
            self.vulnerabilities.extend(self._analyze_authentication_bypass(apk_ctx))
            self.vulnerabilities.extend(self._analyze_keystore_usage(apk_ctx))

            logger.debug(f"Authentication analysis completed. Found {len(self.vulnerabilities)} vulnerabilities.")

            # INTERFACE STANDARDIZATION: Migrate to StandardizedVulnerability if available
            if INTERFACE_MIGRATION_AVAILABLE and self.vulnerabilities:
                try:
                    standardized_vulnerabilities = migrate_to_standardized_vulnerabilities(  # noqa: F821
                        self.vulnerabilities
                    )
                    if standardized_vulnerabilities:
                        logger.info(
                            f"🔄 Migrated {len(standardized_vulnerabilities)} authentication security vulnerabilities to standardized format"  # noqa: E501
                        )
                        # Store standardized vulnerabilities for downstream processing
                        self.standardized_vulnerabilities = standardized_vulnerabilities
                except Exception as e:
                    logger.warning(f"Interface migration failed, continuing with original format: {e}")

        except Exception as e:
            logger.error(f"Error during authentication security analysis: {e}")
            raise

        return self.vulnerabilities

    def _analyze_biometric_implementation(self, apk_ctx: APKContext) -> List[AuthenticationVulnerability]:
        """Analyze biometric authentication implementation (MASTG-TEST-0018)."""
        logger.debug("Analyzing biometric authentication implementation")
        try:
            return self.biometric_analyzer.analyze_biometric_implementation(apk_ctx)
        except Exception as e:
            logger.error(f"Error in biometric analysis: {e}")
            return []

    def _analyze_credential_confirmation(self, apk_ctx: APKContext) -> List[AuthenticationVulnerability]:
        """Analyze credential confirmation implementation (MASTG-TEST-0017)."""
        logger.debug("Analyzing credential confirmation mechanisms")
        try:
            return self.credential_analyzer.analyze_credential_confirmation(apk_ctx)
        except Exception as e:
            logger.error(f"Error in credential analysis: {e}")
            return []

    def _analyze_session_management(self, apk_ctx: APKContext) -> List[AuthenticationVulnerability]:
        """Analyze session management security."""
        logger.debug("Analyzing session management implementation")
        try:
            return self.session_analyzer.analyze_session_management(apk_ctx)
        except Exception as e:
            logger.error(f"Error in session analysis: {e}")
            return []

    def _analyze_hardcoded_secrets(self, apk_ctx: APKContext) -> List[AuthenticationVulnerability]:
        """Analyze hardcoded authentication secrets."""
        logger.debug("Analyzing hardcoded authentication secrets")
        try:
            return self.secrets_analyzer.analyze_hardcoded_secrets(apk_ctx)
        except Exception as e:
            logger.error(f"Error in secrets analysis: {e}")
            return []

    def _analyze_authentication_bypass(self, apk_ctx: APKContext) -> List[AuthenticationVulnerability]:
        """Analyze potential authentication bypass vulnerabilities."""
        logger.debug("Analyzing authentication bypass vulnerabilities")
        try:
            return self.bypass_analyzer.analyze_authentication_bypass(apk_ctx)
        except Exception as e:
            logger.error(f"Error in bypass analysis: {e}")
            return []

    def _analyze_keystore_usage(self, apk_ctx: APKContext) -> List[AuthenticationVulnerability]:
        """Analyze Android Keystore usage for authentication."""
        logger.debug("Analyzing Android Keystore usage")
        try:
            return self.keystore_analyzer.analyze_keystore_usage(apk_ctx)
        except Exception as e:
            logger.error(f"Error in keystore analysis: {e}")
            return []

    def get_analysis_summary(self, apk_ctx: APKContext, vulnerabilities=None) -> dict:
        """Get analysis summary with component details."""
        if vulnerabilities is None:
            vulnerabilities = self.analyze_authentication_security(apk_ctx)

        return {
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities_by_severity": {
                "critical": len([v for v in vulnerabilities if v.severity == "CRITICAL"]),
                "high": len([v for v in vulnerabilities if v.severity == "HIGH"]),
                "medium": len([v for v in vulnerabilities if v.severity == "MEDIUM"]),
                "low": len([v for v in vulnerabilities if v.severity == "LOW"]),
            },
            "component_analysis": {
                "biometric": {
                    "implemented": self.biometric_analyzer.has_biometric_implementation(apk_ctx),
                    "apis_used": self.biometric_analyzer.get_biometric_apis_used(apk_ctx),
                },
                "credential_confirmation": {
                    "implemented": self.credential_analyzer.has_credential_confirmation(apk_ctx),
                    "mechanisms": self.credential_analyzer.get_credential_mechanisms_used(apk_ctx),
                },
                "session_management": {
                    "implemented": self.session_analyzer.has_session_management(apk_ctx),
                    "storage_methods": self.session_analyzer.get_session_storage_methods(apk_ctx),
                },
                "hardcoded_secrets": {
                    "found": self.secrets_analyzer.has_hardcoded_secrets(apk_ctx),
                    "types": self.secrets_analyzer.get_secret_types_found(apk_ctx),
                },
                "authentication_bypass": {
                    "found": self.bypass_analyzer.has_authentication_bypass(apk_ctx),
                    "types": self.bypass_analyzer.get_bypass_types_found(apk_ctx),
                },
                "keystore_usage": {
                    "implemented": self.keystore_analyzer.has_keystore_usage(apk_ctx),
                    "security_score": self.keystore_analyzer.get_security_score(apk_ctx),
                },
            },
        }


def run(apk_ctx: APKContext) -> Tuple[str, Union[str, Text, Tuple[Text, dict]]]:
    """
    Main plugin execution function.

    Args:
        apk_ctx: APK context containing source files and metadata

    Returns:
        Tuple of (status, report) where status is "PASS"/"FAIL"/"ERROR"
        and report is a Rich Text object with detailed findings
    """
    try:
        # Initialize analyzer and run analysis
        analyzer = AuthenticationSecurityAnalyzer()
        vulnerabilities = analyzer.analyze_authentication_security(apk_ctx)

        # Format and return results with structured payload
        status, rich_text = analyzer.formatter.format_plugin_result(vulnerabilities)
        structured_payload = {
            "plugin": "authentication_security_analysis",
            "summary": analyzer.get_analysis_summary(apk_ctx, vulnerabilities=vulnerabilities),
            "standardized_vulnerabilities": getattr(analyzer, "standardized_vulnerabilities", []),
        }
        return status, (rich_text, structured_payload)

    except Exception as e:
        logger.error(f"Error in authentication security analysis: {e}")
        return "⚠️ ERROR", (Text(f"Analysis failed: {str(e)}", style="red"), {"error": str(e)})


def run_plugin(apk_ctx: APKContext) -> Tuple[str, Union[str, Text]]:
    """
    Plugin interface function expected by the plugin manager.

    Args:
        apk_ctx: The APKContext instance containing APK path and metadata

    Returns:
        Tuple[str, Union[str, Text]]: Plugin execution result
    """
    return run(apk_ctx)


# Export main classes for direct usage
__all__ = [
    "AuthenticationSecurityAnalyzer",
    "AuthenticationVulnerability",
    "AuthenticationAnalysisResult",
    "BiometricAnalyzer",
    "CredentialAnalyzer",
    "SessionAnalyzer",
    "SecretsAnalyzer",
    "BypassAnalyzer",
    "KeystoreAnalyzer",
    "AuthenticationAnalysisFormatter",
    "run",
    "run_plugin",
]

# BasePluginV2 interface
try:
    from .v2_plugin import AuthenticationSecurityAnalysisV2, create_plugin  # noqa: F401

    Plugin = AuthenticationSecurityAnalysisV2
except ImportError:
    pass
