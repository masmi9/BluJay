#!/usr/bin/env python3
"""
AODS Scan Profile Optimization System

Provides intelligent plugin selection based on scan goals to dramatically improve performance.
Reduces scan times from 15+ minutes to 30 seconds - 5 minutes based on profile selection.
"""

from enum import Enum
from typing import Dict, List, Set
from dataclasses import dataclass


class ScanProfile(Enum):
    """Predefined scan profiles optimized for different use cases."""

    LIGHTNING = "lightning"  # 30 seconds - Essential credential detection only
    FAST = "fast"  # 2-3 minutes - Common security issues
    STANDARD = "standard"  # 5-8 minutes - Security
    DEEP = "deep"  # 15+ minutes - All plugins (current behavior)
    CUSTOM = "custom"  # User-defined plugin selection


@dataclass
class ProfileConfiguration:
    """Configuration for a scan profile."""

    name: str
    description: str
    estimated_time: str
    plugin_count: int
    plugins: Set[str]
    priority_plugins: Set[str]  # Must-run plugins
    excluded_plugins: Set[str]  # Never run plugins


class ScanProfileManager:
    """Manages scan profile configurations and plugin selection optimization."""

    def __init__(self):
        self.profiles = self._initialize_profiles()

    def _initialize_profiles(self) -> Dict[ScanProfile, ProfileConfiguration]:
        """Initialize predefined scan profiles with optimized plugin selections."""

        profiles = {}

        # LIGHTNING Profile - DETECTION-FIRST fast analysis (30 seconds)
        profiles[ScanProfile.LIGHTNING] = ProfileConfiguration(
            name="Lightning",
            description="DETECTION-FIRST fast analysis with coordinated JADX+Enhanced Static Analysis - full vulnerability coverage with speed-optimized methods",  # noqa: E501
            estimated_time="60 seconds",
            plugin_count=12,
            plugins={
                # DETECTION-FIRST: Full credential & secret detection
                "insecure_data_storage",
                "cryptography_tests",
                "enhanced_data_storage_modular",
                "authentication_security_analysis",
                # DETECTION-FIRST: Coordinated static analysis (cycle-safe)
                "jadx_static_analysis",  # Re-enabled with 60s timeout & cycle prevention
                "enhanced_static_analysis",  # Full pattern detection (coordinates with JADX)
                # DETECTION-FIRST: Critical security analysis
                "enhanced_manifest_analysis",
                "apk_signing_certificate_analyzer",
                "network_cleartext_traffic",
                # DETECTION-FIRST: Additional vulnerability coverage
                "injection_vulnerabilities",  # SQL/Command injection detection
                "webview_security_analysis",  # WebView vulnerabilities
                # TLS/SSL security analysis (fast static-only subset in lightning)
                "advanced_ssl_tls_analyzer",
            },
            priority_plugins={
                "insecure_data_storage",
                "cryptography_tests",
                "jadx_static_analysis",  # High priority for source code analysis
                "enhanced_static_analysis",  # High priority for detection
            },
            excluded_plugins={
                "mastg_integration",  # Compliance reporting (not vulnerability detection)
                "nist_compliance_reporting",  # Compliance reporting (not vulnerability detection)
                "enhanced_encoding_cloud_analysis",  # Has AnalysisPattern import errors
                "dynamic_code_analyzer",  # Too detailed for Lightning mode
                "network_pii_traffic_analyzer",  # May cause hanging on large files
                "data_minimization_analyzer",  # May cause performance issues
                "enhanced_root_detection_bypass_analyzer",  # May cause hanging
                "improper_platform_usage",  # Overlaps with enhanced_manifest_analysis; keep in FAST+
                "examples",  # Demo/template plugin - not for production scans
            },
        )

        # FAST Profile - Common security issues (2-3 minutes)
        profiles[ScanProfile.FAST] = ProfileConfiguration(
            name="Fast",
            description="Common security vulnerabilities & essential analysis",
            estimated_time="2-3 minutes",
            plugin_count=18,
            plugins={
                # All lightning plugins
                "insecure_data_storage",
                "cryptography_tests",
                "enhanced_data_storage_modular",
                "authentication_security_analysis",
                "enhanced_manifest_analysis",
                "apk_signing_certificate_analyzer",
                "network_cleartext_traffic",
                "improper_platform_usage",
                # CRITICAL: JADX required for dynamic analysis
                "jadx_static_analysis",  # Essential for dynamic analysis - provides decompiled source
                "enhanced_static_analysis",  # Works with JADX for analysis
                # Additional common vulnerabilities
                "injection_vulnerabilities",
                "traversal_vulnerabilities",
                "webview_security_analysis",
                "privacy_leak_detection",
                "component_exploitation_plugin",
                "attack_surface_analysis",
                "enhanced_network_security_analysis",
                # Include SSL/TLS analyzer to maintain Lightning ⊆ Fast invariant
                "advanced_ssl_tls_analyzer",
            },
            priority_plugins={
                "insecure_data_storage",
                "cryptography_tests",
                "jadx_static_analysis",  # High priority - required for dynamic analysis
                "injection_vulnerabilities",
            },
            excluded_plugins={
                "mastg_integration",  # Compliance only
                "nist_compliance_reporting",  # Compliance only
                "examples",  # Demo/template plugin - not for production scans
            },
        )

        # STANDARD Profile - Security without slow analyzers (5-8 minutes)
        profiles[ScanProfile.STANDARD] = ProfileConfiguration(
            name="Standard",
            description="Security analysis with optimized performance",
            estimated_time="5-8 minutes",
            plugin_count=41,
            plugins={
                # All fast plugins plus additional analysis
                "insecure_data_storage",
                "cryptography_tests",
                "enhanced_data_storage_modular",
                "authentication_security_analysis",
                "enhanced_manifest_analysis",
                "apk_signing_certificate_analyzer",
                "network_cleartext_traffic",
                "improper_platform_usage",
                "injection_vulnerabilities",
                "traversal_vulnerabilities",
                "webview_security_analysis",
                "privacy_leak_detection",
                "component_exploitation_plugin",
                "attack_surface_analysis",
                "enhanced_network_security_analysis",
                # CRITICAL: JADX required for dynamic analysis
                "jadx_static_analysis",  # Essential for dynamic analysis - provides decompiled source
                "enhanced_static_analysis",  # Include but with timeouts
                "code_quality_injection_analysis",
                "privacy_controls_analysis",
                "anti_tampering_analysis",
                # NOTE: enhanced_root_detection_bypass_analyzer removed (Track 30 - Defect 4)
                # - overlaps with anti_tampering_analysis and insecure_data_storage root detection
                "frida_dynamic_analysis",
                "token_replay_analysis",
                "external_service_analysis",
                "runtime_decryption_analysis",
                # Include full SSL/TLS analyzer in standard profile
                "advanced_ssl_tls_analyzer",
                # Semgrep MASTG analysis for compliance coverage
                "semgrep_mastg_analyzer",
                # Privacy plugins (MASVS-PRIVACY-1 through MASVS-PRIVACY-4)
                "privacy_analyzer",
                "consent_analyzer",
                "data_minimization_analyzer",
                "tracking_analyzer",
                # Code & resilience plugins (MASVS-CODE-4 and MASVS-RESILIENCE-2)
                "dynamic_code_analyzer",
                "emulator_detection_analyzer",
                # Library CVE scanning (MASVS-CODE-2)
                "library_vulnerability_scanner",
                # Biometric authentication security (MASVS-AUTH)
                "biometric_security_analysis",
                # Unused security function detection (MASVS-AUTH/CODE - Track 113.4)
                "unused_security_function_analyzer",
                # Tapjacking / overlay attack detection (MASVS-PLATFORM-9 - Track 113.6)
                "tapjacking_analyzer",
                # Deep link / URL scheme validation (MASVS-PLATFORM-3 - Track 113.7)
                "deep_link_analyzer",
                # IPC / Binder security analysis (MASVS-PLATFORM-1 - Track 113.8)
                "ipc_binder_security",
                # Certificate pinning validation (MASVS-NETWORK-2 - MSTG-NETWORK-5+)
                "cert_pinning_analyzer",
                # Play Integrity / SafetyNet validation (MASVS-RESILIENCE-3 - MSTG-RESILIENCE-6+)
                "play_integrity_analyzer",
                # ML-based malware detection (CWE-506 - Embedded Malicious Code)
                "malware_detection",
                # StrandHogg / task hijacking detection (CWE-927 - AH-1)
                "strandhogg_detector",
                # FileProvider configuration security (CWE-22 - AH-2)
                "fileprovider_security",
            },
            priority_plugins={
                "insecure_data_storage",
                "cryptography_tests",
                "jadx_static_analysis",  # High priority - required for dynamic analysis
                "enhanced_static_analysis",
            },
            excluded_plugins={
                # Avoid slow or deprecated modules in this profile
                "mastg_integration",
                "nist_compliance_reporting",
                "network_pii_traffic_analyzer",
                "examples",  # Demo/template plugin - not for production scans
            },
        )

        # DEEP Profile - All plugins (current behavior, 15+ minutes)
        profiles[ScanProfile.DEEP] = ProfileConfiguration(
            name="Deep",
            description="Complete analysis with all available plugins",
            estimated_time="15+ minutes",
            plugin_count=48,
            plugins=set(),  # Will be populated with all available plugins
            priority_plugins={"insecure_data_storage", "enhanced_static_analysis", "jadx_static_analysis"},
            excluded_plugins={
                "examples",  # Demo/template plugin - not for production scans
                "example_static_analyzer_v2",  # Example plugin - not for production scans
            },
        )

        return profiles

    def get_profile(self, profile: ScanProfile) -> ProfileConfiguration:
        """Get configuration for a specific scan profile."""
        return self.profiles[profile]

    def get_plugins_for_profile(self, profile: ScanProfile, available_plugins: Set[str]) -> Set[str]:
        """Get the set of plugins to run for a specific profile."""
        config = self.profiles[profile]

        if profile == ScanProfile.DEEP:
            # Deep mode runs all available plugins except those explicitly excluded
            return available_plugins - config.excluded_plugins

        # For other profiles, get intersection of profile plugins and available plugins,
        # then remove any explicitly excluded plugins
        selected_plugins = config.plugins.intersection(available_plugins)
        return selected_plugins - config.excluded_plugins

    def should_exclude_plugin(self, plugin_name: str, profile: ScanProfile) -> bool:
        """Check if a plugin should be excluded for the given profile."""
        config = self.profiles[profile]
        return plugin_name in config.excluded_plugins

    def get_profile_info(self, profile: ScanProfile) -> Dict[str, str]:
        """Get human-readable information about a profile."""
        config = self.profiles[profile]
        return {
            "name": config.name,
            "description": config.description,
            "estimated_time": config.estimated_time,
            "plugin_count": str(config.plugin_count),
        }

    def recommend_profile(self, goals: List[str]) -> ScanProfile:
        """Recommend a scan profile based on user goals."""
        goal_keywords = [goal.lower() for goal in goals]

        # Check for specific goal patterns
        if any(keyword in goal_keywords for keyword in ["quick", "fast", "credential", "basic"]):
            return ScanProfile.LIGHTNING
        elif any(keyword in goal_keywords for keyword in ["standard", "common", "vulnerability"]):
            return ScanProfile.FAST
        elif any(keyword in goal_keywords for keyword in ["full", "detailed", "full"]):
            return ScanProfile.STANDARD
        elif any(keyword in goal_keywords for keyword in ["deep", "complete", "all", "compliance"]):
            return ScanProfile.DEEP
        else:
            # Default recommendation based on typical use cases
            return ScanProfile.FAST

    def optimize_plugin_execution_order(self, plugins: Set[str], profile: ScanProfile) -> List[str]:
        """Optimize plugin execution order for the given profile."""
        config = self.profiles[profile]

        # Separate plugins into priority groups
        priority_plugins = []
        regular_plugins = []

        for plugin in plugins:
            if plugin in config.priority_plugins:
                priority_plugins.append(plugin)
            else:
                regular_plugins.append(plugin)

        # Execute priority plugins first, then regular plugins
        return sorted(priority_plugins) + sorted(regular_plugins)


# Global instance for easy access
scan_profile_manager = ScanProfileManager()


def get_recommended_profile(scan_mode: str, vulnerable_app_mode: bool = False) -> ScanProfile:
    """Get recommended profile based on AODS scan parameters."""

    if scan_mode == "safe":
        return ScanProfile.LIGHTNING if not vulnerable_app_mode else ScanProfile.FAST
    elif scan_mode == "deep":
        return ScanProfile.DEEP  # CRITICAL FIX: Always use DEEP profile for deep mode
    else:
        return ScanProfile.FAST


def apply_scan_profile(profile: ScanProfile, available_plugins: Set[str]) -> Dict[str, any]:
    """Apply scan profile and return optimization configuration."""

    manager = scan_profile_manager
    selected_plugins = manager.get_plugins_for_profile(profile, available_plugins)
    execution_order = manager.optimize_plugin_execution_order(selected_plugins, profile)
    profile_info = manager.get_profile_info(profile)

    excluded_count = len(available_plugins) - len(selected_plugins)

    return {
        "profile": profile,
        "profile_info": profile_info,
        "selected_plugins": selected_plugins,
        "execution_order": execution_order,
        "plugin_count": len(selected_plugins),
        "excluded_count": excluded_count,
        "estimated_speedup": f"{excluded_count / len(available_plugins) * 100:.0f}% faster",
    }
