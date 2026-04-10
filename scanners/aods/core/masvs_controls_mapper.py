"""
MASVS Controls Mapping System for AODS

This module provides full mapping between AODS vulnerability types and
Mobile Application Security Verification Standard (MASVS) controls.

Features:
- Complete MASVS v1.5.0 control mapping
- Vulnerability type to MASVS control association
- Compliance scoring and reporting
- Integration with vulnerability ID generation
- Support for custom control mappings

Integration with Remediation System:
- Links MASVS controls to specific remediation guidance
- Enables compliance-driven remediation prioritization
- Provides regulatory context for vulnerability fixes
"""

import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class MASVSLevel(Enum):
    """MASVS verification levels."""

    L1 = "L1"  # Standard Security
    L2 = "L2"  # Defense in Depth
    R = "R"  # Resiliency Against Reverse Engineering


class MASVSCategory(Enum):
    """MASVS control categories."""

    ARCH = "V1"  # Architecture, Design and Threat Modeling
    DATA = "V2"  # Data Storage and Privacy
    CRYPTO = "V3"  # Cryptography
    AUTH = "V4"  # Authentication and Session Management
    NETWORK = "V5"  # Network Communication
    PLATFORM = "V6"  # Platform Interaction
    CODE = "V7"  # Code Quality and Build Settings
    RESILIENCE = "V8"  # Resilience Requirements


@dataclass
class MASVSControl:
    """Individual MASVS control definition."""

    control_id: str
    category: MASVSCategory
    level: MASVSLevel
    title: str
    description: str
    objective: str
    verification_methods: List[str] = field(default_factory=list)
    related_controls: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Validate control data."""
        if not self.control_id.startswith("MSTG-"):
            logger.warning(f"Control ID {self.control_id} doesn't follow MSTG- convention")


@dataclass
class VulnerabilityMASVSMapping:
    """Mapping between vulnerability and MASVS controls."""

    vulnerability_type: str
    primary_controls: List[str] = field(default_factory=list)
    secondary_controls: List[str] = field(default_factory=list)
    compliance_impact: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    remediation_priority: int = 3  # 1-5 scale


class MASVSControlsMapper:
    """
    Full MASVS controls mapping system.

    This class provides mapping between AODS vulnerability types and MASVS controls,
    enabling compliance reporting and remediation prioritization.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._controls_registry: Dict[str, MASVSControl] = {}
        self._vulnerability_mappings: Dict[str, VulnerabilityMASVSMapping] = {}

        # Initialize MASVS controls and mappings
        self._init_masvs_controls()
        self._init_vulnerability_mappings()

    def _init_masvs_controls(self):
        """Initialize full MASVS controls registry."""

        # V1: Architecture, Design and Threat Modeling
        self._register_control(
            "MSTG-ARCH-1",
            MASVSCategory.ARCH,
            MASVSLevel.L1,
            "Security Architecture Review",
            "All app components are identified and have a reason for being included",
            "Ensure minimal attack surface through component analysis",
        )

        self._register_control(
            "MSTG-ARCH-2",
            MASVSCategory.ARCH,
            MASVSLevel.L1,
            "Security Controls Implementation",
            "Security controls are never enforced only on the client side",
            "Prevent client-side security bypass vulnerabilities",
        )

        # V2: Data Storage and Privacy
        self._register_control(
            "MSTG-STORAGE-1",
            MASVSCategory.DATA,
            MASVSLevel.L1,
            "Secure Local Storage",
            "System credential storage facilities are used appropriately to store sensitive data",
            "Protect sensitive data using platform security mechanisms",
        )

        self._register_control(
            "MSTG-STORAGE-2",
            MASVSCategory.DATA,
            MASVSLevel.L1,
            "Prevent Sensitive Data Leakage",
            "No sensitive data should be stored outside of the app container or system credential storage facilities",
            "Ensure sensitive data doesn't leak to external storage",
        )

        self._register_control(
            "MSTG-STORAGE-3",
            MASVSCategory.DATA,
            MASVSLevel.L1,
            "Keyboard Cache Protection",
            "No sensitive data is written to application logs",
            "Prevent sensitive data exposure through logging",
        )

        self._register_control(
            "MSTG-STORAGE-4",
            MASVSCategory.DATA,
            MASVSLevel.L1,
            "Third-Party Sharing",
            "No sensitive data is shared with third parties unless it is a necessary part of the architecture",
            "Control third-party data sharing",
        )

        # V3: Cryptography
        self._register_control(
            "MSTG-CRYPTO-1",
            MASVSCategory.CRYPTO,
            MASVSLevel.L1,
            "Strong Cryptographic Standards",
            "The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption",
            "Prevent hardcoded cryptographic keys",
        )

        self._register_control(
            "MSTG-CRYPTO-2",
            MASVSCategory.CRYPTO,
            MASVSLevel.L1,
            "Proven Cryptographic Algorithms",
            "The app uses proven implementations of cryptographic primitives",
            "Use industry-standard cryptographic implementations",
        )

        self._register_control(
            "MSTG-CRYPTO-3",
            MASVSCategory.CRYPTO,
            MASVSLevel.L1,
            "Appropriate Cryptographic Primitives",
            "The app uses cryptographic primitives that are appropriate for the particular use-case",
            "Select appropriate cryptographic algorithms for use case",
        )

        self._register_control(
            "MSTG-CRYPTO-4",
            MASVSCategory.CRYPTO,
            MASVSLevel.L1,
            "Secure Random Number Generation",
            "The app does not use cryptographic protocols or algorithms that are widely considered depreciated",
            "Avoid deprecated cryptographic protocols",
        )

        # V4: Authentication and Session Management
        self._register_control(
            "MSTG-AUTH-1",
            MASVSCategory.AUTH,
            MASVSLevel.L1,
            "Secure Authentication Architecture",
            "If the app provides users access to a remote service, some form of authentication is performed at the remote endpoint",  # noqa: E501
            "Ensure proper authentication mechanisms",
        )

        self._register_control(
            "MSTG-AUTH-2",
            MASVSCategory.AUTH,
            MASVSLevel.L1,
            "Session Management",
            "If stateful session management is used, the remote endpoint uses randomly generated session identifiers",
            "Implement secure session management",
        )

        self._register_control(
            "MSTG-AUTH-3",
            MASVSCategory.AUTH,
            MASVSLevel.L1,
            "Session Termination",
            "If stateful session management is used, the remote endpoint terminates the existing session when the user logs out",  # noqa: E501
            "Ensure proper session termination",
        )

        # V5: Network Communication
        self._register_control(
            "MSTG-NETWORK-1",
            MASVSCategory.NETWORK,
            MASVSLevel.L1,
            "Secure Network Protocols",
            "Data is encrypted on the network using TLS. The secure channel is used consistently throughout the app",
            "Enforce TLS encryption for network communication",
        )

        self._register_control(
            "MSTG-NETWORK-2",
            MASVSCategory.NETWORK,
            MASVSLevel.L1,
            "TLS Configuration",
            "The TLS settings are in line with current best practices",
            "Use secure TLS configuration",
        )

        self._register_control(
            "MSTG-NETWORK-3",
            MASVSCategory.NETWORK,
            MASVSLevel.L2,
            "Certificate Validation",
            "The app verifies the X.509 certificate of the remote endpoint when the secure channel is established",
            "Implement proper certificate validation",
        )

        # V6: Platform Interaction
        self._register_control(
            "MSTG-PLATFORM-1",
            MASVSCategory.PLATFORM,
            MASVSLevel.L1,
            "IPC Security",
            "The app only requests the minimum set of permissions necessary",
            "Follow principle of least privilege for permissions",
        )

        self._register_control(
            "MSTG-PLATFORM-2",
            MASVSCategory.PLATFORM,
            MASVSLevel.L1,
            "Input Validation",
            "All inputs from external sources and the user are validated and if necessary sanitized",
            "Implement input validation",
        )

        self._register_control(
            "MSTG-PLATFORM-3",
            MASVSCategory.PLATFORM,
            MASVSLevel.L1,
            "Exported Components",
            "The app does not export sensitive functionality via custom URL schemes",
            "Secure custom URL scheme implementations",
        )

        # V7: Code Quality and Build Settings
        self._register_control(
            "MSTG-CODE-1",
            MASVSCategory.CODE,
            MASVSLevel.L1,
            "Code Signing",
            "The app is signed and provisioned with a valid certificate",
            "Ensure proper code signing",
        )

        self._register_control(
            "MSTG-CODE-2",
            MASVSCategory.CODE,
            MASVSLevel.L1,
            "Debug Features",
            "The app has been built in release mode, with settings appropriate for a release build",
            "Disable debug features in production",
        )

        self._register_control(
            "MSTG-CODE-3",
            MASVSCategory.CODE,
            MASVSLevel.L1,
            "Debug Symbols",
            "Debugging symbols have been removed from native binaries",
            "Remove debug symbols from production builds",
        )

        # V8: Resilience Requirements
        self._register_control(
            "MSTG-RESILIENCE-1",
            MASVSCategory.RESILIENCE,
            MASVSLevel.R,
            "Runtime Application Self-Protection",
            "The app detects, and responds to, the presence of a rooted or jailbroken device",
            "Implement root/jailbreak detection",
        )

        self._register_control(
            "MSTG-RESILIENCE-2",
            MASVSCategory.RESILIENCE,
            MASVSLevel.R,
            "Anti-Debugging",
            "The app prevents debugging and/or detects, and responds to, a debugger being attached",
            "Implement anti-debugging mechanisms",
        )

        self._register_control(
            "MSTG-RESILIENCE-3",
            MASVSCategory.RESILIENCE,
            MASVSLevel.R,
            "Tampering Detection",
            "The app detects, and responds to, tampering with executable files and critical data",
            "Implement tampering detection and response",
        )

    def _register_control(
        self, control_id: str, category: MASVSCategory, level: MASVSLevel, title: str, description: str, objective: str
    ):
        """Register a MASVS control in the registry."""
        control = MASVSControl(
            control_id=control_id,
            category=category,
            level=level,
            title=title,
            description=description,
            objective=objective,
        )
        self._controls_registry[control_id] = control

    def _init_vulnerability_mappings(self):
        """Initialize mappings between vulnerability types and MASVS controls."""

        # Import VulnerabilityType to avoid circular imports
        try:
            from core.shared_data_structures.base_vulnerability import VulnerabilityType
        except ImportError:
            logger.warning("Could not import VulnerabilityType for MASVS mapping")
            return

        # Cryptographic vulnerabilities
        self._register_mapping(
            VulnerabilityType.WEAK_CRYPTOGRAPHY.value,
            primary_controls=["MSTG-CRYPTO-1", "MSTG-CRYPTO-2", "MSTG-CRYPTO-3"],
            secondary_controls=["MSTG-CRYPTO-4"],
            compliance_impact="HIGH",
            remediation_priority=4,
        )

        self._register_mapping(
            VulnerabilityType.HARDCODED_SECRETS.value,
            primary_controls=["MSTG-CRYPTO-1", "MSTG-STORAGE-1"],
            secondary_controls=["MSTG-ARCH-2"],
            compliance_impact="CRITICAL",
            remediation_priority=5,
        )

        # Data storage vulnerabilities
        self._register_mapping(
            VulnerabilityType.INSECURE_STORAGE.value,
            primary_controls=["MSTG-STORAGE-1", "MSTG-STORAGE-2"],
            secondary_controls=["MSTG-STORAGE-3"],
            compliance_impact="HIGH",
            remediation_priority=4,
        )

        self._register_mapping(
            VulnerabilityType.UNENCRYPTED_DATA.value,
            primary_controls=["MSTG-STORAGE-1", "MSTG-CRYPTO-1"],
            secondary_controls=["MSTG-STORAGE-2"],
            compliance_impact="HIGH",
            remediation_priority=4,
        )

        # Network security vulnerabilities
        self._register_mapping(
            VulnerabilityType.CLEARTEXT_TRAFFIC.value,
            primary_controls=["MSTG-NETWORK-1", "MSTG-NETWORK-2"],
            secondary_controls=["MSTG-NETWORK-3"],
            compliance_impact="HIGH",
            remediation_priority=4,
        )

        self._register_mapping(
            VulnerabilityType.CERTIFICATE_VALIDATION.value,
            primary_controls=["MSTG-NETWORK-3", "MSTG-NETWORK-2"],
            secondary_controls=["MSTG-NETWORK-1"],
            compliance_impact="HIGH",
            remediation_priority=4,
        )

        # Platform usage vulnerabilities
        self._register_mapping(
            VulnerabilityType.EXPORTED_COMPONENTS.value,
            primary_controls=["MSTG-PLATFORM-3", "MSTG-PLATFORM-1"],
            secondary_controls=["MSTG-PLATFORM-2"],
            compliance_impact="MEDIUM",
            remediation_priority=3,
        )

        self._register_mapping(
            VulnerabilityType.INTENT_SECURITY.value,
            primary_controls=["MSTG-PLATFORM-2", "MSTG-PLATFORM-3"],
            secondary_controls=["MSTG-PLATFORM-1"],
            compliance_impact="MEDIUM",
            remediation_priority=3,
        )

        # Authentication vulnerabilities
        self._register_mapping(
            VulnerabilityType.AUTHENTICATION_BYPASS.value,
            primary_controls=["MSTG-AUTH-1", "MSTG-AUTH-2"],
            secondary_controls=["MSTG-AUTH-3"],
            compliance_impact="CRITICAL",
            remediation_priority=5,
        )

        # Code quality vulnerabilities
        self._register_mapping(
            VulnerabilityType.CODE_INJECTION.value,
            primary_controls=["MSTG-PLATFORM-2", "MSTG-CODE-2"],
            secondary_controls=["MSTG-ARCH-2"],
            compliance_impact="HIGH",
            remediation_priority=4,
        )

        # Runtime manipulation
        self._register_mapping(
            VulnerabilityType.RUNTIME_MANIPULATION.value,
            primary_controls=["MSTG-RESILIENCE-1", "MSTG-RESILIENCE-2"],
            secondary_controls=["MSTG-RESILIENCE-3"],
            compliance_impact="MEDIUM",
            remediation_priority=2,
        )

        # Debugging enabled
        self._register_mapping(
            VulnerabilityType.DEBUGGING_ENABLED.value,
            primary_controls=["MSTG-CODE-2", "MSTG-RESILIENCE-2"],
            secondary_controls=["MSTG-CODE-3"],
            compliance_impact="MEDIUM",
            remediation_priority=3,
        )

    def _register_mapping(
        self,
        vulnerability_type: str,
        primary_controls: List[str],
        secondary_controls: List[str] = None,
        compliance_impact: str = "MEDIUM",
        remediation_priority: int = 3,
    ):
        """Register a vulnerability to MASVS controls mapping."""
        mapping = VulnerabilityMASVSMapping(
            vulnerability_type=vulnerability_type,
            primary_controls=primary_controls,
            secondary_controls=secondary_controls or [],
            compliance_impact=compliance_impact,
            remediation_priority=remediation_priority,
        )
        self._vulnerability_mappings[vulnerability_type] = mapping

    def get_masvs_controls_for_vulnerability(self, vulnerability_type: str) -> Tuple[List[str], List[str]]:
        """
        Get MASVS controls for a vulnerability type.

        Args:
            vulnerability_type: Vulnerability type string

        Returns:
            Tuple of (primary_controls, secondary_controls)
        """
        mapping = self._vulnerability_mappings.get(vulnerability_type)
        if mapping:
            return mapping.primary_controls, mapping.secondary_controls

        # Fallback to general controls if no specific mapping
        return ["MSTG-ARCH-1"], []

    def get_all_controls_for_vulnerability(self, vulnerability_type: str) -> List[str]:
        """Get all MASVS controls (primary + secondary) for a vulnerability type."""
        primary, secondary = self.get_masvs_controls_for_vulnerability(vulnerability_type)
        return primary + secondary

    def get_control_details(self, control_id: str) -> Optional[MASVSControl]:
        """Get detailed information about a specific MASVS control."""
        return self._controls_registry.get(control_id)

    def get_compliance_impact(self, vulnerability_type: str) -> str:
        """Get compliance impact level for a vulnerability type."""
        mapping = self._vulnerability_mappings.get(vulnerability_type)
        return mapping.compliance_impact if mapping else "MEDIUM"

    def get_remediation_priority(self, vulnerability_type: str) -> int:
        """Get remediation priority (1-5) for a vulnerability type."""
        mapping = self._vulnerability_mappings.get(vulnerability_type)
        return mapping.remediation_priority if mapping else 3

    def calculate_compliance_score(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate MASVS compliance score based on detected vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Dictionary with compliance scoring information
        """
        try:
            total_controls = len(self._controls_registry)
            affected_controls = set()
            impact_scores = []

            # Analyze each vulnerability
            for vuln in vulnerabilities:
                vuln_type = vuln.get("vulnerability_type", "")
                controls = self.get_all_controls_for_vulnerability(vuln_type)
                affected_controls.update(controls)

                # Add impact score
                impact = self.get_compliance_impact(vuln_type)
                impact_score = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(impact, 2)
                impact_scores.append(impact_score)

            # Calculate scores
            affected_count = len(affected_controls)
            compliance_percentage = max(0, (total_controls - affected_count) / total_controls * 100)
            average_impact = sum(impact_scores) / len(impact_scores) if impact_scores else 0

            # Determine compliance level
            if compliance_percentage >= 95:
                compliance_level = "EXCELLENT"
            elif compliance_percentage >= 85:
                compliance_level = "GOOD"
            elif compliance_percentage >= 70:
                compliance_level = "FAIR"
            elif compliance_percentage >= 50:
                compliance_level = "POOR"
            else:
                compliance_level = "CRITICAL"

            return {
                "compliance_percentage": round(compliance_percentage, 2),
                "compliance_level": compliance_level,
                "total_masvs_controls": total_controls,
                "affected_controls_count": affected_count,
                "affected_controls": list(affected_controls),
                "average_impact_score": round(average_impact, 2),
                "total_vulnerabilities": len(vulnerabilities),
                "high_impact_vulnerabilities": sum(1 for score in impact_scores if score >= 3),
                "recommendations": self._generate_compliance_recommendations(compliance_percentage, affected_controls),
            }

        except Exception as e:
            self.logger.error(f"Error calculating compliance score: {e}")
            return {"compliance_percentage": 0, "compliance_level": "UNKNOWN", "error": str(e)}

    def _generate_compliance_recommendations(
        self, compliance_percentage: float, affected_controls: Set[str]
    ) -> List[str]:
        """Generate compliance improvement recommendations."""
        recommendations = []

        if compliance_percentage < 50:
            recommendations.append("🚨 URGENT: Critical compliance issues detected - immediate remediation required")
        elif compliance_percentage < 70:
            recommendations.append("⚠️ Multiple compliance gaps identified - prioritize high-impact fixes")
        elif compliance_percentage < 85:
            recommendations.append("📋 Good compliance baseline - focus on remaining security gaps")
        else:
            recommendations.append("✅ Strong compliance posture - maintain current security practices")

        # Category-specific recommendations
        categories_affected = set()
        for control_id in affected_controls:
            control = self.get_control_details(control_id)
            if control:
                categories_affected.add(control.category.value)

        if "V3" in categories_affected:
            recommendations.append("🔐 Focus on cryptographic implementations and key management")
        if "V2" in categories_affected:
            recommendations.append("💾 Review data storage and privacy protection mechanisms")
        if "V5" in categories_affected:
            recommendations.append("🌐 Strengthen network security and TLS configurations")
        if "V6" in categories_affected:
            recommendations.append("📱 Improve platform interaction security controls")

        return recommendations

    def generate_masvs_report(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate full MASVS compliance report."""
        compliance_score = self.calculate_compliance_score(vulnerabilities)

        # Group vulnerabilities by MASVS category
        category_analysis = {}
        for category in MASVSCategory:
            category_vulns = []
            for vuln in vulnerabilities:
                vuln_type = vuln.get("vulnerability_type", "")
                controls = self.get_all_controls_for_vulnerability(vuln_type)

                # Check if any control belongs to this category
                for control_id in controls:
                    control = self.get_control_details(control_id)
                    if control and control.category == category:
                        category_vulns.append(vuln)
                        break

            category_analysis[category.value] = {
                "category_name": category.name,
                "vulnerability_count": len(category_vulns),
                "vulnerabilities": category_vulns[:5],  # Limit for report size
            }

        return {
            "compliance_score": compliance_score,
            "category_analysis": category_analysis,
            "masvs_version": "1.5.0",
            "report_timestamp": (
                logger.handlers[0].formatter.formatTime(logger.makeRecord("masvs", 20, "", 0, "", (), None))
                if logger.handlers
                else "unknown"
            ),
            "total_controls_evaluated": len(self._controls_registry),
        }


# Global instance for use across AODS
_global_masvs_mapper = None


def get_masvs_mapper() -> MASVSControlsMapper:
    """Get the global MASVS controls mapper instance."""
    global _global_masvs_mapper
    if _global_masvs_mapper is None:
        _global_masvs_mapper = MASVSControlsMapper()
    return _global_masvs_mapper


def get_masvs_controls_for_vulnerability_type(vulnerability_type: str) -> List[str]:
    """
    Convenience function to get MASVS controls for a vulnerability type.

    This is the main entry point for MASVS control mapping across AODS.
    """
    mapper = get_masvs_mapper()
    primary, secondary = mapper.get_masvs_controls_for_vulnerability(vulnerability_type)
    return primary + secondary


def enhance_vulnerability_with_masvs(vulnerability_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhance a vulnerability dictionary with MASVS control information.

    This function adds MASVS controls, compliance impact, and remediation priority
    to an existing vulnerability dictionary.
    """
    try:
        mapper = get_masvs_mapper()
        vuln_type = vulnerability_dict.get("vulnerability_type", "")

        # Get MASVS controls
        primary_controls, secondary_controls = mapper.get_masvs_controls_for_vulnerability(vuln_type)
        all_controls = primary_controls + secondary_controls

        # Add MASVS information
        vulnerability_dict.update(
            {
                "masvs_controls": all_controls,
                "masvs_primary_controls": primary_controls,
                "masvs_secondary_controls": secondary_controls,
                "compliance_impact": mapper.get_compliance_impact(vuln_type),
                "remediation_priority": mapper.get_remediation_priority(vuln_type),
            }
        )

        # Add control details for reporting
        control_details = []
        for control_id in primary_controls[:3]:  # Limit to top 3 for brevity
            control = mapper.get_control_details(control_id)
            if control:
                control_details.append(
                    {
                        "id": control.control_id,
                        "title": control.title,
                        "category": control.category.value,
                        "level": control.level.value,
                    }
                )

        vulnerability_dict["masvs_control_details"] = control_details

        return vulnerability_dict

    except Exception as e:
        logger.error(f"Error enhancing vulnerability with MASVS: {e}")
        # Return original vulnerability with minimal MASVS info
        vulnerability_dict.setdefault("masvs_controls", [])
        vulnerability_dict.setdefault("compliance_impact", "MEDIUM")
        vulnerability_dict.setdefault("remediation_priority", 3)
        return vulnerability_dict
