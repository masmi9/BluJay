"""Security analysis framework for APK files."""

import re
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field

from .certificate_analyzer import CertificateInfo, CertificateAnalyzer
from .dex_analyzer import DEXInfo, DEXAnalyzer
from .native_library_analyzer import NativeLibraryInfo, NativeLibraryAnalyzer
from .structure_analyzer import APKStructureInfo, APKStructureAnalyzer
from .manifest_parser import ManifestParser
from ._types import ArchitectureType

logger = logging.getLogger(__name__)


@dataclass
class APKSecurityAnalysisResult:
    """Container for full APK security analysis results."""

    apk_path: str
    overall_security_score: float
    risk_level: str
    certificates: List[CertificateInfo]
    dex_files: List[DEXInfo]
    native_libraries: List[NativeLibraryInfo]
    structure_info: APKStructureInfo
    manifest_analysis: Optional[Dict[str, Any]]
    security_issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    analysis_timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))


class APKSecurityAnalysis:
    """
    Security analysis framework for APK files.

    Orchestrates all security analysis components to provide a unified
    security assessment with scoring, risk evaluation, and recommendations.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.certificate_analyzer = CertificateAnalyzer()
        self.dex_analyzer = DEXAnalyzer()
        self.native_analyzer = NativeLibraryAnalyzer()
        self.structure_analyzer = APKStructureAnalyzer()
        self.manifest_parser = ManifestParser()

        # Security scoring weights
        self.scoring_weights = {
            "certificates": 0.25,
            "dex_analysis": 0.20,
            "native_libraries": 0.15,
            "structure_integrity": 0.20,
            "manifest_security": 0.20,
        }

    def analyze_apk_security(self, apk_path: Union[str, Path]) -> APKSecurityAnalysisResult:
        """
        Perform security analysis of an APK file.

        Args:
            apk_path: Path to APK file

        Returns:
            APKSecurityAnalysisResult with analysis results
        """
        apk_path = Path(apk_path)

        self.logger.info(f"Starting security analysis of {apk_path}")

        # Initialize results container
        security_issues = []
        recommendations = []

        # Certificate analysis
        certificates = self.certificate_analyzer.analyze_apk_certificates(apk_path)
        cert_score = self._evaluate_certificate_security(certificates, security_issues, recommendations)

        # DEX file analysis
        dex_files = self.dex_analyzer.analyze_apk_dex_files(apk_path)
        dex_score = self._evaluate_dex_security(dex_files, security_issues, recommendations)

        # Native library analysis
        native_libraries = self.native_analyzer.analyze_apk_native_libraries(apk_path)
        native_score = self._evaluate_native_security(native_libraries, security_issues, recommendations)

        # Structure analysis
        structure_info = self.structure_analyzer.analyze_apk_structure(apk_path)
        structure_score = self._evaluate_structure_security(structure_info, security_issues, recommendations)

        # Manifest analysis
        manifest_analysis = self.manifest_parser.parse_manifest(apk_path)
        manifest_score = self._evaluate_manifest_security(manifest_analysis, security_issues, recommendations)

        # Calculate overall security score
        overall_score = self._calculate_overall_score(
            {
                "certificates": cert_score,
                "dex_analysis": dex_score,
                "native_libraries": native_score,
                "structure_integrity": structure_score,
                "manifest_security": manifest_score,
            }
        )

        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)

        return APKSecurityAnalysisResult(
            apk_path=str(apk_path),
            overall_security_score=overall_score,
            risk_level=risk_level,
            certificates=certificates,
            dex_files=dex_files,
            native_libraries=native_libraries,
            structure_info=structure_info,
            manifest_analysis=manifest_analysis,
            security_issues=security_issues,
            recommendations=recommendations,
        )

    def _evaluate_certificate_security(
        self, certificates: List[CertificateInfo], issues: List[str], recommendations: List[str]
    ) -> float:
        """Evaluate certificate security and update issues/recommendations."""
        if not certificates:
            issues.append("No certificates found - unsigned APK")
            recommendations.append("Sign APK with a valid certificate")
            return 0.0

        total_score = 0.0
        for cert in certificates:
            validation = self.certificate_analyzer.validate_certificate_security(cert)
            total_score += validation["security_score"]
            issues.extend(validation["issues"])
            recommendations.extend(validation["recommendations"])

        return total_score / len(certificates)

    def _evaluate_dex_security(self, dex_files: List[DEXInfo], issues: List[str], recommendations: List[str]) -> float:
        """Evaluate DEX file security."""
        if not dex_files:
            issues.append("No DEX files found")
            return 0.0

        score = 100.0

        for dex in dex_files:
            issues.extend(dex.security_issues)

            if dex.obfuscation_detected:
                score -= 10
                issues.append(f"Code obfuscation detected in {dex.file_path}")
                recommendations.append("Review obfuscated code for malicious functionality")

            if dex.encryption_detected:
                score -= 20
                issues.append(f"Code encryption/packing detected in {dex.file_path}")
                recommendations.append("Analyze encrypted code thoroughly")

        return max(score, 0.0)

    def _evaluate_native_security(
        self, native_libs: List[NativeLibraryInfo], issues: List[str], recommendations: List[str]
    ) -> float:
        """Evaluate native library security."""
        if not native_libs:
            return 100.0  # No native code is secure

        score = 100.0

        for lib in native_libs:
            issues.extend(lib.security_issues)

            if lib.is_stripped:
                score -= 5
                recommendations.append(f"Stripped library {lib.name} - review for security")

            if lib.architecture == ArchitectureType.UNKNOWN:
                score -= 10
                issues.append(f"Unknown architecture for {lib.name}")

        return max(score, 0.0)

    def _evaluate_structure_security(
        self, structure: APKStructureInfo, issues: List[str], recommendations: List[str]
    ) -> float:
        """Evaluate APK structure security."""
        score = 100.0

        issues.extend(structure.integrity_issues)

        if structure.suspicious_files:
            score -= len(structure.suspicious_files) * 5
            issues.append(f"Suspicious files detected: {len(structure.suspicious_files)}")
            recommendations.append("Review suspicious files for malicious content")

        if not structure.manifest_present:
            score -= 40
            issues.append("AndroidManifest.xml missing")

        if not structure.certificates_present:
            score -= 20
            issues.append("No certificates present")

        return max(score, 0.0)

    def _evaluate_manifest_security(
        self, manifest: Optional[Dict[str, Any]], issues: List[str], recommendations: List[str]
    ) -> float:
        """Evaluate manifest security."""
        if not manifest:
            issues.append("Could not parse AndroidManifest.xml")
            return 0.0

        score = 100.0

        # Check permissions
        permissions = manifest.get("permissions", [])
        dangerous_permissions = [p for p in permissions if "dangerous" in str(p).lower()]

        if dangerous_permissions:
            score -= len(dangerous_permissions) * 2
            issues.append(f"Dangerous permissions detected: {len(dangerous_permissions)}")
            recommendations.append("Review dangerous permissions for necessity")

        # Check for exported components
        exported_components = manifest.get("exported_components", [])
        if exported_components:
            score -= len(exported_components) * 1
            recommendations.append("Review exported components for security")

        return max(score, 0.0)

    def _calculate_overall_score(self, component_scores: Dict[str, float]) -> float:
        """Calculate weighted overall security score."""
        total_score = 0.0
        for component, score in component_scores.items():
            weight = self.scoring_weights.get(component, 0.0)
            total_score += score * weight

        return max(0.0, min(100.0, total_score))

    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level based on security score."""
        if score >= 80:
            return "Low"
        elif score >= 60:
            return "Medium"
        elif score >= 40:
            return "High"
        else:
            return "Critical"

    def analyze_malware_patterns(self, apk_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Enhanced malware pattern detection and analysis.

        Analyzes APK for common malware patterns, suspicious behaviors,
        and potential security threats.
        """
        apk_path = Path(apk_path)
        malware_indicators = {
            "suspicious_permissions": [],
            "obfuscation_patterns": [],
            "network_anomalies": [],
            "file_anomalies": [],
            "behavior_patterns": [],
            "risk_score": 0.0,
        }

        try:
            # Analyze suspicious permission combinations
            manifest_data = self.manifest_parser.parse_manifest(apk_path)
            permissions = manifest_data.get("permissions", [])

            # Check for dangerous permission combinations
            dangerous_combos = [
                (["android.permission.READ_SMS", "android.permission.SEND_SMS"], "SMS manipulation"),
                (["android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"], "Location tracking"),
                (["android.permission.RECORD_AUDIO", "android.permission.INTERNET"], "Audio surveillance"),
                (["android.permission.CAMERA", "android.permission.INTERNET"], "Camera surveillance"),
                (["android.permission.READ_CONTACTS", "android.permission.INTERNET"], "Contact data theft"),
                (["android.permission.CALL_PHONE", "android.permission.INTERNET"], "Premium rate fraud"),
                (
                    ["android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_EXTERNAL_STORAGE"],
                    "File system access",
                ),
            ]

            perm_names = [p.get("name", "") for p in permissions if isinstance(p, dict)]
            for combo, description in dangerous_combos:
                if all(perm in perm_names for perm in combo):
                    malware_indicators["suspicious_permissions"].append(
                        {"pattern": combo, "description": description, "risk_level": "High"}
                    )
                    malware_indicators["risk_score"] += 15

            # Analyze file structure for anomalies
            structure_info = self.structure_analyzer.analyze_apk_structure(apk_path)

            # Check for suspicious file patterns
            suspicious_patterns = [
                (r".*\.dex$", "Multiple DEX files", 10),
                (r"assets/.*\.apk$", "Embedded APK files", 20),
                (r".*/(su|busybox|sqlite3)$", "Root utility binaries", 25),
                (r".*\.(so|dll|exe)$", "Native executables", 5),
                (r"lib/.*/lib.*\.so$", "Unusual native libraries", 10),
            ]

            file_list = structure_info.get("file_list", [])
            for pattern, description, risk_points in suspicious_patterns:
                matching_files = [f for f in file_list if re.match(pattern, f)]
                if matching_files:
                    malware_indicators["file_anomalies"].append(
                        {
                            "pattern": pattern,
                            "description": description,
                            "files": matching_files[:5],  # Limit to first 5 matches
                            "count": len(matching_files),
                            "risk_points": risk_points,
                        }
                    )
                    malware_indicators["risk_score"] += risk_points

            # Analyze network behavior patterns
            network_patterns = self._analyze_network_behavior_patterns(apk_path)
            malware_indicators["network_anomalies"] = network_patterns
            malware_indicators["risk_score"] += sum(p.get("risk_points", 0) for p in network_patterns)

            # Advanced obfuscation detection
            obfuscation_analysis = self._analyze_code_obfuscation(apk_path)
            malware_indicators["obfuscation_patterns"] = obfuscation_analysis
            malware_indicators["risk_score"] += sum(p.get("risk_points", 0) for p in obfuscation_analysis)

            # Behavioral pattern analysis
            behavior_analysis = self._analyze_suspicious_behaviors(apk_path)
            malware_indicators["behavior_patterns"] = behavior_analysis
            malware_indicators["risk_score"] += sum(p.get("risk_points", 0) for p in behavior_analysis)

        except Exception as e:
            self.logger.error(f"Malware pattern analysis failed: {e}")

        return malware_indicators

    def _analyze_network_behavior_patterns(self, apk_path: Path) -> List[Dict[str, Any]]:
        """Analyze network behavior patterns for suspicious activity."""
        network_patterns = []

        try:
            # Extract strings and analyze for network indicators
            all_strings = []
            dex_files = self.dex_analyzer.analyze_apk_dex_files(apk_path)
            for dex in dex_files:
                all_strings.extend(dex.strings)

            # Suspicious network patterns
            suspicious_network_indicators = [
                (r"https?://[a-zA-Z0-9.-]+\.(?:tk|ml|ga|cf|onion)", "Suspicious TLD usage", 15),
                (
                    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",  # noqa: E501
                    "Hardcoded IP addresses",
                    10,
                ),
                (r"(?:cmd|shell|exec|su|root)", "Shell command patterns", 20),
                (r"(?:bot|command|control|c2|cnc)", "C&C patterns", 25),
                (r"(?:encrypt|decrypt|aes|rsa|base64)", "Encryption patterns", 5),
                (r"(?:download|upload|exfiltrate)", "Data transfer patterns", 15),
            ]

            for pattern, description, risk_points in suspicious_network_indicators:
                matches = []
                for string in all_strings:
                    if re.search(pattern, string, re.IGNORECASE):
                        matches.append(string)

                if matches:
                    network_patterns.append(
                        {
                            "pattern": pattern,
                            "description": description,
                            "matches": matches[:3],  # Limit to first 3 matches
                            "count": len(matches),
                            "risk_points": risk_points,
                        }
                    )

        except Exception as e:
            self.logger.debug(f"Network behavior analysis failed: {e}")

        return network_patterns

    def _analyze_code_obfuscation(self, apk_path: Path) -> List[Dict[str, Any]]:
        """Analyze code for obfuscation patterns."""
        obfuscation_patterns = []

        try:
            dex_files = self.dex_analyzer.analyze_apk_dex_files(apk_path)

            for dex in dex_files:
                # Check for obfuscated class names
                obfuscated_classes = [cls for cls in dex.classes if self._is_obfuscated_name(cls)]
                if len(obfuscated_classes) > 10:  # Threshold for obfuscation
                    obfuscation_patterns.append(
                        {
                            "type": "Class name obfuscation",
                            "description": f"Found {len(obfuscated_classes)} obfuscated class names",
                            "sample_names": obfuscated_classes[:5],
                            "risk_points": 10,
                        }
                    )

                # Check for string obfuscation
                suspicious_strings = [s for s in dex.strings if self._is_suspicious_string(s)]
                if suspicious_strings:
                    obfuscation_patterns.append(
                        {
                            "type": "String obfuscation",
                            "description": f"Found {len(suspicious_strings)} suspicious strings",
                            "sample_strings": suspicious_strings[:3],
                            "risk_points": 15,
                        }
                    )

                # Check for reflection usage (potential obfuscation)
                reflection_indicators = [s for s in dex.strings if "reflection" in s.lower() or "invoke" in s.lower()]
                if len(reflection_indicators) > 5:
                    obfuscation_patterns.append(
                        {
                            "type": "Heavy reflection usage",
                            "description": f"Found {len(reflection_indicators)} reflection indicators",
                            "risk_points": 8,
                        }
                    )

        except Exception as e:
            self.logger.debug(f"Code obfuscation analysis failed: {e}")

        return obfuscation_patterns

    def _analyze_suspicious_behaviors(self, apk_path: Path) -> List[Dict[str, Any]]:
        """Analyze for suspicious behavioral patterns."""
        behavior_patterns = []

        try:
            # Analyze manifest for suspicious behaviors
            manifest_data = self.manifest_parser.parse_manifest(apk_path)

            # Check for hidden activities (no launcher intent)
            activities = manifest_data.get("activities", [])
            launcher_activities = [a for a in activities if self._has_launcher_intent(a)]
            if len(activities) > 0 and len(launcher_activities) == 0:
                behavior_patterns.append(
                    {
                        "type": "Hidden application",
                        "description": "No launcher activities found - potential stealth app",
                        "risk_points": 20,
                    }
                )

            # Check for device admin requests
            receivers = manifest_data.get("receivers", [])
            admin_receivers = [r for r in receivers if "DeviceAdminReceiver" in str(r)]
            if admin_receivers:
                behavior_patterns.append(
                    {
                        "type": "Device administration",
                        "description": "Requests device administrator privileges",
                        "risk_points": 15,
                    }
                )

            # Check for accessibility service abuse
            services = manifest_data.get("services", [])
            accessibility_services = [s for s in services if "AccessibilityService" in str(s)]
            if accessibility_services:
                behavior_patterns.append(
                    {
                        "type": "Accessibility service",
                        "description": "Uses accessibility services (potential overlay attacks)",
                        "risk_points": 12,
                    }
                )

            # Check for boot receivers
            boot_receivers = [r for r in receivers if "BOOT_COMPLETED" in str(r)]
            if boot_receivers:
                behavior_patterns.append(
                    {"type": "Boot persistence", "description": "Starts automatically on device boot", "risk_points": 8}
                )

        except Exception as e:
            self.logger.debug(f"Suspicious behavior analysis failed: {e}")

        return behavior_patterns

    def _is_obfuscated_name(self, name: str) -> bool:
        """Check if a class/method name appears obfuscated."""
        if len(name) <= 2:
            return True
        if len(name) == 1 and name.isalpha():
            return True
        if all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in name) and len(name) <= 3:
            return True
        return False

    def _is_suspicious_string(self, string: str) -> bool:
        """Check if a string appears suspicious or obfuscated."""
        if len(string) < 4:
            return False

        # Check for base64-like strings
        if len(string) > 20 and string.isalnum() and string.endswith("="):
            return True

        # Check for hex-encoded strings
        if len(string) > 10 and all(c in "0123456789abcdefABCDEF" for c in string):
            return True

        # Check for encrypted-looking strings
        if len(string) > 15 and sum(1 for c in string if c.isupper()) / len(string) > 0.7:
            return True

        return False

    def _has_launcher_intent(self, activity: Dict[str, Any]) -> bool:
        """Check if activity has launcher intent."""
        intent_filters = activity.get("intent_filters", [])
        for intent_filter in intent_filters:
            actions = intent_filter.get("actions", [])
            categories = intent_filter.get("categories", [])
            if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
                return True
        return False

    def validate_security_best_practices(self, apk_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Validate APK against Android security best practices.

        Checks for compliance with Android security guidelines,
        OWASP Mobile Top 10, and industry best practices.
        """
        apk_path = Path(apk_path)
        validation_results = {
            "overall_compliance": 0.0,
            "passed_checks": [],
            "failed_checks": [],
            "warnings": [],
            "recommendations": [],
        }

        try:
            # Certificate validation
            certificates = self.certificate_analyzer.analyze_apk_certificates(apk_path)

            # Check certificate validity period
            for cert in certificates:
                try:
                    from datetime import datetime

                    not_after = datetime.fromisoformat(cert.not_after.replace("Z", "+00:00"))
                    _not_before = datetime.fromisoformat(cert.not_before.replace("Z", "+00:00"))  # noqa: F841
                    now = datetime.now(not_after.tzinfo)

                    if not_after < now:
                        validation_results["failed_checks"].append(
                            {
                                "check": "Certificate validity",
                                "description": "Certificate has expired",
                                "severity": "High",
                            }
                        )
                    elif (not_after - now).days < 30:
                        validation_results["warnings"].append(
                            {
                                "check": "Certificate expiry warning",
                                "description": "Certificate expires within 30 days",
                                "severity": "Medium",
                            }
                        )
                    else:
                        validation_results["passed_checks"].append(
                            {
                                "check": "Certificate validity",
                                "description": "Certificate is valid and not expiring soon",
                            }
                        )

                    # Check certificate strength
                    if cert.key_size < 2048 and "RSA" in cert.public_key_algorithm:
                        validation_results["failed_checks"].append(
                            {
                                "check": "Certificate key strength",
                                "description": f"RSA key size {cert.key_size} is below recommended 2048 bits",
                                "severity": "Medium",
                            }
                        )

                except Exception:
                    validation_results["warnings"].append(
                        {
                            "check": "Certificate parsing",
                            "description": "Could not fully validate certificate",
                            "severity": "Low",
                        }
                    )

            # Network security validation
            manifest_data = self.manifest_parser.parse_manifest(apk_path)

            # Check for network security config
            application = manifest_data.get("application", {})
            if "android:networkSecurityConfig" not in str(application):
                validation_results["warnings"].append(
                    {
                        "check": "Network security configuration",
                        "description": "No network security configuration specified",
                        "severity": "Medium",
                    }
                )
                validation_results["recommendations"].append(
                    "Implement network security configuration to control cleartext traffic"
                )

            # Check for cleartext traffic allowance
            if "android:usesCleartextTraffic" in str(application) and "true" in str(application):
                validation_results["failed_checks"].append(
                    {
                        "check": "Cleartext traffic",
                        "description": "Application allows cleartext HTTP traffic",
                        "severity": "High",
                    }
                )
                validation_results["recommendations"].append(
                    "Disable cleartext traffic or use network security configuration"
                )

            # Check backup allowance
            if "android:allowBackup" in str(application) and "true" in str(application):
                validation_results["warnings"].append(
                    {
                        "check": "Backup allowance",
                        "description": "Application data backup is enabled",
                        "severity": "Medium",
                    }
                )
                validation_results["recommendations"].append("Consider disabling backup for sensitive applications")

            # Check debug mode
            if "android:debuggable" in str(application) and "true" in str(application):
                validation_results["failed_checks"].append(
                    {
                        "check": "Debug mode",
                        "description": "Application is debuggable in production",
                        "severity": "High",
                    }
                )
                validation_results["recommendations"].append("Disable debug mode for production releases")

            # Calculate overall compliance score
            total_checks = (
                len(validation_results["passed_checks"])
                + len(validation_results["failed_checks"])
                + len(validation_results["warnings"])
            )

            if total_checks > 0:
                passed_weight = len(validation_results["passed_checks"]) * 1.0
                warning_weight = len(validation_results["warnings"]) * 0.5
                compliance_score = (passed_weight + warning_weight) / total_checks * 100
                validation_results["overall_compliance"] = compliance_score

        except Exception as e:
            self.logger.error(f"Security best practices validation failed: {e}")

        return validation_results
