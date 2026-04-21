#!/usr/bin/env python3
"""
Android 14+ Enhanced Security Analyzer - Expanded Categories
==========================================================

Extends the existing Android 14+ Security Analyzer with 10 additional modern
vulnerability categories for full mobile security coverage.

NEW CATEGORIES ADDED:
1. Credential Manager API Security
2. Health Connect API Vulnerabilities
3. Partial Photo Access Issues
4. Foreground Service Type Violations
5. Data Safety Label Compliance
6. App Compatibility Framework Bypasses
7. Restricted Storage Access Issues
8. Runtime Permission Escalation
9. Package Visibility Filtering Bypasses
10. Keystore/Hardware Security Module Issues

Integrates with existing Android 14+ analyzer for unified analysis.
"""

import logging
import re
from typing import Dict, Any, List
from dataclasses import dataclass, field

from core.apk_ctx import APKContext
from core.android_14_security_analyzer import Android14SecurityFinding, Android14AnalysisResult

logger = logging.getLogger(__name__)


@dataclass
class EnhancedAndroid14AnalysisResult:
    """Extended results with additional Android 14+ security categories."""

    # Original categories (from base analyzer)
    base_result: Android14AnalysisResult = field(default_factory=Android14AnalysisResult)

    # NEW ENHANCED CATEGORIES
    credential_manager_issues: List[Android14SecurityFinding] = field(default_factory=list)
    health_connect_issues: List[Android14SecurityFinding] = field(default_factory=list)
    partial_photo_access_issues: List[Android14SecurityFinding] = field(default_factory=list)
    foreground_service_issues: List[Android14SecurityFinding] = field(default_factory=list)
    data_safety_compliance_issues: List[Android14SecurityFinding] = field(default_factory=list)
    app_compatibility_issues: List[Android14SecurityFinding] = field(default_factory=list)
    restricted_storage_issues: List[Android14SecurityFinding] = field(default_factory=list)
    runtime_permission_escalation_issues: List[Android14SecurityFinding] = field(default_factory=list)
    package_visibility_issues: List[Android14SecurityFinding] = field(default_factory=list)
    keystore_hsm_issues: List[Android14SecurityFinding] = field(default_factory=list)

    def get_all_enhanced_findings(self) -> List[Android14SecurityFinding]:
        """Get all findings including base and enhanced categories."""
        all_findings = self.base_result.get_all_findings()

        # Add enhanced categories
        all_findings.extend(self.credential_manager_issues)
        all_findings.extend(self.health_connect_issues)
        all_findings.extend(self.partial_photo_access_issues)
        all_findings.extend(self.foreground_service_issues)
        all_findings.extend(self.data_safety_compliance_issues)
        all_findings.extend(self.app_compatibility_issues)
        all_findings.extend(self.restricted_storage_issues)
        all_findings.extend(self.runtime_permission_escalation_issues)
        all_findings.extend(self.package_visibility_issues)
        all_findings.extend(self.keystore_hsm_issues)

        return all_findings

    def get_enhanced_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics including enhanced categories."""
        all_findings = self.get_all_enhanced_findings()

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        category_counts = {}

        for finding in all_findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1

        return {
            "total_findings": len(all_findings),
            "severity_distribution": severity_counts,
            "category_distribution": category_counts,
            "base_categories": len(self.base_result.get_all_findings()),
            "enhanced_categories": len(all_findings) - len(self.base_result.get_all_findings()),
            "coverage_score": min(100, (len(category_counts) / 20) * 100),  # 20 total categories
        }


class EnhancedAndroid14SecurityAnalyzer:
    """Enhanced Android 14+ Security Analyzer with expanded vulnerability categories."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Base analyzer will be initialized per analysis
        self.base_analyzer = None

        # Enhanced security patterns for new categories
        self.enhanced_patterns = {
            "credential_manager": {
                "patterns": [
                    r"CredentialManager\.create",
                    r"GetCredentialRequest\.Builder",
                    r"CreatePasswordRequest",
                    r"CreatePublicKeyCredentialRequest",
                    r"GetPasswordOption",
                    r"GetPublicKeyCredentialOption",
                    r"CredentialManagerCallback",
                    r"androidx\.credentials",
                ],
                "security_checks": [
                    r"without.*origin.*validation",
                    r"missing.*credential.*verification",
                    r"insecure.*credential.*storage",
                    r"credential.*without.*encryption",
                ],
                "recommendations": [
                    "Implement proper origin validation for credential requests",
                    "Use secure credential storage with hardware-backed keystore",
                    "Validate all credential responses before usage",
                    "Implement proper error handling for credential operations",
                ],
            },
            "health_connect": {
                "patterns": [
                    r"HealthConnectClient",
                    r"androidx\.health\.connect",
                    r"HealthDataService",
                    r"HealthPermission",
                    r"ReadRecordsRequest",
                    r"WriteRecordsRequest",
                    r"AggregateRequest",
                    r"HealthDataCategory",
                ],
                "security_checks": [
                    r"health.*data.*without.*permission",
                    r"sensitive.*health.*unencrypted",
                    r"health.*export.*insecure",
                    r"medical.*data.*logging",
                ],
                "recommendations": [
                    "Request minimal necessary health permissions",
                    "Encrypt all health data in transit and at rest",
                    "Implement proper consent mechanisms for health data access",
                    "Avoid logging sensitive health information",
                ],
            },
            "partial_photo_access": {
                "patterns": [
                    r"READ_MEDIA_IMAGES",
                    r"READ_MEDIA_VIDEO",
                    r"MediaStore\.Images",
                    r"MediaStore\.Video",
                    r"PhotoPicker",
                    r"ActivityResultContracts\.PickVisualMedia",
                    r"PickVisualMediaRequest",
                ],
                "security_checks": [
                    r"media.*access.*without.*permission",
                    r"photo.*metadata.*exposure",
                    r"image.*exif.*data.*leak",
                    r"media.*cache.*insecure",
                ],
                "recommendations": [
                    "Use Photo Picker API instead of direct media access when possible",
                    "Strip EXIF data from images before processing",
                    "Implement secure media caching mechanisms",
                    "Request granular media permissions",
                ],
            },
            "foreground_service": {
                "patterns": [
                    r"startForegroundService",
                    r"ServiceInfo\.FOREGROUND_SERVICE_TYPE",
                    r"FOREGROUND_SERVICE_TYPE_CAMERA",
                    r"FOREGROUND_SERVICE_TYPE_MICROPHONE",
                    r"FOREGROUND_SERVICE_TYPE_LOCATION",
                    r"FOREGROUND_SERVICE_TYPE_PHONE_CALL",
                    r"android:foregroundServiceType",
                ],
                "security_checks": [
                    r"foreground.*service.*without.*type",
                    r"sensitive.*service.*background",
                    r"service.*permission.*bypass",
                    r"foreground.*notification.*missing",
                ],
                "recommendations": [
                    "Declare appropriate foreground service types in manifest",
                    "Implement proper service lifecycle management",
                    "Show clear notifications for foreground services",
                    "Minimize foreground service usage and duration",
                ],
            },
            "data_safety": {
                "patterns": [
                    r"data.*collection",
                    r"privacy.*policy",
                    r"user.*consent",
                    r"data.*sharing",
                    r"analytics.*tracking",
                    r"advertising.*id",
                    r"personal.*information",
                ],
                "security_checks": [
                    r"data.*collection.*undisclosed",
                    r"tracking.*without.*consent",
                    r"personal.*data.*unencrypted",
                    r"analytics.*sensitive.*data",
                ],
                "recommendations": [
                    "Ensure Data Safety labels accurately reflect app behavior",
                    "Implement proper consent mechanisms for data collection",
                    "Encrypt all personal data in transit and at rest",
                    "Minimize data collection to essential functionality only",
                ],
            },
            "app_compatibility": {
                "patterns": [
                    r"targetSdkVersion",
                    r"compileSdkVersion",
                    r"Build\.VERSION\.SDK_INT",
                    r"@TargetApi",
                    r"@RequiresApi",
                    r"compatibility.*mode",
                    r"legacy.*behavior",
                ],
                "security_checks": [
                    r"target.*sdk.*outdated",
                    r"compatibility.*bypass.*security",
                    r"legacy.*mode.*vulnerable",
                    r"api.*level.*downgrade",
                ],
                "recommendations": [
                    "Target the latest stable Android API level",
                    "Avoid relying on compatibility mode for security features",
                    "Test app behavior across different API levels",
                    "Implement proper API level checks for security-sensitive operations",
                ],
            },
            "restricted_storage": {
                "patterns": [
                    r"MANAGE_EXTERNAL_STORAGE",
                    r"Environment\.getExternalStorageDirectory",
                    r"getExternalFilesDir",
                    r"MediaStore\.Downloads",
                    r"DocumentsContract",
                    r"Storage Access Framework",
                    r"scoped.*storage",
                ],
                "security_checks": [
                    r"external.*storage.*unrestricted",
                    r"file.*access.*bypass.*scoped",
                    r"storage.*permission.*escalation",
                    r"media.*files.*insecure.*access",
                ],
                "recommendations": [
                    "Use scoped storage APIs for file access",
                    "Avoid requesting MANAGE_EXTERNAL_STORAGE unless absolutely necessary",
                    "Implement proper file access validation",
                    "Use Storage Access Framework for user-selected files",
                ],
            },
            "runtime_permission_escalation": {
                "patterns": [
                    r"requestPermissions",
                    r"checkSelfPermission",
                    r"shouldShowRequestPermissionRationale",
                    r"onRequestPermissionsResult",
                    r"ActivityCompat\.requestPermissions",
                    r"PermissionChecker\.checkSelfPermission",
                ],
                "security_checks": [
                    r"permission.*request.*without.*rationale",
                    r"permission.*bypass.*attempt",
                    r"runtime.*permission.*escalation",
                    r"permission.*state.*manipulation",
                ],
                "recommendations": [
                    "Implement proper permission request flows with clear rationales",
                    "Handle permission denials gracefully",
                    "Avoid attempting to bypass permission restrictions",
                    "Use least privilege principle for permission requests",
                ],
            },
            "package_visibility": {
                "patterns": [
                    r"<queries>",
                    r"queryIntentActivities",
                    r"getInstalledPackages",
                    r"getInstalledApplications",
                    r"PackageManager\.MATCH_ALL",
                    r"package.*visibility",
                    r"intent.*filter.*query",
                ],
                "security_checks": [
                    r"package.*query.*without.*declaration",
                    r"installed.*apps.*enumeration",
                    r"package.*visibility.*bypass",
                    r"intent.*resolution.*abuse",
                ],
                "recommendations": [
                    "Declare package queries in manifest when needed",
                    "Minimize package visibility requirements",
                    "Avoid enumerating installed applications unnecessarily",
                    "Use specific intent filters instead of broad queries",
                ],
            },
            "keystore_hsm": {
                "patterns": [
                    r"KeyStore\.getInstance",
                    r"KeyGenerator\.getInstance",
                    r"KeyPairGenerator\.getInstance",
                    r"AndroidKeyStore",
                    r"KeyGenParameterSpec",
                    r"KeyProtection",
                    r"setUserAuthenticationRequired",
                    r"setInvalidatedByBiometricEnrollment",
                ],
                "security_checks": [
                    r"keystore.*without.*hardware.*backing",
                    r"key.*generation.*weak.*parameters",
                    r"biometric.*authentication.*bypass",
                    r"key.*attestation.*missing",
                ],
                "recommendations": [
                    "Use hardware-backed keystore when available",
                    "Implement proper key attestation verification",
                    "Require user authentication for sensitive keys",
                    "Use strong key generation parameters",
                ],
            },
        }

    def analyze_enhanced_android14_security(self, apk_ctx: APKContext) -> EnhancedAndroid14AnalysisResult:
        """
        Perform full Android 14+ security analysis with enhanced categories.

        Args:
            apk_ctx: APK analysis context

        Returns:
            EnhancedAndroid14AnalysisResult with all findings
        """
        self.logger.info("🔍 Starting enhanced Android 14+ security analysis")

        try:
            # Initialize base analyzer with APK context
            from core.android_14_security_analyzer import Android14SecurityAnalyzer

            self.base_analyzer = Android14SecurityAnalyzer(apk_ctx)

            # Get base analysis results
            base_result = self.base_analyzer.analyze()

            # Create enhanced result container
            enhanced_result = EnhancedAndroid14AnalysisResult(base_result=base_result)

            # Analyze new enhanced categories
            enhanced_result.credential_manager_issues = self._analyze_credential_manager_security(apk_ctx)
            enhanced_result.health_connect_issues = self._analyze_health_connect_security(apk_ctx)
            enhanced_result.partial_photo_access_issues = self._analyze_partial_photo_access_security(apk_ctx)
            enhanced_result.foreground_service_issues = self._analyze_foreground_service_security(apk_ctx)
            enhanced_result.data_safety_compliance_issues = self._analyze_data_safety_compliance(apk_ctx)
            enhanced_result.app_compatibility_issues = self._analyze_app_compatibility_security(apk_ctx)
            enhanced_result.restricted_storage_issues = self._analyze_restricted_storage_security(apk_ctx)
            enhanced_result.runtime_permission_escalation_issues = self._analyze_runtime_permission_escalation(apk_ctx)
            enhanced_result.package_visibility_issues = self._analyze_package_visibility_security(apk_ctx)
            enhanced_result.keystore_hsm_issues = self._analyze_keystore_hsm_security(apk_ctx)

            # Log analysis summary
            stats = enhanced_result.get_enhanced_summary_stats()
            self.logger.info("✅ Enhanced Android 14+ analysis complete:")
            self.logger.info(f"   Total findings: {stats['total_findings']}")
            self.logger.info(f"   Base categories: {stats['base_categories']}")
            self.logger.info(f"   Enhanced categories: {stats['enhanced_categories']}")
            self.logger.info(f"   Coverage score: {stats['coverage_score']:.1f}%")

            return enhanced_result

        except Exception as e:
            self.logger.error(f"Enhanced Android 14+ analysis failed: {e}")
            # Return empty result if analysis fails
            from core.android_14_security_analyzer import Android14AnalysisResult

            empty_base_result = Android14AnalysisResult()
            return EnhancedAndroid14AnalysisResult(base_result=empty_base_result)

    def _analyze_credential_manager_security(self, apk_ctx: APKContext) -> List[Android14SecurityFinding]:
        """Analyze Credential Manager API security issues."""
        findings = []

        try:
            source_files = apk_ctx.get_java_source_files() if hasattr(apk_ctx, "get_java_source_files") else []

            for source_file in source_files:
                try:
                    content = apk_ctx.read_source_file(source_file)

                    # Check for Credential Manager usage
                    for pattern in self.enhanced_patterns["credential_manager"]["patterns"]:
                        matches = re.finditer(pattern, content, re.IGNORECASE)

                        for match in matches:
                            # Check for security issues
                            if self._has_credential_security_issue(content, match):
                                finding = Android14SecurityFinding(
                                    finding_id=f"enhanced_credential_manager_{len(findings)}",
                                    title="Credential Manager Security Issue",
                                    description=f"Insecure Credential Manager implementation: {match.group()}",
                                    severity="HIGH",
                                    category="credential_manager",
                                    confidence=0.8,
                                    evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                    affected_components=[source_file],
                                    security_impact="Credential theft or unauthorized access",
                                    recommendations=self.enhanced_patterns["credential_manager"]["recommendations"],
                                    masvs_refs=["MSTG-AUTH-1", "MSTG-AUTH-2", "MSTG-CRYPTO-1"],
                                )
                                findings.append(finding)

                except Exception as e:
                    self.logger.debug(f"Error analyzing {source_file} for credential manager: {e}")

        except Exception as e:
            self.logger.error(f"Credential Manager analysis failed: {e}")

        return findings

    def _analyze_health_connect_security(self, apk_ctx: APKContext) -> List[Android14SecurityFinding]:
        """Analyze Health Connect API security issues."""
        findings = []

        try:
            source_files = apk_ctx.get_java_source_files() if hasattr(apk_ctx, "get_java_source_files") else []

            for source_file in source_files:
                try:
                    content = apk_ctx.read_source_file(source_file)

                    # Check for Health Connect usage
                    for pattern in self.enhanced_patterns["health_connect"]["patterns"]:
                        matches = re.finditer(pattern, content, re.IGNORECASE)

                        for match in matches:
                            # Check for security issues
                            if self._has_health_connect_security_issue(content, match):
                                finding = Android14SecurityFinding(
                                    finding_id=f"enhanced_health_connect_{len(findings)}",
                                    title="Health Connect Security Issue",
                                    description=f"Insecure Health Connect implementation: {match.group()}",
                                    severity="CRITICAL",
                                    category="health_connect",
                                    confidence=0.9,
                                    evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                    affected_components=[source_file],
                                    security_impact="Sensitive health data exposure or unauthorized access",
                                    recommendations=self.enhanced_patterns["health_connect"]["recommendations"],
                                    masvs_refs=["MSTG-STORAGE-1", "MSTG-STORAGE-2", "MSTG-PRIVACY-1"],
                                )
                                findings.append(finding)

                except Exception as e:
                    self.logger.debug(f"Error analyzing {source_file} for health connect: {e}")

        except Exception as e:
            self.logger.error(f"Health Connect analysis failed: {e}")

        return findings

    def _analyze_partial_photo_access_security(self, apk_ctx: APKContext) -> List[Android14SecurityFinding]:
        """Analyze partial photo access security issues."""
        findings = []

        try:
            source_files = apk_ctx.get_java_source_files() if hasattr(apk_ctx, "get_java_source_files") else []

            for source_file in source_files:
                try:
                    content = apk_ctx.read_source_file(source_file)

                    # Check for photo access patterns
                    for pattern in self.enhanced_patterns["partial_photo_access"]["patterns"]:
                        matches = re.finditer(pattern, content, re.IGNORECASE)

                        for match in matches:
                            # Check for security issues
                            if self._has_photo_access_security_issue(content, match):
                                finding = Android14SecurityFinding(
                                    finding_id=f"enhanced_photo_access_{len(findings)}",
                                    title="Partial Photo Access Security Issue",
                                    description=f"Insecure photo access implementation: {match.group()}",
                                    severity="MEDIUM",
                                    category="partial_photo_access",
                                    confidence=0.7,
                                    evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                    affected_components=[source_file],
                                    security_impact="Privacy violation or metadata exposure",
                                    recommendations=self.enhanced_patterns["partial_photo_access"]["recommendations"],
                                    masvs_refs=["MSTG-STORAGE-1", "MSTG-PRIVACY-1"],
                                )
                                findings.append(finding)

                except Exception as e:
                    self.logger.debug(f"Error analyzing {source_file} for photo access: {e}")

        except Exception as e:
            self.logger.error(f"Partial photo access analysis failed: {e}")

        return findings

    def _analyze_foreground_service_security(self, apk_ctx: APKContext) -> List[Android14SecurityFinding]:
        """Analyze foreground service security issues."""
        findings = []

        try:
            # Check manifest for foreground service declarations
            manifest_content = apk_ctx.get_manifest_content() if hasattr(apk_ctx, "get_manifest_content") else ""

            # Check source files for foreground service usage
            source_files = apk_ctx.get_java_source_files() if hasattr(apk_ctx, "get_java_source_files") else []

            for source_file in source_files:
                try:
                    content = apk_ctx.read_source_file(source_file)

                    # Check for foreground service patterns
                    for pattern in self.enhanced_patterns["foreground_service"]["patterns"]:
                        matches = re.finditer(pattern, content, re.IGNORECASE)

                        for match in matches:
                            # Check for security issues
                            if self._has_foreground_service_security_issue(content, match, manifest_content):
                                finding = Android14SecurityFinding(
                                    finding_id=f"enhanced_foreground_service_{len(findings)}",
                                    title="Foreground Service Security Issue",
                                    description=f"Insecure foreground service implementation: {match.group()}",
                                    severity="HIGH",
                                    category="foreground_service",
                                    confidence=0.8,
                                    evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                    affected_components=[source_file],
                                    security_impact="Background execution abuse or permission bypass",
                                    recommendations=self.enhanced_patterns["foreground_service"]["recommendations"],
                                    masvs_refs=["MSTG-PLATFORM-1", "MSTG-PLATFORM-7"],
                                )
                                findings.append(finding)

                except Exception as e:
                    self.logger.debug(f"Error analyzing {source_file} for foreground service: {e}")

        except Exception as e:
            self.logger.error(f"Foreground service analysis failed: {e}")

        return findings

    def _analyze_data_safety_compliance(self, apk_ctx: APKContext) -> List[Android14SecurityFinding]:
        """Analyze data safety compliance issues."""
        findings = []

        try:
            source_files = apk_ctx.get_java_source_files() if hasattr(apk_ctx, "get_java_source_files") else []

            for source_file in source_files:
                try:
                    content = apk_ctx.read_source_file(source_file)

                    # Check for data collection patterns
                    for pattern in self.enhanced_patterns["data_safety"]["patterns"]:
                        matches = re.finditer(pattern, content, re.IGNORECASE)

                        for match in matches:
                            # Check for compliance issues
                            if self._has_data_safety_compliance_issue(content, match):
                                finding = Android14SecurityFinding(
                                    finding_id=f"enhanced_data_safety_{len(findings)}",
                                    title="Data Safety Compliance Issue",
                                    description=f"Potential data safety compliance violation: {match.group()}",
                                    severity="MEDIUM",
                                    category="data_safety_compliance",
                                    confidence=0.6,
                                    evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                    affected_components=[source_file],
                                    security_impact="Privacy policy violation or regulatory non-compliance",
                                    recommendations=self.enhanced_patterns["data_safety"]["recommendations"],
                                    masvs_refs=["MSTG-PRIVACY-1", "MSTG-PRIVACY-2"],
                                )
                                findings.append(finding)

                except Exception as e:
                    self.logger.debug(f"Error analyzing {source_file} for data safety: {e}")

        except Exception as e:
            self.logger.error(f"Data safety compliance analysis failed: {e}")

        return findings

    def _analyze_app_compatibility_security(self, apk_ctx: APKContext) -> List[Android14SecurityFinding]:
        """Analyze app compatibility security issues."""
        findings = []

        try:
            # Check manifest for target SDK version
            manifest_content = apk_ctx.get_manifest_content() if hasattr(apk_ctx, "get_manifest_content") else ""

            # Check for outdated target SDK
            target_sdk_match = re.search(r'android:targetSdkVersion="(\d+)"', manifest_content)
            if target_sdk_match:
                target_sdk = int(target_sdk_match.group(1))
                if target_sdk < 33:  # Below Android 13
                    finding = Android14SecurityFinding(
                        finding_id="enhanced_app_compatibility_outdated_target",
                        title="Outdated Target SDK Version",
                        description=f"App targets SDK {target_sdk}, missing modern security features",
                        severity="MEDIUM",
                        category="app_compatibility",
                        confidence=0.9,
                        evidence=[f"targetSdkVersion={target_sdk} in AndroidManifest.xml"],
                        affected_components=["AndroidManifest.xml"],
                        security_impact="Missing modern security protections and privacy features",
                        recommendations=self.enhanced_patterns["app_compatibility"]["recommendations"],
                        masvs_refs=["MSTG-PLATFORM-1"],
                    )
                    findings.append(finding)

            # Check source files for compatibility issues
            source_files = apk_ctx.get_java_source_files() if hasattr(apk_ctx, "get_java_source_files") else []

            for source_file in source_files:
                try:
                    content = apk_ctx.read_source_file(source_file)

                    # Check for compatibility patterns
                    for pattern in self.enhanced_patterns["app_compatibility"]["patterns"]:
                        matches = re.finditer(pattern, content, re.IGNORECASE)

                        for match in matches:
                            # Check for security issues
                            if self._has_app_compatibility_security_issue(content, match):
                                finding = Android14SecurityFinding(
                                    finding_id=f"enhanced_app_compatibility_{len(findings)}",
                                    title="App Compatibility Security Issue",
                                    description=f"Insecure compatibility implementation: {match.group()}",
                                    severity="MEDIUM",
                                    category="app_compatibility",
                                    confidence=0.7,
                                    evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                    affected_components=[source_file],
                                    security_impact="Security feature bypass through compatibility mode",
                                    recommendations=self.enhanced_patterns["app_compatibility"]["recommendations"],
                                    masvs_refs=["MSTG-PLATFORM-1"],
                                )
                                findings.append(finding)

                except Exception as e:
                    self.logger.debug(f"Error analyzing {source_file} for app compatibility: {e}")

        except Exception as e:
            self.logger.error(f"App compatibility analysis failed: {e}")

        return findings

    def _analyze_restricted_storage_security(self, apk_ctx: APKContext) -> List[Android14SecurityFinding]:
        """Analyze restricted storage security issues."""
        findings = []

        try:
            source_files = apk_ctx.get_java_source_files() if hasattr(apk_ctx, "get_java_source_files") else []

            for source_file in source_files:
                try:
                    content = apk_ctx.read_source_file(source_file)

                    # Check for storage access patterns
                    for pattern in self.enhanced_patterns["restricted_storage"]["patterns"]:
                        matches = re.finditer(pattern, content, re.IGNORECASE)

                        for match in matches:
                            # Check for security issues
                            if self._has_restricted_storage_security_issue(content, match):
                                finding = Android14SecurityFinding(
                                    finding_id=f"enhanced_restricted_storage_{len(findings)}",
                                    title="Restricted Storage Security Issue",
                                    description=f"Insecure storage access implementation: {match.group()}",
                                    severity="MEDIUM",
                                    category="restricted_storage",
                                    confidence=0.7,
                                    evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                    affected_components=[source_file],
                                    security_impact="Unauthorized file access or scoped storage bypass",
                                    recommendations=self.enhanced_patterns["restricted_storage"]["recommendations"],
                                    masvs_refs=["MSTG-STORAGE-1", "MSTG-STORAGE-2"],
                                )
                                findings.append(finding)

                except Exception as e:
                    self.logger.debug(f"Error analyzing {source_file} for restricted storage: {e}")

        except Exception as e:
            self.logger.error(f"Restricted storage analysis failed: {e}")

        return findings

    def _analyze_runtime_permission_escalation(self, apk_ctx: APKContext) -> List[Android14SecurityFinding]:
        """Analyze runtime permission escalation issues."""
        findings = []

        try:
            source_files = apk_ctx.get_java_source_files() if hasattr(apk_ctx, "get_java_source_files") else []

            for source_file in source_files:
                try:
                    content = apk_ctx.read_source_file(source_file)

                    # Check for permission patterns
                    for pattern in self.enhanced_patterns["runtime_permission_escalation"]["patterns"]:
                        matches = re.finditer(pattern, content, re.IGNORECASE)

                        for match in matches:
                            # Check for escalation issues
                            if self._has_permission_escalation_issue(content, match):
                                finding = Android14SecurityFinding(
                                    finding_id=f"enhanced_permission_escalation_{len(findings)}",
                                    title="Runtime Permission Escalation Issue",
                                    description=f"Potential permission escalation: {match.group()}",
                                    severity="HIGH",
                                    category="runtime_permission_escalation",
                                    confidence=0.8,
                                    evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                    affected_components=[source_file],
                                    security_impact="Unauthorized permission access or privilege escalation",
                                    recommendations=self.enhanced_patterns["runtime_permission_escalation"][
                                        "recommendations"
                                    ],
                                    masvs_refs=["MSTG-PLATFORM-1", "MSTG-AUTH-1"],
                                )
                                findings.append(finding)

                except Exception as e:
                    self.logger.debug(f"Error analyzing {source_file} for permission escalation: {e}")

        except Exception as e:
            self.logger.error(f"Runtime permission escalation analysis failed: {e}")

        return findings

    def _analyze_package_visibility_security(self, apk_ctx: APKContext) -> List[Android14SecurityFinding]:
        """Analyze package visibility security issues."""
        findings = []

        try:
            # Check manifest for queries declarations
            manifest_content = apk_ctx.get_manifest_content() if hasattr(apk_ctx, "get_manifest_content") else ""

            source_files = apk_ctx.get_java_source_files() if hasattr(apk_ctx, "get_java_source_files") else []

            for source_file in source_files:
                try:
                    content = apk_ctx.read_source_file(source_file)

                    # Check for package visibility patterns
                    for pattern in self.enhanced_patterns["package_visibility"]["patterns"]:
                        matches = re.finditer(pattern, content, re.IGNORECASE)

                        for match in matches:
                            # Check for security issues
                            if self._has_package_visibility_security_issue(content, match, manifest_content):
                                finding = Android14SecurityFinding(
                                    finding_id=f"enhanced_package_visibility_{len(findings)}",
                                    title="Package Visibility Security Issue",
                                    description=f"Insecure package visibility implementation: {match.group()}",
                                    severity="MEDIUM",
                                    category="package_visibility",
                                    confidence=0.7,
                                    evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                    affected_components=[source_file],
                                    security_impact="Privacy violation through app enumeration",
                                    recommendations=self.enhanced_patterns["package_visibility"]["recommendations"],
                                    masvs_refs=["MSTG-PLATFORM-1", "MSTG-PRIVACY-1"],
                                )
                                findings.append(finding)

                except Exception as e:
                    self.logger.debug(f"Error analyzing {source_file} for package visibility: {e}")

        except Exception as e:
            self.logger.error(f"Package visibility analysis failed: {e}")

        return findings

    def _analyze_keystore_hsm_security(self, apk_ctx: APKContext) -> List[Android14SecurityFinding]:
        """Analyze keystore and HSM security issues."""
        findings = []

        try:
            source_files = apk_ctx.get_java_source_files() if hasattr(apk_ctx, "get_java_source_files") else []

            for source_file in source_files:
                try:
                    content = apk_ctx.read_source_file(source_file)

                    # Check for keystore patterns
                    for pattern in self.enhanced_patterns["keystore_hsm"]["patterns"]:
                        matches = re.finditer(pattern, content, re.IGNORECASE)

                        for match in matches:
                            # Check for security issues
                            if self._has_keystore_hsm_security_issue(content, match):
                                finding = Android14SecurityFinding(
                                    finding_id=f"enhanced_keystore_hsm_{len(findings)}",
                                    title="Keystore/HSM Security Issue",
                                    description=f"Insecure keystore implementation: {match.group()}",
                                    severity="HIGH",
                                    category="keystore_hsm",
                                    confidence=0.8,
                                    evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                    affected_components=[source_file],
                                    security_impact="Cryptographic key compromise or weak key protection",
                                    recommendations=self.enhanced_patterns["keystore_hsm"]["recommendations"],
                                    masvs_refs=["MSTG-CRYPTO-1", "MSTG-CRYPTO-2", "MSTG-AUTH-2"],
                                )
                                findings.append(finding)

                except Exception as e:
                    self.logger.debug(f"Error analyzing {source_file} for keystore/HSM: {e}")

        except Exception as e:
            self.logger.error(f"Keystore/HSM analysis failed: {e}")

        return findings

    # Helper methods for security issue detection
    def _has_credential_security_issue(self, content: str, match) -> bool:
        """Check if credential manager implementation has security issues."""
        context = content[max(0, match.start() - 200) : match.end() + 200]

        for check in self.enhanced_patterns["credential_manager"]["security_checks"]:
            if re.search(check, context, re.IGNORECASE):
                return True
        return False

    def _has_health_connect_security_issue(self, content: str, match) -> bool:
        """Check if health connect implementation has security issues."""
        context = content[max(0, match.start() - 200) : match.end() + 200]

        for check in self.enhanced_patterns["health_connect"]["security_checks"]:
            if re.search(check, context, re.IGNORECASE):
                return True
        return False

    def _has_photo_access_security_issue(self, content: str, match) -> bool:
        """Check if photo access implementation has security issues."""
        context = content[max(0, match.start() - 200) : match.end() + 200]

        for check in self.enhanced_patterns["partial_photo_access"]["security_checks"]:
            if re.search(check, context, re.IGNORECASE):
                return True
        return False

    def _has_foreground_service_security_issue(self, content: str, match, manifest_content: str) -> bool:
        """Check if foreground service implementation has security issues."""
        context = content[max(0, match.start() - 200) : match.end() + 200]

        # Check if service type is declared in manifest
        if "startForegroundService" in match.group() and "foregroundServiceType" not in manifest_content:
            return True

        for check in self.enhanced_patterns["foreground_service"]["security_checks"]:
            if re.search(check, context, re.IGNORECASE):
                return True
        return False

    def _has_data_safety_compliance_issue(self, content: str, match) -> bool:
        """Check if data collection has compliance issues."""
        context = content[max(0, match.start() - 200) : match.end() + 200]

        for check in self.enhanced_patterns["data_safety"]["security_checks"]:
            if re.search(check, context, re.IGNORECASE):
                return True
        return False

    def _has_app_compatibility_security_issue(self, content: str, match) -> bool:
        """Check if app compatibility implementation has security issues."""
        context = content[max(0, match.start() - 200) : match.end() + 200]

        for check in self.enhanced_patterns["app_compatibility"]["security_checks"]:
            if re.search(check, context, re.IGNORECASE):
                return True
        return False

    def _has_restricted_storage_security_issue(self, content: str, match) -> bool:
        """Check if storage access implementation has security issues."""
        context = content[max(0, match.start() - 200) : match.end() + 200]

        for check in self.enhanced_patterns["restricted_storage"]["security_checks"]:
            if re.search(check, context, re.IGNORECASE):
                return True
        return False

    def _has_permission_escalation_issue(self, content: str, match) -> bool:
        """Check if permission implementation has escalation issues."""
        context = content[max(0, match.start() - 200) : match.end() + 200]

        for check in self.enhanced_patterns["runtime_permission_escalation"]["security_checks"]:
            if re.search(check, context, re.IGNORECASE):
                return True
        return False

    def _has_package_visibility_security_issue(self, content: str, match, manifest_content: str) -> bool:
        """Check if package visibility implementation has security issues."""
        context = content[max(0, match.start() - 200) : match.end() + 200]

        # Check if queries are declared in manifest when needed
        if "queryIntentActivities" in match.group() and "<queries>" not in manifest_content:
            return True

        for check in self.enhanced_patterns["package_visibility"]["security_checks"]:
            if re.search(check, context, re.IGNORECASE):
                return True
        return False

    def _has_keystore_hsm_security_issue(self, content: str, match) -> bool:
        """Check if keystore implementation has security issues."""
        context = content[max(0, match.start() - 200) : match.end() + 200]

        for check in self.enhanced_patterns["keystore_hsm"]["security_checks"]:
            if re.search(check, context, re.IGNORECASE):
                return True
        return False


# Export main classes
__all__ = [
    "EnhancedAndroid14SecurityAnalyzer",
    "EnhancedAndroid14AnalysisResult",
    "Android14SecurityFinding",  # Re-export from base
]
