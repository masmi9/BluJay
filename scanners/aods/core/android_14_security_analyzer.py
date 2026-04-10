#!/usr/bin/env python3
"""
Android 14+ Security Analyzer - Phase 8 Implementation
=====================================================

Security analysis for Android API 34+ (Android 14) specific features
and security model changes. This analyzer addresses modern Android security features
that are not covered by existing analyzers.

Android 14+ Features Covered:
- Predictive back gesture security issues
- Themed app icon vulnerabilities
- Notification runtime permission bypasses
- Regional preferences security implications
- Grammatical inflection API misuse
- Privacy sandbox integration
- Scoped storage enforcement
- Restricted settings API handling
- Photo picker API security analysis
- Enhanced background activity restrictions

Following the Zero Functionality Loss Requirement established in Phase 7.
"""

import logging
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

from core.apk_ctx import APKContext

logger = logging.getLogger(__name__)


@dataclass
class Android14SecurityFinding:
    """Represents an Android 14+ specific security finding."""

    finding_id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # predictive_back, themed_icons, notifications, etc.
    confidence: float  # 0.0 to 1.0
    evidence: List[str] = field(default_factory=list)
    affected_components: List[str] = field(default_factory=list)
    api_level_impact: int = 34  # Minimum API level affected
    security_impact: str = "UNKNOWN"
    recommendations: List[str] = field(default_factory=list)
    masvs_refs: List[str] = field(default_factory=list)
    timestamp: Optional[str] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class Android14AnalysisResult:
    """Results from Android 14+ security analysis."""

    predictive_back_issues: List[Android14SecurityFinding] = field(default_factory=list)
    themed_icon_issues: List[Android14SecurityFinding] = field(default_factory=list)
    notification_permission_issues: List[Android14SecurityFinding] = field(default_factory=list)
    regional_preferences_issues: List[Android14SecurityFinding] = field(default_factory=list)
    grammatical_inflection_issues: List[Android14SecurityFinding] = field(default_factory=list)
    privacy_sandbox_issues: List[Android14SecurityFinding] = field(default_factory=list)
    scoped_storage_issues: List[Android14SecurityFinding] = field(default_factory=list)
    restricted_settings_issues: List[Android14SecurityFinding] = field(default_factory=list)
    photo_picker_issues: List[Android14SecurityFinding] = field(default_factory=list)
    background_activity_issues: List[Android14SecurityFinding] = field(default_factory=list)

    def get_all_findings(self) -> List[Android14SecurityFinding]:
        """Get all findings across all categories."""
        all_findings = []
        all_findings.extend(self.predictive_back_issues)
        all_findings.extend(self.themed_icon_issues)
        all_findings.extend(self.notification_permission_issues)
        all_findings.extend(self.regional_preferences_issues)
        all_findings.extend(self.grammatical_inflection_issues)
        all_findings.extend(self.privacy_sandbox_issues)
        all_findings.extend(self.scoped_storage_issues)
        all_findings.extend(self.restricted_settings_issues)
        all_findings.extend(self.photo_picker_issues)
        all_findings.extend(self.background_activity_issues)
        return all_findings

    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics for the analysis."""
        all_findings = self.get_all_findings()

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        category_counts = {}

        for finding in all_findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1

        return {
            "total_findings": len(all_findings),
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
            "android_14_compliance": len(all_findings) == 0,
        }


class Android14SecurityAnalyzer:
    """
    Full Android 14+ security analyzer.

    Analyzes Android API 34+ specific security features and potential vulnerabilities
    that are introduced with modern Android security model changes.
    """

    def __init__(self, apk_ctx: APKContext):
        """Initialize the Android 14+ security analyzer."""
        self.apk_ctx = apk_ctx
        self.package_name = apk_ctx.package_name
        self.findings: List[Android14SecurityFinding] = []

        # Android 14+ API patterns and security implications
        self.android_14_patterns = self._initialize_android_14_patterns()

        logger.debug(f"Android 14+ Security Analyzer initialized for {self.package_name}")

    def _initialize_android_14_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize Android 14+ specific security patterns."""
        return {
            "predictive_back": {
                "patterns": [
                    r"OnBackInvokedDispatcher",
                    r"OnBackInvokedCallback",
                    r"setOnBackInvokedDispatcher",
                    r"registerOnBackInvokedCallback",
                    r"PRIORITY_DEFAULT",
                    r"PRIORITY_OVERLAY",
                    r"predictiveBackRoute",
                ],
                "security_concerns": [
                    "Improper back gesture handling can lead to navigation bypasses",
                    "Unvalidated back gesture callbacks may expose sensitive screens",
                    "Priority manipulation can interfere with security flows",
                ],
                "recommendations": [
                    "Validate all back gesture callbacks for security implications",
                    "Ensure sensitive screens properly handle predictive back",
                    "Use appropriate priority levels for back gesture handling",
                ],
            },
            "themed_icons": {
                "patterns": [
                    r"android:icon.*adaptive",
                    r"android:roundIcon",
                    r"android:theme.*DynamicColors",
                    r"DynamicColors\.applyToActivitiesIfAvailable",
                    r"MonetCompat",
                    r"android:colorPrimary.*@android:color/system_accent",
                ],
                "security_concerns": [
                    "Dynamic theming can be exploited for UI spoofing attacks",
                    "Adaptive icons may leak system color preferences",
                    "Theme manipulation can disguise malicious applications",
                ],
                "recommendations": [
                    "Validate themed icon resources for malicious content",
                    "Implement proper bounds checking for dynamic theming",
                    "Avoid exposing sensitive information through theme adaptation",
                ],
            },
            "notification_permissions": {
                "patterns": [
                    r"POST_NOTIFICATIONS",
                    r"NotificationManagerCompat\.areNotificationsEnabled",
                    r"requestPermission.*POST_NOTIFICATIONS",
                    r"NotificationManager\.IMPORTANCE_",
                    r"NotificationChannel.*setImportance",
                    r"PermissionChecker\.checkSelfPermission.*POST_NOTIFICATIONS",
                ],
                "security_concerns": [
                    "Runtime notification permissions can be bypassed",
                    "Notification importance manipulation may bypass user controls",
                    "Missing permission checks can lead to unauthorized notifications",
                ],
                "recommendations": [
                    "Always check POST_NOTIFICATIONS permission before sending notifications",
                    "Respect user notification preferences and importance levels",
                    "Implement graceful degradation when notification permission denied",
                ],
            },
            "regional_preferences": {
                "patterns": [
                    r"LocaleManager",
                    r"setApplicationLocales",
                    r"getApplicationLocales",
                    r"LOCALE_CONFIG",
                    r"android:localeConfig",
                    r"GrammaticalInflectionManager",
                    r"setRequestedGrammaticalGender",
                ],
                "security_concerns": [
                    "Locale manipulation can bypass region-specific security controls",
                    "Grammatical gender settings may leak user preferences",
                    "Regional preferences can be exploited for targeted attacks",
                ],
                "recommendations": [
                    "Validate locale changes against security policies",
                    "Protect grammatical preference data as sensitive information",
                    "Implement region-aware security controls",
                ],
            },
            "privacy_sandbox": {
                "patterns": [
                    r"AdServicesManager",
                    r"Topics.*API",
                    r"FLEDGE",
                    r"Attribution.*Reporting",
                    r"PrivacySandbox",
                    r"AdId.*Manager",
                    r"getTopics",
                    r"runAdAuction",
                ],
                "security_concerns": [
                    "Privacy sandbox APIs may leak user behavior data",
                    "Ad attribution can be exploited for user tracking",
                    "Topics API may expose sensitive user interests",
                ],
                "recommendations": [
                    "Minimize data collection through privacy sandbox APIs",
                    "Implement proper consent mechanisms for ad targeting",
                    "Regularly audit privacy sandbox usage for compliance",
                ],
            },
            "scoped_storage_enforcement": {
                "patterns": [
                    r"MANAGE_EXTERNAL_STORAGE",
                    r"requestLegacyExternalStorage.*false",
                    r"preserveLegacyExternalStorage.*false",
                    r"MediaStore\.createWriteRequest",
                    r"MediaStore\.createDeleteRequest",
                    r"MediaStore\.createTrashRequest",
                    r"StorageManager\.getPrimaryStorageVolume",
                ],
                "security_concerns": [
                    "Improper scoped storage usage can expose user files",
                    "Legacy storage access may bypass modern protections",
                    "Media store operations require proper permission handling",
                ],
                "recommendations": [
                    "Use scoped storage APIs instead of legacy file access",
                    "Implement proper media store request handling",
                    "Avoid requesting MANAGE_EXTERNAL_STORAGE unless necessary",
                ],
            },
            "restricted_settings": {
                "patterns": [
                    r"Settings\.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION",
                    r"Settings\.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
                    r"Settings\.ACTION_MANAGE_OVERLAY_PERMISSION",
                    r"Settings\.ACTION_ACCESSIBILITY_SETTINGS",
                    r"DevicePolicyManager.*setActiveAdmin",
                    r"SYSTEM_ALERT_WINDOW",
                ],
                "security_concerns": [
                    "Restricted settings access can be exploited for privilege escalation",
                    "Battery optimization bypasses may enable persistent malware",
                    "Overlay permissions can facilitate clickjacking attacks",
                ],
                "recommendations": [
                    "Justify restricted settings access with clear user benefit",
                    "Implement proper user consent flows for sensitive permissions",
                    "Monitor and audit restricted settings usage",
                ],
            },
            "photo_picker": {
                "patterns": [
                    r"ACTION_PICK_IMAGES",
                    r"MediaStore\.ACTION_PICK_IMAGES",
                    r"EXTRA_PICK_IMAGES_MAX",
                    r"PhotoPicker",
                    r"PickVisualMedia",
                    r"ActivityResultContracts\.PickMultipleVisualMedia",
                ],
                "security_concerns": [
                    "Photo picker bypass may access unauthorized images",
                    "Metadata leakage through selected photos",
                    "Improper photo picker usage can expose user privacy",
                ],
                "recommendations": [
                    "Use system photo picker instead of direct media access",
                    "Sanitize metadata from selected photos",
                    "Implement proper photo selection limits",
                ],
            },
            "background_activity": {
                "patterns": [
                    r"startActivity.*FLAG_ACTIVITY_NEW_TASK",
                    r"PendingIntent.*FLAG_IMMUTABLE",
                    r"JobScheduler.*setPersisted",
                    r"WorkManager.*setExpedited",
                    r"ForegroundService.*FOREGROUND_SERVICE_TYPE_",
                    r"NotificationManager.*startForeground",
                ],
                "security_concerns": [
                    "Background activity restrictions can be bypassed",
                    "Foreground service abuse may drain battery and resources",
                    "Improper pending intent usage can lead to privilege escalation",
                ],
                "recommendations": [
                    "Use proper foreground service types for background work",
                    "Implement immutable pending intents for security",
                    "Respect background activity restrictions",
                ],
            },
        }

    def analyze(self) -> Android14AnalysisResult:
        """
        Perform full Android 14+ security analysis.

        Returns:
            Android14AnalysisResult containing all findings
        """
        logger.info(f"Starting Android 14+ security analysis for {self.package_name}")

        result = Android14AnalysisResult()

        try:
            # Analyze each Android 14+ security category
            result.predictive_back_issues = self._analyze_predictive_back_security()
            result.themed_icon_issues = self._analyze_themed_icon_security()
            result.notification_permission_issues = self._analyze_notification_permission_security()
            result.regional_preferences_issues = self._analyze_regional_preferences_security()
            result.grammatical_inflection_issues = self._analyze_grammatical_inflection_security()
            result.privacy_sandbox_issues = self._analyze_privacy_sandbox_security()
            result.scoped_storage_issues = self._analyze_scoped_storage_security()
            result.restricted_settings_issues = self._analyze_restricted_settings_security()
            result.photo_picker_issues = self._analyze_photo_picker_security()
            result.background_activity_issues = self._analyze_background_activity_security()

            # Log summary
            stats = result.get_summary_stats()
            logger.info(
                f"Android 14+ analysis completed: {stats['total_findings']} findings across {len(stats['category_breakdown'])} categories"  # noqa: E501
            )

        except Exception as e:
            logger.error(f"Error during Android 14+ security analysis: {e}")
            raise

        return result

    def _analyze_predictive_back_security(self) -> List[Android14SecurityFinding]:
        """Analyze predictive back gesture security implementation."""
        findings = []

        patterns = self.android_14_patterns["predictive_back"]["patterns"]

        # Search for predictive back usage in source files
        for source_file in self.apk_ctx.source_files:
            try:
                with open(source_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        # Check for security issues in predictive back implementation
                        if self._has_predictive_back_security_issue(content, match):
                            finding = Android14SecurityFinding(
                                finding_id=f"android14_predictive_back_{len(findings)}",
                                title="Predictive Back Gesture Security Issue",
                                description=f"Potentially insecure predictive back gesture implementation found: {match.group()}",  # noqa: E501
                                severity="MEDIUM",
                                category="predictive_back",
                                confidence=0.7,
                                evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                affected_components=[source_file],
                                security_impact="Navigation bypass or sensitive screen exposure",
                                recommendations=self.android_14_patterns["predictive_back"]["recommendations"],
                                masvs_refs=["MSTG-PLATFORM-1", "MSTG-PLATFORM-11"],
                            )
                            findings.append(finding)

            except Exception as e:
                logger.debug(f"Error analyzing file {source_file} for predictive back: {e}")

        return findings

    def _analyze_themed_icon_security(self) -> List[Android14SecurityFinding]:
        """Analyze themed app icon security implementation."""
        findings = []

        patterns = self.android_14_patterns["themed_icons"]["patterns"]

        # Check manifest for themed icon configurations
        if self.apk_ctx.manifest_content:
            for pattern in patterns:
                matches = re.finditer(pattern, self.apk_ctx.manifest_content, re.IGNORECASE)
                for match in matches:
                    if self._has_themed_icon_security_issue(self.apk_ctx.manifest_content, match):
                        finding = Android14SecurityFinding(
                            finding_id=f"android14_themed_icon_{len(findings)}",
                            title="Themed Icon Security Vulnerability",
                            description=f"Potentially insecure themed icon configuration: {match.group()}",
                            severity="LOW",
                            category="themed_icons",
                            confidence=0.6,
                            evidence=[f"Pattern '{pattern}' found in AndroidManifest.xml"],
                            affected_components=["AndroidManifest.xml"],
                            security_impact="UI spoofing or theme manipulation attacks",
                            recommendations=self.android_14_patterns["themed_icons"]["recommendations"],
                            masvs_refs=["MSTG-PLATFORM-1"],
                        )
                        findings.append(finding)

        return findings

    def _analyze_notification_permission_security(self) -> List[Android14SecurityFinding]:
        """Analyze notification runtime permission security."""
        findings = []

        patterns = self.android_14_patterns["notification_permissions"]["patterns"]

        # Check for POST_NOTIFICATIONS permission in manifest
        has_notification_permission = False
        if self.apk_ctx.manifest_content:
            if "POST_NOTIFICATIONS" in self.apk_ctx.manifest_content:
                has_notification_permission = True

        # Search for notification usage in source files
        for source_file in self.apk_ctx.source_files:
            try:
                with open(source_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if self._has_notification_permission_security_issue(
                            content, match, has_notification_permission
                        ):
                            severity = "HIGH" if not has_notification_permission else "MEDIUM"
                            finding = Android14SecurityFinding(
                                finding_id=f"android14_notification_perm_{len(findings)}",
                                title="Notification Permission Security Issue",
                                description=f"Notification usage without proper permission handling: {match.group()}",
                                severity=severity,
                                category="notification_permissions",
                                confidence=0.8,
                                evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                affected_components=[source_file],
                                security_impact="Unauthorized notification access or permission bypass",
                                recommendations=self.android_14_patterns["notification_permissions"]["recommendations"],
                                masvs_refs=["MSTG-PLATFORM-1", "MSTG-PLATFORM-11"],
                            )
                            findings.append(finding)

            except Exception as e:
                logger.debug(f"Error analyzing file {source_file} for notification permissions: {e}")

        return findings

    def _analyze_regional_preferences_security(self) -> List[Android14SecurityFinding]:
        """Analyze regional preferences and locale security."""
        findings = []

        patterns = self.android_14_patterns["regional_preferences"]["patterns"]

        for source_file in self.apk_ctx.source_files:
            try:
                with open(source_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if self._has_regional_preferences_security_issue(content, match):
                            finding = Android14SecurityFinding(
                                finding_id=f"android14_regional_pref_{len(findings)}",
                                title="Regional Preferences Security Issue",
                                description=f"Potentially insecure regional preferences usage: {match.group()}",
                                severity="MEDIUM",
                                category="regional_preferences",
                                confidence=0.6,
                                evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                affected_components=[source_file],
                                security_impact="Locale manipulation or privacy leakage",
                                recommendations=self.android_14_patterns["regional_preferences"]["recommendations"],
                                masvs_refs=["MSTG-PRIVACY-1", "MSTG-PLATFORM-1"],
                            )
                            findings.append(finding)

            except Exception as e:
                logger.debug(f"Error analyzing file {source_file} for regional preferences: {e}")

        return findings

    def _analyze_grammatical_inflection_security(self) -> List[Android14SecurityFinding]:
        """Analyze grammatical inflection API security."""
        findings = []

        # This is a subset of regional preferences, so we look for specific grammatical patterns
        grammatical_patterns = [
            r"GrammaticalInflectionManager",
            r"setRequestedGrammaticalGender",
            r"getRequestedGrammaticalGender",
        ]

        for source_file in self.apk_ctx.source_files:
            try:
                with open(source_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern in grammatical_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        finding = Android14SecurityFinding(
                            finding_id=f"android14_grammatical_{len(findings)}",
                            title="Grammatical Inflection Privacy Issue",
                            description=f"Grammatical gender API usage may leak user preferences: {match.group()}",
                            severity="LOW",
                            category="grammatical_inflection",
                            confidence=0.7,
                            evidence=[f"Pattern '{pattern}' found in {source_file}"],
                            affected_components=[source_file],
                            security_impact="User preference privacy leakage",
                            recommendations=[
                                "Protect grammatical preference data as sensitive information",
                                "Implement proper consent for grammatical gender collection",
                                "Minimize storage and transmission of grammatical preferences",
                            ],
                            masvs_refs=["MSTG-PRIVACY-1", "MSTG-PRIVACY-3"],
                        )
                        findings.append(finding)

            except Exception as e:
                logger.debug(f"Error analyzing file {source_file} for grammatical inflection: {e}")

        return findings

    def _analyze_privacy_sandbox_security(self) -> List[Android14SecurityFinding]:
        """Analyze privacy sandbox API security."""
        findings = []

        patterns = self.android_14_patterns["privacy_sandbox"]["patterns"]

        for source_file in self.apk_ctx.source_files:
            try:
                with open(source_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if self._has_privacy_sandbox_security_issue(content, match):
                            finding = Android14SecurityFinding(
                                finding_id=f"android14_privacy_sandbox_{len(findings)}",
                                title="Privacy Sandbox Security Issue",
                                description=f"Potentially privacy-invasive sandbox API usage: {match.group()}",
                                severity="HIGH",
                                category="privacy_sandbox",
                                confidence=0.8,
                                evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                affected_components=[source_file],
                                security_impact="User behavior tracking or privacy violation",
                                recommendations=self.android_14_patterns["privacy_sandbox"]["recommendations"],
                                masvs_refs=["MSTG-PRIVACY-1", "MSTG-PRIVACY-2", "MSTG-PRIVACY-3"],
                            )
                            findings.append(finding)

            except Exception as e:
                logger.debug(f"Error analyzing file {source_file} for privacy sandbox: {e}")

        return findings

    def _analyze_scoped_storage_security(self) -> List[Android14SecurityFinding]:
        """Analyze scoped storage enforcement security."""
        findings = []

        patterns = self.android_14_patterns["scoped_storage_enforcement"]["patterns"]

        # Check manifest for legacy storage usage
        legacy_storage_used = False
        if self.apk_ctx.manifest_content:
            if "requestLegacyExternalStorage" in self.apk_ctx.manifest_content:
                legacy_storage_used = True

        for source_file in self.apk_ctx.source_files:
            try:
                with open(source_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if self._has_scoped_storage_security_issue(content, match, legacy_storage_used):
                            severity = "HIGH" if legacy_storage_used else "MEDIUM"
                            finding = Android14SecurityFinding(
                                finding_id=f"android14_scoped_storage_{len(findings)}",
                                title="Scoped Storage Security Issue",
                                description=f"Potentially insecure storage access pattern: {match.group()}",
                                severity=severity,
                                category="scoped_storage",
                                confidence=0.7,
                                evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                affected_components=[source_file],
                                security_impact="Unauthorized file access or storage bypass",
                                recommendations=self.android_14_patterns["scoped_storage_enforcement"][
                                    "recommendations"
                                ],
                                masvs_refs=["MSTG-STORAGE-1", "MSTG-STORAGE-2"],
                            )
                            findings.append(finding)

            except Exception as e:
                logger.debug(f"Error analyzing file {source_file} for scoped storage: {e}")

        return findings

    def _analyze_restricted_settings_security(self) -> List[Android14SecurityFinding]:
        """Analyze restricted settings API security."""
        findings = []

        patterns = self.android_14_patterns["restricted_settings"]["patterns"]

        for source_file in self.apk_ctx.source_files:
            try:
                with open(source_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if self._has_restricted_settings_security_issue(content, match):
                            finding = Android14SecurityFinding(
                                finding_id=f"android14_restricted_settings_{len(findings)}",
                                title="Restricted Settings Security Issue",
                                description=f"Potentially dangerous restricted settings access: {match.group()}",
                                severity="HIGH",
                                category="restricted_settings",
                                confidence=0.8,
                                evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                affected_components=[source_file],
                                security_impact="Privilege escalation or security bypass",
                                recommendations=self.android_14_patterns["restricted_settings"]["recommendations"],
                                masvs_refs=["MSTG-PLATFORM-1", "MSTG-PLATFORM-11"],
                            )
                            findings.append(finding)

            except Exception as e:
                logger.debug(f"Error analyzing file {source_file} for restricted settings: {e}")

        return findings

    def _analyze_photo_picker_security(self) -> List[Android14SecurityFinding]:
        """Analyze photo picker API security."""
        findings = []

        patterns = self.android_14_patterns["photo_picker"]["patterns"]

        for source_file in self.apk_ctx.source_files:
            try:
                with open(source_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if self._has_photo_picker_security_issue(content, match):
                            finding = Android14SecurityFinding(
                                finding_id=f"android14_photo_picker_{len(findings)}",
                                title="Photo Picker Security Issue",
                                description=f"Potentially insecure photo picker usage: {match.group()}",
                                severity="MEDIUM",
                                category="photo_picker",
                                confidence=0.6,
                                evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                affected_components=[source_file],
                                security_impact="Privacy violation or unauthorized media access",
                                recommendations=self.android_14_patterns["photo_picker"]["recommendations"],
                                masvs_refs=["MSTG-PRIVACY-1", "MSTG-STORAGE-1"],
                            )
                            findings.append(finding)

            except Exception as e:
                logger.debug(f"Error analyzing file {source_file} for photo picker: {e}")

        return findings

    def _analyze_background_activity_security(self) -> List[Android14SecurityFinding]:
        """Analyze background activity restriction security."""
        findings = []

        patterns = self.android_14_patterns["background_activity"]["patterns"]

        for source_file in self.apk_ctx.source_files:
            try:
                with open(source_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if self._has_background_activity_security_issue(content, match):
                            finding = Android14SecurityFinding(
                                finding_id=f"android14_background_activity_{len(findings)}",
                                title="Background Activity Security Issue",
                                description=f"Potentially insecure background activity pattern: {match.group()}",
                                severity="MEDIUM",
                                category="background_activity",
                                confidence=0.7,
                                evidence=[f"Pattern '{pattern}' found in {source_file}"],
                                affected_components=[source_file],
                                security_impact="Background restriction bypass or resource abuse",
                                recommendations=self.android_14_patterns["background_activity"]["recommendations"],
                                masvs_refs=["MSTG-PLATFORM-1", "MSTG-PLATFORM-7"],
                            )
                            findings.append(finding)

            except Exception as e:
                logger.debug(f"Error analyzing file {source_file} for background activity: {e}")

        return findings

    # Helper methods for security issue detection
    def _has_predictive_back_security_issue(self, content: str, match) -> bool:
        """Check if predictive back implementation has security issues."""
        # Look for missing validation or improper priority usage
        context = content[max(0, match.start() - 200) : match.end() + 200]

        security_indicators = [
            r"PRIORITY_OVERLAY.*without.*validation",
            r"registerOnBackInvokedCallback.*without.*check",
            r"OnBackInvokedCallback.*sensitive.*data",
        ]

        for indicator in security_indicators:
            if re.search(indicator, context, re.IGNORECASE):
                return True

        return False

    def _has_themed_icon_security_issue(self, content: str, match) -> bool:
        """Check if themed icon implementation has security issues."""
        # Look for dynamic theming without proper validation
        context = content[max(0, match.start() - 200) : match.end() + 200]

        return "DynamicColors" in context and "validation" not in context.lower()

    def _has_notification_permission_security_issue(self, content: str, match, has_permission: bool) -> bool:
        """Check if notification usage has permission security issues."""
        if not has_permission:
            return True  # Using notifications without declaring permission

        # Look for missing runtime permission checks
        context = content[max(0, match.start() - 200) : match.end() + 200]

        return "checkSelfPermission" not in context and "areNotificationsEnabled" not in context

    def _has_regional_preferences_security_issue(self, content: str, match) -> bool:
        """Check if regional preferences usage has security issues."""
        context = content[max(0, match.start() - 200) : match.end() + 200]

        # Look for locale manipulation without validation
        security_indicators = [
            r"setApplicationLocales.*without.*validation",
            r"LocaleManager.*user.*input",
            r"GrammaticalInflectionManager.*tracking",
        ]

        for indicator in security_indicators:
            if re.search(indicator, context, re.IGNORECASE):
                return True

        return False

    def _has_privacy_sandbox_security_issue(self, content: str, match) -> bool:
        """Check if privacy sandbox usage has security issues."""
        context = content[max(0, match.start() - 200) : match.end() + 200]

        # Look for excessive data collection or missing consent
        privacy_violations = [
            r"getTopics.*without.*consent",
            r"AdServicesManager.*tracking",
            r"runAdAuction.*user.*data",
        ]

        for violation in privacy_violations:
            if re.search(violation, context, re.IGNORECASE):
                return True

        return True  # Privacy sandbox usage is inherently privacy-sensitive

    def _has_scoped_storage_security_issue(self, content: str, match, legacy_used: bool) -> bool:
        """Check if scoped storage usage has security issues."""
        if legacy_used:
            return True  # Using legacy storage is a security issue

        context = content[max(0, match.start() - 200) : match.end() + 200]

        # Look for improper media store usage
        return "MANAGE_EXTERNAL_STORAGE" in context or "createWriteRequest" not in context

    def _has_restricted_settings_security_issue(self, content: str, match) -> bool:
        """Check if restricted settings usage has security issues."""
        context = content[max(0, match.start() - 200) : match.end() + 200]

        # Look for missing user consent or justification
        return "user.*consent" not in context.lower() and "permission.*request" not in context.lower()

    def _has_photo_picker_security_issue(self, content: str, match) -> bool:
        """Check if photo picker usage has security issues."""
        context = content[max(0, match.start() - 200) : match.end() + 200]

        # Look for direct media access instead of picker
        return "MediaStore.Images" in context or "EXTERNAL_STORAGE" in context

    def _has_background_activity_security_issue(self, content: str, match) -> bool:
        """Check if background activity usage has security issues."""
        context = content[max(0, match.start() - 200) : match.end() + 200]

        # Look for improper pending intent usage or foreground service abuse
        security_indicators = [
            r"PendingIntent.*FLAG_MUTABLE",
            r"startActivity.*background.*without.*check",
            r"ForegroundService.*without.*type",
        ]

        for indicator in security_indicators:
            if re.search(indicator, context, re.IGNORECASE):
                return True

        return False

    def cleanup(self):
        """Clean up resources used by the analyzer."""
        self.findings.clear()
        logger.debug("Android 14+ Security Analyzer cleanup completed")
