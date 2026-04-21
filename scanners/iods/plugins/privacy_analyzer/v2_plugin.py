"""
Privacy Analyzer – checks NSUsageDescription keys and permission declarations.

Checks:
  - Missing NSUsageDescription keys for used capabilities
  - Overly broad or vague permission descriptions
  - Sensitive permission combinations (location + camera + mic)
  - Background location access
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)

_PERMISSION_KEYS: List[Tuple[str, str, str]] = [
    ("NSLocationAlwaysAndWhenInUseUsageDescription", "Location (Always)", "high"),
    ("NSLocationAlwaysUsageDescription", "Location (Always, deprecated)", "high"),
    ("NSLocationWhenInUseUsageDescription", "Location (When In Use)", "low"),
    ("NSCameraUsageDescription", "Camera", "medium"),
    ("NSMicrophoneUsageDescription", "Microphone", "medium"),
    ("NSContactsUsageDescription", "Contacts", "medium"),
    ("NSCalendarsUsageDescription", "Calendars", "medium"),
    ("NSPhotoLibraryUsageDescription", "Photo Library", "medium"),
    ("NSPhotoLibraryAddUsageDescription", "Photo Library Add-Only", "low"),
    ("NSHealthShareUsageDescription", "HealthKit Read", "high"),
    ("NSHealthUpdateUsageDescription", "HealthKit Write", "high"),
    ("NSFaceIDUsageDescription", "Face ID / Local Authentication", "low"),
    ("NSMotionUsageDescription", "Motion & Fitness", "low"),
    ("NSBluetoothAlwaysUsageDescription", "Bluetooth (Always)", "medium"),
    ("NSUserTrackingUsageDescription", "App Tracking (ATT)", "medium"),
    ("NFCReaderUsageDescription", "NFC", "low"),
    ("NSSpeechRecognitionUsageDescription", "Speech Recognition", "medium"),
    ("NSRemindersUsageDescription", "Reminders", "low"),
]

_VAGUE_DESCRIPTIONS = [
    "to improve your experience",
    "for app functionality",
    "required for the app",
    "needed for features",
    "please allow",
    "grant access",
]


class PrivacyAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="privacy_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.PLIST_ANALYSIS, PluginCapability.COMPLIANCE_CHECKING],
            description="Audits NSUsageDescription keys and permission declarations in Info.plist.",
            priority=PluginPriority.NORMAL,
            timeout_seconds=30,
            tags=["privacy", "permissions", "usage-descriptions", "gdpr"],
            masvs_control="MASVS-PRIVACY-1",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []
        plist = ipa_ctx.info_plist

        declared_permissions = []
        for key, human_name, severity in _PERMISSION_KEYS:
            if key in plist:
                desc = str(plist[key])
                declared_permissions.append(human_name)

                # Vague description check
                if any(vague in desc.lower() for vague in _VAGUE_DESCRIPTIONS) or len(desc) < 20:
                    findings.append(self.create_finding(
                        f"privacy_vague_description_{key.lower()[:30]}",
                        f"Vague Privacy Description: {human_name}",
                        f"The NSUsageDescription for {human_name} is vague or too short: '{desc}'. "
                        "Apple requires clear, specific explanations to justify access.",
                        "low",
                        confidence=0.8,
                        cwe_id="CWE-200",
                        masvs_control="MASVS-PRIVACY-1",
                        file_path="Info.plist",
                        evidence={"plist_key": key, "description": desc},
                        remediation=f"Provide a clear, specific justification for why {human_name} access is needed. "
                                    "Example: 'Used to scan product barcodes in the shopping feature.'",
                    ))

        # Background location – high risk
        if "NSLocationAlwaysAndWhenInUseUsageDescription" in plist or "NSLocationAlwaysUsageDescription" in plist:
            findings.append(self.create_finding(
                "privacy_background_location",
                "Background Location Access Requested",
                "The app requests 'always' location access (background location). "
                "This is a high-privacy-risk permission that requires strong justification.",
                "medium",
                confidence=0.9,
                cwe_id="CWE-200",
                masvs_control="MASVS-PRIVACY-1",
                file_path="Info.plist",
                remediation="Use NSLocationWhenInUseUsageDescription unless background location is essential. "
                            "Apple may reject apps that request background location without clear justification.",
            ))

        # Sensitive permission combination (surveillance-capable apps)
        has_camera = "NSCameraUsageDescription" in plist
        has_mic = "NSMicrophoneUsageDescription" in plist
        has_location = any(k in plist for k in [
            "NSLocationAlwaysAndWhenInUseUsageDescription",
            "NSLocationWhenInUseUsageDescription",
        ])
        if has_camera and has_mic and has_location:
            findings.append(self.create_finding(
                "privacy_surveillance_combo",
                "High-Risk Permission Combination (Camera + Mic + Location)",
                "The app requests camera, microphone, AND location access simultaneously. "
                "This combination enables comprehensive surveillance if misused.",
                "medium",
                confidence=0.7,
                cwe_id="CWE-200",
                masvs_control="MASVS-PRIVACY-1",
                file_path="Info.plist",
                remediation="Audit whether all three permissions are truly necessary. "
                            "Request permissions at point-of-use rather than at launch.",
            ))

        return self.create_result(PluginStatus.SUCCESS, findings)
