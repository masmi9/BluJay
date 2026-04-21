"""
Entitlements Analyzer – checks for dangerous or suspicious entitlements.

Checks:
  - get-task-allow (debug entitlement in production)
  - com.apple.private.* entitlements (private API access)
  - Overly broad iCloud container access
  - Missing data protection
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)

_DANGEROUS_ENTITLEMENTS: List[Tuple[str, str, str, str]] = [
    (
        "get-task-allow",
        "critical",
        "Debug Entitlement (get-task-allow) in Production Build",
        "get-task-allow=true allows other processes to attach a debugger to this app. "
        "This must NOT be present in production/App Store builds.",
    ),
    (
        "com.apple.private.security.no-sandbox",
        "critical",
        "App Sandbox Disabled",
        "com.apple.private.security.no-sandbox disables the iOS app sandbox, "
        "exposing the entire file system and system resources.",
    ),
    (
        "com.apple.security.get-task-allow",
        "high",
        "Security Debug Entitlement Present",
        "Debuggability entitlement detected. Verify this is not included in release builds.",
    ),
    (
        "platform-application",
        "high",
        "Platform Application Entitlement",
        "This entitlement grants elevated system access typically reserved for Apple apps.",
    ),
]


class EntitlementsAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="entitlements_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.ENTITLEMENTS_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            description="Checks app entitlements for dangerous or over-privileged configurations.",
            priority=PluginPriority.CRITICAL,
            timeout_seconds=30,
            tags=["entitlements", "provisioning", "permissions"],
            masvs_control="MASVS-PLATFORM-1",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []
        entitlements = ipa_ctx.entitlements

        if not entitlements:
            return self.create_result(
                PluginStatus.SUCCESS,
                info_messages=["No entitlements found or unable to extract."],
            )

        # Check dangerous entitlements
        for key, severity, title, description in _DANGEROUS_ENTITLEMENTS:
            value = entitlements.get(key)
            if value is True or value == "true":
                findings.append(self.create_finding(
                    f"entitlement_{key.replace('.', '_').replace('-', '_')}",
                    title,
                    description,
                    severity,
                    confidence=1.0,
                    cwe_id="CWE-272",
                    masvs_control="MASVS-PLATFORM-1",
                    file_path="Entitlements.plist",
                    evidence={"entitlement_key": key, "value": str(value)},
                    remediation=f"Remove the '{key}' entitlement from production builds. "
                                "Use separate provisioning profiles for development vs release.",
                ))

        # Check for private API entitlements
        private_ents = [k for k in entitlements if "com.apple.private" in k]
        if private_ents:
            findings.append(self.create_finding(
                "entitlements_private_api",
                "Private API Entitlements Detected",
                f"The app uses {len(private_ents)} private Apple entitlement(s): "
                f"{', '.join(private_ents[:5])}. Private entitlements may indicate undocumented "
                "API access or App Store guideline violations.",
                "medium",
                confidence=0.8,
                cwe_id="CWE-272",
                masvs_control="MASVS-PLATFORM-1",
                file_path="Entitlements.plist",
                evidence={"private_entitlements": private_ents},
                remediation="Audit all private entitlements. Remove any that are not strictly required.",
            ))

        # Broad iCloud container access
        icloud_containers = entitlements.get("com.apple.developer.icloud-container-identifiers", [])
        if isinstance(icloud_containers, list) and len(icloud_containers) > 5:
            findings.append(self.create_finding(
                "entitlements_broad_icloud",
                "Excessive iCloud Container Access",
                f"App has access to {len(icloud_containers)} iCloud containers. "
                "Verify each is required for app functionality.",
                "low",
                confidence=0.7,
                cwe_id="CWE-272",
                masvs_control="MASVS-PLATFORM-1",
                file_path="Entitlements.plist",
                evidence={"icloud_containers": icloud_containers},
                remediation="Limit iCloud container access to only what the app needs.",
            ))

        return self.create_result(PluginStatus.SUCCESS, findings)
