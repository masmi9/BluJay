"""
Keychain Analyzer – detects insecure Keychain accessibility attributes.

Checks for:
  - kSecAttrAccessibleAlways
  - kSecAttrAccessibleAlwaysThisDeviceOnly
  - Missing kSecAttrAccessible (defaults to insecure)
  - Keychain sharing with broad access groups
"""
from __future__ import annotations

import re
from typing import List

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)

_INSECURE_ATTRS = [
    ("kSecAttrAccessibleAlways", "critical",
     "Keychain item accessible ALWAYS (even when device locked)",
     "kSecAttrAccessibleAlways makes keychain items accessible even when the device is locked or "
     "after reboot. Items can be read by attackers with physical device access."),
    ("kSecAttrAccessibleAlwaysThisDeviceOnly", "high",
     "Keychain item accessible ALWAYS (this device only)",
     "kSecAttrAccessibleAlwaysThisDeviceOnly is accessible when locked. Prefer "
     "kSecAttrAccessibleWhenUnlockedThisDeviceOnly for sensitive data."),
]

_CLASSDUMP_SENSITIVE_PATTERNS = [
    r"SecItemAdd|SecItemUpdate|SecItemCopyMatching",
]


class KeychainAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="keychain_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            description="Detects insecure Keychain accessibility attributes and sharing misconfigurations.",
            priority=PluginPriority.HIGH,
            timeout_seconds=60,
            tags=["keychain", "data-storage", "credentials"],
            masvs_control="MASVS-STORAGE-1",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []

        # Search binary strings for insecure accessibility attributes
        strings = ipa_ctx.get_strings()
        strings_text = "\n".join(strings)

        for attr, severity, title, description in _INSECURE_ATTRS:
            if attr in strings_text:
                findings.append(self.create_finding(
                    f"keychain_{attr.lower()}",
                    title,
                    description,
                    severity,
                    confidence=0.85,
                    cwe_id="CWE-312",
                    masvs_control="MASVS-STORAGE-1",
                    owasp_category="M2: Insecure Data Storage",
                    evidence={"matched_string": attr},
                    remediation="Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly for sensitive items. "
                                "Never use kSecAttrAccessibleAlways in production.",
                    references=["https://developer.apple.com/documentation/security/keychain_services"],
                ))

        # Search classdump for insecure keychain usage patterns
        classdump_dir = ipa_ctx.classdump_dir
        if classdump_dir.exists():
            for hfile in classdump_dir.glob("*.h"):
                content = hfile.read_text(errors="replace")
                # Check if keychain is used but no accessibility attribute set
                if "SecItemAdd" in content and "kSecAttrAccessible" not in content:
                    findings.append(self.create_finding(
                        "keychain_no_accessibility_attr",
                        "Keychain Usage Without Explicit Accessibility Attribute",
                        "SecItemAdd called without kSecAttrAccessible. The default accessibility "
                        "can be less secure than intended.",
                        "medium",
                        confidence=0.7,
                        cwe_id="CWE-312",
                        masvs_control="MASVS-STORAGE-1",
                        file_path=str(hfile),
                        remediation="Always explicitly set kSecAttrAccessibleWhenUnlockedThisDeviceOnly.",
                    ))
                    break

        # Check entitlements for broad keychain-access-groups
        access_groups = ipa_ctx.get_entitlement("keychain-access-groups", [])
        if isinstance(access_groups, list) and len(access_groups) > 3:
            findings.append(self.create_finding(
                "keychain_broad_access_groups",
                "Excessive Keychain Access Groups",
                f"App declares {len(access_groups)} keychain-access-groups in entitlements. "
                "Broad access groups increase the attack surface for keychain data.",
                "low",
                confidence=0.7,
                cwe_id="CWE-312",
                masvs_control="MASVS-STORAGE-1",
                file_path="Entitlements.plist",
                evidence={"access_groups": access_groups},
                remediation="Limit keychain-access-groups to only those required.",
            ))

        return self.create_result(PluginStatus.SUCCESS, findings)
