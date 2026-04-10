"""
Clipboard Analyzer – detects insecure UIPasteboard usage.
"""
from __future__ import annotations

import re
from typing import List

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)


class ClipboardAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="clipboard_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            description="Detects insecure UIPasteboard usage and clipboard data exposure.",
            priority=PluginPriority.NORMAL,
            timeout_seconds=30,
            tags=["clipboard", "pasteboard", "data-exposure"],
            masvs_control="MASVS-STORAGE-3",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []
        strings_text = "\n".join(ipa_ctx.get_strings())

        # UIPasteboard usage
        if re.search(r'\bUIPasteboard\b', strings_text):
            # Check for sensitive data being set
            if re.search(r'(?i)pasteboard.*?(password|token|secret|credential|auth)', strings_text, re.DOTALL):
                findings.append(self.create_finding(
                    "clipboard_sensitive_data",
                    "Sensitive Data Written to Clipboard",
                    "UIPasteboard is used with what appears to be sensitive data (password, token, secret). "
                    "iOS clipboard is accessible to all apps – on iOS 14+, apps receive a banner notification "
                    "when reading clipboard content.",
                    "high",
                    confidence=0.75,
                    cwe_id="CWE-200",
                    masvs_control="MASVS-STORAGE-3",
                    remediation="Avoid placing sensitive data on the clipboard. "
                                "If unavoidable, clear the clipboard immediately after use and set an expiry.",
                ))
            else:
                # General clipboard use – informational
                findings.append(self.create_finding(
                    "clipboard_usage_detected",
                    "UIPasteboard Usage Detected",
                    "The app accesses UIPasteboard (clipboard). Verify no sensitive data "
                    "(passwords, tokens, PII) is written to or read from the clipboard.",
                    "info",
                    confidence=0.6,
                    cwe_id="CWE-200",
                    masvs_control="MASVS-STORAGE-3",
                    remediation="Audit all clipboard access. Avoid storing sensitive data in clipboard. "
                                "Use UITextInputTraits.isSecureTextEntry for password fields to disable copy.",
                ))

        # generalPasteboard (system-wide, highest risk)
        if re.search(r'UIPasteboard\.general|generalPasteboard', strings_text):
            findings.append(self.create_finding(
                "clipboard_general_pasteboard",
                "General (System-Wide) Pasteboard Used",
                "App uses the general system pasteboard, which is accessible by ALL apps on the device. "
                "This is appropriate for user-initiated copy/paste but not for background data.",
                "low",
                confidence=0.7,
                cwe_id="CWE-200",
                masvs_control="MASVS-STORAGE-3",
                remediation="Consider using named app-specific pasteboards (UIPasteboard(name:create:)) "
                            "for app-internal data transfer.",
            ))

        return self.create_result(PluginStatus.SUCCESS, findings)
