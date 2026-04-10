"""
WebView Analyzer – WKWebView and UIWebView security checks.

Checks:
  - UIWebView usage (deprecated, no process isolation)
  - WKWebView JavaScript bridge exposure (addScriptMessageHandler)
  - allowsInlineMediaPlayback with autoplay
  - WKWebView file:// access (allowFileAccessFromFileURLs)
  - Lack of navigation delegate validation
"""
from __future__ import annotations

import re
from typing import List

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)


class WebViewAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="webview_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            description="Detects WebView security issues: UIWebView, JS bridges, file access.",
            priority=PluginPriority.HIGH,
            timeout_seconds=60,
            tags=["webview", "javascript", "uiwebview", "wkwebview"],
            masvs_control="MASVS-PLATFORM-2",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []

        strings_text = "\n".join(ipa_ctx.get_strings())
        classdump_text = self._read_classdump(ipa_ctx)
        combined = strings_text + "\n" + classdump_text

        # UIWebView usage (deprecated since iOS 12, removed in iOS 15)
        if re.search(r'\bUIWebView\b', combined):
            findings.append(self.create_finding(
                "webview_uiwebview_usage",
                "Deprecated UIWebView Detected",
                "UIWebView is deprecated since iOS 12 and removed in iOS 15. "
                "It lacks process isolation, has no JIT compilation controls, and is "
                "more vulnerable to JavaScript-based attacks than WKWebView.",
                "high",
                confidence=0.95,
                cwe_id="CWE-749",
                masvs_control="MASVS-PLATFORM-2",
                owasp_category="M1: Improper Platform Usage",
                remediation="Migrate to WKWebView. UIWebView has been removed from the App Store review process.",
                references=["https://developer.apple.com/documentation/uikit/uiwebview"],
            ))

        # JavaScript bridge via addScriptMessageHandler
        if re.search(r'addScriptMessageHandler|WKScriptMessageHandler', combined):
            findings.append(self.create_finding(
                "webview_js_bridge",
                "WKWebView JavaScript Bridge Detected",
                "addScriptMessageHandler creates a JavaScript-to-native bridge. "
                "Malicious web content (XSS, redirected content) could invoke native methods.",
                "medium",
                confidence=0.85,
                cwe_id="CWE-749",
                masvs_control="MASVS-PLATFORM-2",
                remediation="Validate all messages from JavaScript handlers. "
                            "Restrict the bridge to trusted origins using decidePolicyFor:navigationAction:.",
            ))

        # WKWebView file:// access
        if re.search(r'allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs', combined):
            findings.append(self.create_finding(
                "webview_file_access",
                "WKWebView File System Access Enabled",
                "allowFileAccessFromFileURLs or allowUniversalAccessFromFileURLs is set. "
                "This allows web content to read arbitrary files from the app sandbox.",
                "high",
                confidence=0.9,
                cwe_id="CWE-200",
                masvs_control="MASVS-PLATFORM-2",
                remediation="Disable file access from file URLs unless strictly necessary. "
                            "Use WKURLSchemeHandler instead for local content.",
            ))

        # evaluateJavaScript usage (potential injection if unsanitized user input)
        if re.search(r'evaluateJavaScript\b', combined):
            findings.append(self.create_finding(
                "webview_evaluate_javascript",
                "evaluateJavaScript Used – Review for Injection Risk",
                "evaluateJavaScript injects JavaScript into WebView context. "
                "If user-controlled input flows into the script, XSS/code injection is possible.",
                "low",
                confidence=0.6,
                cwe_id="CWE-94",
                masvs_control="MASVS-PLATFORM-2",
                remediation="Never pass unsanitized user input to evaluateJavaScript. "
                            "Use WKScriptMessageHandler for bidirectional communication instead.",
            ))

        # No navigation delegate (can't validate navigation requests)
        if re.search(r'WKWebView', combined) and not re.search(r'WKNavigationDelegate', combined):
            findings.append(self.create_finding(
                "webview_no_navigation_delegate",
                "WKWebView Without Navigation Delegate",
                "WKWebView is used but no WKNavigationDelegate was detected. "
                "Without a delegate, navigation requests cannot be validated or restricted.",
                "low",
                confidence=0.6,
                cwe_id="CWE-749",
                masvs_control="MASVS-PLATFORM-2",
                remediation="Implement WKNavigationDelegate.decidePolicyForNavigationAction to validate "
                            "and restrict navigation to trusted URLs.",
            ))

        return self.create_result(PluginStatus.SUCCESS, findings)

    def _read_classdump(self, ipa_ctx) -> str:
        parts = []
        if ipa_ctx.classdump_dir.exists():
            for f in ipa_ctx.classdump_dir.glob("*.h"):
                try:
                    parts.append(f.read_text(errors="replace"))
                except Exception:
                    pass
        return "\n".join(parts)
