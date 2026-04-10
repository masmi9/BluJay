#!/usr/bin/env python3
"""
webview_security_analysis - BasePluginV2 Implementation (MASVS-PLATFORM-2)
============================================================================

Detects WebView security misconfigurations: JavaScript enabled, file access,
JavaScript interface bridges, mixed content, and unsafe URL loading.
"""

import re
import time
from pathlib import Path
from typing import List, Set

import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.plugins.base_plugin_v2 import (
    BasePluginV2,
    PluginMetadata,
    PluginResult,
    PluginFinding,
    PluginCapability,
    PluginStatus,
    PluginPriority,
)

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

# --- Detection patterns: (compiled_regex, short_label, title, description, severity, cwe, confidence) ---

_WEBVIEW_PATTERNS = [
    (
        re.compile(r'\.setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)'),
        "setAllowFileAccessFromFileURLs",
        "WebView File URL Cross-Origin Access",
        "setAllowFileAccessFromFileURLs(true) allows JavaScript running in a file:// URL context to access "
        "content from other file:// URLs. An attacker who can inject content into the WebView can read "
        "arbitrary local files via JavaScript.",
        "high",
        "CWE-200",
        0.90,
    ),
    (
        re.compile(r'\.setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)'),
        "setAllowUniversalAccessFromFileURLs",
        "WebView Universal File Access",
        "setAllowUniversalAccessFromFileURLs(true) allows JavaScript in file:// URLs to access content "
        "from any origin, bypassing same-origin policy entirely. This enables local file theft and "
        "cross-origin data exfiltration.",
        "critical",
        "CWE-200",
        0.95,
    ),
    (
        re.compile(r'\.setMixedContentMode\s*\(\s*(?:WebSettings\.)?MIXED_CONTENT_ALWAYS_ALLOW\s*\)'),
        "MIXED_CONTENT_ALWAYS_ALLOW",
        "WebView Mixed Content Allowed",
        "MIXED_CONTENT_ALWAYS_ALLOW permits loading HTTP resources inside HTTPS pages, enabling "
        "man-in-the-middle attacks to inject malicious scripts or content into the WebView.",
        "medium",
        "CWE-319",
        0.85,
    ),
    (
        re.compile(r'\.setAllowFileAccess\s*\(\s*true\s*\)'),
        "setAllowFileAccess",
        "WebView File Access Enabled",
        "setAllowFileAccess(true) allows the WebView to load file:// URLs. Combined with JavaScript "
        "enabled or JavaScript interfaces, this can enable local file reading attacks.",
        "medium",
        "CWE-200",
        0.70,
    ),
    (
        re.compile(r'\.setAllowContentAccess\s*\(\s*true\s*\)'),
        "setAllowContentAccess",
        "WebView Content Provider Access Enabled",
        "setAllowContentAccess(true) allows the WebView to load content:// URLs, potentially accessing "
        "sensitive data from content providers that are not protected by permissions.",
        "medium",
        "CWE-200",
        0.70,
    ),
    (
        re.compile(r'\.addJavascriptInterface\s*\('),
        "addJavascriptInterface",
        "WebView JavaScript Interface Bridge",
        "addJavascriptInterface() exposes Java objects to JavaScript running in the WebView. On API < 17, "
        "ALL public methods are accessible. Even on API >= 17 (with @JavascriptInterface), exposed "
        "methods can be called by any page loaded in the WebView, risking data theft or code execution.",
        "high",
        "CWE-749",
        0.85,
    ),
    (
        re.compile(r'\.setJavaScriptEnabled\s*\(\s*true\s*\)'),
        "setJavaScriptEnabled",
        "WebView JavaScript Enabled",
        "JavaScript is enabled in this WebView. If the WebView loads untrusted content or has other "
        "misconfigurations (file access, JS interfaces), this enables XSS and code execution attacks.",
        "low",
        "CWE-79",
        0.60,
    ),
    (
        re.compile(r'\.evaluateJavascript\s*\(\s*[^"\')\s]'),
        "evaluateJavascript_dynamic",
        "WebView Dynamic JavaScript Evaluation",
        "evaluateJavascript() is called with a non-literal argument, suggesting dynamically constructed "
        "JavaScript code. If the input contains user-controlled data, this enables code injection.",
        "high",
        "CWE-94",
        0.75,
    ),
    (
        re.compile(r'\.loadUrl\s*\(\s*[^"\')\s]'),
        "loadUrl_dynamic",
        "WebView Dynamic URL Loading",
        "WebView.loadUrl() is called with a non-literal argument, suggesting dynamically constructed "
        "URLs. If user input flows into this URL without validation, attackers can redirect the "
        "WebView to malicious pages or inject javascript: URIs.",
        "medium",
        "CWE-601",
        0.70,
    ),
    (
        re.compile(r'\.loadUrl\s*\(\s*["\']javascript:'),
        "loadUrl_javascript",
        "WebView JavaScript URI Execution",
        "WebView.loadUrl() is called with a javascript: URI, executing JavaScript directly in the "
        "WebView context. Ensure the JavaScript content is not derived from untrusted sources.",
        "medium",
        "CWE-94",
        0.75,
    ),
    (
        re.compile(r'\.setWebContentsDebuggingEnabled\s*\(\s*true\s*\)'),
        "setWebContentsDebuggingEnabled",
        "WebView Remote Debugging Enabled",
        "WebView remote debugging is enabled, allowing Chrome DevTools to inspect and modify WebView "
        "content at runtime. This must be disabled in production builds.",
        "medium",
        "CWE-489",
        0.90,
    ),
    (
        re.compile(r'\.setSavePassword\s*\(\s*true\s*\)'),
        "setSavePassword",
        "WebView Password Saving Enabled",
        "WebView password saving is enabled, which stores credentials in plaintext on the device. "
        "This API is deprecated and should not be used.",
        "medium",
        "CWE-312",
        0.85,
    ),
]

# Pattern for detecting WebViews that load URLs without a WebViewClient
# (default behavior navigates to browser for non-http schemes, allows all navigations)
_NO_WEBVIEWCLIENT = re.compile(
    r'(?:WebView|webView|webview|mWebView)\s*[.=].*\.loadUrl\s*\(',
    re.IGNORECASE,
)
_HAS_WEBVIEWCLIENT = re.compile(r'\.setWebViewClient\s*\(')


class WebviewSecurityAnalysisV2(BasePluginV2):
    """Detects WebView security misconfigurations (MASVS-PLATFORM-2)."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="webview_security_analysis",
            version="2.1.0",
            description="Detects WebView security misconfigurations: JS interfaces, file access, mixed content",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["webview", "masvs-platform-2"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        files_scanned = 0

        try:
            source_files = self._get_source_files(apk_ctx)
            for src_path in source_files:
                try:
                    content = Path(src_path).read_text(errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                files_scanned += 1
                rel_path = self._relative_path(src_path, apk_ctx)

                if self._is_library_code(rel_path):
                    continue

                # Skip files with no WebView relevance (fast path)
                if "WebView" not in content and "webView" not in content and "webview" not in content:
                    continue

                findings.extend(self._scan_webview_patterns(content, rel_path))
                findings.extend(self._check_missing_webviewclient(content, rel_path))

            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    "execution_time": time.time() - start_time,
                    "plugin_version": "2.1.0",
                    "files_scanned": files_scanned,
                },
            )

        except Exception as e:
            logger.error(f"webview_security_analysis failed: {e}")
            return PluginResult(
                status=PluginStatus.FAILURE,
                findings=findings,
                metadata={"error": str(e), "execution_time": time.time() - start_time},
            )

    # ------------------------------------------------------------------ helpers

    def _get_source_files(self, apk_ctx) -> List[str]:
        src = getattr(apk_ctx, "source_files", None)
        if src:
            if isinstance(src, dict):
                return [str(f) for f in src.keys() if str(f).endswith((".java", ".kt"))]
            return [str(f) for f in src if str(f).endswith((".java", ".kt"))]
        sources_dir = getattr(apk_ctx, "sources_dir", None)
        if sources_dir and Path(sources_dir).is_dir():
            return [str(p) for p in Path(sources_dir).rglob("*") if p.suffix in (".java", ".kt")]
        return []

    def _relative_path(self, full_path: str, apk_ctx) -> str:
        workspace = getattr(apk_ctx, "workspace_dir", None) or getattr(apk_ctx, "output_dir", None)
        if workspace:
            try:
                return str(Path(full_path).relative_to(workspace))
            except ValueError:
                pass
        parts = Path(full_path).parts
        if "sources" in parts:
            idx = parts.index("sources")
            return str(Path(*parts[idx:]))
        return Path(full_path).name

    def _line_number(self, content: str, pos: int) -> int:
        return content[:pos].count("\n") + 1

    def _snippet(self, content: str, start: int, end: int) -> str:
        line_start = content.rfind("\n", 0, start) + 1
        line_end = content.find("\n", end)
        if line_end == -1:
            line_end = len(content)
        return content[line_start:line_end].strip()[:200]

    # ------------------------------------------------------------------ checks

    def _scan_webview_patterns(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings: List[PluginFinding] = []
        seen_labels: Set[str] = set()

        for pattern, label, title, description, severity, cwe, confidence in _WEBVIEW_PATTERNS:
            if label in seen_labels:
                continue
            m = pattern.search(content)
            if m:
                seen_labels.add(label)
                findings.append(self.create_finding(
                    finding_id=f"webview_{label.lower()}_{len(findings):03d}",
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=confidence,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id=cwe,
                    masvs_control="MASVS-PLATFORM-2",
                    remediation=self._get_remediation(label),
                ))

        return findings

    def _check_missing_webviewclient(self, content: str, rel_path: str) -> List[PluginFinding]:
        """Flag WebViews that load URLs without setting a WebViewClient."""
        m = _NO_WEBVIEWCLIENT.search(content)
        if m and not _HAS_WEBVIEWCLIENT.search(content):
            return [self.create_finding(
                finding_id=f"webview_no_client_{0:03d}",
                title="WebView Without Custom WebViewClient",
                description=(
                    "This WebView loads URLs without setting a WebViewClient. The default behavior "
                    "opens external URLs in the system browser and allows all navigations without "
                    "validation. Set a WebViewClient with shouldOverrideUrlLoading() to control navigation."
                ),
                severity="low",
                confidence=0.60,
                file_path=rel_path,
                line_number=self._line_number(content, m.start()),
                code_snippet=self._snippet(content, m.start(), m.end()),
                cwe_id="CWE-862",
                masvs_control="MASVS-PLATFORM-2",
                remediation="Set a WebViewClient with shouldOverrideUrlLoading() to validate URLs before loading.",
            )]
        return []

    def _get_remediation(self, label: str) -> str:
        remediations = {
            "setAllowFileAccessFromFileURLs": (
                "Set setAllowFileAccessFromFileURLs(false). "
                "This is the default on API >= 16."
            ),
            "setAllowUniversalAccessFromFileURLs": (
                "Set setAllowUniversalAccessFromFileURLs(false). "
                "Never enable for WebViews loading remote content."
            ),
            "MIXED_CONTENT_ALWAYS_ALLOW": (
                "Use MIXED_CONTENT_NEVER_ALLOW or "
                "MIXED_CONTENT_COMPATIBILITY_MODE instead."
            ),
            "setAllowFileAccess": (
                "Set setAllowFileAccess(false) unless file:// access "
                "is explicitly required. Use assets or content "
                "providers instead."
            ),
            "setAllowContentAccess": (
                "Set setAllowContentAccess(false) unless content "
                "provider access is explicitly required."
            ),
            "addJavascriptInterface": (
                "Minimize exposed methods. Use @JavascriptInterface "
                "(API 17+). Validate all inputs from JavaScript."
            ),
            "setJavaScriptEnabled": (
                "Only enable JavaScript if required. Validate all "
                "content loaded into the WebView."
            ),
            "evaluateJavascript_dynamic": (
                "Never pass user-controlled input to "
                "evaluateJavascript(). Use parameterized "
                "messaging instead."
            ),
            "loadUrl_dynamic": (
                "Validate URLs against an allowlist before passing "
                "to loadUrl(). Block javascript: and data: schemes."
            ),
            "loadUrl_javascript": (
                "Avoid javascript: URIs. Use evaluateJavascript() "
                "(API 19+) with hardcoded scripts instead."
            ),
            "setWebContentsDebuggingEnabled": (
                "Disable WebView debugging in production: guard "
                "with BuildConfig.DEBUG check."
            ),
            "setSavePassword": (
                "Set setSavePassword(false). This API is deprecated "
                "since API 18."
            ),
        }
        return remediations.get(label, "Review and fix the WebView security configuration.")


# Plugin factory
def create_plugin() -> WebviewSecurityAnalysisV2:
    return WebviewSecurityAnalysisV2()


__all__ = ["WebviewSecurityAnalysisV2", "create_plugin"]
