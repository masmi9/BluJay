#!/usr/bin/env python3
"""
deep_link_analyzer - BasePluginV2 Implementation (MASVS-PLATFORM-3)
====================================================================

Detects deep link and URL scheme security issues:
- Custom schemes without App Links verification
- Intent.parseUri() with unvalidated input
- Deep link parameters passed to WebView.loadUrl()
- Missing input validation in deep link handlers
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

# --- Source code patterns ---

_DEEPLINK_SOURCE_PATTERNS = [
    (
        re.compile(r'Intent\.parseUri\s*\('),
        "Intent.parseUri",
        "Intent Parsing from URI",
        "Intent.parseUri() creates an Intent from a URI string. If the URI is user-controlled "
        "(e.g., from a deep link), an attacker can craft a URI that targets internal components, "
        "bypasses access controls, or triggers unintended actions.",
        "high",
        "CWE-939",
        0.85,
    ),
    (
        re.compile(r'getIntent\(\)\.getData\(\).*loadUrl\s*\(|getData\(\)\.toString\(\).*loadUrl\s*\('),
        "deeplink_to_webview",
        "Deep Link Data Passed to WebView",
        "Data from a deep link Intent is passed to WebView.loadUrl(). An attacker can craft a "
        "deep link that loads arbitrary URLs or injects javascript: URIs in the WebView.",
        "high",
        "CWE-939",
        0.80,
    ),
    (
        re.compile(r'getQueryParameter\s*\([^)]+\)\s*.*(?:loadUrl|evaluateJavascript|startActivity)\s*\('),
        "deeplink_param_injection",
        "Deep Link Parameter Used in Sensitive Operation",
        "A deep link query parameter is used directly in a sensitive operation (loadUrl, "
        "evaluateJavascript, or startActivity) without validation. This enables injection "
        "attacks through crafted deep links.",
        "high",
        "CWE-939",
        0.75,
    ),
    (
        re.compile(r'Uri\.parse\s*\([^)]*getStringExtra\s*\('),
        "uri_from_extra",
        "URI Constructed from Intent Extra",
        "A URI is constructed from an Intent extra, which can be controlled by an external app. "
        "Without validation, this can redirect to malicious URLs or access local files.",
        "medium",
        "CWE-939",
        0.70,
    ),
    (
        re.compile(
            r'startActivity\s*\(\s*(?:new\s+)?Intent\s*\('
            r'\s*Intent\.ACTION_VIEW\s*,\s*(?:uri|data|url)',
            re.IGNORECASE,
        ),
        "unvalidated_view_intent",
        "Unvalidated ACTION_VIEW Intent",
        "An ACTION_VIEW Intent is created with a potentially unvalidated URI. If the URI comes "
        "from user input or deep link data, it could open malicious URLs or trigger other apps.",
        "medium",
        "CWE-939",
        0.65,
    ),
]

# Manifest patterns for deep link declarations
_DEEPLINK_SCHEME = re.compile(
    r'<data\s+[^>]*android:scheme\s*=\s*"([^"]+)"[^>]*/?>',
    re.IGNORECASE,
)
_AUTOVERIFY = re.compile(r'android:autoVerify\s*=\s*"true"', re.IGNORECASE)
_INTENT_FILTER = re.compile(r'<intent-filter\b[^>]*>(.*?)</intent-filter>', re.DOTALL | re.IGNORECASE)
_BROWSABLE = re.compile(r'android\.intent\.category\.BROWSABLE', re.IGNORECASE)
_DEEPLINK_HOST = re.compile(r'<data\s+[^>]*android:host\s*=\s*"([^"]+)"', re.IGNORECASE)
_BROAD_PATH_PREFIX = re.compile(r'android:pathPrefix\s*=\s*"/"', re.IGNORECASE)


class DeepLinkAnalyzerV2(BasePluginV2):
    """Detects deep link and URL scheme security issues (MASVS-PLATFORM-3)."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="deep_link_analyzer",
            version="1.0.0",
            description="Detects deep link and URL scheme security issues",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["deeplink", "url-scheme", "masvs-platform-3"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        files_scanned = 0

        try:
            # Check manifest for deep link declarations
            findings.extend(self._check_manifest_deeplinks(apk_ctx))

            # Scan source files for deep link handling patterns
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

                findings.extend(self._scan_source_patterns(content, rel_path))

            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    "execution_time": time.time() - start_time,
                    "plugin_version": "1.0.0",
                    "files_scanned": files_scanned,
                },
            )

        except Exception as e:
            logger.error(f"deep_link_analyzer failed: {e}")
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

    def _check_manifest_deeplinks(self, apk_ctx) -> List[PluginFinding]:
        """Check AndroidManifest.xml for insecure deep link declarations."""
        manifest_path = getattr(apk_ctx, "manifest_path", None)
        if not manifest_path:
            workspace = getattr(apk_ctx, "workspace_dir", None) or getattr(apk_ctx, "output_dir", None)
            if workspace:
                candidate = Path(workspace) / "AndroidManifest.xml"
                if candidate.exists():
                    manifest_path = str(candidate)

        if not manifest_path or not Path(manifest_path).exists():
            return []

        try:
            content = Path(manifest_path).read_text(errors="replace")
        except (OSError, UnicodeDecodeError):
            return []

        findings = []
        seen_schemes: Set[str] = set()

        for intent_filter_m in _INTENT_FILTER.finditer(content):
            filter_text = intent_filter_m.group(1)
            if not _BROWSABLE.search(filter_text):
                continue

            # Find scheme declarations in this intent-filter
            for scheme_m in _DEEPLINK_SCHEME.finditer(filter_text):
                scheme = scheme_m.group(1).lower()
                if scheme in seen_schemes:
                    continue
                seen_schemes.add(scheme)

                # Check for custom schemes (non-http/https) without autoVerify
                if scheme not in ("http", "https"):
                    # Custom scheme - these can be registered by any app
                    has_autoverify = _AUTOVERIFY.search(intent_filter_m.group(0))
                    if not has_autoverify:
                        findings.append(self.create_finding(
                            finding_id=f"deeplink_custom_scheme_{len(findings):03d}",
                            title=f"Custom URL Scheme Without Verification: {scheme}://",
                            description=(
                                f"Custom URL scheme '{scheme}://' is declared as BROWSABLE without "
                                "autoVerify. Any app can register the same scheme, leading to scheme "
                                "collision. An attacker's app could intercept deep links intended for "
                                "this app. Use App Links (https with autoVerify) instead."
                            ),
                            severity="medium",
                            confidence=0.75,
                            file_path="AndroidManifest.xml",
                            line_number=self._line_number(content, intent_filter_m.start()),
                            code_snippet=self._snippet(content, intent_filter_m.start(), intent_filter_m.end()),
                            cwe_id="CWE-939",
                            masvs_control="MASVS-PLATFORM-3",
                            remediation=(
                                "Prefer HTTPS App Links with android:autoVerify=\"true\" and a valid "
                                "assetlinks.json on your server. If custom schemes are required, validate "
                                "all incoming data from deep link Intents."
                            ),
                        ))

                # AH-4: autoVerify with http-only scheme (should be https)
                if scheme == "http":
                    has_autoverify = _AUTOVERIFY.search(intent_filter_m.group(0))
                    has_https = any(
                        s.group(1).lower() == "https"
                        for s in _DEEPLINK_SCHEME.finditer(filter_text)
                    )
                    if has_autoverify and not has_https:
                        findings.append(self.create_finding(
                            finding_id=f"deeplink_http_autoverify_{len(findings):03d}",
                            title="App Links: autoVerify with HTTP scheme only",
                            description=(
                                "Intent filter declares autoVerify=\"true\" with scheme=\"http\" "
                                "but no scheme=\"https\". App Links verification requires HTTPS."
                            ),
                            severity="medium", confidence=0.75,
                            file_path="AndroidManifest.xml",
                            line_number=self._line_number(content, intent_filter_m.start()),
                            cwe_id="CWE-350", masvs_control="MASVS-PLATFORM-3",
                            remediation="Add android:scheme=\"https\" for proper App Links verification",
                        ))

                # AH-4: wildcard host with autoVerify
                for host_m in _DEEPLINK_HOST.finditer(filter_text):
                    host = host_m.group(1)
                    if host == "*" and _AUTOVERIFY.search(intent_filter_m.group(0)):
                        findings.append(self.create_finding(
                            finding_id=f"deeplink_wildcard_host_{len(findings):03d}",
                            title="App Links: Wildcard host with autoVerify",
                            description=(
                                "Intent filter uses a wildcard host \"*\" with autoVerify. "
                                "Wildcard hosts cannot be verified via assetlinks.json."
                            ),
                            severity="medium", confidence=0.80,
                            file_path="AndroidManifest.xml",
                            line_number=self._line_number(content, intent_filter_m.start()),
                            cwe_id="CWE-350", masvs_control="MASVS-PLATFORM-3",
                            remediation="Use specific domain hosts instead of wildcards for App Links",
                        ))

        # AH-4: Partial autoVerify coverage across intent filters
        all_hosts = set()
        verified_hosts = set()
        for intent_filter_m in _INTENT_FILTER.finditer(content):
            filter_text = intent_filter_m.group(1)
            has_verify = bool(_AUTOVERIFY.search(intent_filter_m.group(0)))
            for host_m in _DEEPLINK_HOST.finditer(filter_text):
                host = host_m.group(1)
                if host != "*":
                    all_hosts.add(host)
                    if has_verify:
                        verified_hosts.add(host)
        unverified = all_hosts - verified_hosts
        if verified_hosts and unverified:
            findings.append(self.create_finding(
                finding_id=f"deeplink_partial_verify_{len(findings):03d}",
                title=f"App Links: Partial autoVerify ({len(verified_hosts)}/{len(all_hosts)} hosts)",
                description=(
                    f"App declares {len(all_hosts)} deep link hosts but only "
                    f"{len(verified_hosts)} have autoVerify. On Android < 12, partial "
                    "verification causes ALL links to fall back to the disambiguation dialog. "
                    f"Unverified hosts: {', '.join(sorted(unverified)[:5])}"
                ),
                severity="high", confidence=0.80,
                file_path="AndroidManifest.xml", line_number=None,
                cwe_id="CWE-350", masvs_control="MASVS-PLATFORM-3",
                remediation="Add autoVerify=\"true\" to ALL intent filters with deep link hosts",
            ))

        return findings

    def _scan_source_patterns(self, content: str, rel_path: str) -> List[PluginFinding]:
        """Scan source file for deep link handling patterns."""
        findings = []
        seen_labels: Set[str] = set()

        for pattern, label, title, description, severity, cwe, confidence in _DEEPLINK_SOURCE_PATTERNS:
            if label in seen_labels:
                continue
            m = pattern.search(content)
            if m:
                seen_labels.add(label)
                findings.append(self.create_finding(
                    finding_id=f"deeplink_{label.lower()}_{len(findings):03d}",
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=confidence,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id=cwe,
                    masvs_control="MASVS-PLATFORM-3",
                    remediation="Validate all deep link parameters before use. Prefer App Links with autoVerify.",
                ))

        return findings


# Plugin factory
def create_plugin() -> DeepLinkAnalyzerV2:
    return DeepLinkAnalyzerV2()


__all__ = ["DeepLinkAnalyzerV2", "create_plugin"]
