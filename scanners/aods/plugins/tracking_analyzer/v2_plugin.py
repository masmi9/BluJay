#!/usr/bin/env python3
"""
tracking_analyzer - BasePluginV2 Implementation (MASVS-PRIVACY-4)
==================================================================

Detects user tracking mechanisms, advertising ID usage without LAT check,
device fingerprinting, and tracking SDK integrations.

Complementary to privacy_leak_detection (which covers Firebase Analytics,
Google Analytics, Facebook SDK). This plugin focuses on attribution/MMP SDKs,
fingerprinting techniques, and ad-tech integrations.
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Set
from xml.etree import ElementTree

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

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# --- Detection patterns ---

# Ad ID access without LAT (Limit Ad Tracking) check
_AD_ID_PATTERN = re.compile(r"AdvertisingIdClient\s*\.\s*getAdvertisingIdInfo\s*\(")
_LAT_CHECK_PATTERN = re.compile(r"isLimitAdTrackingEnabled\s*\(")

# Tracking / attribution SDKs (NOT covered by privacy_leak_detection)
_TRACKING_SDKS = [
    (re.compile(r"com\.appsflyer"), "AppsFlyer"),
    (re.compile(r"com\.adjust\.sdk"), "Adjust"),
    (re.compile(r"io\.branch"), "Branch.io"),
    (re.compile(r"com\.moengage"), "MoEngage"),
    (re.compile(r"com\.braze"), "Braze"),
    (re.compile(r"com\.singular\.sdk"), "Singular"),
    (re.compile(r"com\.kochava"), "Kochava"),
    (re.compile(r"com\.tenjin"), "Tenjin"),
]

# Fingerprinting signals - >=3 in the same file is suspicious
_FINGERPRINT_SIGNALS = [
    re.compile(r"Build\.FINGERPRINT"),
    re.compile(r"Build\.MODEL"),
    re.compile(r"Build\.MANUFACTURER"),
    re.compile(r"Settings\.Secure.*ANDROID_ID"),
    re.compile(r"getLine1Number\s*\("),
    re.compile(r"SensorManager"),
    re.compile(r"DisplayMetrics"),
    re.compile(r"Build\.BOARD"),
    re.compile(r"Build\.HARDWARE"),
]
_FINGERPRINT_THRESHOLD = 3

# AppSet ID
_APPSET_PATTERN = re.compile(r"com\.google\.android\.gms\.appset")

# WebView tracking: WebView + JS enabled + cookie/localStorage
_WEBVIEW_PATTERN = re.compile(r"WebView")
_JS_ENABLED_PATTERN = re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)")
_COOKIE_STORAGE_PATTERN = re.compile(r"CookieManager|localStorage|sessionStorage|document\.cookie")


class TrackingAnalyzerV2(BasePluginV2):
    """Detects user tracking mechanisms and fingerprinting (MASVS-PRIVACY-4)."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="tracking_analyzer",
            version="2.1.0",
            description="Detects tracking SDKs, advertising ID misuse, and device fingerprinting",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["privacy", "masvs-privacy-4"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        files_scanned = 0

        try:
            # --- Source file analysis ---
            source_files = self._get_source_files(apk_ctx)
            for src_path in source_files:
                try:
                    content = Path(src_path).read_text(errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                files_scanned += 1
                rel_path = self._relative_path(src_path, apk_ctx)

                is_lib = self._is_library_code(rel_path)

                # Tracking SDK detection runs on ALL files (detecting SDK presence is intentional)
                findings.extend(self._check_tracking_sdks(content, rel_path))

                # Skip library code for vulnerability-oriented checks
                if is_lib:
                    continue

                findings.extend(self._check_ad_id_without_lat(content, rel_path))
                findings.extend(self._check_fingerprinting(content, rel_path))
                findings.extend(self._check_appset_id(content, rel_path))
                findings.extend(self._check_webview_tracking(content, rel_path))

            # --- Manifest analysis ---
            manifest_path = self._get_manifest_path(apk_ctx)
            if manifest_path:
                findings.extend(self._check_manifest_ad_metadata(manifest_path))

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
            logger.error(f"tracking_analyzer failed: {e}")
            return PluginResult(
                status=PluginStatus.FAILURE,
                findings=findings,
                metadata={"error": str(e), "execution_time": time.time() - start_time},
            )

    # ------------------------------------------------------------------ helpers

    def _get_source_files(self, apk_ctx) -> List[str]:
        src = getattr(apk_ctx, "source_files", None)
        if src:
            return [str(f) for f in src if str(f).endswith((".java", ".kt"))]
        sources_dir = getattr(apk_ctx, "sources_dir", None)
        if sources_dir and Path(sources_dir).is_dir():
            return [str(p) for p in Path(sources_dir).rglob("*") if p.suffix in (".java", ".kt")]
        return []

    def _get_manifest_path(self, apk_ctx) -> Optional[str]:
        mp = getattr(apk_ctx, "manifest_path", None)
        if mp and Path(mp).is_file():
            return str(mp)
        return None

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

    def _line_number(self, content: str, match_start: int) -> int:
        return content[:match_start].count("\n") + 1

    def _snippet(self, content: str, match_start: int, match_end: int) -> str:
        line_start = content.rfind("\n", 0, match_start) + 1
        line_end = content.find("\n", match_end)
        if line_end == -1:
            line_end = len(content)
        return content[line_start:line_end].strip()[:200]

    # ------------------------------------------------------------------ checks

    def _check_ad_id_without_lat(self, content: str, rel_path: str) -> List[PluginFinding]:
        m = _AD_ID_PATTERN.search(content)
        if not m:
            return []
        if _LAT_CHECK_PATTERN.search(content):
            return []
        return [self.create_finding(
            finding_id="tracking_ad_id_no_lat_000",
            title="Advertising ID Used Without LAT Check",
            description=(
                "AdvertisingIdClient.getAdvertisingIdInfo() is called without checking "
                "isLimitAdTrackingEnabled(). Users who opt out of ad tracking are still tracked."
            ),
            severity="high",
            confidence=0.85,
            file_path=rel_path,
            line_number=self._line_number(content, m.start()),
            code_snippet=self._snippet(content, m.start(), m.end()),
            cwe_id="CWE-359",
            masvs_control="MASVS-PRIVACY-4",
            remediation=(
                "Always check isLimitAdTrackingEnabled() before using the advertising ID. "
                "If LAT is enabled, do not use the ID for tracking or ad personalization."
            ),
        )]

    def _check_tracking_sdks(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings = []
        seen: Set[str] = set()
        for pattern, sdk_name in _TRACKING_SDKS:
            m = pattern.search(content)
            if m and sdk_name not in seen:
                seen.add(sdk_name)
                findings.append(self.create_finding(
                    finding_id=f"tracking_sdk_{len(findings):03d}",
                    title=f"Tracking SDK Detected: {sdk_name}",
                    description=(
                        f"Import of {sdk_name} tracking/attribution SDK detected. "
                        "This SDK collects user data for attribution and analytics. "
                        "Ensure proper user consent and privacy policy disclosure."
                    ),
                    severity="medium",
                    confidence=0.9,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id="CWE-359",
                    masvs_control="MASVS-PRIVACY-4",
                    remediation=(
                        f"Document {sdk_name} usage in your privacy policy. "
                        "Implement opt-out mechanisms and honor user tracking preferences."
                    ),
                ))
        return findings

    def _check_fingerprinting(self, content: str, rel_path: str) -> List[PluginFinding]:
        matches = []
        for pattern in _FINGERPRINT_SIGNALS:
            m = pattern.search(content)
            if m:
                matches.append(m)

        if len(matches) < _FINGERPRINT_THRESHOLD:
            return []

        # Skip emulator detection code - Build properties used for anti-tamper/RE
        # are defensive, not fingerprinting for tracking purposes
        emulator_indicators = (
            "isemulator", "emulator", "check_emulator",
            "\"generic\"", "\"goldfish\"", "\"sdk_gphone\"",
            "\"google_sdk\"", "\"vbox\"", "\"nox\"",
            "EmulatorDetect", "isRunningOnEmulator",
        )
        content_lower = content.lower()
        emulator_hits = sum(1 for ind in emulator_indicators if ind.lower() in content_lower)
        if emulator_hits >= 2:
            return []

        signals = ", ".join(m.group(0) for m in matches[:5])
        first_match = min(matches, key=lambda x: x.start())
        return [self.create_finding(
            finding_id="tracking_fingerprint_000",
            title=f"Device Fingerprinting Detected ({len(matches)} signals)",
            description=(
                f"File collects {len(matches)} device fingerprinting signals: {signals}. "
                "Combining multiple device attributes can uniquely identify users "
                "without consent, violating privacy regulations."
            ),
            severity="high",
            confidence=0.75,
            file_path=rel_path,
            line_number=self._line_number(content, first_match.start()),
            cwe_id="CWE-359",
            masvs_control="MASVS-PRIVACY-4",
            remediation=(
                "Avoid collecting multiple device attributes for fingerprinting. "
                "Use privacy-preserving identifiers (e.g., App Set ID) instead."
            ),
        )]

    def _check_appset_id(self, content: str, rel_path: str) -> List[PluginFinding]:
        m = _APPSET_PATTERN.search(content)
        if not m:
            return []
        return [self.create_finding(
            finding_id="tracking_appset_000",
            title="App Set ID Usage",
            description=(
                "App Set ID (com.google.android.gms.appset) is used. This ID is shared "
                "across apps from the same developer and can enable cross-app analytics."
            ),
            severity="info",
            confidence=0.9,
            file_path=rel_path,
            line_number=self._line_number(content, m.start()),
            code_snippet=self._snippet(content, m.start(), m.end()),
            cwe_id="CWE-359",
            masvs_control="MASVS-PRIVACY-4",
            remediation="Document App Set ID usage in your privacy policy.",
        )]

    def _check_webview_tracking(self, content: str, rel_path: str) -> List[PluginFinding]:
        if not _WEBVIEW_PATTERN.search(content):
            return []
        js_match = _JS_ENABLED_PATTERN.search(content)
        if not js_match:
            return []
        if not _COOKIE_STORAGE_PATTERN.search(content):
            return []
        return [self.create_finding(
            finding_id="tracking_webview_000",
            title="WebView Tracking via Cookies/Storage",
            description=(
                "WebView with JavaScript enabled uses cookies or localStorage, "
                "which can enable cross-site tracking and user profiling."
            ),
            severity="medium",
            confidence=0.7,
            file_path=rel_path,
            line_number=self._line_number(content, js_match.start()),
            code_snippet=self._snippet(content, js_match.start(), js_match.end()),
            cwe_id="CWE-359",
            masvs_control="MASVS-PRIVACY-4",
            remediation=(
                "Clear cookies and localStorage between sessions. "
                "Consider using WebView with cookie restrictions or SameSite policy."
            ),
        )]

    def _check_manifest_ad_metadata(self, manifest_path: str) -> List[PluginFinding]:
        try:
            tree = ElementTree.parse(manifest_path)
            root = tree.getroot()
        except (ElementTree.ParseError, OSError):
            return []

        for elem in root.iter("meta-data"):
            name = elem.get(f"{ANDROID_NS}name") or elem.get("name") or ""
            if name == "com.google.android.gms.ads.APPLICATION_ID":
                return [self.create_finding(
                    finding_id="tracking_ad_meta_000",
                    title="AdMob/Google Ads Integration",
                    description=(
                        "Manifest declares com.google.android.gms.ads.APPLICATION_ID metadata, "
                        "indicating Google AdMob or Google Ads SDK integration. "
                        "Ad SDKs collect device data for ad targeting."
                    ),
                    severity="info",
                    confidence=0.95,
                    file_path="AndroidManifest.xml",
                    cwe_id="CWE-359",
                    masvs_control="MASVS-PRIVACY-4",
                    remediation=(
                        "Ensure ad SDK usage is disclosed in the privacy policy. "
                        "Implement GDPR/CCPA consent mechanisms before loading ads."
                    ),
                )]
        return []


# Plugin factory
def create_plugin() -> TrackingAnalyzerV2:
    return TrackingAnalyzerV2()


__all__ = ["TrackingAnalyzerV2", "create_plugin"]
