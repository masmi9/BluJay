#!/usr/bin/env python3
"""
privacy_leak_detection - Sensitive Data Leak Detection
======================================================

Detects sensitive data flowing to insecure channels: clipboard, intents,
notifications, WebView URLs, and SharedPreferences in world-readable mode.

MASVS-STORAGE-1: Secure Data Storage
CWE-200: Exposure of Sensitive Information
CWE-359: Exposure of Private Personal Information
"""

import re
import time
from pathlib import Path
from typing import List

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


# --- Sensitive keyword pattern (shared across checks) ---
_SENSITIVE = (
    r"(?:password|passwd|token|secret|credential|ssn|credit.?card|cvv|"
    r"pin.?code|account.?number|auth|session|private.?key|otp)"
)

# --- Clipboard patterns ---
_CLIPBOARD_SENSITIVE = re.compile(
    r'(?:ClipboardManager|clipboard).*(?:setPrimaryClip|setText)\s*\([^)]*' + _SENSITIVE,
    re.IGNORECASE,
)

# --- Intent data leak patterns ---
_INTENT_SENSITIVE = re.compile(
    r'(?:intent|Intent)\s*\.?\s*putExtra\s*\([^)]*' + _SENSITIVE,
    re.IGNORECASE,
)

# --- Notification PII patterns ---
_NOTIFICATION_SENSITIVE = re.compile(
    r'(?:setContentText|setContentTitle|setSubText|setBigText)\s*\([^)]*' + _SENSITIVE,
    re.IGNORECASE,
)

# --- WebView URL with auth tokens ---
_WEBVIEW_AUTH = re.compile(
    r'(?:loadUrl|loadData|postUrl)\s*\([^)]*(?:token|session|auth|jwt|bearer|api.?key)',
    re.IGNORECASE,
)

# NOTE: MODE_WORLD_READABLE check REMOVED - now covered by insecure_data_storage
# and enhanced_data_storage_modular (structured bridges, Phase 2).

# --- Hardcoded URL with credentials ---
_URL_CREDENTIALS = re.compile(
    r'(?:https?://)[^"]*(?:password|token|key|secret)=[^"&\s]{4,}',
    re.IGNORECASE,
)

# --- External storage for sensitive data ---
_EXTERNAL_SENSITIVE = re.compile(
    r'(?:getExternalFilesDir|getExternalStorageDirectory|Environment\.getExternalStorage)'
    r'[^;]{0,200}(?:' + _SENSITIVE + r')',
    re.IGNORECASE | re.DOTALL,
)


class PrivacyLeakDetectionV2(BasePluginV2):
    """Detects sensitive data flowing to insecure channels."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="privacy_leak_detection",
            version="3.0.0",
            description="Sensitive data leak detection: clipboard, intents, notifications, WebView (CWE-200/359)",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["privacy", "masvs-storage-1", "cwe-200"],
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

                findings.extend(self._check_clipboard_leaks(content, rel_path))
                findings.extend(self._check_intent_leaks(content, rel_path))
                findings.extend(self._check_notification_leaks(content, rel_path))
                findings.extend(self._check_webview_leaks(content, rel_path))
                findings.extend(self._check_storage_leaks(content, rel_path))

            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    "execution_time": time.time() - start_time,
                    "plugin_version": "3.0.0",
                    "files_scanned": files_scanned,
                },
            )
        except Exception as e:
            logger.error("privacy_leak_detection failed: %s", e)
            return PluginResult(
                status=PluginStatus.FAILURE,
                findings=findings,
                metadata={"error": type(e).__name__, "execution_time": time.time() - start_time},
            )

    # ------------------------------------------------------------------ source helpers

    def _get_source_files(self, apk_ctx) -> List[str]:
        src = getattr(apk_ctx, "source_files", None)
        if src:
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

    def _snippet(self, content: str, match) -> str:
        line_start = content.rfind("\n", 0, match.start()) + 1
        line_end = content.find("\n", match.end())
        if line_end == -1:
            line_end = len(content)
        return content[line_start:line_end].strip()[:200]

    # ------------------------------------------------------------------ checks

    def _check_clipboard_leaks(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings = []
        for match in _CLIPBOARD_SENSITIVE.finditer(content):
            line = self._line_number(content, match.start())
            findings.append(PluginFinding(
                finding_id=f"pld_clip_sensitive_{line}",
                title="Privacy Leak: Sensitive data written to clipboard",
                description=(
                    "Clipboard contents are accessible to all apps on the device. "
                    f"Code: {self._snippet(content, match)}"
                ),
                severity="high",
                confidence=0.80,
                cwe_id="CWE-200",
                file_path=rel_path,
                line_number=line,
                remediation="Avoid putting sensitive data on the clipboard. Use in-app copy instead.",
            ))
        return findings

    def _check_intent_leaks(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings = []
        for match in _INTENT_SENSITIVE.finditer(content):
            line = self._line_number(content, match.start())
            findings.append(PluginFinding(
                finding_id=f"pld_intent_sensitive_{line}",
                title="Privacy Leak: Sensitive data in Intent extras",
                description=(
                    "Sensitive data passed via Intent extras can be intercepted by other apps "
                    "if the intent is implicit or the receiving component is exported. "
                    f"Code: {self._snippet(content, match)}"
                ),
                severity="high",
                confidence=0.75,
                cwe_id="CWE-927",
                file_path=rel_path,
                line_number=line,
                remediation="Use explicit intents with setComponent() for sensitive data transfer",
            ))
        return findings

    def _check_notification_leaks(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings = []
        for match in _NOTIFICATION_SENSITIVE.finditer(content):
            line = self._line_number(content, match.start())
            findings.append(PluginFinding(
                finding_id=f"pld_notif_sensitive_{line}",
                title="Privacy Leak: Sensitive data in notification",
                description=(
                    "Notifications are visible on the lock screen and to notification listeners. "
                    f"Code: {self._snippet(content, match)}"
                ),
                severity="medium",
                confidence=0.70,
                cwe_id="CWE-200",
                file_path=rel_path,
                line_number=line,
                remediation="Use setVisibility(VISIBILITY_SECRET) and redact sensitive data",
            ))
        return findings

    def _check_webview_leaks(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings = []
        for match in _WEBVIEW_AUTH.finditer(content):
            line = self._line_number(content, match.start())
            findings.append(PluginFinding(
                finding_id=f"pld_webview_auth_{line}",
                title="Privacy Leak: Auth token in WebView URL",
                description=(
                    "Authentication tokens in WebView URLs are logged in browser history, "
                    "may appear in server logs, and can leak via Referer headers. "
                    f"Code: {self._snippet(content, match)}"
                ),
                severity="high",
                confidence=0.75,
                cwe_id="CWE-598",
                file_path=rel_path,
                line_number=line,
                remediation="Pass tokens via HTTP headers instead of URL parameters",
            ))
        for match in _URL_CREDENTIALS.finditer(content):
            line = self._line_number(content, match.start())
            findings.append(PluginFinding(
                finding_id=f"pld_url_creds_{line}",
                title="Privacy Leak: Credentials embedded in URL",
                description=f"URL contains embedded credentials or tokens. Code: {self._snippet(content, match)}",
                severity="high",
                confidence=0.70,
                cwe_id="CWE-798",
                file_path=rel_path,
                line_number=line,
            ))
        return findings

    def _check_storage_leaks(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings = []
        # NOTE: MODE_WORLD_READABLE check removed - covered by insecure_data_storage
        for match in _EXTERNAL_SENSITIVE.finditer(content):
            line = self._line_number(content, match.start())
            findings.append(PluginFinding(
                finding_id=f"pld_external_sensitive_{line}",
                title="Privacy Leak: Sensitive data on external storage",
                description=(
                    "External storage is world-readable pre-Android 10. "
                    f"Code: {self._snippet(content, match)}"
                ),
                severity="high",
                confidence=0.70,
                cwe_id="CWE-312",
                file_path=rel_path,
                line_number=line,
                remediation="Use internal storage or EncryptedFile for sensitive data",
            ))
        return findings


def create_plugin() -> PrivacyLeakDetectionV2:
    return PrivacyLeakDetectionV2()


__all__ = ["PrivacyLeakDetectionV2", "create_plugin"]
