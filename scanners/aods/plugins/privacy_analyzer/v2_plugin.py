#!/usr/bin/env python3
"""
privacy_analyzer - BasePluginV2 Implementation (MASVS-PRIVACY-1)
================================================================

Detects privacy policy compliance gaps: hardcoded PII, clipboard access,
screenshot vulnerability, logging PII, and unencrypted SharedPreferences.
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

# --- Detection patterns ---

_HARDCODED_PII_PATTERNS = [
    (
        re.compile(r'"[^"]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"'),
        "email",
        "Hardcoded Email Address",
        "A hardcoded email address was found in a string literal. This may expose PII.",
    ),
    (
        re.compile(r'"\+?\d[\d\s\-]{8,15}"'),
        "phone",
        "Hardcoded Phone Number",
        "A hardcoded phone number was found in a string literal.",
    ),
    (
        re.compile(r'"\d{3}-\d{2}-\d{4}"'),
        "ssn",
        "Hardcoded SSN Pattern",
        "A string matching the SSN format (XXX-XX-XXXX) was found hardcoded.",
    ),
]

_CLIPBOARD_PATTERNS = [
    (
        re.compile(r"ClipboardManager.*getPrimaryClip|getPrimaryClip\s*\("),
        "clipboard_read",
        "Clipboard Data Read",
        "Application reads from the clipboard, which may contain sensitive data from other apps.",
    ),
    (
        re.compile(r"ClipboardManager.*setPrimaryClip|setPrimaryClip\s*\("),
        "clipboard_write",
        "Sensitive Data Written to Clipboard",
        "Application writes to the clipboard. Sensitive data on the clipboard is accessible to all apps.",
    ),
]

_LOG_PII_PATTERN = re.compile(
    r"Log\.[diwev]\s*\([^)]*(?:email|password|ssn|token|secret|credential|credit.?card|social.?security)",
    re.IGNORECASE,
)

_SHARED_PREFS_PATTERN = re.compile(r"getSharedPreferences\s*\(")
_ENCRYPTED_PREFS_PATTERN = re.compile(r"EncryptedSharedPreferences")

_FLAG_SECURE_PATTERN = re.compile(r"FLAG_SECURE|WindowManager\.LayoutParams\.FLAG_SECURE")


class PrivacyAnalyzerV2(BasePluginV2):
    """Detects privacy policy compliance gaps (MASVS-PRIVACY-1)."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="privacy_analyzer",
            version="2.1.0",
            description="Detects hardcoded PII, clipboard access, screenshot vulnerability, and logging PII",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["privacy", "masvs-privacy-1"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        files_scanned = 0

        try:
            source_files = self._get_source_files(apk_ctx)
            has_flag_secure = False

            for src_path in source_files:
                try:
                    content = Path(src_path).read_text(errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                files_scanned += 1
                rel_path = self._relative_path(src_path, apk_ctx)

                if self._is_library_code(rel_path):
                    continue

                findings.extend(self._check_hardcoded_pii(content, rel_path))
                findings.extend(self._check_clipboard_access(content, rel_path))
                findings.extend(self._check_log_pii(content, rel_path))
                findings.extend(self._check_unencrypted_prefs(content, rel_path))

                if _FLAG_SECURE_PATTERN.search(content):
                    has_flag_secure = True

            # Screenshot vulnerability: global check
            if files_scanned > 0 and not has_flag_secure:
                findings.append(self.create_finding(
                    finding_id="privacy_no_flag_secure_000",
                    title="No FLAG_SECURE Screenshot Protection",
                    description=(
                        "No use of FLAG_SECURE was found in the application. Activities handling "
                        "sensitive data should set FLAG_SECURE to prevent screenshots and screen recording."
                    ),
                    severity="low",
                    confidence=0.5,
                    file_path="app://source",
                    cwe_id="CWE-200",
                    masvs_control="MASVS-PRIVACY-1",
                    remediation="Set FLAG_SECURE on activities that display sensitive information.",
                ))

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
            logger.error(f"privacy_analyzer failed: {e}")
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

    # Date format chars that commonly appear with @ (e.g. "yyyy-MM-dd@HH-mm-ss")
    _DATE_FMT_AROUND_AT = re.compile(r'[yYMdHhmsS]{2,}.*@.*[yYMdHhmsS]{2,}')

    def _check_hardcoded_pii(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings = []
        seen: Set[str] = set()
        for pattern, label, title, description in _HARDCODED_PII_PATTERNS:
            if label in seen:
                continue
            m = pattern.search(content)
            if m:
                matched_str = m.group(0).strip('"')

                # Email FP: skip date format strings containing @ (e.g. "yyyy-MM-dd@HH:mm")
                if label == "email" and self._DATE_FMT_AROUND_AT.search(matched_str):
                    continue

                # Phone FP: pure digit strings without separators or + prefix are numeric constants
                if label == "phone":
                    if not re.search(r'[\s\-]', matched_str) and not matched_str.startswith('+'):
                        continue

                seen.add(label)
                findings.append(self.create_finding(
                    finding_id=f"privacy_pii_{label}_{len(findings):03d}",
                    title=title,
                    description=description,
                    severity="medium",
                    confidence=0.7,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id="CWE-312",
                    masvs_control="MASVS-PRIVACY-1",
                    remediation="Remove hardcoded PII from source code. Use secure storage or configuration.",
                ))
        return findings

    def _check_clipboard_access(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings = []
        seen: Set[str] = set()
        for pattern, label, title, description in _CLIPBOARD_PATTERNS:
            if label in seen:
                continue
            m = pattern.search(content)
            if m:
                seen.add(label)
                findings.append(self.create_finding(
                    finding_id=f"privacy_clip_{label}_{len(findings):03d}",
                    title=title,
                    description=description,
                    severity="medium",
                    confidence=0.7,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id="CWE-200",
                    masvs_control="MASVS-PRIVACY-1",
                    remediation="Avoid placing sensitive data on the clipboard or clear it after use.",
                ))
        return findings

    def _check_log_pii(self, content: str, rel_path: str) -> List[PluginFinding]:
        m = _LOG_PII_PATTERN.search(content)
        if not m:
            return []
        return [self.create_finding(
            finding_id="privacy_log_pii_000",
            title="Logging PII Data",
            description=(
                "Application logs potentially sensitive data (email, password, token, etc.). "
                "Log output may be accessible to other apps or captured in crash reports."
            ),
            severity="high",
            confidence=0.8,
            file_path=rel_path,
            line_number=self._line_number(content, m.start()),
            code_snippet=self._snippet(content, m.start(), m.end()),
            cwe_id="CWE-532",
            masvs_control="MASVS-PRIVACY-1",
            remediation="Remove PII from log statements. Use ProGuard to strip Log calls in release builds.",
        )]

    def _check_unencrypted_prefs(self, content: str, rel_path: str) -> List[PluginFinding]:
        if not _SHARED_PREFS_PATTERN.search(content):
            return []
        if _ENCRYPTED_PREFS_PATTERN.search(content):
            return []
        m = _SHARED_PREFS_PATTERN.search(content)
        return [self.create_finding(
            finding_id="privacy_unenc_prefs_000",
            title="Unencrypted SharedPreferences",
            description=(
                "getSharedPreferences is used without EncryptedSharedPreferences in the same class. "
                "Standard SharedPreferences stores data in plaintext XML on the device."
            ),
            severity="medium",
            confidence=0.6,
            file_path=rel_path,
            line_number=self._line_number(content, m.start()),
            code_snippet=self._snippet(content, m.start(), m.end()),
            cwe_id="CWE-312",
            masvs_control="MASVS-PRIVACY-1",
            remediation="Use EncryptedSharedPreferences from the AndroidX Security library.",
        )]


# Plugin factory
def create_plugin() -> PrivacyAnalyzerV2:
    return PrivacyAnalyzerV2()


__all__ = ["PrivacyAnalyzerV2", "create_plugin"]
