#!/usr/bin/env python3
"""
enhanced_static_analysis - Insecure Logging & Debug Artifact Detection
======================================================================

Detects sensitive data in Android logging calls, debug print statements,
stack trace exposure, and other static patterns that leak information.

MASVS-STORAGE-3: Insecure Logging
CWE-532: Information Exposure Through Log Files
CWE-215: Insertion of Sensitive Information Into Debugging Code
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


# --- Detection patterns ---

# Sensitive keywords in log arguments
_SENSITIVE_KW = (
    r"(?:password|passwd|pwd|secret|token|api.?key|credential|auth.?token|"
    r"session.?id|private.?key|ssn|credit.?card|cvv|pin.?code|otp|"
    r"access.?token|refresh.?token|bearer|jwt|cookie)"
)

# Android Log.x() with sensitive data
_LOG_SENSITIVE = re.compile(
    r'\bLog\.(d|v|i|e|w|wtf)\s*\([^)]*' + _SENSITIVE_KW,
    re.IGNORECASE,
)

# Android Log.x() logging full objects (may contain PII)
_LOG_TOSTRING = re.compile(
    r'\bLog\.(d|v|i|e|w|wtf)\s*\([^)]*\.toString\s*\(\)',
)

# System.out/err print statements (debug code left in production)
_SYSOUT = re.compile(
    r'\bSystem\.(out|err)\.(print|println)\s*\(',
)

# Stack trace printing (exposes internal structure)
_STACKTRACE = re.compile(
    r'\b(?:e|ex|exc|exception|error|t|throwable)\.printStackTrace\s*\(',
    re.IGNORECASE,
)

# Verbose logging with string concatenation (potential injection)
_LOG_CONCAT = re.compile(
    r'\bLog\.(d|v|i|e|w|wtf)\s*\(\s*\w+\s*,\s*"[^"]*"\s*\+\s*(?:' + _SENSITIVE_KW + r')',
    re.IGNORECASE,
)

# Timber/SLF4J/Logback sensitive logging
_TIMBER_SENSITIVE = re.compile(
    r'\bTimber\.(d|v|i|e|w|wtf)\s*\([^)]*' + _SENSITIVE_KW,
    re.IGNORECASE,
)

# BuildConfig.DEBUG not checked before logging
_LOG_NO_DEBUG_CHECK = re.compile(
    r'\bLog\.(d|v)\s*\(',
)

# Patterns that indicate the log is in a debug/test context (reduce FPs)
_DEBUG_GUARD = re.compile(
    r'(?:if\s*\(\s*BuildConfig\.DEBUG|if\s*\(\s*DEBUG|@Debug|isDebugMode)',
    re.IGNORECASE,
)


class EnhancedStaticAnalysisV2(BasePluginV2):
    """Detects insecure logging and debug artifacts in Android source code."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="enhanced_static_analysis",
            version="3.0.0",
            description="Insecure logging and debug artifact detection (CWE-532/215)",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["logging", "masvs-storage-3", "cwe-532"],
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

                findings.extend(self._check_sensitive_logging(content, rel_path))
                findings.extend(self._check_debug_artifacts(content, rel_path))

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
            logger.error("enhanced_static_analysis failed: %s", e)
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

    def _has_debug_guard(self, content: str, pos: int) -> bool:
        """Check if a log statement is inside a BuildConfig.DEBUG guard."""
        # Look back up to 5 lines for a debug guard
        search_start = max(0, content.rfind("\n", 0, max(0, pos - 500)))
        context = content[search_start:pos]
        return bool(_DEBUG_GUARD.search(context))

    # ------------------------------------------------------------------ checks

    def _check_sensitive_logging(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings = []
        seen_lines = set()

        # Pattern 1: Log.x() with sensitive keywords
        for match in _LOG_SENSITIVE.finditer(content):
            line = self._line_number(content, match.start())
            if line in seen_lines:
                continue
            seen_lines.add(line)
            if self._has_debug_guard(content, match.start()):
                continue
            snippet = self._snippet(content, match)
            findings.append(PluginFinding(
                finding_id=f"esa_log_sensitive_{line}",
                title="Insecure Logging: Sensitive data in Log statement",
                description=(
                    f"Log.{match.group(1)}() call contains sensitive keyword. "
                    "Android logs are readable by any app on the device via logcat. "
                    f"Code: {snippet}"
                ),
                severity="high",
                confidence=0.80,
                cwe_id="CWE-532",
                file_path=rel_path,
                line_number=line,
                remediation="Remove sensitive data from log statements or gate behind BuildConfig.DEBUG",
            ))

        # Pattern 2: Timber.x() with sensitive keywords
        for match in _TIMBER_SENSITIVE.finditer(content):
            line = self._line_number(content, match.start())
            if line in seen_lines:
                continue
            seen_lines.add(line)
            findings.append(PluginFinding(
                finding_id=f"esa_timber_sensitive_{line}",
                title="Insecure Logging: Sensitive data in Timber log",
                description=(
                    f"Timber.{match.group(1)}() call contains sensitive keyword. "
                    f"Code: {self._snippet(content, match)}"
                ),
                severity="high",
                confidence=0.75,
                cwe_id="CWE-532",
                file_path=rel_path,
                line_number=line,
                remediation="Use Timber.plant() with a release tree that strips sensitive logs",
            ))

        # Pattern 3: Log.x() with toString() - may leak PII from objects
        for match in _LOG_TOSTRING.finditer(content):
            line = self._line_number(content, match.start())
            if line in seen_lines:
                continue
            seen_lines.add(line)
            if self._has_debug_guard(content, match.start()):
                continue
            findings.append(PluginFinding(
                finding_id=f"esa_log_tostring_{line}",
                title="Insecure Logging: Object toString() in log may expose PII",
                description=(
                    f"Log.{match.group(1)}() call logs an object's toString() representation "
                    "which may contain sensitive fields. "
                    f"Code: {self._snippet(content, match)}"
                ),
                severity="medium",
                confidence=0.55,
                cwe_id="CWE-532",
                file_path=rel_path,
                line_number=line,
            ))

        return findings

    def _check_debug_artifacts(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings = []
        seen_lines = set()

        # System.out/err.print (debug statements in production)
        for match in _SYSOUT.finditer(content):
            line = self._line_number(content, match.start())
            if line in seen_lines:
                continue
            seen_lines.add(line)
            findings.append(PluginFinding(
                finding_id=f"esa_sysout_{line}",
                title="Debug Artifact: System.out/err.print in production code",
                description=(
                    "System.out/err.print statements should not appear in release builds. "
                    f"Code: {self._snippet(content, match)}"
                ),
                severity="low",
                confidence=0.70,
                cwe_id="CWE-215",
                file_path=rel_path,
                line_number=line,
                remediation="Replace with proper logging framework or remove",
            ))

        # printStackTrace() calls
        for match in _STACKTRACE.finditer(content):
            line = self._line_number(content, match.start())
            if line in seen_lines:
                continue
            seen_lines.add(line)
            findings.append(PluginFinding(
                finding_id=f"esa_stacktrace_{line}",
                title="Debug Artifact: printStackTrace() exposes internal structure",
                description=(
                    "Stack trace printing in production code exposes class names, "
                    "method signatures, and line numbers to attackers. "
                    f"Code: {self._snippet(content, match)}"
                ),
                severity="medium",
                confidence=0.75,
                cwe_id="CWE-215",
                file_path=rel_path,
                line_number=line,
                remediation="Use a logging framework with proper error handling instead",
            ))

        return findings


def create_plugin() -> EnhancedStaticAnalysisV2:
    """Create plugin instance."""
    return EnhancedStaticAnalysisV2()


__all__ = ["EnhancedStaticAnalysisV2", "create_plugin"]
