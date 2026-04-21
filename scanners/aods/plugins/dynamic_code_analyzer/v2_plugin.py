#!/usr/bin/env python3
"""
dynamic_code_analyzer - BasePluginV2 Implementation (MASVS-CODE-4)
==================================================================

Detects dynamic code loading, runtime execution, and reflection usage.
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

# --- Detection patterns: (compiled_regex, short_label, title, description, severity, cwe) ---

_DYNAMIC_CODE_PATTERNS = [
    (
        re.compile(r"DexClassLoader\s*\("),
        "DexClassLoader",
        "Dynamic DEX Class Loading",
        "DexClassLoader dynamically loads .dex files at runtime, which can execute untrusted code.",
        "high",
        "CWE-94",
    ),
    (
        re.compile(r"PathClassLoader\s*\("),
        "PathClassLoader",
        "Dynamic Path Class Loading",
        "PathClassLoader loads classes from a specified path at runtime.",
        "high",
        "CWE-94",
    ),
    (
        re.compile(r"dalvik\.system\.DexFile"),
        "DexFile",
        "Direct DEX File Manipulation",
        "Direct use of dalvik.system.DexFile allows loading arbitrary DEX bytecode.",
        "high",
        "CWE-94",
    ),
    (
        re.compile(r"URLClassLoader\s*\("),
        "URLClassLoader",
        "URL-Based Class Loading",
        "URLClassLoader loads classes from remote URLs, enabling remote code execution.",
        "high",
        "CWE-94",
    ),
    (
        re.compile(r"Runtime\.getRuntime\(\)\s*\.\s*exec\s*\("),
        "Runtime.exec",
        "Runtime Command Execution",
        "Runtime.getRuntime().exec() executes arbitrary system commands, risking command injection.",
        "critical",
        "CWE-78",
    ),
    (
        re.compile(r"ProcessBuilder\s*\("),
        "ProcessBuilder",
        "Process Builder Command Execution",
        "ProcessBuilder creates OS processes, enabling arbitrary command execution.",
        "high",
        "CWE-78",
    ),
    (
        re.compile(r"\.setAccessible\s*\(\s*true\s*\)"),
        "setAccessible",
        "Accessibility Bypass via Reflection",
        "setAccessible(true) bypasses Java access controls, allowing access to private fields/methods.",
        "high",
        "CWE-749",
    ),
    (
        re.compile(r"System\.loadLibrary\s*\("),
        "System.loadLibrary",
        "Native Library Loading",
        "System.loadLibrary() loads native .so libraries which may contain unsafe native code.",
        "medium",
        "CWE-427",
    ),
    (
        re.compile(r"System\.load\s*\("),
        "System.load",
        "Direct Native Library Loading",
        "System.load() loads a native library from an absolute path.",
        "medium",
        "CWE-427",
    ),
    (
        re.compile(r"Class\.forName\s*\("),
        "Class.forName",
        "Reflective Class Loading",
        "Class.forName() loads classes by name at runtime, enabling reflective code execution.",
        "medium",
        "CWE-470",
    ),
    (
        re.compile(r"InMemoryDexClassLoader\s*\("),
        "InMemoryDexClassLoader",
        "In-Memory DEX Class Loading",
        "InMemoryDexClassLoader loads DEX bytecode from memory at runtime, "
        "enabling dynamic code execution from external sources.",
        "high",
        "CWE-94",
    ),
    (
        re.compile(r"\.addJavascriptInterface\s*\("),
        "addJavascriptInterface",
        "WebView JavaScript Interface Bridge",
        "addJavascriptInterface() exposes Java objects to JavaScript in WebViews. "
        "Malicious JS can invoke exposed methods, risking data theft or code execution.",
        "high",
        "CWE-749",
    ),
]


class DynamicCodeAnalyzerV2(BasePluginV2):
    """Detects dynamic code loading, runtime execution, and reflection (MASVS-CODE-4)."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="dynamic_code_analyzer",
            version="2.1.0",
            description="Detects dynamic code loading, runtime execution, and reflection usage",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["code", "masvs-code-4"],
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

                findings.extend(self._scan_file(content, rel_path))

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
            logger.error(f"dynamic_code_analyzer failed: {e}")
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

    # Safe read-only commands that are not exploitable
    _SAFE_EXEC_KEYWORDS = ("getprop", "/proc/", "/sys/", "uname", "cat /proc", "cat /sys")

    def _scan_file(self, content: str, rel_path: str) -> List[PluginFinding]:
        """Scan a single file for all dynamic code patterns. Per-file dedup: first match per pattern."""
        findings = []
        seen_labels: Set[str] = set()

        for pattern, label, title, description, severity, cwe in _DYNAMIC_CODE_PATTERNS:
            if label in seen_labels:
                continue
            m = pattern.search(content)
            if m:
                # Safe-command check for exec/ProcessBuilder
                if label in ("Runtime.exec", "ProcessBuilder"):
                    ctx = content[m.start():min(len(content), m.start() + 256)].lower()
                    if any(kw in ctx for kw in self._SAFE_EXEC_KEYWORDS):
                        continue

                seen_labels.add(label)
                findings.append(self.create_finding(
                    finding_id=f"dyncode_{label.lower().replace('.', '_')}_{len(findings):03d}",
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=0.85 if severity in ("critical", "high") else 0.7,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id=cwe,
                    masvs_control="MASVS-CODE-4",
                    remediation="Avoid dynamic code loading where possible; validate all loaded code.",
                ))

        return findings


# Plugin factory
def create_plugin() -> DynamicCodeAnalyzerV2:
    return DynamicCodeAnalyzerV2()


__all__ = ["DynamicCodeAnalyzerV2", "create_plugin"]
