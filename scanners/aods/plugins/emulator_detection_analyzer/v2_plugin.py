#!/usr/bin/env python3
"""
emulator_detection_analyzer - BasePluginV2 Implementation (MASVS-RESILIENCE-2)
==============================================================================

Detects emulator/root detection patterns as resilience features (INFO severity).
These are defensive anti-RE mechanisms, not vulnerabilities.
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

# --- Detection patterns: (compiled_regex, category_label, description) ---
# ALL findings are INFO - this is a resilience assessment, not vulnerability detection.

_EMULATOR_STRING_CHECKS = [
    (re.compile(r'["\']goldfish["\']'), "goldfish", "Goldfish emulator string check"),
    (re.compile(r'["\']generic["\']'), "generic", "Generic device string check"),
    (re.compile(r'["\']sdk["\']'), "sdk", "SDK emulator string check"),
    (re.compile(r'["\']Genymotion["\']', re.IGNORECASE), "genymotion", "Genymotion emulator detection"),
    (re.compile(r'["\']google_sdk["\']'), "google_sdk", "Google SDK emulator check"),
    (re.compile(r"qemu", re.IGNORECASE), "qemu", "QEMU emulator reference"),
]

_ROOT_BINARY_CHECKS = [
    (re.compile(r"/system/bin/su"), "system_bin_su", "Root binary /system/bin/su check"),
    (re.compile(r"/system/xbin/su"), "system_xbin_su", "Root binary /system/xbin/su check"),
    (re.compile(r"Superuser\.apk"), "superuser_apk", "Superuser.apk root indicator check"),
    (re.compile(r'which\s+su'), "which_su", "Shell 'which su' root detection"),
]

_DEBUG_PROPERTY_CHECKS = [
    (re.compile(r"ro\.debuggable"), "ro_debuggable", "Debug property ro.debuggable check"),
    (re.compile(r"ro\.secure"), "ro_secure", "Security property ro.secure check"),
    (re.compile(r"ro\.kernel\.qemu"), "ro_kernel_qemu", "QEMU kernel property check"),
]

_PROC_INSPECTION_CHECKS = [
    (re.compile(r"/proc/cpuinfo"), "proc_cpuinfo", "/proc/cpuinfo inspection"),
    (re.compile(r"/proc/self/maps"), "proc_self_maps", "/proc/self/maps inspection"),
    (re.compile(r"/proc/version"), "proc_version", "/proc/version inspection"),
]


class EmulatorDetectionAnalyzerV2(BasePluginV2):
    """Detects emulator/root detection patterns as resilience features (MASVS-RESILIENCE-2)."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="emulator_detection_analyzer",
            version="2.1.0",
            description="Detects emulator/root detection patterns as resilience features",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["resilience", "masvs-resilience-2"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        files_scanned = 0
        total_checks = 0

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

                file_findings = self._scan_file(content, rel_path)
                total_checks += len(file_findings)
                findings.extend(file_findings)

            # Summary finding
            if total_checks > 0:
                findings.append(self.create_finding(
                    finding_id="emu_summary_000",
                    title=f"App Implements {total_checks} Emulator/Root Detection Checks",
                    description=(
                        f"The application implements {total_checks} emulator/root detection checks "
                        f"across {files_scanned} source files. This is a defensive resilience feature "
                        "that protects against reverse engineering and runtime tampering."
                    ),
                    severity="info",
                    confidence=0.9,
                    file_path="app://source",
                    cwe_id="CWE-693",
                    masvs_control="MASVS-RESILIENCE-2",
                    remediation="No action needed. Emulator/root detection is a recommended resilience practice.",
                ))

            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    "execution_time": time.time() - start_time,
                    "plugin_version": "2.1.0",
                    "files_scanned": files_scanned,
                    "detection_checks_found": total_checks,
                },
            )

        except Exception as e:
            logger.error(f"emulator_detection_analyzer failed: {e}")
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

    def _scan_file(self, content: str, rel_path: str) -> List[PluginFinding]:
        """Scan a single file for emulator/root detection patterns. Per-file dedup."""
        findings = []
        seen: Set[str] = set()

        all_checks = [
            (_EMULATOR_STRING_CHECKS, "Emulator String Check"),
            (_ROOT_BINARY_CHECKS, "Root Binary Check"),
            (_DEBUG_PROPERTY_CHECKS, "Debug Property Check"),
            (_PROC_INSPECTION_CHECKS, "/proc Inspection Check"),
        ]

        for check_list, category in all_checks:
            for pattern, label, description in check_list:
                if label in seen:
                    continue
                m = pattern.search(content)
                if m:
                    seen.add(label)
                    findings.append(self.create_finding(
                        finding_id=f"emu_{label}_{len(findings):03d}",
                        title=f"{category}: {description}",
                        description=(
                            f"{description}. This is a defensive anti-reverse-engineering feature, "
                            "not a vulnerability."
                        ),
                        severity="info",
                        confidence=0.85,
                        file_path=rel_path,
                        line_number=self._line_number(content, m.start()),
                        code_snippet=self._snippet(content, m.start(), m.end()),
                        cwe_id="CWE-693",
                        masvs_control="MASVS-RESILIENCE-2",
                        remediation="No action needed. This is a recommended resilience practice.",
                    ))

        return findings


# Plugin factory
def create_plugin() -> EmulatorDetectionAnalyzerV2:
    return EmulatorDetectionAnalyzerV2()


__all__ = ["EmulatorDetectionAnalyzerV2", "create_plugin"]
