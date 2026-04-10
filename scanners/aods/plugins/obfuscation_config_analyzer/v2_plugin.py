#!/usr/bin/env python3
"""
obfuscation_config_analyzer - BasePluginV2 Implementation (MASVS-RESILIENCE-3)
===============================================================================

Detects missing or weak code obfuscation configuration:
- ProGuard/R8 disabled or misconfigured
- -dontobfuscate, -dontoptimize, -dontshrink flags
- Debug symbols in release builds
- Overly permissive -keep rules exposing security-critical classes
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

# --- ProGuard configuration patterns ---

_PROGUARD_WEAKNESS_PATTERNS = [
    (
        re.compile(r'-dontobfuscate\b'),
        "dontobfuscate",
        "Code Obfuscation Disabled",
        "ProGuard/R8 obfuscation is explicitly disabled with -dontobfuscate. Class and method "
        "names remain readable, making reverse engineering trivial.",
        "medium",
        "CWE-693",
        0.90,
    ),
    (
        re.compile(r'-dontoptimize\b'),
        "dontoptimize",
        "Code Optimization Disabled",
        "ProGuard/R8 optimization is disabled with -dontoptimize. Optimization can remove dead "
        "code and make control flow harder to follow.",
        "low",
        "CWE-693",
        0.75,
    ),
    (
        re.compile(r'-dontshrink\b'),
        "dontshrink",
        "Code Shrinking Disabled",
        "ProGuard/R8 code shrinking is disabled with -dontshrink. Unused classes and methods "
        "remain in the APK, increasing the attack surface and making analysis easier.",
        "low",
        "CWE-693",
        0.75,
    ),
    (
        re.compile(r'-keepattributes\s+.*(?:SourceFile|LineNumberTable)'),
        "keep_debug_attrs",
        "Debug Attributes Retained",
        "Source file names and/or line number tables are kept in the release build. This makes "
        "stack traces more useful to attackers for reverse engineering.",
        "low",
        "CWE-693",
        0.70,
    ),
    (
        re.compile(r'-keep\s+(?:public\s+)?class\s+\*\s'),
        "keep_all_classes",
        "Overly Broad Keep Rule",
        "A very broad -keep rule preserves all classes from obfuscation, effectively negating "
        "ProGuard/R8 protection.",
        "medium",
        "CWE-693",
        0.80,
    ),
]

# Gradle build patterns indicating missing obfuscation
_GRADLE_PATTERNS = [
    (
        re.compile(r'minifyEnabled\s+false'),
        "minify_disabled",
        "Code Minification Disabled in Build",
        "minifyEnabled is set to false in the Gradle build configuration. ProGuard/R8 will not "
        "run, leaving code completely unobfuscated.",
        "medium",
        "CWE-693",
        0.85,
    ),
    (
        re.compile(r'shrinkResources\s+false'),
        "shrink_resources_disabled",
        "Resource Shrinking Disabled",
        "shrinkResources is set to false. Unused resources remain in the APK, potentially "
        "exposing debug resources or internal assets.",
        "info",
        "CWE-693",
        0.60,
    ),
]


class ObfuscationConfigAnalyzerV2(BasePluginV2):
    """Detects missing or weak obfuscation configuration (MASVS-RESILIENCE-3)."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="obfuscation_config_analyzer",
            version="1.0.0",
            description="Detects missing or weak ProGuard/R8 obfuscation configuration",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.LOW,
            timeout_seconds=60,
            supported_platforms=["android"],
            tags=["obfuscation", "proguard", "masvs-resilience-3"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        files_scanned = 0

        try:
            workspace = getattr(apk_ctx, "workspace_dir", None) or getattr(apk_ctx, "output_dir", None)
            if not workspace:
                return PluginResult(
                    status=PluginStatus.SUCCESS,
                    findings=[],
                    metadata={"execution_time": time.time() - start_time, "files_scanned": 0},
                )

            workspace_path = Path(workspace)

            # Check ProGuard configuration files
            proguard_files = list(workspace_path.rglob("proguard*.pro")) + \
                list(workspace_path.rglob("proguard*.txt")) + \
                list(workspace_path.rglob("proguard*.cfg"))

            for pg_file in proguard_files:
                try:
                    content = pg_file.read_text(errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                files_scanned += 1
                rel_path = self._relative_path(str(pg_file), apk_ctx)
                findings.extend(self._check_proguard_config(content, rel_path))

            # Check Gradle build files
            gradle_files = list(workspace_path.rglob("build.gradle")) + \
                list(workspace_path.rglob("build.gradle.kts"))

            for gradle_file in gradle_files:
                try:
                    content = gradle_file.read_text(errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                files_scanned += 1
                rel_path = self._relative_path(str(gradle_file), apk_ctx)
                findings.extend(self._check_gradle_config(content, rel_path))

            # If no ProGuard files found at all, that's also concerning
            if not proguard_files and not gradle_files:
                # Check if decompiled source shows unobfuscated class names
                findings.extend(self._check_obfuscation_evidence(apk_ctx))

            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    "execution_time": time.time() - start_time,
                    "plugin_version": "1.0.0",
                    "files_scanned": files_scanned,
                    "proguard_files_found": len(proguard_files),
                },
            )

        except Exception as e:
            logger.error(f"obfuscation_config_analyzer failed: {e}")
            return PluginResult(
                status=PluginStatus.FAILURE,
                findings=findings,
                metadata={"error": str(e), "execution_time": time.time() - start_time},
            )

    # ------------------------------------------------------------------ helpers

    def _relative_path(self, full_path: str, apk_ctx) -> str:
        workspace = getattr(apk_ctx, "workspace_dir", None) or getattr(apk_ctx, "output_dir", None)
        if workspace:
            try:
                return str(Path(full_path).relative_to(workspace))
            except ValueError:
                pass
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

    def _check_proguard_config(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings = []
        seen_labels: Set[str] = set()

        for pattern, label, title, description, severity, cwe, confidence in _PROGUARD_WEAKNESS_PATTERNS:
            if label in seen_labels:
                continue
            m = pattern.search(content)
            if m:
                seen_labels.add(label)
                findings.append(self.create_finding(
                    finding_id=f"obfuscation_{label}_{len(findings):03d}",
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=confidence,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id=cwe,
                    masvs_control="MASVS-RESILIENCE-3",
                    remediation="Enable full ProGuard/R8 obfuscation for release builds.",
                ))

        return findings

    def _check_gradle_config(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings = []
        seen_labels: Set[str] = set()

        for pattern, label, title, description, severity, cwe, confidence in _GRADLE_PATTERNS:
            if label in seen_labels:
                continue
            m = pattern.search(content)
            if m:
                seen_labels.add(label)
                findings.append(self.create_finding(
                    finding_id=f"obfuscation_{label}_{len(findings):03d}",
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=confidence,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id=cwe,
                    masvs_control="MASVS-RESILIENCE-3",
                    remediation="Set minifyEnabled true in the release build type.",
                ))

        return findings

    def _check_obfuscation_evidence(self, apk_ctx) -> List[PluginFinding]:
        """If no config files found, check if source shows signs of being unobfuscated."""
        sources_dir = getattr(apk_ctx, "sources_dir", None)
        if not sources_dir or not Path(sources_dir).is_dir():
            return []

        # Sample a few source files to check for readable class/method names
        sample_count = 0
        readable_count = 0
        readable_re = re.compile(r'(?:public|private|protected)\s+(?:class|interface)\s+[A-Z][a-z]+[A-Za-z]{3,}')

        for src_file in Path(sources_dir).rglob("*.java"):
            if self._is_library_code(str(src_file)):
                continue
            try:
                content = src_file.read_text(errors="replace")[:2000]
            except (OSError, UnicodeDecodeError):
                continue
            sample_count += 1
            if readable_re.search(content):
                readable_count += 1
            if sample_count >= 50:
                break

        if sample_count >= 10 and readable_count / sample_count > 0.8:
            return [self.create_finding(
                finding_id="obfuscation_not_applied_000",
                title="Code Appears Unobfuscated",
                description=(
                    f"Analysis of {sample_count} source files found {readable_count} "
                    f"({readable_count*100//sample_count}%) with fully readable class names, "
                    "suggesting ProGuard/R8 obfuscation is not applied. Readable code makes "
                    "reverse engineering trivial."
                ),
                severity="info",
                confidence=0.60,
                file_path="(sampled source files)",
                line_number=None,
                cwe_id="CWE-693",
                masvs_control="MASVS-RESILIENCE-3",
                remediation="Enable ProGuard/R8 with minifyEnabled true in the release build type.",
            )]

        return []


# Plugin factory
def create_plugin() -> ObfuscationConfigAnalyzerV2:
    return ObfuscationConfigAnalyzerV2()


__all__ = ["ObfuscationConfigAnalyzerV2", "create_plugin"]
