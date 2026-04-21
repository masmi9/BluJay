#!/usr/bin/env python3
"""
tapjacking_analyzer - BasePluginV2 Implementation (MASVS-PLATFORM-9)
=====================================================================

Detects tapjacking / overlay attack vulnerabilities:
- Missing filterTouchesWhenObscured on sensitive views
- SYSTEM_ALERT_WINDOW permission usage
- TYPE_APPLICATION_OVERLAY window creation
- Accessibility service binding (potential abuse vector)
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

_TAPJACKING_SOURCE_PATTERNS = [
    (
        re.compile(r'TYPE_APPLICATION_OVERLAY'),
        "TYPE_APPLICATION_OVERLAY",
        "Application Overlay Window",
        "TYPE_APPLICATION_OVERLAY creates a window that draws over other apps. This can be used "
        "for tapjacking attacks where a malicious overlay captures user taps intended for the "
        "app underneath.",
        "high",
        "CWE-1021",
        0.85,
    ),
    (
        re.compile(r'TYPE_SYSTEM_ALERT|TYPE_SYSTEM_OVERLAY|TYPE_PHONE'),
        "TYPE_SYSTEM_OVERLAY",
        "Legacy System Overlay Window",
        "Legacy system overlay window type detected. These deprecated types can draw over other "
        "apps, enabling tapjacking attacks.",
        "high",
        "CWE-1021",
        0.80,
    ),
    (
        re.compile(r'BIND_ACCESSIBILITY_SERVICE'),
        "BIND_ACCESSIBILITY_SERVICE",
        "Accessibility Service Binding",
        "BIND_ACCESSIBILITY_SERVICE enables the app to receive accessibility events from other apps. "
        "This can be abused to monitor user interactions, capture keystrokes, or perform click "
        "injection attacks.",
        "medium",
        "CWE-284",
        0.65,
    ),
    (
        re.compile(r'AccessibilityService'),
        "AccessibilityService",
        "Accessibility Service Implementation",
        "App implements AccessibilityService, which can observe and interact with UI elements "
        "in other apps. Verify this is used for legitimate accessibility purposes.",
        "medium",
        "CWE-284",
        0.60,
    ),
    (
        re.compile(r'\.performClick\s*\(|\.performGlobalAction\s*\('),
        "performClick",
        "Programmatic Click Injection",
        "performClick() or performGlobalAction() programmatically simulates user interactions. "
        "In an accessibility service context, this enables click injection attacks.",
        "high",
        "CWE-1021",
        0.75,
    ),
]

# Manifest patterns
_MANIFEST_OVERLAY_PERMISSION = re.compile(
    r'android\.permission\.SYSTEM_ALERT_WINDOW',
)


class TapjackingAnalyzerV2(BasePluginV2):
    """Detects tapjacking and overlay attack vulnerabilities (MASVS-PLATFORM-9)."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="tapjacking_analyzer",
            version="1.0.0",
            description="Detects tapjacking, overlay attacks, and accessibility service abuse",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["tapjacking", "overlay", "masvs-platform-9"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        files_scanned = 0

        try:
            # Check manifest for SYSTEM_ALERT_WINDOW permission
            findings.extend(self._check_manifest(apk_ctx))

            # Scan source files for overlay/tapjacking patterns
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

            # Check XML layouts for missing filterTouchesWhenObscured
            findings.extend(self._check_xml_layouts(apk_ctx))

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
            logger.error(f"tapjacking_analyzer failed: {e}")
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

    def _check_manifest(self, apk_ctx) -> List[PluginFinding]:
        """Check AndroidManifest.xml for SYSTEM_ALERT_WINDOW permission."""
        manifest_path = getattr(apk_ctx, "manifest_path", None)
        if not manifest_path:
            # Try to find manifest in workspace
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
        m = _MANIFEST_OVERLAY_PERMISSION.search(content)
        if m:
            findings.append(self.create_finding(
                finding_id="tapjack_system_alert_window_000",
                title="SYSTEM_ALERT_WINDOW Permission Declared",
                description=(
                    "The app declares SYSTEM_ALERT_WINDOW permission, which allows drawing overlay "
                    "windows on top of other apps. This is a prerequisite for tapjacking attacks "
                    "where a transparent overlay captures user touches intended for the app below."
                ),
                severity="medium",
                confidence=0.80,
                file_path="AndroidManifest.xml",
                line_number=self._line_number(content, m.start()),
                code_snippet=self._snippet(content, m.start(), m.end()),
                cwe_id="CWE-1021",
                masvs_control="MASVS-PLATFORM-9",
                remediation=(
                    "Remove SYSTEM_ALERT_WINDOW permission unless overlay functionality is essential. "
                    "If required, implement filterTouchesWhenObscured on all sensitive views."
                ),
            ))
        return findings

    def _scan_source_patterns(self, content: str, rel_path: str) -> List[PluginFinding]:
        """Scan source file for tapjacking-related patterns."""
        findings = []
        seen_labels: Set[str] = set()

        for pattern, label, title, description, severity, cwe, confidence in _TAPJACKING_SOURCE_PATTERNS:
            if label in seen_labels:
                continue
            m = pattern.search(content)
            if m:
                seen_labels.add(label)
                findings.append(self.create_finding(
                    finding_id=f"tapjack_{label.lower()}_{len(findings):03d}",
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=confidence,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id=cwe,
                    masvs_control="MASVS-PLATFORM-9",
                    remediation=(
                        "Implement filterTouchesWhenObscured on sensitive "
                        "views and validate overlay permissions."
                    ),
                ))

        return findings

    def _check_xml_layouts(self, apk_ctx) -> List[PluginFinding]:
        """Check XML layouts for sensitive views missing filterTouchesWhenObscured."""
        workspace = getattr(apk_ctx, "workspace_dir", None) or getattr(apk_ctx, "output_dir", None)
        if not workspace:
            return []

        res_dir = Path(workspace) / "res"
        if not res_dir.is_dir():
            return []

        findings = []
        # Only check layout directories
        sensitive_view_re = re.compile(
            r'<\s*(?:Button|EditText|Switch|CheckBox|RadioButton|ToggleButton)\b'
        )
        filter_re = re.compile(r'android:filterTouchesWhenObscured\s*=\s*"true"')

        layouts_checked = 0
        for layout_dir in res_dir.iterdir():
            if not layout_dir.name.startswith("layout"):
                continue
            for xml_file in layout_dir.glob("*.xml"):
                try:
                    content = xml_file.read_text(errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                layouts_checked += 1

                # Check if file has sensitive interactive views without filterTouchesWhenObscured
                if sensitive_view_re.search(content) and not filter_re.search(content):
                    m = sensitive_view_re.search(content)
                    rel = self._relative_path(str(xml_file), apk_ctx)
                    findings.append(self.create_finding(
                        finding_id=f"tapjack_missing_filter_{len(findings):03d}",
                        title="Missing filterTouchesWhenObscured on Interactive Views",
                        description=(
                            f"Layout {xml_file.name} contains interactive views (Button, EditText, etc.) "
                            "without android:filterTouchesWhenObscured=\"true\". Without this attribute, "
                            "the view will accept touch events even when obscured by an overlay, making "
                            "it vulnerable to tapjacking attacks."
                        ),
                        severity="low",
                        confidence=0.55,
                        file_path=rel,
                        line_number=self._line_number(content, m.start()) if m else None,
                        code_snippet=self._snippet(content, m.start(), m.end()) if m else None,
                        cwe_id="CWE-1021",
                        masvs_control="MASVS-PLATFORM-9",
                        remediation=(
                            "Add android:filterTouchesWhenObscured=\"true\" to sensitive interactive "
                            "views, or set it programmatically with View.setFilterTouchesWhenObscured(true)."
                        ),
                    ))
                    # One finding per layout file is sufficient
                    if len(findings) >= 3:
                        break
            if len(findings) >= 3:
                break

        return findings


# Plugin factory
def create_plugin() -> TapjackingAnalyzerV2:
    return TapjackingAnalyzerV2()


__all__ = ["TapjackingAnalyzerV2", "create_plugin"]
