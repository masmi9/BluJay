#!/usr/bin/env python3
"""
strandhogg_detector - StrandHogg / Task Hijacking Detection (AH-1)
===================================================================

Detects StrandHogg v1 (manifest-level task hijacking) and v2 (source-level
task manipulation) vulnerabilities in Android applications.

StrandHogg allows a malicious app to hijack the task stack of a legitimate
app, overlaying phishing UIs to steal credentials.

MASVS-PLATFORM-1: Platform Interaction Security
CWE-927: Improper Verification of Intent by Broadcast Receiver
"""

import re
import time
from pathlib import Path
from typing import List, Optional

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

# Source-level StrandHogg v2 patterns
_FLAG_NEW_TASK = re.compile(r'FLAG_ACTIVITY_NEW_TASK', re.IGNORECASE)
_SET_TASK_AFFINITY = re.compile(r'setTaskAffinity\s*\(', re.IGNORECASE)
_MOVE_TASK_BACK = re.compile(r'moveTaskToBack\s*\(', re.IGNORECASE)
_FLAG_CLEAR_TOP = re.compile(r'FLAG_ACTIVITY_CLEAR_TOP')

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


class StrandhoggDetectorV2(BasePluginV2):
    """Detects StrandHogg v1/v2 task hijacking vulnerabilities."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="strandhogg_detector",
            version="1.0.0",
            description="StrandHogg / task hijacking detection - taskAffinity, launchMode, reparenting (CWE-927)",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=60,
            supported_platforms=["android"],
            tags=["strandhogg", "task-hijacking", "masvs-platform-1", "cwe-927"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []

        try:
            findings.extend(self._check_manifest(apk_ctx))
            findings.extend(self._check_source(apk_ctx))

            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={"execution_time": time.time() - start_time, "plugin_version": "1.0.0"},
            )
        except Exception as e:
            logger.error("strandhogg_detector failed: %s", e)
            return PluginResult(
                status=PluginStatus.FAILURE, findings=findings,
                metadata={"error": type(e).__name__, "execution_time": time.time() - start_time},
            )

    def _check_manifest(self, apk_ctx) -> List[PluginFinding]:
        """Check AndroidManifest.xml for StrandHogg v1 patterns."""
        findings = []
        manifest_path = getattr(apk_ctx, "manifest_path", None)
        if not manifest_path:
            return findings

        manifest_path = Path(manifest_path) if not isinstance(manifest_path, Path) else manifest_path
        if not manifest_path.exists():
            return findings

        try:
            from core.xml_safe import safe_parse
            tree = safe_parse(str(manifest_path))
            root = tree.getroot()
        except Exception:
            return findings

        package = root.get("package", "")
        target_sdk = self._get_target_sdk(root)
        idx = 0

        for activity in root.findall(".//activity"):
            name = activity.get(f"{_ANDROID_NS}name", "")
            exported = self._is_exported(activity)
            if not exported:
                continue

            task_affinity = activity.get(f"{_ANDROID_NS}taskAffinity")
            launch_mode = activity.get(f"{_ANDROID_NS}launchMode", "")
            reparenting = activity.get(f"{_ANDROID_NS}allowTaskReparenting", "")
            has_permission = activity.get(f"{_ANDROID_NS}permission") is not None

            # StrandHogg v1: empty taskAffinity on exported activity
            if task_affinity == "":
                findings.append(PluginFinding(
                    finding_id=f"strandhogg_{idx:03d}",
                    title=f"StrandHogg v1: Empty taskAffinity on exported activity {name}",
                    description=(
                        f"Activity '{name}' is exported with taskAffinity=\"\" (empty). "
                        "This allows a malicious app to hijack the task stack, displaying "
                        "a phishing overlay when the user launches this app."
                    ),
                    severity="high", confidence=0.85, cwe_id="CWE-927",
                    file_path="AndroidManifest.xml", line_number=None,
                    remediation=(
                        "Set android:taskAffinity to your package name or remove the attribute. "
                        "For targetSdkVersion >= 31, Android mitigates StrandHogg v1."
                    ),
                ))
                idx += 1

            # StrandHogg v1: taskAffinity set to foreign package
            if task_affinity and task_affinity != "" and task_affinity != package:
                if not task_affinity.startswith(package):
                    findings.append(PluginFinding(
                        finding_id=f"strandhogg_{idx:03d}",
                        title=f"StrandHogg v1: Foreign taskAffinity on exported activity {name}",
                        description=(
                            f"Activity '{name}' has taskAffinity=\"{task_affinity}\" which differs "
                            f"from the app's package name '{package}'. This enables task hijacking."
                        ),
                        severity="critical", confidence=0.90, cwe_id="CWE-927",
                        file_path="AndroidManifest.xml", line_number=None,
                    ))
                    idx += 1

            # singleTask + exported without permission
            if launch_mode == "singleTask" and not has_permission:
                findings.append(PluginFinding(
                    finding_id=f"strandhogg_{idx:03d}",
                    title=f"Task Hijacking Risk: singleTask exported activity {name}",
                    description=(
                        f"Activity '{name}' uses launchMode=\"singleTask\" and is exported "
                        "without permission protection. An attacker can inject activities into "
                        "this task stack."
                    ),
                    severity="medium", confidence=0.70, cwe_id="CWE-927",
                    file_path="AndroidManifest.xml", line_number=None,
                    remediation="Add android:permission with protectionLevel=\"signature\"",
                ))
                idx += 1

            # allowTaskReparenting + exported
            if reparenting.lower() == "true":
                findings.append(PluginFinding(
                    finding_id=f"strandhogg_{idx:03d}",
                    title=f"Task Hijacking Risk: allowTaskReparenting on exported activity {name}",
                    description=(
                        f"Activity '{name}' has allowTaskReparenting=\"true\" and is exported. "
                        "This allows the activity to move between tasks, enabling UI spoofing."
                    ),
                    severity="medium", confidence=0.75, cwe_id="CWE-927",
                    file_path="AndroidManifest.xml", line_number=None,
                    remediation="Set android:allowTaskReparenting=\"false\" or restrict export",
                ))
                idx += 1

        # Info-level note if targetSdk < 31
        if target_sdk and target_sdk < 31 and findings:
            findings.append(PluginFinding(
                finding_id=f"strandhogg_{idx:03d}",
                title="StrandHogg Mitigation: targetSdkVersion < 31",
                description=(
                    f"App targets SDK {target_sdk} (< 31). Android 12 (SDK 31) mitigates "
                    "StrandHogg v1 by restricting task affinity. Upgrading targetSdkVersion "
                    "reduces task hijacking risk."
                ),
                severity="info", confidence=0.90, cwe_id="CWE-927",
                file_path="AndroidManifest.xml", line_number=None,
                remediation="Upgrade targetSdkVersion to 31 or higher",
            ))

        return findings

    def _check_source(self, apk_ctx) -> List[PluginFinding]:
        """Check source code for StrandHogg v2 patterns."""
        findings = []
        src = getattr(apk_ctx, "source_files", None)
        if not src:
            sources_dir = getattr(apk_ctx, "sources_dir", None)
            if sources_dir and Path(sources_dir).is_dir():
                src = [str(p) for p in Path(sources_dir).rglob("*") if p.suffix in (".java", ".kt")]
            else:
                return findings

        idx = 100
        for src_path in src:
            try:
                content = Path(src_path).read_text(errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            rel = self._relative_path(src_path, apk_ctx)
            if self._is_library_code(rel):
                continue

            # FLAG_ACTIVITY_NEW_TASK + FLAG_ACTIVITY_CLEAR_TOP in same method
            if _FLAG_NEW_TASK.search(content) and _FLAG_CLEAR_TOP.search(content):
                for m in _FLAG_NEW_TASK.finditer(content):
                    line = content[:m.start()].count("\n") + 1
                    findings.append(PluginFinding(
                        finding_id=f"strandhogg_{idx:03d}",
                        title="StrandHogg v2: FLAG_ACTIVITY_NEW_TASK + CLEAR_TOP combination",
                        description=(
                            "Source code uses FLAG_ACTIVITY_NEW_TASK combined with "
                            "FLAG_ACTIVITY_CLEAR_TOP, which can be used for task stack manipulation."
                        ),
                        severity="medium", confidence=0.60, cwe_id="CWE-927",
                        file_path=rel, line_number=line,
                    ))
                    idx += 1
                    break  # One per file

            # Dynamic setTaskAffinity()
            for m in _SET_TASK_AFFINITY.finditer(content):
                line = content[:m.start()].count("\n") + 1
                findings.append(PluginFinding(
                    finding_id=f"strandhogg_{idx:03d}",
                    title="StrandHogg v2: Dynamic setTaskAffinity() call",
                    description="setTaskAffinity() is called dynamically, enabling runtime task manipulation.",
                    severity="medium", confidence=0.65, cwe_id="CWE-927",
                    file_path=rel, line_number=line,
                ))
                idx += 1
                break

            # moveTaskToBack() concealment
            for m in _MOVE_TASK_BACK.finditer(content):
                line = content[:m.start()].count("\n") + 1
                findings.append(PluginFinding(
                    finding_id=f"strandhogg_{idx:03d}",
                    title="Task Concealment: moveTaskToBack() usage",
                    description="moveTaskToBack() can be used to conceal malicious task stack manipulation.",
                    severity="low", confidence=0.50, cwe_id="CWE-927",
                    file_path=rel, line_number=line,
                ))
                idx += 1
                break

        return findings

    def _relative_path(self, full, ctx):
        ws = getattr(ctx, "workspace_dir", None) or getattr(ctx, "output_dir", None)
        if ws:
            try:
                return str(Path(full).relative_to(ws))
            except (ValueError, TypeError):
                pass
        parts = Path(full).parts
        if "sources" in parts:
            return str(Path(*parts[parts.index("sources"):]))
        return Path(full).name

    @staticmethod
    def _is_exported(element) -> bool:
        exported = element.get(f"{_ANDROID_NS}exported")
        if exported == "true":
            return True
        if exported == "false":
            return False
        # Default: exported if has intent-filter
        return len(element.findall("intent-filter")) > 0

    @staticmethod
    def _get_target_sdk(root) -> Optional[int]:
        for uses_sdk in root.findall(".//uses-sdk"):
            target = uses_sdk.get(f"{_ANDROID_NS}targetSdkVersion")
            if target:
                try:
                    return int(target)
                except ValueError:
                    pass
        return None


def create_plugin():
    return StrandhoggDetectorV2()


__all__ = ["StrandhoggDetectorV2", "create_plugin"]
