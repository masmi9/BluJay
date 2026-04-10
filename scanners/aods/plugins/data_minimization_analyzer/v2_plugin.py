#!/usr/bin/env python3
"""
data_minimization_analyzer - BasePluginV2 Implementation (MASVS-PRIVACY-2)
==========================================================================

Detects excessive data collection, missing data deletion practices,
over-declared permissions, and package visibility over-queries.
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

_PII_PATTERNS = [
    (
        re.compile(r"\.getDeviceId\s*\("),
        "getDeviceId()",
        "Collects hardware device ID (IMEI) - ANDROID_ID is less invasive",
    ),
    (
        re.compile(r"\.getImei\s*\("),
        "getImei()",
        "Collects IMEI - ANDROID_ID is less invasive",
    ),
    (
        re.compile(r"\.getSubscriberId\s*\("),
        "getSubscriberId()",
        "Collects IMSI subscriber ID - excessive for most use cases",
    ),
    (
        re.compile(r"getLine1Number\s*\("),
        "getLine1Number()",
        "Collects phone number - rarely needed and privacy-invasive",
    ),
]

_CONTENT_ACCESS_PATTERNS = [
    (
        re.compile(r"ContactsContract"),
        "ContactsContract",
        "Accesses user contacts via ContactsContract",
    ),
    (
        re.compile(r"Telephony\.Sms|Telephony\.MmsSms"),
        "SMS content provider",
        "Accesses SMS messages",
    ),
    (
        re.compile(r"CallLog\.Calls|CallLog\.CONTENT_URI"),
        "CallLog",
        "Accesses call log history",
    ),
]

_DATA_WRITE_METHODS = re.compile(r"openFileOutput\s*\(|\.edit\(\)\s*\.put|getSharedPreferences\s*\(")
_DATA_DELETE_METHODS = re.compile(r"\.delete\s*\(|\.deleteFile\s*\(|\.clear\s*\(|\.remove\s*\(")

# SharedPreferences key prefixes that indicate SDK/third-party code.
# In obfuscated APKs, class paths are mangled but SharedPreferences key
# strings retain the original SDK package identifiers.
_SDK_PREFS_PREFIXES = (
    "com.google.firebase",
    "com.google.android.gms",
    "com.google.android.datatransport",
    "com.facebook.",
    "com.appsflyer.",
    "com.adjust.",
    "com.ironsource.",
    "com.applovin.",
    "com.unity3d.",
    "admob_",
    "com.crashlytics.",
)

_SENSITIVE_PERMISSIONS = {
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_EXTERNAL_STORAGE",
}

_OVER_DECL_THRESHOLD = 3


class DataMinimizationAnalyzerV2(BasePluginV2):
    """Detects excessive data collection and missing data-deletion practices (MASVS-PRIVACY-2)."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="data_minimization_analyzer",
            version="2.1.0",
            description="Detects excessive data collection, missing deletion, and over-declared permissions",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["privacy", "masvs-privacy-2"],
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

                if self._is_library_code(rel_path):
                    continue

                findings.extend(self._check_pii_collection(content, rel_path))
                findings.extend(self._check_content_access(content, rel_path))
                findings.extend(self._check_no_data_deletion(content, rel_path))

            # --- Manifest analysis ---
            manifest_path = self._get_manifest_path(apk_ctx)
            if manifest_path:
                findings.extend(self._check_over_declared_permissions(manifest_path))
                findings.extend(self._check_package_visibility(manifest_path))

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
            logger.error(f"data_minimization_analyzer failed: {e}")
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

    def _check_pii_collection(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings = []
        seen: Set[str] = set()
        for pattern, api_name, reason in _PII_PATTERNS:
            m = pattern.search(content)
            if m and api_name not in seen:
                seen.add(api_name)
                findings.append(self.create_finding(
                    finding_id=f"data_min_pii_{len(findings):03d}",
                    title=f"Excessive PII Collection: {api_name}",
                    description=f"{reason}. Consider using less invasive identifiers.",
                    severity="medium",
                    confidence=0.8,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id="CWE-250",
                    masvs_control="MASVS-PRIVACY-2",
                    remediation="Use ANDROID_ID or instance-scoped identifiers instead of hardware IDs.",
                ))
        return findings

    def _check_content_access(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings = []
        seen: Set[str] = set()
        for pattern, name, reason in _CONTENT_ACCESS_PATTERNS:
            m = pattern.search(content)
            if m and name not in seen:
                seen.add(name)
                findings.append(self.create_finding(
                    finding_id=f"data_min_content_{len(findings):03d}",
                    title=f"Sensitive Content Access: {name}",
                    description=f"{reason}. Verify this data is essential to app functionality.",
                    severity="medium",
                    confidence=0.7,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id="CWE-359",
                    masvs_control="MASVS-PRIVACY-2",
                    remediation="Only access sensitive content providers when strictly necessary.",
                ))
        return findings

    def _check_no_data_deletion(self, content: str, rel_path: str) -> List[PluginFinding]:
        write_match = _DATA_WRITE_METHODS.search(content)
        if not write_match:
            return []
        if _DATA_DELETE_METHODS.search(content):
            return []
        # Skip SDK code detected via SharedPreferences key names
        # (handles obfuscated paths where _is_library_code misses)
        content_lower = content.lower()
        if any(prefix in content_lower for prefix in _SDK_PREFS_PREFIXES):
            return []
        # Class writes data but never deletes - potential data retention issue
        class_match = re.search(r"class\s+(\w+)", content)
        class_name = class_match.group(1) if class_match else Path(rel_path).stem
        return [self.create_finding(
            finding_id="data_min_no_delete_000",
            title=f"No Data Deletion in {class_name}",
            description=(
                f"Class {class_name} writes persistent data (SharedPreferences/files) "
                "but has no corresponding delete/clear methods. This may violate "
                "data minimization requirements (right to erasure)."
            ),
            severity="low",
            confidence=0.6,
            file_path=rel_path,
            line_number=self._line_number(content, write_match.start()),
            code_snippet=self._snippet(content, write_match.start(), write_match.end()),
            cwe_id="CWE-459",
            masvs_control="MASVS-PRIVACY-2",
            remediation="Implement data deletion methods (clear/delete) for all persistent data stores.",
        )]

    def _check_over_declared_permissions(self, manifest_path: str) -> List[PluginFinding]:
        try:
            tree = ElementTree.parse(manifest_path)
            root = tree.getroot()
        except (ElementTree.ParseError, OSError):
            return []

        declared: List[str] = []
        for elem in root.iter("uses-permission"):
            perm_name = elem.get(f"{ANDROID_NS}name") or elem.get("name") or ""
            if perm_name in _SENSITIVE_PERMISSIONS:
                declared.append(perm_name)

        if len(declared) < _OVER_DECL_THRESHOLD:
            return []

        perm_list = ", ".join(p.split(".")[-1] for p in declared)
        return [self.create_finding(
            finding_id="data_min_over_perm_000",
            title=f"Over-Declared Sensitive Permissions ({len(declared)})",
            description=(
                f"Manifest declares {len(declared)} sensitive permissions: {perm_list}. "
                "Requesting more permissions than necessary increases attack surface "
                "and may violate data minimization principles."
            ),
            severity="medium",
            confidence=0.7,
            file_path="AndroidManifest.xml",
            cwe_id="CWE-250",
            masvs_control="MASVS-PRIVACY-2",
            remediation="Review each permission and remove those not essential to core functionality.",
        )]

    def _check_package_visibility(self, manifest_path: str) -> List[PluginFinding]:
        try:
            tree = ElementTree.parse(manifest_path)
            root = tree.getroot()
        except (ElementTree.ParseError, OSError):
            return []

        queries_elem = root.find("queries")
        if queries_elem is None:
            return []

        pkg_entries = queries_elem.findall("package")
        if len(pkg_entries) <= 5:
            return []

        return [self.create_finding(
            finding_id="data_min_pkg_vis_000",
            title=f"Excessive Package Visibility Queries ({len(pkg_entries)} packages)",
            description=(
                f"Manifest <queries> block lists {len(pkg_entries)} specific packages. "
                "Querying too many installed packages can be used for fingerprinting "
                "and violates the principle of data minimization (Android 11+)."
            ),
            severity="low",
            confidence=0.7,
            file_path="AndroidManifest.xml",
            cwe_id="CWE-200",
            masvs_control="MASVS-PRIVACY-2",
            remediation="Minimize <queries> entries to only packages essential for app functionality.",
        )]


# Plugin factory
def create_plugin() -> DataMinimizationAnalyzerV2:
    return DataMinimizationAnalyzerV2()


__all__ = ["DataMinimizationAnalyzerV2", "create_plugin"]
