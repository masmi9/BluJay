#!/usr/bin/env python3
"""
ipc_binder_security - BasePluginV2 Implementation (Track 113.8)
===============================================================

Detects IPC/Binder security vulnerabilities in Android source code:
- PendingIntent with FLAG_MUTABLE + implicit Intent (CWE-927)
- bindService / startService without permission enforcement (CWE-926)
- Messenger IPC without sender validation (CWE-284)
- ContentProvider.call() without permission enforcement (CWE-284)
- grantUriPermission with overly broad URI patterns (CWE-732)
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


# --- IPC / Binder source code patterns ---

_IPC_SOURCE_PATTERNS = [
    (
        re.compile(
            r'PendingIntent\.get(?:Activity|Service|Broadcast|ForegroundService)\s*\([^)]*'
            r'(?:FLAG_MUTABLE|0x02000000)',
            re.DOTALL,
        ),
        "pending_intent_mutable",
        "Mutable PendingIntent",
        "A PendingIntent is created with FLAG_MUTABLE, allowing the receiving app to modify the "
        "underlying Intent. If the base Intent is implicit (no explicit component), a malicious app "
        "can intercept and alter the PendingIntent to redirect it or steal data.",
        "high",
        "CWE-927",
        0.85,
        "MASVS-PLATFORM-1",
    ),
    (
        re.compile(
            r'(?:bind(?:Isolated)?Service|startService|startForegroundService)\s*\(\s*'
            r'new\s+Intent\s*\(',
        ),
        "implicit_service_binding",
        "Implicit Intent for Service Binding",
        "A service is started or bound using an implicit Intent (new Intent without explicit "
        "component). On Android 5.0+, implicit service Intents throw an exception, but on older "
        "versions a malicious app can intercept the binding and impersonate the service.",
        "medium",
        "CWE-927",
        0.80,
        "MASVS-PLATFORM-1",
    ),
    (
        re.compile(
            r'new\s+Messenger\s*\(\s*(?:new\s+Handler|handler|mHandler)',
            re.IGNORECASE,
        ),
        "messenger_ipc",
        "Messenger IPC Without Sender Validation",
        "A Messenger is created for IPC communication. Messenger-based IPC does not provide "
        "built-in sender identity validation. Without explicit sender checks in handleMessage(), "
        "any app can send messages to this Messenger.",
        "medium",
        "CWE-284",
        0.70,
        "MASVS-PLATFORM-1",
    ),
    (
        re.compile(
            r'grantUriPermission\s*\([^)]*,\s*[^)]*,\s*'
            r'(?:Intent\.FLAG_GRANT_READ_URI_PERMISSION\s*\|\s*Intent\.FLAG_GRANT_WRITE_URI_PERMISSION'
            r'|FLAG_GRANT_READ_URI_PERMISSION\s*\|\s*FLAG_GRANT_WRITE_URI_PERMISSION)',
        ),
        "broad_uri_permission",
        "Overly Broad URI Permission Grant",
        "grantUriPermission() is called with both READ and WRITE permissions. Granting full "
        "read/write access to a content URI exposes more data than may be necessary, violating "
        "the principle of least privilege.",
        "medium",
        "CWE-732",
        0.80,
        "MASVS-PLATFORM-1",
    ),
    (
        re.compile(
            r'\.addFlags\s*\([^)]*FLAG_GRANT_(?:READ|WRITE)_URI_PERMISSION'
            r'[^)]*FLAG_GRANT_(?:READ|WRITE)_URI_PERMISSION',
        ),
        "intent_flag_uri_rw",
        "Intent Grants Read+Write URI Access",
        "An Intent is configured with both FLAG_GRANT_READ_URI_PERMISSION and "
        "FLAG_GRANT_WRITE_URI_PERMISSION. This grants the receiving component full access to "
        "the content URI, which may expose sensitive data.",
        "medium",
        "CWE-732",
        0.75,
        "MASVS-PLATFORM-1",
    ),
]

# Patterns that require method-context analysis (checked only within specific class/method bodies)
_CONTENTPROVIDER_CALL_RE = re.compile(
    r'(?:public\s+Bundle\s+call\s*\([^)]*\))',
)
_PERMISSION_CHECK_RE = re.compile(
    r'(?:checkCallingPermission|checkCallingOrSelfPermission|enforceCallingPermission'
    r'|enforceCallingOrSelfPermission|getCallingUid|Binder\.getCallingUid)',
)

# Manifest pattern for mutable PendingIntent via receiver
_MANIFEST_RECEIVER_NO_PERMISSION_RE = re.compile(
    r'<receiver[^>]*android:exported\s*=\s*"true"[^>]*>(?:(?!</receiver>).)*?'
    r'<intent-filter',
    re.DOTALL,
)

# Library path prefixes to skip
_LIBRARY_PREFIXES = (
    "android/support/", "androidx/", "com/google/", "com/facebook/", "com/squareup/",
    "com/bumptech/", "com/airbnb/", "io/reactivex/", "kotlin/", "kotlinx/",
    "org/apache/", "org/json/", "com/crashlytics/", "com/amplitude/",
    "okhttp3/", "retrofit2/", "dagger/", "butterknife/",
)


class IPCBinderSecurityV2(BasePluginV2):
    """Detects IPC/Binder security vulnerabilities (MASVS-PLATFORM-1, Track 113.8)."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="ipc_binder_security",
            version="1.0.0",
            description="Detects IPC/Binder security vulnerabilities (PendingIntent, Messenger, ContentProvider)",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["ipc", "binder", "pendingintent", "masvs-platform-1"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        files_scanned = 0

        try:
            workspace = getattr(apk_ctx, "workspace_dir", None) or getattr(apk_ctx, "output_dir", None)
            sources_dir = getattr(apk_ctx, "sources_dir", None)
            if not workspace and not sources_dir:
                return PluginResult(
                    status=PluginStatus.SUCCESS,
                    findings=[],
                    metadata={"execution_time": time.time() - start_time, "files_scanned": 0},
                )

            # Scan Java source files
            search_dirs = []
            if sources_dir and Path(sources_dir).is_dir():
                search_dirs.append(Path(sources_dir))
            if workspace:
                wp = Path(workspace)
                for subdir in ("sources", "java_source", "src"):
                    candidate = wp / subdir
                    if candidate.is_dir():
                        search_dirs.append(candidate)
                if not search_dirs:
                    search_dirs.append(wp)

            seen_labels: Set[str] = set()
            for search_dir in search_dirs:
                for java_file in search_dir.rglob("*.java"):
                    rel = str(java_file)
                    if self._is_library_code(rel):
                        continue
                    try:
                        content = java_file.read_text(errors="replace")
                    except (OSError, UnicodeDecodeError):
                        continue
                    files_scanned += 1

                    # Fast-path: skip files without IPC-related keywords
                    if not _has_ipc_keywords(content):
                        continue

                    rel_path = self._relative_path(str(java_file), apk_ctx)
                    findings.extend(self._check_source_patterns(content, rel_path, seen_labels))
                    findings.extend(self._check_contentprovider_call(content, rel_path, seen_labels))

            # Scan AndroidManifest.xml for exported receivers without permissions
            manifest_path = self._find_manifest(apk_ctx)
            if manifest_path:
                files_scanned += 1
                try:
                    manifest_content = Path(manifest_path).read_text(errors="replace")
                    findings.extend(self._check_manifest_ipc(manifest_content, seen_labels))
                except (OSError, UnicodeDecodeError):
                    pass

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
            logger.error(f"ipc_binder_security failed: {e}")
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

    def _find_manifest(self, apk_ctx) -> str:
        """Locate AndroidManifest.xml."""
        workspace = getattr(apk_ctx, "workspace_dir", None) or getattr(apk_ctx, "output_dir", None)
        if not workspace:
            return ""
        wp = Path(workspace)
        for candidate in [wp / "AndroidManifest.xml", wp / "resources" / "AndroidManifest.xml"]:
            if candidate.exists():
                return str(candidate)
        # Glob fallback
        manifests = list(wp.rglob("AndroidManifest.xml"))
        if manifests:
            return str(manifests[0])
        return ""

    # ------------------------------------------------------------------ checks

    def _check_source_patterns(
        self, content: str, rel_path: str, seen_labels: Set[str]
    ) -> List[PluginFinding]:
        findings = []
        for pattern, label, title, description, severity, cwe, confidence, masvs in _IPC_SOURCE_PATTERNS:
            dedup_key = f"{label}:{rel_path}"
            if dedup_key in seen_labels:
                continue
            m = pattern.search(content)
            if m:
                seen_labels.add(dedup_key)
                findings.append(self.create_finding(
                    finding_id=f"ipc_{label}_{len(findings):03d}",
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=confidence,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id=cwe,
                    masvs_control=masvs,
                    remediation=_REMEDIATION.get(label, "Review IPC security implementation."),
                ))
        return findings

    def _check_contentprovider_call(
        self, content: str, rel_path: str, seen_labels: Set[str]
    ) -> List[PluginFinding]:
        """Detect ContentProvider.call() methods without permission checks."""
        dedup_key = f"contentprovider_call:{rel_path}"
        if dedup_key in seen_labels:
            return []

        # Find ContentProvider.call() override
        m = _CONTENTPROVIDER_CALL_RE.search(content)
        if not m:
            return []

        # Check if there's a permission check within ~500 chars after the method declaration
        method_body_start = m.end()
        method_body_window = content[method_body_start:method_body_start + 500]
        if _PERMISSION_CHECK_RE.search(method_body_window):
            return []  # Has permission check - OK

        seen_labels.add(dedup_key)
        return [self.create_finding(
            finding_id=f"ipc_contentprovider_no_perm_{0:03d}",
            title="ContentProvider.call() Without Permission Check",
            description=(
                "A ContentProvider overrides the call() method without checking caller permissions. "
                "Without checkCallingPermission() or enforceCallingPermission(), any app can invoke "
                "this method and potentially access or modify protected data."
            ),
            severity="high",
            confidence=0.75,
            file_path=rel_path,
            line_number=self._line_number(content, m.start()),
            code_snippet=self._snippet(content, m.start(), m.end()),
            cwe_id="CWE-284",
            masvs_control="MASVS-PLATFORM-1",
            remediation=(
                "Add checkCallingPermission() or enforceCallingPermission() at the start of "
                "the call() method. Validate the caller's identity using Binder.getCallingUid()."
            ),
        )]

    def _check_manifest_ipc(
        self, content: str, seen_labels: Set[str]
    ) -> List[PluginFinding]:
        """Check manifest for exported receivers without permission protection."""
        findings = []
        for m in _MANIFEST_RECEIVER_NO_PERMISSION_RE.finditer(content):
            matched = m.group(0)
            # Skip if there's a permission attribute
            if 'android:permission=' in matched:
                continue
            dedup_key = f"manifest_exported_receiver:{m.start()}"
            if dedup_key in seen_labels:
                continue
            seen_labels.add(dedup_key)
            findings.append(self.create_finding(
                finding_id=f"ipc_exported_receiver_{len(findings):03d}",
                title="Exported BroadcastReceiver Without Permission",
                description=(
                    "A BroadcastReceiver is exported with an intent-filter but no android:permission "
                    "attribute. Any app can send broadcasts to this receiver, potentially triggering "
                    "unintended behavior or accessing sensitive functionality."
                ),
                severity="medium",
                confidence=0.80,
                file_path="AndroidManifest.xml",
                line_number=self._line_number(content, m.start()),
                code_snippet=self._snippet(content, m.start(), m.end())[:150],
                cwe_id="CWE-926",
                masvs_control="MASVS-PLATFORM-1",
                remediation=(
                    "Add android:permission to the receiver to restrict which apps can send broadcasts. "
                    "Use signature-level permissions for internal broadcasts."
                ),
            ))
        return findings


def _has_ipc_keywords(content: str) -> bool:
    """Fast check for IPC-related keywords before running regex patterns."""
    return any(kw in content for kw in (
        "PendingIntent", "bindService", "startService", "Messenger",
        "grantUriPermission", "FLAG_GRANT", "ContentProvider",
        "FLAG_MUTABLE",
    ))


_REMEDIATION = {
    "pending_intent_mutable": (
        "Use FLAG_IMMUTABLE instead of FLAG_MUTABLE unless the PendingIntent must be modified "
        "by the receiving app. If FLAG_MUTABLE is required, set an explicit component on the "
        "base Intent to prevent interception."
    ),
    "implicit_service_binding": (
        "Use explicit Intents (with setComponent() or setClassName()) for service binding. "
        "On Android 5.0+, implicit service Intents are rejected at runtime."
    ),
    "messenger_ipc": (
        "Validate sender identity in handleMessage() using Binder.getCallingUid() and "
        "getCallingPid(). Reject messages from untrusted callers."
    ),
    "broad_uri_permission": (
        "Grant only the minimum required permission (READ or WRITE, not both). "
        "Use more specific URI paths to limit the scope of the permission grant."
    ),
    "intent_flag_uri_rw": (
        "Only grant the minimum required URI permission. Use FLAG_GRANT_READ_URI_PERMISSION "
        "or FLAG_GRANT_WRITE_URI_PERMISSION, not both, unless full access is truly needed."
    ),
}


# Plugin factory
def create_plugin() -> IPCBinderSecurityV2:
    return IPCBinderSecurityV2()


__all__ = ["IPCBinderSecurityV2", "create_plugin"]
