#!/usr/bin/env python3
"""
fileprovider_security - FileProvider Configuration Security (AH-2)
===================================================================

Analyzes FileProvider declarations in AndroidManifest.xml and the
corresponding file_paths.xml for overly broad path sharing that could
expose the filesystem to other apps.

MASVS-PLATFORM-1, MASVS-STORAGE-2
CWE-22: Path Traversal
CWE-639: Authorization Bypass Through User-Controlled Key
"""

import re
import time
from pathlib import Path
from typing import List, Dict

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

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Risk levels by path element type when path="." or path=""
_PATH_RISK: Dict[str, str] = {
    "root-path": "critical",
    "external-path": "high",
    "external-files-path": "high",
    "external-cache-path": "medium",
    "external-media-path": "medium",
    "files-path": "medium",
    "cache-path": "low",
}

# Source patterns
_GET_URI_FOR_FILE = re.compile(r'getUriForFile\s*\(', re.IGNORECASE)
_GRANT_URI_PERM = re.compile(
    r'grantUriPermission\s*\([^)]*FLAG_GRANT_(?:READ|WRITE)_URI_PERMISSION',
)


class FileProviderSecurityV2(BasePluginV2):
    """Analyzes FileProvider configuration for overly broad file sharing."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="fileprovider_security",
            version="1.0.0",
            description="FileProvider configuration security - path scope, export, permission (CWE-22/639)",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=60,
            supported_platforms=["android"],
            tags=["fileprovider", "storage", "masvs-platform-1", "cwe-22"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []

        try:
            findings.extend(self._check_manifest(apk_ctx))
            findings.extend(self._check_source(apk_ctx))

            return PluginResult(
                status=PluginStatus.SUCCESS, findings=findings,
                metadata={"execution_time": time.time() - start_time, "plugin_version": "1.0.0"},
            )
        except Exception as e:
            logger.error("fileprovider_security failed: %s", e)
            return PluginResult(
                status=PluginStatus.FAILURE, findings=findings,
                metadata={"error": type(e).__name__, "execution_time": time.time() - start_time},
            )

    def _check_manifest(self, apk_ctx) -> List[PluginFinding]:
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

        idx = 0
        for provider in root.findall(".//provider"):
            name = provider.get(f"{_ANDROID_NS}name", "")
            if "FileProvider" not in name and "fileprovider" not in name.lower():
                continue

            exported = provider.get(f"{_ANDROID_NS}exported", "false")

            # CRITICAL: exported FileProvider
            if exported.lower() == "true":
                findings.append(PluginFinding(
                    finding_id=f"fp_security_{idx:03d}",
                    title=f"FileProvider Exported: {name}",
                    description=(
                        "FileProvider is declared with android:exported=\"true\". This exposes "
                        "shared files to ALL apps on the device. FileProvider should always be "
                        "android:exported=\"false\" and use grantUriPermission for controlled access."
                    ),
                    severity="critical", confidence=0.95, cwe_id="CWE-22",
                    file_path="AndroidManifest.xml", line_number=None,
                    remediation="Set android:exported=\"false\" on the FileProvider declaration",
                ))
                idx += 1

            # Find file_paths.xml resource
            for meta in provider.findall("meta-data"):
                meta_name = meta.get(f"{_ANDROID_NS}name", "")
                if "file_provider_paths" in meta_name.lower() or meta_name == "android.support.FILE_PROVIDER_PATHS":
                    resource = meta.get(f"{_ANDROID_NS}resource", "")
                    if resource:
                        path_findings = self._analyze_file_paths(apk_ctx, resource, name)
                        findings.extend(path_findings)
                        idx += len(path_findings)

        return findings

    def _analyze_file_paths(self, apk_ctx, resource_ref: str, provider_name: str) -> List[PluginFinding]:
        """Analyze the file_paths.xml for overly broad path declarations."""
        findings = []

        # Resolve resource path - typically @xml/file_paths → res/xml/file_paths.xml
        res_name = resource_ref.replace("@xml/", "").replace("@", "")
        decompiled = getattr(apk_ctx, "decompiled_path", None) or getattr(apk_ctx, "sources_dir", None)
        if not decompiled:
            return findings

        decompiled = Path(decompiled) if not isinstance(decompiled, Path) else decompiled
        candidates = [
            decompiled / "res" / "xml" / f"{res_name}.xml",
            decompiled.parent / "res" / "xml" / f"{res_name}.xml",
        ]

        xml_path = None
        for c in candidates:
            if c.exists():
                xml_path = c
                break

        if not xml_path:
            return findings

        try:
            from core.xml_safe import safe_parse
            tree = safe_parse(str(xml_path))
            root = tree.getroot()
        except Exception:
            return findings

        idx = 200
        total_paths = 0

        for tag, risk_level in _PATH_RISK.items():
            for elem in root.findall(f".//{tag}"):
                total_paths += 1
                path_attr = elem.get("path", "")

                # Broad path: "." or "" (expose entire scope)
                if path_attr in (".", ""):
                    findings.append(PluginFinding(
                        finding_id=f"fp_security_{idx:03d}",
                        title=f"FileProvider Broad Path: <{tag} path=\"{path_attr}\"/>",
                        description=(
                            f"FileProvider path declaration <{tag} path=\"{path_attr}\"/> "
                            f"exposes the entire {tag.replace('-', ' ')} directory. "
                            "This grants access to all files in that scope."
                        ),
                        severity=risk_level, confidence=0.85, cwe_id="CWE-22",
                        file_path=str(xml_path.name),
                        line_number=None,
                        remediation=f"Restrict to a specific subdirectory: <{tag} path=\"shared_docs/\"/>",
                    ))
                    idx += 1

        # Over-sharing: too many path elements
        if total_paths > 5:
            findings.append(PluginFinding(
                finding_id=f"fp_security_{idx:03d}",
                title=f"FileProvider Over-Sharing: {total_paths} path declarations",
                description=(
                    f"FileProvider for {provider_name} declares {total_paths} path elements. "
                    "Each path element increases the attack surface for file access."
                ),
                severity="medium", confidence=0.60, cwe_id="CWE-639",
                file_path=str(xml_path.name),
                line_number=None,
                remediation="Reduce the number of shared paths to the minimum required",
            ))

        return findings

    def _check_source(self, apk_ctx) -> List[PluginFinding]:
        findings = []
        src = getattr(apk_ctx, "source_files", None)
        if not src:
            d = getattr(apk_ctx, "sources_dir", None)
            if d and Path(d).is_dir():
                src = [str(p) for p in Path(d).rglob("*") if p.suffix in (".java", ".kt")]
            else:
                return findings

        idx = 300
        for src_path in src:
            try:
                content = Path(src_path).read_text(errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            rel = self._relative_path(src_path, apk_ctx)
            if self._is_library_code(rel):
                continue

            for m in _GRANT_URI_PERM.finditer(content):
                line = content[:m.start()].count("\n") + 1
                findings.append(PluginFinding(
                    finding_id=f"fp_security_{idx:03d}",
                    title="FileProvider: Broad URI permission grant",
                    description=(
                        "grantUriPermission() called with read/write flags. "
                        "Verify the URI is scoped to the minimum necessary path."
                    ),
                    severity="medium", confidence=0.60, cwe_id="CWE-639",
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


def create_plugin():
    return FileProviderSecurityV2()


__all__ = ["FileProviderSecurityV2", "create_plugin"]
