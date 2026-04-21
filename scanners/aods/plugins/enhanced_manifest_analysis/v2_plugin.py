#!/usr/bin/env python3
"""
enhanced_manifest_analysis - BasePluginV2 Implementation
=============================================================

BasePluginV2 migration providing standardized interface.
"""

import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Set

from core.xml_safe import safe_parse

import sys
from pathlib import Path

# Path setup for standalone execution
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

# Known malware permission combination patterns for IoC detection.
# Each entry defines a set of permissions that, when requested together,
# indicate a suspicious behavioral pattern commonly seen in malware families.
SUSPICIOUS_COMBOS: List[Dict[str, Any]] = [
    {
        "name": "SMS Trojan Indicators",
        "permissions": {
            "android.permission.RECEIVE_SMS",
            "android.permission.INTERNET",
            "android.permission.READ_CONTACTS",
        },
        "category": "sms_trojan",
        "severity": "high",
        "cwe": "CWE-506",
        "description": (
            "Permission combination commonly associated with SMS trojans "
            "that intercept messages and exfiltrate contact data."
        ),
    },
    {
        "name": "Spyware Indicators",
        "permissions": {
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.INTERNET",
        },
        "category": "spyware",
        "severity": "high",
        "cwe": "CWE-200",
        "description": (
            "Permission combination commonly associated with spyware "
            "that records audio/video and tracks location."
        ),
    },
    {
        "name": "Banking Trojan Indicators",
        "permissions": {
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.INTERNET",
        },
        "category": "banking_trojan",
        "severity": "critical",
        "cwe": "CWE-506",
        "description": (
            "Permission combination commonly associated with banking trojans "
            "using overlay attacks and accessibility abuse."
        ),
    },
    {
        "name": "Data Exfiltration Indicators",
        "permissions": {
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.INTERNET",
        },
        "category": "data_exfiltration",
        "severity": "high",
        "cwe": "CWE-200",
        "description": (
            "Permission combination enabling bulk data exfiltration "
            "of contacts, call logs, and storage."
        ),
    },
    {
        "name": "Ransomware Indicators",
        "permissions": {
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.INTERNET",
        },
        "category": "ransomware",
        "severity": "critical",
        "cwe": "CWE-506",
        "description": (
            "Permission combination associated with ransomware: device admin "
            "for lock, storage write for encryption, internet for C2."
        ),
    },
    {
        "name": "Stalkerware Indicators",
        "permissions": {
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_SMS",
            "android.permission.INTERNET",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        },
        "category": "stalkerware",
        "severity": "high",
        "cwe": "CWE-359",
        "description": (
            "Permission combination associated with stalkerware that "
            "silently monitors location, messages, and calls."
        ),
    },
]

# Severity ordering for downgrade on partial matches
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class EnhancedManifestAnalysisV2(BasePluginV2):
    """
    Enhanced Manifest Analysis - BasePluginV2 Implementation
    """

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="enhanced_manifest_analysis",
            version="2.0.0",
            description="Enhanced Manifest Analysis - Migrated to BasePluginV2",
            author="AODS Team",
            capabilities=[PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=300,
            supported_platforms=["android"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        """Execute structured manifest analysis with full field preservation."""
        start_time = time.time()

        try:
            findings = self._run_structured_analysis(apk_ctx)

            # Also check permission combos (V2-native, no legacy dependency)
            permissions = self._extract_permissions_from_manifest(apk_ctx)
            if permissions:
                combo_findings = self._check_suspicious_permission_combos(permissions)
                if combo_findings:
                    logger.info(
                        "Suspicious permission combo detection",
                        combo_findings_count=len(combo_findings),
                        total_permissions=len(permissions),
                    )
                    findings.extend(combo_findings)

            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    "execution_time": time.time() - start_time,
                    "plugin_version": "3.0.0",
                    "bridge": "structured",
                },
            )

        except Exception as e:
            logger.error("enhanced_manifest_analysis failed: %s", e)
            return PluginResult(
                status=PluginStatus.FAILURE,
                findings=[],
                metadata={"error": type(e).__name__, "execution_time": time.time() - start_time},
            )

    def _run_structured_analysis(self, apk_ctx) -> List[PluginFinding]:
        """Call the structured analysis pipeline and convert to PluginFinding.

        Calls EnhancedManifestAnalysisPlugin.analyze_manifest() which returns
        ManifestAnalysisResult, then migrate_to_standardized_vulnerabilities()
        to get fully-structured dicts with line_number, component_name,
        cwe_id, owasp_category, masvs_control, and full recommendations.
        """
        try:
            from plugins.enhanced_manifest_analysis import (
                EnhancedManifestAnalysisPlugin,
                migrate_to_standardized_vulnerabilities,
            )

            plugin = EnhancedManifestAnalysisPlugin()
            result = plugin.analyze_manifest(apk_ctx)
            vuln_dicts = migrate_to_standardized_vulnerabilities(result)

            findings = []
            for i, v in enumerate(vuln_dicts):
                # Full recommendations list → joined string
                recs = v.get("recommendations", [])
                remediation = "; ".join(str(r) for r in recs)[:500] if recs else None

                findings.append(PluginFinding(
                    finding_id=f"enhanced_manifest_analysis_{i:03d}",
                    title=str(v.get("title", "Manifest Security Issue")),
                    description=str(v.get("description", ""))[:500],
                    severity=self._normalize_severity(v.get("severity", "medium")),
                    confidence=self._normalize_confidence(v.get("confidence", 0.5)),
                    file_path=str(v.get("location", "AndroidManifest.xml")),
                    line_number=v.get("line_number"),
                    cwe_id=v.get("cwe_id"),
                    owasp_category=v.get("owasp_category"),
                    evidence=v.get("evidence") if isinstance(v.get("evidence"), dict) else {},
                    references=v.get("references", []),
                    remediation=remediation,
                    code_snippet=v.get("code_snippet"),
                ))

            return findings

        except Exception as e:
            logger.debug("Structured analysis failed, falling back to run_plugin: %s", e)
            return self._fallback_legacy(apk_ctx)

    def _fallback_legacy(self, apk_ctx) -> List[PluginFinding]:
        """Fallback to run_plugin() if structured analysis fails."""
        try:
            from plugins.enhanced_manifest_analysis import run_plugin
            result = run_plugin(apk_ctx)
            if isinstance(result, tuple) and len(result) >= 2 and isinstance(result[1], dict):
                vulns = result[1].get("vulnerabilities", [])
                if isinstance(vulns, list):
                    return [
                        PluginFinding(
                            finding_id=f"enhanced_manifest_analysis_{i:03d}",
                            title=str(v.get("title", "Finding")),
                            description=str(v.get("description", ""))[:500],
                            severity=self._normalize_severity(v.get("severity", "medium")),
                            confidence=self._normalize_confidence(v.get("confidence", 0.5)),
                            file_path=str(v.get("location", "AndroidManifest.xml")),
                            line_number=v.get("line_number"),
                            cwe_id=v.get("cwe_id"),
                        )
                        for i, v in enumerate(vulns) if isinstance(v, dict)
                    ]
        except Exception:
            pass
        return []

    def _extract_permissions_from_manifest(self, apk_ctx) -> Set[str]:
        """Extract the set of requested permission names from AndroidManifest.xml.

        Parses <uses-permission android:name="..."/> elements from the manifest
        and returns a set of fully-qualified permission strings.
        """
        permissions: Set[str] = set()
        manifest_path: Optional[Path] = None

        # Resolve manifest path from APK context
        if hasattr(apk_ctx, "manifest_path") and apk_ctx.manifest_path:
            candidate = Path(apk_ctx.manifest_path)
            if candidate.exists():
                manifest_path = candidate

        if manifest_path is None:
            logger.debug("No manifest_path available on apk_ctx; skipping permission extraction")
            return permissions

        try:
            tree = safe_parse(str(manifest_path))
            root = tree.getroot()
            android_ns = "{http://schemas.android.com/apk/res/android}"

            for elem in root.findall(".//uses-permission"):
                perm_name = elem.get(f"{android_ns}name")
                if perm_name:
                    permissions.add(perm_name)

            logger.debug(
                "Extracted permissions from manifest",
                permission_count=len(permissions),
                manifest_path=str(manifest_path),
            )
        except ET.ParseError as e:
            logger.warning(f"Failed to parse manifest XML for permission extraction: {e}")
        except Exception as e:
            logger.debug(f"Permission extraction failed: {e}")

        return permissions

    @staticmethod
    def _lower_severity(severity: str) -> str:
        """Return the next lower severity level.

        For example, ``"critical"`` becomes ``"high"``, ``"high"`` becomes
        ``"medium"``, etc.  ``"info"`` stays at ``"info"``.
        """
        try:
            idx = _SEVERITY_ORDER.index(severity)
        except ValueError:
            return "medium"
        return _SEVERITY_ORDER[min(idx + 1, len(_SEVERITY_ORDER) - 1)]

    def _check_suspicious_permission_combos(self, permissions: Set[str]) -> List[PluginFinding]:
        """Check for known malicious permission combination patterns.

        For each combo defined in ``SUSPICIOUS_COMBOS``:
        - **Full match** (all required permissions present): emit finding at
          the configured severity with confidence 0.85.
        - **Partial match** (>= 80 % of required permissions present): emit
          finding one severity level lower with confidence 0.60.

        Returns a list of ``PluginFinding`` instances, one per matched combo.
        """
        findings: List[PluginFinding] = []

        for combo in SUSPICIOUS_COMBOS:
            required: Set[str] = combo["permissions"]
            matched: Set[str] = permissions & required
            missing: Set[str] = required - permissions

            match_ratio = len(matched) / len(required) if required else 0.0
            is_full_match = match_ratio == 1.0
            is_partial_match = match_ratio >= 0.8 and not is_full_match

            if not (is_full_match or is_partial_match):
                continue

            category_upper = combo["category"].upper()
            finding_id = f"PERM_COMBO_{category_upper}_001"

            if is_full_match:
                severity = combo["severity"]
                confidence = 0.85
                match_type = "Full match"
            else:
                severity = self._lower_severity(combo["severity"])
                confidence = 0.60
                match_type = f"Partial match ({len(matched)}/{len(required)} permissions)"

            title = f"Suspicious Permission Combo: {combo['name']}"
            description = (
                f"{combo['description']} "
                f"{match_type} - {len(matched)} of {len(required)} indicator permissions present."
            )

            evidence: Dict[str, Any] = {
                "combo_name": combo["name"],
                "category": combo["category"],
                "match_type": "full" if is_full_match else "partial",
                "match_ratio": round(match_ratio, 2),
                "matched_permissions": sorted(matched),
                "missing_permissions": sorted(missing),
            }

            cwe_number = combo["cwe"].split("-")[1] if "-" in combo["cwe"] else combo["cwe"]
            refs = [
                f"https://cwe.mitre.org/data/definitions/{cwe_number}.html",
                "https://developer.android.com/guide/topics/permissions/overview",
            ]

            finding = PluginFinding(
                finding_id=finding_id,
                title=title,
                description=description,
                severity=severity,
                confidence=confidence,
                file_path="AndroidManifest.xml",
                line_number=None,
                cwe_id=combo["cwe"],
                owasp_category="M01-Improper-Platform-Usage",
                evidence=evidence,
                references=refs,
                remediation=(
                    f"Review the necessity of the following permissions: "
                    f"{', '.join(sorted(matched))}. "
                    f"Remove any that are not strictly required for core app functionality."
                ),
            )
            findings.append(finding)

            logger.info(
                "Detected suspicious permission combination",
                combo_name=combo["name"],
                match_type="full" if is_full_match else "partial",
                match_ratio=round(match_ratio, 2),
                matched_count=len(matched),
                required_count=len(required),
            )

        return findings

    def _normalize_severity(self, severity: Any) -> str:
        """Normalize severity value to valid string."""
        if isinstance(severity, str):
            severity_lower = severity.lower()
            if severity_lower in ["critical", "high", "medium", "low", "info"]:
                return severity_lower
        return "medium"

    def _normalize_confidence(self, confidence: Any) -> float:
        """Normalize confidence value to float [0.0-1.0]."""
        if isinstance(confidence, (int, float)):
            return max(0.0, min(1.0, float(confidence)))
        if isinstance(confidence, str):
            confidence_lower = confidence.lower()
            return {"high": 0.9, "medium": 0.5, "low": 0.3}.get(confidence_lower, 0.5)
        return 0.5


# Plugin factory


def create_plugin() -> EnhancedManifestAnalysisV2:
    """Create plugin instance."""
    return EnhancedManifestAnalysisV2()


__all__ = ["EnhancedManifestAnalysisV2", "create_plugin"]
