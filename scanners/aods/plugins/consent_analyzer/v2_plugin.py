#!/usr/bin/env python3
"""
consent_analyzer - BasePluginV2 Implementation (MASVS-PRIVACY-3)
================================================================

Detects missing consent mechanisms for data collection using negative-detection:
flags when consent patterns are ABSENT despite data collection APIs being used.
"""

import re
import time
from pathlib import Path
from typing import List, Optional
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

# --- Data collection indicators (presence means the app collects data) ---

_DATA_COLLECTION_APIS = re.compile(
    r"getSharedPreferences\s*\("
    r"|getLastKnownLocation\s*\("
    r"|requestLocationUpdates\s*\("
    r"|ContactsContract"
    r"|TelephonyManager"
    r"|getDeviceId\s*\("
    r"|getAdvertisingIdInfo\s*\("
    r"|FirebaseAnalytics"
    r"|\.getImei\s*\("
)

# --- Consent mechanism indicators ---

_CONSENT_PATTERNS = re.compile(
    r"AlertDialog.*consent"
    r"|consent.*dialog"
    r"|opt.?in"
    r"|accept.*terms"
    r"|agree.*privacy"
    r"|ConsentForm"
    r"|UserConsent"
    r"|showConsentDialog"
    r"|consent_accepted"
    r"|hasUserConsent",
    re.IGNORECASE,
)

_PRIVACY_POLICY_PATTERNS = re.compile(
    r"privacy.{0,5}policy"
    r"|terms.{0,5}service"
    r"|privacypolicy"
    r"|PrivacyPolicy"
    r"|privacy_policy_url",
    re.IGNORECASE,
)

_OPT_OUT_PATTERNS = re.compile(
    r"opt.?out"
    r"|unsubscribe"
    r"|disable.{0,5}tracking"
    r"|do.?not.?track"
    r"|withdraw.?consent"
    r"|revoke.?consent",
    re.IGNORECASE,
)

_GDPR_PATTERNS = re.compile(
    r"GDPR"
    r"|data.?protection"
    r"|CCPA"
    r"|LGPD"
    r"|right.?to.?erasure"
    r"|data.?subject",
    re.IGNORECASE,
)

_PII_ACCESS_APIS = re.compile(
    r"getLastKnownLocation\s*\("
    r"|requestLocationUpdates\s*\("
    r"|ContactsContract"
    r"|getDeviceId\s*\("
    r"|\.getImei\s*\("
)

_RATIONALE_PATTERN = re.compile(r"shouldShowRequestPermissionRationale")

_DANGEROUS_MANIFEST_PERMS = {
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
}


class ConsentAnalyzerV2(BasePluginV2):
    """Detects missing consent mechanisms for data collection (MASVS-PRIVACY-3)."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="consent_analyzer",
            version="2.1.0",
            description="Detects missing consent dialogs, privacy policies, opt-out, and permission rationale",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["privacy", "masvs-privacy-3"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        files_scanned = 0

        try:
            source_files = self._get_source_files(apk_ctx)
            all_content = ""
            has_data_collection = False
            has_consent = False
            has_privacy_policy = False
            has_opt_out = False
            has_gdpr = False
            has_pii_access = False

            for src_path in source_files:
                try:
                    content = Path(src_path).read_text(errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                files_scanned += 1

                if self._is_library_code(str(src_path)):
                    continue

                all_content += content + "\n"

                if _DATA_COLLECTION_APIS.search(content):
                    has_data_collection = True
                if _CONSENT_PATTERNS.search(content):
                    has_consent = True
                if _PRIVACY_POLICY_PATTERNS.search(content):
                    has_privacy_policy = True
                if _OPT_OUT_PATTERNS.search(content):
                    has_opt_out = True
                if _GDPR_PATTERNS.search(content):
                    has_gdpr = True
                if _PII_ACCESS_APIS.search(content):
                    has_pii_access = True

            # Negative detection: flag when consent is ABSENT despite data collection
            if has_data_collection and not has_consent:
                findings.append(self.create_finding(
                    finding_id="consent_no_dialog_000",
                    title="No Consent Dialog for Data Collection",
                    description=(
                        "Application uses data collection APIs (SharedPreferences, Location, Contacts, etc.) "
                        "but no consent dialog or consent mechanism was found in the source code."
                    ),
                    severity="medium",
                    confidence=0.7,
                    file_path="app://source",
                    cwe_id="CWE-862",
                    masvs_control="MASVS-PRIVACY-3",
                    remediation="Implement a consent dialog before collecting user data.",
                ))

            if files_scanned > 0 and not has_privacy_policy:
                findings.append(self.create_finding(
                    finding_id="consent_no_privacy_policy_000",
                    title="Missing Privacy Policy Reference",
                    description=(
                        "No privacy policy or terms of service URL reference was found in the source code. "
                        "Apps that collect user data should reference a privacy policy."
                    ),
                    severity="low",
                    confidence=0.6,
                    file_path="app://source",
                    cwe_id="CWE-693",
                    masvs_control="MASVS-PRIVACY-3",
                    remediation="Add a link to the app's privacy policy in the settings or about screen.",
                ))

            if has_data_collection and not has_opt_out:
                findings.append(self.create_finding(
                    finding_id="consent_no_opt_out_000",
                    title="No Opt-Out Mechanism for Data Collection",
                    description=(
                        "Application collects data but no opt-out, unsubscribe, or disable-tracking "
                        "mechanism was found. Users should be able to withdraw consent."
                    ),
                    severity="medium",
                    confidence=0.6,
                    file_path="app://source",
                    cwe_id="CWE-862",
                    masvs_control="MASVS-PRIVACY-3",
                    remediation="Implement an opt-out mechanism allowing users to withdraw data collection consent.",
                ))

            if has_pii_access and not has_gdpr:
                findings.append(self.create_finding(
                    finding_id="consent_no_gdpr_000",
                    title="GDPR/Data Protection Reference Absent",
                    description=(
                        "Application accesses PII (location, contacts, device ID) but no GDPR, CCPA, "
                        "or data protection framework reference was found."
                    ),
                    severity="low",
                    confidence=0.5,
                    file_path="app://source",
                    cwe_id="CWE-693",
                    masvs_control="MASVS-PRIVACY-3",
                    remediation="Implement data protection compliance references (GDPR, CCPA) where applicable.",
                ))

            # Manifest: dangerous permissions without rationale
            manifest_path = self._get_manifest_path(apk_ctx)
            if manifest_path:
                findings.extend(self._check_permission_rationale(
                    manifest_path, _RATIONALE_PATTERN.search(all_content) is not None
                ))

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
            logger.error(f"consent_analyzer failed: {e}")
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

    def _check_permission_rationale(self, manifest_path: str, has_rationale: bool) -> List[PluginFinding]:
        """Flag dangerous permissions when no shouldShowRequestPermissionRationale is found."""
        try:
            tree = ElementTree.parse(manifest_path)
            root = tree.getroot()
        except (ElementTree.ParseError, OSError):
            return []

        dangerous_found: List[str] = []
        for elem in root.iter("uses-permission"):
            perm_name = elem.get(f"{ANDROID_NS}name") or elem.get("name") or ""
            if perm_name in _DANGEROUS_MANIFEST_PERMS:
                dangerous_found.append(perm_name)

        if not dangerous_found or has_rationale:
            return []

        perm_list = ", ".join(p.split(".")[-1] for p in dangerous_found)
        return [self.create_finding(
            finding_id="consent_no_rationale_000",
            title=f"Dangerous Permission Without Rationale ({len(dangerous_found)})",
            description=(
                f"Manifest declares dangerous permissions ({perm_list}) but "
                "shouldShowRequestPermissionRationale is not used in the source code. "
                "Users should understand why the app needs each permission."
            ),
            severity="medium",
            confidence=0.7,
            file_path="AndroidManifest.xml",
            cwe_id="CWE-862",
            masvs_control="MASVS-PRIVACY-3",
            remediation="Use shouldShowRequestPermissionRationale() to explain why each permission is needed.",
        )]


# Plugin factory
def create_plugin() -> ConsentAnalyzerV2:
    return ConsentAnalyzerV2()


__all__ = ["ConsentAnalyzerV2", "create_plugin"]
