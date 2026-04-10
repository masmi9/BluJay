"""
Certificate Pinning Analyzer – checks for SSL certificate pinning implementation.
"""
from __future__ import annotations

import re
from typing import List

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)

_PINNING_PATTERNS = [
    r'TrustKit',
    r'SSLPinning',
    r'certificatePinning',
    r'pinnedCertificates',
    r'AFSSLPinningModeCertificate|AFSSLPinningModePublicKey',
    r'ServerTrustPolicy\.(pinCertificates|pinPublicKeys)',
    r'SecCertificateCopyData',
    r'kSecTrustAnchorCertificates',
    r'NSPinnedDomains',
    r'publicKeyHash',
    r'certificateHash',
]

_COMBINED = re.compile("|".join(_PINNING_PATTERNS), re.IGNORECASE)

_BYPASS_PATTERNS = [
    (r'AFSSLPinningModeNone', "AFNetworking Pinning Disabled", "AFSSLPinningModeNone disables all cert pinning."),
    (r'evaluateServerTrust.*true|trustAllCertificates', "Trust-All Certificate Override",
     "All certificates are unconditionally trusted."),
]


class CertPinningAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="cert_pinning_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.NETWORK_ANALYSIS, PluginCapability.STATIC_ANALYSIS],
            description="Checks for SSL certificate pinning implementation and bypass patterns.",
            priority=PluginPriority.NORMAL,
            timeout_seconds=60,
            tags=["pinning", "certificate", "ssl", "tls", "mitm"],
            masvs_control="MASVS-NETWORK-2",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []

        strings_text = "\n".join(ipa_ctx.get_strings())
        classdump_dir = ipa_ctx.classdump_dir
        classdump_text = ""
        if classdump_dir.exists():
            for f in classdump_dir.glob("*.h"):
                try:
                    classdump_text += f.read_text(errors="replace") + "\n"
                except Exception:
                    pass
        combined = strings_text + "\n" + classdump_text

        # Check for pinning implementation
        pinning_matches = _COMBINED.findall(combined)
        has_pinning = bool(pinning_matches)

        # Check for NSPinnedDomains in Info.plist (iOS 14+ built-in pinning)
        ats = ipa_ctx.info_plist.get("NSAppTransportSecurity", {})
        has_ns_pinning = bool(ats.get("NSPinnedDomains"))

        if not has_pinning and not has_ns_pinning:
            findings.append(self.create_finding(
                "pinning_not_implemented",
                "SSL Certificate Pinning Not Detected",
                "No certificate pinning implementation was detected. Without pinning, "
                "the app is vulnerable to man-in-the-middle attacks using a trusted CA certificate.",
                "medium",
                confidence=0.65,
                cwe_id="CWE-295",
                masvs_control="MASVS-NETWORK-2",
                remediation="Implement certificate pinning using one of: "
                            "NSPinnedDomains in Info.plist (iOS 14+), TrustKit framework, "
                            "or custom URLSessionDelegate with certificate hash comparison. "
                            "Pin the leaf certificate or SubjectPublicKeyInfo hash.",
                references=[
                    "https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity/nspinneddomains",
                    "https://github.com/datatheorem/TrustKit",
                ],
            ))
        else:
            # Pinning exists – check for bypass patterns
            for bypass_pattern, title, desc in _BYPASS_PATTERNS:
                if re.search(bypass_pattern, combined, re.IGNORECASE):
                    findings.append(self.create_finding(
                        f"pinning_bypass_{title.lower().replace(' ', '_')}",
                        f"Certificate Pinning Bypass: {title}",
                        desc,
                        "high",
                        confidence=0.85,
                        cwe_id="CWE-295",
                        masvs_control="MASVS-NETWORK-2",
                        remediation="Remove pinning bypass code. Never disable pinning in production builds.",
                    ))

        return self.create_result(PluginStatus.SUCCESS, findings)
