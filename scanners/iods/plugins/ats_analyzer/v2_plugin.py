"""
ATS Analyzer – App Transport Security configuration checks.

Checks for NSAllowsArbitraryLoads, exception domains, minimum TLS versions,
and other ATS misconfigurations in Info.plist.
"""
from __future__ import annotations

from typing import Any, Dict, List

from core.plugins.base_plugin_ios import (
    BasePluginIOS,
    PluginCapability,
    PluginFinding,
    PluginMetadata,
    PluginPriority,
    PluginResult,
    PluginStatus,
)


class ATSAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="ats_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.PLIST_ANALYSIS, PluginCapability.NETWORK_ANALYSIS],
            description="Checks App Transport Security (ATS) configuration in Info.plist.",
            priority=PluginPriority.CRITICAL,
            timeout_seconds=30,
            tags=["ats", "network", "tls", "http"],
            masvs_control="MASVS-NETWORK-1",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []

        ats = ipa_ctx.info_plist.get("NSAppTransportSecurity", {})
        if not ats:
            # ATS not explicitly configured – default is secure in iOS 9+
            return self.create_result(PluginStatus.SUCCESS, findings)

        # NSAllowsArbitraryLoads = YES
        if ats.get("NSAllowsArbitraryLoads") is True:
            findings.append(self.create_finding(
                "ats_arbitrary_loads",
                "ATS NSAllowsArbitraryLoads Enabled",
                "NSAllowsArbitraryLoads=YES disables App Transport Security globally, "
                "allowing cleartext HTTP and weak TLS connections to any domain.",
                "high",
                confidence=1.0,
                cwe_id="CWE-319",
                masvs_control="MASVS-NETWORK-1",
                owasp_category="M3: Insecure Communication",
                file_path="Info.plist",
                remediation="Remove NSAllowsArbitraryLoads. Use specific NSExceptionDomains for "
                            "legitimate exceptions and justify each in App Store review.",
                references=["https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity"],
            ))

        # NSAllowsArbitraryLoadsInWebContent = YES
        if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
            findings.append(self.create_finding(
                "ats_arbitrary_web_content",
                "ATS NSAllowsArbitraryLoadsInWebContent Enabled",
                "Allows WKWebView and UIWebView to load arbitrary HTTP content.",
                "medium",
                confidence=0.95,
                cwe_id="CWE-319",
                masvs_control="MASVS-NETWORK-1",
                file_path="Info.plist",
                remediation="Remove NSAllowsArbitraryLoadsInWebContent and ensure WebView content is served over HTTPS.",
            ))

        # NSAllowsLocalNetworking = YES
        if ats.get("NSAllowsLocalNetworking") is True:
            findings.append(self.create_finding(
                "ats_local_networking",
                "ATS Local Networking Exceptions Enabled",
                "NSAllowsLocalNetworking allows cleartext communication on local networks.",
                "low",
                confidence=0.85,
                cwe_id="CWE-319",
                masvs_control="MASVS-NETWORK-1",
                file_path="Info.plist",
                remediation="Only use this in development. Remove for production builds.",
            ))

        # Check exception domains
        exception_domains: Dict[str, Any] = ats.get("NSExceptionDomains", {})
        for domain, domain_config in exception_domains.items():
            if domain_config.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                findings.append(self.create_finding(
                    f"ats_insecure_domain_{domain.replace('.', '_')}",
                    f"ATS Insecure HTTP Allowed for Domain: {domain}",
                    f"NSExceptionAllowsInsecureHTTPLoads=YES for '{domain}' allows cleartext HTTP.",
                    "medium",
                    confidence=0.9,
                    cwe_id="CWE-319",
                    masvs_control="MASVS-NETWORK-1",
                    file_path="Info.plist",
                    evidence={"domain": domain, "config": str(domain_config)},
                    remediation=f"Serve all content from '{domain}' over HTTPS and remove the insecure exception.",
                ))

            min_tls = domain_config.get("NSExceptionMinimumTLSVersion", "")
            if min_tls in ("TLSv1.0", "TLSv1.1"):
                findings.append(self.create_finding(
                    f"ats_weak_tls_{domain.replace('.', '_')}",
                    f"Weak Minimum TLS Version for Domain: {domain}",
                    f"Minimum TLS version is {min_tls} for '{domain}'. TLS 1.0/1.1 are deprecated.",
                    "medium",
                    confidence=0.9,
                    cwe_id="CWE-326",
                    masvs_control="MASVS-NETWORK-1",
                    file_path="Info.plist",
                    evidence={"domain": domain, "tls_version": min_tls},
                    remediation="Set NSExceptionMinimumTLSVersion to TLSv1.2 or remove the exception.",
                ))

        return self.create_result(PluginStatus.SUCCESS, findings)
