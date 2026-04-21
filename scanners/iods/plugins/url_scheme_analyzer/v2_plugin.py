"""
URL Scheme Analyzer – checks custom URL scheme and Universal Links configuration.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)


class URLSchemeAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="url_scheme_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.PLIST_ANALYSIS, PluginCapability.STATIC_ANALYSIS],
            description="Checks custom URL schemes and Universal Links for security misconfigurations.",
            priority=PluginPriority.NORMAL,
            timeout_seconds=30,
            tags=["url-scheme", "deep-link", "universal-links"],
            masvs_control="MASVS-PLATFORM-3",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []
        plist = ipa_ctx.info_plist

        # Custom URL schemes
        url_types: List[Dict[str, Any]] = plist.get("CFBundleURLTypes", [])
        custom_schemes = []
        for url_type in url_types:
            schemes = url_type.get("CFBundleURLSchemes", [])
            custom_schemes.extend(schemes)

        if custom_schemes:
            # Check for overly generic scheme names that could be hijacked
            for scheme in custom_schemes:
                if re.match(r'^[a-z]{1,4}$', scheme, re.IGNORECASE):
                    findings.append(self.create_finding(
                        f"url_scheme_generic_{scheme}",
                        f"Generic/Short URL Scheme Registered: {scheme}://",
                        f"The URL scheme '{scheme}://' is very short and may conflict with "
                        "system or other app schemes. Short schemes are easily hijacked by malicious apps.",
                        "medium",
                        confidence=0.7,
                        cwe_id="CWE-939",
                        masvs_control="MASVS-PLATFORM-3",
                        file_path="Info.plist",
                        evidence={"scheme": scheme},
                        remediation=f"Use a unique, app-specific URL scheme (e.g., 'com.company.appname') "
                                    "to prevent scheme hijacking. Validate all incoming URL parameters.",
                    ))

        # Check if URL scheme handler validates parameters
        strings_text = "\n".join(ipa_ctx.get_strings())
        if custom_schemes and not re.search(r'openURL|application.*url.*options', strings_text, re.IGNORECASE):
            findings.append(self.create_finding(
                "url_scheme_no_validation",
                "URL Scheme Handler May Lack Input Validation",
                "Custom URL schemes are registered but no URL validation pattern was detected. "
                "Malicious apps can invoke your URL scheme with arbitrary parameters.",
                "medium",
                confidence=0.55,
                cwe_id="CWE-939",
                masvs_control="MASVS-PLATFORM-3",
                file_path="Info.plist",
                evidence={"custom_schemes": custom_schemes},
                remediation="Validate all parameters in application:openURL:options: before processing. "
                            "Use Universal Links (HTTPS) instead of custom schemes where possible.",
            ))

        # Universal Links – check for associated domains
        assoc_domains = ipa_ctx.get_entitlement("com.apple.developer.associated-domains", [])
        if not assoc_domains and custom_schemes:
            findings.append(self.create_finding(
                "url_scheme_no_universal_links",
                "Custom URL Schemes Without Universal Links",
                "App uses custom URL schemes but has no Universal Links (associated-domains). "
                "Custom URL schemes are less secure than Universal Links.",
                "info",
                confidence=0.6,
                cwe_id="CWE-939",
                masvs_control="MASVS-PLATFORM-3",
                remediation="Migrate to Universal Links (HTTPS-based) for deep linking. "
                            "They cannot be hijacked by other apps.",
            ))

        return self.create_result(PluginStatus.SUCCESS, findings)
