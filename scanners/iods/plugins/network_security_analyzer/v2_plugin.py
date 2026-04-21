"""
Network Security Analyzer – SSL/TLS and certificate validation bypass detection.

Checks:
  - NSURLSessionDelegate ignoring SSL errors (didReceiveChallenge accepting all)
  - allowsAnyHTTPSCertificateForHost usage
  - AFNetworking / Alamofire insecure config
  - SSLSetSessionOption ignoring errors
  - Custom HostnameVerifier accepting all
"""
from __future__ import annotations

import re
from typing import List

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)

_SSL_BYPASS_PATTERNS = [
    (
        r'completionHandler\(\.useCredential|didReceiveChallenge.*completionHandler.*useCredential',
        "NSURLSession SSL Bypass Pattern",
        "CWE-295", "high",
        "App implements NSURLSessionDelegate with potential certificate bypass. "
        "Accepting any credential in didReceiveChallenge disables SSL validation.",
    ),
    (
        r'setAllowsAnyHTTPSCertificate|allowsAnyHTTPSCertificate',
        "Insecure HTTPS Certificate Acceptance",
        "CWE-295", "critical",
        "setAllowsAnyHTTPSCertificate:YES disables all SSL certificate validation, "
        "making the app vulnerable to man-in-the-middle attacks.",
    ),
    (
        r'kCFStreamSSLValidatesCertificateChain.*false|kCFStreamSSLValidatesCertificateChain.*kCFBooleanFalse',
        "SSL Certificate Chain Validation Disabled",
        "CWE-295", "critical",
        "kCFStreamSSLValidatesCertificateChain=false disables SSL certificate chain validation.",
    ),
    (
        r'SSLSetSessionOption.*kSSLSessionOptionBreakOnServerAuth',
        "SSL Session Breakpoint Set (cert bypass risk)",
        "CWE-295", "medium",
        "kSSLSessionOptionBreakOnServerAuth is set. Verify the auth challenge handler "
        "does not blindly accept all certificates.",
    ),
    (
        r'NSURLAuthenticationMethodServerTrust.*useCredential',
        "Server Trust Authentication Potentially Bypassed",
        "CWE-295", "high",
        "Pattern suggests NSURLAuthenticationMethodServerTrust challenge may be accepted "
        "without proper certificate validation.",
    ),
    (
        r'pinningMode.*AFSSLPinningModeNone',
        "AFNetworking SSL Pinning Disabled",
        "CWE-295", "medium",
        "AFNetworking is configured with AFSSLPinningModeNone, disabling certificate pinning.",
    ),
    (
        r'ServerTrustPolicy\.disableEvaluation',
        "Alamofire Server Trust Evaluation Disabled",
        "CWE-295", "high",
        "Alamofire is configured with disableEvaluation, bypassing all SSL certificate checks.",
    ),
]


class NetworkSecurityAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="network_security_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.NETWORK_ANALYSIS, PluginCapability.STATIC_ANALYSIS],
            description="Detects SSL/TLS bypass patterns and insecure network configurations.",
            priority=PluginPriority.CRITICAL,
            timeout_seconds=90,
            tags=["network", "ssl", "tls", "certificate", "mitm"],
            masvs_control="MASVS-NETWORK-1",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []

        strings_text = "\n".join(ipa_ctx.get_strings())
        classdump_text = self._read_classdump(ipa_ctx)
        combined = strings_text + "\n" + classdump_text

        for pattern, title, cwe, severity, description in _SSL_BYPASS_PATTERNS:
            m = re.search(pattern, combined, re.IGNORECASE)
            if m:
                findings.append(self.create_finding(
                    f"network_{cwe.lower().replace('-', '_')}_{title.lower().split()[0]}",
                    title,
                    description,
                    severity,
                    confidence=0.85,
                    cwe_id=cwe,
                    masvs_control="MASVS-NETWORK-1",
                    owasp_category="M3: Insecure Communication",
                    code_snippet=m.group(0)[:200],
                    remediation="Implement proper SSL certificate validation. Use certificate pinning "
                                "for high-security communications. Never bypass SSL errors in production.",
                    references=[
                        "https://developer.apple.com/documentation/security/certificate_key_and_trust_services",
                        "https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication",
                    ],
                ))

        # Check for cleartext HTTP URLs in strings
        http_urls = re.findall(r'http://[a-zA-Z0-9.-]+(?:/[^\s"\']*)?', strings_text)
        # Filter out localhost and test URLs
        real_http = [u for u in http_urls if not any(
            skip in u for skip in ["localhost", "127.0.0.1", "0.0.0.0", "example.com"]
        )]
        if real_http:
            findings.append(self.create_finding(
                "network_cleartext_http",
                "Cleartext HTTP URLs Detected",
                f"Found {len(real_http)} cleartext HTTP URL(s) in binary strings. "
                "Cleartext communication is vulnerable to interception and modification.",
                "medium",
                confidence=0.75,
                cwe_id="CWE-319",
                masvs_control="MASVS-NETWORK-1",
                evidence={"http_urls": real_http[:10]},
                remediation="Replace all http:// URLs with https://. Enable ATS in Info.plist.",
            ))

        return self.create_result(PluginStatus.SUCCESS, findings)

    def _read_classdump(self, ipa_ctx) -> str:
        result = []
        if ipa_ctx.classdump_dir.exists():
            for f in ipa_ctx.classdump_dir.glob("*.h"):
                try:
                    result.append(f.read_text(errors="replace"))
                except Exception:
                    pass
        return "\n".join(result)
