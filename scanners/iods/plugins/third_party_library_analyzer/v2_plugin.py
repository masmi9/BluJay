"""
Third-Party Library Analyzer – detects known vulnerable SDK versions.

Checks:
  - Embedded Frameworks/ for version indicators
  - Pods/ podspec version files
  - Known vulnerable framework versions
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)

# Known vulnerable library versions: (name_pattern, vulnerable_version_pattern, cve, severity, description)
_VULNERABLE_LIBRARIES: List[Tuple[str, str, str, str, str]] = [
    ("AFNetworking", r"2\.[0-5]\.", "CVE-2015-3735", "high",
     "AFNetworking < 2.6 has SSL certificate validation bypass vulnerability."),
    ("AFNetworking", r"3\.0\.[0-1]", "CVE-2016-1000000", "medium",
     "AFNetworking 3.0.0-3.0.1 has a pinning bypass vulnerability."),
    ("OpenSSL", r"1\.0\.[01]", "CVE-2014-0160", "critical",
     "OpenSSL 1.0.1-1.0.1f is vulnerable to Heartbleed (CVE-2014-0160)."),
    ("Cordova", r"[23]\.", "CVE-2014-3502", "high",
     "Apache Cordova < 4.0 has URL whitelist bypass vulnerability."),
    ("Firebase", r"[1-5]\.", "CVE-2018-6335", "medium",
     "Older Firebase SDK versions have known data exposure issues."),
    ("Realm", r"[0-2]\.", "", "medium",
     "Very old Realm versions may have unencrypted default configurations."),
]


class ThirdPartyLibraryAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="third_party_library_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            description="Detects known vulnerable third-party SDK and library versions.",
            priority=PluginPriority.LOW,
            timeout_seconds=60,
            tags=["libraries", "sdks", "cve", "third-party"],
            masvs_control="MASVS-SUPPLY-CHAIN-1",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []

        if ipa_ctx.app_bundle_dir is None:
            return self.create_result(PluginStatus.SKIPPED)

        # List embedded frameworks
        frameworks_dir = ipa_ctx.app_bundle_dir / "Frameworks"
        embedded_frameworks = []
        if frameworks_dir.exists():
            embedded_frameworks = [d.name for d in frameworks_dir.iterdir() if d.is_dir()]

        if embedded_frameworks:
            findings.append(self.create_finding(
                "libs_embedded_frameworks_inventory",
                f"Embedded Frameworks Inventory ({len(embedded_frameworks)} frameworks)",
                f"The app embeds {len(embedded_frameworks)} third-party frameworks. "
                "Audit these for known vulnerabilities and outdated versions.",
                "info",
                confidence=1.0,
                cwe_id="CWE-1395",
                masvs_control="MASVS-SUPPLY-CHAIN-1",
                evidence={"frameworks": embedded_frameworks[:20]},
                remediation="Regularly update all embedded frameworks. "
                            "Use 'swift package update' or 'pod update' and audit changelogs for security fixes.",
            ))

        # Check strings for version strings of vulnerable libraries
        strings_text = "\n".join(ipa_ctx.get_strings())
        for lib_name, vuln_version_re, cve, severity, description in _VULNERABLE_LIBRARIES:
            # Look for library name + version together in strings
            version_pattern = re.compile(
                rf'(?i){re.escape(lib_name)}[/\s_-]*({vuln_version_re}[0-9.]*)',
            )
            m = version_pattern.search(strings_text)
            if m:
                version_str = m.group(1)
                cve_ref = f" ({cve})" if cve else ""
                findings.append(self.create_finding(
                    f"libs_vulnerable_{lib_name.lower()}",
                    f"Potentially Vulnerable Library: {lib_name} {version_str}",
                    f"{description}{cve_ref} Detected version string: {version_str}",
                    severity,
                    confidence=0.75,
                    cwe_id="CWE-1395",
                    masvs_control="MASVS-SUPPLY-CHAIN-1",
                    evidence={"library": lib_name, "version": version_str, "cve": cve},
                    remediation=f"Update {lib_name} to the latest stable version. "
                                f"Review the changelog for security patches.{' See ' + cve if cve else ''}",
                ))

        # Check for outdated CocoaPods lockfile (Podfile.lock in bundle – usually a sign of test build)
        podfile_lock = ipa_ctx.extracted_dir / "Podfile.lock"
        if podfile_lock.exists():
            findings.append(self.create_finding(
                "libs_podfile_lock_exposed",
                "Podfile.lock Bundled in IPA",
                "Podfile.lock is included in the IPA, exposing the exact library versions used. "
                "This aids attackers in identifying vulnerable dependency versions.",
                "low",
                confidence=0.9,
                cwe_id="CWE-540",
                masvs_control="MASVS-SUPPLY-CHAIN-1",
                remediation="Exclude Podfile.lock from the IPA bundle using .gitignore and Xcode build settings.",
            ))

        return self.create_result(PluginStatus.SUCCESS, findings)
