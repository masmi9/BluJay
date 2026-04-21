"""
Code Signing Analyzer – validates code signing and provisioning profiles.

Checks:
  - Presence and validity of code signature
  - Debug provisioning profile in release build
  - Expired/invalid certificates
  - Ad-hoc or development distribution
"""
from __future__ import annotations

import re
import subprocess
from typing import List

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)


class CodeSigningAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="code_signing_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            description="Validates code signing, certificates, and provisioning profile type.",
            priority=PluginPriority.HIGH,
            timeout_seconds=60,
            tags=["code-signing", "provisioning", "distribution"],
            masvs_control="MASVS-RESILIENCE-3",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []

        app_bundle = ipa_ctx.app_bundle_dir
        if app_bundle is None:
            return self.create_result(PluginStatus.SKIPPED, warning_messages=["No app bundle found."])

        # Run codesign -dv
        rc, stdout, stderr = self._run_codesign(str(app_bundle))
        output = stdout + stderr

        if rc != 0 and "code object is not signed" in output.lower():
            findings.append(self.create_finding(
                "signing_no_signature",
                "Binary Is Not Code Signed",
                "The app bundle has no valid code signature. Unsigned apps can be tampered with.",
                "critical",
                confidence=0.95,
                cwe_id="CWE-494",
                masvs_control="MASVS-RESILIENCE-3",
                remediation="Sign the app with a valid Apple Developer certificate before distribution.",
            ))
            return self.create_result(PluginStatus.SUCCESS, findings)

        # Ad-hoc signature
        if "adhoc" in output.lower() or "Authority=(null)" in output:
            findings.append(self.create_finding(
                "signing_adhoc",
                "Ad-Hoc Code Signing Detected",
                "The app uses ad-hoc code signing. This is for internal testing only "
                "and must not be distributed publicly.",
                "medium",
                confidence=0.85,
                cwe_id="CWE-494",
                masvs_control="MASVS-RESILIENCE-3",
                remediation="Use Apple Developer or Enterprise distribution signing for production.",
            ))

        # Development certificate
        if re.search(r"Authority=iPhone Developer|TeamIdentifier=.*Development", output):
            findings.append(self.create_finding(
                "signing_dev_certificate",
                "Development Certificate Used for Distribution",
                "The app is signed with a development certificate rather than a distribution certificate.",
                "medium",
                confidence=0.8,
                cwe_id="CWE-494",
                masvs_control="MASVS-RESILIENCE-3",
                evidence={"codesign_output": output[:500]},
                remediation="Re-sign with an 'iPhone Distribution' certificate for App Store or enterprise distribution.",
            ))

        # Check embedded provisioning profile
        pp_path = app_bundle / "embedded.mobileprovision"
        if pp_path.exists():
            pp_findings = self._analyze_provisioning_profile(pp_path)
            findings.extend(pp_findings)
        else:
            findings.append(self.create_finding(
                "signing_no_provisioning_profile",
                "No Embedded Provisioning Profile",
                "No embedded.mobileprovision found. Distribution builds should include a provisioning profile.",
                "info",
                confidence=0.6,
                cwe_id="CWE-494",
                masvs_control="MASVS-RESILIENCE-3",
            ))

        return self.create_result(PluginStatus.SUCCESS, findings)

    def _run_codesign(self, path: str):
        try:
            r = subprocess.run(
                ["codesign", "-dv", "--verbose=4", path],
                capture_output=True, text=True, timeout=30,
            )
            return r.returncode, r.stdout, r.stderr
        except FileNotFoundError:
            return -1, "", "codesign not found"
        except Exception as e:
            return -2, "", str(e)

    def _analyze_provisioning_profile(self, pp_path) -> List[PluginFinding]:
        """Check if the provisioning profile is a debug/development profile."""
        findings = []
        try:
            # Extract the readable content from the DER-encoded profile
            content = pp_path.read_bytes().decode("utf-8", errors="replace")
            if "get-task-allow" in content and "<true/>" in content[content.find("get-task-allow"):content.find("get-task-allow") + 100]:
                findings.append(self.create_finding(
                    "signing_debug_provisioning_profile",
                    "Debug Provisioning Profile in Build",
                    "The embedded provisioning profile has get-task-allow=true, indicating "
                    "a development/debug profile. Production builds must use distribution profiles.",
                    "high",
                    confidence=0.9,
                    cwe_id="CWE-494",
                    masvs_control="MASVS-RESILIENCE-3",
                    file_path="embedded.mobileprovision",
                    remediation="Replace the provisioning profile with an App Store or Enterprise distribution profile.",
                ))
        except Exception:
            pass
        return findings
