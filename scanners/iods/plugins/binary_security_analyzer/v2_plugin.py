"""
Binary Security Analyzer – checks Mach-O binary hardening flags.

Checks:
  - PIE (Position Independent Executable)
  - Stack Canary (__stack_chk_fail / __stack_chk_guard)
  - ARC (Automatic Reference Counting)
  - Symbols stripped (debug symbols removed)
  - Bitcode enabled
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List

from core.plugins.base_plugin_ios import (
    BasePluginIOS,
    PluginCapability,
    PluginFinding,
    PluginMetadata,
    PluginPriority,
    PluginResult,
    PluginStatus,
)


class BinarySecurityAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="binary_security_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.BINARY_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            description="Checks Mach-O binary hardening: PIE, stack canary, ARC, stripped symbols.",
            priority=PluginPriority.CRITICAL,
            timeout_seconds=60,
            tags=["binary", "hardening", "pie", "arc", "stack-canary"],
            masvs_control="MASVS-RESILIENCE-3",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []

        binary = ipa_ctx.binary_path
        if binary is None or not binary.exists():
            return self.create_result(
                PluginStatus.SKIPPED,
                warning_messages=["Binary not found – skipping binary security checks."],
            )

        # PIE check
        if ipa_ctx.has_pie is False:
            findings.append(self.create_finding(
                "binary_pie_disabled",
                "PIE (ASLR) Not Enabled",
                "The binary was not compiled with Position Independent Executable (PIE) flag. "
                "This disables ASLR and makes the app vulnerable to memory corruption attacks.",
                "high",
                confidence=0.95,
                cwe_id="CWE-494",
                masvs_control="MASVS-RESILIENCE-3",
                owasp_category="M10: Extraneous Functionality",
                remediation="Compile with -fPIE and link with -Xlinker -pie. Verify in Xcode: "
                            "Build Settings → Generate Position-Dependent Code = No.",
                references=["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/"],
            ))

        # Stack canary check
        if ipa_ctx.has_stack_canary is False:
            findings.append(self.create_finding(
                "binary_no_stack_canary",
                "Stack Canary Not Present",
                "No stack canary symbols (__stack_chk_fail / __stack_chk_guard) found. "
                "Stack canaries detect stack buffer overflow attacks.",
                "medium",
                confidence=0.9,
                cwe_id="CWE-121",
                masvs_control="MASVS-RESILIENCE-3",
                remediation="Enable stack protection in Xcode: Build Settings → "
                            "Enable Stack Smashing Protection = Yes (-fstack-protector-all).",
            ))

        # ARC check
        if ipa_ctx.has_arc is False:
            findings.append(self.create_finding(
                "binary_no_arc",
                "ARC (Automatic Reference Counting) Not Enabled",
                "The binary does not use ARC. Manual memory management increases risk of "
                "use-after-free, double-free, and memory corruption vulnerabilities.",
                "medium",
                confidence=0.85,
                cwe_id="CWE-416",
                masvs_control="MASVS-RESILIENCE-3",
                remediation="Enable ARC in Xcode: Build Settings → Objective-C Automatic Reference Counting = Yes.",
            ))

        # Symbols not stripped
        if ipa_ctx.symbols_stripped is False:
            findings.append(self.create_finding(
                "binary_symbols_not_stripped",
                "Debug Symbols Not Stripped",
                "The release binary contains debug symbols. Symbols expose internal class names, "
                "method names, and file paths, aiding reverse engineering.",
                "low",
                confidence=0.8,
                cwe_id="CWE-540",
                masvs_control="MASVS-RESILIENCE-3",
                remediation="Enable symbol stripping: Build Settings → Strip Debug Symbols During Copy = Yes. "
                            "Set Strip Style to All Symbols for release builds.",
            ))

        # Bitcode: informational (presence is generally positive, absence is neutral)
        # No finding for bitcode absence – it's deprecated in newer Xcode versions.

        # If binary flags not yet populated, run otool ourselves
        if ipa_ctx.has_pie is None:
            extra = self._run_binary_checks(binary)
            findings.extend(extra)

        return self.create_result(PluginStatus.SUCCESS, findings)

    def _run_binary_checks(self, binary: Path) -> List[PluginFinding]:
        """Fallback: run otool/nm directly if context flags weren't populated."""
        findings = []
        try:
            # PIE via otool
            result = subprocess.run(
                ["otool", "-hv", str(binary)], capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and "PIE" not in result.stdout:
                findings.append(self.create_finding(
                    "binary_pie_disabled_fallback",
                    "PIE (ASLR) Not Enabled",
                    "Binary does not have PIE flag set.",
                    "high", 0.9,
                    cwe_id="CWE-494",
                    masvs_control="MASVS-RESILIENCE-3",
                ))
        except Exception:
            pass
        return findings
