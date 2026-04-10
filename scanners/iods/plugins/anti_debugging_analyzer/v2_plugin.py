"""
Anti-Debugging Analyzer – checks for anti-debugging protections.

Checks for PT_DENY_ATTACH, sysctl-based debugging detection,
and other anti-debugging mechanisms.
"""
from __future__ import annotations

import re
from typing import List

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)

_ANTI_DEBUG_PATTERNS = [
    r'PT_DENY_ATTACH',
    r'ptrace',
    r'sysctl.*P_TRACED',
    r'kinfo_proc',
    r'isBeingDebugged',
    r'AmIBeingDebugged',
    r'P_TRACED',
    r'KERN_PROC_PID',
    r'anti.?debug',
    r'debugger.?detect',
]

_COMBINED = re.compile("|".join(_ANTI_DEBUG_PATTERNS), re.IGNORECASE)


class AntiDebuggingAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="anti_debugging_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.BINARY_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            description="Checks for anti-debugging protections: PT_DENY_ATTACH, sysctl, ptrace.",
            priority=PluginPriority.LOW,
            timeout_seconds=30,
            tags=["anti-debugging", "ptrace", "tamper-detection"],
            masvs_control="MASVS-RESILIENCE-2",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []

        # Check binary strings + symbols
        strings_text = "\n".join(ipa_ctx.get_strings())
        symbols_file = ipa_ctx.otool_dir / "symbols.txt"
        symbols_text = symbols_file.read_text(errors="replace") if symbols_file.exists() else ""
        combined = strings_text + "\n" + symbols_text

        matches = _COMBINED.findall(combined)
        if not matches:
            findings.append(self.create_finding(
                "anti_debug_missing",
                "No Anti-Debugging Protection Detected",
                "No anti-debugging patterns (PT_DENY_ATTACH, ptrace, sysctl P_TRACED) were found. "
                "For high-security apps, anti-debugging prevents runtime analysis and tampering.",
                "low",
                confidence=0.6,
                cwe_id="CWE-693",
                masvs_control="MASVS-RESILIENCE-2",
                remediation="Implement anti-debugging using ptrace(PT_DENY_ATTACH, 0, 0, 0) "
                            "or sysctl-based detection. Call early in application:didFinishLaunchingWithOptions:.",
                references=["https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0085/"],
            ))
        else:
            # Found – verify PT_DENY_ATTACH specifically (strongest protection)
            if not re.search(r'PT_DENY_ATTACH', combined):
                findings.append(self.create_finding(
                    "anti_debug_no_deny_attach",
                    "Anti-Debugging Lacks PT_DENY_ATTACH",
                    "Anti-debugging is implemented but PT_DENY_ATTACH was not detected. "
                    "PT_DENY_ATTACH is the most reliable method to prevent debugger attachment on iOS.",
                    "info",
                    confidence=0.55,
                    cwe_id="CWE-693",
                    masvs_control="MASVS-RESILIENCE-2",
                    evidence={"found_patterns": list(set(matches))[:5]},
                    remediation="Add ptrace(PT_DENY_ATTACH, 0, 0, 0) as an additional layer of protection.",
                ))

        return self.create_result(PluginStatus.SUCCESS, findings)
