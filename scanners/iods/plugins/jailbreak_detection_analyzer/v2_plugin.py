"""
Jailbreak Detection Analyzer – checks for jailbreak detection implementation.

Checks binary strings for known jailbreak detection patterns.
Flags absence in security-sensitive apps.
"""
from __future__ import annotations

import re
from typing import List

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)

_JB_DETECTION_PATTERNS = [
    r'/Applications/Cydia\.app',
    r'/Library/MobileSubstrate/MobileSubstrate\.dylib',
    r'/bin/bash',
    r'/usr/sbin/sshd',
    r'/etc/apt',
    r'cydia://',
    r'SBSettings',
    r'MobileSubstrate',
    r'jailbreak',
    r'isFakeLocation',
    r'RootHelper',
    r'isJailbroken',
    r'JailbreakDetect',
    r'DTTJailbreakDetection',
]

_COMBINED_PATTERN = re.compile("|".join(_JB_DETECTION_PATTERNS), re.IGNORECASE)


class JailbreakDetectionAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="jailbreak_detection_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            description="Checks for jailbreak detection implementation in security-sensitive apps.",
            priority=PluginPriority.LOW,
            timeout_seconds=30,
            tags=["jailbreak", "tamper-detection", "resilience"],
            masvs_control="MASVS-RESILIENCE-1",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []

        strings_text = "\n".join(ipa_ctx.get_strings())
        matches = _COMBINED_PATTERN.findall(strings_text)

        if not matches:
            # No jailbreak detection found
            findings.append(self.create_finding(
                "jailbreak_detection_missing",
                "No Jailbreak Detection Implemented",
                "No known jailbreak detection patterns were found in the binary. "
                "For banking, healthcare, or enterprise apps, jailbreak detection is recommended "
                "to prevent running in compromised environments.",
                "low",
                confidence=0.65,
                cwe_id="CWE-693",
                masvs_control="MASVS-RESILIENCE-1",
                remediation="Implement jailbreak detection using multiple heuristics: "
                            "file existence checks (/Applications/Cydia.app), "
                            "fork() test, dylib injection checks, and integrity verification. "
                            "Consider using a library like DTTJailbreakDetection or IOSSecuritySuite.",
                references=["https://github.com/securing/IOSSecuritySuite"],
            ))
        else:
            # Detection found – check for quality (basic vs multi-vector)
            unique_matches = set(m.lower() for m in matches)
            if len(unique_matches) < 3:
                findings.append(self.create_finding(
                    "jailbreak_detection_weak",
                    "Weak Jailbreak Detection (Single-Vector)",
                    f"Only {len(unique_matches)} jailbreak detection vector(s) detected. "
                    "Single-check detection is easily bypassed by tools like Liberty Lite or Shadow.",
                    "info",
                    confidence=0.6,
                    cwe_id="CWE-693",
                    masvs_control="MASVS-RESILIENCE-1",
                    evidence={"detected_patterns": list(unique_matches)[:5]},
                    remediation="Strengthen jailbreak detection with multiple independent checks: "
                                "file system checks, dynamic library injection tests, "
                                "process integrity checks, and sandbox violation tests.",
                ))

        return self.create_result(PluginStatus.SUCCESS, findings)
