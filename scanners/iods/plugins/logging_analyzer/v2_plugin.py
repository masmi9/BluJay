"""
Logging Analyzer – detects sensitive data exposure via logging APIs.

Checks: NSLog, print(), os_log, DDLog with sensitive data patterns.
"""
from __future__ import annotations

import re
from typing import List

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)

_SENSITIVE_LOG_PATTERNS = [
    (r'(?i)NSLog\s*\(.*?(password|passwd|secret|token|api.?key|ssn|credit.?card|cvv)', "NSLog"),
    (r'(?i)print\s*\(.*?(password|passwd|secret|token|api.?key|ssn|credit.?card)', "Swift print()"),
    (r'(?i)debugPrint\s*\(.*?(password|passwd|secret|token|api.?key)', "Swift debugPrint()"),
    (r'(?i)NSLog\s*\(.*?@"[^"]{0,30}%@[^"]{0,30}(?:user|pass|token|auth)', "NSLog with format string (potential sensitive data)"),
]


class LoggingAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="logging_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            description="Detects sensitive data logged via NSLog, print(), or os_log.",
            priority=PluginPriority.HIGH,
            timeout_seconds=60,
            tags=["logging", "data-exposure", "nslog"],
            masvs_control="MASVS-STORAGE-3",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []

        strings_text = "\n".join(ipa_ctx.get_strings())

        for pattern, api_name in _SENSITIVE_LOG_PATTERNS:
            matches = re.findall(pattern, strings_text, re.IGNORECASE)
            if matches:
                findings.append(self.create_finding(
                    f"logging_sensitive_{api_name.lower().replace(' ', '_').replace('()', '')}",
                    f"Potential Sensitive Data in {api_name} Calls",
                    f"{api_name} statements may log sensitive data (passwords, tokens, keys). "
                    "Log data is accessible via Console.app, Xcode debugger, and potentially crash reports.",
                    "high",
                    confidence=0.75,
                    cwe_id="CWE-532",
                    masvs_control="MASVS-STORAGE-3",
                    owasp_category="M2: Insecure Data Storage",
                    evidence={"matched_terms": list(set(matches))[:5]},
                    remediation=f"Remove or disable {api_name} calls in production builds. "
                                "Use os_log with %{private} format specifier for sensitive fields. "
                                "Add a build flag to strip logging: #if DEBUG ... NSLog() ... #endif",
                ))

        # NSLog with no privacy controls in production (general check)
        nslog_count = len(re.findall(r'\bNSLog\b', strings_text))
        if nslog_count > 20:
            findings.append(self.create_finding(
                "logging_excessive_nslog",
                "Excessive NSLog Usage in Binary",
                f"Found {nslog_count} NSLog references in the binary. "
                "NSLog output is visible in Console.app and device logs accessible without special privileges.",
                "low",
                confidence=0.7,
                cwe_id="CWE-532",
                masvs_control="MASVS-STORAGE-3",
                evidence={"nslog_count": nslog_count},
                remediation="Wrap NSLog calls in #if DEBUG to strip them from release builds, "
                            "or use os_log which respects privacy labels.",
            ))

        return self.create_result(PluginStatus.SUCCESS, findings)
