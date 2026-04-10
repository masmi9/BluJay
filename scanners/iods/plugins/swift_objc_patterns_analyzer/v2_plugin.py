"""
Swift/ObjC Patterns Analyzer – unsafe language patterns.

Checks:
  - sprintf/strcpy/strcat (buffer overflow risk in ObjC)
  - Unsafe Swift force-unwraps in security-critical paths
  - Objective-C format string injection (NSString stringWithFormat: with user input)
  - Insecure random (rand(), arc4random() for crypto purposes)
  - NSException/setjmp abuse
"""
from __future__ import annotations

import re
from typing import List

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)

_UNSAFE_PATTERNS = [
    (r'\bsprintf\s*\(', "sprintf Usage (Buffer Overflow Risk)", "CWE-120", "medium",
     "sprintf is vulnerable to buffer overflow. Use snprintf with explicit size limits."),
    (r'\bstrcpy\s*\(', "strcpy Usage (Buffer Overflow Risk)", "CWE-120", "medium",
     "strcpy has no bounds checking. Use strlcpy or NSString equivalents."),
    (r'\bstrcat\s*\(', "strcat Usage (Buffer Overflow Risk)", "CWE-120", "medium",
     "strcat has no bounds checking. Use strlcat or NSString appendString:."),
    (r'\bgets\s*\(', "gets() Usage (Unbounded Input)", "CWE-120", "high",
     "gets() is unbounded and always vulnerable to buffer overflow. Use fgets()."),
    (r'\brand\s*\(\s*\)', "rand() Used for Random Values", "CWE-338", "medium",
     "rand() is a weak pseudo-random number generator. Use SecRandomCopyBytes for security-critical randomness."),
    (r'\barc4random\s*\(\)', "arc4random() Usage – Review Context", "CWE-338", "info",
     "arc4random() is acceptable for non-security use. Verify it is not used for key generation or tokens."),
    (r'stringWithFormat:\s*@"%@"\s*,\s*(?:user|input|param|arg|query)', "Format String with User Input",
     "CWE-134", "high",
     "NSString stringWithFormat: with user-controlled format string enables format string injection."),
    (r'system\s*\(', "system() Call Detected", "CWE-78", "high",
     "system() executes shell commands. Never pass user input to system()."),
    (r'popen\s*\(', "popen() Call Detected", "CWE-78", "high",
     "popen() executes shell commands. Use NSTask or posix_spawn instead."),
]


class SwiftObjCPatternsAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="swift_objc_patterns_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            description="Detects unsafe C/ObjC patterns: buffer overflows, format strings, weak RNG.",
            priority=PluginPriority.NORMAL,
            timeout_seconds=60,
            tags=["swift", "objective-c", "buffer-overflow", "format-string"],
            masvs_control="MASVS-CODE-4",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []

        strings_text = "\n".join(ipa_ctx.get_strings())
        symbols_file = ipa_ctx.otool_dir / "symbols.txt"
        symbols_text = symbols_file.read_text(errors="replace") if symbols_file.exists() else ""
        combined = strings_text + "\n" + symbols_text

        for pattern, title, cwe, severity, description in _UNSAFE_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                findings.append(self.create_finding(
                    f"swift_objc_{cwe.lower().replace('-', '_')}_{title[:20].lower().replace(' ', '_')}",
                    title,
                    description,
                    severity,
                    confidence=0.75,
                    cwe_id=cwe,
                    masvs_control="MASVS-CODE-4",
                    owasp_category="M7: Client Code Quality",
                    remediation=description,
                ))

        return self.create_result(PluginStatus.SUCCESS, findings)
