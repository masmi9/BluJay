"""
Hardcoded Secrets Analyzer – entropy-based and pattern-based secret detection.

Detects: API keys, tokens, AWS credentials, Google API keys, private keys,
JWT secrets, and other high-entropy strings in the binary.
"""
from __future__ import annotations

import math
import re
from typing import List, Optional, Tuple

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)

_SECRET_PATTERNS: List[Tuple[str, str, str, str]] = [
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", "CWE-312", "high"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", "CWE-312", "critical"),
    (r'(?i)aws.{0,20}secret.{0,20}[=:]["\s]*[A-Za-z0-9+/]{40}', "AWS Secret Key", "CWE-312", "critical"),
    (r'sk-[a-zA-Z0-9]{32,}', "OpenAI/Stripe Secret Key", "CWE-312", "critical"),
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "JWT Token", "CWE-312", "high"),
    (r'(?i)github[_\s]?token[=:\s]["\']?[a-zA-Z0-9_]{35,}', "GitHub Token", "CWE-312", "high"),
    (r'(?i)slack[_\s]?token[=:\s]["\']?xox[bp]-[a-zA-Z0-9-]{10,}', "Slack Token", "CWE-312", "high"),
    (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', "Private Key in Binary", "CWE-321", "critical"),
    (r'(?i)(password|passwd|api_key|api_secret|client_secret)[=:\s]["\'][^"\']{8,64}["\']',
     "Hardcoded Credential", "CWE-259", "high"),
    (r'(?i)basic [a-zA-Z0-9+/]{20,}={0,2}', "Hardcoded Basic Auth", "CWE-259", "high"),
]

_MIN_ENTROPY = 4.0  # Shannon entropy threshold for high-entropy string detection
_MIN_LENGTH = 20
_MAX_LENGTH = 200


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    ln = len(s)
    for count in freq.values():
        p = count / ln
        entropy -= p * math.log2(p)
    return entropy


class HardcodedSecretsAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="hardcoded_secrets_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            description="Detects hardcoded API keys, tokens, credentials via pattern matching and entropy analysis.",
            priority=PluginPriority.CRITICAL,
            timeout_seconds=120,
            tags=["secrets", "api-keys", "credentials", "entropy"],
            masvs_control="MASVS-STORAGE-2",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []
        seen_secrets: set = set()

        strings_list = ipa_ctx.get_strings()
        strings_text = "\n".join(strings_list)

        # Pattern-based detection
        for pattern, name, cwe, severity in _SECRET_PATTERNS:
            for m in re.finditer(pattern, strings_text, re.IGNORECASE | re.MULTILINE):
                matched = m.group(0).strip()
                # Deduplicate
                key = matched[:40]
                if key in seen_secrets:
                    continue
                seen_secrets.add(key)
                findings.append(self.create_finding(
                    f"secrets_{name.lower().replace(' ', '_').replace('/', '_')}",
                    f"Hardcoded {name} Detected",
                    f"A {name} was found hardcoded in the binary: {matched[:60]}...",
                    severity,
                    confidence=0.85,
                    cwe_id=cwe,
                    masvs_control="MASVS-STORAGE-2",
                    owasp_category="M2: Insecure Data Storage",
                    code_snippet=matched[:200],
                    evidence={"secret_type": name, "preview": matched[:40]},
                    remediation=f"Remove the hardcoded {name}. "
                                "Store secrets in a secure server-side configuration, "
                                "iOS Keychain, or environment-based injection. "
                                "Rotate any exposed credentials immediately.",
                ))

        # High-entropy string detection on extracted strings
        high_entropy_found = 0
        for s in strings_list:
            s = s.strip()
            if _MIN_LENGTH <= len(s) <= _MAX_LENGTH:
                entropy = _shannon_entropy(s)
                if entropy >= _MIN_ENTROPY and self._looks_like_secret(s):
                    if s in seen_secrets:
                        continue
                    seen_secrets.add(s)
                    high_entropy_found += 1
                    if high_entropy_found <= 5:  # Cap at 5 entropy findings
                        findings.append(self.create_finding(
                            f"secrets_high_entropy_{high_entropy_found}",
                            "High-Entropy String (Potential Secret)",
                            f"A high-entropy string (entropy={entropy:.2f}) was found in the binary. "
                            "This may be a hardcoded secret, key, or token.",
                            "medium",
                            confidence=0.55,
                            cwe_id="CWE-312",
                            masvs_control="MASVS-STORAGE-2",
                            code_snippet=s[:100],
                            evidence={"entropy": round(entropy, 2), "length": len(s)},
                            remediation="Review this string. If it is a secret, move it to Keychain or server-side configuration.",
                        ))

        return self.create_result(PluginStatus.SUCCESS, findings)

    @staticmethod
    def _looks_like_secret(s: str) -> bool:
        """Heuristic: exclude common non-secret high-entropy strings."""
        # Skip URL paths, base64 images, common hash-looking framework strings
        if s.startswith(("http", "www.", "/", "<", "{", "[")):
            return False
        if re.match(r'^[0-9a-f]{32,}$', s, re.IGNORECASE):  # Hex string (could be key)
            return True
        if re.match(r'^[A-Za-z0-9+/]{40,}={0,2}$', s):  # Base64-looking
            return True
        # Avoid common framework strings
        if any(skip in s for skip in ["com.apple", "UIKit", ".framework", "Bundle"]):
            return False
        return True
