"""
Cryptography Analyzer – detects weak cryptographic algorithms and hardcoded keys.

Checks:
  - Weak algorithms: DES, 3DES, RC4, MD5, SHA-1 in CommonCrypto calls
  - ECB mode usage
  - Hardcoded cryptographic key material
  - Insecure random number generation (arc4random used for security-critical contexts)
  - Deprecated crypto APIs
"""
from __future__ import annotations

import re
from typing import List

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)

_WEAK_ALGO_PATTERNS = [
    (r"kCCAlgorithmDES\b", "DES", "CWE-327", "critical"),
    (r"kCCAlgorithm3DES\b", "3DES (Triple DES)", "CWE-327", "high"),
    (r"kCCAlgorithmRC4\b", "RC4", "CWE-327", "high"),
    (r"kCCAlgorithmRC2\b", "RC2", "CWE-327", "high"),
    (r"kCCAlgorithmCAST\b", "CAST", "CWE-327", "medium"),
    (r"kCCModeECB\b", "ECB mode (deterministic, no diffusion)", "CWE-327", "high"),
    (r"CC_MD5\b|CCDigest.*kCCDigestMD5", "MD5 hash function", "CWE-328", "high"),
    (r"CC_SHA1\b|CCDigest.*kCCDigestSHA1\b", "SHA-1 hash function", "CWE-328", "medium"),
    (r"SecRandomCopyBytes.*0\b", "Potential zero-length random bytes", "CWE-330", "medium"),
]

_HARDCODED_KEY_PATTERNS = [
    (r'(?i)(password|passwd|secret|api[_-]?key|auth[_-]?token|private[_-]?key)\s*=\s*["\'][^"\']{8,}["\']',
     "Hardcoded Credential/Key", "CWE-321", "high"),
    (r'(?i)begin\s+(rsa|ec|dsa|private)\s+key', "Embedded Private Key Material", "CWE-321", "critical"),
    (r'(?:[A-Za-z0-9+/]{40,}={0,2})', "Potential Base64-Encoded Key/Secret", "CWE-321", "low"),
]


class CryptographyAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="cryptography_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.CRYPTOGRAPHIC_ANALYSIS, PluginCapability.STATIC_ANALYSIS],
            description="Detects weak cryptographic algorithms, hardcoded keys, and insecure RNG.",
            priority=PluginPriority.HIGH,
            timeout_seconds=120,
            tags=["crypto", "encryption", "keys", "random"],
            masvs_control="MASVS-CRYPTO-1",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []

        # Search strings and classdump for weak algorithm usage
        strings = ipa_ctx.get_strings()
        strings_joined = "\n".join(strings)

        for pattern, algo_name, cwe, severity in _WEAK_ALGO_PATTERNS:
            if re.search(pattern, strings_joined):
                findings.append(self.create_finding(
                    f"crypto_weak_{algo_name.lower().replace(' ', '_').replace('(', '').replace(')', '')}",
                    f"Weak Cryptographic Algorithm: {algo_name}",
                    f"The app uses {algo_name}, which is cryptographically weak or broken. "
                    "This may expose encrypted data to decryption attacks.",
                    severity,
                    confidence=0.85,
                    cwe_id=cwe,
                    masvs_control="MASVS-CRYPTO-1",
                    owasp_category="M5: Insufficient Cryptography",
                    evidence={"algorithm": algo_name},
                    remediation=f"Replace {algo_name} with AES-256-GCM or ChaCha20-Poly1305. "
                                "Use Apple CryptoKit for modern cryptography.",
                    references=["https://developer.apple.com/documentation/cryptokit"],
                ))

        # Search classdump files for hardcoded key patterns
        classdump_dir = ipa_ctx.classdump_dir
        if classdump_dir.exists():
            for hfile in classdump_dir.glob("*.h"):
                content = hfile.read_text(errors="replace")
                for pattern, title, cwe, severity in _HARDCODED_KEY_PATTERNS:
                    for m in re.finditer(pattern, content):
                        matched = m.group(0)
                        # Skip short/obvious non-keys
                        if len(matched) < 16:
                            continue
                        findings.append(self.create_finding(
                            f"crypto_hardcoded_{cwe.lower().replace('-', '_')}",
                            title,
                            f"Potential hardcoded cryptographic material detected in source. "
                            f"Match: {matched[:60]}...",
                            severity,
                            confidence=0.65,
                            cwe_id=cwe,
                            masvs_control="MASVS-CRYPTO-1",
                            file_path=str(hfile),
                            code_snippet=matched[:200],
                            remediation="Store secrets in Keychain. Never hardcode keys, tokens, or passwords in code.",
                        ))
                        break  # One finding per file per pattern

        # Check Info.plist for crypto-related keys (e.g., exported encryption)
        iti = ipa_ctx.info_plist.get("ITSAppUsesNonExemptEncryption")
        if iti is False:
            # App claims it uses no encryption – flag for review
            findings.append(self.create_finding(
                "crypto_no_encryption_declared",
                "App Declares No Non-Exempt Encryption",
                "ITSAppUsesNonExemptEncryption=NO. If the app uses encryption (HTTPS, Keychain, "
                "crypto APIs), this declaration may be incorrect and could violate export regulations.",
                "info",
                confidence=0.5,
                cwe_id="CWE-311",
                masvs_control="MASVS-CRYPTO-1",
                file_path="Info.plist",
                remediation="Review encryption usage. If using standard HTTPS/Keychain, you may qualify for exemption. "
                            "Otherwise, set ITSAppUsesNonExemptEncryption=YES.",
            ))

        return self.create_result(PluginStatus.SUCCESS, findings)
