#!/usr/bin/env python3
"""
cryptography_tests - BasePluginV2 Implementation (MASVS-CRYPTO-1)
==================================================================

Detects insecure PRNG usage (CWE-330), weak key derivation functions
(CWE-916), and low PBKDF2 iteration counts in decompiled Java/Kotlin sources.
"""

import re
import time
from pathlib import Path
from typing import List, Set

import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.plugins.base_plugin_v2 import (
    BasePluginV2,
    PluginMetadata,
    PluginResult,
    PluginFinding,
    PluginCapability,
    PluginStatus,
    PluginPriority,
)

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

# --- Compiled detection patterns ---

_INSECURE_RANDOM = [
    (re.compile(r'\bnew\s+Random\s*\('), "java.util.Random", "CWE-330"),
    (re.compile(r'\bMath\.random\s*\('), "Math.random()", "CWE-330"),
    (re.compile(r'\bnew\s+java\.util\.Random\s*\('), "java.util.Random (qualified)", "CWE-330"),
]

_WEAK_KDF = [
    (re.compile(r'PBEWith(?:MD5|SHA1)', re.IGNORECASE), "Weak PBE algorithm (MD5/SHA1)", "CWE-916"),
    (re.compile(r'SecretKeySpec\s*\(\s*\w+\.getBytes\s*\('), "Key from string getBytes()", "CWE-916"),
]

_HARDCODED_KEY = [
    # Hardcoded byte array key: static byte[] = new byte[]{...} near SecretKeySpec
    (
        re.compile(r'(?:static\s+)?(?:final\s+)?byte\[\]\s+\w+\s*=\s*(?:new\s+byte\[\]\s*)?\{[0-9,\s]{16,}\}'),
        "Hardcoded byte array key", "CWE-321",
    ),
    # Hardcoded string key passed to SecretKeySpec
    (
        re.compile(r'SecretKeySpec\s*\(\s*["\'][^"\']{8,}["\']\.getBytes'),
        "Hardcoded string key in SecretKeySpec", "CWE-321",
    ),
    # Hardcoded API token/key in HTTP header
    (
        re.compile(
            r'(?:setRequestProperty|header|addHeader)\s*\([^)]*'
            r'(?:TOKEN|KEY|SECRET|AUTHORIZATION)[^)]*,\s*["\'][A-Za-z0-9]{20,}["\']',
            re.IGNORECASE,
        ),
        "Hardcoded API token in HTTP header", "CWE-798",
    ),
    # AWS access key
    (re.compile(r'["\']AKIA[A-Z0-9]{16}["\']'), "Hardcoded AWS access key", "CWE-798"),
    # Google API key
    (re.compile(r'["\']AIza[A-Za-z0-9_-]{35}["\']'), "Hardcoded Google API key", "CWE-798"),
    # Firebase server key (FCM)
    (re.compile(r'["\']AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{100,}["\']'), "Hardcoded Firebase server key", "CWE-798"),
    # PEM private key embedded in source
    (re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'), "Embedded PEM private key", "CWE-321"),
    # Generic secret assignment: variable named key/secret/token = long string literal
    (
        re.compile(
            r'(?:private|static|final)\s+.*'
            r'(?:SECRET|PRIVATE_KEY|SIGNING_KEY|ENCRYPTION_KEY|MASTER_KEY)\s*=\s*"[^"]{16,}"',
            re.IGNORECASE,
        ),
        "Hardcoded secret constant", "CWE-798",
    ),
    # Generic password/credential assignment: password = "..."
    (
        re.compile(
            r'(?:String\s+)?(?:password|passwd|pwd|passcode)\s*=\s*"[^"]{3,}"',
            re.IGNORECASE,
        ),
        "Hardcoded password in source code", "CWE-798",
    ),
    # Generic API key/token assignment (not cloud-specific)
    (
        re.compile(
            r'(?:String\s+)?(?:api_key|apiKey|API_KEY|auth_token|authToken)\s*=\s*"[^"]{8,}"',
        ),
        "Hardcoded API key or auth token", "CWE-798",
    ),
    # Hardcoded secret in string comparison: .equals("secretvalue")
    # Match .equals() with strings containing secret/key/pass-like substrings, or long alphanumeric strings
    (
        re.compile(
            r'\.equals\s*\(\s*"(?:[^"]*(?:secret|key|pass|token|pin|admin|root)[^"]*|[A-Za-z0-9_]{12,})"',
            re.IGNORECASE,
        ),
        "Hardcoded secret in string comparison", "CWE-798",
    ),
    # Credentials embedded in UI text: setText("...password: xxx...")
    (
        re.compile(
            r'setText\s*\(\s*"[^"]*(?:password|api.?key|secret|token|credential)[^"]*"',
            re.IGNORECASE,
        ),
        "Credentials embedded in UI string", "CWE-798",
    ),
    # Base64-encoded secrets
    (
        re.compile(
            r'Base64\.(?:decode|decodeToString)\s*\(\s*"[A-Za-z0-9+/=]{20,}"'
        ),
        "Base64-encoded secret in source code", "CWE-798",
    ),
    # KeyStore with null or empty password
    (
        re.compile(
            r'KeyStore\.(?:getInstance|load)\s*\([^)]*(?:null|"")\s*(?:\)|,)',
        ),
        "KeyStore loaded with null/empty password", "CWE-521",
    ),
]

_PBKDF2_LOW_ITER = re.compile(r'new\s+PBEKeySpec\s*\([^,]+,\s*[^,]+,\s*(\d+)')

_WEAK_HASH_KDF = [
    (
        re.compile(r'MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-1|SHA1)["\']'),
        "Weak hash for key derivation (MD5/SHA-1)",
        "CWE-916",
    ),
]

# Context keywords that indicate crypto usage (for smart dedup of Random)
_CRYPTO_CONTEXT = re.compile(r'\b(?:key|token|nonce|iv|salt|cipher|encrypt|decrypt|secret|hmac)\b', re.IGNORECASE)

# SecureRandom import indicates developer awareness
_SECURE_RANDOM_IMPORT = re.compile(r'(?:import\s+)?java\.security\.SecureRandom')


class CryptographyTestsV2(BasePluginV2):
    """Detects insecure cryptographic patterns in source code (MASVS-CRYPTO-1)."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="cryptography_tests",
            version="2.1.0",
            description="Detects insecure PRNG, weak KDF, and low PBKDF2 iterations",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["crypto", "masvs-crypto-1"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        files_scanned = 0

        try:
            source_files = self._get_source_files(apk_ctx)
            for src_path in source_files:
                try:
                    content = Path(src_path).read_text(errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                files_scanned += 1
                rel_path = self._relative_path(src_path, apk_ctx)

                if self._is_library_code(rel_path):
                    continue

                findings.extend(self._check_insecure_random(content, rel_path))
                findings.extend(self._check_weak_kdf(content, rel_path))
                findings.extend(self._check_pbkdf2_iterations(content, rel_path))
                findings.extend(self._check_weak_hash_kdf(content, rel_path))
                findings.extend(self._check_hardcoded_keys(content, rel_path))

            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    "execution_time": time.time() - start_time,
                    "plugin_version": "2.1.0",
                    "files_scanned": files_scanned,
                },
            )

        except Exception as e:
            logger.error(f"cryptography_tests failed: {e}")
            return PluginResult(
                status=PluginStatus.FAILURE,
                findings=findings,
                metadata={"error": str(e), "execution_time": time.time() - start_time},
            )

    # ------------------------------------------------------------------ helpers

    def _get_source_files(self, apk_ctx) -> List[str]:
        src = getattr(apk_ctx, "source_files", None)
        if src:
            return [str(f) for f in src if str(f).endswith((".java", ".kt"))]
        sources_dir = getattr(apk_ctx, "sources_dir", None)
        if sources_dir and Path(sources_dir).is_dir():
            return [str(p) for p in Path(sources_dir).rglob("*") if p.suffix in (".java", ".kt")]
        return []

    def _relative_path(self, full_path: str, apk_ctx) -> str:
        workspace = getattr(apk_ctx, "workspace_dir", None) or getattr(apk_ctx, "output_dir", None)
        if workspace:
            try:
                return str(Path(full_path).relative_to(workspace))
            except ValueError:
                pass
        parts = Path(full_path).parts
        if "sources" in parts:
            idx = parts.index("sources")
            return str(Path(*parts[idx:]))
        return Path(full_path).name

    def _line_number(self, content: str, pos: int) -> int:
        return content[:pos].count("\n") + 1

    def _snippet(self, content: str, start: int, end: int) -> str:
        line_start = content.rfind("\n", 0, start) + 1
        line_end = content.find("\n", end)
        if line_end == -1:
            line_end = len(content)
        return content[line_start:line_end].strip()[:200]

    # ------------------------------------------------------------------ checks

    def _check_insecure_random(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings: List[PluginFinding] = []
        seen: Set[str] = set()

        # Smart dedup: if SecureRandom is imported AND Random is NOT used in crypto context, skip
        has_secure_random = bool(_SECURE_RANDOM_IMPORT.search(content))

        for pattern, api_name, cwe in _INSECURE_RANDOM:
            m = pattern.search(content)
            if m and api_name not in seen:
                seen.add(api_name)
                # Check surrounding context (20 lines around match)
                ctx_start = max(0, content.rfind("\n", 0, max(0, m.start() - 500)) + 1)
                ctx_end = min(len(content), content.find("\n", min(len(content), m.end() + 500)))
                if ctx_end == -1:
                    ctx_end = len(content)
                context = content[ctx_start:ctx_end]

                if has_secure_random and not _CRYPTO_CONTEXT.search(context):
                    # Random used for non-crypto purpose alongside SecureRandom - lower severity
                    severity = "low"
                    confidence = 0.5
                else:
                    severity = "medium"
                    confidence = 0.8

                findings.append(self.create_finding(
                    finding_id=f"crypto_insecure_random_{len(findings):03d}",
                    title=f"Insecure PRNG: {api_name}",
                    description=(
                        f"{api_name} is not cryptographically secure. Use java.security.SecureRandom "
                        "for generating keys, tokens, nonces, IVs, or salts."
                    ),
                    severity=severity,
                    confidence=confidence,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id=cwe,
                    masvs_control="MASVS-CRYPTO-1",
                    remediation="Replace with java.security.SecureRandom for security-sensitive randomness.",
                ))
        return findings

    def _check_weak_kdf(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings: List[PluginFinding] = []
        seen: Set[str] = set()
        for pattern, desc, cwe in _WEAK_KDF:
            m = pattern.search(content)
            if m and desc not in seen:
                seen.add(desc)
                findings.append(self.create_finding(
                    finding_id=f"crypto_weak_kdf_{len(findings):03d}",
                    title=f"Weak Key Derivation: {desc}",
                    description=(
                        f"{desc} detected. Weak key derivation functions make it easier "
                        "to brute-force encryption keys. Use PBKDF2WithHmacSHA256 with "
                        "at least 10000 iterations."
                    ),
                    severity="high",
                    confidence=0.85,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id=cwe,
                    masvs_control="MASVS-CRYPTO-1",
                    remediation="Use PBKDF2WithHmacSHA256 or Argon2 for key derivation.",
                ))
        return findings

    def _check_pbkdf2_iterations(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings: List[PluginFinding] = []
        for m in _PBKDF2_LOW_ITER.finditer(content):
            try:
                iterations = int(m.group(1))
            except (ValueError, IndexError):
                continue
            if iterations < 10000:
                findings.append(self.create_finding(
                    finding_id=f"crypto_low_pbkdf2_{len(findings):03d}",
                    title=f"Low PBKDF2 Iterations ({iterations})",
                    description=(
                        f"PBEKeySpec uses only {iterations} iterations. OWASP recommends "
                        "at least 600000 for PBKDF2-HMAC-SHA256 (minimum 10000). Low "
                        "iteration counts allow faster brute-force attacks."
                    ),
                    severity="high",
                    confidence=0.9,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id="CWE-916",
                    masvs_control="MASVS-CRYPTO-1",
                    remediation="Increase PBKDF2 iterations to at least 10000 (600000 recommended).",
                ))
        return findings

    def _check_weak_hash_kdf(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings: List[PluginFinding] = []
        seen: Set[str] = set()
        for pattern, desc, cwe in _WEAK_HASH_KDF:
            m = pattern.search(content)
            if m and desc not in seen:
                seen.add(desc)
                # Only flag if used in key derivation context (not general hashing)
                ctx_start = max(0, m.start() - 300)
                ctx_end = min(len(content), m.end() + 300)
                context = content[ctx_start:ctx_end].lower()
                if any(kw in context for kw in ("key", "password", "kdf", "derive", "secret", "encrypt")):
                    findings.append(self.create_finding(
                        finding_id=f"crypto_weak_hash_kdf_{len(findings):03d}",
                        title=f"Weak Hash for Key Derivation: {desc}",
                        description=(
                            f"{desc}. MD5 and SHA-1 are broken for cryptographic purposes. "
                            "Use SHA-256 or stronger hash in key derivation."
                        ),
                        severity="high",
                        confidence=0.75,
                        file_path=rel_path,
                        line_number=self._line_number(content, m.start()),
                        code_snippet=self._snippet(content, m.start(), m.end()),
                        cwe_id=cwe,
                        masvs_control="MASVS-CRYPTO-1",
                        remediation="Use SHA-256 or stronger for key derivation, or use PBKDF2/Argon2.",
                    ))
        return findings

    def _check_hardcoded_keys(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings: List[PluginFinding] = []
        seen: Set[str] = set()
        for pattern, desc, cwe in _HARDCODED_KEY:
            m = pattern.search(content)
            if m and desc not in seen:
                seen.add(desc)
                severity = "critical" if cwe == "CWE-321" else "high"
                findings.append(self.create_finding(
                    finding_id=f"crypto_hardcoded_key_{len(findings):03d}",
                    title=f"Hardcoded Cryptographic Material: {desc}",
                    description=(
                        f"{desc}. Hardcoded keys/tokens can be extracted from the APK by any attacker. "
                        "Use Android Keystore or runtime key generation."
                    ),
                    severity=severity,
                    confidence=0.80,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id=cwe,
                    masvs_control="MASVS-CRYPTO-1",
                    remediation=(
                        "Never hardcode cryptographic keys or API tokens. "
                        "Use Android Keystore for key storage or fetch "
                        "secrets from a secure backend at runtime."
                    ),
                ))
        return findings


# Plugin factory
def create_plugin() -> CryptographyTestsV2:
    return CryptographyTestsV2()


__all__ = ["CryptographyTestsV2", "create_plugin"]
