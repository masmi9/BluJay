#!/usr/bin/env python3
"""
runtime_decryption_analysis - Insecure Crypto Implementation Detection
========================================================================

Detects insecure cryptographic implementations: ECB mode, static IVs,
weak algorithms, insecure key generation, and missing integrity checks.

MASVS-CRYPTO-1: Cryptographic Implementation
CWE-327: Use of a Broken or Risky Cryptographic Algorithm
CWE-329: Generation of Predictable IV with CBC Mode
"""

import re
import time
from pathlib import Path
from typing import List

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

# --- ECB mode (no diffusion, pattern-preserving) ---
_ECB_MODE = re.compile(
    r'Cipher\.getInstance\s*\(\s*"[^"]*(?:/ECB/|ECB)[^"]*"',
    re.IGNORECASE,
)

# --- Static/hardcoded IV ---
_STATIC_IV = re.compile(
    r'(?:IvParameterSpec|GCMParameterSpec)\s*\(\s*(?:'
    r'new\s+byte\s*\[\s*\]\s*\{[0-9,\s]+\}|'  # Hardcoded byte array
    r'"[^"]+"\s*\.getBytes|'  # String literal as IV
    r'(?:FIXED|STATIC|DEFAULT|ZERO)_?IV'  # Named constant suggesting static IV
    r')',
    re.IGNORECASE,
)

# --- Weak/deprecated algorithms ---
_WEAK_ALGO = re.compile(
    r'Cipher\.getInstance\s*\(\s*"(?:DES|DESede|RC4|RC2|Blowfish|ARC4)[/"]',
    re.IGNORECASE,
)

# --- No padding (NoPadding with CBC = padding oracle) ---
_NO_PADDING = re.compile(
    r'Cipher\.getInstance\s*\(\s*"[^"]*(?:CBC|ECB)/NoPadding"',
    re.IGNORECASE,
)

# --- Weak hash for integrity ---
_WEAK_HASH = re.compile(
    r'MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"',
    re.IGNORECASE,
)

# --- Key derived from password without proper KDF ---
_KEY_FROM_STRING = re.compile(
    r'SecretKeySpec\s*\(\s*(?:\w+\.getBytes\s*\(\s*\)|"[^"]+"\s*\.getBytes)',
)

# --- AES without GCM (no authentication) ---
_AES_NO_GCM = re.compile(
    r'Cipher\.getInstance\s*\(\s*"AES(?:/(?:CBC|ECB|CTR)/\w+)?"',
    re.IGNORECASE,
)
_AES_GCM = re.compile(
    r'Cipher\.getInstance\s*\(\s*"AES/GCM/',
    re.IGNORECASE,
)


class RuntimeDecryptionAnalysisV2(BasePluginV2):
    """Detects insecure cryptographic implementation patterns."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="runtime_decryption_analysis",
            version="3.0.0",
            description="Insecure crypto implementation detection: ECB, static IV, weak algos (CWE-327/329)",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["crypto", "masvs-crypto-1", "cwe-327"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        files_scanned = 0

        try:
            for src_path in self._get_source_files(apk_ctx):
                try:
                    content = Path(src_path).read_text(errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                files_scanned += 1
                rel = self._relative_path(src_path, apk_ctx)
                if self._is_library_code(rel):
                    continue

                findings.extend(self._check_crypto_patterns(content, rel))

            return PluginResult(
                status=PluginStatus.SUCCESS, findings=findings,
                metadata={"execution_time": time.time() - start_time, "files_scanned": files_scanned},
            )
        except Exception as e:
            logger.error("runtime_decryption_analysis failed: %s", e)
            return PluginResult(status=PluginStatus.FAILURE, findings=findings,
                                metadata={"error": type(e).__name__})

    def _get_source_files(self, ctx):
        src = getattr(ctx, "source_files", None)
        if src:
            return [str(f) for f in src if str(f).endswith((".java", ".kt"))]
        d = getattr(ctx, "sources_dir", None)
        if d and Path(d).is_dir():
            return [str(p) for p in Path(d).rglob("*") if p.suffix in (".java", ".kt")]
        return []

    def _relative_path(self, full, ctx):
        ws = getattr(ctx, "workspace_dir", None) or getattr(ctx, "output_dir", None)
        if ws:
            try:
                return str(Path(full).relative_to(ws))
            except ValueError:
                pass
        parts = Path(full).parts
        if "sources" in parts:
            return str(Path(*parts[parts.index("sources"):]))
        return Path(full).name

    def _ln(self, content, pos):
        return content[:pos].count("\n") + 1

    def _snip(self, content, m):
        s = content.rfind("\n", 0, m.start()) + 1
        e = content.find("\n", m.end())
        return content[s:e if e != -1 else len(content)].strip()[:200]

    def _check_crypto_patterns(self, content, rel):
        findings = []

        # ECB mode
        for m in _ECB_MODE.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"rda_ecb_{self._ln(content, m.start())}",
                title="Weak Crypto: ECB mode preserves data patterns",
                description=(
                    "ECB (Electronic Codebook) mode encrypts each block independently, "
                    f"preserving patterns in the plaintext. Code: {self._snip(content, m)}"
                ),
                severity="high", confidence=0.90, cwe_id="CWE-327",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use AES/GCM/NoPadding for authenticated encryption",
            ))

        # Static IV
        for m in _STATIC_IV.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"rda_static_iv_{self._ln(content, m.start())}",
                title="Weak Crypto: Static/hardcoded initialization vector",
                description=(
                    "Static IV makes CBC/GCM encryption deterministic - identical plaintexts "
                    f"produce identical ciphertexts. Code: {self._snip(content, m)}"
                ),
                severity="high", confidence=0.85, cwe_id="CWE-329",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Generate a random IV per encryption operation using SecureRandom",
            ))

        # Weak algorithms
        for m in _WEAK_ALGO.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"rda_weak_algo_{self._ln(content, m.start())}",
                title="Weak Crypto: Deprecated/broken algorithm",
                description=f"Use of broken cipher (DES/RC4/Blowfish). Code: {self._snip(content, m)}",
                severity="high", confidence=0.90, cwe_id="CWE-327",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use AES-256 with GCM mode",
            ))

        # NoPadding with CBC
        for m in _NO_PADDING.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"rda_nopad_{self._ln(content, m.start())}",
                title="Weak Crypto: NoPadding may enable padding oracle attacks",
                description=f"CBC/ECB with NoPadding. Code: {self._snip(content, m)}",
                severity="medium", confidence=0.70, cwe_id="CWE-327",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use AES/GCM/NoPadding (GCM handles padding internally)",
            ))

        # Weak hash
        for m in _WEAK_HASH.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"rda_weak_hash_{self._ln(content, m.start())}",
                title="Weak Hash: MD5 or SHA-1 for integrity/verification",
                description=f"MD5/SHA-1 are collision-vulnerable. Code: {self._snip(content, m)}",
                severity="medium", confidence=0.75, cwe_id="CWE-328",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use SHA-256 or SHA-3 for integrity checks",
            ))

        # Key from string bytes
        for m in _KEY_FROM_STRING.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"rda_key_string_{self._ln(content, m.start())}",
                title="Weak Key Derivation: Key from string bytes without KDF",
                description=(
                    "SecretKeySpec created from string.getBytes() without a proper key derivation function. "
                    f"Code: {self._snip(content, m)}"
                ),
                severity="high", confidence=0.80, cwe_id="CWE-916",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use PBKDF2, scrypt, or Argon2 to derive keys from passwords",
            ))

        # AES without authenticated encryption
        if _AES_NO_GCM.search(content) and not _AES_GCM.search(content):
            m = _AES_NO_GCM.search(content)
            findings.append(PluginFinding(
                finding_id=f"rda_aes_no_auth_{self._ln(content, m.start())}",
                title="AES without Authenticated Encryption (no GCM)",
                description=(
                    "AES used without GCM mode - no integrity protection. "
                    f"Encrypted data can be silently modified. Code: {self._snip(content, m)}"
                ),
                severity="medium", confidence=0.65, cwe_id="CWE-327",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use AES/GCM/NoPadding for authenticated encryption",
            ))

        return findings


def create_plugin():
    return RuntimeDecryptionAnalysisV2()


__all__ = ["RuntimeDecryptionAnalysisV2", "create_plugin"]
