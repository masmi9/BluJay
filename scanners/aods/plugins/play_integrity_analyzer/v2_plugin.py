#!/usr/bin/env python3
"""
play_integrity_analyzer - BasePluginV2 Implementation (MSTG-RESILIENCE-6+)
==========================================================================

Validates Play Integrity / SafetyNet attestation implementation:
- Detects client-only attestation validation (should be server-side)
- Flags hardcoded nonces (should be random per request)
- Warns on deprecated SafetyNet usage (should use Play Integrity API)
- Checks for missing nonce validation in attestation flow
- Detects token parsing without server verification
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


# --- Source code patterns ---

_ATTESTATION_PATTERNS = [
    # Deprecated SafetyNet usage
    (
        re.compile(
            r'SafetyNet\.getClient\s*\([^)]*\)\s*\.attest\s*\(',
        ),
        "deprecated_safetynet",
        "Deprecated SafetyNet Attestation API",
        "The application uses the deprecated SafetyNet Attestation API. SafetyNet has been "
        "superseded by the Play Integrity API, which provides stronger device attestation "
        "with better tamper detection and is actively maintained by Google.",
        "medium",
        "CWE-693",
        0.85,
        "MASVS-RESILIENCE-3",
    ),
    # Client-side JWS verification (should be server-side)
    (
        re.compile(
            r'\.getJwsResult\s*\(\s*\)'
            r'|JsonWebSignature\.parser\s*\(\s*\)'
            r'|JWSVerifier\s*\('
            r'|SignedJWT\.parse\s*\(',
        ),
        "client_side_jws",
        "Client-Side Attestation Token Verification",
        "Attestation token (JWS) verification is performed on the client device. A rooted or "
        "compromised device can tamper with the verification logic. Attestation tokens MUST be "
        "sent to your server and verified there using Google's verification endpoint.",
        "high",
        "CWE-345",
        0.80,
        "MASVS-RESILIENCE-3",
    ),
    # Hardcoded nonce in attestation request
    (
        re.compile(
            r'(?:\.setNonce|\.nonce|attest)\s*\(\s*"[A-Za-z0-9+/=]{8,}"',
        ),
        "hardcoded_nonce",
        "Hardcoded Attestation Nonce",
        "A hardcoded string is used as the attestation nonce. Nonces must be randomly generated "
        "per request by the server and validated on return to prevent replay attacks. A hardcoded "
        "nonce allows an attacker to reuse a previously captured attestation result.",
        "high",
        "CWE-330",
        0.85,
        "MASVS-RESILIENCE-3",
    ),
    # Hardcoded nonce via byte array
    (
        re.compile(
            r'(?:\.setNonce|\.nonce|attest)\s*\(\s*(?:new\s+byte\s*\[\s*\]\s*\{|"[^"]{4,}"\.getBytes)',
        ),
        "hardcoded_nonce_bytes",
        "Hardcoded Attestation Nonce (Byte Array)",
        "A static byte array or fixed string is used as the attestation nonce. Nonces should be "
        "cryptographically random values generated server-side for each attestation request.",
        "high",
        "CWE-330",
        0.80,
        "MASVS-RESILIENCE-3",
    ),
    # Missing server validation - local token parsing
    (
        re.compile(
            r'IntegrityTokenResponse\s*\w+\s*=.*\.token\s*\(\s*\)'
            r'|\.getToken\s*\(\s*\)\.split\s*\('
            r'|Base64\.decode\s*\([^)]*getToken',
            re.DOTALL,
        ),
        "local_token_parsing",
        "Local Attestation Token Parsing",
        "The attestation token is being parsed locally on the device. While the token must be "
        "obtained on the client, it should be sent to your server for validation via the "
        "Play Integrity API server endpoint, not decoded on the client.",
        "medium",
        "CWE-345",
        0.70,
        "MASVS-RESILIENCE-3",
    ),
]

# Positive indicator - proper Play Integrity usage (reduces missing-attestation false alarm)
_PLAY_INTEGRITY_USAGE_RE = re.compile(
    r'IntegrityManagerFactory\.create\s*\('
    r'|IntegrityTokenRequest\.builder\s*\('
    r'|com\.google\.android\.play\.core\.integrity',
)

# Nonce generation indicators (proper random nonce)
_RANDOM_NONCE_RE = re.compile(
    r'SecureRandom|UUID\.randomUUID|generateNonce|createNonce|randomBytes',
    re.IGNORECASE,
)

# Library paths to skip
_LIBRARY_PREFIXES = (
    "android/support/", "androidx/", "com/google/", "com/facebook/", "com/squareup/",
    "com/bumptech/", "io/reactivex/", "kotlin/", "kotlinx/", "org/apache/",
    "okhttp3/", "retrofit2/",
)


class PlayIntegrityAnalyzerV2(BasePluginV2):
    """Validates Play Integrity / SafetyNet attestation (MSTG-RESILIENCE-6+)."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="play_integrity_analyzer",
            version="1.0.0",
            description="Validates Play Integrity / SafetyNet attestation implementation quality",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.LOW,
            timeout_seconds=60,
            supported_platforms=["android"],
            tags=["play-integrity", "safetynet", "attestation", "masvs-resilience-6"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        files_scanned = 0
        has_attestation = False
        has_random_nonce = False

        try:
            workspace = getattr(apk_ctx, "workspace_dir", None) or getattr(apk_ctx, "output_dir", None)
            sources_dir = getattr(apk_ctx, "sources_dir", None)
            if not workspace and not sources_dir:
                return PluginResult(
                    status=PluginStatus.SUCCESS,
                    findings=[],
                    metadata={"execution_time": time.time() - start_time, "files_scanned": 0},
                )

            search_dirs = []
            if sources_dir and Path(sources_dir).is_dir():
                search_dirs.append(Path(sources_dir))
            if workspace:
                wp = Path(workspace)
                for subdir in ("sources", "java_source", "src"):
                    candidate = wp / subdir
                    if candidate.is_dir():
                        search_dirs.append(candidate)
                if not search_dirs:
                    search_dirs.append(wp)

            seen_labels: Set[str] = set()
            for search_dir in search_dirs:
                for java_file in search_dir.rglob("*.java"):
                    rel = str(java_file)
                    if self._is_library_code(rel):
                        continue
                    try:
                        content = java_file.read_text(errors="replace")
                    except (OSError, UnicodeDecodeError):
                        continue
                    files_scanned += 1

                    # Fast-path: skip files without attestation keywords
                    if not _has_attestation_keywords(content):
                        continue

                    # Track attestation and nonce usage
                    if _PLAY_INTEGRITY_USAGE_RE.search(content):
                        has_attestation = True
                    if "SafetyNet" in content and "attest" in content:
                        has_attestation = True
                    if _RANDOM_NONCE_RE.search(content):
                        has_random_nonce = True

                    rel_path = self._relative_path(str(java_file), apk_ctx)
                    findings.extend(self._check_attestation_patterns(content, rel_path, seen_labels))

            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    "execution_time": time.time() - start_time,
                    "plugin_version": "1.0.0",
                    "files_scanned": files_scanned,
                    "has_attestation": has_attestation,
                    "has_random_nonce": has_random_nonce,
                },
            )

        except Exception as e:
            logger.error(f"play_integrity_analyzer failed: {e}")
            return PluginResult(
                status=PluginStatus.FAILURE,
                findings=findings,
                metadata={"error": str(e), "execution_time": time.time() - start_time},
            )

    # ------------------------------------------------------------------ helpers

    def _relative_path(self, full_path: str, apk_ctx) -> str:
        workspace = getattr(apk_ctx, "workspace_dir", None) or getattr(apk_ctx, "output_dir", None)
        if workspace:
            try:
                return str(Path(full_path).relative_to(workspace))
            except ValueError:
                pass
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

    def _check_attestation_patterns(
        self, content: str, rel_path: str, seen_labels: Set[str]
    ) -> List[PluginFinding]:
        findings = []
        for pattern, label, title, description, severity, cwe, confidence, masvs in _ATTESTATION_PATTERNS:
            dedup_key = f"{label}:{rel_path}"
            if dedup_key in seen_labels:
                continue
            m = pattern.search(content)
            if m:
                seen_labels.add(dedup_key)
                findings.append(self.create_finding(
                    finding_id=f"integrity_{label}_{len(findings):03d}",
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=confidence,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id=cwe,
                    masvs_control=masvs,
                    remediation=_REMEDIATION.get(label, "Review attestation implementation."),
                ))
        return findings


def _has_attestation_keywords(content: str) -> bool:
    """Fast check for attestation-related keywords."""
    return any(kw in content for kw in (
        "SafetyNet", "Integrity", "attest", "JwsResult", "IntegrityToken",
        "SignedJWT", "Nonce", "nonce",
    ))


_REMEDIATION = {
    "deprecated_safetynet": (
        "Migrate from SafetyNet Attestation API to the Play Integrity API. "
        "See https://developer.android.com/google/play/integrity for migration guide."
    ),
    "client_side_jws": (
        "Send the attestation token to your backend server. Verify the token server-side "
        "using Google's Play Integrity API decryption endpoint or the SafetyNet verification "
        "API. Never verify attestation tokens on the client device."
    ),
    "hardcoded_nonce": (
        "Generate a cryptographically random nonce on your server for each attestation request. "
        "Send it to the client, include it in the attestation call, and validate it on the server "
        "when the token is returned. Use SecureRandom or UUID.randomUUID()."
    ),
    "hardcoded_nonce_bytes": (
        "Replace the static byte array with a server-generated random nonce. "
        "Use SecureRandom to generate at least 16 bytes of randomness per request."
    ),
    "local_token_parsing": (
        "Send the raw attestation token to your server without parsing it locally. "
        "Your server should call Google's API to decrypt and validate the token, then "
        "make trust decisions based on the verified result."
    ),
}


# Plugin factory
def create_plugin() -> PlayIntegrityAnalyzerV2:
    return PlayIntegrityAnalyzerV2()


__all__ = ["PlayIntegrityAnalyzerV2", "create_plugin"]
