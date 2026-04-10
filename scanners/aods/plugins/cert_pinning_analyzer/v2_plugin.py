#!/usr/bin/env python3
"""
cert_pinning_analyzer - BasePluginV2 Implementation (MSTG-NETWORK-5+)
=====================================================================

Validates certificate pinning implementation quality:
- OkHttp CertificatePinner detection and configuration analysis
- NetworkSecurityConfig pin-set validation (backup pins, algorithm strength)
- Missing certificate pinning detection for network-heavy apps
- Retrofit/Volley pinning configuration checks
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

_CERT_PINNER_BUILDER_RE = re.compile(
    r'(?:new\s+)?CertificatePinner\.Builder\s*\(\s*\)',
)
_CERT_PINNER_ADD_RE = re.compile(
    r'\.add\s*\(\s*"([^"]+)"\s*,\s*"(sha\d+/[^"]+)"',
    re.IGNORECASE,
)
_CERT_PINNER_SHA1_RE = re.compile(
    r'\.add\s*\([^)]*"sha1/[^"]+"',
    re.IGNORECASE,
)
_OKHTTP_NO_PINNER_RE = re.compile(
    r'(?:new\s+)?OkHttpClient\.Builder\s*\(\s*\)'
    r'(?:(?!\.certificatePinner).){0,500}'
    r'\.build\s*\(\s*\)',
    re.DOTALL,
)
_TRUST_MANAGER_FACTORY_RE = re.compile(
    r'TrustManagerFactory\.getInstance\s*\(\s*"([^"]+)"\s*\)',
)

# NSC XML patterns
_PIN_SET_RE = re.compile(
    r'<pin-set\b[^>]*>(.*?)</pin-set>',
    re.DOTALL,
)
_PIN_DIGEST_RE = re.compile(
    r'<pin\s+digest="([^"]+)"[^>]*>([^<]+)</pin>',
)
_PIN_EXPIRATION_RE = re.compile(
    r'<pin-set\s+expiration="([^"]+)"',
)
_DOMAIN_CONFIG_RE = re.compile(
    r'<domain-config[^>]*>(.*?)</domain-config>',
    re.DOTALL,
)
_DOMAIN_RE = re.compile(
    r'<domain\b[^>]*>([^<]+)</domain>',
)

# Network-heavy indicators (to flag missing pinning)
_NETWORK_HEAVY_INDICATORS = [
    re.compile(r'OkHttpClient'),
    re.compile(r'Retrofit\.Builder'),
    re.compile(r'Volley\.newRequestQueue'),
    re.compile(r'HttpURLConnection'),
    re.compile(r'HttpsURLConnection'),
]

# Library paths to skip
_LIBRARY_PREFIXES = (
    "android/support/", "androidx/", "com/google/", "com/facebook/", "com/squareup/",
    "com/bumptech/", "io/reactivex/", "kotlin/", "kotlinx/", "org/apache/",
    "okhttp3/", "retrofit2/", "com/android/volley/",
)


class CertPinningAnalyzerV2(BasePluginV2):
    """Validates certificate pinning implementation (MSTG-NETWORK-5+)."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="cert_pinning_analyzer",
            version="1.0.0",
            description="Validates certificate pinning implementation quality (OkHttp, NSC)",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=90,
            supported_platforms=["android"],
            tags=["certificate-pinning", "okhttp", "network-security-config", "masvs-network-5"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        files_scanned = 0
        has_pinning = False
        has_network_usage = False

        try:
            workspace = getattr(apk_ctx, "workspace_dir", None) or getattr(apk_ctx, "output_dir", None)
            sources_dir = getattr(apk_ctx, "sources_dir", None)
            if not workspace and not sources_dir:
                return PluginResult(
                    status=PluginStatus.SUCCESS,
                    findings=[],
                    metadata={"execution_time": time.time() - start_time, "files_scanned": 0},
                )

            # 1. Scan NSC XML files
            wp = Path(workspace) if workspace else None
            if wp:
                nsc_findings, nsc_has_pinning = self._check_nsc_files(wp)
                findings.extend(nsc_findings)
                if nsc_has_pinning:
                    has_pinning = True

            # 2. Scan Java source files
            search_dirs = []
            if sources_dir and Path(sources_dir).is_dir():
                search_dirs.append(Path(sources_dir))
            if wp:
                for subdir in ("sources", "java_source", "src"):
                    candidate = wp / subdir
                    if candidate.is_dir():
                        search_dirs.append(candidate)

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

                    # Check for network usage
                    if not has_network_usage:
                        for indicator in _NETWORK_HEAVY_INDICATORS:
                            if indicator.search(content):
                                has_network_usage = True
                                break

                    # Check OkHttp pinning patterns
                    rel_path = self._relative_path(str(java_file), apk_ctx)
                    source_findings = self._check_source_pinning(content, rel_path, seen_labels)
                    findings.extend(source_findings)
                    if any("CertificatePinner" in content for _ in [1]):
                        if _CERT_PINNER_BUILDER_RE.search(content):
                            has_pinning = True

            # 3. Flag missing pinning for network-heavy apps
            if has_network_usage and not has_pinning:
                findings.append(self.create_finding(
                    finding_id="cert_pinning_missing_000",
                    title="Certificate Pinning Not Implemented",
                    description=(
                        "The application uses HTTP/HTTPS networking libraries but does not implement "
                        "certificate pinning. Without pinning, the app relies solely on the system "
                        "certificate store, making it vulnerable to man-in-the-middle attacks via "
                        "compromised or rogue CAs."
                    ),
                    severity="medium",
                    confidence=0.70,
                    file_path=None,
                    line_number=None,
                    cwe_id="CWE-295",
                    masvs_control="MASVS-NETWORK-2",
                    remediation=(
                        "Implement certificate pinning using OkHttp CertificatePinner or Android "
                        "network_security_config.xml with <pin-set>. Include at least one backup pin."
                    ),
                ))

            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    "execution_time": time.time() - start_time,
                    "plugin_version": "1.0.0",
                    "files_scanned": files_scanned,
                    "has_pinning": has_pinning,
                    "has_network_usage": has_network_usage,
                },
            )

        except Exception as e:
            logger.error(f"cert_pinning_analyzer failed: {e}")
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

    def _check_nsc_files(self, workspace: Path) -> tuple:
        """Check NetworkSecurityConfig XML files for pin-set quality."""
        findings: List[PluginFinding] = []
        has_pinning = False

        nsc_candidates = (
            list(workspace.rglob("network_security_config.xml"))
            + list(workspace.rglob("network-security-config.xml"))
            + list(workspace.rglob("network_config.xml"))
        )

        for nsc_file in nsc_candidates:
            try:
                content = nsc_file.read_text(errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = nsc_file.name

            # Check for pin-set elements
            pin_sets = _PIN_SET_RE.findall(content)
            if pin_sets:
                has_pinning = True

            for pin_set_match in _PIN_SET_RE.finditer(content):
                pin_set_content = pin_set_match.group(1)
                pins = _PIN_DIGEST_RE.findall(pin_set_content)

                # Check pin count (should have backup pins)
                if len(pins) < 2:
                    findings.append(self.create_finding(
                        finding_id=f"cert_pinning_no_backup_{len(findings):03d}",
                        title="Certificate Pin-Set Without Backup Pin",
                        description=(
                            f"The pin-set contains only {len(pins)} pin(s). Without a backup pin, "
                            "certificate rotation will cause app connectivity failures. Include at "
                            "least one backup pin for a different key to ensure continuity."
                        ),
                        severity="medium",
                        confidence=0.85,
                        file_path=rel_path,
                        line_number=self._line_number(content, pin_set_match.start()),
                        cwe_id="CWE-295",
                        masvs_control="MASVS-NETWORK-2",
                        remediation="Add at least one backup pin with a different key to the pin-set.",
                    ))

                # Check for weak digest algorithm
                for digest_alg, pin_value in pins:
                    if digest_alg.lower() == "sha-1" or digest_alg.lower() == "sha1":
                        findings.append(self.create_finding(
                            finding_id=f"cert_pinning_weak_digest_{len(findings):03d}",
                            title="Certificate Pin Uses Weak SHA-1 Digest",
                            description=(
                                f"A certificate pin uses the SHA-1 digest algorithm ('{digest_alg}'). "
                                "SHA-1 is cryptographically weak and collision attacks are practical. "
                                "Use SHA-256 for certificate pinning."
                            ),
                            severity="medium",
                            confidence=0.90,
                            file_path=rel_path,
                            line_number=self._line_number(content, pin_set_match.start()),
                            cwe_id="CWE-328",
                            masvs_control="MASVS-NETWORK-2",
                            remediation="Change pin digest to SHA-256.",
                        ))

                # Check expiration
                exp_match = _PIN_EXPIRATION_RE.search(pin_set_match.group(0))
                if not exp_match:
                    findings.append(self.create_finding(
                        finding_id=f"cert_pinning_no_expiry_{len(findings):03d}",
                        title="Certificate Pin-Set Without Expiration",
                        description=(
                            "The pin-set does not specify an expiration date. While not required, "
                            "setting an expiration acts as a safety net - if pins become stale, "
                            "the app falls back to standard validation instead of blocking all traffic."
                        ),
                        severity="info",
                        confidence=0.80,
                        file_path=rel_path,
                        line_number=self._line_number(content, pin_set_match.start()),
                        cwe_id="CWE-295",
                        masvs_control="MASVS-NETWORK-2",
                        remediation="Add expiration=\"YYYY-MM-DD\" to the pin-set element.",
                    ))

        return findings, has_pinning

    def _check_source_pinning(
        self, content: str, rel_path: str, seen_labels: Set[str]
    ) -> List[PluginFinding]:
        """Check Java source for OkHttp CertificatePinner patterns."""
        findings = []

        # Check for SHA-1 pins in CertificatePinner
        sha1_key = f"sha1_pin:{rel_path}"
        if sha1_key not in seen_labels:
            m = _CERT_PINNER_SHA1_RE.search(content)
            if m:
                seen_labels.add(sha1_key)
                findings.append(self.create_finding(
                    finding_id=f"cert_pinning_sha1_code_{len(findings):03d}",
                    title="OkHttp CertificatePinner Uses SHA-1",
                    description=(
                        "CertificatePinner.add() uses a SHA-1 pin digest. SHA-1 is cryptographically "
                        "weak. Use SHA-256 pins instead."
                    ),
                    severity="medium",
                    confidence=0.90,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id="CWE-328",
                    masvs_control="MASVS-NETWORK-2",
                    remediation="Replace sha1/ pins with sha256/ pins in CertificatePinner.",
                ))

        # Check for OkHttpClient without CertificatePinner
        no_pinner_key = f"no_pinner:{rel_path}"
        if no_pinner_key not in seen_labels and "OkHttpClient" in content:
            m = _OKHTTP_NO_PINNER_RE.search(content)
            if m:
                # Verify there's no separate certificatePinner call nearby
                if ".certificatePinner" not in content:
                    seen_labels.add(no_pinner_key)
                    findings.append(self.create_finding(
                        finding_id=f"cert_pinning_okhttp_missing_{len(findings):03d}",
                        title="OkHttpClient Built Without Certificate Pinning",
                        description=(
                            "An OkHttpClient is built without configuring a CertificatePinner. "
                            "The client will accept any valid certificate, making it vulnerable "
                            "to man-in-the-middle attacks via rogue CAs."
                        ),
                        severity="low",
                        confidence=0.65,
                        file_path=rel_path,
                        line_number=self._line_number(content, m.start()),
                        code_snippet=self._snippet(content, m.start(), m.end()),
                        cwe_id="CWE-295",
                        masvs_control="MASVS-NETWORK-2",
                        remediation=(
                            "Add .certificatePinner(pinner) to the OkHttpClient.Builder chain "
                            "with SHA-256 pins for your server's certificate."
                        ),
                    ))

        return findings


# Plugin factory
def create_plugin() -> CertPinningAnalyzerV2:
    return CertPinningAnalyzerV2()


__all__ = ["CertPinningAnalyzerV2", "create_plugin"]
