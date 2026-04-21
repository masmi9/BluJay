#!/usr/bin/env python3
"""
authentication_security_analysis - BasePluginV2 Implementation (MASVS-AUTH)
============================================================================

Wires the existing OAuthAnalyzer (MSTG-AUTH-3/5) for OAuth/PKCE analysis
and adds direct source scanning for hardcoded credentials (CWE-798) and
authentication bypass patterns (CWE-287).
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

# --- OAuth vuln_type → finding metadata mapping ---

_OAUTH_VULN_MAP = {
    "missing_token_expiration": {
        "cwe": "CWE-613", "severity": "high", "mastg": "MSTG-AUTH-3",
        "remediation": "Implement token expiration checks and enforce short-lived access tokens.",
    },
    "missing_token_refresh": {
        "cwe": "CWE-613", "severity": "medium", "mastg": "MSTG-AUTH-3",
        "remediation": "Implement a token refresh mechanism using refresh tokens.",
    },
    "missing_token_revocation": {
        "cwe": "CWE-613", "severity": "high", "mastg": "MSTG-AUTH-2",
        "remediation": "Revoke tokens server-side on logout and provide a revocation endpoint.",
    },
    "missing_oauth_state": {
        "cwe": "CWE-352", "severity": "high", "mastg": "MSTG-AUTH-5",
        "remediation": "Generate a unique state parameter per OAuth request and validate on callback.",
    },
    "missing_pkce": {
        "cwe": "CWE-287", "severity": "medium", "mastg": "MSTG-AUTH-5",
        "remediation": "Implement PKCE (RFC 7636) with S256 code challenge method.",
    },
    "hardcoded_oauth_secret": {
        "cwe": "CWE-798", "severity": "critical", "mastg": "MSTG-AUTH-1",
        "remediation": "Remove hardcoded client secrets; use dynamic client registration or backend proxy.",
    },
    "insecure_token_storage": {
        "cwe": "CWE-922", "severity": "high", "mastg": "MSTG-AUTH-2",
        "remediation": "Use EncryptedSharedPreferences or Android Keystore for token storage.",
    },
    "implicit_flow_usage": {
        "cwe": "CWE-287", "severity": "medium", "mastg": "MSTG-AUTH-5",
        "remediation": "Migrate from implicit flow to authorization code flow with PKCE.",
    },
    "missing_scope_validation": {
        "cwe": "CWE-863", "severity": "medium", "mastg": "MSTG-AUTH-5",
        "remediation": "Validate returned OAuth scopes match requested scopes.",
    },
    "insecure_redirect_uri": {
        "cwe": "CWE-601", "severity": "high", "mastg": "MSTG-AUTH-5",
        "remediation": "Use exact-match redirect URIs with app-scheme or verified HTTPS endpoints.",
    },
    "missing_token_binding": {
        "cwe": "CWE-384", "severity": "medium", "mastg": "MSTG-AUTH-2",
        "remediation": "Bind tokens to the device or session using DPoP or certificate binding.",
    },
}

# --- Direct source scan patterns ---

_HARDCODED_CRED_PATTERNS = [
    (
        re.compile(r'(?:password|passwd|pwd)\s*=\s*"[^"]{4,}"', re.IGNORECASE),
        "Hardcoded password",
        "CWE-798",
    ),
    (
        re.compile(r'(?:api_?key|apikey|secret_?key)\s*=\s*"[^"]{8,}"', re.IGNORECASE),
        "Hardcoded API key",
        "CWE-798",
    ),
    (
        re.compile(r'(?:auth_?token|access_?token|bearer)\s*=\s*"[^"]{10,}"', re.IGNORECASE),
        "Hardcoded auth token",
        "CWE-798",
    ),
]

_AUTH_BYPASS_PATTERNS = [
    (
        re.compile(r'if\s*\(\s*(?:true|1|"debug")\s*\)'),
        "Debug always-true auth check",
        "CWE-287",
    ),
    (
        re.compile(r'BYPASS_AUTH\s*=\s*true', re.IGNORECASE),
        "Authentication bypass flag",
        "CWE-287",
    ),
    (
        re.compile(r'BuildConfig\.DEBUG\s*&&\s*return\s+true'),
        "Debug-mode authentication bypass",
        "CWE-287",
    ),
]


class AuthenticationSecurityAnalysisV2(BasePluginV2):
    """OAuth, credential, and auth bypass analysis (MASVS-AUTH)."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="authentication_security_analysis",
            version="2.1.0",
            description="OAuth/PKCE analysis, hardcoded credential detection, and auth bypass detection",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=180,
            supported_platforms=["android"],
            tags=["auth", "oauth", "masvs-auth"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        files_scanned = 0

        try:
            # 1. Run OAuthAnalyzer on apk_ctx (uses apk_ctx.source_files dict)
            findings.extend(self._run_oauth_analyzer(apk_ctx))

            # 2. Direct source file scanning for credentials + bypass patterns
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

                findings.extend(self._check_hardcoded_credentials(content, rel_path))
                findings.extend(self._check_auth_bypass(content, rel_path))

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
            logger.error(f"authentication_security_analysis failed: {e}")
            return PluginResult(
                status=PluginStatus.FAILURE,
                findings=findings,
                metadata={"error": str(e), "execution_time": time.time() - start_time},
            )

    # ------------------------------------------------------------------ OAuth

    def _run_oauth_analyzer(self, apk_ctx) -> List[PluginFinding]:
        # OAuthAnalyzer requires source_files as a dict (path→content)
        src = getattr(apk_ctx, "source_files", None)
        if not src or not isinstance(src, dict):
            return []

        try:
            from .oauth_analyzer import OAuthAnalyzer
        except ImportError:
            logger.warning("oauth_analyzer not available, skipping OAuth analysis")
            return []

        oauth = OAuthAnalyzer()
        vulns = oauth.analyze_oauth_security(apk_ctx)
        return self._convert_oauth_vulns(vulns)

    def _convert_oauth_vulns(self, vulns) -> List[PluginFinding]:
        findings: List[PluginFinding] = []
        seen: Set[str] = set()
        for vuln in vulns:
            dedup_key = f"{vuln.vuln_type}:{vuln.location}"
            if dedup_key in seen:
                continue

            # Skip findings in third-party SDK code
            if vuln.location and self._is_library_code(vuln.location):
                continue

            seen.add(dedup_key)

            meta = _OAUTH_VULN_MAP.get(vuln.vuln_type, {})
            cwe = meta.get("cwe", "CWE-287")
            severity = meta.get("severity", "medium")
            mastg = meta.get("mastg", "MSTG-AUTH-1")
            remediation = meta.get("remediation")

            # Parse file_path and line from location "file:line" format
            file_path = vuln.location
            line_number = vuln.line_number
            if ":" in vuln.location and vuln.location != "global":
                parts = vuln.location.rsplit(":", 1)
                file_path = parts[0]

            findings.append(self.create_finding(
                finding_id=f"auth_oauth_{len(findings):03d}",
                title=f"OAuth: {vuln.vuln_type.replace('_', ' ').title()}",
                description=f"{meta.get('remediation', vuln.value)[:200] if meta else vuln.value[:200]}",
                severity=severity,
                confidence=0.8,
                file_path=file_path,
                line_number=line_number,
                code_snippet=vuln.value[:200] if vuln.value else None,
                cwe_id=cwe,
                masvs_control=mastg,
                remediation=remediation,
            ))
        return findings

    # ------------------------------------------------------------------ helpers

    def _get_source_files(self, apk_ctx) -> List[str]:
        src = getattr(apk_ctx, "source_files", None)
        if src:
            # source_files can be list of paths or dict (path→content)
            if isinstance(src, dict):
                return [str(f) for f in src.keys() if str(f).endswith((".java", ".kt"))]
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

    # toString() debug string pattern: return "ClassName(field=..." or "Result{field=..."
    _TOSTRING_CTX = re.compile(r'(?:return\s+)?"\w+[\(\{].*=')

    def _check_hardcoded_credentials(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings: List[PluginFinding] = []
        seen: Set[str] = set()
        for pattern, desc, cwe in _HARDCODED_CRED_PATTERNS:
            m = pattern.search(content)
            if m and desc not in seen:
                # Skip toString() debug output patterns
                line_start = content.rfind("\n", 0, m.start()) + 1
                line_end = content.find("\n", m.end())
                if line_end == -1:
                    line_end = len(content)
                line = content[line_start:line_end]
                if self._TOSTRING_CTX.search(line):
                    continue

                seen.add(desc)
                findings.append(self.create_finding(
                    finding_id=f"auth_hardcoded_{len(findings):03d}",
                    title=f"Hardcoded Credential: {desc}",
                    description=(
                        f"{desc} found in source code. Hardcoded credentials can be extracted "
                        "by decompiling the APK and may lead to unauthorized access."
                    ),
                    severity="high",
                    confidence=0.8,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id=cwe,
                    masvs_control="MASVS-AUTH-1",
                    remediation="Store credentials securely using Android Keystore or fetch from a secure backend.",
                ))
        return findings

    def _check_auth_bypass(self, content: str, rel_path: str) -> List[PluginFinding]:
        findings: List[PluginFinding] = []
        seen: Set[str] = set()
        for pattern, desc, cwe in _AUTH_BYPASS_PATTERNS:
            m = pattern.search(content)
            if m and desc not in seen:
                seen.add(desc)
                findings.append(self.create_finding(
                    finding_id=f"auth_bypass_{len(findings):03d}",
                    title=f"Authentication Bypass: {desc}",
                    description=(
                        f"{desc} detected. This pattern may allow attackers to bypass "
                        "authentication controls. Remove debug bypasses before release."
                    ),
                    severity="critical",
                    confidence=0.85,
                    file_path=rel_path,
                    line_number=self._line_number(content, m.start()),
                    code_snippet=self._snippet(content, m.start(), m.end()),
                    cwe_id=cwe,
                    masvs_control="MASVS-AUTH-1",
                    remediation="Remove all debug/test authentication bypasses before production release.",
                ))
        return findings


# Plugin factory
def create_plugin() -> AuthenticationSecurityAnalysisV2:
    return AuthenticationSecurityAnalysisV2()


__all__ = ["AuthenticationSecurityAnalysisV2", "create_plugin"]
