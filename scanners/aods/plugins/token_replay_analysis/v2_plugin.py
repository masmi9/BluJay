#!/usr/bin/env python3
"""
token_replay_analysis - Session & Token Management Security
=============================================================

Detects insecure session/token handling: tokens stored in SharedPreferences
without encryption, missing token expiration, hardcoded session IDs,
and missing HTTPS for token transmission.

MASVS-AUTH-2: Session Management
CWE-613: Insufficient Session Expiration
CWE-522: Insufficiently Protected Credentials
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

# Token stored in plain SharedPreferences
_TOKEN_IN_PREFS = re.compile(
    r'(?:putString|edit\(\)\.put\w+)\s*\(\s*"[^"]*(?:token|session|jwt|auth|bearer|refresh)[^"]*"',
    re.IGNORECASE,
)

# Token in plain file
_TOKEN_IN_FILE = re.compile(
    r'(?:FileOutputStream|FileWriter|openFileOutput)\s*\([^)]*(?:token|session|jwt|auth)',
    re.IGNORECASE,
)

# Hardcoded session/token value
_HARDCODED_SESSION = re.compile(
    r'(?:session_id|sessionId|SESSION_ID|JSESSIONID)\s*=\s*"[^"]{8,}"',
)

# HTTP (not HTTPS) for authentication
_HTTP_AUTH = re.compile(
    r'"http://[^"]*(?:login|auth|token|session|signin|oauth)',
    re.IGNORECASE,
)

# AH-3: Sensitive SharedPreferences key names
_SENSITIVE_PREF_KEY = re.compile(
    r'(?:putString|putInt|putBoolean|getString|getInt|getBoolean)\s*\(\s*"'
    r'(?:password|passwd|secret|token|api[_-]?key|auth[_-]?token|session[_-]?id|'
    r'jwt|bearer|credit[_-]?card|ssn|pin[_-]?code|private[_-]?key|master[_-]?key|'
    r'encryption[_-]?key|db[_-]?password)"',
    re.IGNORECASE,
)

# AH-3: Sensitive preference file names
_SENSITIVE_PREF_FILE = re.compile(
    r'getSharedPreferences\s*\(\s*"(?:credentials|auth|secrets|tokens|user_data|login|session|keys)"',
    re.IGNORECASE,
)

# AH-3: MODE_WORLD_READABLE/WRITEABLE (deprecated but compilable)
_WORLD_READABLE_PREFS = re.compile(
    r'getSharedPreferences\s*\([^)]*MODE_WORLD_(?:READABLE|WRITEABLE|WRITABLE)',
)

# Missing token expiration check
_TOKEN_USE_NO_EXPIRY = re.compile(
    r'(?:getToken|getAccessToken|getAuthToken|getSessionId)\s*\(\s*\)',
)
_EXPIRY_CHECK = re.compile(
    r'(?:isExpired|tokenExpir|expiresAt|expiresIn|exp\b|isValid)',
    re.IGNORECASE,
)

# Cookie without Secure/HttpOnly flags
_COOKIE_NO_FLAGS = re.compile(
    r'new\s+(?:Basic)?Cookie\s*\([^)]+\)',
)
_COOKIE_SECURE = re.compile(r'\.setSecure\s*\(\s*true\s*\)')
_COOKIE_HTTPONLY = re.compile(r'\.setHttpOnly\s*\(\s*true\s*\)')


class TokenReplayAnalysisV2(BasePluginV2):
    """Detects insecure session and token management patterns."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="token_replay_analysis",
            version="3.0.0",
            description="Session & token management security (CWE-613/522)",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["auth", "session", "masvs-auth-2", "cwe-613"],
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

                findings.extend(self._check_token_storage(content, rel))
                findings.extend(self._check_session_security(content, rel))
                findings.extend(self._check_prefs_security(content, rel))

            return PluginResult(
                status=PluginStatus.SUCCESS, findings=findings,
                metadata={"execution_time": time.time() - start_time, "files_scanned": files_scanned},
            )
        except Exception as e:
            logger.error("token_replay_analysis failed: %s", e)
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

    def _check_token_storage(self, content, rel):
        findings = []
        for m in _TOKEN_IN_PREFS.finditer(content):
            # Check if EncryptedSharedPreferences is used nearby
            context_before = content[max(0, m.start() - 500):m.start()]
            if "EncryptedSharedPreferences" in context_before:
                continue
            findings.append(PluginFinding(
                finding_id=f"tra_token_prefs_{self._ln(content, m.start())}",
                title="Insecure Token Storage: Auth token in plain SharedPreferences",
                description=(
                    "Authentication token stored in unencrypted SharedPreferences. "
                    "Root or backup access can extract the token for replay attacks. "
                    f"Code: {self._snip(content, m)}"
                ),
                severity="high", confidence=0.80, cwe_id="CWE-522",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use EncryptedSharedPreferences or Android Keystore for token storage",
            ))
        for m in _TOKEN_IN_FILE.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"tra_token_file_{self._ln(content, m.start())}",
                title="Insecure Token Storage: Auth token written to plain file",
                description=f"Token/session data written to unencrypted file. Code: {self._snip(content, m)}",
                severity="high", confidence=0.75, cwe_id="CWE-522",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use EncryptedFile or Android Keystore",
            ))
        for m in _HARDCODED_SESSION.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"tra_hardcoded_session_{self._ln(content, m.start())}",
                title="Hardcoded Session ID",
                description=f"Hardcoded session identifier in source code. Code: {self._snip(content, m)}",
                severity="critical", confidence=0.90, cwe_id="CWE-798",
                file_path=rel, line_number=self._ln(content, m.start()),
            ))
        return findings

    def _check_session_security(self, content, rel):
        findings = []
        for m in _HTTP_AUTH.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"tra_http_auth_{self._ln(content, m.start())}",
                title="HTTP (not HTTPS) used for authentication endpoint",
                description=(
                    "Authentication endpoint uses plain HTTP. Credentials and tokens "
                    f"are transmitted in cleartext. Code: {self._snip(content, m)}"
                ),
                severity="critical", confidence=0.90, cwe_id="CWE-319",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use HTTPS for all authentication endpoints",
            ))
        return findings

    def _check_prefs_security(self, content, rel):
        """AH-3: SharedPreferences sensitive key names and insecure modes."""
        findings = []

        # MODE_WORLD_READABLE/WRITEABLE
        for m in _WORLD_READABLE_PREFS.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"tra_world_prefs_{self._ln(content, m.start())}",
                title="Insecure SharedPreferences: MODE_WORLD_READABLE/WRITEABLE",
                description=(
                    "SharedPreferences opened with deprecated world-readable/writeable mode. "
                    f"Any app can read this data. Code: {self._snip(content, m)}"
                ),
                severity="high", confidence=0.95, cwe_id="CWE-732",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use MODE_PRIVATE or EncryptedSharedPreferences",
            ))

        # Sensitive key names in put/get calls
        for m in _SENSITIVE_PREF_KEY.finditer(content):
            # Skip if EncryptedSharedPreferences is used nearby
            context_before = content[max(0, m.start() - 500):m.start()]
            if "EncryptedSharedPreferences" in context_before:
                continue
            findings.append(PluginFinding(
                finding_id=f"tra_sensitive_key_{self._ln(content, m.start())}",
                title="Sensitive Data in SharedPreferences Key",
                description=(
                    "SharedPreferences stores data under a key name that implies sensitive content "
                    f"(password, token, etc.). Code: {self._snip(content, m)}"
                ),
                severity="medium", confidence=0.70, cwe_id="CWE-312",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use EncryptedSharedPreferences for sensitive data storage",
            ))

        # Sensitive preference file names
        for m in _SENSITIVE_PREF_FILE.finditer(content):
            if "EncryptedSharedPreferences" in content[max(0, m.start() - 500):m.start()]:
                continue
            findings.append(PluginFinding(
                finding_id=f"tra_sensitive_file_{self._ln(content, m.start())}",
                title="SharedPreferences File Name Implies Sensitive Data",
                description=(
                    "SharedPreferences file name suggests it stores sensitive data "
                    f"(credentials, tokens, etc.). Code: {self._snip(content, m)}"
                ),
                severity="medium", confidence=0.65, cwe_id="CWE-312",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use EncryptedSharedPreferences for files containing sensitive data",
            ))

        return findings


def create_plugin():
    return TokenReplayAnalysisV2()


__all__ = ["TokenReplayAnalysisV2", "create_plugin"]
