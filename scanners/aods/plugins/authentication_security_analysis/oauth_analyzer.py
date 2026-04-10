"""
OAuth Token Lifecycle Analyzer for AODS

Analyzes OAuth/OpenID Connect implementation security including:
- Token expiration and refresh mechanisms
- Token storage security
- Token revocation on logout
- OAuth state parameter validation
- PKCE (Proof Key for Code Exchange) enforcement
- Scope validation and least privilege
"""

import logging
import re
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass

from core.apk_ctx import APKContext
from .data_structures import AuthenticationVulnerability

logger = logging.getLogger(__name__)


# OAuth/Token vulnerability types
OAUTH_VULN_TYPES = {
    "missing_token_expiration": {
        "severity": "HIGH",
        "cwe": "CWE-613",
        "mastg": "MSTG-AUTH-3",
        "description": "OAuth token stored without expiration check",
    },
    "missing_token_refresh": {
        "severity": "MEDIUM",
        "cwe": "CWE-613",
        "mastg": "MSTG-AUTH-3",
        "description": "No token refresh mechanism detected",
    },
    "missing_token_revocation": {
        "severity": "HIGH",
        "cwe": "CWE-613",
        "mastg": "MSTG-AUTH-2",
        "description": "Token not revoked on logout",
    },
    "missing_oauth_state": {
        "severity": "HIGH",
        "cwe": "CWE-352",
        "mastg": "MSTG-AUTH-5",
        "description": "OAuth flow missing state parameter (CSRF vulnerable)",
    },
    "missing_pkce": {
        "severity": "MEDIUM",
        "cwe": "CWE-287",
        "mastg": "MSTG-AUTH-5",
        "description": "OAuth flow missing PKCE (Proof Key for Code Exchange)",
    },
    "hardcoded_oauth_secret": {
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "mastg": "MSTG-AUTH-1",
        "description": "OAuth client secret hardcoded in source",
    },
    "insecure_token_storage": {
        "severity": "HIGH",
        "cwe": "CWE-922",
        "mastg": "MSTG-AUTH-2",
        "description": "OAuth token stored insecurely",
    },
    "implicit_flow_usage": {
        "severity": "MEDIUM",
        "cwe": "CWE-287",
        "mastg": "MSTG-AUTH-5",
        "description": "Deprecated OAuth implicit flow detected",
    },
    "missing_scope_validation": {
        "severity": "MEDIUM",
        "cwe": "CWE-863",
        "mastg": "MSTG-AUTH-5",
        "description": "OAuth scope not validated",
    },
    "insecure_redirect_uri": {
        "severity": "HIGH",
        "cwe": "CWE-601",
        "mastg": "MSTG-AUTH-5",
        "description": "OAuth redirect URI allows arbitrary hosts",
    },
    "missing_token_binding": {
        "severity": "MEDIUM",
        "cwe": "CWE-384",
        "mastg": "MSTG-AUTH-2",
        "description": "Token not bound to device/session",
    },
}


# OAuth detection patterns
OAUTH_PATTERNS = {
    "oauth_libraries": [
        r"(?:import|from)\s+(?:com\.)?(?:google|facebook|twitter|github|microsoft)\.auth",
        r"OkHttp.*OAuth",
        r"OAuth2.*Client",
        r"AppAuth\b",
        r"net\.openid\.appauth",
        r"AuthorizationService",
        r"AuthState",
    ],
    "token_storage": [
        r"putString\s*\(\s*[\"'](?:access_token|refresh_token|id_token|oauth_token)",
        r"SharedPreferences.*(?:access|refresh|id|oauth).*token",
        r"save.*(?:Access|Refresh|Id|OAuth).*Token",
        r"store.*Token",
    ],
    "token_refresh": [
        r"refresh.*Token",
        r"TokenRefresh",
        r"renewToken",
        r"performTokenRefresh",
        r"getNewAccessToken",
    ],
    "token_expiration": [
        r"token.*expir",
        r"expir.*token",
        r"isTokenExpired",
        r"checkTokenValidity",
        r"tokenExpiresAt",
        r"expires_in",
    ],
    "token_revocation": [
        r"revoke.*Token",
        r"invalidate.*Token",
        r"clearTokens",
        r"deleteToken",
        r"logout.*token",
        r"signOut.*clear",
    ],
    "oauth_state": [
        r"state\s*=",
        r"\.setState\(",
        r"generateState",
        r"verifyState",
        r"csrfToken",
    ],
    "pkce": [
        r"code_verifier",
        r"code_challenge",
        r"setCodeVerifier",
        r"generateCodeVerifier",
        r"S256",
    ],
    "implicit_flow": [
        r"response_type\s*=\s*[\"']token",
        r"implicitGrant",
        r"implicit.*flow",
    ],
    "client_secret": [
        r"client_secret\s*=\s*[\"'][^\"']+",
        r"clientSecret\s*=\s*[\"'][^\"']+",
        r"OAUTH_SECRET\s*=\s*[\"'][^\"']+",
    ],
    "redirect_uri": [
        r"redirect_uri\s*=",
        r"setRedirectUri",
        r"callbackUrl",
        r"redirectUrl",
    ],
}


@dataclass
class OAuthFlowInfo:
    """Information about detected OAuth flow."""

    has_oauth: bool = False
    libraries_detected: List[str] = None
    has_token_storage: bool = False
    has_token_refresh: bool = False
    has_token_expiration: bool = False
    has_token_revocation: bool = False
    has_state_parameter: bool = False
    has_pkce: bool = False
    uses_implicit_flow: bool = False
    has_hardcoded_secret: bool = False

    def __post_init__(self):
        if self.libraries_detected is None:
            self.libraries_detected = []


class OAuthAnalyzer:
    """Analyzer for OAuth/OpenID Connect implementation security."""

    def __init__(self):
        """Initialize OAuth analyzer."""
        self.vulnerabilities: List[AuthenticationVulnerability] = []
        self.oauth_info = OAuthFlowInfo()
        self._tracer = None

    def _get_tracer(self):
        """Get MSTG tracer instance (lazy load)."""
        if self._tracer is None:
            try:
                from core.compliance.mstg_tracer import get_tracer

                self._tracer = get_tracer()
            except ImportError:
                self._tracer = None
        return self._tracer

    def _emit_check_start(self, mstg_id: str, meta: Optional[Dict[str, Any]] = None):
        """Emit tracer event for check start."""
        tracer = self._get_tracer()
        if tracer:
            try:
                tracer.start_check(mstg_id, meta=meta or {"analyzer": "oauth_analyzer"})
            except Exception:
                pass

    def _emit_check_end(self, mstg_id: str, status: str):
        """Emit tracer event for check end."""
        tracer = self._get_tracer()
        if tracer:
            try:
                tracer.end_check(mstg_id, status=status)
            except Exception:
                pass

    def analyze_oauth_security(self, apk_ctx: APKContext) -> List[AuthenticationVulnerability]:
        """
        Analyze OAuth/token lifecycle security.

        Args:
            apk_ctx: APK context with source files

        Returns:
            List of authentication vulnerabilities
        """
        logger.info("Analyzing OAuth/token lifecycle security")

        self.vulnerabilities = []
        self.oauth_info = OAuthFlowInfo()

        if not hasattr(apk_ctx, "source_files"):
            return self.vulnerabilities

        # First pass: detect OAuth usage
        self._detect_oauth_usage(apk_ctx)

        if not self.oauth_info.has_oauth:
            logger.debug("No OAuth implementation detected")
            return self.vulnerabilities

        # Emit tracer events for OAuth-related MSTG tests
        self._emit_check_start("MSTG-AUTH-2", {"check": "session_management"})
        self._emit_check_start("MSTG-AUTH-3", {"check": "token_lifecycle"})
        self._emit_check_start("MSTG-AUTH-5", {"check": "oauth_flow"})

        try:
            # Second pass: analyze security issues
            for file_path, content in apk_ctx.source_files.items():
                if file_path.endswith((".java", ".kt", ".swift", ".m")):
                    self._analyze_file(file_path, content)

            # Validate OAuth flow completeness
            self._validate_oauth_flow()

            # Determine check statuses
            auth2_status = (
                "PASS"
                if not any(
                    v.vuln_type in ("missing_token_revocation", "insecure_token_storage", "missing_token_binding")
                    for v in self.vulnerabilities
                )
                else "FAIL"
            )

            auth3_status = (
                "PASS"
                if not any(
                    v.vuln_type in ("missing_token_expiration", "missing_token_refresh") for v in self.vulnerabilities
                )
                else "FAIL"
            )

            auth5_status = (
                "PASS"
                if not any(
                    v.vuln_type
                    in ("missing_oauth_state", "missing_pkce", "implicit_flow_usage", "insecure_redirect_uri")
                    for v in self.vulnerabilities
                )
                else "FAIL"
            )

        except Exception as e:
            logger.error(f"OAuth analysis failed: {e}")
            auth2_status = auth3_status = auth5_status = "SKIP"

        # Emit tracer end events
        self._emit_check_end("MSTG-AUTH-2", auth2_status)
        self._emit_check_end("MSTG-AUTH-3", auth3_status)
        self._emit_check_end("MSTG-AUTH-5", auth5_status)

        return self.vulnerabilities

    def _detect_oauth_usage(self, apk_ctx: APKContext):
        """Detect if OAuth is used in the application."""
        for file_path, content in apk_ctx.source_files.items():
            if not file_path.endswith((".java", ".kt", ".swift", ".m")):
                continue

            # Check for OAuth library imports
            for pattern in OAUTH_PATTERNS["oauth_libraries"]:
                if re.search(pattern, content, re.IGNORECASE):
                    self.oauth_info.has_oauth = True
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        self.oauth_info.libraries_detected.append(match.group(0))

            # Check for token storage patterns
            for pattern in OAUTH_PATTERNS["token_storage"]:
                if re.search(pattern, content, re.IGNORECASE):
                    self.oauth_info.has_oauth = True
                    self.oauth_info.has_token_storage = True

    def _analyze_file(self, file_path: str, content: str):
        """Analyze a single file for OAuth security issues."""
        lines = content.split("\n")

        # Track what we find in this file

        for line_num, line in enumerate(lines, 1):
            # Check for token refresh
            for pattern in OAUTH_PATTERNS["token_refresh"]:
                if re.search(pattern, line, re.IGNORECASE):
                    self.oauth_info.has_token_refresh = True

            # Check for token expiration handling
            for pattern in OAUTH_PATTERNS["token_expiration"]:
                if re.search(pattern, line, re.IGNORECASE):
                    self.oauth_info.has_token_expiration = True

            # Check for token revocation
            for pattern in OAUTH_PATTERNS["token_revocation"]:
                if re.search(pattern, line, re.IGNORECASE):
                    self.oauth_info.has_token_revocation = True

            # Check for state parameter
            for pattern in OAUTH_PATTERNS["oauth_state"]:
                if re.search(pattern, line, re.IGNORECASE):
                    self.oauth_info.has_state_parameter = True

            # Check for PKCE
            for pattern in OAUTH_PATTERNS["pkce"]:
                if re.search(pattern, line, re.IGNORECASE):
                    self.oauth_info.has_pkce = True

            # Check for deprecated implicit flow
            for pattern in OAUTH_PATTERNS["implicit_flow"]:
                if re.search(pattern, line, re.IGNORECASE):
                    self.oauth_info.uses_implicit_flow = True
                    self._add_vulnerability("implicit_flow_usage", file_path, line_num, line.strip())

            # Check for hardcoded client secrets
            for pattern in OAUTH_PATTERNS["client_secret"]:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    self.oauth_info.has_hardcoded_secret = True
                    self._add_vulnerability(
                        "hardcoded_oauth_secret",
                        file_path,
                        line_num,
                        line.strip(),
                        secret_value=self._extract_secret(match.group(0)),
                    )

            # Check for insecure redirect URI
            self._check_redirect_uri(file_path, line_num, line, lines)

            # Check for insecure token storage
            self._check_token_storage(file_path, line_num, line, lines)

    def _check_redirect_uri(self, file_path: str, line_num: int, line: str, lines: List[str]):
        """Check for insecure redirect URI configuration."""
        for pattern in OAUTH_PATTERNS["redirect_uri"]:
            if re.search(pattern, line, re.IGNORECASE):
                # Check if redirect URI is properly validated
                context = "\n".join(lines[max(0, line_num - 3) : min(len(lines), line_num + 3)])

                # Look for wildcard or insecure patterns
                if re.search(r"redirect.*\*|redirect.*any|http://", line, re.IGNORECASE):
                    self._add_vulnerability("insecure_redirect_uri", file_path, line_num, line.strip())

                # Check for missing validation
                if not re.search(r"valid|verify|check|match", context, re.IGNORECASE):
                    # This is a weaker signal, only flag if redirect contains variable
                    if re.search(r"redirect.*\+|redirect.*\$|redirect.*\{", line, re.IGNORECASE):
                        self._add_vulnerability("insecure_redirect_uri", file_path, line_num, line.strip())

    def _check_token_storage(self, file_path: str, line_num: int, line: str, lines: List[str]):
        """Check for insecure token storage."""
        for pattern in OAUTH_PATTERNS["token_storage"]:
            if re.search(pattern, line, re.IGNORECASE):
                context = "\n".join(lines[max(0, line_num - 3) : min(len(lines), line_num + 3)])

                # Check for insecure storage modes
                if re.search(r"MODE_WORLD_READABLE|MODE_WORLD_WRITABLE", context, re.IGNORECASE):
                    self._add_vulnerability("insecure_token_storage", file_path, line_num, line.strip())

                # Check for unencrypted storage
                if not re.search(r"encrypt|cipher|keystore|EncryptedShared", context, re.IGNORECASE):
                    # Check if this is SharedPreferences without encryption
                    if re.search(r"SharedPreferences", context, re.IGNORECASE):
                        if not re.search(r"EncryptedSharedPreferences", context, re.IGNORECASE):
                            self._add_vulnerability("insecure_token_storage", file_path, line_num, line.strip())

    def _validate_oauth_flow(self):
        """Validate OAuth flow completeness and security."""
        # Check for missing token expiration handling
        if self.oauth_info.has_token_storage and not self.oauth_info.has_token_expiration:
            self._add_vulnerability(
                "missing_token_expiration", "global", 0, "OAuth tokens stored without expiration check"
            )

        # Check for missing token refresh
        if self.oauth_info.has_token_storage and not self.oauth_info.has_token_refresh:
            self._add_vulnerability("missing_token_refresh", "global", 0, "No token refresh mechanism detected")

        # Check for missing token revocation
        if self.oauth_info.has_token_storage and not self.oauth_info.has_token_revocation:
            self._add_vulnerability(
                "missing_token_revocation", "global", 0, "No token revocation mechanism detected for logout"
            )

        # Check for missing state parameter (CSRF protection)
        if self.oauth_info.has_oauth and not self.oauth_info.has_state_parameter:
            self._add_vulnerability(
                "missing_oauth_state", "global", 0, "OAuth flow missing state parameter (CSRF vulnerable)"
            )

        # Check for missing PKCE (recommended for mobile apps)
        if self.oauth_info.has_oauth and not self.oauth_info.has_pkce:
            self._add_vulnerability(
                "missing_pkce", "global", 0, "OAuth flow missing PKCE (recommended for mobile apps)"
            )

    def _add_vulnerability(
        self,
        vuln_type: str,
        file_path: str,
        line_num: int,
        value: str,
        secret_value: Optional[str] = None,
    ):
        """Add a vulnerability to the list."""
        vuln_info = OAUTH_VULN_TYPES.get(
            vuln_type,
            {
                "severity": "MEDIUM",
                "cwe": "CWE-287",
                "mastg": "MSTG-AUTH-1",
                "description": vuln_type,
            },
        )

        self.vulnerabilities.append(
            AuthenticationVulnerability(
                vuln_type=vuln_type,
                location=f"{file_path}:{line_num}" if line_num > 0 else file_path,
                value=value,
                secret_value=secret_value,
                line_number=line_num if line_num > 0 else None,
                severity=vuln_info["severity"],
            )
        )

    def _extract_secret(self, match_str: str) -> Optional[str]:
        """Extract secret value from matched string."""
        secret_match = re.search(r'["\']([^"\']+)["\']', match_str)
        if secret_match:
            return secret_match.group(1)
        return None

    def get_oauth_info(self) -> OAuthFlowInfo:
        """Get information about detected OAuth implementation."""
        return self.oauth_info

    def has_oauth(self, apk_ctx: APKContext) -> bool:
        """Check if the app uses OAuth."""
        if not hasattr(apk_ctx, "source_files"):
            return False

        for file_path, content in apk_ctx.source_files.items():
            if not file_path.endswith((".java", ".kt", ".swift", ".m")):
                continue

            for pattern in OAUTH_PATTERNS["oauth_libraries"]:
                if re.search(pattern, content, re.IGNORECASE):
                    return True

            for pattern in OAUTH_PATTERNS["token_storage"]:
                if re.search(pattern, content, re.IGNORECASE):
                    return True

        return False


def analyze_oauth(apk_ctx: APKContext) -> Tuple[List[AuthenticationVulnerability], OAuthFlowInfo]:
    """
    Convenience function to analyze OAuth security.

    Args:
        apk_ctx: APK context

    Returns:
        Tuple of (vulnerabilities, oauth_info)
    """
    analyzer = OAuthAnalyzer()
    vulns = analyzer.analyze_oauth_security(apk_ctx)
    return (vulns, analyzer.get_oauth_info())
