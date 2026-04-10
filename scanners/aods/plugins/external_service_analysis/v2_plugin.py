#!/usr/bin/env python3
"""
external_service_analysis - External Service Security
======================================================

Detects insecure integration with external services: unvalidated Firebase
configs, unprotected API endpoints, missing certificate validation, and
third-party SDK data exposure.

MASVS-NETWORK-1: Network Communication Security
CWE-295: Improper Certificate Validation
CWE-319: Cleartext Transmission of Sensitive Information
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

# NOTE: TrustAllCerts and HostnameVerifier checks REMOVED - now covered by
# advanced_ssl_tls_analyzer (structured bridge, Phase 2). Keeping these here
# would produce duplicate CWE-295 findings.

# --- HTTP logging interceptor at body level ---
_HTTP_LOGGING = re.compile(
    r'HttpLoggingInterceptor[^;]*Level\.BODY',
)

# --- Firebase open database rules ---
_FIREBASE_URL = re.compile(
    r'"https://[^"]*\.firebaseio\.com[^"]*"',
)

# --- Retrofit/OkHttp base URL with HTTP ---
_RETROFIT_HTTP = re.compile(
    r'(?:baseUrl|BASE_URL|base_url)\s*(?:=|\()\s*"http://[^"]*"',
    re.IGNORECASE,
)

# --- WebSocket without TLS ---
_WS_NO_TLS = re.compile(
    r'"ws://[^"]*"',  # ws:// instead of wss://
)

# --- Analytics with PII ---
_ANALYTICS_PII = re.compile(
    r'(?:logEvent|setUserProperty|track|identify)\s*\([^)]*(?:email|phone|name|address|ssn|password)',
    re.IGNORECASE,
)


class ExternalServiceAnalysisV2(BasePluginV2):
    """Detects insecure external service integration patterns."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="external_service_analysis",
            version="3.0.0",
            description="External service security: cert validation, Firebase, HTTP logging (CWE-295/319)",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["network", "masvs-network-1", "cwe-295"],
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

                # NOTE: cert validation checks moved to advanced_ssl_tls_analyzer
                findings.extend(self._check_network_security(content, rel))
                findings.extend(self._check_analytics_pii(content, rel))

            return PluginResult(
                status=PluginStatus.SUCCESS, findings=findings,
                metadata={"execution_time": time.time() - start_time, "files_scanned": files_scanned},
            )
        except Exception as e:
            logger.error("external_service_analysis failed: %s", e)
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

    def _check_network_security(self, content, rel):
        findings = []
        for m in _HTTP_LOGGING.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"esa_http_logging_{self._ln(content, m.start())}",
                title="HTTP Body Logging: credentials may appear in logs",
                description=(
                    "HttpLoggingInterceptor at BODY level logs full request/response bodies "
                    f"including auth tokens and credentials. Code: {self._snip(content, m)}"
                ),
                severity="high", confidence=0.80, cwe_id="CWE-532",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use Level.HEADERS or Level.BASIC in production builds",
            ))
        for m in _RETROFIT_HTTP.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"esa_retrofit_http_{self._ln(content, m.start())}",
                title="API Base URL uses HTTP instead of HTTPS",
                description=f"Retrofit/OkHttp base URL uses cleartext HTTP. Code: {self._snip(content, m)}",
                severity="high", confidence=0.85, cwe_id="CWE-319",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use HTTPS for all API communication",
            ))
        for m in _WS_NO_TLS.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"esa_ws_notls_{self._ln(content, m.start())}",
                title="WebSocket without TLS (ws:// instead of wss://)",
                description=f"Unencrypted WebSocket connection. Code: {self._snip(content, m)}",
                severity="medium", confidence=0.80, cwe_id="CWE-319",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use wss:// for secure WebSocket connections",
            ))
        return findings

    def _check_analytics_pii(self, content, rel):
        findings = []
        for m in _ANALYTICS_PII.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"esa_analytics_pii_{self._ln(content, m.start())}",
                title="PII sent to analytics/tracking service",
                description=(
                    "Personally identifiable information passed to analytics SDK. "
                    f"Code: {self._snip(content, m)}"
                ),
                severity="medium", confidence=0.65, cwe_id="CWE-359",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Hash or anonymize PII before sending to analytics",
            ))
        return findings


def create_plugin():
    return ExternalServiceAnalysisV2()


__all__ = ["ExternalServiceAnalysisV2", "create_plugin"]
