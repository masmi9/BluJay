#!/usr/bin/env python3
"""
unused_security_function_analyzer - BasePluginV2 Implementation (MASVS-AUTH/CODE)
==================================================================================

Detects security-critical methods that are declared but never called.
Common pattern: developers implement signature verification, token validation,
or certificate checking methods but forget to wire them into the code path.

Uses lightweight call-graph analysis:
1. Scan all source files for security-critical method declarations
2. Search entire codebase for call sites referencing those methods
3. Flag methods with zero external callers
"""

import re
import time
from pathlib import Path
from typing import Dict, List, Tuple

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

# --- Security-critical method name patterns ---
# These are method names that SHOULD be called if they exist.
# If declared but never invoked, it's a potential vulnerability.

_SECURITY_METHOD_PATTERNS = [
    # Purchase / payment signature verification
    re.compile(
        r'(?:public|protected|static)\s+\S+\s+(verify(?:Purchase|Signature|Payment|Receipt|Token|License))\s*\('
    ),
    # Certificate / TLS validation
    re.compile(r'(?:public|protected|static)\s+\S+\s+(validate(?:Certificate|Ssl|Tls|ServerCert|Chain))\s*\('),
    re.compile(
        r'(?:public|protected|static)\s+\S+\s+'
        r'(check(?:Certificate|ServerTrusted|ClientTrusted|ServerIdentity))\s*\('
    ),
    # Authentication / authorization checks
    re.compile(r'(?:public|protected|static)\s+\S+\s+(verify(?:Auth|Credentials|Identity|Session|Nonce))\s*\('),
    re.compile(r'(?:public|protected|static)\s+\S+\s+(authenticate(?:User|Request|Token|Session)?)\s*\('),
    # Integrity checks
    re.compile(r'(?:public|protected|static)\s+\S+\s+(verify(?:Integrity|Checksum|Hash|Hmac|Mac|Digest))\s*\('),
    re.compile(r'(?:public|protected|static)\s+\S+\s+(check(?:Integrity|Tamper|Root|Debugger))\s*\('),
    # Input validation
    re.compile(r'(?:public|protected|static)\s+\S+\s+(sanitize(?:Input|Sql|Html|Url|Path))\s*\('),
    re.compile(r'(?:public|protected|static)\s+\S+\s+(validate(?:Input|Request|Parameters|Token))\s*\('),
    # Encryption key validation
    re.compile(r'(?:public|protected|static)\s+\S+\s+(verify(?:Key|Encryption|Decryption|Signing))\s*\('),
]

# Method names that are typically called by the framework (not directly by app code)
# These should NOT be flagged as unused even if no direct callers are found
_FRAMEWORK_CALLBACKS = {
    "checkServerTrusted", "checkClientTrusted",  # X509TrustManager interface
    "verify",  # HostnameVerifier interface
    "onReceivedSslError",  # WebViewClient
    "authenticate",  # Authenticator
}


class UnusedSecurityFunctionAnalyzerV2(BasePluginV2):
    """Detects security-critical methods that are declared but never called."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="unused_security_function_analyzer",
            version="1.0.0",
            description="Detects security-critical methods declared but never called (dead security code)",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.LOW,  # Runs after other plugins; needs full source scan
            timeout_seconds=180,
            supported_platforms=["android"],
            tags=["dead-code", "masvs-auth", "masvs-code"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        files_scanned = 0

        try:
            source_files = self._get_source_files(apk_ctx)
            if not source_files:
                return PluginResult(
                    status=PluginStatus.SUCCESS,
                    findings=[],
                    metadata={"execution_time": time.time() - start_time, "files_scanned": 0},
                )

            # Phase 1: Collect all security-critical method declarations
            # Key: method_name, Value: (file_path, line_number, snippet, declaring_class)
            security_methods: Dict[str, List[Tuple[str, int, str, str]]] = {}
            file_contents: Dict[str, str] = {}

            for src_path in source_files:
                try:
                    content = Path(src_path).read_text(errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                files_scanned += 1
                rel_path = self._relative_path(src_path, apk_ctx)

                if self._is_library_code(rel_path):
                    continue

                file_contents[rel_path] = content
                declaring_class = self._extract_class_name(content)

                for pattern in _SECURITY_METHOD_PATTERNS:
                    for m in pattern.finditer(content):
                        method_name = m.group(1)
                        # Skip framework callbacks
                        if method_name in _FRAMEWORK_CALLBACKS:
                            continue
                        if method_name not in security_methods:
                            security_methods[method_name] = []
                        security_methods[method_name].append((
                            rel_path,
                            self._line_number(content, m.start()),
                            self._snippet(content, m.start(), m.end()),
                            declaring_class,
                        ))

            if not security_methods:
                return PluginResult(
                    status=PluginStatus.SUCCESS,
                    findings=[],
                    metadata={
                        "execution_time": time.time() - start_time,
                        "files_scanned": files_scanned,
                        "security_methods_found": 0,
                    },
                )

            # Phase 2: Search for call sites
            # Pre-strip comments from all file contents for accurate call-site detection
            stripped_contents: Dict[str, str] = {}
            for rel_path, content in file_contents.items():
                stripped_contents[rel_path] = self._strip_comments(content)

            for method_name, declarations in security_methods.items():
                # Simple call-site pattern: methodName(
                call_pattern = re.compile(re.escape(method_name) + r'\s*\(')

                total_calls = 0
                for rel_path, stripped in stripped_contents.items():
                    for call_m in call_pattern.finditer(stripped):
                        # Exclude the declaration itself (same line in original content)
                        call_line = stripped[:call_m.start()].count("\n") + 1
                        is_declaration = False
                        for decl_path, decl_line, _, _ in declarations:
                            if decl_path == rel_path and decl_line == call_line:
                                is_declaration = True
                                break
                        if not is_declaration:
                            total_calls += 1

                if total_calls == 0:
                    # This security method is declared but never called!
                    for decl_path, decl_line, decl_snippet, decl_class in declarations:
                        findings.append(self.create_finding(
                            finding_id=f"unused_security_{method_name}_{len(findings):03d}",
                            title=f"Unused Security Function: {method_name}()",
                            description=(
                                f"Security-critical method {decl_class}.{method_name}() is declared "
                                f"but never called in the codebase. This may indicate that a security "
                                f"check (signature verification, authentication, integrity validation) "
                                f"was implemented but not wired into the execution path, leaving the "
                                f"application unprotected."
                            ),
                            severity="high",
                            confidence=0.75,
                            file_path=decl_path,
                            line_number=decl_line,
                            code_snippet=decl_snippet,
                            cwe_id="CWE-561",
                            masvs_control="MASVS-AUTH-1",
                            remediation=(
                                f"Call {method_name}() at the appropriate point in the security flow. "
                                f"If the method is intentionally unused, remove it to reduce dead code."
                            ),
                        ))

            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    "execution_time": time.time() - start_time,
                    "plugin_version": "1.0.0",
                    "files_scanned": files_scanned,
                    "security_methods_found": len(security_methods),
                    "unused_methods": len(findings),
                },
            )

        except Exception as e:
            logger.error(f"unused_security_function_analyzer failed: {e}")
            return PluginResult(
                status=PluginStatus.FAILURE,
                findings=findings,
                metadata={"error": str(e), "execution_time": time.time() - start_time},
            )

    # ------------------------------------------------------------------ helpers

    def _get_source_files(self, apk_ctx) -> List[str]:
        src = getattr(apk_ctx, "source_files", None)
        if src:
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

    _COMMENT_RE = re.compile(r'//[^\n]*|/\*.*?\*/', re.DOTALL)

    def _strip_comments(self, content: str) -> str:
        """Remove Java/Kotlin comments while preserving line numbers."""
        def _replace(m: re.Match) -> str:
            # Replace with same number of newlines to preserve line count
            return "\n" * m.group(0).count("\n")
        return self._COMMENT_RE.sub(_replace, content)

    def _extract_class_name(self, content: str) -> str:
        """Extract the top-level class name from source file."""
        m = re.search(r'(?:public\s+)?class\s+(\w+)', content)
        if m:
            return m.group(1)
        return "Unknown"


# Plugin factory
def create_plugin() -> UnusedSecurityFunctionAnalyzerV2:
    return UnusedSecurityFunctionAnalyzerV2()


__all__ = ["UnusedSecurityFunctionAnalyzerV2", "create_plugin"]
