"""
Authentication Bypass Analyzer for AODS
Handles detection and analysis of authentication bypass vulnerabilities.
"""

import logging
import re
from typing import List, Optional, Dict, Any

from core.apk_ctx import APKContext
from .data_structures import AuthenticationVulnerability, AuthenticationPatternCategory, AUTHENTICATION_PATTERNS

logger = logging.getLogger(__name__)


class BypassAnalyzer:
    """Analyzer for authentication bypass vulnerabilities."""

    def __init__(self):
        """Initialize bypass analyzer with patterns."""
        self.vulnerabilities = []
        self.bypass_patterns = AUTHENTICATION_PATTERNS[AuthenticationPatternCategory.AUTHENTICATION_BYPASS.value]
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
                tracer.start_check(mstg_id, meta=meta or {"analyzer": "bypass_analyzer"})
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

    def analyze_authentication_bypass(self, apk_ctx: APKContext) -> List[AuthenticationVulnerability]:
        """Analyze potential authentication bypass vulnerabilities."""
        logger.info("Analyzing authentication bypass vulnerabilities")

        self.vulnerabilities = []

        # Emit tracer event for bypass check (MSTG-AUTH-1 - verify app requires authentication)
        self._emit_check_start("MSTG-AUTH-1", {"check": "authentication_bypass"})

        try:
            if hasattr(apk_ctx, "source_files"):
                for file_path, content in apk_ctx.source_files.items():
                    if file_path.endswith((".java", ".kt")):
                        self._check_authentication_bypass_patterns(file_path, content)

            # Determine check status based on severity of findings
            has_critical = any(v.severity == "CRITICAL" for v in self.vulnerabilities)
            has_high = any(v.severity == "HIGH" for v in self.vulnerabilities)
            status = "FAIL" if (has_critical or has_high) else ("WARN" if self.vulnerabilities else "PASS")
        except Exception as e:
            logger.error(f"Authentication bypass analysis failed: {e}")
            status = "SKIP"

        self._emit_check_end("MSTG-AUTH-1", status)

        return self.vulnerabilities

    def _check_authentication_bypass_patterns(self, file_path: str, content: str):
        """Check for authentication bypass patterns."""
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            # Check basic bypass patterns
            for pattern in self.bypass_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.vulnerabilities.append(
                        AuthenticationVulnerability(
                            vuln_type="authentication_bypass",
                            location=f"{file_path}:{line_num}",
                            value=line.strip(),
                            line_number=line_num,
                            severity="CRITICAL",
                        )
                    )

            # Check for debug-based bypasses
            if re.search(r"if.*debug.*return.*true", line, re.IGNORECASE):
                self.vulnerabilities.append(
                    AuthenticationVulnerability(
                        vuln_type="debug_authentication_bypass",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="CRITICAL",
                    )
                )

            # Check for hardcoded bypass flags
            if re.search(r"(?:bypass|skip|ignore).*auth.*=.*true", line, re.IGNORECASE):
                self.vulnerabilities.append(
                    AuthenticationVulnerability(
                        vuln_type="hardcoded_bypass_flag",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="CRITICAL",
                    )
                )

            # Check for empty authentication methods
            if re.search(r"(?:authenticate|login|verify).*\(\).*\{.*return.*true.*\}", line, re.IGNORECASE):
                self.vulnerabilities.append(
                    AuthenticationVulnerability(
                        vuln_type="empty_authentication_method",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="CRITICAL",
                    )
                )

            # Check for test mode bypasses
            if re.search(r"test.*mode.*auth", line, re.IGNORECASE):
                context_lines = lines[max(0, line_num - 2) : min(len(lines), line_num + 2)]
                context = "\n".join(context_lines)

                if re.search(r"return.*true|bypass|skip", context, re.IGNORECASE):
                    self.vulnerabilities.append(
                        AuthenticationVulnerability(
                            vuln_type="test_mode_bypass",
                            location=f"{file_path}:{line_num}",
                            value=line.strip(),
                            line_number=line_num,
                            severity="HIGH",
                        )
                    )

            # Check for weak authentication logic
            if re.search(r"password.*==.*\"\"", line, re.IGNORECASE):
                self.vulnerabilities.append(
                    AuthenticationVulnerability(
                        vuln_type="empty_password_bypass",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="CRITICAL",
                    )
                )

            # Check for commented out authentication
            if re.search(r"//.*(?:authenticate|login|verify|check.*auth)", line, re.IGNORECASE):
                self.vulnerabilities.append(
                    AuthenticationVulnerability(
                        vuln_type="commented_authentication",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="HIGH",
                    )
                )

            # Check for always-true authentication
            if re.search(r"(?:if|return).*\(.*true.*\).*auth", line, re.IGNORECASE):
                self.vulnerabilities.append(
                    AuthenticationVulnerability(
                        vuln_type="always_true_authentication",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="CRITICAL",
                    )
                )

            # Check for authentication state manipulation
            if re.search(r"(?:is|set).*(?:authenticated|logged.*in).*=.*true", line, re.IGNORECASE):
                context_lines = lines[max(0, line_num - 3) : min(len(lines), line_num + 1)]
                context = "\n".join(context_lines)

                # Check if there's actual authentication logic before this
                if not re.search(r"password|credential|biometric|pin", context, re.IGNORECASE):
                    self.vulnerabilities.append(
                        AuthenticationVulnerability(
                            vuln_type="direct_auth_state_manipulation",
                            location=f"{file_path}:{line_num}",
                            value=line.strip(),
                            line_number=line_num,
                            severity="HIGH",
                        )
                    )

            # Check for hardcoded admin credentials
            if re.search(r"(?:admin|root|master).*(?:password|pin)", line, re.IGNORECASE):
                if re.search(r"[\"'][^\"']{4,}[\"']", line):  # Has a hardcoded value
                    self.vulnerabilities.append(
                        AuthenticationVulnerability(
                            vuln_type="hardcoded_admin_credentials",
                            location=f"{file_path}:{line_num}",
                            value=line.strip(),
                            line_number=line_num,
                            severity="CRITICAL",
                        )
                    )

    def has_authentication_bypass(self, apk_ctx: APKContext) -> bool:
        """Check if the app has authentication bypass vulnerabilities."""
        vulnerabilities = self.analyze_authentication_bypass(apk_ctx)
        return len(vulnerabilities) > 0

    def get_bypass_types_found(self, apk_ctx: APKContext) -> List[str]:
        """Get list of bypass vulnerability types found."""
        vulnerabilities = self.analyze_authentication_bypass(apk_ctx)
        bypass_types = []

        for vuln in vulnerabilities:
            if vuln.vuln_type not in bypass_types:
                bypass_types.append(vuln.vuln_type)

        return bypass_types

    def get_critical_bypasses(self, apk_ctx: APKContext) -> List[AuthenticationVulnerability]:
        """Get only critical authentication bypass vulnerabilities."""
        vulnerabilities = self.analyze_authentication_bypass(apk_ctx)
        return [vuln for vuln in vulnerabilities if vuln.severity == "CRITICAL"]

    def analyze_debug_flags(self, apk_ctx: APKContext) -> List[dict]:
        """Analyze debug-related authentication bypasses specifically."""
        debug_issues = []

        if not hasattr(apk_ctx, "source_files"):
            return debug_issues

        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith((".java", ".kt")):
                lines = content.split("\n")
                for line_num, line in enumerate(lines, 1):
                    if re.search(r"BuildConfig\.DEBUG", line, re.IGNORECASE):
                        context_lines = lines[max(0, line_num - 2) : min(len(lines), line_num + 3)]
                        context = "\n".join(context_lines)

                        if re.search(r"auth|login|credential", context, re.IGNORECASE):
                            debug_issues.append(
                                {
                                    "location": f"{file_path}:{line_num}",
                                    "line": line.strip(),
                                    "context": context,
                                    "risk": "Debug flag used in authentication logic",
                                }
                            )

        return debug_issues
