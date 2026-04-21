#!/usr/bin/env python3
"""
attack_surface_analysis - Intent & PendingIntent Security Analyzer
===================================================================

Detects mutable PendingIntents, implicit intents without explicit targets,
intent redirection vulnerabilities, and dynamic broadcast receiver risks.

MASVS-PLATFORM-1: Platform Interaction Security
CWE-927: Use of Implicit Intent for Sensitive Communication
CWE-926: Improper Export of Android Application Components
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

# --- PendingIntent patterns ---
_PENDING_MUTABLE = re.compile(
    r'PendingIntent\.get(?:Activity|Service|Broadcast|ForegroundService)\s*\([^)]*FLAG_MUTABLE',
)
_PENDING_IMPLICIT = re.compile(
    r'PendingIntent\.get(?:Activity|Service|Broadcast)\s*\([^)]*new\s+Intent\s*\(\s*\)',
)

# --- Implicit intent patterns ---
_IMPLICIT_INTENT = re.compile(
    r'new\s+Intent\s*\(\s*"[^"]+"\s*\)',  # Action-only intent: new Intent("com.example.ACTION")
)
_INTENT_REDIRECT = re.compile(
    r'(?:startActivity|startService|sendBroadcast)\s*\(\s*getIntent\s*\(\s*\)\.get',
    re.IGNORECASE,
)

# --- Dynamic receiver patterns ---
_DYNAMIC_RECEIVER = re.compile(
    r'registerReceiver\s*\(\s*\w+\s*,\s*new\s+IntentFilter',
)
_EXPORTED_RECEIVER = re.compile(
    r'registerReceiver\s*\([^)]*RECEIVER_EXPORTED',
)

# --- Sticky broadcast ---
_STICKY_BROADCAST = re.compile(
    r'sendStickyBroadcast\s*\(',
)

# --- Deep link without validation ---
_DEEP_LINK_NO_VALIDATE = re.compile(
    r'getIntent\s*\(\s*\)\s*\.getData\s*\(\s*\)',
)


class AttackSurfaceAnalysisV2(BasePluginV2):
    """Analyzes intent and PendingIntent attack surface."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="attack_surface_analysis",
            version="3.0.0",
            description="Intent & PendingIntent security analysis (CWE-927/926)",
            author="AODS Team",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            supported_platforms=["android"],
            tags=["intents", "masvs-platform-1", "cwe-927"],
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

                findings.extend(self._check_pending_intents(content, rel))
                findings.extend(self._check_implicit_intents(content, rel))
                findings.extend(self._check_receivers(content, rel))

            return PluginResult(
                status=PluginStatus.SUCCESS, findings=findings,
                metadata={"execution_time": time.time() - start_time, "files_scanned": files_scanned},
            )
        except Exception as e:
            logger.error("attack_surface_analysis failed: %s", e)
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

    def _check_pending_intents(self, content, rel):
        findings = []
        for m in _PENDING_MUTABLE.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"asa_pending_mutable_{self._ln(content, m.start())}",
                title="Mutable PendingIntent - intent hijacking risk",
                description=(
                    "FLAG_MUTABLE PendingIntent can be modified by a malicious app "
                    f"to redirect the intent to an attacker-controlled component. Code: {self._snip(content, m)}"
                ),
                severity="high", confidence=0.85, cwe_id="CWE-927",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use FLAG_IMMUTABLE unless mutability is explicitly required",
            ))
        for m in _PENDING_IMPLICIT.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"asa_pending_implicit_{self._ln(content, m.start())}",
                title="PendingIntent with implicit Intent - delivery uncertainty",
                description=(
                    "PendingIntent wraps an implicit Intent (no explicit target component). "
                    f"Code: {self._snip(content, m)}"
                ),
                severity="medium", confidence=0.70, cwe_id="CWE-927",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Set an explicit component on the Intent before wrapping in PendingIntent",
            ))
        return findings

    def _check_implicit_intents(self, content, rel):
        findings = []
        for m in _INTENT_REDIRECT.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"asa_intent_redirect_{self._ln(content, m.start())}",
                title="Intent Redirection - attacker can control destination",
                description=(
                    "Incoming intent data is forwarded via startActivity/startService without validation. "
                    f"Code: {self._snip(content, m)}"
                ),
                severity="high", confidence=0.80, cwe_id="CWE-927",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Validate intent extras before forwarding; use explicit component targets",
            ))
        for m in _STICKY_BROADCAST.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"asa_sticky_{self._ln(content, m.start())}",
                title="Sticky Broadcast - data persists and accessible to any app",
                description=f"sendStickyBroadcast is deprecated and insecure. Code: {self._snip(content, m)}",
                severity="medium", confidence=0.85, cwe_id="CWE-927",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use LocalBroadcastManager or explicit broadcasts instead",
            ))
        return findings

    def _check_receivers(self, content, rel):
        findings = []
        for m in _EXPORTED_RECEIVER.finditer(content):
            findings.append(PluginFinding(
                finding_id=f"asa_exported_recv_{self._ln(content, m.start())}",
                title="Exported Dynamic Receiver - accessible to all apps",
                description=(
                    "Dynamic broadcast receiver registered with RECEIVER_EXPORTED flag. "
                    f"Code: {self._snip(content, m)}"
                ),
                severity="medium", confidence=0.80, cwe_id="CWE-926",
                file_path=rel, line_number=self._ln(content, m.start()),
                remediation="Use RECEIVER_NOT_EXPORTED unless cross-app communication is required",
            ))
        return findings


def create_plugin():
    return AttackSurfaceAnalysisV2()


__all__ = ["AttackSurfaceAnalysisV2", "create_plugin"]
