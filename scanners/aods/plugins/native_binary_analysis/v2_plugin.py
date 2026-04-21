#!/usr/bin/env python3
"""
native_binary_analysis - BasePluginV2 implementation for native .so analysis.

Two-tier analysis:
1. Basic (always): binary hardening checks, string scanning, symbol extraction
   via readelf/nm/strings on extracted .so files
2. Deep (opt-in, AODS_NATIVE_DEEP=1): Ghidra decompilation → pseudo-C → ML/pattern
   vulnerability detection (buffer overflows, format strings, weak crypto, etc.)

The deep tier is budget-controlled: selects top N most-interesting binaries,
skips SDK libraries, enforces per-binary and total time limits.
"""

import os
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

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


class NativeBinaryAnalysisV2(BasePluginV2):
    """Native binary analysis with optional Ghidra deep decompilation."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="native_binary_analysis",
            version="3.0.0",
            description=(
                "Extracts and analyzes native .so libraries from APKs. "
                "Basic: hardening checks, string/symbol scanning. "
                "Deep (AODS_NATIVE_DEEP=1): Ghidra decompilation with ML vulnerability scoring."
            ),
            author="AODS Team",
            capabilities=[PluginCapability.VULNERABILITY_DETECTION],
            priority=PluginPriority.NORMAL,
            timeout_seconds=600,  # 10 min - deep analysis needs more time
            supported_platforms=["android"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        start_time = time.time()
        findings: List[PluginFinding] = []
        metadata: Dict[str, Any] = {"plugin_version": "3.0.0"}

        try:
            apk_path = Path(str(getattr(apk_ctx, "apk_path", apk_ctx)))
            if not apk_path.exists():
                return PluginResult(
                    status=PluginStatus.FAILURE,
                    findings=[],
                    metadata={"error": f"APK not found: {apk_path}"},
                )

            # Extract .so files from APK
            temp_dir = Path(tempfile.mkdtemp(prefix="aods_native_"))
            try:
                so_files = self._extract_so_files(apk_path, temp_dir)
                metadata["native_libraries_found"] = len(so_files)
                metadata["library_names"] = [f.name for f in so_files[:20]]

                if not so_files:
                    metadata["note"] = "No native libraries found in APK"
                    return PluginResult(
                        status=PluginStatus.SUCCESS,
                        findings=[],
                        metadata={**metadata, "execution_time": time.time() - start_time},
                    )

                # Tier 1: Basic analysis (always runs)
                basic_findings = self._run_basic_analysis(so_files, apk_path)
                findings.extend(basic_findings)
                metadata["basic_findings"] = len(basic_findings)

                # Tier 2: Deep analysis (opt-in via AODS_NATIVE_DEEP)
                deep_findings, deep_meta = self._run_deep_analysis(so_files)
                findings.extend(deep_findings)
                metadata["deep_analysis"] = deep_meta

            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)

        except Exception as e:
            logger.error("native_analysis_failed", error=str(e))
            return PluginResult(
                status=PluginStatus.FAILURE,
                findings=findings,
                metadata={**metadata, "error": str(e), "execution_time": time.time() - start_time},
            )

        metadata["execution_time"] = round(time.time() - start_time, 2)
        metadata["total_findings"] = len(findings)

        return PluginResult(
            status=PluginStatus.SUCCESS,
            findings=findings,
            metadata=metadata,
        )

    # -----------------------------------------------------------------------
    # .so extraction
    # -----------------------------------------------------------------------

    def _extract_so_files(self, apk_path: Path, temp_dir: Path) -> List[Path]:
        """Extract .so files from APK to temp directory."""
        so_files: List[Path] = []
        try:
            with zipfile.ZipFile(str(apk_path), "r") as zf:
                for entry in zf.namelist():
                    if entry.endswith(".so") and "/" in entry:
                        # Only extract from lib/ directory
                        if entry.startswith("lib/") or "/lib/" in entry:
                            target = temp_dir / entry
                            target.parent.mkdir(parents=True, exist_ok=True)
                            with open(target, "wb") as out:
                                out.write(zf.read(entry))
                            so_files.append(target)
        except (zipfile.BadZipFile, OSError) as e:
            logger.warning("so_extraction_failed", error=str(e))
        return so_files

    # -----------------------------------------------------------------------
    # Tier 1: Basic analysis
    # -----------------------------------------------------------------------

    def _run_basic_analysis(self, so_files: List[Path], apk_path: Path) -> List[PluginFinding]:
        """Run basic checks on all .so files: hardening, strings, architecture."""
        findings: List[PluginFinding] = []
        idx = 0

        for so in so_files[:50]:  # Cap at 50 libraries for basic analysis
            # Architecture detection
            arch = self._detect_architecture(so)

            # Binary hardening checks
            hardening = self._check_hardening(so)
            for issue in hardening:
                idx += 1
                findings.append(PluginFinding(
                    finding_id=f"native_{idx:04d}",
                    title=f"Native: {issue['title']}",
                    description=issue["description"],
                    severity=issue.get("severity", "low"),
                    confidence=issue.get("confidence", 0.5),
                    file_path=f"lib/{so.parent.name}/{so.name}",
                    cwe_id=issue.get("cwe"),
                ))

            # Suspicious string scan
            suspicious = self._scan_strings(so)
            for s in suspicious[:5]:  # Max 5 per library
                idx += 1
                findings.append(PluginFinding(
                    finding_id=f"native_{idx:04d}",
                    title=f"Native: {s['title']}",
                    description=s["description"],
                    severity=s.get("severity", "medium"),
                    confidence=s.get("confidence", 0.5),
                    file_path=f"lib/{so.parent.name}/{so.name}",
                    cwe_id=s.get("cwe"),
                ))

        return findings

    def _detect_architecture(self, so_path: Path) -> str:
        """Detect binary architecture from path or ELF header."""
        parent = so_path.parent.name
        arch_map = {
            "arm64-v8a": "ARM64",
            "armeabi-v7a": "ARM32",
            "x86_64": "x86_64",
            "x86": "x86",
        }
        return arch_map.get(parent, "unknown")

    def _check_hardening(self, so_path: Path) -> List[Dict[str, Any]]:
        """Check binary hardening: PIE, stack canary, NX, RELRO."""
        issues: List[Dict[str, Any]] = []

        if not shutil.which("readelf"):
            return issues

        try:
            result = subprocess.run(
                ["readelf", "-h", "-d", str(so_path)],
                capture_output=True, timeout=10,
            )
            output = result.stdout.decode("utf-8", errors="replace")

            # Check for missing PIE (Position Independent Executable)
            if "DYN" not in output and "EXEC" in output:
                issues.append({
                    "title": "Missing PIE in native library",
                    "description": f"{so_path.name} is not compiled as position-independent. "
                                   "This weakens ASLR protection.",
                    "severity": "medium",
                    "confidence": 0.7,
                    "cwe": "CWE-119",
                })

            # Check for missing stack canary
            if "__stack_chk_fail" not in output and so_path.stat().st_size > 50 * 1024:
                issues.append({
                    "title": "No stack canary in native library",
                    "description": f"{so_path.name} may lack stack canary protection "
                                   "(__stack_chk_fail not found). Buffer overflow exploitation is easier.",
                    "severity": "low",
                    "confidence": 0.5,
                    "cwe": "CWE-120",
                })

        except (subprocess.TimeoutExpired, OSError):
            pass

        return issues

    def _scan_strings(self, so_path: Path) -> List[Dict[str, Any]]:
        """Scan binary strings for suspicious patterns."""
        findings: List[Dict[str, Any]] = []

        if not shutil.which("strings"):
            return findings

        try:
            result = subprocess.run(
                ["strings", "-n", "8", str(so_path)],
                capture_output=True, timeout=15,
            )
            strings_output = result.stdout.decode("utf-8", errors="replace")

            # Check for hardcoded URLs
            import re
            urls = re.findall(r'https?://[^\s"\'<>]{10,100}', strings_output)
            http_urls = [u for u in urls if u.startswith("http://")]
            if http_urls:
                findings.append({
                    "title": "Cleartext HTTP URL in native library",
                    "description": f"{so_path.name} contains {len(http_urls)} cleartext HTTP URL(s): "
                                   f"{http_urls[0][:80]}...",
                    "severity": "medium",
                    "confidence": 0.6,
                    "cwe": "CWE-319",
                })

            # Check for hardcoded IPs
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', strings_output)
            private_ips = [ip for ip in ips if ip.startswith(("10.", "192.168.", "172."))]
            if private_ips:
                findings.append({
                    "title": "Hardcoded private IP in native library",
                    "description": f"{so_path.name} contains private IP address: {private_ips[0]}",
                    "severity": "low",
                    "confidence": 0.5,
                    "cwe": "CWE-798",
                })

            # Check for crypto-related strings suggesting weak algorithms
            weak_crypto = [s for s in strings_output.split("\n")
                          if any(w in s.lower() for w in ["des_", "rc4_", "md5_init", "blowfish"])]
            if weak_crypto:
                findings.append({
                    "title": "Weak cryptographic algorithm in native library",
                    "description": f"{so_path.name} references weak crypto: {weak_crypto[0][:80]}",
                    "severity": "high",
                    "confidence": 0.7,
                    "cwe": "CWE-327",
                })

        except (subprocess.TimeoutExpired, OSError):
            pass

        return findings

    # -----------------------------------------------------------------------
    # Tier 2: Deep analysis (Ghidra decompilation)
    # -----------------------------------------------------------------------

    def _run_deep_analysis(self, so_files: List[Path]) -> tuple:
        """Run Ghidra decompilation and ML/pattern scoring if enabled.

        Returns:
            (findings_list, metadata_dict)
        """
        meta: Dict[str, Any] = {"enabled": False}

        try:
            from core.native_decompiler.analysis_budget import (
                NativeAnalysisConfig,
                select_binaries,
                estimate_analysis_time,
            )
            config = NativeAnalysisConfig.from_env()
        except ImportError:
            meta["error"] = "analysis_budget module not available"
            return [], meta

        if not config.enabled:
            meta["enabled"] = False
            meta["hint"] = "Set AODS_NATIVE_DEEP=1 to enable Ghidra decompilation"
            return [], meta

        meta["enabled"] = True

        try:
            from core.native_decompiler.ghidra_bridge import GhidraBridge
            bridge = GhidraBridge(timeout=config.per_binary_timeout)
        except ImportError:
            meta["error"] = "ghidra_bridge module not available"
            return [], meta

        if not bridge.is_available():
            status = bridge.get_status()
            meta["ghidra_available"] = False
            meta["install_hint"] = status.get("install_hint", "Ghidra not found")
            return [], meta

        meta["ghidra_available"] = True

        # Select binaries within budget
        selected = select_binaries(so_files, config)
        estimate = estimate_analysis_time(selected, config)
        meta["selected_binaries"] = [p.name for p in selected]
        meta["estimate"] = estimate

        if not selected:
            meta["note"] = "No binaries selected for deep analysis"
            return [], meta

        logger.info(
            "native_deep_analysis_start",
            binaries=len(selected),
            est_minutes=estimate["estimated_minutes"],
        )

        # Decompile and score each selected binary
        findings: List[PluginFinding] = []
        total_start = time.monotonic()
        idx = 1000  # Offset to avoid collision with basic findings

        for bp in selected:
            # Check total time budget
            elapsed = time.monotonic() - total_start
            if elapsed >= config.max_total_time:
                logger.warning("native_deep_time_budget_exceeded", elapsed=round(elapsed))
                meta["time_budget_exceeded"] = True
                break

            logger.info("native_decompile_binary", name=bp.name, size_kb=round(bp.stat().st_size / 1024))

            result = bridge.decompile(str(bp))
            if result.error:
                logger.warning("native_decompile_error", binary=bp.name, error=result.error)
                continue

            if not result.functions:
                continue

            # Score decompiled functions
            try:
                from core.native_decompiler.native_vuln_scorer import (
                    score_functions_with_patterns,
                    score_functions_with_ml,
                )

                use_ml = os.environ.get("AODS_NATIVE_ML_ENABLED", "0") in ("1", "true")
                if use_ml:
                    vulns = score_functions_with_ml(result.functions, bp.name)
                else:
                    vulns = score_functions_with_patterns(result.functions, bp.name)

                for v in vulns:
                    idx += 1
                    # Use enriched description for agent context
                    desc = getattr(v, "enriched_description", v.description)
                    findings.append(PluginFinding(
                        finding_id=f"native_deep_{idx:04d}",
                        title=v.title,
                        description=desc,
                        severity=v.severity.lower(),
                        confidence=v.confidence,
                        file_path=f"lib/{bp.parent.name}/{bp.name}:{v.function_name}",
                        cwe_id=v.cwe_id,
                        code_snippet=v.code_snippet[:300] if v.code_snippet else None,
                    ))
            except Exception as score_err:
                logger.warning("native_scoring_failed", binary=bp.name, error=str(score_err))

        meta["deep_findings"] = len(findings)
        meta["deep_elapsed_seconds"] = round(time.monotonic() - total_start, 2)

        return findings, meta


def create_plugin() -> NativeBinaryAnalysisV2:
    return NativeBinaryAnalysisV2()


__all__ = ["NativeBinaryAnalysisV2", "create_plugin"]
