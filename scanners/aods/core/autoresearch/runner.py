"""
core.autoresearch.runner - Subprocess-isolated corpus scanning.

Runs AODS scans via subprocess to ensure config changes (ml_thresholds.json)
are picked up fresh. Follows the pattern from core.enterprise.__init__.py.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)

from .metrics import ScanResult, parse_report
from .parameter_space import REPO_ROOT


@dataclass
class ApkEntry:
    """An APK in the test corpus."""

    name: str
    apk_type: str  # "vulnerable" or "production"
    path: str  # Relative to REPO_ROOT


APK_CORPUS: List[ApkEntry] = [
    ApkEntry("DIVA", "vulnerable", "apks/vulnerable_apps/DIVA.apk"),
    ApkEntry("InsecureBankv2", "vulnerable", "apks/vulnerable_apps/InsecureBankv2.apk"),
    ApkEntry("AndroGoat", "vulnerable", "apks/vulnerable_apps/AndroGoat.apk"),
    ApkEntry("InjuredAndroid", "vulnerable", "apks/vulnerable_apps/InjuredAndroid.apk"),
    ApkEntry("PIVAA", "vulnerable", "apks/vulnerable_apps/PIVAA.apk"),
    ApkEntry("UnCrackable-Level1", "vulnerable", "apks/vulnerable_apps/UnCrackable-Level1.apk"),
    ApkEntry("TikTok", "production", "apks/tiktok.apk"),
    ApkEntry("CapCut", "production", "apks/capcut.apk"),
]

FAST_PROXY_NAMES = {"DIVA", "InsecureBankv2", "TikTok"}


def get_corpus(
    subset: Optional[List[str]] = None,
    fast_proxy: bool = False,
) -> List[ApkEntry]:
    """Filter the APK corpus by subset names or fast proxy mode."""
    if fast_proxy:
        return [a for a in APK_CORPUS if a.name in FAST_PROXY_NAMES]
    if subset:
        name_set = set(subset)
        return [a for a in APK_CORPUS if a.name in name_set]
    return list(APK_CORPUS)


def _run_single_scan(
    apk: ApkEntry,
    profile: str,
    output_dir: Path,
    timeout: int,
    env_overrides: Optional[Dict[str, str]] = None,
) -> ScanResult:
    """Run a single APK scan via subprocess."""
    apk_path = REPO_ROOT / apk.path
    scan_dir = output_dir / apk.name
    scan_dir.mkdir(parents=True, exist_ok=True)
    report_file = scan_dir / f"{apk.name}_report.json"

    if not apk_path.exists():
        logger.warning("apk_not_found", apk=apk.name, path=str(apk_path))
        return ScanResult(
            apk_name=apk.name,
            apk_type=apk.apk_type,
            success=False,
        )

    cmd = [
        sys.executable,
        "dyna.py",
        "--apk", str(apk_path),
        "--static-only",
        "--formats", "json",
        "--profile", profile,
        "--output", str(report_file),
    ]

    env = os.environ.copy()
    # Skip the MITRE integrity check in scan subprocesses for performance  - 
    # it takes ~60s scanning 848 files. The false-positive on malware_detection
    # is now fixed (allowlisted), but the 60s overhead is still undesirable.
    env["AODS_SKIP_MITRE_CHECK"] = "1"
    if env_overrides:
        env.update(env_overrides)

    start_time = time.monotonic()

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(REPO_ROOT),
            env=env,
        )
        elapsed = time.monotonic() - start_time

        if proc.returncode != 0:
            logger.warning(
                "scan_failed",
                apk=apk.name,
                exit_code=proc.returncode,
                stderr=proc.stderr[:300] if proc.stderr else "",
            )
            return ScanResult(
                apk_name=apk.name,
                apk_type=apk.apk_type,
                scan_time_seconds=elapsed,
                success=False,
            )

        # Use the known report path, fall back to glob if dyna.py
        # wrote to an auto-generated name instead
        if report_file.exists():
            json_reports = [report_file]
        else:
            json_reports = list(scan_dir.glob("*.json"))
            if not json_reports:
                json_reports = list(scan_dir.rglob("*.json"))

        if json_reports:
            result = parse_report(json_reports[0], apk.name, apk.apk_type)
            result.scan_time_seconds = elapsed
            return result

        logger.warning("no_report_found", apk=apk.name, dir=str(scan_dir))
        return ScanResult(
            apk_name=apk.name,
            apk_type=apk.apk_type,
            scan_time_seconds=elapsed,
            success=False,
        )

    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start_time
        logger.warning("scan_timeout", apk=apk.name, timeout=timeout)
        return ScanResult(
            apk_name=apk.name,
            apk_type=apk.apk_type,
            scan_time_seconds=elapsed,
            success=False,
        )
    except Exception as e:
        elapsed = time.monotonic() - start_time
        logger.error("scan_exception", apk=apk.name, error=str(e))
        return ScanResult(
            apk_name=apk.name,
            apk_type=apk.apk_type,
            scan_time_seconds=elapsed,
            success=False,
        )


def run_corpus(
    apks: List[ApkEntry],
    profile: str,
    output_dir: Path,
    timeout: int = 600,
    env_overrides: Optional[Dict[str, str]] = None,
    max_workers: int = 2,
) -> List[ScanResult]:
    """Run scans for all APKs in the corpus.

    Args:
        apks: List of APK entries to scan.
        profile: Scan profile to use (e.g. "standard").
        output_dir: Directory for scan output.
        timeout: Per-scan timeout in seconds.
        env_overrides: Extra env vars for scan subprocesses.
        max_workers: Max concurrent scans.

    Returns:
        List of ScanResult for each APK.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    results: List[ScanResult] = []

    logger.info("corpus_scan_start", apk_count=len(apks), profile=profile, workers=max_workers)

    if max_workers > 1 and len(apks) > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    _run_single_scan, apk, profile, output_dir, timeout, env_overrides
                ): apk.name
                for apk in apks
            }
            for future in as_completed(futures):
                apk_name = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    logger.info(
                        "scan_complete",
                        apk=apk_name,
                        findings=result.total_findings,
                        time=round(result.scan_time_seconds, 1),
                        success=result.success,
                    )
                except Exception as e:
                    logger.error("scan_future_error", apk=apk_name, error=str(e))
                    results.append(ScanResult(
                        apk_name=apk_name,
                        apk_type="unknown",
                        success=False,
                    ))
    else:
        for apk in apks:
            result = _run_single_scan(apk, profile, output_dir, timeout, env_overrides)
            results.append(result)
            logger.info(
                "scan_complete",
                apk=apk.name,
                findings=result.total_findings,
                time=round(result.scan_time_seconds, 1),
                success=result.success,
            )

    successful = sum(1 for r in results if r.success)
    logger.info("corpus_scan_done", total=len(results), successful=successful)
    return results
