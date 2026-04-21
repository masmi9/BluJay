"""
Wrapper around AODS (dyna.py).
Runs dyna.py as a subprocess, streams progress, parses JSON output.
"""
import asyncio
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import structlog

logger = structlog.get_logger()

# Progress queues keyed by scan_id
_progress_queues: dict[int, asyncio.Queue] = {}


def get_progress_queue(scan_id: int) -> asyncio.Queue | None:
    return _progress_queues.get(scan_id)


def _find_dyna_py() -> Path | None:
    """Locate dyna.py from config, then search common sibling paths."""
    from config import settings
    configured = getattr(settings, "aods_path", None)
    if configured:
        p = Path(configured)
        if p.exists():
            return p

    candidates = [
        Path(__file__).parent.parent.parent.parent / "AODS" / "dyna.py",
        Path.home() / "repos" / "AODS" / "dyna.py",
        Path(r"C:/Users/MalikSmith/repos/AODS/dyna.py"),
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _find_ios_scan_py() -> Path | None:
    """Locate ios_scan.py from config, then search common sibling paths."""
    from config import settings
    configured = getattr(settings, "iods_path", None)
    if configured:
        p = Path(configured)
        if p.exists():
            return p

    candidates = [
        Path(__file__).parent.parent.parent.parent / "IODS" / "ios_scan.py",
        Path.home() / "repos" / "IODS" / "ios_scan.py",
        Path(r"C:/Users/MalikSmith/repos/IODS/ios_scan.py"),
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _ensure_apktool_wrapper(dyna_dir: Path) -> None:
    """
    dyna.py calls `apktool` as a plain subprocess command.  On Windows this
    requires a .bat wrapper because apktool is distributed as a .jar.
    Create apktool.bat in the AODS directory if it is absent or stale.
    """
    from config import settings
    bat = dyna_dir / "apktool.bat"
    jar = Path(str(settings.apktool_jar))
    if not jar.exists():
        logger.warning("apktool.jar not found — skipping wrapper creation", jar=str(jar))
        return
    expected = f'@echo off\njava -jar "{jar}" %*\n'
    if bat.exists() and bat.read_text() == expected:
        return
    bat.write_text(expected)
    logger.info("Created apktool.bat wrapper for AODS", path=str(bat))


def _find_python_for_aods() -> str:
    """
    Return the Python executable to use for running dyna.py.
    Prefers the AODS venv python so its dependencies are available.
    Falls back to the current interpreter.
    """
    from config import settings
    venv_python = getattr(settings, "aods_venv_python", None)
    if venv_python:
        p = Path(venv_python)
        if p.exists():
            return str(p)
    return sys.executable


def _find_python_for_iods() -> str:
    """
    Return the Python executable to use for running ios_scan.py.
    Prefers the IODS venv python so its dependencies are available.
    Falls back to the current interpreter.
    """
    from config import settings
    venv_python = getattr(settings, "iods_venv_python", None)
    if venv_python:
        p = Path(venv_python)
        if p.exists():
            return str(p)
    return sys.executable


def _parse_aods_output(output_dir: Path, package_name: str) -> dict:
    """
    Parse AODS JSON report from the output directory.
    Returns a normalized dict with 'findings', 'summary', 'masvs'.
    """
    # AODS writes files like: aods_parallel_<pkg>_<hash>.json, <pkg>_results.json, results.json
    candidates = (
        list(output_dir.glob("*.json"))
        + list(output_dir.glob("**/*.json"))
    )
    # Filter out tiny stub files (< 10 bytes) and prefer largest file (most complete)
    candidates = [p for p in candidates if p.stat().st_size > 10]
    if not candidates:
        return {"findings": [], "summary": {}, "raw": {}}

    # Prefer largest file (most complete report); fall back to most recently modified
    report_file = max(candidates, key=lambda p: p.stat().st_size)
    try:
        raw = json.loads(report_file.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        logger.warning("Failed to parse AODS JSON", error=str(e))
        return {"findings": [], "summary": {}, "raw": {}}

    # Normalize — AODS output structure varies by version
    findings = (
        raw.get("vulnerabilities")
        or raw.get("findings")
        or raw.get("results", {}).get("vulnerabilities", [])
        or []
    )

    summary = (
        raw.get("executive_summary")
        or raw.get("summary")
        or {}
    )

    masvs = raw.get("masvs_compliance") or raw.get("compliance") or {}

    return {
        "findings": findings,
        "summary": summary,
        "masvs": masvs,
        "raw": raw,
        "report_file": str(report_file),
    }


async def run_scan(
    scan_id: int,
    apk_path: Path,
    package_name: str,
    mode: str = "deep",
    platform: str = "android",
    device_udid: str | None = None,
    db_session_factory=None,
) -> None:
    """
    Full AODS/IODS scan pipeline.  Runs as a background task.
    Updates the OwaspScan row and emits progress events.
    Dispatches to AODS (dyna.py) for Android or IODS (ios_scan.py) for iOS.
    """
    from database import AsyncSessionLocal
    from models.owasp import OwaspScan

    async def _update(status: str, progress: int = 0, **kwargs):
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            row = (await db.execute(select(OwaspScan).where(OwaspScan.id == scan_id))).scalar_one_or_none()
            if row:
                row.status = status
                row.progress = progress
                for k, v in kwargs.items():
                    setattr(row, k, v)
                await db.commit()

    async def _emit(msg: str, pct: int, status: str | None = None):
        q = _progress_queues.get(scan_id)
        if q:
            payload: dict = {"type": "progress", "progress": pct, "message": msg}
            if status:
                payload["status"] = status
            await q.put(payload)

    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues[scan_id] = queue

    if platform == "ios":
        scanner = _find_ios_scan_py()
        if not scanner:
            await _update("failed", error="ios_scan.py not found — set iods_path in settings")
            return
        output_dir = Path(scanner.parent) / "output" / str(scan_id)
        output_dir.mkdir(parents=True, exist_ok=True)
        python = _find_python_for_iods()
        iods_mode = "safe" if mode == "quick" else mode
        cmd = [
            python, str(scanner),
            "--ipa", str(apk_path),
            "--mode", iods_mode,
            "--formats", "json",
            "--output-dir", str(output_dir),
        ]
        if device_udid:
            cmd.extend(["--device-udid", device_udid])
        scanner_dir = scanner.parent
    else:
        scanner = _find_dyna_py()
        if not scanner:
            await _update("failed", error="dyna.py not found — set aods_path in settings")
            return
        output_dir = Path(scanner.parent) / "output" / str(scan_id)
        output_dir.mkdir(parents=True, exist_ok=True)
        _ensure_apktool_wrapper(scanner.parent)
        python = _find_python_for_aods()
        dyna_mode = "safe" if mode == "quick" else mode
        cmd = [
            python, str(scanner),
            "--apk", str(apk_path),
            "--pkg", package_name,
            "--mode", dyna_mode,
            "--formats", "json",
            "--output", str(output_dir),
            "--sequential",   # Windows doesn't support Unix signals used by parallel mode
        ]
        scanner_dir = scanner.parent

    t0 = time.monotonic()
    await _update("running", progress=5)
    scanner_label = "IODS" if platform == "ios" else "AODS"
    await _emit(f"Starting {scanner_label} scanner...", 5)

    loop = asyncio.get_event_loop()
    done_event = asyncio.Event()
    result_holder: list[int] = []

    def _run_subprocess():
        try:
            from config import settings
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONUTF8"] = "1"
            env["PATH"] = str(scanner_dir) + os.pathsep + env.get("PATH", "")
            # Tell AODS to invoke apktool via java -jar (Windows: .bat files can't
            # be found by subprocess.run with shell=False / CreateProcess)
            if settings.apktool_jar and Path(str(settings.apktool_jar)).exists():
                env["APKTOOL_JAR"] = str(settings.apktool_jar)
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=str(scanner_dir),
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
            )
            pct = 5
            for line in proc.stdout:
                line = line.rstrip()
                logger.debug("scanner", line=line)
                # Rough progress from keywords in dyna.py output
                if any(k in line.lower() for k in ("static", "decompil")):
                    pct = max(pct, 15)
                elif any(k in line.lower() for k in ("frida", "dynamic", "instrument")):
                    pct = max(pct, 40)
                elif any(k in line.lower() for k in ("scan", "analyz")):
                    pct = max(pct, 60)
                elif any(k in line.lower() for k in ("report", "generat", "output")):
                    pct = max(pct, 85)
                asyncio.run_coroutine_threadsafe(_emit(line[:200], pct), loop)
            proc.wait()
            result_holder.append(proc.returncode)
        except Exception as e:
            logger.exception("AODS subprocess error", error=str(e))
            result_holder.append(-1)
        finally:
            loop.call_soon_threadsafe(done_event.set)

    thread = threading.Thread(target=_run_subprocess, daemon=True, name=f"aods-{scan_id}")
    thread.start()
    await done_event.wait()

    duration = time.monotonic() - t0
    returncode = result_holder[0] if result_holder else -1

    await _emit("Parsing results...", 90)
    parsed = _parse_aods_output(output_dir, package_name)

    # Try HTML report
    html_files = list(output_dir.glob("*.html")) + list(output_dir.glob("**/*.html"))
    report_html = None
    if html_files:
        try:
            report_html = max(html_files, key=lambda p: p.stat().st_mtime).read_text(
                encoding="utf-8", errors="replace"
            )
        except Exception:
            pass

    if returncode == 0 or parsed["findings"]:
        await _update(
            "complete",
            progress=100,
            findings_json=json.dumps(parsed["findings"]),
            summary_json=json.dumps(parsed["summary"]),
            report_html=report_html,
            duration_s=duration,
        )
        await _emit(f"Scan complete — {len(parsed['findings'])} findings", 100, status="complete")
    else:
        await _update(
            "failed",
            progress=100,
            error=f"Scanner exited with code {returncode}",
            duration_s=duration,
        )
        await _emit("Scan failed — check server logs", 100, status="error")

    _progress_queues.pop(scan_id, None)
