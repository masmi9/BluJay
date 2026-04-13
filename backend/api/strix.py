"""
Strix AI agent integration for BluJay.

Strix is an autonomous multi-agent pentesting tool that actively validates
vulnerabilities with real PoCs — browser automation, HTTP proxy, terminal
execution, and multi-agent orchestration.

This module lets BluJay:
  1. Launch Strix scans against backend targets discovered during mobile app analysis
  2. Track scan progress in real time via polling or WebSocket
  3. Pull Strix findings back into BluJay's database
  4. Correlate Strix network/API findings with BluJay's mobile static + dynamic results
  5. Feed Strix output back through metatron-qwen for unified AI triage

Architecture:
  BluJay static/dynamic scan
       │
       ▼
  Extract backend target (URL/IP from APK strings, traffic intercept, etc.)
       │
       ▼
  POST /strix/scan  ──► Strix subprocess (headless -n mode)
       │                    └─► Docker sandbox
       │                    └─► Multi-agent: recon → exploit → validate PoC
       ▼
  GET /strix/scan/{id}/status  ──► poll progress
       │
       ▼
  GET /strix/scan/{id}/results ──► parse strix_runs/<name>/
       │
       ▼
  POST /ollama/analyze  ──► metatron-qwen unified triage
       │
       ▼
  BluJay dashboard — correlated mobile + network findings

Endpoints:
  POST   /strix/scan              — launch a new Strix scan
  GET    /strix/scan/{id}         — get scan record
  GET    /strix/scan/{id}/status  — lightweight status poll
  GET    /strix/scan/{id}/results — parsed findings from strix_runs/
  POST   /strix/scan/{id}/cancel  — kill the scan process
  GET    /strix/scans             — list all scans (filterable by session)
  DELETE /strix/scan/{id}         — delete scan record
  GET    /strix/status            — check Strix is installed + Docker is running
"""

import asyncio
import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.agent import StrixScan

logger = structlog.get_logger()
router = APIRouter()

# ── Where Strix writes its run output ──────────────────────────────────────
# Strix saves results to strix_runs/<run_name>/ relative to cwd.
# We pin the cwd to the project root so the path is predictable.
STRIX_RUNS_DIR = Path.home() / "strix_runs"

# ── Default LLM for Strix ──────────────────────────────────────────────────
# Uses metatron-qwen via Ollama by default (fully local, no API key).
# Override with any LiteLLM-compatible model string.
DEFAULT_STRIX_LLM = "ollama/metatron-qwen"
DEFAULT_OLLAMA_BASE = "http://localhost:11434"


# ──────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ──────────────────────────────────────────────────────────────────────────

class StartScanRequest(BaseModel):
    target: str                                    # URL, IP, domain, or local path
    session_id: int | None = None                  # link to a BluJay analysis session
    scan_mode: str = "standard"                    # quick | standard | deep
    instruction: str | None = None                 # custom Strix instructions
    llm_model: str = DEFAULT_STRIX_LLM             # LiteLLM model string
    ollama_base: str = DEFAULT_OLLAMA_BASE         # Ollama API base (if using local model)
    llm_api_key: str | None = None                 # API key (not needed for local models)
    auto_triage: bool = True                       # auto-feed results to metatron-qwen after scan


class ScanStatusResponse(BaseModel):
    id: int
    status: str
    target: str
    scan_mode: str
    session_id: int | None
    started_at: str | None
    completed_at: str | None
    duration_seconds: float | None
    vuln_count: int | None
    risk_level: str | None
    error: str | None


# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────

def _strix_installed() -> bool:
    """Check if the strix CLI is on PATH."""
    return shutil.which("strix") is not None


def _docker_running() -> bool:
    """Check if Docker daemon is reachable."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _parse_strix_run_dir(run_name: str) -> dict:
    """
    Parse the strix_runs/<run_name>/ directory for findings.
    Strix writes:
      - report.json or findings.json  (structured vulnerability data)
      - events.jsonl                  (agent event stream)
      - summary.md or report.md       (human-readable report)
    Returns a dict with parsed findings.
    """
    run_dir = STRIX_RUNS_DIR / run_name
    if not run_dir.exists():
        return {"error": f"Run directory not found: {run_dir}", "findings": [], "vuln_count": 0}

    findings = []
    risk_level = "NONE"

    # Try structured JSON report first
    for fname in ["report.json", "findings.json", "vulnerabilities.json"]:
        fpath = run_dir / fname
        if fpath.exists():
            try:
                data = json.loads(fpath.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    findings = data
                elif isinstance(data, dict):
                    findings = data.get("findings", data.get("vulnerabilities", []))
                break
            except Exception as e:
                logger.warning("Failed to parse Strix JSON report", file=str(fpath), error=str(e))

    # Parse events.jsonl for findings if no JSON report
    if not findings:
        events_path = run_dir / "events.jsonl"
        if events_path.exists():
            try:
                for line in events_path.read_text(encoding="utf-8").splitlines():
                    event = json.loads(line)
                    if event.get("type") == "vulnerability_found":
                        findings.append(event.get("data", event))
            except Exception as e:
                logger.warning("Failed to parse events.jsonl", error=str(e))

    # Determine overall risk level from findings
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    max_sev = 0
    for f in findings:
        sev = str(f.get("severity", "")).upper()
        max_sev = max(max_sev, severity_rank.get(sev, 0))

    risk_map = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "NONE"}
    risk_level = risk_map.get(max_sev, "NONE")

    # Read markdown summary if present
    summary = ""
    for fname in ["summary.md", "report.md", "README.md"]:
        fpath = run_dir / fname
        if fpath.exists():
            summary = fpath.read_text(encoding="utf-8")
            break

    return {
        "findings": findings,
        "vuln_count": len(findings),
        "risk_level": risk_level,
        "summary": summary,
        "run_dir": str(run_dir),
    }


async def _run_strix_scan(scan_id: int, request: StartScanRequest):
    """
    Background task: runs Strix as a subprocess in headless (-n) mode,
    streams output, then parses results and updates the DB record.
    """
    from database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        scan = await db.get(StrixScan, scan_id)
        if not scan:
            return

        # Build environment
        env = os.environ.copy()
        env["STRIX_LLM"] = request.llm_model
        env["STRIX_TELEMETRY"] = "0"  # no phone-home during BluJay-initiated scans

        if request.llm_api_key:
            env["LLM_API_KEY"] = request.llm_api_key
        elif "ollama" in request.llm_model.lower():
            env["LLM_API_BASE"] = request.ollama_base
            env["LLM_API_KEY"] = "ollama"  # litellm requires a non-empty key

        # Build command
        cmd = [
            "strix",
            "--non-interactive",
            "--target", request.target,
            "--scan-mode", request.scan_mode,
        ]
        if request.instruction:
            cmd += ["--instruction", request.instruction]

        # Update record to running
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        await db.commit()

        raw_output_lines = []
        run_name = None
        proc = None

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
                cwd=str(Path.home()),
            )

            # Store PID for cancellation
            scan.pid = proc.pid
            await db.commit()

            # Stream output
            async for line_bytes in proc.stdout:
                line = line_bytes.decode("utf-8", errors="replace").rstrip()
                raw_output_lines.append(line)

                # Strix prints run name early in output: "Run: <name>"
                if run_name is None and "Run:" in line:
                    match = re.search(r"Run:\s*(\S+)", line)
                    if match:
                        run_name = match.group(1)
                        scan.run_name = run_name
                        await db.commit()

            await proc.wait()
            exit_code = proc.returncode

            scan.raw_output = "\n".join(raw_output_lines)
            scan.completed_at = datetime.utcnow()
            scan.duration_seconds = (
                scan.completed_at - scan.started_at
            ).total_seconds() if scan.started_at else None

            if exit_code == 0:
                scan.status = "complete"
                scan.vuln_count = 0
                scan.risk_level = "NONE"
            elif exit_code == 2:
                # Exit code 2 = vulnerabilities found (Strix convention)
                scan.status = "complete"
                # Parse results from run dir
                if run_name:
                    parsed = _parse_strix_run_dir(run_name)
                    scan.findings_json = json.dumps(parsed.get("findings", []))
                    scan.vuln_count = parsed.get("vuln_count", 0)
                    scan.risk_level = parsed.get("risk_level", "UNKNOWN")
                else:
                    # Fall back to counting severity mentions in output
                    output_text = scan.raw_output or ""
                    scan.vuln_count = output_text.upper().count("CRITICAL") + \
                                      output_text.upper().count("HIGH") + \
                                      output_text.upper().count("MEDIUM")
                    scan.risk_level = "UNKNOWN"
            else:
                scan.status = "error"
                scan.error = f"Strix exited with code {exit_code}"

            await db.commit()

            # Auto-triage: feed Strix findings through metatron-qwen
            if request.auto_triage and scan.status == "complete" and scan.findings_json:
                await _auto_triage(db, scan)

        except asyncio.CancelledError:
            if proc and proc.returncode is None:
                proc.terminate()
            scan.status = "cancelled"
            scan.raw_output = "\n".join(raw_output_lines)
            scan.completed_at = datetime.utcnow()
            await db.commit()

        except Exception as e:
            logger.error("Strix scan failed", scan_id=scan_id, error=str(e))
            scan.status = "error"
            scan.error = str(e)
            scan.raw_output = "\n".join(raw_output_lines)
            scan.completed_at = datetime.utcnow()
            await db.commit()


async def _auto_triage(db: AsyncSession, scan: StrixScan):
    """
    After a Strix scan completes, automatically feed findings to metatron-qwen
    via the existing /ollama/analyze endpoint logic (direct call, no HTTP round-trip).
    """
    try:
        import httpx
        findings = json.loads(scan.findings_json or "[]")
        if not findings:
            return

        prompt_data = json.dumps(findings, indent=2)

        async with httpx.AsyncClient(timeout=180.0) as client:
            resp = await client.post(
                "http://localhost:8000/api/v1/ollama/analyze",
                json={
                    "scan_data": prompt_data,
                    "source": "strix",
                    "session_id": scan.session_id,
                    "extra_context": (
                        f"These findings were generated by Strix autonomous pentest agents "
                        f"targeting: {scan.target}. Each finding includes a validated PoC. "
                        f"Prioritize findings with confirmed exploitation paths."
                    ),
                },
            )
            if resp.status_code == 200:
                logger.info("Auto-triage complete", scan_id=scan.id)
            else:
                logger.warning("Auto-triage failed", status=resp.status_code)
    except Exception as e:
        logger.warning("Auto-triage error", error=str(e))


# ──────────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────────

@router.get("/status", summary="Check if Strix and Docker are available")
async def strix_status():
    """
    Pre-flight check. Call this before launching a scan to confirm
    Strix CLI and Docker are both reachable.
    """
    strix_ok = _strix_installed()
    docker_ok = _docker_running()

    return {
        "strix_installed": strix_ok,
        "docker_running": docker_ok,
        "ready": strix_ok and docker_ok,
        "hints": [
            *([] if strix_ok else ["Install Strix: curl -sSL https://strix.ai/install | bash"]),
            *([] if docker_ok else ["Start Docker Desktop or run: sudo systemctl start docker"]),
        ],
    }


@router.post("/scan", summary="Launch a Strix autonomous pentest scan")
async def start_scan(
    body: StartScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Launches Strix in headless mode against a target extracted from your
    mobile app analysis (backend URL, API endpoint, server IP).

    Strix will:
    - Run recon (OSINT, attack surface mapping)
    - Attempt to exploit discovered vulnerabilities with real PoCs
    - Validate findings with browser automation and HTTP proxy
    - Save results to strix_runs/<run_name>/

    If auto_triage=true (default), findings are automatically fed to
    metatron-qwen for unified mobile + network AI triage.

    Runs asynchronously — poll GET /strix/scan/{id}/status for progress.
    """
    if not _strix_installed():
        raise HTTPException(
            503,
            "Strix is not installed. Run: curl -sSL https://strix.ai/install | bash"
        )
    if not _docker_running():
        raise HTTPException(
            503,
            "Docker is not running. Strix requires Docker for its sandbox environment."
        )

    if body.scan_mode not in ("quick", "standard", "deep"):
        raise HTTPException(400, "scan_mode must be one of: quick, standard, deep")

    # Create DB record
    scan = StrixScan(
        session_id=body.session_id,
        target=body.target,
        scan_mode=body.scan_mode,
        instruction=body.instruction,
        llm_model=body.llm_model,
        status="pending",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Fire background task
    background_tasks.add_task(_run_strix_scan, scan.id, body)

    return {
        "id": scan.id,
        "status": "pending",
        "target": scan.target,
        "scan_mode": scan.scan_mode,
        "session_id": scan.session_id,
        "message": f"Strix scan started. Poll GET /api/v1/strix/scan/{scan.id}/status for progress.",
    }


@router.get("/scan/{scan_id}", summary="Get full scan record")
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(StrixScan, scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found.")
    return _scan_to_dict(scan, include_output=True)


@router.get("/scan/{scan_id}/status", summary="Lightweight status poll")
async def scan_status(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Fast endpoint for polling — returns status + counts only, no raw output."""
    scan = await db.get(StrixScan, scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found.")
    return ScanStatusResponse(
        id=scan.id,
        status=scan.status,
        target=scan.target,
        scan_mode=scan.scan_mode,
        session_id=scan.session_id,
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        duration_seconds=scan.duration_seconds,
        vuln_count=scan.vuln_count,
        risk_level=scan.risk_level,
        error=scan.error,
    )


@router.get("/scan/{scan_id}/results", summary="Get parsed Strix findings")
async def scan_results(scan_id: int, db: AsyncSession = Depends(get_db)):
    """
    Returns structured findings parsed from strix_runs/<run_name>/.
    Also re-parses the run directory live in case new files were written
    after the scan completed.
    """
    scan = await db.get(StrixScan, scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found.")

    if scan.status not in ("complete", "error"):
        return {
            "id": scan.id,
            "status": scan.status,
            "message": "Scan still in progress. Check back when status is 'complete'.",
        }

    # Re-parse from disk for freshest data
    parsed = {}
    if scan.run_name:
        parsed = _parse_strix_run_dir(scan.run_name)

    # Fall back to stored findings_json
    findings = parsed.get("findings") or json.loads(scan.findings_json or "[]")

    return {
        "id": scan.id,
        "status": scan.status,
        "target": scan.target,
        "scan_mode": scan.scan_mode,
        "session_id": scan.session_id,
        "run_name": scan.run_name,
        "vuln_count": scan.vuln_count or len(findings),
        "risk_level": scan.risk_level or parsed.get("risk_level"),
        "findings": findings,
        "summary": parsed.get("summary", ""),
        "run_dir": parsed.get("run_dir"),
        "duration_seconds": scan.duration_seconds,
    }


@router.post("/scan/{scan_id}/cancel", summary="Cancel a running Strix scan")
async def cancel_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(StrixScan, scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found.")
    if scan.status not in ("pending", "running"):
        raise HTTPException(400, f"Scan is already {scan.status} — cannot cancel.")

    if scan.pid:
        try:
            import signal
            os.kill(scan.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass  # Already finished

    scan.status = "cancelled"
    scan.completed_at = datetime.utcnow()
    await db.commit()

    return {"id": scan.id, "status": "cancelled"}


@router.get("/scans", summary="List all Strix scans")
async def list_scans(
    session_id: int | None = Query(default=None),
    status: str | None = Query(default=None),
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    q = select(StrixScan).order_by(StrixScan.created_at.desc())
    if session_id is not None:
        q = q.where(StrixScan.session_id == session_id)
    if status:
        q = q.where(StrixScan.status == status)
    q = q.offset(skip).limit(limit)

    rows = (await db.execute(q)).scalars().all()
    return [_scan_to_dict(r, include_output=False) for r in rows]


@router.delete("/scan/{scan_id}", summary="Delete a scan record")
async def delete_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(StrixScan, scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found.")
    if scan.status == "running":
        raise HTTPException(400, "Cannot delete a running scan. Cancel it first.")
    await db.delete(scan)
    await db.commit()
    return {"status": "deleted", "id": scan_id}


# ──────────────────────────────────────────────────────────────────────────
# Serialization helper
# ──────────────────────────────────────────────────────────────────────────

def _scan_to_dict(scan: StrixScan, include_output: bool = False) -> dict:
    d = {
        "id": scan.id,
        "created_at": scan.created_at.isoformat(),
        "updated_at": scan.updated_at.isoformat() if scan.updated_at else None,
        "session_id": scan.session_id,
        "target": scan.target,
        "scan_mode": scan.scan_mode,
        "instruction": scan.instruction,
        "llm_model": scan.llm_model,
        "status": scan.status,
        "run_name": scan.run_name,
        "vuln_count": scan.vuln_count,
        "risk_level": scan.risk_level,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "duration_seconds": scan.duration_seconds,
        "error": scan.error,
    }
    if include_output:
        d["raw_output"] = scan.raw_output
        d["findings"] = json.loads(scan.findings_json or "[]")
    return d
