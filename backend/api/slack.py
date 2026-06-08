"""
Slack slash command triggers for BluJay.

Register two slash commands in your Slack app pointing at this server:
  /scan    → POST <host>/api/v1/slack  (text: <package> or <serial>:<package>)
  /pentest → POST <host>/api/v1/slack  (text: <package> or <serial>:<package>)

Required env vars:
  SLACK_SIGNING_SECRET  — from Slack app "Basic Information" page
  SLACK_BOT_TOKEN       — xoxb-... (only needed for bot-initiated messages)

Flow:
  /scan    → pull APK → static analysis → post findings summary to channel
  /pentest → pull APK → static analysis → autonomous pipeline → post gate/report to channel
"""
import asyncio
import hashlib
import hmac
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import parse_qs

import httpx
import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import JSONResponse

from config import settings

logger = structlog.get_logger()
router = APIRouter()


# ── Slack helpers ──────────────────────────────────────────────────────────────

def _verify_signature(headers: dict, raw_body: str) -> None:
    """Validates the Slack request signature. Skipped when SLACK_SIGNING_SECRET is unset (dev)."""
    if not settings.slack_signing_secret:
        logger.warning("SLACK_SIGNING_SECRET not set — skipping signature verification")
        return

    timestamp = headers.get("x-slack-request-timestamp", "")
    slack_sig = headers.get("x-slack-signature", "")

    if not timestamp or not slack_sig:
        raise HTTPException(403, "Missing Slack signature headers")

    try:
        if abs(time.time() - int(timestamp)) > 300:
            raise HTTPException(403, "Slack request timestamp too old (replay protection)")
    except ValueError:
        raise HTTPException(403, "Invalid Slack timestamp")

    basestring = f"v0:{timestamp}:{raw_body}"
    computed = "v0=" + hmac.new(
        settings.slack_signing_secret.encode(),
        basestring.encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(computed, slack_sig):
        raise HTTPException(403, "Invalid Slack signature")


async def _post_to_slack(response_url: str, text: str) -> None:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(response_url, json={"text": text})
    except Exception as exc:
        logger.warning("Failed to post Slack update", error=str(exc))


# ── Pipeline helpers ───────────────────────────────────────────────────────────

async def _launch_and_monitor_pipeline(
    analysis_id: int,
    package: str,
    response_url: str,
) -> None:
    from api.pipeline import _runs, _queues as _pipe_queues, _run_pipeline
    from agents.state import AgentState

    run_id = str(uuid.uuid4())
    short_id = run_id[:8]
    now_iso = datetime.now(timezone.utc).isoformat()

    initial_state: AgentState = {
        "run_id": run_id,
        "target_url": f"android://{package}",
        "scan_type": "android",
        "session_id": analysis_id,
        "recon_results": [],
        "exploit_findings": [],
        "variant_iterations": 0,
        "validated_findings": [],
        "report_sarif": {},
        "report_summary": "",
        "gate_decision": None,
        "gate_summary": "",
        "messages": [],
        "status": "running",
        "error": None,
    }
    _runs[run_id] = {
        "status": "running",
        "target_url": f"android://{package}",
        "scan_type": "android",
        "state_snapshot": None,
        "gate_payload": None,
        "started_at": now_iso,
        "finished_at": None,
    }
    _pipe_queues[run_id] = asyncio.Queue(maxsize=1000)

    asyncio.create_task(_run_pipeline(run_id, initial_state))
    await _post_to_slack(response_url, f":robot_face: Pentest pipeline `{short_id}` launched for `{package}`.")

    pipe_q = _pipe_queues[run_id]
    while True:
        event = await pipe_q.get()
        evt_type = event.get("type")

        if evt_type == "interrupt":
            gate = event.get("data", {})
            sev = gate.get("severity_counts", {})
            await _post_to_slack(
                response_url,
                f":warning: *Pipeline `{short_id}` awaiting human review*\n"
                f"Critical: {sev.get('critical', 0)}  "
                f"High: {sev.get('high', 0)}  "
                f"Medium: {sev.get('medium', 0)}\n"
                f"Resume: `POST /api/v1/pipeline/{run_id}/resume`  "
                f'body: `{{"decision": "approved"}}`',
            )
            return

        elif evt_type == "done":
            snap = _runs[run_id].get("state_snapshot") or {}
            report = snap.get("report_summary") or "No report summary available."
            await _post_to_slack(
                response_url,
                f":tada: *Pipeline `{short_id}` complete*\n{report[:1500]}",
            )
            return

        elif evt_type == "error":
            await _post_to_slack(
                response_url,
                f":x: Pipeline `{short_id}` failed: {event.get('message')}",
            )
            return


# ── Main background task ───────────────────────────────────────────────────────

async def _slack_run_task(
    package: str,
    serial: str | None,
    response_url: str,
    auto_pipeline: bool,
) -> None:
    from core import adb_manager
    from core.apk_analyzer import run_analysis
    from api.analysis import _progress_queues
    from database import AsyncSessionLocal
    from models.analysis import Analysis, StaticFinding
    from sqlalchemy import select, func

    # --- Resolve device ---
    try:
        devices = await adb_manager.get_devices()
    except Exception as e:
        await _post_to_slack(response_url, f":x: ADB error: {e}")
        return

    connected = [d for d in devices if d.state == "device"]
    if not connected:
        await _post_to_slack(response_url, ":x: No ADB devices are connected.")
        return

    if serial:
        if serial not in {d.serial for d in connected}:
            await _post_to_slack(response_url, f":x: Device `{serial}` is not connected or not authorized.")
            return
        target_serial = serial
    else:
        target_serial = connected[0].serial

    # --- Pull APK ---
    await _post_to_slack(response_url, f":arrow_down: Pulling `{package}` from `{target_serial}`...")
    try:
        apk_path = await adb_manager.pull_apk(target_serial, package, settings.uploads_dir)
    except RuntimeError as e:
        await _post_to_slack(response_url, f":x: Pull failed: {e}")
        return

    # --- Hash & dedup ---
    import hashlib as _hashlib
    content = apk_path.read_bytes()
    sha256 = _hashlib.sha256(content).hexdigest()
    already_complete = False

    async with AsyncSessionLocal() as db:
        existing = await db.execute(select(Analysis).where(Analysis.apk_sha256 == sha256))
        analysis = existing.scalar_one_or_none()

        if analysis:
            already_complete = analysis.status == "complete"
            analysis_id = analysis.id
        else:
            analysis = Analysis(
                apk_filename=f"{package}.apk",
                apk_sha256=sha256,
                upload_path=str(apk_path),
                status="pending",
            )
            db.add(analysis)
            await db.commit()
            await db.refresh(analysis)
            analysis_id = analysis.id

    # --- Run analysis (skip if dedup hit) ---
    if already_complete:
        await _post_to_slack(
            response_url,
            f":information_source: `{package}` was already analyzed (#{analysis_id}) — using cached results.",
        )
    else:
        queue: asyncio.Queue = asyncio.Queue()
        _progress_queues[analysis_id] = queue

        asyncio.create_task(run_analysis(analysis_id, apk_path, queue, AsyncSessionLocal))
        await _post_to_slack(response_url, f":mag: Analyzing `{package}` (run #{analysis_id})...")

        while True:
            event = await queue.get()
            if event.get("type") == "complete":
                break
            elif event.get("type") == "error":
                await _post_to_slack(response_url, f":x: Analysis failed: {event.get('message')}")
                return

    # --- Post findings summary ---
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(
            select(StaticFinding.severity, func.count(StaticFinding.id))
            .where(StaticFinding.analysis_id == analysis_id)
            .group_by(StaticFinding.severity)
        )).all()

    counts = {sev: cnt for sev, cnt in rows}
    await _post_to_slack(
        response_url,
        f":white_check_mark: *Analysis #{analysis_id} — `{package}`*\n"
        f"Critical: *{counts.get('critical', 0)}*  |  "
        f"High: *{counts.get('high', 0)}*  |  "
        f"Medium: *{counts.get('medium', 0)}*  |  "
        f"Low: *{counts.get('low', 0)}*",
    )

    if auto_pipeline:
        await _launch_and_monitor_pipeline(analysis_id, package, response_url)


# ── Endpoint ───────────────────────────────────────────────────────────────────

@router.post("")
async def slack_command(request: Request, background_tasks: BackgroundTasks):
    """
    Receives Slack slash commands (/scan and /pentest).
    Returns an immediate ACK; all work happens in a background task.
    """
    raw_body = (await request.body()).decode()
    _verify_signature(dict(request.headers), raw_body)

    params = parse_qs(raw_body)
    command = params.get("command", [""])[0]          # "/scan" or "/pentest"
    text = params.get("text", [""])[0].strip()
    response_url = params.get("response_url", [""])[0]

    if not text:
        usage = (
            "Usage:\n"
            "  `/scan <package>`  — static analysis only\n"
            "  `/scan <serial>:<package>`  — target a specific device\n"
            "  `/pentest <package>`  — full autonomous pipeline\n"
            "  `/pentest <serial>:<package>`  — full pipeline on a specific device"
        )
        return JSONResponse({"text": usage})

    # Parse optional serial prefix: "serial:package" or just "package"
    if ":" in text:
        serial, _, package = text.partition(":")
        serial = serial.strip() or None
        package = package.strip()
    else:
        serial = None
        package = text

    if not package:
        return JSONResponse({"text": ":x: Package name is required."})

    auto_pipeline = command == "/pentest"
    action = "pentest pipeline" if auto_pipeline else "scan"

    background_tasks.add_task(_slack_run_task, package, serial, response_url, auto_pipeline)

    logger.info("Slack trigger received", command=command, package=package, serial=serial)

    return JSONResponse({
        "response_type": "in_channel",
        "text": f":rocket: Queued {action} for `{package}`...",
    })
