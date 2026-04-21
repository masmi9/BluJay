"""
Ollama / metatron-qwen integration for BluJay.
Exposes AI-powered triage and remediation analysis using a local LLM —
no cloud, no API keys. Requires Ollama running locally with the
metatron-qwen model loaded (from the METATRON project).
"""

import json
import time
from datetime import datetime

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.agent import OllamaAnalysis

logger = structlog.get_logger()

router = APIRouter()

# Ollama runs locally — this is the default address
OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "metatron-qwen"
OLLAMA_TIMEOUT = 180.0  # seconds — LLM inference can be slow on CPU


# ──────────────────────────────────────────────
# Pydantic schemas
# ──────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    scan_data: str | dict | list          # raw findings — string, JSON dict, or list
    source: str = "manual"               # static | owasp | cve | fuzzing | tls | jwt | manual
    session_id: int | None = None
    model: str = DEFAULT_MODEL
    extra_context: str | None = None     # optional extra instructions


class SessionAnalyzeRequest(BaseModel):
    session_id: int
    sources: list[str] = []              # empty = include all available sources
    model: str = DEFAULT_MODEL


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _build_prompt(scan_data: str, source: str, extra_context: str | None = None) -> str:
    """
    Build a structured prompt for metatron-qwen tailored to mobile app security.
    """
    source_context = {
        "static":   "static analysis of a mobile app (decompiled APK/IPA — secrets, permissions, hardcoded values, insecure APIs)",
        "owasp":    "OWASP MASVS dynamic scan of a mobile application",
        "cve":      "CVE / vulnerability database lookup for libraries used by a mobile app",
        "fuzzing":  "API fuzzing results targeting endpoints discovered in a mobile app",
        "tls":      "TLS/SSL audit of a mobile app's backend server",
        "jwt":      "JWT token analysis from a mobile app's authentication flow",
        "frida":    "Frida dynamic instrumentation output from a live mobile app session",
        "manual":   "mobile application security scan data",
    }.get(source, "mobile application security scan data")

    extra = f"\n\nAdditional context: {extra_context}" if extra_context else ""

    return f"""You are an expert mobile application penetration tester and security analyst.

You have been given the following output from {source_context}.

Your job:
1. Identify all security vulnerabilities present in the data.
2. Classify each by severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO.
3. Map each finding to the relevant OWASP MASVS control or OWASP Mobile Top 10 category where applicable.
4. For each vulnerability, suggest a concrete remediation step.
5. Provide an overall risk summary at the end.

Format your response as:

FINDINGS:
[List each finding with: Name | Severity | OWASP Category | Description | Remediation]

OVERALL RISK: [CRITICAL / HIGH / MEDIUM / LOW]

SUMMARY:
[2-3 sentence executive summary of the security posture]

Scan Data:
{scan_data}{extra}"""


async def _call_ollama(prompt: str, model: str = DEFAULT_MODEL) -> tuple[str, float]:
    """
    Call the local Ollama API. Returns (response_text, duration_ms).
    Raises HTTPException if Ollama is unreachable or returns an error.
    """
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            resp = await client.post(f"{OLLAMA_BASE_URL}/api/generate", json=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.ConnectError:
        raise HTTPException(
            503,
            "Ollama is not running. Start it with: ollama run metatron-qwen"
        )
    except httpx.TimeoutException:
        raise HTTPException(504, "Ollama timed out — the model may still be loading.")
    except httpx.HTTPStatusError as e:
        raise HTTPException(502, f"Ollama returned an error: {e.response.text}")

    duration_ms = (time.monotonic() - start) * 1000
    response_text = data.get("response", "")

    if not response_text:
        raise HTTPException(502, "Ollama returned an empty response.")

    return response_text, duration_ms


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@router.get("/status", summary="Check if Ollama is running and metatron-qwen is available")
async def ollama_status():
    """
    Pings the local Ollama instance and checks that metatron-qwen is listed.
    Use this from the UI to show a 'AI Ready' / 'AI Offline' indicator.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
            resp.raise_for_status()
            tags = resp.json()
    except Exception as e:
        return {
            "ollama_running": False,
            "model_available": False,
            "error": str(e),
            "hint": "Run: ollama run metatron-qwen",
        }

    models = [m["name"] for m in tags.get("models", [])]
    model_available = any(DEFAULT_MODEL in m for m in models)

    return {
        "ollama_running": True,
        "model_available": model_available,
        "available_models": models,
        "default_model": DEFAULT_MODEL,
        "hint": None if model_available else f"Model not found. Run: ollama pull metatron-qwen",
    }


@router.post("/analyze", summary="Run AI triage on scan data from any BluJay module")
async def analyze(
    body: AnalyzeRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Feed scan output from any BluJay module (static, OWASP, CVE, fuzzing, TLS, JWT, etc.)
    to the local metatron-qwen model for AI-powered vulnerability triage.

    scan_data can be a plain string, a dict, or a list — it will be serialized automatically.
    """
    # Normalize scan_data to string
    if isinstance(body.scan_data, (dict, list)):
        scan_str = json.dumps(body.scan_data, indent=2)
    else:
        scan_str = str(body.scan_data)

    if not scan_str.strip():
        raise HTTPException(400, "scan_data cannot be empty.")

    # Persist record as running
    record = OllamaAnalysis(
        session_id=body.session_id,
        source=body.source,
        scan_input=scan_str,
        status="running",
        model_used=body.model,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    # Build prompt and call the model
    prompt = _build_prompt(scan_str, body.source, body.extra_context)

    try:
        ai_response, duration_ms = await _call_ollama(prompt, body.model)
        record.ai_response = ai_response
        record.status = "complete"
        record.duration_ms = duration_ms
    except HTTPException as e:
        record.status = "error"
        record.error = e.detail
        await db.commit()
        raise
    except Exception as e:
        record.status = "error"
        record.error = str(e)
        await db.commit()
        logger.error("Ollama analysis failed", error=str(e))
        raise HTTPException(500, f"Analysis failed: {e}")

    await db.commit()

    return {
        "id": record.id,
        "status": record.status,
        "source": record.source,
        "session_id": record.session_id,
        "model_used": record.model_used,
        "ai_response": record.ai_response,
        "duration_ms": record.duration_ms,
        "created_at": record.created_at.isoformat(),
    }


@router.post("/analyze/session", summary="Run AI triage across all findings for a session")
async def analyze_session(
    body: SessionAnalyzeRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Pulls all existing OllamaAnalysis records for a session and feeds them
    together into the model for a unified risk assessment across all sources.

    Useful for a final 'full report' after running static + OWASP + CVE + fuzzing.
    """
    q = select(OllamaAnalysis).where(
        OllamaAnalysis.session_id == body.session_id,
        OllamaAnalysis.status == "complete",
    )
    if body.sources:
        q = q.where(OllamaAnalysis.source.in_(body.sources))

    rows = (await db.execute(q)).scalars().all()

    if not rows:
        raise HTTPException(
            404,
            f"No completed analyses found for session {body.session_id}. "
            "Run /ollama/analyze for each scan module first."
        )

    # Combine all findings into one payload
    combined = "\n\n".join(
        f"=== {r.source.upper()} FINDINGS ===\n{r.ai_response}"
        for r in rows
    )

    prompt = f"""You are an expert mobile application security analyst performing a final consolidated risk assessment.

Below are AI-generated vulnerability findings from multiple security scan modules run against the same mobile application.

Your job:
1. Correlate and deduplicate findings across modules.
2. Identify attack chains — where one vulnerability enables exploitation of another.
3. Rank the top 5 most critical issues by exploitability and impact.
4. Provide an overall CVSS-style risk rating: CRITICAL / HIGH / MEDIUM / LOW.
5. Write an executive summary suitable for a security report.

Combined Findings:
{combined}"""

    record = OllamaAnalysis(
        session_id=body.session_id,
        source="consolidated",
        scan_input=combined,
        status="running",
        model_used=body.model,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    try:
        ai_response, duration_ms = await _call_ollama(prompt, body.model)
        record.ai_response = ai_response
        record.status = "complete"
        record.duration_ms = duration_ms
    except HTTPException as e:
        record.status = "error"
        record.error = e.detail
        await db.commit()
        raise
    except Exception as e:
        record.status = "error"
        record.error = str(e)
        await db.commit()
        raise HTTPException(500, f"Consolidated analysis failed: {e}")

    await db.commit()

    return {
        "id": record.id,
        "status": record.status,
        "source": "consolidated",
        "session_id": record.session_id,
        "model_used": record.model_used,
        "ai_response": record.ai_response,
        "duration_ms": record.duration_ms,
        "sources_included": [r.source for r in rows],
        "created_at": record.created_at.isoformat(),
    }


@router.get("/history", summary="Retrieve past AI analyses")
async def get_history(
    session_id: int | None = Query(default=None),
    source: str | None = Query(default=None),
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    q = select(OllamaAnalysis).order_by(OllamaAnalysis.created_at.desc())
    if session_id is not None:
        q = q.where(OllamaAnalysis.session_id == session_id)
    if source:
        q = q.where(OllamaAnalysis.source == source)
    q = q.offset(skip).limit(limit)

    rows = (await db.execute(q)).scalars().all()
    return [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat(),
            "session_id": r.session_id,
            "source": r.source,
            "status": r.status,
            "model_used": r.model_used,
            "ai_response": r.ai_response,
            "error": r.error,
            "duration_ms": r.duration_ms,
        }
        for r in rows
    ]


@router.delete("/history/{analysis_id}", summary="Delete a single AI analysis record")
async def delete_analysis(analysis_id: int, db: AsyncSession = Depends(get_db)):
    row = await db.get(OllamaAnalysis, analysis_id)
    if not row:
        raise HTTPException(404, f"Analysis {analysis_id} not found.")
    await db.delete(row)
    await db.commit()
    return {"status": "deleted", "id": analysis_id}
