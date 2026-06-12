"""
Burp-style Intruder: spray a payload list into marked positions in an HTTP request template.
Positions are marked with §...§ in the raw request body, headers, or URL.

Attack types:
  sniper       — one position, one payload list, sequential replacements
  battering_ram — same payload inserted into all positions simultaneously
  pitchfork    — parallel lists, payload N applied to position N (zips lists)
  cluster_bomb  — cartesian product of all payload lists (use with care)
"""
import asyncio
import time
import re
import uuid
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()

# job_id → job dict
_jobs: dict[str, dict] = {}

POSITION_RE = re.compile(r'§([^§]*)§')


class IntruderRequest(BaseModel):
    target_url: str
    raw_request: str = Field(..., description="Full HTTP request template with §position§ markers")
    payloads: list[list[str]] = Field(..., description="One list per position. For sniper provide one list.")
    attack_type: str = Field("sniper", description="sniper | battering_ram | pitchfork | cluster_bomb")
    concurrency: int = Field(10, ge=1, le=50)
    timeout: float = Field(10.0, ge=1, le=60)
    follow_redirects: bool = True


class IntruderJob(BaseModel):
    job_id: str
    status: str
    total: int
    completed: int
    results: list[dict]
    error: str | None = None


@router.post("/run", response_model=IntruderJob)
async def run_intruder(req: IntruderRequest):
    positions = POSITION_RE.findall(req.raw_request)
    if not positions:
        raise HTTPException(400, "No §position§ markers found in the request template")

    payload_sets = _build_payload_sets(req.attack_type, positions, req.payloads)
    if not payload_sets:
        raise HTTPException(400, "No payloads generated — check attack type and payload lists")

    job_id = str(uuid.uuid4())[:8]
    job: dict = {
        "job_id": job_id,
        "status": "running",
        "total": len(payload_sets),
        "completed": 0,
        "results": [],
        "error": None,
    }
    _jobs[job_id] = job
    asyncio.create_task(_execute(job, req, payload_sets))
    return _to_model(job)


@router.get("/jobs/{job_id}", response_model=IntruderJob)
async def get_job(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return _to_model(job)


@router.get("/jobs", response_model=list[IntruderJob])
async def list_jobs():
    return [_to_model(j) for j in _jobs.values()]


@router.delete("/jobs/{job_id}")
async def cancel_job(job_id: str):
    job = _jobs.pop(job_id, None)
    if job:
        job["status"] = "cancelled"
    return {"status": "cancelled", "job_id": job_id}


# ── Internals ─────────────────────────────────────────────────────────────────

def _to_model(job: dict) -> IntruderJob:
    return IntruderJob(**{k: job[k] for k in IntruderJob.model_fields})


def _build_payload_sets(attack_type: str, positions: list[str], payload_lists: list[list[str]]) -> list[list[str]]:
    n = len(positions)
    if attack_type == "sniper":
        # One list; cycle through positions one at a time
        plist = payload_lists[0] if payload_lists else []
        sets = []
        for pos_idx in range(n):
            for payload in plist:
                row = [pos for pos in positions]  # defaults: original text
                row[pos_idx] = payload
                sets.append(row)
        return sets
    elif attack_type == "battering_ram":
        plist = payload_lists[0] if payload_lists else []
        return [[p] * n for p in plist]
    elif attack_type == "pitchfork":
        from itertools import zip_longest
        padded = list(zip_longest(*payload_lists, fillvalue=""))
        return [list(row) for row in padded]
    elif attack_type == "cluster_bomb":
        from itertools import product
        return [list(combo) for combo in product(*payload_lists)]
    return []


def _apply_payloads(template: str, payload_values: list[str]) -> str:
    result = template
    for val in payload_values:
        result = POSITION_RE.sub(val, result, count=1)
    return result


def _parse_raw_request(raw: str, target_url: str):
    """Parse a raw HTTP request string into method, url, headers, body."""
    lines = raw.replace('\r\n', '\n').split('\n')
    if not lines:
        return "GET", target_url, {}, None

    # First line: METHOD PATH HTTP/1.1
    parts = lines[0].split(' ')
    method = parts[0].upper() if parts else "GET"
    path = parts[1] if len(parts) > 1 else "/"

    parsed_target = urlparse(target_url)
    base = f"{parsed_target.scheme}://{parsed_target.netloc}"
    url = base + path if path.startswith('/') else target_url

    headers: dict[str, str] = {}
    body_start = None
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == "":
            body_start = i + 1
            break
        if ':' in line:
            k, _, v = line.partition(':')
            headers[k.strip()] = v.strip()

    body = '\n'.join(lines[body_start:]).strip() if body_start else None
    return method, url, headers, body


async def _execute(job: dict, req: IntruderRequest, payload_sets: list[list[str]]) -> None:
    sem = asyncio.Semaphore(req.concurrency)

    async def _fire(idx: int, payload_values: list[str]) -> None:
        async with sem:
            filled = _apply_payloads(req.raw_request, payload_values)
            method, url, headers, body = _parse_raw_request(filled, req.target_url)
            start = time.monotonic()
            try:
                async with httpx.AsyncClient(
                    timeout=req.timeout,
                    follow_redirects=req.follow_redirects,
                    verify=False,
                ) as client:
                    r = await client.request(method, url, headers=headers, content=body)
                elapsed = round((time.monotonic() - start) * 1000)
                job["results"].append({
                    "idx": idx,
                    "payloads": payload_values,
                    "status": r.status_code,
                    "length": len(r.content),
                    "time_ms": elapsed,
                    "error": None,
                })
            except Exception as exc:
                elapsed = round((time.monotonic() - start) * 1000)
                job["results"].append({
                    "idx": idx,
                    "payloads": payload_values,
                    "status": None,
                    "length": 0,
                    "time_ms": elapsed,
                    "error": str(exc),
                })
            finally:
                job["completed"] += 1

    try:
        await asyncio.gather(*[_fire(i, pvs) for i, pvs in enumerate(payload_sets)])
        job["status"] = "complete"
    except Exception as exc:
        job["status"] = "error"
        job["error"] = str(exc)
