"""
Domain OSINT API — full passive + active enumeration.
"""
import asyncio

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

router = APIRouter()

_jobs: dict[int, dict] = {}
_counter = 0


class DomainOsintRequest(BaseModel):
    target: str
    dns_baseline: bool = True
    crtsh: bool = True
    passive_dns: bool = True
    shodan: bool = True
    external_dns_txt: bool = True
    brute_force: bool = False
    wordlist_path: str | None = None
    brute_workers: int = 300


@router.post("/start")
async def start_osint(req: DomainOsintRequest, background_tasks: BackgroundTasks):
    global _counter
    _counter += 1
    job_id = _counter
    _jobs[job_id] = {
        "id": job_id,
        "target": req.target,
        "status": "running",
        "result": None,
        "error": None,
    }
    background_tasks.add_task(_run, job_id, req)
    return {"job_id": job_id, "status": "running"}


async def _run(job_id: int, req: DomainOsintRequest) -> None:
    from core.domain_osint_engine import run_domain_osint
    try:
        result = await run_domain_osint(
            target=req.target,
            dns_baseline=req.dns_baseline,
            crtsh=req.crtsh,
            passive_dns=req.passive_dns,
            shodan=req.shodan,
            external_dns_txt=req.external_dns_txt,
        )

        # Optional brute-force step
        if req.brute_force and req.wordlist_path:
            from pathlib import Path
            from core.dnsbrute2 import brute_force_async
            import re

            domain = re.sub(r"https?://", "", req.target).split("/")[0].split(":")[0].lower()
            wl_path = Path(req.wordlist_path)
            if wl_path.exists():
                words = [
                    line.strip().lower()
                    for line in wl_path.read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.strip() and not line.startswith("#")
                ]
                brute_hits = await brute_force_async(words, [domain], workers=req.brute_workers)
                for hit in brute_hits:
                    if hit.fqdn not in result.subdomains:
                        result.subdomains.append(hit.fqdn)
                    for ip in hit.ips:
                        result.resolved_hosts[hit.fqdn] = ip

        _jobs[job_id]["status"] = "done"
        _jobs[job_id]["result"] = result.to_dict()

    except Exception as e:
        _jobs[job_id]["status"] = "error"
        _jobs[job_id]["error"] = str(e)


@router.get("")
async def list_osint_jobs():
    return list(_jobs.values())


@router.get("/{job_id}")
async def get_osint_job(job_id: int):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@router.delete("/{job_id}")
async def delete_osint_job(job_id: int):
    if job_id not in _jobs:
        raise HTTPException(404, "Job not found")
    del _jobs[job_id]
    return {"status": "deleted"}
