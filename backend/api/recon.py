"""
Recon API — subdomain enum + cloud bucket discovery.
"""
from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel

router = APIRouter()

_jobs: dict[int, dict] = {}
_counter = 0


class ReconRequest(BaseModel):
    target: str
    package_name: str | None = None
    check_subdomains: bool = True
    check_buckets: bool = True
    resolve_hosts: bool = True


@router.post("/start")
async def start_recon(req: ReconRequest, background_tasks: BackgroundTasks):
    global _counter
    _counter += 1
    job_id = _counter
    _jobs[job_id] = {"id": job_id, "target": req.target, "status": "running", "result": None, "error": None}
    background_tasks.add_task(_run, job_id, req)
    return {"job_id": job_id, "status": "running"}


async def _run(job_id: int, req: ReconRequest) -> None:
    from core.recon_engine import run_recon
    try:
        result = await run_recon(
            target=req.target,
            package_name=req.package_name,
            check_subdomains=req.check_subdomains,
            check_buckets=req.check_buckets,
            resolve_hosts=req.resolve_hosts,
        )
        _jobs[job_id]["status"] = "done"
        _jobs[job_id]["result"] = {
            "target": result.target,
            "subdomains": result.subdomains,
            "resolved_hosts": result.resolved_hosts,
            "open_buckets": result.open_buckets,
            "findings": [
                {
                    "type": f.type, "host": f.host, "detail": f.detail,
                    "severity": f.severity, "resolved_ip": f.resolved_ip,
                    "status_code": f.status_code,
                }
                for f in result.findings
            ],
        }
    except Exception as e:
        _jobs[job_id]["status"] = "error"
        _jobs[job_id]["error"] = str(e)


@router.get("/{job_id}")
async def get_recon(job_id: int):
    job = _jobs.get(job_id)
    if not job:
        from fastapi import HTTPException
        raise HTTPException(404, "Job not found")
    return job


@router.get("")
async def list_recon():
    return list(_jobs.values())
