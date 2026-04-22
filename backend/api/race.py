from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


class RaceRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str = ""
    count: int = 10


@router.post("/run")
async def run_race(body: RaceRequest):
    if not body.url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")
    if body.count < 1 or body.count > 50:
        raise HTTPException(400, "count must be between 1 and 50")

    from core.race_engine import run_race as _run
    results = await _run(
        method=body.method.upper(),
        url=body.url,
        headers=body.headers,
        body=body.body,
        count=body.count,
    )
    return {"results": results}
