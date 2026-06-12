from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter()


class IDORConfigRequest(BaseModel):
    enabled: bool = False
    victim_auth: str = ""
    victim_auth_header: str = "Authorization"
    attacker_auth: str = ""
    attacker_auth_header: str = "Authorization"
    cooldown_seconds: float = 0.3
    test_unauthenticated: bool = True


@router.post("/configure")
async def configure_idor(session_id: int = Query(...), body: IDORConfigRequest = ...):
    from api.router import get_idor_interceptor
    from core.idor_interceptor import IDORConfig
    cfg = IDORConfig(
        enabled=body.enabled,
        victim_auth=body.victim_auth,
        victim_auth_header=body.victim_auth_header,
        attacker_auth=body.attacker_auth,
        attacker_auth_header=body.attacker_auth_header,
        cooldown_seconds=body.cooldown_seconds,
        test_unauthenticated=body.test_unauthenticated,
    )
    get_idor_interceptor().configure(session_id, cfg)
    return {"ok": True, "enabled": body.enabled}


@router.get("/stats")
async def get_idor_stats(session_id: int = Query(...)):
    from api.router import get_idor_interceptor
    return get_idor_interceptor().get_stats(session_id)


@router.get("/findings")
async def get_idor_findings(session_id: int = Query(...)):
    from api.router import get_idor_interceptor
    return {"findings": get_idor_interceptor().get_findings(session_id)}


@router.delete("/clear")
async def clear_idor(session_id: int = Query(...)):
    from api.router import get_idor_interceptor
    get_idor_interceptor().clear(session_id)
    return {"ok": True}
