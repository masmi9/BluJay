import asyncio
import json

from pathlib import Path
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models.jwt_test import JwtTest
from schemas.jwt_test import JwtBruteForceResult, JwtDecodeResult, JwtTestCreate, JwtTestOut

router = APIRouter()

_DEFAULT_WORDLIST = Path(__file__).parent.parent / "wordlists" / "jwt_secrets.txt"

# test_id -> asyncio.Queue for brute-force progress
_brute_queues: dict[int, asyncio.Queue] = {}

def get_brute_queue(test_id: int) -> asyncio.Queue | None:
    return _brute_queues.get(test_id)

@router.post("/decode", response_model=JwtDecodeResult)
async def decode_token(body: JwtTestCreate, db: AsyncSession = Depends(get_db)):
    from core.jwt_attacker import decode_jwt, forge_alg_none, test_kid_injection, escalate_roles

    try:
        decoded = decode_jwt(body.token)
    except Exception as exc:
        raise HTTPException(400, f"Invalid JWT: {exc}")

    alg_none = forge_alg_none(body.token)
    kid_tokens = test_kid_injection(body.token)
    role_tokens = escalate_roles(body.token)

    # Persist
    jt = JwtTest(
        session_id=body.session_id,
        analysis_id=body.analysis_id,
        raw_token=body.token,
        decoded_header=json.dumps(decoded["header"]),
        decoded_payload=json.dumps(decoded["payload"]),
        alg_none_token=alg_none,
        kid_injection_payloads=json.dumps(kid_tokens),
        role_escalation_tokens=json.dumps(role_tokens),
    )
    db.add(jt)
    await db.commit()

    return JwtDecodeResult(
        header=decoded["header"],
        payload=decoded["payload"],
        alg_none_token=alg_none,
        kid_tokens=kid_tokens,
        role_tokens=role_tokens,
    )


@router.post("/brute-force/{test_id}", response_model=dict)
async def start_brute_force(
    test_id: int,
    background_tasks: BackgroundTasks,
    wordlist: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    jt = await db.get(JwtTest, test_id)
    if not jt:
        raise HTTPException(404, "JWT test not found")

    wl = wordlist or str(_DEFAULT_WORDLIST)
    queue: asyncio.Queue = asyncio.Queue()
    _brute_queues[test_id] = queue

    async def _run():
        from core.jwt_attacker import brute_force_hmac
        result = await brute_force_hmac(jt.raw_token, wl, queue)
        if result["found"]:
            jt.hmac_secret_found = result["secret"]
            jt.notes = (jt.notes or "") + f"\nHMAC secret found: {result['secret']}"
            async with db.begin_nested():
                db.add(jt)
            await db.commit()
        _brute_queues.pop(test_id, None)

    background_tasks.add_task(_run)
    return {"status": "started", "test_id": test_id}


@router.post("/forge", response_model=dict)
async def forge_attacks(body: JwtTestCreate):
    from core.jwt_attacker import forge_alg_none, test_kid_injection, escalate_roles, rs256_to_hs256

    try:
        alg_none = forge_alg_none(body.token)
        kids = test_kid_injection(body.token)
        roles = escalate_roles(body.token)
    except Exception as exc:
        raise HTTPException(400, str(exc))

    return {
        "alg_none": alg_none,
        "kid_injection": kids,
        "role_escalation": roles,
    }


@router.get("/tests", response_model=list[JwtTestOut])
async def list_tests(
    session_id: int | None = Query(None),
    analysis_id: int | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(JwtTest).order_by(JwtTest.created_at.desc())
    if session_id is not None:
        q = q.where(JwtTest.session_id == session_id)
    if analysis_id is not None:
        q = q.where(JwtTest.analysis_id == analysis_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/from-flows", response_model=list[str])
async def scan_flows(session_id: int = Query(...), db: AsyncSession = Depends(get_db)):
    from models.session import ProxyFlow
    from core.jwt_attacker import scan_flows_for_jwts

    result = await db.execute(
        select(ProxyFlow).where(ProxyFlow.session_id == session_id)
    )
    flows = result.scalars().all()
    return scan_flows_for_jwts(flows)
