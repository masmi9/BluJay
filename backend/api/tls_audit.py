import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.tls_audit import TlsAudit
from schemas.tls_audit import TlsAuditOut, TlsAuditRequest

router = APIRouter()


@router.post("/audit", response_model=list[TlsAuditOut])
async def run_audit(body: TlsAuditRequest, db: AsyncSession = Depends(get_db)):
    from core.tls_auditor import audit_host, extract_hosts_from_session

    # Collect (host, port) pairs
    pairs: list[tuple[str, int]] = [(h.strip(), body.port) for h in body.hosts if h.strip()]

    if body.session_id:
        session_pairs = await extract_hosts_from_session(body.session_id, db)
        existing = {p[0] for p in pairs}
        for h, p in session_pairs:
            if h not in existing:
                pairs.append((h, p))

    if not pairs:
        raise HTTPException(400, "No hosts to audit")

    loop = asyncio.get_event_loop()

    async def _audit_one(host: str, port: int) -> TlsAudit:
        result = await loop.run_in_executor(None, audit_host, host, port)
        ta = TlsAudit(
            host=result["host"],
            port=result["port"],
            session_id=body.session_id,
            analysis_id=body.analysis_id,
            status=result["status"],
            cert_subject=result.get("cert_subject"),
            cert_issuer=result.get("cert_issuer"),
            cert_expiry=result.get("cert_expiry"),
            cert_self_signed=result.get("cert_self_signed"),
            tls10_enabled=result["tls10_enabled"],
            tls11_enabled=result["tls11_enabled"],
            tls12_enabled=result["tls12_enabled"],
            tls13_enabled=result["tls13_enabled"],
            hsts_present=result["hsts_present"],
            weak_ciphers=json.dumps(result.get("weak_ciphers", [])),
            findings_json=json.dumps(result.get("findings_json", [])),
            error=result.get("error"),
        )
        db.add(ta)
        return ta

    # Cap concurrency at 5
    sem = asyncio.Semaphore(5)

    async def _limited(host: str, port: int):
        async with sem:
            return await _audit_one(host, port)

    audits = await asyncio.gather(*[_limited(h, p) for h, p in pairs])
    await db.commit()
    for a in audits:
        await db.refresh(a)
    return list(audits)


@router.get("/audits", response_model=list[TlsAuditOut])
async def list_audits(
    session_id: int | None = None,
    analysis_id: int | None = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(TlsAudit).order_by(TlsAudit.audited_at.desc())
    if session_id is not None:
        q = q.where(TlsAudit.session_id == session_id)
    if analysis_id is not None:
        q = q.where(TlsAudit.analysis_id == analysis_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/audits/{audit_id}", response_model=TlsAuditOut)
async def get_audit(audit_id: int, db: AsyncSession = Depends(get_db)):
    ta = await db.get(TlsAudit, audit_id)
    if not ta:
        raise HTTPException(404, "Audit not found")
    return ta
