"""
API Testing module router.

Endpoints:
  GET  /api-testing/suites                              — list suites
  POST /api-testing/suites                              — create suite
  GET  /api-testing/suites/{id}                         — get suite
  POST /api-testing/suites/{id}/import-flows            — rebuild context from proxy flows
  GET  /api-testing/suites/{id}/tests                   — list tests
  POST /api-testing/suites/{id}/tests                   — create test
  POST /api-testing/suites/{id}/tests/bulk-create       — create multiple tests at once
  POST /api-testing/suites/{id}/tests/{tid}/run         — execute test (background)
  GET  /api-testing/suites/{id}/tests/{tid}/results     — get test results
  DELETE /api-testing/suites/{id}/tests/{tid}/results   — clear results (reset)
  POST /api-testing/suites/{id}/tests/{tid}/export      — export findings to analysis
  POST /api-testing/suites/{id}/fuzz                    — run fuzzing sweep on suite flows
"""
from __future__ import annotations

import json

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import AsyncSessionLocal, get_db
from models.api_testing import ApiTest, ApiTestResult, ApiTestSuite

router = APIRouter()


# ── Pydantic schemas ─────────────────────────────────────────────────────────

class SuiteCreate(BaseModel):
    name: str
    session_id: int | None = None
    analysis_id: int | None = None
    target_app: str | None = None
    platform: str = "android"


class TestCreate(BaseModel):
    test_type: str   # idor_sweep | auth_strip | token_replay | cross_user_auth
    name: str
    description: str | None = None
    method: str = "GET"
    url: str
    headers: dict = {}
    body: str | None = None
    config: dict = {}


class FuzzRequest(BaseModel):
    """Kick off an API fuzzer sweep against all captured flows for this suite."""
    session_id: int | None = None
    analysis_id: int | None = None
    attacks: list[str] = ["sqli", "xss", "path_traversal", "ssti"]


# ── Serialisation helpers ────────────────────────────────────────────────────

def _j(s: str | None, default):
    if not s:
        return default
    try:
        return json.loads(s)
    except Exception:
        return default


def _suite_out(suite: ApiTestSuite, test_count: int) -> dict:
    return {
        "id": suite.id,
        "name": suite.name,
        "target_app": suite.target_app,
        "platform": suite.platform,
        "status": suite.status,
        "flow_count": suite.flow_count or 0,
        "session_id": suite.session_id,
        "analysis_id": suite.analysis_id,
        "auth_contexts": _j(suite.auth_contexts_json, []),
        "collected_ids": _j(suite.collected_ids_json, {}),
        "test_count": test_count,
    }


def _test_out(test: ApiTest, result_count: int = 0) -> dict:
    return {
        "id": test.id,
        "suite_id": test.suite_id,
        "test_type": test.test_type,
        "name": test.name,
        "description": test.description,
        "method": test.method,
        "url": test.url,
        "headers": _j(test.headers_json, {}),
        "body": test.body,
        "config": _j(test.config_json, {}),
        "status": test.status,
        "run_count": test.run_count or 0,
        "vulnerable_count": test.vulnerable_count or 0,
        "result_count": result_count,
    }


def _result_out(r: ApiTestResult) -> dict:
    return {
        "id": r.id,
        "test_id": r.test_id,
        "label": r.label,
        "request_method": r.request_method,
        "request_url": r.request_url,
        "request_headers": _j(r.request_headers_json, {}),
        "request_body": r.request_body,
        "response_status": r.response_status,
        "response_headers": _j(r.response_headers_json, {}),
        "response_body": r.response_body,
        "duration_ms": r.duration_ms,
        "is_vulnerable": r.is_vulnerable or False,
        "finding": r.finding,
        "severity": r.severity,
        "diff_summary": r.diff_summary,
    }


# ── Suite routes ─────────────────────────────────────────────────────────────

@router.get("/suites")
async def list_suites(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(ApiTestSuite).order_by(ApiTestSuite.id.desc()))
    suites = res.scalars().all()
    out = []
    for s in suites:
        tc = await db.execute(select(ApiTest).where(ApiTest.suite_id == s.id))
        out.append(_suite_out(s, len(tc.scalars().all())))
    return out


@router.post("/suites", status_code=201)
async def create_suite(body: SuiteCreate, db: AsyncSession = Depends(get_db)):
    suite = ApiTestSuite(
        name=body.name,
        session_id=body.session_id,
        analysis_id=body.analysis_id,
        target_app=body.target_app,
        platform=body.platform,
        status="building",
    )
    db.add(suite)
    await db.commit()
    await db.refresh(suite)
    return _suite_out(suite, 0)


@router.get("/suites/{suite_id}")
async def get_suite(suite_id: int, db: AsyncSession = Depends(get_db)):
    suite = await db.get(ApiTestSuite, suite_id)
    if not suite:
        raise HTTPException(404, "Suite not found")
    tc = await db.execute(select(ApiTest).where(ApiTest.suite_id == suite_id))
    return _suite_out(suite, len(tc.scalars().all()))


@router.post("/suites/{suite_id}/import-flows")
async def import_flows(suite_id: int, db: AsyncSession = Depends(get_db)):
    """
    Scan all proxy flows for suite.session_id and rebuild the context:
    auth_contexts, collected_ids, and return suggested test cases.
    """
    suite = await db.get(ApiTestSuite, suite_id)
    if not suite:
        raise HTTPException(404, "Suite not found")
    if not suite.session_id:
        raise HTTPException(400, "Suite has no linked session — attach a session_id first")

    from core.api_context_builder import build_suite_context
    ctx = await build_suite_context(suite.session_id, db)

    suite.auth_contexts_json = json.dumps(ctx["auth_contexts"])
    suite.collected_ids_json = json.dumps(ctx["collected_ids"])
    suite.flow_count = ctx["flow_count"]
    suite.status = "ready"
    await db.commit()

    return {
        "ok": True,
        "flow_count": ctx["flow_count"],
        "auth_contexts": ctx["auth_contexts"],
        "collected_ids": ctx["collected_ids"],
        "suggested_tests": ctx["suggested_tests"],
    }


# ── Test routes ──────────────────────────────────────────────────────────────

@router.get("/suites/{suite_id}/tests")
async def list_tests(suite_id: int, db: AsyncSession = Depends(get_db)):
    res = await db.execute(
        select(ApiTest).where(ApiTest.suite_id == suite_id).order_by(ApiTest.id)
    )
    tests = res.scalars().all()
    out = []
    for t in tests:
        rc = await db.execute(select(ApiTestResult).where(ApiTestResult.test_id == t.id))
        out.append(_test_out(t, len(rc.scalars().all())))
    return out


@router.post("/suites/{suite_id}/tests", status_code=201)
async def create_test(suite_id: int, body: TestCreate, db: AsyncSession = Depends(get_db)):
    suite = await db.get(ApiTestSuite, suite_id)
    if not suite:
        raise HTTPException(404, "Suite not found")
    test = ApiTest(
        suite_id=suite_id,
        test_type=body.test_type,
        name=body.name,
        description=body.description,
        method=body.method,
        url=body.url,
        headers_json=json.dumps(body.headers),
        body=body.body,
        config_json=json.dumps(body.config),
        status="pending",
    )
    db.add(test)
    await db.commit()
    await db.refresh(test)
    return _test_out(test, 0)


@router.post("/suites/{suite_id}/tests/bulk-create", status_code=201)
async def bulk_create_tests(
    suite_id: int,
    tests: list[TestCreate],
    db: AsyncSession = Depends(get_db),
):
    """Create multiple tests at once (used by 'Add All Suggested' action)."""
    suite = await db.get(ApiTestSuite, suite_id)
    if not suite:
        raise HTTPException(404, "Suite not found")
    rows = []
    for body in tests:
        row = ApiTest(
            suite_id=suite_id,
            test_type=body.test_type,
            name=body.name,
            description=body.description,
            method=body.method,
            url=body.url,
            headers_json=json.dumps(body.headers),
            body=body.body,
            config_json=json.dumps(body.config),
            status="pending",
        )
        db.add(row)
        rows.append(row)
    await db.commit()
    return {"ok": True, "created": len(rows)}


@router.post("/suites/{suite_id}/tests/{test_id}/run")
async def run_test(
    suite_id: int,
    test_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    test = await db.get(ApiTest, test_id)
    if not test or test.suite_id != suite_id:
        raise HTTPException(404, "Test not found")
    if test.status == "running":
        raise HTTPException(409, "Test is already running")

    from core.api_test_engine import register_test_queue, run_test as _run
    register_test_queue(test_id)
    background_tasks.add_task(_run, test_id, AsyncSessionLocal)
    return {"ok": True, "test_id": test_id}


@router.get("/suites/{suite_id}/tests/{test_id}/results")
async def get_results(suite_id: int, test_id: int, db: AsyncSession = Depends(get_db)):
    test = await db.get(ApiTest, test_id)
    if not test or test.suite_id != suite_id:
        raise HTTPException(404, "Test not found")
    res = await db.execute(
        select(ApiTestResult).where(ApiTestResult.test_id == test_id).order_by(ApiTestResult.id)
    )
    return [_result_out(r) for r in res.scalars().all()]


@router.delete("/suites/{suite_id}/tests/{test_id}/results")
async def clear_results(suite_id: int, test_id: int, db: AsyncSession = Depends(get_db)):
    """Reset a test back to pending and delete all its results."""
    test = await db.get(ApiTest, test_id)
    if not test or test.suite_id != suite_id:
        raise HTTPException(404, "Test not found")
    from sqlalchemy import delete as _del
    await db.execute(_del(ApiTestResult).where(ApiTestResult.test_id == test_id))
    test.status = "pending"
    test.run_count = 0
    test.vulnerable_count = 0
    await db.commit()
    return {"ok": True}


@router.post("/suites/{suite_id}/tests/{test_id}/export")
async def export_finding(suite_id: int, test_id: int, db: AsyncSession = Depends(get_db)):
    """
    Export vulnerable ApiTestResults as StaticFinding rows on the suite's analysis.
    Requires suite.analysis_id to be set.
    """
    suite = await db.get(ApiTestSuite, suite_id)
    test = await db.get(ApiTest, test_id)
    if not suite or not test:
        raise HTTPException(404, "Suite or test not found")
    if not suite.analysis_id:
        raise HTTPException(400, "Suite is not linked to an analysis — set analysis_id first")

    res = await db.execute(
        select(ApiTestResult).where(
            ApiTestResult.test_id == test_id,
            ApiTestResult.is_vulnerable == True,  # noqa: E712
        )
    )
    vuln = res.scalars().all()
    if not vuln:
        raise HTTPException(400, "No vulnerable results to export")

    from models.analysis import StaticFinding
    for r in vuln:
        db.add(StaticFinding(
            analysis_id=suite.analysis_id,
            category="api_testing",
            severity=r.severity or "high",
            title=test.name,
            description=r.finding or test.description or test.name,
            file_path=r.request_url,
            evidence=json.dumps({
                "match": f"{r.request_method} {r.request_url} → HTTP {r.response_status}",
                "context": (r.response_body or "")[:500],
            }),
            rule_id=f"api_test_{test.test_type}",
        ))
    await db.commit()
    return {"ok": True, "exported": len(vuln)}


# ── Integrated fuzzer ────────────────────────────────────────────────────────

@router.post("/suites/{suite_id}/fuzz", status_code=201)
async def fuzz_suite(
    suite_id: int,
    body: FuzzRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Delegate to the existing API fuzzer engine against all flows captured for
    this suite's session (or the provided session_id override).

    Creates a FuzzJob and returns its id so the caller can subscribe to
    /ws/fuzzing/{job_id} for real-time progress.
    """
    from models.fuzzing import FuzzJob
    from models.session import ProxyFlow
    from core.api_fuzzer import extract_endpoints_from_flows, run_fuzz_job

    # Resolve session to read flows from
    suite = await db.get(ApiTestSuite, suite_id)
    if not suite:
        raise HTTPException(404, "Suite not found")

    effective_session = body.session_id or suite.session_id
    effective_analysis = body.analysis_id or suite.analysis_id

    specs: list[dict] = []
    if effective_session:
        res = await db.execute(
            select(ProxyFlow).where(ProxyFlow.session_id == effective_session)
        )
        flows = res.scalars().all()
        specs.extend(extract_endpoints_from_flows(flows))

    if not specs:
        raise HTTPException(
            400,
            "No proxy flows found for this suite's session. "
            "Start a proxy session and capture some traffic first.",
        )

    job = FuzzJob(
        session_id=effective_session,
        analysis_id=effective_analysis,
        attacks=json.dumps(body.attacks),
        endpoint_count=len(specs),
        status="pending",
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    from database import AsyncSessionLocal as _sl
    from api.fuzzing import _fuzz_queues
    import asyncio
    _fuzz_queues[job.id] = asyncio.Queue(maxsize=2000)
    background_tasks.add_task(run_fuzz_job, job.id, specs, _sl)

    return {"ok": True, "fuzz_job_id": job.id, "endpoint_count": len(specs)}
