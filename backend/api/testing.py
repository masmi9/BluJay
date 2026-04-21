"""
Testing Lab API — test app registry, test runs, accuracy tracking,
and vulnerability reproduction builder.
"""
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.testing import TestApp, TestRun

router = APIRouter()


# ── Test App registry ─────────────────────────────────────────────────────────

class TestAppCreate(BaseModel):
    display_name: str
    package_name: str
    apk_path: str | None = None
    category: str | None = None
    description: str | None = None
    is_vulnerable_app: bool = False


@router.post("/apps", status_code=201)
async def create_test_app(body: TestAppCreate, db: AsyncSession = Depends(get_db)):
    app = TestApp(**body.model_dump())
    db.add(app)
    await db.commit()
    await db.refresh(app)
    return _app_out(app)


@router.get("/apps")
async def list_test_apps(db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(TestApp).order_by(TestApp.display_name))).scalars().all()
    return [_app_out(r) for r in rows]


@router.get("/apps/{app_id}")
async def get_test_app(app_id: int, db: AsyncSession = Depends(get_db)):
    app = await _app_or_404(app_id, db)
    runs = (
        await db.execute(
            select(TestRun).where(TestRun.test_app_id == app_id).order_by(TestRun.created_at.desc())
        )
    ).scalars().all()
    return {**_app_out(app), "runs": [_run_out(r) for r in runs]}


@router.delete("/apps/{app_id}", status_code=204)
async def delete_test_app(app_id: int, db: AsyncSession = Depends(get_db)):
    app = await _app_or_404(app_id, db)
    await db.delete(app)
    await db.commit()


# ── Test Runs ─────────────────────────────────────────────────────────────────

class TestRunCreate(BaseModel):
    test_app_id: int
    analysis_id: int | None = None
    owasp_scan_id: int | None = None
    frida_script_name: str | None = None
    frida_script_source: str | None = None
    findings: list[dict] = []
    notes: str | None = None


@router.post("/runs", status_code=201)
async def create_test_run(body: TestRunCreate, db: AsyncSession = Depends(get_db)):
    await _app_or_404(body.test_app_id, db)

    reproduction = _build_reproduction(body.findings)

    run = TestRun(
        test_app_id=body.test_app_id,
        analysis_id=body.analysis_id,
        owasp_scan_id=body.owasp_scan_id,
        frida_script_name=body.frida_script_name,
        frida_script_source=body.frida_script_source,
        findings_json=json.dumps(body.findings),
        reproduction_steps=json.dumps(reproduction),
        notes=body.notes,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    return _run_out(run)


@router.get("/runs/{run_id}")
async def get_test_run(run_id: int, db: AsyncSession = Depends(get_db)):
    run = await _run_or_404(run_id, db)
    return _run_out(run)


class AccuracyUpdate(BaseModel):
    true_positives: int
    false_positives: int
    false_negatives: int = 0
    notes: str | None = None


@router.patch("/runs/{run_id}/accuracy")
async def update_accuracy(run_id: int, body: AccuracyUpdate, db: AsyncSession = Depends(get_db)):
    run = await _run_or_404(run_id, db)
    run.true_positives = body.true_positives
    run.false_positives = body.false_positives
    run.false_negatives = body.false_negatives
    if body.notes:
        run.notes = body.notes
    await db.commit()
    return _run_out(run)


@router.delete("/runs/{run_id}", status_code=204)
async def delete_run(run_id: int, db: AsyncSession = Depends(get_db)):
    run = await _run_or_404(run_id, db)
    await db.delete(run)
    await db.commit()


# ── Accuracy dashboard ────────────────────────────────────────────────────────

@router.get("/accuracy")
async def accuracy_dashboard(db: AsyncSession = Depends(get_db)):
    """Aggregate precision/recall across all test runs."""
    runs = (await db.execute(select(TestRun))).scalars().all()
    total_tp = sum(r.true_positives for r in runs)
    total_fp = sum(r.false_positives for r in runs)
    total_fn = sum(r.false_negatives for r in runs)

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else None
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else None
    f1 = (2 * precision * recall / (precision + recall)) if (precision and recall) else None

    return {
        "total_runs": len(runs),
        "total_tp": total_tp,
        "total_fp": total_fp,
        "total_fn": total_fn,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
    }


# ── Reproduction builder ──────────────────────────────────────────────────────

class ReproductionRequest(BaseModel):
    findings: list[dict]


@router.post("/reproduce")
async def build_reproduction(body: ReproductionRequest):
    """
    Given a list of findings (from static, OWASP, or Frida), generate
    structured reproduction steps for a vulnerability report.
    """
    steps = _build_reproduction(body.findings)
    return {"steps": steps}


# ── internals ─────────────────────────────────────────────────────────────────

def _build_reproduction(findings: list[dict]) -> list[dict]:
    """
    Build a structured reproduction block for each finding.
    Each step has: title, description, commands[], expected_output, evidence.
    """
    steps = []
    for i, f in enumerate(findings, 1):
        title = f.get("title") or f.get("name") or f"Finding {i}"
        severity = (f.get("severity") or f.get("risk_level") or "unknown").upper()
        category = f.get("category") or f.get("type") or ""
        description = f.get("description") or ""
        evidence = f.get("evidence") or f.get("match") or ""
        file_path = f.get("file_path") or ""
        package = f.get("package") or ""
        cwe = f.get("cwe_id") or ""
        attack_path = f.get("attack_path") or ""

        commands = _infer_commands(f)

        steps.append({
            "step": i,
            "title": f"[{severity}] {title}",
            "category": category,
            "cwe": cwe,
            "description": description,
            "commands": commands,
            "expected_output": _infer_expected(f),
            "evidence": evidence,
            "file_ref": f"{file_path}:{f['line_number']}" if file_path and f.get("line_number") else file_path,
            "attack_path": attack_path,
        })
    return steps


def _infer_commands(f: dict) -> list[str]:
    """Generate runnable PoC commands from finding metadata."""
    cmds = []
    pkg = f.get("package") or f.get("component", {}).get("package") if isinstance(f.get("component"), dict) else ""
    component = f.get("component") or ""
    category = (f.get("category") or f.get("type") or "").lower()

    if "exported" in category or "component" in category:
        comp_name = (component if isinstance(component, str) else component.get("name", "")) if component else ""
        comp_type = f.get("component_type") or "activity"
        if comp_type == "activity" and comp_name:
            cmds.append(f"adb shell am start -n {pkg}/{comp_name}")
        elif comp_type == "service" and comp_name:
            cmds.append(f"adb shell am startservice -n {pkg}/{comp_name}")
        elif comp_type == "receiver" and comp_name:
            cmds.append(f"adb shell am broadcast -n {pkg}/{comp_name}")
        elif comp_type == "provider" and pkg:
            cmds.append(f'adb shell content query --uri content://{pkg}/')

    if "sql" in category or "injection" in category:
        cmds.append("# Test SQL injection in content provider")
        cmds.append(f"adb shell content query --uri \"content://{pkg}/\" --where \"1=1--\"")

    if "cleartext" in category or "network" in category:
        cmds.append("# Capture traffic with mitmproxy on port 8080")
        cmds.append("adb shell settings put global http_proxy 127.0.0.1:8080")

    if "backup" in (f.get("rule_id") or ""):
        cmds.append(f"adb backup -noapk {pkg} backup.ab")
        cmds.append("java -jar abe.jar unpack backup.ab backup.tar && tar xf backup.tar")

    if "debug" in (f.get("rule_id") or ""):
        cmds.append(f"adb jdwp  # find debuggable PID")
        cmds.append("adb forward tcp:8700 jdwp:<PID>")
        cmds.append("jdb -attach localhost:8700")

    evidence = f.get("evidence") or ""
    if isinstance(evidence, str):
        try:
            ev = json.loads(evidence)
            match = ev.get("match") or ev.get("context") or ""
        except Exception:
            match = evidence
    else:
        match = str(evidence)

    if match and not cmds:
        cmds.append(f"# Evidence found in source — review: {match[:120]}")

    return cmds or ["# Manual verification required — see description above"]


def _infer_expected(f: dict) -> str:
    category = (f.get("category") or f.get("type") or "").lower()
    if "exported" in category:
        return "Component launches without SecurityException — confirms missing access control"
    if "sql" in category or "inject" in category:
        return "Query returns rows or error exposing DB structure — confirms injection"
    if "cleartext" in category or "network" in category:
        return "Plaintext HTTP traffic visible in proxy — confirms unencrypted communication"
    if "secret" in category or "hardcoded" in category:
        return "Secret visible in decompiled source — confirm API access with extracted credential"
    if "backup" in (f.get("rule_id") or ""):
        return "App data directory extracted to backup.tar without root access"
    if "debug" in (f.get("rule_id") or ""):
        return "Debugger attaches to process — can inspect memory and modify runtime state"
    return "Vulnerability confirmed when observed behaviour matches description"


def _app_out(a: TestApp) -> dict:
    return {
        "id": a.id,
        "created_at": a.created_at.isoformat(),
        "display_name": a.display_name,
        "package_name": a.package_name,
        "apk_path": a.apk_path,
        "category": a.category,
        "description": a.description,
        "is_vulnerable_app": a.is_vulnerable_app,
    }


def _run_out(r: TestRun) -> dict:
    findings = json.loads(r.findings_json or "[]")
    steps = json.loads(r.reproduction_steps or "[]")
    tp, fp, fn = r.true_positives, r.false_positives, r.false_negatives
    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else None
    return {
        "id": r.id,
        "created_at": r.created_at.isoformat(),
        "test_app_id": r.test_app_id,
        "analysis_id": r.analysis_id,
        "owasp_scan_id": r.owasp_scan_id,
        "frida_script_name": r.frida_script_name,
        "frida_script_source": r.frida_script_source,
        "findings": findings,
        "finding_count": len(findings),
        "reproduction_steps": steps,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 3) if precision is not None else None,
        "recall": round(recall, 3) if recall is not None else None,
        "notes": r.notes,
    }


async def _app_or_404(app_id: int, db: AsyncSession) -> TestApp:
    row = (await db.execute(select(TestApp).where(TestApp.id == app_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Test app not found")
    return row


async def _run_or_404(run_id: int, db: AsyncSession) -> TestRun:
    row = (await db.execute(select(TestRun).where(TestRun.id == run_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Test run not found")
    return row
