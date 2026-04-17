"""
Diff / Change Detection API.

POST /diff          — compute a diff between two analyses and persist it
GET  /diff          — list all diffs
GET  /diff/{id}     — retrieve a specific diff
DELETE /diff/{id}   — remove a diff record
"""
import json
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.analysis import Analysis, StaticFinding
from models.analysis_diff import AnalysisDiff
from schemas.diff import DiffOut, DiffRequest, DiffSummary, FindingSnap

router = APIRouter()


def _finding_key(f: StaticFinding) -> str:
    """Stable key for deduplication: prefer rule_id, fall back to category+title."""
    return f.rule_id if f.rule_id else f"{f.category}::{f.title}"


def _snap(f: StaticFinding) -> dict:
    return {
        "category": f.category,
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "file_path": f.file_path,
        "rule_id": f.rule_id,
    }


async def _compute_diff(
    baseline_id: int,
    target_id: int,
    diff_type: str,
    db: AsyncSession,
) -> AnalysisDiff:
    # ── load both analyses ────────────────────────────────────────────────
    b_row = await db.scalar(select(Analysis).where(Analysis.id == baseline_id))
    t_row = await db.scalar(select(Analysis).where(Analysis.id == target_id))
    if not b_row:
        raise HTTPException(404, f"Baseline analysis {baseline_id} not found")
    if not t_row:
        raise HTTPException(404, f"Target analysis {target_id} not found")

    # ── static findings diff ──────────────────────────────────────────────
    b_findings_q = await db.execute(
        select(StaticFinding).where(StaticFinding.analysis_id == baseline_id)
    )
    t_findings_q = await db.execute(
        select(StaticFinding).where(StaticFinding.analysis_id == target_id)
    )
    b_findings = {_finding_key(f): f for f in b_findings_q.scalars().all()}
    t_findings = {_finding_key(f): f for f in t_findings_q.scalars().all()}

    added_keys = set(t_findings) - set(b_findings)
    removed_keys = set(b_findings) - set(t_findings)

    added_snaps = [_snap(t_findings[k]) for k in sorted(added_keys)]
    removed_snaps = [_snap(b_findings[k]) for k in sorted(removed_keys)]

    # severity delta
    b_sev = Counter(f.severity for f in b_findings.values())
    t_sev = Counter(f.severity for f in t_findings.values())
    all_sevs = set(b_sev) | set(t_sev)
    severity_delta = {s: t_sev.get(s, 0) - b_sev.get(s, 0) for s in all_sevs if t_sev.get(s, 0) - b_sev.get(s, 0) != 0}

    # ── permissions diff ──────────────────────────────────────────────────
    # Permissions live in static_findings with category "dangerous_permission"
    b_perms = {f.title for f in b_findings.values() if f.category == "dangerous_permission"}
    t_perms = {f.title for f in t_findings.values() if f.category == "dangerous_permission"}
    added_perms = sorted(t_perms - b_perms)
    removed_perms = sorted(b_perms - t_perms)

    # ── human-readable summary ────────────────────────────────────────────
    parts = []
    if added_snaps:
        parts.append(f"+{len(added_snaps)} finding(s)")
    if removed_snaps:
        parts.append(f"-{len(removed_snaps)} finding(s)")
    if added_perms:
        parts.append(f"+{len(added_perms)} permission(s)")
    if removed_perms:
        parts.append(f"-{len(removed_perms)} permission(s)")
    summary = ", ".join(parts) if parts else "No changes detected"

    diff = AnalysisDiff(
        baseline_id=baseline_id,
        target_id=target_id,
        diff_type=diff_type,
        added_findings=json.dumps(added_snaps),
        removed_findings=json.dumps(removed_snaps),
        added_permissions=json.dumps(added_perms),
        removed_permissions=json.dumps(removed_perms),
        severity_delta=json.dumps(severity_delta),
        summary=summary,
    )
    db.add(diff)
    await db.commit()
    await db.refresh(diff)
    return diff


def _deserialize(diff: AnalysisDiff) -> DiffOut:
    return DiffOut(
        id=diff.id,
        created_at=diff.created_at,
        baseline_id=diff.baseline_id,
        target_id=diff.target_id,
        diff_type=diff.diff_type,
        added_findings=[FindingSnap(**f) for f in json.loads(diff.added_findings or "[]")],
        removed_findings=[FindingSnap(**f) for f in json.loads(diff.removed_findings or "[]")],
        added_permissions=json.loads(diff.added_permissions or "[]"),
        removed_permissions=json.loads(diff.removed_permissions or "[]"),
        severity_delta=json.loads(diff.severity_delta or "{}"),
        summary=diff.summary,
    )


@router.post("", response_model=DiffOut, status_code=201)
async def create_diff(body: DiffRequest, db: AsyncSession = Depends(get_db)):
    """Compute and persist a diff between two analyses."""
    diff = await _compute_diff(body.baseline_id, body.target_id, body.diff_type, db)
    return _deserialize(diff)


@router.get("", response_model=list[DiffSummary])
async def list_diffs(db: AsyncSession = Depends(get_db)):
    rows = await db.execute(select(AnalysisDiff).order_by(AnalysisDiff.created_at.desc()))
    return rows.scalars().all()


@router.get("/{diff_id}", response_model=DiffOut)
async def get_diff(diff_id: int, db: AsyncSession = Depends(get_db)):
    diff = await db.scalar(select(AnalysisDiff).where(AnalysisDiff.id == diff_id))
    if not diff:
        raise HTTPException(404, "Diff not found")
    return _deserialize(diff)


@router.delete("/{diff_id}", status_code=204)
async def delete_diff(diff_id: int, db: AsyncSession = Depends(get_db)):
    diff = await db.scalar(select(AnalysisDiff).where(AnalysisDiff.id == diff_id))
    if not diff:
        raise HTTPException(404, "Diff not found")
    await db.delete(diff)
    await db.commit()
