"""
Risk scoring and graph builder for a completed analysis.
Score is 0-100 (higher = riskier). Grade: A<=20, B<=40, C<=60, D<=80, F>80.
"""
from __future__ import annotations

import structlog

logger = structlog.get_logger()

SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
MAX_SCORE = 100

GRADE_THRESHOLDS = [
    (20, "A"),
    (40, "B"),
    (60, "C"),
    (80, "D"),
    (101, "F"),
]


def _grade(score: float) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score <= threshold:
            return grade
    return "F"


async def compute_risk_score(analysis_id: int, db) -> dict:
    from sqlalchemy import select, func
    from models.analysis import StaticFinding
    from models.cve import CveMatch

    # Static findings breakdown
    result = await db.execute(
        select(StaticFinding.severity, func.count().label("cnt"))
        .where(StaticFinding.analysis_id == analysis_id)
        .group_by(StaticFinding.severity)
    )
    finding_counts: dict[str, int] = {}
    raw_score = 0
    for row in result.all():
        sev = (row.severity or "info").lower()
        cnt = row.cnt
        finding_counts[sev] = cnt
        raw_score += SEVERITY_WEIGHTS.get(sev, 0) * cnt

    # CVE bonus
    cve_result = await db.execute(
        select(CveMatch.severity, func.count().label("cnt"))
        .where(CveMatch.analysis_id == analysis_id)
        .group_by(CveMatch.severity)
    )
    cve_counts: dict[str, int] = {}
    for row in cve_result.all():
        sev = (row.severity or "info").lower()
        cnt = row.cnt
        cve_counts[sev] = cnt
        raw_score += int(SEVERITY_WEIGHTS.get(sev, 0) * cnt * 0.5)  # CVEs count at half weight

    # Normalize to 0-100 (cap denominator at a reasonable maximum)
    # Denominator: assume 100 critical findings = max score.
    # Commercial apps produce high raw scores from binary/permission scanning;
    # calibrated at 100 criticals so large apps don't all saturate at 100/100.
    denominator = 100 * SEVERITY_WEIGHTS["critical"]
    score = min(int((raw_score / denominator) * MAX_SCORE), MAX_SCORE)

    breakdown = {
        "findings": finding_counts,
        "cves": cve_counts,
        "raw_score": raw_score,
    }

    return {
        "score": score,
        "grade": _grade(score),
        "breakdown": breakdown,
        "finding_count_by_severity": finding_counts,
    }


async def build_graph(analysis_id: int, db) -> dict:
    from sqlalchemy import select, distinct
    from models.analysis import Analysis, StaticFinding
    from models.cve import DetectedLibrary, CveMatch
    from models.session import DynamicSession, ProxyFlow

    nodes: list[dict] = []
    edges: list[dict] = []

    def _nid(type_: str, id_: int | str) -> str:
        return f"{type_}:{id_}"

    # Root analysis node
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        return {"nodes": [], "edges": []}

    root_id = _nid("analysis", analysis_id)
    nodes.append({"id": root_id, "type": "analysis", "label": analysis.apk_filename, "severity": None})

    # Static findings (group by category+severity to avoid clutter)
    findings_result = await db.execute(
        select(StaticFinding)
        .where(StaticFinding.analysis_id == analysis_id)
        .order_by(StaticFinding.severity)
        .limit(100)
    )
    for f in findings_result.scalars().all():
        nid = _nid("finding", f.id)
        nodes.append({"id": nid, "type": "finding", "label": f.title[:50], "severity": f.severity})
        edges.append({"source": root_id, "target": nid, "relation": "has_finding"})

    # Detected libraries
    libs_result = await db.execute(
        select(DetectedLibrary).where(DetectedLibrary.analysis_id == analysis_id)
    )
    for lib in libs_result.scalars().all():
        nid = _nid("library", lib.id)
        nodes.append({"id": nid, "type": "library", "label": f"{lib.name}@{lib.version or '?'}", "severity": None})
        edges.append({"source": root_id, "target": nid, "relation": "uses_library"})

        # CVEs per library
        cve_result = await db.execute(
            select(CveMatch).where(CveMatch.library_id == lib.id)
        )
        for cve in cve_result.scalars().all():
            cve_nid = _nid("cve", cve.id)
            nodes.append({"id": cve_nid, "type": "cve", "label": cve.cve_id or cve.osv_id, "severity": cve.severity})
            edges.append({"source": nid, "target": cve_nid, "relation": "has_cve"})

    # Network hosts from proxy flows
    sessions_result = await db.execute(
        select(DynamicSession.id).where(DynamicSession.analysis_id == analysis_id)
    )
    session_ids = [r[0] for r in sessions_result.all()]
    if session_ids:
        hosts_result = await db.execute(
            select(distinct(ProxyFlow.host))
            .where(ProxyFlow.session_id.in_(session_ids))
        )
        for (host,) in hosts_result.all():
            if not host:
                continue
            nid = _nid("host", host)
            nodes.append({"id": nid, "type": "host", "label": host, "severity": None})
            edges.append({"source": root_id, "target": nid, "relation": "contacts_host"})

    return {"nodes": nodes, "edges": edges}
