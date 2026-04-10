from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from schemas.risk import RiskScore, RiskGraph, GraphNode, GraphEdge

router = APIRouter()


@router.get("/{analysis_id}/score", response_model=RiskScore)
async def get_score(analysis_id: int, db: AsyncSession = Depends(get_db)):
    from models.analysis import Analysis
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")

    from core.risk_scorer import compute_risk_score
    result = await compute_risk_score(analysis_id, db)
    return RiskScore(**result)


@router.get("/{analysis_id}/graph", response_model=RiskGraph)
async def get_graph(analysis_id: int, db: AsyncSession = Depends(get_db)):
    from models.analysis import Analysis
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")

    from core.risk_scorer import build_graph
    result = await build_graph(analysis_id, db)
    return RiskGraph(
        nodes=[GraphNode(**n) for n in result["nodes"]],
        edges=[GraphEdge(**e) for e in result["edges"]],
    )
