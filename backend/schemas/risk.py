from pydantic import BaseModel


class RiskScore(BaseModel):
    score: int
    grade: str
    breakdown: dict
    finding_count_by_severity: dict[str, int]


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    severity: str | None


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str


class RiskGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
