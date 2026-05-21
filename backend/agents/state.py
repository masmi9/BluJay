from typing import Annotated, TypedDict

from langgraph.graph.message import add_messages


class AgentState(TypedDict):
    # ── Input ─────────────────────────────────────────────────────────────────
    run_id: str
    target_url: str
    scan_type: str          # "web" | "api"
    session_id: int | None

    # ── Node outputs ──────────────────────────────────────────────────────────
    recon_results: list[dict]
    exploit_findings: list[dict]
    variant_iterations: int
    validated_findings: list[dict]

    report_sarif: dict
    report_summary: str

    # ── Human gate ────────────────────────────────────────────────────────────
    gate_decision: str | None   # "approved" | "denied"
    gate_summary: str

    # ── LLM conversation context ──────────────────────────────────────────────
    messages: Annotated[list, add_messages]

    # ── Control ───────────────────────────────────────────────────────────────
    status: str
    error: str | None
