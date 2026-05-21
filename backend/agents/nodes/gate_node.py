"""
Node 03 — Human Review Gate.

Pauses the LangGraph pipeline using interrupt() so a human can approve or
deny progression to PoC validation.

Flow:
  1. Summarise findings using Claude.
  2. Call interrupt() — graph checkpoints and pauses here.
  3. External system receives interrupt payload via WebSocket / API response.
  4. POST /api/v1/pipeline/{run_id}/resume with {"decision": "approved"|"denied"}
     triggers graph.ainvoke(Command(resume=decision), config).
  5. Node returns gate_decision into state.
"""
import json

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from agents.llm import get_exploit_llm
from agents.state import AgentState
from langgraph.types import interrupt

logger = structlog.get_logger()

_SUMMARY_SYSTEM = """You are a senior security analyst writing a concise executive summary
for a human reviewer who must decide whether to proceed with PoC exploitation.

Given the list of findings, write 3–5 sentences covering:
- Total finding count and severity breakdown
- The two most critical vulnerabilities and their impact
- Recommendation (proceed / do not proceed)

Be direct and factual. No fluff.
"""


async def gate_node(state: AgentState) -> dict:
    findings = state.get("exploit_findings", [])
    logger.info("gate_node: preparing interrupt", run_id=state["run_id"], findings=len(findings))

    # ── Summarise findings with Claude ────────────────────────────────────────
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    summary_resp = await get_exploit_llm().ainvoke(
        [
            SystemMessage(content=_SUMMARY_SYSTEM),
            HumanMessage(
                content=(
                    f"Target: {state['target_url']}\n"
                    f"Findings ({len(findings)} total):\n"
                    f"{json.dumps(findings, indent=2)}"
                )
            ),
        ]
    )
    summary = summary_resp.content if isinstance(summary_resp.content, str) else str(summary_resp.content)

    # ── Interrupt — graph pauses here until resume is called ──────────────────
    interrupt_payload = {
        "run_id": state["run_id"],
        "summary": summary,
        "severity_breakdown": severity_counts,
        "finding_count": len(findings),
        "critical_findings": [f for f in findings if f.get("severity") in ("critical", "high")][:5],
    }

    decision: str = interrupt(interrupt_payload)

    logger.info("gate_node resumed", run_id=state["run_id"], decision=decision)
    return {
        "gate_decision": decision,
        "gate_summary": summary,
        "status": "poc_validation" if decision == "approved" else "denied",
    }
