"""
LangGraph pipeline — BluJay autonomous agent graph (Layer 2).

Topology:
  START → recon → exploit → gate* → poc → report → END
                                  ↘ END (if denied)

  * gate uses interrupt() — graph checkpoints and pauses until
    POST /api/v1/pipeline/{run_id}/resume is called.

Checkpointing: MemorySaver (in-process). State survives the interrupt.
LLM strategy:
  - recon, report → Ollama (local, free)
  - exploit, gate, poc → Claude via Anthropic API (billed)
  Graceful degradation: falls back to Ollama when ANTHROPIC_API_KEY absent.
"""
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from agents.nodes.exploit_node import exploit_node
from agents.nodes.gate_node import gate_node
from agents.nodes.poc_node import poc_node
from agents.nodes.recon_node import recon_node
from agents.nodes.report_node import report_node
from agents.state import AgentState


# ── Routing ────────────────────────────────────────────────────────────────────

def _route_after_gate(state: AgentState) -> str:
    if state.get("gate_decision") == "denied":
        return END
    return "poc"


# ── Graph assembly ─────────────────────────────────────────────────────────────

_workflow = StateGraph(AgentState)

_workflow.add_node("recon", recon_node)
_workflow.add_node("exploit", exploit_node)
_workflow.add_node("gate", gate_node)
_workflow.add_node("poc", poc_node)
_workflow.add_node("report", report_node)

_workflow.add_edge(START, "recon")
_workflow.add_edge("recon", "exploit")
_workflow.add_edge("exploit", "gate")
_workflow.add_conditional_edges("gate", _route_after_gate, {"poc": "poc", END: END})
_workflow.add_edge("poc", "report")
_workflow.add_edge("report", END)

_checkpointer = MemorySaver()

# Compile — gate_node calls interrupt() internally after building the finding
# summary, so interrupt_before is not needed here. The checkpointer saves full
# state at the interrupt point; resume via Command(resume=decision).
graph = _workflow.compile(checkpointer=_checkpointer)
