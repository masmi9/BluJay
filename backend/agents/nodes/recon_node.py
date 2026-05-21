"""
Node 01 — Recon Agent.

Uses Ollama (local, free) to orchestrate subdomain enumeration, port scanning,
TLS inspection, cloud bucket discovery, and IMDS probing against the target.

Tools called (via BluJay REST API):
  - recon_target   → subdomain enum, nmap scan
  - audit_tls      → cipher/protocol analysis
  - probe_cloud_metadata → IMDS, S3/GCS/Azure buckets
"""
import json

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from agents.llm import get_routine_llm
from agents.state import AgentState
from agents.tools import audit_tls, probe_cloud_metadata, recon_target

logger = structlog.get_logger()

_SYSTEM = """You are a recon agent for a security assessment pipeline.
Given a target URL, plan and execute recon to map the attack surface.
Call the available tools to gather:
1. Subdomains and open ports (recon_target)
2. TLS/SSL configuration weaknesses (audit_tls)
3. Cloud metadata / exposed bucket misconfigurations (probe_cloud_metadata)

After calling the tools, summarise the findings as a JSON list of dicts with keys:
  type, target, finding, severity (info|low|medium|high|critical), evidence

Return ONLY the JSON array, no prose.
"""

TOOLS = [recon_target, audit_tls, probe_cloud_metadata]


async def recon_node(state: AgentState) -> dict:
    logger.info("recon_node starting", run_id=state["run_id"], target=state["target_url"])

    llm = get_routine_llm().bind_tools(TOOLS)

    messages = [
        SystemMessage(content=_SYSTEM),
        HumanMessage(content=f"Target: {state['target_url']}\nScan type: {state['scan_type']}"),
    ]

    # ReAct loop — max 6 rounds to prevent runaway tool calls
    recon_results: list[dict] = []
    for _ in range(6):
        response = await llm.ainvoke(messages)
        messages.append(response)

        if not response.tool_calls:
            # LLM returned final answer — parse JSON list
            try:
                text = response.content if isinstance(response.content, str) else ""
                start = text.find("[")
                end = text.rfind("]") + 1
                if start != -1 and end > start:
                    recon_results = json.loads(text[start:end])
            except (json.JSONDecodeError, ValueError):
                recon_results = [{"type": "raw", "finding": response.content, "severity": "info"}]
            break

        # Execute tool calls and feed results back
        from langchain_core.messages import ToolMessage
        for tc in response.tool_calls:
            tool_fn = {t.name: t for t in TOOLS}.get(tc["name"])
            if not tool_fn:
                continue
            try:
                result = await tool_fn.ainvoke(tc["args"])
                messages.append(ToolMessage(content=json.dumps(result, default=str), tool_call_id=tc["id"]))
            except Exception as exc:
                messages.append(ToolMessage(content=f"Error: {exc}", tool_call_id=tc["id"]))

    logger.info("recon_node done", run_id=state["run_id"], findings=len(recon_results))
    return {
        "recon_results": recon_results,
        "status": "exploiting",
        "messages": messages,
    }
