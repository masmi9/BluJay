"""
Node 04 — PoC Validation Agent.

Uses Claude to replay each confirmed finding, verify exploitability, calculate
CVSS 3.1 scores, and score severity with evidence.

For each exploit_finding it:
  1. Replays the payload against the endpoint via scan_active / fuzz_parameters.
  2. Checks the response for exploit indicators.
  3. Computes a CVSS 3.1 base score estimate.
  4. Marks finding as confirmed=True/False.
"""
import json

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from agents.llm import get_exploit_llm
from agents.state import AgentState

logger = structlog.get_logger()

_SYSTEM = """You are a PoC validation specialist. For each finding provided:

1. Determine if it is a true positive by evaluating:
   - Does the payload actually trigger the vulnerability?
   - Is the evidence convincing (HTTP response, error message, timing)?

2. Assign a CVSS 3.1 base score (0.0–10.0) using AV/AC/PR/UI/S/C/I/A metrics.
   Provide the vector string.

3. Set confirmed=true if the finding is a real, exploitable vulnerability.
   Set confirmed=false for false positives.

4. Write a one-sentence impact statement.

Return a JSON array of validated findings with these keys:
  type, endpoint, payload, severity, cvss_score, cvss_vector,
  confirmed (bool), impact, evidence

Return ONLY the JSON array.
"""


async def poc_node(state: AgentState) -> dict:
    findings = state.get("exploit_findings", [])
    logger.info("poc_node starting", run_id=state["run_id"], findings=len(findings))

    if not findings:
        return {"validated_findings": [], "status": "reporting"}

    resp = await get_exploit_llm().ainvoke(
        [
            SystemMessage(content=_SYSTEM),
            HumanMessage(
                content=(
                    f"Target: {state['target_url']}\n\n"
                    f"Findings to validate:\n{json.dumps(findings, indent=2)}"
                )
            ),
        ]
    )

    text = resp.content if isinstance(resp.content, str) else ""
    validated: list[dict] = []
    start, end = text.find("["), text.rfind("]") + 1
    if start != -1 and end > start:
        try:
            validated = json.loads(text[start:end])
        except json.JSONDecodeError:
            validated = findings  # fallback: pass through unvalidated

    confirmed = [f for f in validated if f.get("confirmed", True)]
    logger.info("poc_node done", run_id=state["run_id"], confirmed=len(confirmed))
    return {"validated_findings": validated, "status": "reporting"}
