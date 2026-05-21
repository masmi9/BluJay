"""
Node 05 — Report Agent.

Uses Ollama (local) to generate:
  - SARIF 2.1 report (for GitHub Code Scanning / CI gating)
  - OWASP MASVS / WSTG mapping per finding
  - Human-readable remediation steps
  - Executive summary
"""
import json
from datetime import datetime, timezone

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from agents.llm import get_routine_llm
from agents.state import AgentState

logger = structlog.get_logger()

_SYSTEM = """You are a security report generator.

Given a list of validated findings, produce:

1. A SARIF 2.1 JSON report conforming to the schema at
   https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json
   Include: runs[0].tool (name=BluJay, version=2.0),
            runs[0].results[] with level, message, locations, and
            a partialFingerprints entry with "primaryLocationLineHash".

2. An "owasp_mapping" list — each entry: {finding_type, owasp_category, masvs_id, cwe_id}

3. A "remediation" list — each entry: {finding_type, steps: [string, ...], priority}

4. An "executive_summary" string (3–5 sentences, plain English, no jargon).

Return a single JSON object with keys: sarif, owasp_mapping, remediation, executive_summary.
Return ONLY the JSON object.
"""


async def report_node(state: AgentState) -> dict:
    findings = state.get("validated_findings", [])
    logger.info("report_node starting", run_id=state["run_id"], findings=len(findings))

    if not findings:
        sarif = _empty_sarif(state["target_url"])
        return {
            "report_sarif": sarif,
            "report_summary": "No confirmed findings.",
            "status": "completed",
        }

    resp = await get_routine_llm().ainvoke(
        [
            SystemMessage(content=_SYSTEM),
            HumanMessage(
                content=(
                    f"Target: {state['target_url']}\n"
                    f"Run ID: {state['run_id']}\n"
                    f"Validated findings:\n{json.dumps(findings, indent=2)}"
                )
            ),
        ]
    )

    text = resp.content if isinstance(resp.content, str) else ""
    report_data: dict = {}
    start, end = text.find("{"), text.rfind("}") + 1
    if start != -1 and end > start:
        try:
            report_data = json.loads(text[start:end])
        except json.JSONDecodeError:
            pass

    sarif = report_data.get("sarif") or _empty_sarif(state["target_url"])
    summary = report_data.get("executive_summary", "Report generated.")

    logger.info("report_node done", run_id=state["run_id"])
    return {
        "report_sarif": sarif,
        "report_summary": summary,
        "status": "completed",
    }


def _empty_sarif(target: str) -> dict:
    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "BluJay", "version": "2.0", "rules": []}},
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": f"BluJay pipeline target={target}",
                        "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }
