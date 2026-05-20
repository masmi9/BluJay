"""Orchestrates AI agent probe execution for a scan."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from database import AsyncSessionLocal
from models.ai_agent import AIAgentFinding, AIAgentScan


async def run_scan(scan_id: int) -> None:
    async with AsyncSessionLocal() as db:
        scan = await db.get(AIAgentScan, scan_id)
        if not scan:
            return

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        await db.commit()

        categories: list[str] = json.loads(scan.probe_categories or "[]")
        cancelled_flag = [False]
        all_findings: list[dict] = []

        try:
            if "infra" in categories:
                from scanners.ai_agent.probes.infra_check import run_all as run_infra
                infra_findings = await run_infra(scan.target_url, cancelled_flag)
                all_findings.extend(infra_findings)

            if "prompt_injection" in categories and not cancelled_flag[0]:
                from scanners.ai_agent.probes.prompt_injection import run_all as run_pi
                pi_findings = await run_pi(scan.target_url, scan.protocol_type, cancelled_flag)
                all_findings.extend(pi_findings)

            # Persist findings
            for f in all_findings:
                finding = AIAgentFinding(
                    scan_id=scan_id,
                    category=f["category"],
                    severity=f["severity"],
                    title=f["title"],
                    detail=f["detail"],
                    evidence=f.get("evidence"),
                    probe_id=f["probe_id"],
                    request_payload=f.get("request_payload"),
                    raw_response=f.get("raw_response"),
                    confirmed=f.get("confirmed", False),
                )
                db.add(finding)

            completed_at = datetime.now(timezone.utc)
            scan.status = "cancelled" if cancelled_flag[0] else "complete"
            scan.finding_count = len(all_findings)
            scan.findings_json = json.dumps([f["probe_id"] for f in all_findings])
            scan.completed_at = completed_at
            scan.duration_seconds = (completed_at - scan.started_at).total_seconds()
            await db.commit()

        except asyncio.CancelledError:
            scan.status = "cancelled"
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
        except Exception as exc:
            scan.status = "error"
            scan.error = str(exc)[:500]
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
