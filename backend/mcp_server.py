"""
BluJay MCP Server.

Exposes the BluJay mobile security database as an MCP tool-server so that
Claude (or any MCP-compatible client) can query analyses, findings, CVEs,
TLS audits, and more without writing raw SQL.

Also exposes action tools that trigger scans, pipeline runs, and perf tests
against the running BluJay FastAPI backend (localhost:8000).

Run standalone:
    cd backend
    python mcp_server.py

Or point an MCP client at it via stdio transport (default).

The server uses a synchronous SQLite connection (sqlite+pysqlite) to avoid
asyncio complexity in the MCP tool handlers.
"""

import json
import os
import sys
from pathlib import Path

# Make sure backend/ is importable when run from any cwd.
sys.path.insert(0, str(Path(__file__).parent))

from config import settings

# Resolve a synchronous SQLite URL from the same DB path the app uses.
_SYNC_URL = str(settings.db_url).replace("sqlite+aiosqlite", "sqlite+pysqlite")

import httpx
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

_engine = create_engine(_SYNC_URL, connect_args={"check_same_thread": False})
_Session = sessionmaker(bind=_engine)

from mcp.server.fastmcp import FastMCP

_API_BASE = os.getenv("BLUJAY_API_BASE", "http://localhost:8000/api/v1")

mcp = FastMCP(
    "BluJay",
    instructions=(
        "BluJay is an autonomous AppSec platform. "
        "Use the query tools to inspect analyses, findings, CVEs, TLS audits, "
        "JWT tests, campaigns, and diffs. "
        "Use the action tools to start pipeline runs, trigger web/API scans, "
        "run performance tests, and launch Strix autonomous pentests. "
        "Always check run/job status after starting an action."
    ),
)


# ── helper ───────────────────────────────────────────────────────────────────

def _rows(sql: str, params: dict | None = None) -> list[dict]:
    with _Session() as s:
        result = s.execute(text(sql), params or {})
        cols = result.keys()
        return [dict(zip(cols, row)) for row in result.fetchall()]


def _one(sql: str, params: dict | None = None) -> dict | None:
    rows = _rows(sql, params)
    return rows[0] if rows else None


# ── tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def list_analyses(limit: int = 20, platform: str | None = None) -> list[dict]:
    """List recent analyses. Optionally filter by platform ('android' or 'ios')."""
    sql = (
        "SELECT id, created_at, apk_filename, package_name, version_name, "
        "platform, status, bundle_id FROM analyses"
    )
    conditions, params = [], {}
    if platform:
        conditions.append("platform = :platform")
        params["platform"] = platform
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY created_at DESC LIMIT :limit"
    params["limit"] = limit
    return _rows(sql, params)


@mcp.tool()
def get_analysis(analysis_id: int) -> dict | None:
    """Get full details for a specific analysis by ID."""
    return _one(
        "SELECT * FROM analyses WHERE id = :id",
        {"id": analysis_id},
    )


@mcp.tool()
def get_findings(
    analysis_id: int,
    severity: str | None = None,
    category: str | None = None,
) -> list[dict]:
    """
    Get static findings for an analysis.
    severity: critical | high | medium | low | info
    category: hardcoded_secret | insecure_config | dangerous_permission |
              exported_component | manifest_issue
    """
    sql = (
        "SELECT id, category, severity, title, description, file_path, line_number, rule_id "
        "FROM static_findings WHERE analysis_id = :aid"
    )
    params: dict = {"aid": analysis_id}
    if severity:
        sql += " AND severity = :sev"
        params["sev"] = severity
    if category:
        sql += " AND category = :cat"
        params["cat"] = category
    sql += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
    return _rows(sql, params)


@mcp.tool()
def get_finding_summary(analysis_id: int) -> dict:
    """Return a severity breakdown of findings for an analysis."""
    rows = _rows(
        "SELECT severity, COUNT(*) as count FROM static_findings "
        "WHERE analysis_id = :aid GROUP BY severity",
        {"aid": analysis_id},
    )
    return {r["severity"]: r["count"] for r in rows}


@mcp.tool()
def list_cve_matches(analysis_id: int) -> list[dict]:
    """List CVE matches for an analysis, joined with library names."""
    return _rows(
        "SELECT cm.id, cm.osv_id, cm.cve_id, cm.severity, cm.cvss_score, "
        "cm.summary, cm.fixed_version, cm.published, "
        "dl.name as library_name, dl.version as library_version, dl.ecosystem "
        "FROM cve_matches cm "
        "JOIN detected_libraries dl ON dl.id = cm.library_id "
        "WHERE cm.analysis_id = :aid "
        "ORDER BY cm.cvss_score DESC NULLS LAST",
        {"aid": analysis_id},
    )


@mcp.tool()
def list_tls_audits(
    analysis_id: int | None = None,
    session_id: int | None = None,
) -> list[dict]:
    """List TLS audit results, optionally filtered by analysis or dynamic session."""
    sql = "SELECT * FROM tls_audits WHERE 1=1"
    params: dict = {}
    if analysis_id is not None:
        sql += " AND analysis_id = :aid"
        params["aid"] = analysis_id
    if session_id is not None:
        sql += " AND session_id = :sid"
        params["sid"] = session_id
    sql += " ORDER BY audited_at DESC"
    return _rows(sql, params)


@mcp.tool()
def list_jwt_tests(analysis_id: int | None = None) -> list[dict]:
    """List JWT test results, optionally filtered by analysis ID."""
    sql = "SELECT * FROM jwt_tests WHERE 1=1"
    params: dict = {}
    if analysis_id is not None:
        sql += " AND analysis_id = :aid"
        params["aid"] = analysis_id
    sql += " ORDER BY created_at DESC"
    return _rows(sql, params)


@mcp.tool()
def list_campaigns(limit: int = 20) -> list[dict]:
    """List multi-APK campaigns with target counts and statuses."""
    return _rows(
        "SELECT cj.id, cj.created_at, cj.name, cj.platform, cj.status, "
        "COUNT(ct.id) as total_targets, "
        "SUM(CASE WHEN ct.status='complete' THEN 1 ELSE 0 END) as complete, "
        "SUM(CASE WHEN ct.status='failed' THEN 1 ELSE 0 END) as failed "
        "FROM campaign_jobs cj "
        "LEFT JOIN campaign_targets ct ON ct.campaign_id = cj.id "
        "GROUP BY cj.id ORDER BY cj.created_at DESC LIMIT :limit",
        {"limit": limit},
    )


@mcp.tool()
def get_campaign(campaign_id: int) -> dict | None:
    """Get a campaign and all its targets."""
    campaign = _one("SELECT * FROM campaign_jobs WHERE id = :id", {"id": campaign_id})
    if not campaign:
        return None
    targets = _rows(
        "SELECT * FROM campaign_targets WHERE campaign_id = :cid ORDER BY id",
        {"cid": campaign_id},
    )
    return {**campaign, "targets": targets}


@mcp.tool()
def list_diffs(limit: int = 20) -> list[dict]:
    """List analysis diff records (change detection results)."""
    return _rows(
        "SELECT id, created_at, baseline_id, target_id, diff_type, summary "
        "FROM analysis_diffs ORDER BY created_at DESC LIMIT :limit",
        {"limit": limit},
    )


@mcp.tool()
def get_diff(diff_id: int) -> dict | None:
    """Get a full diff record including added/removed findings and permissions."""
    row = _one("SELECT * FROM analysis_diffs WHERE id = :id", {"id": diff_id})
    if not row:
        return None
    # Parse JSON fields for readability
    for field in ("added_findings", "removed_findings", "added_permissions",
                  "removed_permissions", "severity_delta"):
        val = row.get(field)
        if val:
            try:
                row[field] = json.loads(val)
            except Exception:
                pass
    return row


@mcp.tool()
def list_owasp_scans(platform: str | None = None, limit: int = 20) -> list[dict]:
    """List OWASP scan results, optionally filtered by platform."""
    sql = (
        "SELECT id, created_at, analysis_id, platform, package_name, "
        "mode, status, progress, error FROM owasp_scans WHERE 1=1"
    )
    params: dict = {}
    if platform:
        sql += " AND platform = :platform"
        params["platform"] = platform
    sql += " ORDER BY created_at DESC LIMIT :limit"
    params["limit"] = limit
    return _rows(sql, params)


@mcp.tool()
def list_dynamic_sessions(limit: int = 20) -> list[dict]:
    """List dynamic analysis sessions."""
    return _rows(
        "SELECT id, created_at, device_serial, package_name, platform, "
        "status, proxy_port, frida_attached FROM dynamic_sessions "
        "ORDER BY created_at DESC LIMIT :limit",
        {"limit": limit},
    )


@mcp.tool()
def search_findings(keyword: str, limit: int = 50) -> list[dict]:
    """Full-text search across finding titles and descriptions."""
    return _rows(
        "SELECT sf.id, sf.analysis_id, sf.category, sf.severity, sf.title, "
        "sf.description, sf.file_path, a.apk_filename, a.package_name "
        "FROM static_findings sf "
        "JOIN analyses a ON a.id = sf.analysis_id "
        "WHERE sf.title LIKE :kw OR sf.description LIKE :kw "
        "ORDER BY CASE sf.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
        "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END "
        "LIMIT :limit",
        {"kw": f"%{keyword}%", "limit": limit},
    )


# ── action tools — trigger scans and pipelines ────────────────────────────────

def _post(path: str, body: dict) -> dict:
    """POST to the BluJay REST API and return the JSON response."""
    try:
        r = httpx.post(f"{_API_BASE}{path}", json=body, timeout=30)
        r.raise_for_status()
        return r.json()
    except httpx.HTTPStatusError as exc:
        return {"error": f"HTTP {exc.response.status_code}", "detail": exc.response.text}
    except httpx.RequestError as exc:
        return {"error": "connection_failed", "detail": str(exc)}


def _get(path: str, params: dict | None = None) -> dict | list:
    """GET from the BluJay REST API and return the JSON response."""
    try:
        r = httpx.get(f"{_API_BASE}{path}", params=params, timeout=15)
        r.raise_for_status()
        return r.json()
    except httpx.HTTPStatusError as exc:
        return {"error": f"HTTP {exc.response.status_code}", "detail": exc.response.text}
    except httpx.RequestError as exc:
        return {"error": "connection_failed", "detail": str(exc)}


@mcp.tool()
def start_pipeline(target_url: str, scan_type: str = "web") -> dict:
    """
    Start an autonomous LangGraph pentest pipeline against a URL.

    The pipeline runs: Recon → Exploit (with variant loop) → Human Gate →
    PoC Validation → Report.

    scan_type: 'web' | 'api'

    Returns a run_id. Use get_pipeline_run(run_id) to poll status.
    When the pipeline reaches the Human Gate it pauses — use
    resume_pipeline(run_id, decision) to approve or deny.
    """
    return _post("/pipeline/run", {"target_url": target_url, "scan_type": scan_type})


@mcp.tool()
def get_pipeline_run(run_id: str) -> dict:
    """
    Get the current status and results of a pipeline run.

    Status values: running | awaiting_review | completed | denied | failed

    When status is 'awaiting_review', gate_payload contains the finding
    summary that needs human approval before PoC validation proceeds.
    """
    return _get(f"/pipeline/{run_id}")


@mcp.tool()
def resume_pipeline(run_id: str, decision: str) -> dict:
    """
    Resume a pipeline run that is paused at the Human Review Gate.

    decision: 'approved' — continue to PoC validation and report
              'denied'   — stop the pipeline immediately

    Only valid when get_pipeline_run shows status='awaiting_review'.
    """
    return _post(f"/pipeline/{run_id}/resume", {"decision": decision})


@mcp.tool()
def run_web_scan(
    target_url: str,
    scan_types: list[str] | None = None,
) -> dict:
    """
    Run the BluJay active web scanner against a URL.

    Detects: XSS, SQLi, SSRF, path traversal, open redirect.

    scan_types: list of checks to run, e.g. ['xss', 'sqli', 'ssrf'].
    Leave None to run all checks.

    Returns a scan result dict with findings keyed by type.
    """
    body: dict = {"target_url": target_url}
    if scan_types:
        body["scan_types"] = scan_types
    return _post("/scanner/active", body)


@mcp.tool()
def run_perf_test(
    target_url: str,
    finding_type: str,
    vus: int = 10,
    duration: str = "30s",
) -> dict:
    """
    Trigger a k6 performance / load test informed by a security finding.

    finding_type maps to a test script:
      race_condition  → concurrent load, state mutation under pressure
      auth_endpoint   → brute-force rate limit, lockout threshold detection
      idor_found      → enumeration load, ID range sweep at scale
      api_endpoint    → spike test, DoS viability assessment
      slow_response   → stress test, timing-based vulnerability confirmation

    vus: virtual users (default 10)
    duration: k6 duration string, e.g. '30s', '2m' (default '30s')

    Returns a job_id. Poll GET /perf/{job_id} for status and metrics.
    """
    return _post("/perf/run", {
        "target_url": target_url,
        "finding_type": finding_type,
        "vus": vus,
        "duration": duration,
    })


@mcp.tool()
def get_perf_job(job_id: str) -> dict:
    """
    Get the status and output metrics for a running or completed k6 perf job.

    Metrics include p95/p99 latency, requests/sec, error rate, and rate-limit
    threshold detection where applicable.
    """
    return _get(f"/perf/{job_id}")


@mcp.tool()
def start_strix(
    target_url: str,
    session_id: int | None = None,
) -> dict:
    """
    Launch Strix — BluJay's multi-agent autonomous pentest coordinator.

    Strix orchestrates a full pentest lifecycle: recon, exploit, PoC
    confirmation, and report generation in a Docker-sandboxed environment.
    Uses Claude for exploit reasoning and Ollama for routine tasks.

    session_id: optionally link to an existing dynamic analysis session.

    Returns a strix_run_id for tracking.
    """
    body: dict = {"target_url": target_url}
    if session_id is not None:
        body["session_id"] = session_id
    return _post("/strix/start", body)


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
