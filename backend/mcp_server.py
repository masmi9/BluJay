"""
BluJay MCP Server.

Exposes the BluJay mobile security database as an MCP tool-server so that
Claude (or any MCP-compatible client) can query analyses, findings, CVEs,
TLS audits, and more without writing raw SQL.

Run standalone:
    cd backend
    python mcp_server.py

Or point an MCP client at it via stdio transport (default).

The server uses a synchronous SQLite connection (sqlite+pysqlite) to avoid
asyncio complexity in the MCP tool handlers.
"""

import json
import sys
from pathlib import Path

# Make sure backend/ is importable when run from any cwd.
sys.path.insert(0, str(Path(__file__).parent))

from config import settings

# Resolve a synchronous SQLite URL from the same DB path the app uses.
_SYNC_URL = str(settings.db_url).replace("sqlite+aiosqlite", "sqlite+pysqlite")

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

_engine = create_engine(_SYNC_URL, connect_args={"check_same_thread": False})
_Session = sessionmaker(bind=_engine)

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "BluJay",
    instructions=(
        "BluJay is a mobile security analysis platform. "
        "Use these tools to inspect Android/iOS APK/IPA analyses, "
        "static findings, CVE matches, TLS audits, JWT tests, "
        "campaigns, and analysis diffs."
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


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
