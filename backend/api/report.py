"""
Report generation: HTML (self-contained) and SARIF 2.1.0.
"""
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.analysis import Analysis, StaticFinding
from models.owasp import OwaspScan
from models.scanner import ScanFinding
from models.session import DynamicSession

router = APIRouter()

_SEV_COLOR = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#3b82f6",
    "info":     "#6b7280",
}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _badge(sev: str) -> str:
    color = _SEV_COLOR.get(sev, "#6b7280")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:11px;font-weight:600">{sev.upper()}</span>'
    )


def _render_html(
    analysis: Analysis,
    static_findings: list[StaticFinding],
    owasp: OwaspScan | None,
    scan_findings: list[ScanFinding],
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in static_findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    for f in scan_findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    static_rows = ""
    for f in sorted(static_findings, key=lambda x: _SEV_ORDER.get(x.severity, 5)):
        ev = ""
        if f.evidence:
            try:
                ev_obj = json.loads(f.evidence)
                ev = ev_obj.get("match", "") or ev_obj.get("context", "")
            except Exception:
                ev = f.evidence
        static_rows += (
            f"<tr>"
            f"<td>{_badge(f.severity)}</td>"
            f"<td>{f.category}</td>"
            f"<td><strong>{f.title}</strong><br><small style='color:#aaa'>{f.description[:200]}</small></td>"
            f"<td><code style='font-size:11px'>{f.file_path or ''}</code></td>"
            f"<td><code style='font-size:11px;word-break:break-all'>{ev[:120]}</code></td>"
            f"</tr>"
        )

    scan_rows = ""
    for f in sorted(scan_findings, key=lambda x: _SEV_ORDER.get(x.severity, 5)):
        scan_rows += (
            f"<tr>"
            f"<td>{_badge(f.severity)}</td>"
            f"<td>{'Active' if f.scan_type == 'active' else 'Passive'}</td>"
            f"<td><strong>{f.title}</strong><br><small style='color:#aaa'>{f.detail[:200]}</small></td>"
            f"<td style='word-break:break-all;font-size:11px'>{f.url[:100]}</td>"
            f"</tr>"
        )

    owasp_section = ""
    if owasp and owasp.findings_json:
        try:
            owasp_data = json.loads(owasp.findings_json)
            findings_list = owasp_data if isinstance(owasp_data, list) else owasp_data.get("findings", [])
            owasp_rows = ""
            for of in findings_list[:50]:
                sev = of.get("severity", "info")
                owasp_rows += (
                    f"<tr>"
                    f"<td>{_badge(sev)}</td>"
                    f"<td>{of.get('check_id', '')}</td>"
                    f"<td>{of.get('title', of.get('check_name', ''))}</td>"
                    f"<td style='font-size:11px'>{str(of.get('detail', of.get('description', '')))[:200]}</td>"
                    f"</tr>"
                )
            owasp_section = f"""
            <h2>OWASP MASVS Scan</h2>
            <table>
              <thead><tr><th>Severity</th><th>Check</th><th>Title</th><th>Detail</th></tr></thead>
              <tbody>{owasp_rows}</tbody>
            </table>"""
        except Exception:
            pass

    # Pre-compute conditional blocks — Python 3.11 can't handle nested f-strings with quotes
    summary_cards = "".join(
        f'<div class="card"><div class="num" style="color:{_SEV_COLOR[s]}">{sev_counts[s]}</div>'
        f'<div class="lbl">{s}</div></div>'
        for s in ("critical", "high", "medium", "low", "info")
    )
    static_table = (
        '<p style="color:#52525b">No static findings.</p>'
        if not static_rows else
        f'<table><thead><tr><th>Severity</th><th>Category</th><th>Finding</th>'
        f'<th>File</th><th>Evidence</th></tr></thead><tbody>{static_rows}</tbody></table>'
    )
    scan_table = (
        '<p style="color:#52525b">No scanner findings for this analysis.</p>'
        if not scan_rows else
        f'<table><thead><tr><th>Severity</th><th>Type</th><th>Finding</th>'
        f'<th>URL</th></tr></thead><tbody>{scan_rows}</tbody></table>'
    )
    total_count = len(static_findings) + len(scan_findings)
    static_count = len(static_findings)
    scan_count = len(scan_findings)
    dash = "\u2014"
    pkg = analysis.package_name or dash
    ver_name = analysis.version_name or dash
    ver_code = analysis.version_code or dash
    ver = f"{ver_name} ({ver_code})"
    platform = analysis.platform.upper()
    min_sdk = str(analysis.min_sdk or dash)
    tgt_sdk = str(analysis.target_sdk or dash)
    sha_short = analysis.apk_sha256[:32]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BluJay Report — {analysis.apk_filename}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background:#0f1117; color:#e4e4e7; margin:0; padding:0; }}
  .header {{ background:#1a1d27; padding:32px 40px; border-bottom:1px solid #27272a; }}
  .header h1 {{ margin:0 0 4px; font-size:22px; color:#fff; }}
  .header p  {{ margin:0; color:#71717a; font-size:13px; }}
  .content {{ padding:32px 40px; }}
  .summary {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:32px; }}
  .card {{ background:#1a1d27; border:1px solid #27272a; border-radius:8px;
           padding:16px 24px; min-width:100px; text-align:center; }}
  .card .num {{ font-size:28px; font-weight:700; }}
  .card .lbl {{ font-size:11px; color:#71717a; margin-top:2px; text-transform:uppercase; }}
  h2 {{ font-size:15px; color:#a1a1aa; text-transform:uppercase; letter-spacing:.08em;
        margin:32px 0 12px; border-bottom:1px solid #27272a; padding-bottom:8px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th {{ text-align:left; padding:8px 10px; background:#1a1d27; color:#71717a;
        font-weight:600; font-size:11px; text-transform:uppercase; }}
  td {{ padding:8px 10px; border-bottom:1px solid #1e1e24; vertical-align:top; }}
  tr:hover td {{ background:#16181f; }}
  code {{ background:#1e2030; padding:2px 6px; border-radius:4px; font-family:monospace; }}
  .footer {{ text-align:center; color:#3f3f46; font-size:11px;
             padding:24px; border-top:1px solid #27272a; margin-top:32px; }}
  .meta {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
           gap:12px; margin-bottom:32px; }}
  .meta-item {{ background:#1a1d27; border:1px solid #27272a; border-radius:6px; padding:12px 16px; }}
  .meta-item .key {{ font-size:10px; color:#52525b; text-transform:uppercase; margin-bottom:4px; }}
  .meta-item .val {{ font-size:13px; color:#e4e4e7; font-weight:500; }}
</style>
</head>
<body>
<div class="header">
  <h1>Security Analysis Report</h1>
  <p>{analysis.apk_filename} &nbsp;·&nbsp; Generated {now} &nbsp;·&nbsp; BluJay</p>
</div>
<div class="content">

  <div class="meta">
    <div class="meta-item"><div class="key">Package</div><div class="val">{pkg}</div></div>
    <div class="meta-item"><div class="key">Version</div><div class="val">{ver}</div></div>
    <div class="meta-item"><div class="key">Platform</div><div class="val">{platform}</div></div>
    <div class="meta-item"><div class="key">Min SDK</div><div class="val">{min_sdk}</div></div>
    <div class="meta-item"><div class="key">Target SDK</div><div class="val">{tgt_sdk}</div></div>
    <div class="meta-item"><div class="key">SHA-256</div><div class="val" style="font-size:10px;font-family:monospace">{sha_short}&#8230;</div></div>
  </div>

  <h2>Finding Summary</h2>
  <div class="summary">
    {summary_cards}
    <div class="card"><div class="num">{total_count}</div><div class="lbl">Total</div></div>
  </div>

  <h2>Static Analysis Findings ({static_count})</h2>
  {static_table}

  {owasp_section}

  <h2>Network / Scanner Findings ({scan_count})</h2>
  {scan_table}

</div>
<div class="footer">Generated by BluJay · {now}</div>
</body>
</html>"""


@router.get("/analysis/{analysis_id}", response_class=HTMLResponse)
async def report_html(analysis_id: int, db: AsyncSession = Depends(get_db)):
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")

    static_findings = (
        await db.execute(select(StaticFinding).where(StaticFinding.analysis_id == analysis_id))
    ).scalars().all()

    owasp = (
        await db.execute(select(OwaspScan).where(OwaspScan.analysis_id == analysis_id).limit(1))
    ).scalar_one_or_none()

    sessions = (
        await db.execute(select(DynamicSession).where(DynamicSession.analysis_id == analysis_id))
    ).scalars().all()
    session_ids = [s.id for s in sessions]

    scan_findings: list[ScanFinding] = []
    if session_ids:
        scan_findings = (
            await db.execute(
                select(ScanFinding).where(ScanFinding.session_id.in_(session_ids))
            )
        ).scalars().all()

    html = _render_html(analysis, list(static_findings), owasp, scan_findings)
    filename = f"blujay-report-{analysis.package_name or analysis_id}.html"
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/analysis/{analysis_id}/sarif")
async def report_sarif(analysis_id: int, db: AsyncSession = Depends(get_db)):
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")

    static_findings = (
        await db.execute(select(StaticFinding).where(StaticFinding.analysis_id == analysis_id))
    ).scalars().all()

    sessions = (
        await db.execute(select(DynamicSession).where(DynamicSession.analysis_id == analysis_id))
    ).scalars().all()
    session_ids = [s.id for s in sessions]

    scan_findings: list[ScanFinding] = []
    if session_ids:
        scan_findings = (
            await db.execute(
                select(ScanFinding).where(ScanFinding.session_id.in_(session_ids))
            )
        ).scalars().all()

    _sev_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}

    results = []
    rules = {}

    for f in static_findings:
        rule_id = f.rule_id or f"BJ-{f.category[:8].upper()}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {"level": _sev_map.get(f.severity, "warning")},
                "properties": {"security-severity": {"critical": "9.8", "high": "8.0", "medium": "5.0", "low": "2.0", "info": "0.0"}.get(f.severity, "0.0")},
            }
        results.append({
            "ruleId": rule_id,
            "level": _sev_map.get(f.severity, "warning"),
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path or "unknown"},
                    "region": {"startLine": f.line_number or 1},
                }
            }],
        })

    for f in scan_findings:
        rule_id = f"BJ-NET-{f.check_name[:12].upper().replace('-', '_')}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {"level": _sev_map.get(f.severity, "warning")},
            }
        results.append({
            "ruleId": rule_id,
            "level": _sev_map.get(f.severity, "warning"),
            "message": {"text": f"{f.detail} | URL: {f.url}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.url}}}],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "BluJay",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/blujay",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "artifacts": [{"location": {"uri": analysis.apk_filename}}],
        }],
    }
    filename = f"blujay-{analysis.package_name or analysis_id}.sarif"
    return JSONResponse(
        content=sarif,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
