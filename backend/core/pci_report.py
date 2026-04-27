"""
PCI report generator.
Produces: structured JSON, executive HTML summary, technical HTML detail report.
"""
from __future__ import annotations
import html
import json
from datetime import datetime, timezone
from typing import Any

from core.pci_models import (
    PciFinding, PciScanSummary, PCI_REQ_LABELS, SEVERITY_WEIGHT,
)


# ── JSON report ───────────────────────────────────────────────────────────────

def generate_json_report(
    findings: list[PciFinding],
    summary: PciScanSummary,
    meta: dict[str, Any] | None = None,
) -> str:
    summary.tally(findings)
    report = {
        "report_type": "pci_dss_v4",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "meta": meta or {},
        "summary": summary.to_dict(),
        "findings": [f.to_dict() for f in sorted(
            findings,
            key=lambda x: (-SEVERITY_WEIGHT.get(x.severity, 0), x.category),
        )],
    }
    return json.dumps(report, indent=2, default=str)


# ── Shared HTML utilities ─────────────────────────────────────────────────────

_SEV_COLORS: dict[str, str] = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#3b82f6",
    "info":     "#71717a",
}

_BASE_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #0f0f0f; color: #e4e4e7; font-size: 13px; line-height: 1.5; }
.page { max-width: 960px; margin: 0 auto; padding: 24px 16px; }
h1 { font-size: 22px; font-weight: 700; color: #fff; }
h2 { font-size: 15px; font-weight: 600; color: #e4e4e7; margin: 24px 0 8px; }
h3 { font-size: 13px; font-weight: 600; color: #a1a1aa; margin: 0 0 4px; }
table { width: 100%; border-collapse: collapse; margin-bottom: 16px; }
th { text-align: left; padding: 8px 10px; font-size: 11px; text-transform: uppercase;
     letter-spacing: .05em; color: #71717a; border-bottom: 1px solid #27272a; }
td { padding: 8px 10px; border-bottom: 1px solid #1a1a1f; vertical-align: top; }
tr:last-child td { border-bottom: none; }
.card { background: #18181b; border: 1px solid #27272a; border-radius: 8px;
        padding: 16px; margin-bottom: 16px; }
.badge { display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 11px;
         font-weight: 600; border: 1px solid transparent; }
.sev-critical { background: #7f1d1d20; color: #ef4444; border-color: #ef444430; }
.sev-high     { background: #7c2d1220; color: #f97316; border-color: #f9731630; }
.sev-medium   { background: #71390020; color: #eab308; border-color: #eab30830; }
.sev-low      { background: #1e3a5f20; color: #3b82f6; border-color: #3b82f630; }
.sev-info     { background: #27272a30; color: #71717a; border-color: #71717a30; }
.req-badge { display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 11px;
             background: #1d4ed820; color: #60a5fa; border: 1px solid #1d4ed830; font-family: monospace; }
pre { background: #0a0a0a; padding: 10px; border-radius: 6px; font-size: 11px;
      white-space: pre-wrap; word-break: break-all; color: #a1a1aa; overflow: auto; }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.grid-5 { display: grid; grid-template-columns: repeat(5,1fr); gap: 10px; }
.sev-box { padding: 12px; border-radius: 8px; text-align: center; }
.sev-box .count { font-size: 28px; font-weight: 700; }
.sev-box .label { font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }
.proc-tag { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 12px;
             background: #1d4ed820; color: #60a5fa; border: 1px solid #1d4ed830; margin: 3px; }
.disclaimer { margin-top: 24px; padding: 12px; background: #18181b; border-radius: 8px;
              color: #71717a; font-size: 11px; border: 1px solid #27272a; }
header { background: linear-gradient(135deg, #1e3a8a 0%, #1d4ed8 100%);
         padding: 28px 24px; border-radius: 10px; margin-bottom: 24px; }
header h1 { color: #fff; margin-bottom: 4px; }
header .sub { color: #bfdbfe; font-size: 12px; }
"""


def _sev_box(sev: str, count: int) -> str:
    col = _SEV_COLORS.get(sev, "#71717a")
    return (
        f'<div class="sev-box" style="background:{col}15;border:1px solid {col}30">'
        f'<div class="count" style="color:{col}">{count}</div>'
        f'<div class="label" style="color:{col}">{sev.upper()}</div>'
        f'</div>'
    )


def _badge(sev: str) -> str:
    return f'<span class="badge sev-{sev}">{sev}</span>'


def _req_badge(req: str) -> str:
    return f'<span class="req-badge">{html.escape(req)}</span>' if req else ""


# ── PCI Requirement coverage table ────────────────────────────────────────────

def _req_coverage_table(summary: PciScanSummary) -> str:
    rows = ""
    for req, label in PCI_REQ_LABELS.items():
        count = summary.findings_by_pci_req.get(req, 0)
        status_col = "#ef444420" if count else "#16a34a20"
        status_text_col = "#ef4444" if count else "#4ade80"
        status_label = f"{count} finding{'s' if count != 1 else ''}" if count else "No findings"
        rows += (
            f"<tr><td style='color:#a1a1aa;font-family:monospace'>{html.escape(req)}</td>"
            f"<td>{html.escape(label)}</td>"
            f"<td style='background:{status_col};color:{status_text_col};border-radius:4px;padding:4px 8px;text-align:center'>"
            f"{status_label}</td></tr>"
        )
    return f"""
    <h2>PCI DSS v4.0 Requirement Coverage</h2>
    <div class="card" style="padding:0">
    <table>
      <thead><tr><th>Requirement</th><th>Description</th><th style="text-align:center">Status</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
    </div>"""


# ── Executive HTML report ─────────────────────────────────────────────────────

def generate_html_executive(
    findings: list[PciFinding],
    summary: PciScanSummary,
    meta: dict[str, Any] | None = None,
) -> str:
    summary.tally(findings)
    s = summary.findings_by_severity
    top = [f for f in findings if f.severity in ("critical", "high")][:10]
    top_sorted = sorted(top, key=lambda x: -SEVERITY_WEIGHT.get(x.severity, 0))
    meta = meta or {}
    scan_date = meta.get("scan_date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    assessor = meta.get("assessor", "BluJay PCI Scanner")

    top_rows = "".join(
        f"<tr><td>{_badge(f.severity)}</td>"
        f"<td>{html.escape(f.title[:80])}</td>"
        f"<td style='color:#71717a;font-family:monospace'>{html.escape(f.target[:40])}</td>"
        f"<td>{_req_badge(f.pci_req)}</td></tr>"
        for f in top_sorted
    ) or "<tr><td colspan='4' style='color:#71717a'>No critical or high findings</td></tr>"

    proc_tags = "".join(
        f'<span class="proc-tag">{html.escape(p)}</span>'
        for p in (summary.processors_detected or ["None detected"])
    )

    scope_stat = (
        f"<b>{summary.target_count}</b> target(s) &nbsp;|&nbsp; "
        f"<b>{summary.hosts_live}</b> live host(s) &nbsp;|&nbsp; "
        f"<b>{summary.ports_open}</b> open port(s) &nbsp;|&nbsp; "
        f"<b>{summary.pages_crawled}</b> pages crawled"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PCI DSS Executive Report — {html.escape(summary.scope_name)}</title>
<style>{_BASE_CSS}
.exec-only {{ }}
</style>
</head>
<body>
<div class="page">

<header>
  <h1>PCI DSS External Vulnerability Assessment</h1>
  <div class="sub">{html.escape(summary.scope_name)} &nbsp;·&nbsp; {html.escape(scan_date)} &nbsp;·&nbsp; {html.escape(assessor)}</div>
  <div class="sub" style="margin-top:6px">Profile: {html.escape(summary.scan_profile)} &nbsp;·&nbsp; {scope_stat}</div>
</header>

<h2>Risk Summary</h2>
<div class="grid-5" style="margin-bottom:16px">
  {_sev_box('critical', s.get('critical',0))}
  {_sev_box('high',     s.get('high',0))}
  {_sev_box('medium',   s.get('medium',0))}
  {_sev_box('low',      s.get('low',0))}
  {_sev_box('info',     s.get('info',0))}
</div>

<h2>Payment Processors Detected</h2>
<div class="card">{proc_tags}</div>

{_req_coverage_table(summary)}

<h2>Top Critical &amp; High Findings</h2>
<div class="card" style="padding:0">
<table>
  <thead><tr><th>Severity</th><th>Finding</th><th>Target</th><th>PCI DSS</th></tr></thead>
  <tbody>{top_rows}</tbody>
</table>
</div>

<h2>Remediation Priorities</h2>
<div class="card" style="padding:0">
<table>
  <thead><tr><th>Priority</th><th>Action</th><th>PCI DSS Req</th></tr></thead>
  <tbody>
    {"".join(
      f"<tr><td style='color:#ef4444'>Immediate</td>"
      f"<td>{html.escape(f.remediation.description[:100] if f.remediation.description else f.title[:100])}</td>"
      f"<td>{_req_badge(f.pci_req)}</td></tr>"
      for f in top_sorted[:5]
    ) or "<tr><td colspan='3' style='color:#71717a'>No immediate remediation required</td></tr>"}
  </tbody>
</table>
</div>

<div class="disclaimer">
  <strong>Disclaimer:</strong> This report was generated automatically by BluJay PCI Scanner.
  It is intended as a technical aid and does not constitute a formal PCI DSS assessment.
  A Qualified Security Assessor (QSA) must validate compliance. CVSS scores and PCI DSS
  requirement mappings are approximate and should be reviewed by a security professional.
  This report does not replace penetration testing, SAQ, or ROC requirements.
</div>

</div>
</body>
</html>"""


# ── Technical HTML report ─────────────────────────────────────────────────────

def generate_html_technical(
    findings: list[PciFinding],
    summary: PciScanSummary,
    meta: dict[str, Any] | None = None,
) -> str:
    summary.tally(findings)
    meta = meta or {}
    scan_date = meta.get("scan_date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    sorted_findings = sorted(
        findings,
        key=lambda x: (-SEVERITY_WEIGHT.get(x.severity, 0), x.category, x.target),
    )

    def finding_section(f: PciFinding, idx: int) -> str:
        cvss_str = f" | CVSS {f.cvss_score:.1f}" if f.cvss_score else ""
        cves = " ".join(
            f'<a href="https://nvd.nist.gov/vuln/detail/{c}" style="color:#60a5fa">{html.escape(c)}</a>'
            for c in f.cve_ids
        ) if f.cve_ids else "<em style='color:#52525b'>None</em>"

        ev = f.evidence
        ev_parts = ""
        if ev.banner:
            ev_parts += f"<h3>Banner</h3><pre>{html.escape(ev.banner[:300])}</pre>"
        if ev.raw_request:
            ev_parts += f"<h3>Request</h3><pre>{html.escape(ev.raw_request[:600])}</pre>"
        if ev.raw_response:
            ev_parts += f"<h3>Response</h3><pre>{html.escape(ev.raw_response[:600])}</pre>"
        if ev.notes:
            ev_parts += f"<h3>Notes</h3><pre>{html.escape(ev.notes[:300])}</pre>"

        return f"""
        <div class="card" id="F{idx}">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
            <div>
              <span style="color:#71717a;font-size:11px">#{idx+1} &nbsp;·&nbsp; {html.escape(f.plugin_id or f.check_name)}</span>
              <h2 style="margin:4px 0">{html.escape(f.title)}</h2>
            </div>
            <div style="text-align:right;white-space:nowrap">
              {_badge(f.severity)}
              {_req_badge(f.pci_req)}
            </div>
          </div>
          <div style="margin-top:10px;display:grid;grid-template-columns:repeat(3,1fr);gap:8px;font-size:11px;color:#71717a">
            <div>Target: <span style="color:#a1a1aa">{html.escape(f.target[:60])}</span></div>
            {"<div>Port/Service: <span style='color:#a1a1aa'>" + str(f.port) + "/" + html.escape(f.service) + "</span></div>" if f.port else ""}
            <div>Category: <span style="color:#a1a1aa">{html.escape(f.category)}</span></div>
            <div>Phase: <span style="color:#a1a1aa">{html.escape(f.phase)}</span></div>
            <div>CVSS{cvss_str}</div>
            <div>CVEs: {cves}</div>
          </div>
          <div style="margin-top:12px">
            <h3>Description</h3>
            <p style="color:#a1a1aa;margin-top:4px">{html.escape(f.detail)}</p>
          </div>
          {"<div style='margin-top:12px'><h3>Evidence</h3>" + ev_parts + "</div>" if ev_parts else ""}
          {"<div style='margin-top:12px'><h3>Remediation</h3><p style='color:#a1a1aa;margin-top:4px'>" + html.escape(f.remediation.description) + "</p></div>" if f.remediation.description else ""}
        </div>"""

    finding_sections = "\n".join(finding_section(f, i) for i, f in enumerate(sorted_findings))

    network_rows = ""
    if summary.hosts_live:
        network_rows += f"<tr><td>Live Hosts</td><td>{summary.hosts_live}</td></tr>"
        network_rows += f"<tr><td>Open Ports</td><td>{summary.ports_open}</td></tr>"
    if summary.pages_crawled:
        network_rows += f"<tr><td>Pages Crawled</td><td>{summary.pages_crawled}</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PCI DSS Technical Report — {html.escape(summary.scope_name)}</title>
<style>{_BASE_CSS}
</style>
</head>
<body>
<div class="page">

<header>
  <h1>PCI DSS Technical Assessment Report</h1>
  <div class="sub">{html.escape(summary.scope_name)} &nbsp;·&nbsp; {html.escape(scan_date)}</div>
  <div class="sub" style="margin-top:4px">
    {sum(summary.findings_by_severity.values())} total findings &nbsp;|&nbsp;
    {summary.findings_by_severity.get('critical',0)} critical &nbsp;|&nbsp;
    {summary.findings_by_severity.get('high',0)} high
  </div>
</header>

{"<h2>Network Summary</h2><div class='card' style='padding:0'><table><tbody>" + network_rows + "</tbody></table></div>" if network_rows else ""}

{_req_coverage_table(summary)}

<h2>All Findings ({len(sorted_findings)})</h2>
{finding_sections or "<div class='card' style='color:#71717a'>No findings recorded.</div>"}

<div class="disclaimer">
  <strong>Disclaimer:</strong> Automated tool output — must be reviewed by a qualified security professional.
  PCI DSS compliance requires a formal assessment by a QSA or completion of the appropriate SAQ.
  This report does not constitute an Attestation of Compliance (AOC).
</div>

</div>
</body>
</html>"""
