"""
IODS Standard Execution – sequential scan path.

Flow: extract IPA → run static plugins → EVRE → ML → generate reports
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Dict, List

from core.logging_config import get_logger
from core.ipa.ipa_context import IPAContext
from core.ipa.ipa_extractor import IPAExtractor
from core.ipa.ipa_analyzer import IPAAnalyzer
from core.plugins.ios_plugin_manager import IOSPluginManager

logger = get_logger(__name__)


def run_standard_scan(ctx) -> int:
    """
    Execute the standard sequential scan.

    Args:
        ctx: ExecutionContext from execution_setup.py

    Returns:
        Exit code (0=success, 1=findings exceed threshold, 2=error)
    """
    args = ctx.args
    output_mgr = ctx.output_mgr

    output_mgr.banner()
    output_mgr.scan_start(args.ipa, args.mode, args.profile)

    # ── 1. Build IPA context ──────────────────────────────────────────────────
    ipa_ctx = IPAContext(
        ipa_path=args.ipa,
        workspace_root=getattr(args, "workspace", "workspace"),
    )
    ipa_ctx.scan_mode = args.mode
    ipa_ctx.scan_profile = args.profile
    ipa_ctx.ml_enabled = ctx.ml_enabled
    ipa_ctx.is_vulnerable_app_mode = getattr(args, "vulnerable_app_mode", False)

    # ── 2. Extract IPA ────────────────────────────────────────────────────────
    analyzer = IPAAnalyzer(ipa_ctx)
    t0 = time.time()
    if not analyzer.prepare():
        output_mgr.error("IPA extraction failed – aborting scan.")
        return 2

    logger.info("Extraction complete", elapsed=f"{time.time() - t0:.2f}s")

    # ── 3. Load and run plugins ───────────────────────────────────────────────
    plugin_mgr = IOSPluginManager(plugins_dir="plugins", profile=args.profile)
    plugin_mgr.discover_plugins()

    t1 = time.time()
    all_findings: List[Dict[str, Any]] = []

    if not ctx.dynamic_enabled or ctx.static_only:
        # Static analysis
        static_results = plugin_mgr.run_static_plugins(
            ipa_ctx,
            max_workers=int(os.environ.get("IODS_PARALLEL_WORKERS", "4")) if ctx.parallel else 1,
        )
        for r in static_results:
            all_findings.extend(r.get("findings", []))
            output_mgr.plugin_progress(
                r["plugin"],
                r.get("status", "?"),
                r.get("execution_time", 0),
                len(r.get("findings", [])),
            )

    if ctx.dynamic_enabled and not ctx.static_only:
        # Dynamic analysis
        dynamic_results = plugin_mgr.run_dynamic_plugins(ipa_ctx)
        for r in dynamic_results:
            all_findings.extend(r.get("findings", []))

    logger.info(
        "Plugin execution complete",
        findings=len(all_findings),
        elapsed=f"{time.time() - t1:.2f}s",
    )

    # ── 4. ML false-positive reduction ────────────────────────────────────────
    if ctx.ml_enabled and all_findings:
        try:
            from core.ml.ios_unified_pipeline import IOSMLPipeline
            pipeline = IOSMLPipeline(threshold=ctx.ml_fp_threshold)
            all_findings = pipeline.filter_findings(all_findings, ipa_ctx)
            logger.info("ML filtering complete", remaining=len(all_findings))
        except Exception as e:
            logger.warning("ML pipeline failed, using unfiltered findings", error=str(e))

    # ── 5. EVRE reporting pipeline ────────────────────────────────────────────
    try:
        from core.evre import IOSReportingEngine
        engine = IOSReportingEngine(
            ipa_ctx=ipa_ctx,
            findings=all_findings,
            config=ctx.config_data,
        )
        report_data = engine.run_pipeline()
    except Exception as e:
        logger.warning("EVRE pipeline error, building basic report", error=str(e))
        report_data = _build_basic_report(ipa_ctx, all_findings)

    # ── 6. Write reports ──────────────────────────────────────────────────────
    output_dir = Path(getattr(args, "output_dir", "reports"))
    output_dir.mkdir(parents=True, exist_ok=True)
    formats = getattr(args, "formats", ["json", "txt"])

    written = _write_reports(report_data, ipa_ctx, output_dir, formats)
    for path in written:
        output_mgr.report_saved(path)

    # ── 7. Summary ────────────────────────────────────────────────────────────
    summary = analyzer.get_summary()
    summary["total_findings"] = len(all_findings)
    severity_counts: Dict[str, int] = {}
    for f in all_findings:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    summary["severity_counts"] = severity_counts
    output_mgr.scan_complete(summary)

    # ── 8. Cleanup workspace ──────────────────────────────────────────────────
    if not getattr(args, "keep_workspace", False):
        import shutil
        try:
            shutil.rmtree(ipa_ctx.workspace_dir, ignore_errors=True)
        except Exception:
            pass

    # ── 9. Exit code ──────────────────────────────────────────────────────────
    if getattr(args, "fail_on_critical", False) and severity_counts.get("critical", 0) > 0:
        return 1
    if getattr(args, "fail_on_high", False) and severity_counts.get("high", 0) > 0:
        return 1
    return 0


def _build_basic_report(ipa_ctx: IPAContext, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Minimal report when EVRE is unavailable."""
    return {
        "app": ipa_ctx.summary(),
        "findings": findings,
        "total_findings": len(findings),
    }


def _write_reports(
    report_data: Dict[str, Any],
    ipa_ctx: IPAContext,
    output_dir: Path,
    formats: List[str],
) -> List[str]:
    """Write report files in requested formats. Returns list of written paths."""
    import json
    import csv
    import io

    written = []
    base_name = f"{ipa_ctx.app_name}_{ipa_ctx.analysis_id}"

    for fmt in formats:
        try:
            if fmt == "json":
                path = output_dir / f"{base_name}.json"
                path.write_text(json.dumps(report_data, indent=2, default=str))
                written.append(str(path))

            elif fmt == "txt":
                path = output_dir / f"{base_name}.txt"
                path.write_text(_format_txt_report(report_data, ipa_ctx))
                written.append(str(path))

            elif fmt == "csv":
                path = output_dir / f"{base_name}.csv"
                _write_csv_report(report_data, path)
                written.append(str(path))

            elif fmt == "html":
                path = output_dir / f"{base_name}.html"
                path.write_text(_format_html_report(report_data, ipa_ctx))
                written.append(str(path))
        except Exception as e:
            logger.warning("Failed to write report", fmt=fmt, error=str(e))

    return written


def _format_txt_report(report_data: Dict[str, Any], ipa_ctx: IPAContext) -> str:
    lines = [
        "=" * 70,
        "IODS – iOS Security Analysis Report",
        "=" * 70,
        f"App:      {ipa_ctx.display_name or ipa_ctx.app_name}",
        f"Bundle:   {ipa_ctx.bundle_id}",
        f"Version:  {ipa_ctx.short_version}",
        f"Profile:  {ipa_ctx.scan_profile}",
        f"Mode:     {ipa_ctx.scan_mode}",
        "",
        f"Total Findings: {report_data.get('total_findings', 0)}",
        "-" * 70,
    ]
    for finding in report_data.get("findings", []):
        lines += [
            "",
            f"[{finding.get('severity', '?').upper()}] {finding.get('title', 'Unknown')}",
            f"  ID:       {finding.get('finding_id', '?')}",
            f"  CWE:      {finding.get('cwe_id', 'N/A')}",
            f"  MASVS:    {finding.get('masvs_control', 'N/A')}",
            f"  File:     {finding.get('file_path', 'N/A')}",
            f"  Confidence: {finding.get('confidence', 0):.0%}",
            f"  {finding.get('description', '')}",
        ]
        if finding.get("remediation"):
            lines.append(f"  Remediation: {finding['remediation']}")
    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


def _write_csv_report(report_data: Dict[str, Any], path: Path) -> None:
    import csv
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "finding_id", "title", "severity", "confidence",
            "cwe_id", "masvs_control", "file_path", "line_number",
            "vulnerability_type", "description",
        ])
        writer.writeheader()
        for finding in report_data.get("findings", []):
            writer.writerow({k: finding.get(k, "") for k in writer.fieldnames})


def _format_html_report(report_data: Dict[str, Any], ipa_ctx: IPAContext) -> str:
    findings_html = ""
    for f in report_data.get("findings", []):
        sev = f.get("severity", "info").lower()
        color = {"critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107",
                 "low": "#0dcaf0", "info": "#6c757d"}.get(sev, "#6c757d")
        findings_html += f"""
        <div class="finding" style="border-left: 4px solid {color}; margin: 12px 0; padding: 12px; background: #f8f9fa;">
          <h4 style="color:{color}; margin:0">[{sev.upper()}] {f.get('title','')}</h4>
          <p>{f.get('description','')}</p>
          <small>CWE: {f.get('cwe_id','N/A')} | MASVS: {f.get('masvs_control','N/A')} | File: {f.get('file_path','N/A')}</small>
          {'<p><strong>Remediation:</strong> ' + f.get('remediation','') + '</p>' if f.get('remediation') else ''}
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>IODS Report – {ipa_ctx.display_name}</title>
<style>body{{font-family:sans-serif;max-width:1000px;margin:auto;padding:20px}}
h1{{color:#0d6efd}} .meta{{background:#e9ecef;padding:12px;border-radius:4px}}</style>
</head>
<body>
<h1>IODS iOS Security Report</h1>
<div class="meta">
  <b>App:</b> {ipa_ctx.display_name or ipa_ctx.app_name} &nbsp;
  <b>Bundle:</b> {ipa_ctx.bundle_id} &nbsp;
  <b>Version:</b> {ipa_ctx.short_version} &nbsp;
  <b>Findings:</b> {report_data.get('total_findings',0)}
</div>
<h2>Findings</h2>
{findings_html or '<p>No findings.</p>'}
</body></html>"""
