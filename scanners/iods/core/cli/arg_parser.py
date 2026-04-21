"""
IODS CLI Argument Parser.
"""
from __future__ import annotations

import argparse


def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ios_scan.py",
        description="IODS – iOS OWASP Dynamic Scan Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ios_scan.py --ipa MyApp.ipa --mode safe
  python ios_scan.py --ipa MyApp.ipa --mode deep --profile standard
  python ios_scan.py --ipa MyApp.ipa --static-only --formats json html
  python ios_scan.py --batch-targets targets.txt --ci-mode --fail-on-critical
        """,
    )

    # ── Core ──────────────────────────────────────────────────────────────────
    core = parser.add_argument_group("Core")
    core.add_argument("--ipa", metavar="PATH", help="Path to the IPA file to analyze")
    core.add_argument("--mode", choices=["safe", "deep", "agent"], default="safe",
                      help="Scan mode: safe (static only), deep (static+dynamic), agent (AI-assisted)")
    core.add_argument("--profile", choices=["lightning", "fast", "standard", "deep"], default="standard",
                      help="Analysis depth profile")

    # ── Execution control ─────────────────────────────────────────────────────
    exec_group = parser.add_argument_group("Execution")
    exec_group.add_argument("--static-only", action="store_true",
                            help="Run static analysis only (no device required)")
    exec_group.add_argument("--dynamic-only", action="store_true",
                            help="Run dynamic analysis only (requires device + Frida)")
    exec_group.add_argument("--parallel", action="store_true", default=True,
                            help="Run static plugins in parallel (default: true)")
    exec_group.add_argument("--sequential", action="store_true",
                            help="Run plugins sequentially")
    exec_group.add_argument("--disable-ml", action="store_true",
                            help="Disable ML false-positive reduction")
    exec_group.add_argument("--vulnerable-app-mode", action="store_true",
                            help="Relax ML thresholds (for CTF/test apps)")
    exec_group.add_argument("--device-udid", metavar="UDID",
                            help="Device UDID for dynamic analysis")

    # ── Output ────────────────────────────────────────────────────────────────
    out_group = parser.add_argument_group("Output")
    out_group.add_argument("--output-dir", metavar="DIR", default="reports",
                           help="Directory for output reports (default: reports/)")
    out_group.add_argument("--formats", nargs="+", choices=["json", "html", "csv", "txt"],
                           default=["json", "txt"],
                           help="Report formats to generate (default: json txt)")
    out_group.add_argument("--verbose", "-v", action="store_true",
                           help="Verbose output")
    out_group.add_argument("--quiet", "-q", action="store_true",
                           help="Suppress console output")

    # ── ML ────────────────────────────────────────────────────────────────────
    ml_group = parser.add_argument_group("ML")
    ml_group.add_argument("--app-profile", choices=["production", "vulnerable", "qa_vulnerable"],
                          default="production",
                          help="App profile for ML threshold selection")
    ml_group.add_argument("--ml-fp-threshold", type=float, metavar="FLOAT",
                          help="Override ML false-positive threshold (0.0–1.0)")
    ml_group.add_argument("--force-ml-filtering", action="store_true",
                          help="Force ML filtering even in safe mode")

    # ── Batch / CI ────────────────────────────────────────────────────────────
    batch_group = parser.add_argument_group("Batch / CI")
    batch_group.add_argument("--batch-targets", metavar="FILE",
                             help="File listing IPA paths (one per line) for batch analysis")
    batch_group.add_argument("--batch-parallel", action="store_true",
                             help="Analyze batch targets in parallel")
    batch_group.add_argument("--ci-mode", action="store_true",
                             help="CI/CD mode: machine-readable output, strict exit codes")
    batch_group.add_argument("--fail-on-critical", action="store_true",
                             help="Exit non-zero if any critical findings are detected")
    batch_group.add_argument("--fail-on-high", action="store_true",
                             help="Exit non-zero if any high-severity findings are detected")

    # ── Compliance ────────────────────────────────────────────────────────────
    comp_group = parser.add_argument_group("Compliance")
    comp_group.add_argument("--compliance", nargs="+",
                            choices=["masvs", "owasp", "nist", "pci"],
                            help="Compliance frameworks to map findings to")

    # ── Workspace ─────────────────────────────────────────────────────────────
    ws_group = parser.add_argument_group("Workspace")
    ws_group.add_argument("--workspace", metavar="DIR", default="workspace",
                          help="Workspace root for decompiled artifacts (default: workspace/)")
    ws_group.add_argument("--keep-workspace", action="store_true",
                          help="Keep decompiled artifacts after scan")

    return parser
