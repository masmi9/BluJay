#!/usr/bin/env python3
"""
BluJay headless CLI — upload an APK, wait for analysis, export findings.

Usage:
  python cli.py scan --apk app.apk
  python cli.py scan --apk app.apk --format sarif --output results.sarif
  python cli.py scan --apk app.apk --format json  --output results.json
  python cli.py scan --apk app.apk --format html  --output report.html
  python cli.py scan --apk app.apk --fail-on high  # exit 1 if high/critical found

Environment:
  BLUJAY_URL  — base URL of the BluJay backend (default: http://localhost:8000)
"""

import argparse
import json
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    print("pip install requests", file=sys.stderr)
    sys.exit(2)


def _base(url: str) -> str:
    return url.rstrip("/") + "/api/v1"


def upload(base: str, apk: Path) -> int:
    with open(apk, "rb") as f:
        r = requests.post(f"{base}/analyses", files={"file": (apk.name, f, "application/octet-stream")})
    r.raise_for_status()
    return r.json()["id"]


def wait(base: str, analysis_id: int, poll: int = 3, timeout: int = 600) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(f"{base}/analyses/{analysis_id}")
        r.raise_for_status()
        data = r.json()
        status = data.get("status")
        print(f"  [{status}] ...", end="\r", flush=True)
        if status == "complete":
            print()
            return data
        if status == "failed":
            print()
            print(f"Analysis failed: {data.get('error_message')}", file=sys.stderr)
            sys.exit(1)
        time.sleep(poll)
    print(f"\nTimeout after {timeout}s", file=sys.stderr)
    sys.exit(1)


def fetch_report(base: str, analysis_id: int, fmt: str) -> bytes:
    endpoint = f"{base}/report/analysis/{analysis_id}"
    if fmt == "sarif":
        endpoint += "/sarif"
    r = requests.get(endpoint)
    r.raise_for_status()
    return r.content


def fetch_findings(base: str, analysis_id: int) -> list[dict]:
    r = requests.get(f"{base}/analyses/{analysis_id}/findings")
    r.raise_for_status()
    return r.json().get("findings", [])


_FAIL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def check_threshold(findings: list[dict], threshold: str) -> bool:
    thresh_level = _FAIL_ORDER.get(threshold, 99)
    for f in findings:
        if _FAIL_ORDER.get(f.get("severity", "info"), 99) <= thresh_level:
            return True
    return False


def cmd_scan(args: argparse.Namespace) -> None:
    apk = Path(args.apk)
    if not apk.exists():
        print(f"File not found: {apk}", file=sys.stderr)
        sys.exit(1)

    base = _base(args.url)
    print(f"Uploading {apk.name} → {base}")
    analysis_id = upload(base, apk)
    print(f"Analysis ID: {analysis_id} — waiting for completion...")
    wait(base, analysis_id)

    fmt = args.format
    content = fetch_report(base, analysis_id, fmt)

    if args.output:
        Path(args.output).write_bytes(content)
        print(f"Report written to {args.output}")
    else:
        sys.stdout.buffer.write(content)

    if args.fail_on:
        findings = fetch_findings(base, analysis_id)
        if check_threshold(findings, args.fail_on):
            print(f"\nFAIL: findings at or above '{args.fail_on}' severity found.", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"PASS: no findings at or above '{args.fail_on}' severity.")


def main() -> None:
    parser = argparse.ArgumentParser(description="BluJay headless CLI")
    parser.add_argument("--url", default="http://localhost:8000", help="BluJay backend URL")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Upload and analyse an APK/IPA")
    scan_p.add_argument("--apk", required=True, help="Path to the APK or IPA file")
    scan_p.add_argument("--format", choices=["html", "sarif", "json"], default="html")
    scan_p.add_argument("--output", help="Write report to this file instead of stdout")
    scan_p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                        help="Exit code 1 if any finding matches this severity or higher")

    args = parser.parse_args()
    if args.command == "scan":
        cmd_scan(args)


if __name__ == "__main__":
    main()
