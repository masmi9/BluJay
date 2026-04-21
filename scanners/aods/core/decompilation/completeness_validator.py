#!/usr/bin/env python3
"""
Completeness validator skeleton: validates manifest/resources/imports presence and
supports a stub for validate_and_escalate (not implemented here).
"""

from __future__ import annotations

from typing import Any, Dict, List


def summarize_components(findings: List[Dict[str, Any]]) -> Dict[str, bool]:
    manifest_seen = False
    resources_present = False
    imports_ok = False

    for f in findings:
        if not isinstance(f, dict):
            continue
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        fp = str(ev.get("file_path", ""))
        if "AndroidManifest.xml" in fp:
            manifest_seen = True
        if "/res/" in fp or "/assets/" in fp:
            resources_present = True
        if ev.get("file_path") and ev.get("code_snippet"):
            imports_ok = True

    return {
        "manifest_seen": manifest_seen,
        "resources_present": resources_present,
        "imports_ok": imports_ok,
    }


def validate_components(report: Dict[str, Any], mode: str = "optimized") -> Dict[str, Any]:
    findings = report.get("findings") or report.get("vulnerabilities") or report.get("vulnerability_findings") or []
    comp = summarize_components(findings)

    # Honor metadata.manifest_present like the CI gate implementation
    md = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    if isinstance(md, dict) and md.get("manifest_present"):
        comp["manifest_seen"] = True

    failures = []
    if not comp["manifest_seen"]:
        failures.append("AndroidManifest.xml not observed")
    if mode in {"optimized", "complete"} and not comp["imports_ok"]:
        failures.append("imports linkage heuristic not satisfied")
    status = "PASS" if not failures else "FAIL"
    return {"status": status, "details": comp, "failures": failures}


def validate_and_escalate(report: Dict[str, Any], mode: str = "optimized") -> Dict[str, Any]:
    # Placeholder for future: re-run decompilation with elevated flags when needed
    return validate_components(report, mode=mode)
