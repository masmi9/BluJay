#!/usr/bin/env python3
"""
Evidence Quality Metrics Utility
================================

Computes evidence quality coverage metrics over vulnerability findings and
evaluates them against enforcement thresholds.

This utility is tolerant to multiple shapes used across AODS:
- Canonical schema: findings include a list under 'evidence' with entries that
  may have 'evidence_type' == 'code_snippet' and nested 'location' with
  'file_path' and 'line_number'.
- Final serializer schema: findings include a dict under 'evidence' with
  'file_path' and 'line_number'.

Outputs concise coverage percentages to support CI gates and local validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass(frozen=True)
class EvidenceQualityThresholds:
    code_snippet_pct: float = 0.90
    line_number_pct: float = 0.85
    file_path_pct: float = 0.90
    taxonomy_pct: float = 0.95  # OWASP or CWE present


def _safe_get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return default


def _has_code_snippet(evidence: Any) -> bool:
    # Canonical list form
    if isinstance(evidence, list):
        for ev in evidence:
            if not isinstance(ev, dict):
                continue
            ev_type = _safe_get(ev, "evidence_type", "")
            content = _safe_get(ev, "content", "")
            if isinstance(ev_type, str) and ev_type.lower() == "code_snippet" and bool(content):
                return True
        return False

    # Final serializer dict form (no explicit evidence_type; treat content or code_snippet as snippet)
    if isinstance(evidence, dict):
        content = _safe_get(evidence, "content", "")
        if bool(content):
            return True
        # Also accept 'code_snippet' as valid snippet content
        code_snippet = _safe_get(evidence, "code_snippet", "")
        return bool(code_snippet)

    return False


def _has_file_path(evidence: Any) -> bool:
    if isinstance(evidence, list):
        for ev in evidence:
            if not isinstance(ev, dict):
                continue
            loc = _safe_get(ev, "location", {})
            if isinstance(loc, dict) and bool(_safe_get(loc, "file_path", "")):
                return True
        return False

    if isinstance(evidence, dict):
        return bool(_safe_get(evidence, "file_path", ""))

    return False


def _has_line_number(evidence: Any) -> bool:
    if isinstance(evidence, list):
        for ev in evidence:
            if not isinstance(ev, dict):
                continue
            loc = _safe_get(ev, "location", {})
            ln = _safe_get(loc, "line_number", None) if isinstance(loc, dict) else None
            if isinstance(ln, int):
                return True
            # tolerate numeric strings
            if isinstance(ln, str) and ln.isdigit():
                return True
        return False

    if isinstance(evidence, dict):
        ln = _safe_get(evidence, "line_number", None)
        if isinstance(ln, int):
            return True
        if isinstance(ln, str) and ln.isdigit():
            return True
    return False


def _has_taxonomy(finding: Dict[str, Any]) -> bool:
    taxonomy = _safe_get(finding, "taxonomy", {})
    if isinstance(taxonomy, dict):
        owasp = _safe_get(taxonomy, "owasp_categories", [])
        cwe = _safe_get(taxonomy, "cwe_ids", [])
        if isinstance(owasp, list) and len(owasp) > 0:
            return True
        if isinstance(cwe, list) and len(cwe) > 0:
            return True
    # fallback: alternate shapes
    owasp_alt = _safe_get(finding, "owasp_category", [])
    if isinstance(owasp_alt, list) and len(owasp_alt) > 0:
        return True
    if isinstance(owasp_alt, str) and owasp_alt.strip():
        return True
    cwe_alt = _safe_get(finding, "cwe_id", "")
    if isinstance(cwe_alt, str) and cwe_alt.strip():
        return True
    return False


def calculate_evidence_quality_metrics(findings: List[Dict[str, Any]]) -> Dict[str, float]:
    total = len(findings) if isinstance(findings, list) else 0
    if total == 0:
        return {
            "total": 0.0,
            "code_snippet_pct": 0.0,
            "line_number_pct": 0.0,
            "file_path_pct": 0.0,
            "taxonomy_pct": 0.0,
        }

    code_snippet = 0
    line_number = 0
    file_path = 0
    taxonomy = 0

    for f in findings:
        if not isinstance(f, dict):
            continue
        ev = _safe_get(f, "evidence", None)
        if _has_code_snippet(ev):
            code_snippet += 1
        if _has_line_number(ev):
            line_number += 1
        if _has_file_path(ev):
            file_path += 1
        if _has_taxonomy(f):
            taxonomy += 1

    return {
        "total": float(total),
        "code_snippet_pct": code_snippet / total,
        "line_number_pct": line_number / total,
        "file_path_pct": file_path / total,
        "taxonomy_pct": taxonomy / total,
    }


def check_thresholds(
    metrics: Dict[str, float], thresholds: EvidenceQualityThresholds | None = None
) -> Tuple[bool, Dict[str, Tuple[float, float]]]:
    """Return (ok, failures) where failures maps metric->(value, required)."""
    t = thresholds or EvidenceQualityThresholds()
    failures: Dict[str, Tuple[float, float]] = {}

    for key, required in (
        ("code_snippet_pct", t.code_snippet_pct),
        ("line_number_pct", t.line_number_pct),
        ("file_path_pct", t.file_path_pct),
        ("taxonomy_pct", t.taxonomy_pct),
    ):
        value = float(metrics.get(key, 0.0) or 0.0)
        if value < required:
            failures[key] = (value, required)

    return (len(failures) == 0, failures)


__all__ = [
    "EvidenceQualityThresholds",
    "calculate_evidence_quality_metrics",
    "check_thresholds",
]
