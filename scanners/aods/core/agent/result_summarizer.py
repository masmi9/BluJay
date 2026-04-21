"""
core.agent.result_summarizer - Summarize large tool results before sending to LLM.

When tool results exceed a configurable threshold, this module produces
a compact summary that preserves key information (titles, severities,
CWEs) while reducing token count. Full data remains available via
follow-up tool calls with specific indices.
"""

from __future__ import annotations

import json
from typing import Any, Dict

# Default threshold - results larger than this get summarized
DEFAULT_SUMMARIZE_THRESHOLD = 8000


def should_summarize(tool_name: str, result_data: Any, threshold: int = DEFAULT_SUMMARIZE_THRESHOLD) -> bool:
    """Check if a tool result should be summarized.

    Args:
        tool_name: Name of the tool that produced the result.
        result_data: The result data dict.
        threshold: Character threshold for summarization.

    Returns:
        True if the result should be summarized.
    """
    if not isinstance(result_data, dict):
        return False
    try:
        serialized = json.dumps(result_data, default=str)
        return len(serialized) > threshold
    except (TypeError, ValueError):
        return False


def summarize_tool_result(tool_name: str, result_data: Dict) -> Dict:
    """Produce a compact summary of a large tool result.

    Dispatches to tool-specific summarizers based on tool_name.
    Falls back to generic value truncation for unknown tools.

    Args:
        tool_name: Name of the tool.
        result_data: The full result data dict.

    Returns:
        Summarized dict with key information preserved.
    """
    if tool_name == "list_findings":
        return _summarize_findings_list(result_data)
    if tool_name == "get_report_section":
        return _summarize_report_section(result_data)
    if tool_name == "search_source":
        return _summarize_search_results(result_data)
    return _truncate_large_values(result_data)


def _summarize_findings_list(data: Dict) -> Dict:
    """Summarize a list_findings response.

    Groups findings by severity and CWE, preserving titles but
    removing verbose fields (description, evidence, code_snippet).
    """
    findings = data.get("findings", [])
    if not isinstance(findings, list):
        return data

    by_severity: Dict[str, int] = {}
    by_cwe: Dict[str, int] = {}
    compact_findings = []

    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        by_severity[sev] = by_severity.get(sev, 0) + 1

        cwe = f.get("cwe_id") or f.get("cwe", "")
        if cwe:
            by_cwe[str(cwe)] = by_cwe.get(str(cwe), 0) + 1

        compact_findings.append({
            "index": f.get("index", len(compact_findings)),
            "title": f.get("title", ""),
            "severity": sev,
            "cwe": cwe,
            "confidence": f.get("confidence", 0),
            "file": f.get("file_path", f.get("file", "")),
        })

    return {
        "_summarized": True,
        "total": data.get("total_filtered", len(findings)),
        "has_more": data.get("has_more", False),
        "offset": data.get("offset", 0),
        "returned": len(compact_findings),
        "by_severity": by_severity,
        "by_cwe": by_cwe,
        "findings": compact_findings,
        "_note": (
            "This is a summary. Use get_finding_detail with the finding index "
            "to examine individual findings in depth."
        ),
    }


def _summarize_report_section(data: Dict) -> Dict:
    """Summarize a large report section."""
    content = data.get("content", "")
    if isinstance(content, str) and len(content) > 5000:
        return {
            "_summarized": True,
            "content": content[:5000],
            "_original_chars": len(content),
            "_note": "Content truncated. Use get_finding_detail for individual findings.",
        }
    # For dict content, truncate large nested values
    if isinstance(content, (dict, list)):
        return _truncate_large_values(data)
    return data


def _summarize_search_results(data: Dict) -> Dict:
    """Summarize large search results."""
    matches = data.get("matches", [])
    if not isinstance(matches, list):
        return data

    compact = []
    for m in matches:
        compact.append({
            "file": m.get("file", ""),
            "line": m.get("line", 0),
            "content": (m.get("content", "") or "")[:80],
        })

    return {
        "_summarized": True,
        "total_matches": data.get("total_matches", len(matches)),
        "matches": compact,
    }


def _truncate_large_values(data: Dict, max_value_len: int = 2000) -> Dict:
    """Generic truncation: cap string values at max_value_len."""
    result = {}
    for key, value in data.items():
        if isinstance(value, str) and len(value) > max_value_len:
            result[key] = value[:max_value_len]
            result[f"_{key}_truncated"] = True
            result[f"_{key}_original_len"] = len(value)
        elif isinstance(value, list) and len(value) > 50:
            result[key] = value[:50]
            result[f"_{key}_truncated"] = True
            result[f"_{key}_total"] = len(value)
        else:
            result[key] = value
    return result
