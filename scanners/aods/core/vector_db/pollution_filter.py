"""
AODS Vector DB Pollution Filter
===============================

This module implements the "No Pollution" policy for the vector database.
It ensures that example, demo, test, and template findings are never indexed,
preventing synthetic vulnerabilities from contaminating the semantic layer.

Key Rules:
1. Never index findings from example/demo/test plugins
2. Never index findings with placeholder/demo content markers
3. Never index findings without stable identifiers (finding_id or id)
4. Never index findings without owner metadata (enforced at index time)

Example plugins that MUST be excluded:
- plugins/example_static_analyzer_v2
- plugins/examples/*
- Any plugin with 'example_', 'demo_', 'template_', 'test_' prefix

Content markers that indicate synthetic findings:
- "not implemented"
- "placeholder"
- "demo vulnerability"
- "example finding"
- "TODO"
- "FIXME"
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

# Logging with graceful fallback
try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Denylist Configuration
# ---------------------------------------------------------------------------

# Plugin source patterns to exclude (case-insensitive match)
EXCLUDED_PLUGIN_PATTERNS: List[str] = [
    "example_static_analyzer_v2",
    "example_",
    "demo_",
    "template_",
    "test_",
    "examples/",
    "example/",
    "mock_",
    "stub_",
    "fake_",
    "sample_",
]

# Content markers that indicate synthetic/placeholder findings (case-insensitive)
EXCLUDED_CONTENT_MARKERS: List[str] = [
    "not implemented",
    "placeholder",
    "demo vulnerability",
    "example finding",
    "example vulnerability",
    "sample vulnerability",
    "todo:",
    "fixme:",
    "xxx:",
    "this is a test",
    "this is an example",
    "for testing purposes",
    "for demonstration",
]

# Additional patterns that indicate unreliable findings
EXCLUDED_DESCRIPTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"\[placeholder\]", re.IGNORECASE),
    re.compile(r"\[example\]", re.IGNORECASE),
    re.compile(r"\[demo\]", re.IGNORECASE),
    re.compile(r"lorem\s+ipsum", re.IGNORECASE),
    re.compile(r"foo\s*bar", re.IGNORECASE),
    re.compile(r"test\s+vulnerability\s+\d+", re.IGNORECASE),
]

# Minimum description length for valid findings (too short = likely placeholder)
MIN_DESCRIPTION_LENGTH = 10


# ---------------------------------------------------------------------------
# Pollution Filter Functions
# ---------------------------------------------------------------------------


def should_index_finding(finding: Dict[str, Any]) -> bool:
    """
    Check if a finding should be indexed in the vector database.

    This function implements the "No Pollution" policy to ensure only
    legitimate, production findings are indexed.

    Args:
        finding: The finding dict to evaluate

    Returns:
        True if the finding should be indexed, False otherwise

    Examples:
        >>> should_index_finding({"plugin_source": "example_static_analyzer_v2"})
        False
        >>> should_index_finding({"description": "This is a placeholder"})
        False
        >>> should_index_finding({"title": "SQL Injection", "id": "abc123"})
        True
    """
    # Check plugin source denylist
    source = str(finding.get("plugin_source", "") or finding.get("source", "") or "")
    if _is_excluded_source(source):
        logger.debug("pollution_filter_excluded", reason="source_denylist", source=source)
        return False

    # Check content markers
    description = str(finding.get("description", "") or "")
    title = str(finding.get("title", "") or finding.get("name", "") or "")
    combined_text = f"{title} {description}".lower()

    if _has_excluded_markers(combined_text):
        logger.debug("pollution_filter_excluded", reason="content_marker", title=title[:50])
        return False

    # Check regex patterns
    if _matches_excluded_patterns(combined_text):
        logger.debug("pollution_filter_excluded", reason="pattern_match", title=title[:50])
        return False

    # Require stable identifier
    finding_id = finding.get("id") or finding.get("finding_id") or finding.get("unique_id")
    if not finding_id:
        logger.debug("pollution_filter_excluded", reason="no_stable_id", title=title[:50])
        return False

    # Check minimum description length
    if len(description.strip()) < MIN_DESCRIPTION_LENGTH:
        logger.debug(
            "pollution_filter_excluded",
            reason="description_too_short",
            length=len(description),
            title=title[:50],
        )
        return False

    return True


def _is_excluded_source(source: str) -> bool:
    """Check if the source matches any excluded plugin pattern."""
    source_lower = source.lower()
    for pattern in EXCLUDED_PLUGIN_PATTERNS:
        if pattern.lower() in source_lower:
            return True
    return False


def _has_excluded_markers(text: str) -> bool:
    """Check if the text contains any excluded content markers."""
    for marker in EXCLUDED_CONTENT_MARKERS:
        if marker in text:
            return True
    return False


def _matches_excluded_patterns(text: str) -> bool:
    """Check if the text matches any excluded regex patterns."""
    for pattern in EXCLUDED_DESCRIPTION_PATTERNS:
        if pattern.search(text):
            return True
    return False


def can_index_with_context(finding: Dict[str, Any], scan_context: Dict[str, Any]) -> bool:
    """
    Check if a finding can be indexed given its scan context.

    This function adds ownership validation on top of the basic pollution filter.

    Args:
        finding: The finding dict to evaluate
        scan_context: Context from the scan (must include owner_user_id)

    Returns:
        True if the finding can be indexed, False otherwise
    """
    # Apply basic pollution filter first
    if not should_index_finding(finding):
        return False

    # Require owner metadata
    owner_user_id = scan_context.get("owner_user_id")
    if not owner_user_id:
        logger.warning(
            "pollution_filter_no_owner",
            scan_id=scan_context.get("scan_id", "unknown"),
        )
        return False

    return True


def get_pollution_filter_stats(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Get statistics about filtering applied to a list of findings.

    Args:
        findings: List of findings to analyze

    Returns:
        Dict with counts of included/excluded findings by reason
    """
    stats = {
        "total": len(findings),
        "included": 0,
        "excluded_source": 0,
        "excluded_content": 0,
        "excluded_pattern": 0,
        "excluded_no_id": 0,
        "excluded_short_desc": 0,
    }

    for finding in findings:
        source = str(finding.get("plugin_source", "") or finding.get("source", "") or "")
        description = str(finding.get("description", "") or "")
        title = str(finding.get("title", "") or finding.get("name", "") or "")
        combined_text = f"{title} {description}".lower()

        if _is_excluded_source(source):
            stats["excluded_source"] += 1
        elif _has_excluded_markers(combined_text):
            stats["excluded_content"] += 1
        elif _matches_excluded_patterns(combined_text):
            stats["excluded_pattern"] += 1
        elif not (finding.get("id") or finding.get("finding_id") or finding.get("unique_id")):
            stats["excluded_no_id"] += 1
        elif len(description.strip()) < MIN_DESCRIPTION_LENGTH:
            stats["excluded_short_desc"] += 1
        else:
            stats["included"] += 1

    return stats


def add_exclusion_pattern(pattern: str, pattern_type: str = "source") -> None:
    """
    Add a new exclusion pattern at runtime.

    Args:
        pattern: The pattern to add
        pattern_type: One of 'source', 'content', 'regex'

    Raises:
        ValueError: If pattern_type is invalid
    """
    if pattern_type == "source":
        if pattern not in EXCLUDED_PLUGIN_PATTERNS:
            EXCLUDED_PLUGIN_PATTERNS.append(pattern)
    elif pattern_type == "content":
        if pattern not in EXCLUDED_CONTENT_MARKERS:
            EXCLUDED_CONTENT_MARKERS.append(pattern)
    elif pattern_type == "regex":
        compiled = re.compile(pattern, re.IGNORECASE)
        EXCLUDED_DESCRIPTION_PATTERNS.append(compiled)
    else:
        raise ValueError(f"Invalid pattern_type: {pattern_type}. Must be 'source', 'content', or 'regex'")

    logger.info("pollution_filter_pattern_added", pattern_type=pattern_type, pattern=pattern)
