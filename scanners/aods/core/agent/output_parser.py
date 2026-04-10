"""
core.agent.output_parser - Shared structured output parser for all agents (Track 104).

Extracts structured JSON from LLM responses using 3 strategies in priority order:
1. XML tags - ``<tag>JSON</tag>``
2. Markdown code blocks - ``` ```json JSON ``` ```
3. Bare JSON - brace-matched ``json.JSONDecoder().raw_decode()``

Public API:
    parse_structured_output() - Parse JSON from agent response text
    make_parse_check() - Create a parse_check callback for AgentLoop retry
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, Optional, Set

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


def parse_structured_output(
    response_text: str,
    xml_tag: str,
    expected_fields: Set[str],
    agent_name: str = "agent",
) -> Optional[Dict[str, Any]]:
    """Extract structured JSON from an agent response.

    Tries three strategies in order:
    1. XML tags  - ``<xml_tag>...</xml_tag>``
    2. Code blocks - ``` ```json {...} ``` ``` with brace balancing
    3. Bare JSON - ``json.JSONDecoder().raw_decode()`` from first ``{``

    Args:
        response_text: Full LLM response text.
        xml_tag: Expected XML wrapper tag (e.g. ``"triage_json"``).
        expected_fields: Set of field names; at least one must be present for
            strategy 3 (bare JSON) to accept the result.
        agent_name: Agent name for log messages.

    Returns:
        Parsed dict on success, ``None`` on failure.
    """
    if not response_text or not response_text.strip():
        return None

    # Strategy 1: XML tags
    result = _parse_xml_tag(response_text, xml_tag, agent_name)
    if result is not None:
        return result

    # Strategy 2: Markdown code blocks (with brace balancing)
    result = _parse_code_block(response_text, agent_name)
    if result is not None:
        return result

    # Strategy 3: Bare JSON via raw_decode
    result = _parse_bare_json(response_text, expected_fields, agent_name)
    if result is not None:
        return result

    logger.info("output_parse_all_failed", agent=agent_name)
    return None


def make_parse_check(
    xml_tag: str,
    expected_fields: Set[str],
) -> Callable[[str], bool]:
    """Create a parse_check callback for AgentLoop retry mechanism.

    Returns a callable that returns True if the response contains parseable
    structured output, False otherwise.
    """

    def _check(response_text: str) -> bool:
        return parse_structured_output(
            response_text, xml_tag, expected_fields, agent_name="parse_check"
        ) is not None

    return _check


# ---------------------------------------------------------------------------
# Internal parsing strategies
# ---------------------------------------------------------------------------


def _parse_xml_tag(
    text: str, xml_tag: str, agent_name: str
) -> Optional[Dict[str, Any]]:
    """Strategy 1: Extract JSON from ``<xml_tag>...</xml_tag>``.

    Uses rfind for the closing tag to handle nested XML-like content
    inside JSON values.
    """
    open_tag = f"<{xml_tag}>"
    close_tag = f"</{xml_tag}>"
    start = text.find(open_tag)
    if start == -1:
        return None
    end = text.rfind(close_tag)
    if end == -1 or end <= start:
        return None
    inner = text[start + len(open_tag):end].strip()
    if not inner:
        return None
    try:
        data = json.loads(inner)
        if isinstance(data, dict):
            logger.debug("output_parsed_via_xml", agent=agent_name, tag=xml_tag)
            return data
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("output_xml_parse_failed", agent=agent_name, error=str(e))
    return None


def _parse_code_block(text: str, agent_name: str) -> Optional[Dict[str, Any]]:
    """Strategy 2: Extract JSON from markdown code blocks with brace balancing.

    Handles nested JSON properly by finding the opening ``{`` inside the code
    block and using ``json.JSONDecoder().raw_decode()`` from that position.
    """
    # Find ```json or ``` blocks
    block_pattern = r"```(?:json)?\s*(\{[\s\S]*?)\s*```"
    for match in re.finditer(block_pattern, text):
        block_content = match.group(1).strip()
        try:
            decoder = json.JSONDecoder()
            data, _ = decoder.raw_decode(block_content)
            if isinstance(data, dict):
                logger.debug("output_parsed_via_code_block", agent=agent_name)
                return data
        except (json.JSONDecodeError, ValueError):
            continue
    return None


def _parse_bare_json(
    text: str, expected_fields: Set[str], agent_name: str
) -> Optional[Dict[str, Any]]:
    """Strategy 3: Extract bare JSON using ``json.JSONDecoder().raw_decode()``.

    Scans for the first ``{`` and uses raw_decode to handle nested braces
    correctly.  Only accepts the result if at least one expected field is
    present in the parsed dict.
    """
    idx = text.find("{")
    if idx == -1:
        return None

    decoder = json.JSONDecoder()
    # Try raw_decode from each { found
    while idx < len(text):
        try:
            data, end_idx = decoder.raw_decode(text, idx)
            if isinstance(data, dict) and expected_fields & set(data.keys()):
                logger.debug("output_parsed_via_bare_json", agent=agent_name)
                return data
        except (json.JSONDecodeError, ValueError):
            pass
        # Find next {
        next_idx = text.find("{", idx + 1)
        if next_idx == -1:
            break
        idx = next_idx

    return None
