"""Safe XML parsing utilities - XXE prevention.

All XML parsing of untrusted content (APK manifests, resource files,
network security configs) MUST use these wrappers instead of raw
xml.etree.ElementTree.parse() or .fromstring().

defusedxml blocks:
- External entity expansion (XXE file disclosure / SSRF)
- DTD retrieval
- Billion laughs (exponential entity expansion DoS)

Usage:
    from core.xml_safe import safe_parse, safe_fromstring

    tree = safe_parse("AndroidManifest.xml")
    root = safe_fromstring(xml_bytes)
"""

from __future__ import annotations

import logging
import warnings
import xml.etree.ElementTree as _ET
from pathlib import Path
from typing import Optional, Union

_logger = logging.getLogger(__name__)

try:
    import defusedxml.ElementTree as _defused_ET

    _HAS_DEFUSEDXML = True
except ImportError:
    _HAS_DEFUSEDXML = False
    warnings.warn(
        "defusedxml is not installed - XML parsing falls back to stdlib "
        "without XXE protection. Install defusedxml: pip install defusedxml",
        stacklevel=1,
    )

_XXE_FALLBACK_WARNED = False


def _warn_fallback() -> None:
    """Emit a one-time runtime warning when falling back to unsafe parsing."""
    global _XXE_FALLBACK_WARNED
    if not _XXE_FALLBACK_WARNED:
        _logger.warning(
            "defusedxml unavailable - parsing XML with stdlib (no XXE protection). "
            "Install defusedxml to fix: pip install defusedxml"
        )
        _XXE_FALLBACK_WARNED = True


def safe_parse(
    source: Union[str, Path],
) -> _ET.ElementTree:
    """Parse an XML file with XXE protection.

    Uses defusedxml if available, otherwise falls back to stdlib
    with a logged warning.
    """
    if _HAS_DEFUSEDXML:
        return _defused_ET.parse(str(source))
    _warn_fallback()
    return _ET.parse(str(source))


def safe_fromstring(text: Union[str, bytes]) -> _ET.Element:
    """Parse XML from a string/bytes with XXE protection."""
    if _HAS_DEFUSEDXML:
        return _defused_ET.fromstring(text)
    _warn_fallback()
    return _ET.fromstring(text)


def safe_iterparse(
    source: Union[str, Path],
    events: Optional[tuple] = None,
):
    """Iteratively parse an XML file with XXE protection."""
    if _HAS_DEFUSEDXML:
        return _defused_ET.iterparse(str(source), events=events)
    _warn_fallback()
    return _ET.iterparse(str(source), events=events)
