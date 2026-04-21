"""
Shared Android Manifest XML parsing utilities.

Extracts common logic duplicated across manifest_analyzer.py files in
network_cleartext_traffic, enhanced_static_analysis, improper_platform_usage,
and attack_surface_analysis plugins.
"""

import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Dict, Optional

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def extract_target_sdk(root: ET.Element) -> Optional[int]:
    """Extract target SDK version from a parsed manifest root element.

    Checks ``<uses-sdk>`` first, then falls back to an attribute on
    ``<application>`` (rare but seen in some build configurations).

    Returns:
        The integer target SDK version, or ``None`` if unavailable.
    """
    try:
        uses_sdk = root.find(".//uses-sdk")
        if uses_sdk is not None:
            target_sdk = uses_sdk.get(f"{ANDROID_NS}targetSdkVersion")
            if target_sdk:
                return int(target_sdk)

        # Fallback: some manifests store it on the application element
        application = root.find(".//application")
        if application is not None:
            target_sdk = application.get(f"{ANDROID_NS}targetSdkVersion")
            if target_sdk:
                return int(target_sdk)

        return None
    except (ValueError, TypeError):
        return None


def extract_min_sdk(root: ET.Element) -> Optional[int]:
    """Extract minimum SDK version from a parsed manifest root element.

    Returns:
        The integer min SDK version, or ``None`` if unavailable.
    """
    try:
        uses_sdk = root.find(".//uses-sdk")
        if uses_sdk is not None:
            min_sdk = uses_sdk.get(f"{ANDROID_NS}minSdkVersion")
            if min_sdk:
                return int(min_sdk)
        return None
    except (ValueError, TypeError):
        return None


def is_component_exported(element: ET.Element) -> bool:
    """Determine whether an Android component element is exported.

    Checks the ``android:exported`` attribute first (case-insensitive).
    If the attribute is absent, the component is considered exported when
    it declares at least one ``<intent-filter>`` child (recursive search).
    """
    exported_attr = element.get(f"{ANDROID_NS}exported")
    if exported_attr is not None:
        return exported_attr.lower() == "true"

    # Implicit: exported if intent-filter children exist
    intent_filters = element.findall(".//intent-filter")
    return len(intent_filters) > 0


def extract_manifest_from_apk(apk_path: str, temp_dir: Path) -> Optional[Path]:
    """Extract ``AndroidManifest.xml`` from an APK zip archive.

    Args:
        apk_path: Filesystem path to the ``.apk`` file.
        temp_dir: Directory where the manifest will be written.

    Returns:
        Path to the extracted manifest file, or ``None`` on failure.
    """
    try:
        apk_path_obj = Path(apk_path)
        if not apk_path_obj.exists():
            return None

        with zipfile.ZipFile(apk_path_obj, "r") as apk_zip:
            if "AndroidManifest.xml" not in apk_zip.namelist():
                return None

            temp_dir.mkdir(parents=True, exist_ok=True)
            manifest_path = temp_dir / "AndroidManifest.xml"

            with apk_zip.open("AndroidManifest.xml") as manifest_file:
                with open(manifest_path, "wb") as output_file:
                    output_file.write(manifest_file.read())

            return manifest_path

    except Exception as e:
        logger.warning("Failed to extract manifest from APK: %s", e)
        return None


# ---------------------------------------------------------------------------
# Track 72: Manifest line-number mapping
# ---------------------------------------------------------------------------

# Regex to extract android:name="..." from manifest XML lines
_ANDROID_NAME_RE = re.compile(r'android:name\s*=\s*"([^"]*)"', re.IGNORECASE)
_TAG_RE = re.compile(r"<\s*(activity|service|receiver|provider|uses-permission|uses-sdk|application)\b", re.IGNORECASE)
_ATTR_RE = re.compile(
    r"android:(debuggable|allowBackup|usesCleartextTraffic|networkSecurityConfig"
    r'|targetSdkVersion|minSdkVersion)\s*=\s*"([^"]*)"',
    re.IGNORECASE,
)


def build_manifest_line_map(manifest_path: str) -> Dict[str, int]:
    """Read AndroidManifest.xml as text and build ``{element_key: line_number}`` mapping.

    Keys are of the form ``"activity:com.example.MainActivity"``,
    ``"uses-permission:android.permission.INTERNET"``,
    ``"application:debuggable"``, ``"uses-sdk:targetSdkVersion"``, etc.

    Handles both single-line and multi-line XML elements by tracking the
    current open tag across continuation lines until the element closes
    (``>`` or ``/>``).

    Returns an empty dict on any I/O failure.
    """
    line_map: Dict[str, int] = {}
    try:
        text = Path(manifest_path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return line_map

    current_tag: Optional[str] = None
    tag_start_line: int = 0

    for lineno, line in enumerate(text.splitlines(), start=1):
        tag_m = _TAG_RE.search(line)
        if tag_m:
            current_tag = tag_m.group(1).lower()
            tag_start_line = lineno
            # Record bare tag line (fallback for default/missing attributes)
            if current_tag not in line_map:
                line_map[current_tag] = tag_start_line

        # Process attributes on current line if inside a tracked element
        if current_tag:
            name_m = _ANDROID_NAME_RE.search(line)
            if name_m:
                name_val = name_m.group(1)
                line_map[f"{current_tag}:{name_val}"] = tag_start_line

            for attr_m in _ATTR_RE.finditer(line):
                attr_name = attr_m.group(1)
                line_map[f"{current_tag}:{attr_name}"] = tag_start_line

            # Check if element closes on this line
            if ">" in line or "/>" in line:
                current_tag = None

    return line_map


def lookup_manifest_line(
    line_map: Dict[str, int],
    location: str,
    component_name: Optional[str] = None,
    permission_name: Optional[str] = None,
    title: Optional[str] = None,
    evidence: Optional[str] = None,
) -> Optional[int]:
    """Map a finding's fields to a manifest line number.

    Tries several key patterns to maximise hit rate:
    1. Exact ``"tag:component_name"`` (e.g. ``"activity:com.example.Main"``)
    2. ``"uses-permission:permission_name"`` for permission findings
    3. Attribute-based keys (``"application:debuggable"``, ``"uses-sdk:targetSdkVersion"``)
    4. Bare location/title/evidence string as a fallback prefix scan
    """
    if not line_map:
        return None

    loc = (location or "").strip().lower()
    # Combine all textual fields for keyword matching
    text = " ".join(s.lower() for s in (location or "", title or "", evidence or "") if s)

    # 1. Direct component_name lookup
    if component_name:
        cn = component_name.strip()
        for tag in ("activity", "service", "receiver", "provider", "uses-permission"):
            key = f"{tag}:{cn}"
            if key in line_map:
                return line_map[key]
        # Try case-insensitive match
        cn_lower = cn.lower()
        for key, lineno in line_map.items():
            if key.lower().endswith(f":{cn_lower}"):
                return lineno

    # 2. Permission findings - use permission_name field or extract from location
    if permission_name:
        pn = permission_name.strip()
        key = f"uses-permission:{pn}"
        if key in line_map:
            return line_map[key]
        # Case-insensitive fallback
        pn_lower = pn.lower()
        for k, lineno in line_map.items():
            if k.startswith("uses-permission:") and k.lower().endswith(pn_lower):
                return lineno

    if "permission" in loc:
        for key, lineno in line_map.items():
            if key.startswith("uses-permission:") and loc in key.lower():
                return lineno

    # 3. Attribute-based findings (debuggable, backup, SDK versions)
    # Search across location + title + evidence for keyword matches
    attr_keywords = {
        "debuggable": "application:debuggable",
        "backup": "application:allowBackup",
        "cleartext": "application:usesCleartextTraffic",
        "network security": "application:networkSecurityConfig",
        "target sdk": "uses-sdk:targetSdkVersion",
        "targetsdk": "uses-sdk:targetSdkVersion",
        "minimum sdk": "uses-sdk:minSdkVersion",
        "minsdk": "uses-sdk:minSdkVersion",
    }
    for keyword, map_key in attr_keywords.items():
        if keyword in text:
            if map_key in line_map:
                return line_map[map_key]
            # Fallback: attribute absent (JADX strips defaults) - use tag line
            tag = map_key.split(":")[0]
            if tag in line_map:
                return line_map[tag]

    # 4. Fallback: scan line_map keys for any match with the location text
    for key, lineno in line_map.items():
        if loc and loc in key.lower():
            return lineno

    return None
