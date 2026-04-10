"""
core.stix_exporter - Export IoCs and findings as STIX 2.1 JSON bundles.

Converts AODS scan IoCs and malware detection findings into
`STIX 2.1 <https://docs.oasis-open.org/cti/stix/v2.1/>`_ JSON bundles
suitable for import into threat intelligence platforms (MISP, OpenCTI,
ThreatConnect, etc.).

No external ``stix2`` library dependency - objects are built manually
following the OASIS STIX 2.1 specification.

Usage::

    from core.stix_exporter import export_iocs_to_stix

    bundle = export_iocs_to_stix(
        iocs=[{"type": "ip_address", "value": "1.2.3.4", ...}],
        scan_id="abc123",
        apk_name="malware.apk",
    )
    # bundle is a JSON-serializable dict (STIX Bundle)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# STIX 2.1 ID generation
# ---------------------------------------------------------------------------

def _stix_id(obj_type: str) -> str:
    """Generate a STIX 2.1 compliant deterministic-format ID."""
    return f"{obj_type}--{uuid.uuid4()}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ---------------------------------------------------------------------------
# STIX pattern builders
# ---------------------------------------------------------------------------

_IOC_TYPE_TO_STIX_PATTERN = {
    "ip_address": lambda v: f"[ipv4-addr:value = '{_escape(v.split(':')[0])}']",
    "domain": lambda v: f"[domain-name:value = '{_escape(v)}']",
    "url": lambda v: f"[url:value = '{_escape(v)}']",
    "file_path": lambda v: f"[file:name = '{_escape(v.rsplit('/', 1)[-1])}']",
    "file_hash": lambda v: f"[file:hashes.'SHA-256' = '{_escape(v)}']",
    "command": lambda v: f"[process:command_line = '{_escape(v)}']",
    "library": lambda v: f"[file:name = '{_escape(v)}']",
}


def _escape(s: str) -> str:
    """Escape single quotes for STIX patterns."""
    return s.replace("\\", "\\\\").replace("'", "\\'")


def _build_stix_pattern(ioc_type: str, value: str) -> str:
    """Build a STIX 2.1 pattern string for an IoC."""
    builder = _IOC_TYPE_TO_STIX_PATTERN.get(ioc_type)
    if builder:
        return builder(value)
    # Fallback: generic artifact
    return f"[artifact:payload_bin = '{_escape(value)}']"


# ---------------------------------------------------------------------------
# STIX severity mapping
# ---------------------------------------------------------------------------

_SEVERITY_TO_TLP = {
    "critical": "red",
    "high": "amber",
    "medium": "green",
    "low": "white",
    "info": "white",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def export_iocs_to_stix(
    iocs: List[Dict[str, Any]],
    *,
    scan_id: str = "",
    apk_name: str = "",
    families: Optional[List[str]] = None,
    mitre_techniques: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Convert a list of IoC dicts into a STIX 2.1 JSON Bundle.

    Parameters
    ----------
    iocs
        List of IoC dicts (as returned by ``collect_iocs_from_frida_events``
        or extracted from scan results). Each must have ``type`` and ``value``.
    scan_id
        AODS scan session ID (added to object labels).
    apk_name
        APK filename (used as Malware object name if families not provided).
    families
        Optional list of detected malware family names for Malware objects.
    mitre_techniques
        Optional list of MITRE ATT&CK technique IDs (e.g. ``["T1071"]``).

    Returns
    -------
    dict
        A STIX 2.1 Bundle (JSON-serializable dict).
    """
    now = _now_iso()
    identity_id = _stix_id("identity")
    objects: List[Dict[str, Any]] = []

    # --- Identity (AODS as the source) ---
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "AODS - Automated OWASP Dynamic Scan",
        "identity_class": "system",
    }
    objects.append(identity)

    # --- Malware objects (per detected family) ---
    malware_ids: List[str] = []
    family_list = families or []
    if not family_list and apk_name:
        family_list = [apk_name]

    for family in family_list:
        mid = _stix_id("malware")
        malware_ids.append(mid)
        objects.append({
            "type": "malware",
            "spec_version": "2.1",
            "id": mid,
            "created": now,
            "modified": now,
            "name": family,
            "malware_types": ["trojan"],
            "is_family": True,
            "created_by_ref": identity_id,
            "labels": [f"aods-scan:{scan_id}"] if scan_id else [],
        })

    # --- Attack-Pattern objects (MITRE ATT&CK) ---
    attack_pattern_ids: List[str] = []
    for technique in (mitre_techniques or []):
        apid = _stix_id("attack-pattern")
        attack_pattern_ids.append(apid)
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": apid,
            "created": now,
            "modified": now,
            "name": technique,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": technique,
            }],
            "created_by_ref": identity_id,
        })

    # --- Indicator objects (per IoC) ---
    for ioc in iocs:
        ioc_type = ioc.get("type", "unknown")
        value = ioc.get("value", "")
        if not value:
            continue

        severity = ioc.get("severity", "medium")
        confidence = ioc.get("confidence", 0.5)
        source = ioc.get("source", "static")
        context = ioc.get("context", {})

        indicator_id = _stix_id("indicator")
        pattern = _build_stix_pattern(ioc_type, value)

        labels = [f"ioc-type:{ioc_type}", f"source:{source}"]
        if scan_id:
            labels.append(f"aods-scan:{scan_id}")

        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f"{ioc_type}: {value[:80]}",
            "description": f"IoC extracted by AODS ({source} analysis)",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": int(confidence * 100),
            "labels": labels,
            "created_by_ref": identity_id,
            "object_marking_refs": [],
            "external_references": [],
        }

        # Add TLP marking description
        tlp = _SEVERITY_TO_TLP.get(severity, "white")
        indicator["description"] += f" [TLP:{tlp.upper()}]"

        # Add context as custom properties
        if context:
            indicator["x_aods_context"] = {
                k: v for k, v in context.items()
                if isinstance(v, (str, int, float, bool)) and k != "stack_trace"
            }

        objects.append(indicator)

        # --- Relationships: indicator → malware ---
        for mid in malware_ids:
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _stix_id("relationship"),
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": mid,
                "created_by_ref": identity_id,
            })

        # --- Relationships: indicator → attack-pattern ---
        for apid in attack_pattern_ids:
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _stix_id("relationship"),
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": apid,
                "created_by_ref": identity_id,
            })

    # --- Bundle ---
    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": objects,
    }

    logger.info(
        "STIX bundle exported: %d IoCs, %d objects, scan=%s",
        len(iocs), len(objects), scan_id,
    )
    return bundle
