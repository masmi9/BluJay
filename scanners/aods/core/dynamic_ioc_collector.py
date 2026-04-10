"""
core.dynamic_ioc_collector - Extract structured IoCs from Frida runtime events.

Processes Frida ``send()`` messages (network_communication, file_access,
malware_behavior, filesystem_ioc) and converts them into a list of
structured IoC dicts suitable for indexing via ``IoCCorrelator`` and
export via the ``/api/scans/{id}/iocs`` endpoint.

Each returned IoC has:
    type      - ip_address | domain | url | file_path | command | library
    value     - the extracted indicator string
    source    - "dynamic" (runtime-observed via Frida)
    severity  - critical | high | medium | low
    confidence - 0.0–1.0
    context   - dict with hook, timestamp, evidence details
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

_RFC1918_RE = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)"
)

_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$"
)


def _is_private_ip(ip: str) -> bool:
    return bool(_RFC1918_RE.match(ip))


def _extract_host_from_url(url: str) -> Optional[str]:
    """Return host from a URL, or None."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def collect_iocs_from_frida_events(
    events: List[Dict[str, Any]],
    *,
    include_private_ips: bool = False,
) -> List[Dict[str, Any]]:
    """Convert a list of Frida ``send()`` event dicts into structured IoCs.

    Parameters
    ----------
    events
        Raw Frida messages. Each dict should have at least a ``type`` key
        (``network_communication``, ``file_access``, ``malware_behavior``,
        ``filesystem_ioc``).
    include_private_ips
        If *False* (default), RFC-1918 / loopback IPs are filtered out.

    Returns
    -------
    list[dict]
        Deduplicated IoC dicts ready for ``IoCCorrelator.index_iocs()``.
    """
    seen: Set[str] = set()  # (type, value) dedup
    iocs: List[Dict[str, Any]] = []

    for event in events:
        msg_type = event.get("type", "")

        if msg_type == "network_communication":
            _process_network_event(event, iocs, seen, include_private_ips)
        elif msg_type == "file_access":
            _process_file_access_event(event, iocs, seen)
        elif msg_type == "filesystem_ioc":
            _process_filesystem_ioc_event(event, iocs, seen)
        elif msg_type == "malware_behavior":
            _process_malware_behavior_event(event, iocs, seen)

    return iocs


# ---------------------------------------------------------------------------
# Event processors
# ---------------------------------------------------------------------------


def _add_ioc(
    iocs: List[Dict[str, Any]],
    seen: Set[str],
    ioc_type: str,
    value: str,
    severity: str,
    confidence: float,
    context: Dict[str, Any],
) -> None:
    """Append a deduplicated IoC to the list."""
    key = f"{ioc_type}:{value}"
    if key in seen:
        return
    seen.add(key)
    iocs.append({
        "type": ioc_type,
        "value": value,
        "source": "dynamic",
        "severity": severity,
        "confidence": round(min(max(confidence, 0.0), 1.0), 3),
        "context": context,
    })


def _process_network_event(
    event: Dict[str, Any],
    iocs: List[Dict[str, Any]],
    seen: Set[str],
    include_private_ips: bool,
) -> None:
    """Extract IPs, domains, and URLs from network_communication events."""
    url = event.get("url", "")
    host = event.get("host", "")
    port = event.get("port")
    ts = event.get("timestamp")

    # URL-level IoC
    if url and url != "unknown":
        _add_ioc(iocs, seen, "url", url[:500], "medium", 0.85, {
            "hook": event.get("method") or event.get("connection_type", "network"),
            "timestamp": ts,
            "is_https": event.get("is_https", False),
            "library": event.get("library", ""),
        })

        # Extract host from URL
        extracted_host = _extract_host_from_url(url)
        if extracted_host:
            host = extracted_host

    if host and host != "unknown":
        if _IP_RE.match(host):
            if include_private_ips or not _is_private_ip(host):
                sev = "high" if (port and port not in (80, 443, 8080, 8443)) else "medium"
                _add_ioc(iocs, seen, "ip_address", host, sev, 0.90, {
                    "hook": "network",
                    "timestamp": ts,
                    "port": port,
                    "is_suspicious_port": port not in (None, 80, 443, 8080, 8443),
                })
        elif _DOMAIN_RE.match(host):
            _add_ioc(iocs, seen, "domain", host, "medium", 0.80, {
                "hook": "network",
                "timestamp": ts,
                "port": port,
            })

    # Socket connections with host + port (no URL)
    if not url and host and port:
        addr = f"{host}:{port}"
        if _IP_RE.match(host) and (include_private_ips or not _is_private_ip(host)):
            _add_ioc(iocs, seen, "ip_address", addr, "high", 0.90, {
                "hook": "socket",
                "timestamp": ts,
                "port": port,
            })


def _process_file_access_event(
    event: Dict[str, Any],
    iocs: List[Dict[str, Any]],
    seen: Set[str],
) -> None:
    """Extract file-path IoCs from general storage_hooks file_access events."""
    file_path = event.get("file_path", "")
    if not file_path:
        return

    operation = event.get("operation", "")
    ts = event.get("timestamp")

    # Only track writes to suspicious locations or reads of sensitive paths
    if operation == "write":
        lower = file_path.lower()
        suspicious = any(lower.endswith(ext) for ext in (
            ".so", ".dex", ".jar", ".apk", ".bin", ".elf", ".sh",
        ))
        if suspicious or "/data/local/tmp/" in file_path:
            _add_ioc(iocs, seen, "file_path", file_path[:500], "high", 0.85, {
                "hook": "storage",
                "operation": "write",
                "timestamp": ts,
            })


def _process_filesystem_ioc_event(
    event: Dict[str, Any],
    iocs: List[Dict[str, Any]],
    seen: Set[str],
) -> None:
    """Process filesystem_ioc events from filesystem_ioc_hooks.js."""
    ioc_type = event.get("ioc_type", "")
    severity = event.get("severity", "medium")
    evidence = event.get("evidence", {})
    ts = event.get("timestamp")

    if ioc_type == "file_drop":
        fp = evidence.get("file_path", "")
        if fp:
            _add_ioc(iocs, seen, "file_path", fp[:500], severity, 0.90, {
                "hook": "filesystem_ioc",
                "operation": "file_drop",
                "timestamp": ts,
                "is_payload": evidence.get("is_payload", False),
            })

    elif ioc_type == "sensitive_read":
        fp = evidence.get("file_path", "")
        if fp:
            _add_ioc(iocs, seen, "file_path", fp[:500], severity, 0.75, {
                "hook": "filesystem_ioc",
                "operation": "sensitive_read",
                "timestamp": ts,
            })

    elif ioc_type == "command_exec":
        cmd = evidence.get("command", "")
        if cmd:
            _add_ioc(iocs, seen, "command", cmd[:500], severity, 0.90, {
                "hook": "filesystem_ioc",
                "operation": "command_exec",
                "timestamp": ts,
            })

    elif ioc_type == "dynamic_code_load":
        dex_path = evidence.get("dex_path", "")
        if dex_path:
            _add_ioc(iocs, seen, "file_path", dex_path[:500], "critical", 0.95, {
                "hook": "filesystem_ioc",
                "operation": "dynamic_code_load",
                "timestamp": ts,
            })

    elif ioc_type == "native_lib_load":
        lib = evidence.get("library_name") or evidence.get("library_path", "")
        if lib:
            _add_ioc(iocs, seen, "library", lib[:300], severity, 0.70, {
                "hook": "filesystem_ioc",
                "operation": "native_lib_load",
                "timestamp": ts,
            })


def _process_malware_behavior_event(
    event: Dict[str, Any],
    iocs: List[Dict[str, Any]],
    seen: Set[str],
) -> None:
    """Extract IoCs from malware_behavior events (C2, mining, etc.)."""
    behavior = event.get("behavior_type", "")
    evidence = event.get("evidence", {})
    severity = event.get("severity", "high")
    ts = event.get("timestamp")

    if behavior == "c2_communication":
        host = evidence.get("host", "")
        port = evidence.get("port")
        if host:
            value = f"{host}:{port}" if port else host
            _add_ioc(iocs, seen, "ip_address", value, "critical", 0.95, {
                "hook": "malware_behavior",
                "behavior": "c2_communication",
                "timestamp": ts,
                "ip_based": evidence.get("ip_based", False),
                "suspicious_port": evidence.get("suspicious_port", False),
            })

    elif behavior in ("crypto_mining_webview", "crypto_mining_cpu", "crypto_mining_wakelock"):
        url = evidence.get("url", "")
        tag = evidence.get("tag", "")
        indicator = url or tag or behavior
        _add_ioc(iocs, seen, "url" if url else "command", indicator[:500], severity, 0.90, {
            "hook": "malware_behavior",
            "behavior": behavior,
            "timestamp": ts,
        })

    elif behavior == "sms_send":
        dest = evidence.get("destination", "")
        if dest:
            _add_ioc(iocs, seen, "command", f"sms:{dest}", "critical", 0.95, {
                "hook": "malware_behavior",
                "behavior": "sms_send",
                "timestamp": ts,
            })
