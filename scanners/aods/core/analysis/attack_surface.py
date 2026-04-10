"""
Attack Surface Graph Builder
============================

Parses AndroidManifest.xml and scan findings to produce a directed graph
of Android components, their exposure (exported status, permissions,
intent filters, deep links), inter-component relationships, and overlaid
vulnerability findings.

The output is a JSON-serialisable dataclass consumed by the React
``<AttackSurfaceGraph />`` component via ``GET /api/scans/{id}/attack-surface``.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from core.manifest_parsing_utils import ANDROID_NS, is_component_exported
from core.xml_safe import safe_parse

# ---------------------------------------------------------------------------
# Permission risk classification (Android SDK dangerous permissions)
# ---------------------------------------------------------------------------

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
}

SIGNATURE_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.PACKAGE_USAGE_STATS",
}


def _classify_permission_risk(perm_name: str) -> str:
    """Return risk level: dangerous, signature, or normal."""
    if perm_name in DANGEROUS_PERMISSIONS:
        return "dangerous"
    if perm_name in SIGNATURE_PERMISSIONS:
        return "signature"
    return "normal"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

_COMPONENT_TAGS = ("activity", "service", "receiver", "provider")


@dataclass
class GraphNode:
    id: str
    node_type: str  # activity|service|receiver|provider|permission|entry_point|deep_link|warning
    label: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)
    severity: Optional[str] = None


@dataclass
class GraphEdge:
    source: str
    target: str
    relationship: str  # exports|requires_permission|intent_filter|ipc_call|attack_chain
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackSurfaceGraph:
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _worst_severity(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if a is None:
        return b
    if b is None:
        return a
    return a if _SEV_ORDER.get(a, 0) >= _SEV_ORDER.get(b, 0) else b


# ---------------------------------------------------------------------------
# Intent-filter / deep-link extraction
# ---------------------------------------------------------------------------


def _extract_intent_filters(component_elem) -> List[Dict[str, Any]]:
    """Return list of intent-filter dicts with actions, categories, data."""
    filters: List[Dict[str, Any]] = []
    for intf in component_elem.findall("intent-filter"):
        actions = [a.get(f"{ANDROID_NS}name", "") for a in intf.findall("action")]
        categories = [c.get(f"{ANDROID_NS}name", "") for c in intf.findall("category")]
        data_elems = intf.findall("data")
        schemes: List[str] = []
        hosts: List[str] = []
        paths: List[str] = []
        for d in data_elems:
            s = d.get(f"{ANDROID_NS}scheme")
            if s:
                schemes.append(s)
            h = d.get(f"{ANDROID_NS}host")
            if h:
                hosts.append(h)
            p = d.get(f"{ANDROID_NS}path") or d.get(f"{ANDROID_NS}pathPrefix") or d.get(f"{ANDROID_NS}pathPattern")
            if p:
                paths.append(p)
        filters.append({
            "actions": [a for a in actions if a],
            "categories": [c for c in categories if c],
            "schemes": schemes,
            "hosts": hosts,
            "paths": paths,
        })
    return filters


# ---------------------------------------------------------------------------
# Core builder
# ---------------------------------------------------------------------------

# IPC patterns in Java source: startActivity/bindService/startService/sendBroadcast
_IPC_PATTERN = re.compile(
    r"(startActivit(?:y|ies)|bindService|startService|startForegroundService"
    r"|sendBroadcast|sendOrderedBroadcast|sendStickyBroadcast"
    r"|getContentResolver|ContentResolver)\b",
    re.IGNORECASE,
)

# Component class reference in code: "com.example.SomeActivity"
_CLASS_REF_PATTERN = re.compile(r"([a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*){2,})")


def extract_manifest_data(manifest_path: Optional[Path]) -> Optional[Dict[str, Any]]:
    """Parse AndroidManifest.xml into a serialisable dict for report storage.

    This allows the attack surface graph to be rebuilt even after the
    workspace/APK is deleted, by persisting the parsed manifest data in the
    scan report.

    Returns:
        Dict with ``components``, ``requested_permissions`` keys, or None.
    """
    if not manifest_path or not Path(manifest_path).exists():
        return None
    try:
        tree = safe_parse(manifest_path)
        root = tree.getroot()
    except Exception as exc:
        logger.warning("Failed to parse manifest for extraction: %s", exc)
        return None

    if root is None:
        return None

    requested_permissions: List[str] = []
    for up in root.findall("uses-permission"):
        perm_name = up.get(f"{ANDROID_NS}name", "")
        if perm_name:
            requested_permissions.append(perm_name)

    app = root.find("application")
    search_root = app if app is not None else root

    components: List[Dict[str, Any]] = []
    for tag in _COMPONENT_TAGS:
        for elem in search_root.findall(tag):
            name = elem.get(f"{ANDROID_NS}name", "")
            if not name:
                continue
            components.append({
                "tag": tag,
                "name": name,
                "exported": is_component_exported(elem),
                "permission": elem.get(f"{ANDROID_NS}permission", "") or None,
                "intent_filters": _extract_intent_filters(elem),
            })

    return {
        "components": components,
        "requested_permissions": sorted(set(requested_permissions)),
    }


def _populate_from_manifest_data(
    manifest_data: Dict[str, Any],
    nodes_by_id: Dict[str, GraphNode],
    component_names: Dict[str, str],
    edges: List[GraphEdge],
) -> tuple:
    """Populate nodes/edges from pre-parsed manifest data dict.

    Returns (exported_count, dangerous_perm_count, requested_permissions).
    """
    exported_count = 0
    dangerous_perm_count = 0
    requested_permissions = set(manifest_data.get("requested_permissions", []))

    for comp in manifest_data.get("components", []):
        tag = comp["tag"]
        name = comp["name"]
        exported = comp.get("exported", False)
        permission = comp.get("permission")
        intent_filters = comp.get("intent_filters", [])

        node_id = f"{tag}:{name}"
        short_name = name.rsplit(".", 1)[-1] if "." in name else name
        node = GraphNode(
            id=node_id,
            node_type=tag,
            label=short_name,
            metadata={
                "full_name": name,
                "exported": exported,
                "permission": permission,
                "intent_filters": intent_filters,
            },
        )
        nodes_by_id[node_id] = node
        component_names[name] = node_id
        component_names[short_name] = node_id

        if exported:
            exported_count += 1

        if permission:
            perm_id = f"permission:{permission}"
            if perm_id not in nodes_by_id:
                perm_short = permission.rsplit(".", 1)[-1] if "." in permission else permission
                risk = _classify_permission_risk(permission)
                nodes_by_id[perm_id] = GraphNode(
                    id=perm_id,
                    node_type="permission",
                    label=perm_short,
                    metadata={"full_name": permission, "risk_level": risk},
                )
                if risk == "dangerous":
                    dangerous_perm_count += 1
            edges.append(GraphEdge(
                source=node_id,
                target=perm_id,
                relationship="requires_permission",
            ))

        for intf in intent_filters:
            for scheme in intf.get("schemes", []):
                if scheme in ("http", "https"):
                    continue
                dl_id = f"deep_link:{scheme}"
                hosts = intf.get("hosts", [])
                if dl_id not in nodes_by_id:
                    nodes_by_id[dl_id] = GraphNode(
                        id=dl_id,
                        node_type="deep_link",
                        label=f"{scheme}://",
                        metadata={"scheme": scheme, "hosts": hosts},
                    )
                edge_meta: Dict[str, Any] = {}
                if intf.get("actions"):
                    edge_meta["actions"] = intf["actions"]
                if scheme:
                    edge_meta["scheme"] = scheme
                if hosts:
                    edge_meta["hosts"] = hosts
                edges.append(GraphEdge(
                    source=dl_id,
                    target=node_id,
                    relationship="intent_filter",
                    metadata=edge_meta,
                ))

    return exported_count, dangerous_perm_count, requested_permissions


def build_attack_surface_graph(
    manifest_path: Optional[Path],
    findings: List[Dict[str, Any]],
    attack_chains: Optional[List[Dict[str, Any]]] = None,
    manifest_data: Optional[Dict[str, Any]] = None,
) -> AttackSurfaceGraph:
    """Build the full attack-surface graph.

    Args:
        manifest_path: Path to decoded AndroidManifest.xml (may be None).
        findings: List of finding dicts from the scan report.
        attack_chains: Optional attack chains from the narration agent.
        manifest_data: Pre-parsed manifest data dict (used when manifest file
            is no longer available). Takes precedence if manifest_path is also
            provided but the file doesn't exist.

    Returns:
        ``AttackSurfaceGraph`` ready for JSON serialisation.
    """
    graph = AttackSurfaceGraph()
    nodes_by_id: Dict[str, GraphNode] = {}
    component_names: Dict[str, str] = {}  # short_name -> node_id

    # ------------------------------------------------------------------
    # 1. Parse manifest (from file or pre-parsed data)
    # ------------------------------------------------------------------
    exported_count = 0
    dangerous_perm_count = 0
    requested_permissions: set = set()

    manifest_file_exists = manifest_path and Path(manifest_path).exists()

    manifest_parsed = False
    if manifest_file_exists:
        # Parse from file (live workspace available)
        try:
            tree = safe_parse(manifest_path)
            root = tree.getroot()
        except Exception as exc:
            logger.warning("Failed to parse manifest for attack surface: %s", exc)
            root = None

        if root is not None:
            manifest_parsed = True
            # Extract <uses-permission> from manifest root
            for up in root.findall("uses-permission"):
                perm_name = up.get(f"{ANDROID_NS}name", "")
                if perm_name:
                    requested_permissions.add(perm_name)

            app = root.find("application")
            search_root = app if app is not None else root

            for tag in _COMPONENT_TAGS:
                for elem in search_root.findall(tag):
                    name = elem.get(f"{ANDROID_NS}name", "")
                    if not name:
                        continue
                    exported = is_component_exported(elem)
                    permission = elem.get(f"{ANDROID_NS}permission", "")
                    intent_filters = _extract_intent_filters(elem)

                    node_id = f"{tag}:{name}"
                    short_name = name.rsplit(".", 1)[-1] if "." in name else name
                    node = GraphNode(
                        id=node_id,
                        node_type=tag,
                        label=short_name,
                        metadata={
                            "full_name": name,
                            "exported": exported,
                            "permission": permission or None,
                            "intent_filters": intent_filters,
                        },
                    )
                    nodes_by_id[node_id] = node
                    component_names[name] = node_id
                    component_names[short_name] = node_id

                    if exported:
                        exported_count += 1

                    # Permission node + edge (with risk classification)
                    if permission:
                        perm_id = f"permission:{permission}"
                        if perm_id not in nodes_by_id:
                            perm_short = permission.rsplit(".", 1)[-1] if "." in permission else permission
                            risk = _classify_permission_risk(permission)
                            nodes_by_id[perm_id] = GraphNode(
                                id=perm_id,
                                node_type="permission",
                                label=perm_short,
                                metadata={"full_name": permission, "risk_level": risk},
                            )
                            if risk == "dangerous":
                                dangerous_perm_count += 1
                        graph.edges.append(GraphEdge(
                            source=node_id,
                            target=perm_id,
                            relationship="requires_permission",
                        ))

                    # Deep link nodes + edges
                    for intf in intent_filters:
                        for scheme in intf.get("schemes", []):
                            if scheme in ("http", "https"):
                                continue  # skip generic web schemes
                            dl_id = f"deep_link:{scheme}"
                            hosts = intf.get("hosts", [])
                            if dl_id not in nodes_by_id:
                                nodes_by_id[dl_id] = GraphNode(
                                    id=dl_id,
                                    node_type="deep_link",
                                    label=f"{scheme}://",
                                    metadata={"scheme": scheme, "hosts": hosts},
                                )
                            # Intent-filter edge with action/scheme metadata
                            edge_meta: Dict[str, Any] = {}
                            if intf.get("actions"):
                                edge_meta["actions"] = intf["actions"]
                            if scheme:
                                edge_meta["scheme"] = scheme
                            if hosts:
                                edge_meta["hosts"] = hosts
                            graph.edges.append(GraphEdge(
                                source=dl_id,
                                target=node_id,
                                relationship="intent_filter",
                                metadata=edge_meta,
                            ))

                        # Intent-filter edges without deep link (action-only filters)
                        if not intf.get("schemes") and intf.get("actions"):
                            # These aren't deep links, but the actions are metadata
                            # on other edges - they get wired through IPC / export edges
                            pass

            # ----------------------------------------------------------
            # 1b. Malware permission combo detection
            # ----------------------------------------------------------
            _detect_permission_combos(
                requested_permissions, nodes_by_id, graph.edges
            )
    if not manifest_parsed and manifest_data and isinstance(manifest_data, dict):
        # Rebuild from persisted manifest data (file missing, unparseable, or binary AXML)
        logger.info("Building attack surface from persisted manifest_data (manifest file unavailable or unparseable)")
        exported_count, dangerous_perm_count, requested_permissions = _populate_from_manifest_data(
            manifest_data, nodes_by_id, component_names, graph.edges
        )
        _detect_permission_combos(
            requested_permissions, nodes_by_id, graph.edges
        )

    # ------------------------------------------------------------------
    # 1c. Synthesize components from findings when manifest is unavailable
    # ------------------------------------------------------------------
    if not nodes_by_id:
        _COMPONENT_TYPE_HINTS = {
            "Activity": "activity",
            "Service": "service",
            "Receiver": "receiver",
            "Provider": "provider",
        }
        _NOT_COMPONENT = {
            "android.permission", "uses", "application", "manifest",
            "intent", "meta", "data", "category", "action",
        }
        # Regex patterns to extract fully-qualified class names from various fields
        _MANIFEST_COMPONENT_RE = re.compile(
            r"(?:app://)?AndroidManifest\.xml\s*[-\u2013\u2014]\s*([\w.]+)"
        )
        # "Exported activities: com.example.Foo" or "Component com.example.Foo is exported"
        # or "Exported provider without permissions: com.example.Foo"
        _TEXT_COMPONENT_RE = re.compile(
            r"(?:Exported\s+\w+(?:\s+without\s+permissions)?[:\s]+|Component\s+|Provider\s+)([\w.]{5,})"
        )

        def _is_valid_class(name: str) -> bool:
            if any(name.startswith(p) or name == p for p in _NOT_COMPONENT):
                return False
            parts = name.split(".")
            if len(parts) < 2:
                return False
            return parts[-1][0].isupper()

        def _add_inferred_node(full_name: str, f: Dict[str, Any]) -> None:
            short_name = full_name.rsplit(".", 1)[-1]
            tag = "activity"
            for suffix, t in _COMPONENT_TYPE_HINTS.items():
                if short_name.endswith(suffix):
                    tag = t
                    break
            node_id = f"{tag}:{full_name}"
            if node_id in nodes_by_id:
                return
            title_lower = (f.get("title") or "").lower()
            is_exported = "exported" in title_lower or "world-accessible" in title_lower
            nodes_by_id[node_id] = GraphNode(
                id=node_id,
                node_type=tag,
                label=short_name,
                metadata={"full_name": full_name, "exported": is_exported, "inferred": True},
            )
            component_names[full_name] = node_id
            component_names[short_name] = node_id
            nonlocal exported_count
            if is_exported:
                exported_count += 1

        for f in findings:
            # Source 1: file_path "app://AndroidManifest.xml - com.example.Foo"
            fp = f.get("file_path") or ""
            m = _MANIFEST_COMPONENT_RE.search(fp)
            if m and _is_valid_class(m.group(1)):
                _add_inferred_node(m.group(1), f)
                continue
            # Source 2: code_snippet, evidence.code_snippet, description
            for text in [
                f.get("code_snippet") or "",
                (f.get("evidence") or {}).get("code_snippet") or "",
                f.get("description") or "",
            ]:
                if not text:
                    continue
                tm = _TEXT_COMPONENT_RE.search(text)
                if tm and _is_valid_class(tm.group(1)):
                    _add_inferred_node(tm.group(1), f)
                    break
        if nodes_by_id:
            logger.info(
                "Synthesized %d component nodes from finding file_paths (no manifest available)",
                len(nodes_by_id),
            )

    # ------------------------------------------------------------------
    # 2. Entry-point node for exported components
    # ------------------------------------------------------------------
    entry_id = "entry:external"
    has_exported = False
    for nid, node in list(nodes_by_id.items()):
        if node.node_type in _COMPONENT_TAGS and node.metadata.get("exported"):
            if not has_exported:
                nodes_by_id[entry_id] = GraphNode(
                    id=entry_id,
                    node_type="entry_point",
                    label="External Caller",
                )
                has_exported = True
            graph.edges.append(GraphEdge(
                source=entry_id,
                target=nid,
                relationship="exports",
            ))

    # ------------------------------------------------------------------
    # 3. Map findings to components + MITRE technique propagation
    # ------------------------------------------------------------------
    findings_mapped = 0
    all_mitre_techniques: set = set()
    unmapped_findings: List[Dict[str, Any]] = []

    for f in findings:
        fid = f.get("finding_id") or f.get("id") or ""
        severity = (f.get("severity") or "info").lower()
        evidence = f.get("evidence") or {}
        comp_name = evidence.get("component_name") or evidence.get("component") or ""
        file_path = f.get("file_path") or ""
        title = f.get("title") or ""
        code = f.get("code_snippet") or ""

        # Extract MITRE techniques from finding evidence
        mitre_techniques = evidence.get("mitre_techniques") or []
        if isinstance(mitre_techniques, list):
            all_mitre_techniques.update(mitre_techniques)

        target_node_id = _match_finding_to_component(
            comp_name, file_path, title, component_names
        )
        if target_node_id and target_node_id in nodes_by_id:
            node = nodes_by_id[target_node_id]
            if fid not in node.findings:
                node.findings.append(fid)
            node.severity = _worst_severity(node.severity, severity)
            findings_mapped += 1

            # Propagate MITRE techniques to node
            if mitre_techniques:
                existing = node.metadata.get("mitre_techniques", [])
                merged = list(set(existing) | set(mitre_techniques))
                node.metadata["mitre_techniques"] = merged
        else:
            # Track unmapped for fallback assignment
            unmapped_findings.append(f)

        # IPC edges from code snippets
        if code and _IPC_PATTERN.search(code):
            _add_ipc_edges(
                target_node_id, code, component_names, nodes_by_id, graph.edges
            )

    # ------------------------------------------------------------------
    # 3b. Assign unmapped findings to synthetic nodes
    # ------------------------------------------------------------------
    _assign_unmapped_findings(
        unmapped_findings, nodes_by_id, graph.edges, findings_mapped
    )
    # Recount after assignment
    findings_mapped = sum(
        len(n.findings) for n in nodes_by_id.values()
    )

    # ------------------------------------------------------------------
    # 4. Attack chain edges
    # ------------------------------------------------------------------
    chain_count = 0
    if attack_chains:
        for chain in attack_chains:
            steps = chain.get("steps") or []
            for i in range(len(steps) - 1):
                graph.edges.append(GraphEdge(
                    source=f"chain_step:{i}",
                    target=f"chain_step:{i + 1}",
                    relationship="attack_chain",
                    metadata={
                        "chain_name": chain.get("name", ""),
                        "step_from": steps[i] if isinstance(steps[i], str) else str(steps[i]),
                        "step_to": steps[i + 1] if isinstance(steps[i + 1], str) else str(steps[i + 1]),
                    },
                ))
                chain_count += 1

    # ------------------------------------------------------------------
    # 5. Assemble
    # ------------------------------------------------------------------
    graph.nodes = list(nodes_by_id.values())
    graph.stats = {
        "total_components": sum(
            1 for n in graph.nodes if n.node_type in _COMPONENT_TAGS
        ),
        "exported": exported_count,
        "permissions": sum(1 for n in graph.nodes if n.node_type == "permission"),
        "dangerous_permissions": dangerous_perm_count,
        "permission_combos": sum(1 for n in graph.nodes if n.node_type == "warning"),
        "deep_links": sum(1 for n in graph.nodes if n.node_type == "deep_link"),
        "findings_mapped": findings_mapped,
        "attack_chains": chain_count,
        "total_findings": len(findings),
        "mitre_techniques_total": len(all_mitre_techniques),
    }
    return graph


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detect_permission_combos(
    requested_permissions: set,
    nodes_by_id: Dict[str, GraphNode],
    edges: List[GraphEdge],
) -> int:
    """Check requested permissions against known malware combos.

    Returns count of warning nodes added.
    """
    try:
        from plugins.enhanced_manifest_analysis.v2_plugin import SUSPICIOUS_COMBOS
    except ImportError:
        SUSPICIOUS_COMBOS = []

    warnings_added = 0
    for combo in SUSPICIOUS_COMBOS:
        combo_perms = combo.get("permissions", set())
        if not combo_perms:
            continue
        # Check overlap - ≥80% of combo permissions present
        if isinstance(combo_perms, (set, frozenset)):
            overlap = combo_perms & requested_permissions
        else:
            overlap = set(combo_perms) & requested_permissions
            combo_perms = set(combo_perms)
        if len(combo_perms) > 0 and len(overlap) / len(combo_perms) >= 0.8:
            combo_name = combo.get("name", "Unknown Combo")
            warn_id = f"warning:{combo.get('category', 'unknown')}"
            if warn_id not in nodes_by_id:
                nodes_by_id[warn_id] = GraphNode(
                    id=warn_id,
                    node_type="warning",
                    label=combo_name,
                    metadata={
                        "combo_name": combo_name,
                        "category": combo.get("category", ""),
                        "severity": combo.get("severity", "high"),
                        "cwe": combo.get("cwe", ""),
                        "description": combo.get("description", ""),
                        "matched_permissions": sorted(overlap),
                    },
                )
                # Connect warning to matched permission nodes
                for perm in overlap:
                    perm_id = f"permission:{perm}"
                    if perm_id not in nodes_by_id:
                        perm_short = perm.rsplit(".", 1)[-1] if "." in perm else perm
                        risk = _classify_permission_risk(perm)
                        nodes_by_id[perm_id] = GraphNode(
                            id=perm_id,
                            node_type="permission",
                            label=perm_short,
                            metadata={"full_name": perm, "risk_level": risk},
                        )
                    edges.append(GraphEdge(
                        source=warn_id,
                        target=perm_id,
                        relationship="requires_permission",
                        metadata={"combo": combo_name},
                    ))
                warnings_added += 1
    return warnings_added


_FILEPATH_COMPONENT_RE = re.compile(
    r"(?:app://)?AndroidManifest\.xml\s*[-\u2013\u2014]\s*([\w.]+)"
)


def _match_finding_to_component(
    comp_name: str,
    file_path: str,
    title: str,
    component_names: Dict[str, str],
) -> Optional[str]:
    """Try to map a finding to a component node id."""
    # 1. Direct component_name match
    if comp_name:
        if comp_name in component_names:
            return component_names[comp_name]
        short = comp_name.rsplit(".", 1)[-1] if "." in comp_name else comp_name
        if short in component_names:
            return component_names[short]

    # 2. Extract component from "app://AndroidManifest.xml - com.example.Foo" pattern
    if file_path:
        m = _FILEPATH_COMPONENT_RE.search(file_path)
        if m:
            extracted = m.group(1)
            if extracted in component_names:
                return component_names[extracted]
            extracted_short = extracted.rsplit(".", 1)[-1] if "." in extracted else extracted
            if extracted_short in component_names:
                return component_names[extracted_short]

    # 3. File path contains component class name
    if file_path:
        for name, nid in component_names.items():
            if "." not in name and name in file_path:
                return nid

    # 4. Title contains component class name
    if title:
        for name, nid in component_names.items():
            if "." not in name and len(name) > 4 and name in title:
                return nid

    return None


def _add_ipc_edges(
    source_id: Optional[str],
    code: str,
    component_names: Dict[str, str],
    nodes_by_id: Dict[str, GraphNode],
    edges: List[GraphEdge],
) -> None:
    """Extract IPC target references from code and add edges."""
    if not source_id:
        return
    for m in _CLASS_REF_PATTERN.finditer(code):
        ref = m.group(1)
        target_id = component_names.get(ref)
        if not target_id:
            short = ref.rsplit(".", 1)[-1]
            target_id = component_names.get(short)
        if target_id and target_id != source_id and target_id in nodes_by_id:
            edge = GraphEdge(
                source=source_id,
                target=target_id,
                relationship="ipc_call",
                metadata={"reference": ref},
            )
            # Avoid duplicate IPC edges
            existing = any(
                e.source == edge.source
                and e.target == edge.target
                and e.relationship == "ipc_call"
                for e in edges
            )
            if not existing:
                edges.append(edge)


# ---------------------------------------------------------------------------
# Keywords for classifying unmapped findings into synthetic nodes
# ---------------------------------------------------------------------------

_APP_CONFIG_KEYWORDS = re.compile(
    r"(debugg?able|allow.?backup|cleartext|network.?security|"
    r"usesCleartextTraffic|test.?only|android:debuggable|"
    r"backup.?flag|backup.?agent|full.?backup|"
    r"certificate.?pinning|ssl.?pinning|"
    r"insecure.?configuration|manifest.?config)",
    re.IGNORECASE,
)

_MANIFEST_FILE_PATTERN = re.compile(r"AndroidManifest\.xml", re.IGNORECASE)


def _assign_unmapped_findings(
    unmapped: List[Dict[str, Any]],
    nodes_by_id: Dict[str, GraphNode],
    edges: List[GraphEdge],
    already_mapped: int,
) -> None:
    """Assign unmapped findings to synthetic graph nodes.

    Creates two synthetic node types:
    - ``config:application`` - for manifest/app-level configuration findings
    - ``unmapped:findings`` - catch-all for anything else

    Nodes are only created if they receive at least one finding.
    """
    if not unmapped:
        return

    app_config_id = "config:application"
    unmapped_id = "unmapped:findings"

    for f in unmapped:
        fid = f.get("finding_id") or f.get("id") or ""
        if not fid:
            continue
        severity = (f.get("severity") or "info").lower()
        file_path = f.get("file_path") or ""
        title = f.get("title") or ""

        # Decide: is this an app-config finding or generic unmapped?
        is_manifest = bool(_MANIFEST_FILE_PATTERN.search(file_path))
        is_config_topic = bool(_APP_CONFIG_KEYWORDS.search(title))

        if is_manifest or is_config_topic:
            target_id = app_config_id
            if target_id not in nodes_by_id:
                nodes_by_id[target_id] = GraphNode(
                    id=target_id,
                    node_type="app_config",
                    label="App Configuration",
                    metadata={
                        "full_name": "Application-level manifest configuration",
                        "description": "Findings related to application-wide security settings in AndroidManifest.xml",
                    },
                )
        else:
            target_id = unmapped_id
            if target_id not in nodes_by_id:
                nodes_by_id[target_id] = GraphNode(
                    id=target_id,
                    node_type="app_config",
                    label="Other Findings",
                    metadata={
                        "full_name": "Findings not mapped to a specific component",
                        "description": "Security findings that could not be associated with a specific Android component",
                    },
                )

        node = nodes_by_id[target_id]
        if fid not in node.findings:
            node.findings.append(fid)
        node.severity = _worst_severity(node.severity, severity)
