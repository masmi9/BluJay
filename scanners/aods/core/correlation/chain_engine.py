#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class RuleStep:
    match_plugin: Optional[str] = None
    match_tag: Optional[str] = None


def _matches(finding: Dict[str, Any], step: RuleStep) -> bool:
    if step.match_plugin:
        ps = str(finding.get("plugin_source", "")).lower()
        if step.match_plugin.lower() not in ps:
            return False
    if step.match_tag:
        tags = finding.get("tags") or []
        if isinstance(tags, list):
            if step.match_tag not in [str(t) for t in tags]:
                return False
        else:
            return False
    return True


def correlate_findings(findings: List[Dict[str, Any]], rule: List[RuleStep]) -> List[List[Dict[str, Any]]]:
    """Return chains (list of finding sequences) that satisfy the ordered rule steps.

    Simplified approach: greedy left-to-right matching; findings used once per chain.
    Chains are scoped within same package_name when present to avoid cross-target linking.
    """
    chains: List[List[Dict[str, Any]]] = []
    if not findings or not rule:
        return chains

    remaining = findings[:]

    def _pkg(f: Dict[str, Any]) -> Optional[str]:
        return f.get("package_name") or f.get("metadata", {}).get("package_name")

    # Group by package_name (or single group if absent)
    groups: Dict[Optional[str], List[Dict[str, Any]]] = {}
    for f in remaining:
        groups.setdefault(_pkg(f), []).append(f)

    for _, group in groups.items():
        used_idx: set[int] = set()
        # attempt to extract as many chains as possible
        while True:
            seq: List[Dict[str, Any]] = []
            last_idx = -1
            for step in rule:
                matched = False
                for i, f in enumerate(group):
                    if i in used_idx or i <= last_idx:
                        continue
                    if _matches(f, step):
                        seq.append(f)
                        last_idx = i
                        matched = True
                        break
                if not matched:
                    seq = []
                    break
            if seq:
                chains.append(seq)
                # mark used
                for i, f in enumerate(group):
                    if f in seq:
                        used_idx.add(i)
            else:
                break
    return chains


__all__ = ["RuleStep", "correlate_findings"]
