from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


def load_taxonomy(path: str | Path = "compliance/masvs_mstg/taxonomy.yaml") -> Dict[str, Any]:
    """Load MASVS/MASTG taxonomy from YAML or JSON.
    Fallback order:
    - provided path (YAML/JSON)
    - compliance/masvs_mstg/taxonomy.yaml
    - compliance/masvs_mstg/taxonomy.json
    Returns a minimal structure when nothing is found.
    """
    p = Path(path)
    if not p.exists():
        # try default yaml/json
        for cand in (
            Path("compliance/masvs_mstg/taxonomy.yaml"),
            Path("compliance/masvs_mstg/taxonomy.json"),
        ):
            if cand.exists():
                p = cand
                break
    if not p.exists():
        return {"version": {"masvs": "2.0", "mastg": "2.0"}, "tests": []}

    if p.suffix.lower() in (".yaml", ".yml"):
        if yaml is None:
            # Minimal YAML parse for id/category-only lists
            tests: List[Dict[str, str]] = []
            cur: Dict[str, str] = {}
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line.startswith("- id:"):
                    if cur:
                        tests.append(cur)
                    cur = {"id": line.split(":", 1)[1].strip().strip('"')}
                elif line.startswith("category:") and cur:
                    cur["category"] = line.split(":", 1)[1].strip().strip('"')
            if cur:
                tests.append(cur)
            return {"version": {"masvs": "2.0", "mastg": "2.0"}, "tests": tests}
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8", errors="replace")) or {}
            return data if isinstance(data, dict) else {"version": {"masvs": "2.0", "mastg": "2.0"}, "tests": []}
        except Exception:
            return {"version": {"masvs": "2.0", "mastg": "2.0"}, "tests": []}

    # JSON input
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace")) or {}
    except Exception:
        return {"version": {"masvs": "2.0", "mastg": "2.0"}, "tests": []}


def taxonomy_defined_counts(taxonomy: Dict[str, Any]) -> Dict[str, int]:
    """Compute total defined MSTG tests per category from taxonomy dict."""
    counts: Dict[str, int] = {}
    tests = taxonomy.get("tests") or []
    if not isinstance(tests, list):
        return counts
    for t in tests:
        try:
            cat = str(t.get("category", "UNKNOWN")).upper()
            counts[cat] = counts.get(cat, 0) + 1
        except Exception:
            continue
    return counts
