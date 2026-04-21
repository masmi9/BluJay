from __future__ import annotations

from typing import List, Dict, Tuple

from .script_suggester import ScriptSuggestion


def _suggestion_key(s: ScriptSuggestion) -> Tuple[str, Tuple[Tuple[str, str], ...]]:
    """Create a stable key for a suggestion based on template and sorted params."""
    params = tuple(sorted(((k, str(v)) for k, v in (s.params or {}).items())))
    return (s.template_id, params)


def resolve_conflicts(suggestions: List[ScriptSuggestion], max_count: int) -> List[ScriptSuggestion]:
    """Resolve duplicate/overlapping suggestions and cap to top-N by score.

    Rules:
    - Deduplicate by (template_id, params)
    - Prefer higher score; stable order among equals
    - Cap to max_count (>=1)
    """
    if not suggestions:
        return []

    max_count = max(1, int(max_count or 1))

    # Deduplicate by key, keeping highest score
    best_by_key: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], ScriptSuggestion] = {}
    for s in suggestions:
        key = _suggestion_key(s)
        prev = best_by_key.get(key)
        if prev is None or float(getattr(s, "score", 0.0) or 0.0) > float(getattr(prev, "score", 0.0) or 0.0):
            best_by_key[key] = s

    deduped = list(best_by_key.values())
    # Sort by score desc, then by template_id for determinism
    deduped.sort(
        key=lambda x: (float(getattr(x, "score", 0.0) or 0.0), str(getattr(x, "template_id", ""))), reverse=True
    )

    return deduped[:max_count]
