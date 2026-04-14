"""
Builds an ApiTestSuite context from captured proxy flows for a session.

Scans all ProxyFlow rows for a session and extracts:
  - auth_contexts: distinct session tokens/credentials found in request headers
  - collected_ids: resource IDs found in URL params, grouped by endpoint pattern
  - suggested_tests: auto-generated test case specs (not yet persisted)

The result is merged into ApiTestSuite.auth_contexts_json /
ApiTestSuite.collected_ids_json by the import-flows endpoint.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from urllib.parse import parse_qs, urlparse, urlunparse, urlencode

from sqlalchemy import select

# Headers whose values are session credentials
_AUTH_HEADER_NAMES: frozenset[str] = frozenset({
    "x-tt-token",
    "authorization",
    "x-session-token",
    "x-auth-token",
    "x-api-key",
    "token",
    "x-access-token",
    "x-user-token",
    "x-device-token",
})

# Cookie sub-string patterns that suggest session data
_SESSION_COOKIE_RE = re.compile(
    r"(?:session|token|auth|sid|ssid|jwt|access|refresh|login)[\w\-]*=[^;,\s]{6,}",
    re.IGNORECASE,
)

# Snowflake / large integer IDs (ByteDance uses 15-19 digit integers)
_SNOWFLAKE_RE = re.compile(r"\b\d{13,}\b")

# Query parameter names that are likely resource identifiers
_ID_PARAM_NAMES: frozenset[str] = frozenset({
    "user_id", "uid", "report_id", "post_id", "video_id", "comment_id",
    "item_id", "creator_id", "account_id", "id", "object_id",
    "resource_id", "content_id", "target_id", "src_user_id",
})


# ── URL normalisation ────────────────────────────────────────────────────────

def _normalize_pattern(url: str) -> str:
    """Replace digit-only path segments with {id} and strip query string."""
    try:
        p = urlparse(url)
        parts = ["{id}" if re.fullmatch(r"\d+", seg) else seg for seg in p.path.split("/")]
        return f"{p.scheme}://{p.netloc}{'/'.join(parts)}"
    except Exception:
        return url


def _extract_id_params(url: str) -> dict[str, list[str]]:
    """Return {param_name: [value, ...]} for ID-bearing query parameters."""
    try:
        p = urlparse(url)
        params = parse_qs(p.query, keep_blank_values=False)
        return {
            k: vals
            for k, vals in params.items()
            if k.lower() in _ID_PARAM_NAMES or (vals and _SNOWFLAKE_RE.fullmatch(vals[0]))
        }
    except Exception:
        return {}


def _short_url(url: str, max_len: int = 70) -> str:
    try:
        p = urlparse(url)
        s = p.path
        if p.query:
            s += "?" + p.query[:30] + ("…" if len(p.query) > 30 else "")
        return s[:max_len]
    except Exception:
        return url[:max_len]


# ── Main builder ─────────────────────────────────────────────────────────────

async def build_suite_context(session_id: int, db) -> dict:
    """
    Scan all proxy flows for session_id and return a context dict:
    {
        auth_contexts:   [{id, label, header_name, header_value, first_seen_url}, …],
        collected_ids:   {endpoint_pattern: {param_name: [values]}},
        suggested_tests: [{test_type, name, description, method, url, headers, config}, …],
        flow_count:      int,
    }
    """
    from models.session import ProxyFlow

    result = await db.execute(
        select(ProxyFlow)
        .where(ProxyFlow.session_id == session_id)
        .order_by(ProxyFlow.timestamp)
    )
    flows = result.scalars().all()

    # token_key → {header_name, header_value, first_seen_url}
    token_map: dict[str, dict] = {}

    # pattern → {method, example_url, example_headers, query_ids: {name: set(values)}, has_auth}
    endpoint_map: dict[str, dict] = {}

    for flow in flows:
        try:
            headers: dict[str, str] = json.loads(flow.request_headers or "{}")
        except Exception:
            headers = {}

        # ── Auth token extraction ──
        for hname, hval in headers.items():
            hval_str = str(hval)
            hl = hname.lower()

            # Named auth headers
            if hl in _AUTH_HEADER_NAMES and len(hval_str) > 8:
                key = f"{hl}:{hval_str[:64]}"
                if key not in token_map:
                    token_map[key] = {
                        "header_name": hname,
                        "header_value": hval_str,
                        "first_seen_url": flow.url or "",
                    }

            # Session cookies
            if hl == "cookie":
                for m in _SESSION_COOKIE_RE.finditer(hval_str):
                    ck = m.group(0)
                    key = f"cookie:{ck[:64]}"
                    if key not in token_map:
                        token_map[key] = {
                            "header_name": "Cookie",
                            "header_value": ck,
                            "first_seen_url": flow.url or "",
                        }

        # ── Endpoint & ID collection ──
        if not flow.url:
            continue

        pattern = _normalize_pattern(flow.url)
        if pattern not in endpoint_map:
            endpoint_map[pattern] = {
                "method": flow.method or "GET",
                "example_url": flow.url,
                "example_headers": headers,
                "query_ids": defaultdict(set),
                "has_auth": False,
            }

        ep = endpoint_map[pattern]
        if any(h.lower() in _AUTH_HEADER_NAMES for h in headers):
            ep["has_auth"] = True

        for pname, vals in _extract_id_params(flow.url).items():
            for v in vals:
                ep["query_ids"][pname].add(v)

    # ── Build auth_contexts list (dedup by token value) ──
    seen_vals: set[str] = set()
    auth_contexts: list[dict] = []
    for idx, ctx in enumerate(token_map.values()):
        dedup_key = ctx["header_value"][:32]
        if dedup_key in seen_vals:
            continue
        seen_vals.add(dedup_key)
        auth_contexts.append({
            "id": idx,
            "label": f"Account {len(auth_contexts) + 1}",
            "header_name": ctx["header_name"],
            "header_value": ctx["header_value"],
            "first_seen_url": ctx["first_seen_url"],
        })

    # ── Build collected_ids ──
    collected_ids: dict[str, dict[str, list[str]]] = {}
    for pattern, ep_data in endpoint_map.items():
        id_params = {k: list(v) for k, v in ep_data["query_ids"].items() if v}
        if id_params:
            collected_ids[pattern] = id_params

    # ── Generate suggested tests ──
    suggested: list[dict] = []

    for pattern, ep_data in endpoint_map.items():
        q_ids = {k: list(v) for k, v in ep_data["query_ids"].items() if v}
        headers = ep_data["example_headers"]
        auth_header_names = [h for h in headers if h.lower() in _AUTH_HEADER_NAMES]

        # Auth strip — any authenticated endpoint
        if ep_data["has_auth"]:
            suggested.append({
                "test_type": "auth_strip",
                "name": f"Auth Strip — {_short_url(ep_data['example_url'])}",
                "description": (
                    f"Test whether {ep_data['method']} {pattern} enforces authentication. "
                    f"Strips {', '.join(auth_header_names) or 'session headers'} and compares response."
                ),
                "method": ep_data["method"],
                "url": ep_data["example_url"],
                "headers": headers,
                "body": None,
                "config": {"auth_headers": auth_header_names},
            })

        # IDOR sweep — endpoints with ID-bearing query params
        for param_name, values in q_ids.items():
            suggested.append({
                "test_type": "idor_sweep",
                "name": f"IDOR Sweep — {_short_url(ep_data['example_url'])} [{param_name}]",
                "description": (
                    f"Enumerate {param_name} on {ep_data['method']} {pattern}. "
                    f"{len(values)} unique ID(s) collected from traffic. "
                    f"Tests unauthenticated access and cross-user data disclosure."
                ),
                "method": ep_data["method"],
                "url": ep_data["example_url"],
                "headers": headers,
                "body": None,
                "config": {
                    "param_name": param_name,
                    "param_type": "query",
                    "base_value": values[0] if values else "",
                    "collected_ids": values[:20],
                    "test_no_auth": ep_data["has_auth"],
                },
            })

    # Cross-user auth — if 2+ distinct tokens observed
    if len(auth_contexts) >= 2:
        auth_ep = next(
            (ep for ep in endpoint_map.values() if ep["has_auth"] and ep["query_ids"]),
            next((ep for ep in endpoint_map.values() if ep["has_auth"]), None),
        )
        if auth_ep:
            suggested.append({
                "test_type": "cross_user_auth",
                "name": f"Cross-User Auth — {_short_url(auth_ep['example_url'])}",
                "description": (
                    f"Replay a request captured for {auth_contexts[0]['label']} "
                    f"using {auth_contexts[1]['label']}'s session token. "
                    f"Detects broken object-level authorization (BOLA/IDOR)."
                ),
                "method": auth_ep["method"],
                "url": auth_ep["example_url"],
                "headers": auth_ep["example_headers"],
                "body": None,
                "config": {
                    "account_a": auth_contexts[0],
                    "account_b": auth_contexts[1],
                },
            })

    # Token replay — if any token seen
    if auth_contexts:
        ctx = auth_contexts[0]
        auth_ep = next((ep for ep in endpoint_map.values() if ep["has_auth"]), None)
        if auth_ep:
            suggested.append({
                "test_type": "token_replay",
                "name": f"Token Replay — {ctx['label']} ({ctx['header_name']})",
                "description": (
                    f"Capture {ctx['header_name']} for {ctx['label']}, log out of the app, "
                    f"then replay the token to test whether the server invalidates it on logout."
                ),
                "method": auth_ep["method"],
                "url": auth_ep["example_url"],
                "headers": auth_ep["example_headers"],
                "body": None,
                "config": {
                    "token_header": ctx["header_name"],
                    "token_value": ctx["header_value"],
                    "account_label": ctx["label"],
                },
            })

    return {
        "auth_contexts": auth_contexts,
        "collected_ids": collected_ids,
        "suggested_tests": suggested,
        "flow_count": len(flows),
    }
