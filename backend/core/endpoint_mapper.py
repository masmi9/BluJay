"""
Live endpoint mapper — builds a deduplicated API surface map from proxied flows.

For each flow, the path is normalized (integers → {id}, UUIDs → {uuid}) and
the resulting pattern is used as the map key.  The mapper tracks methods, params,
auth headers, response codes, and raises flags useful for IDOR/auth testing.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

# ── Normalization regexes ─────────────────────────────────────────────────────

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_INT_RE = re.compile(r"^\d+$")
_LONG_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)  # opaque tokens / hashes

# Headers that indicate authentication is present
_AUTH_HEADER_NAMES = {
    "authorization",
    "x-auth-token",
    "x-api-key",
    "x-access-token",
    "x-session-token",
    "x-user-token",
    "cookie",
}

# Response / request body patterns that suggest PII
_PII_RE = re.compile(
    r'\b[\w.+-]+@[\w-]+\.\w+\b'       # email
    r'|\b\d{3}[-. ]?\d{2}[-. ]?\d{4}\b'  # SSN-like
    r'|\b(?:ssn|credit_card|card_number|cvv|dob|date_of_birth)\b',
    re.IGNORECASE,
)

_SENSITIVE_METHODS = {"DELETE", "PUT", "PATCH"}

# Skip these hosts entirely — they pollute the map
_SKIP_HOSTS = {
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "www.google-analytics.com",
    "ssl.gstatic.com",
    "accounts.google.com",
}


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class EndpointParam:
    name: str
    type: str   # integer | uuid | string | boolean
    sample: str


@dataclass
class MappedEndpoint:
    pattern: str
    host: str
    methods: list[str] = field(default_factory=list)
    sample_url: str = ""
    auth_headers: list[str] = field(default_factory=list)
    path_params: list[dict] = field(default_factory=list)
    query_params: list[dict] = field(default_factory=list)
    body_params: list[dict] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    response_codes: list[int] = field(default_factory=list)
    count: int = 0
    feature: str | None = None
    first_seen: str = ""
    last_seen: str = ""

    # internal sets for dedup — not serialised
    _methods: set = field(default_factory=set, repr=False)
    _auth_headers: set = field(default_factory=set, repr=False)
    _flags: set = field(default_factory=set, repr=False)
    _response_codes: set = field(default_factory=set, repr=False)

    def to_dict(self) -> dict:
        return {
            "pattern": self.pattern,
            "host": self.host,
            "methods": sorted(self._methods),
            "sample_url": self.sample_url,
            "auth_headers": sorted(self._auth_headers),
            "path_params": self.path_params,
            "query_params": self.query_params,
            "body_params": self.body_params,
            "flags": sorted(self._flags),
            "response_codes": sorted(self._response_codes),
            "count": self.count,
            "feature": self.feature,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalize_segment(seg: str) -> tuple[str, str | None]:
    """Return (normalized_segment, param_type|None)."""
    if not seg:
        return seg, None
    if _UUID_RE.match(seg):
        return "{uuid}", "uuid"
    if _INT_RE.match(seg):
        return "{id}", "integer"
    if _LONG_HEX_RE.match(seg) and len(seg) >= 20:
        return "{hash}", "string"
    return seg, None


def normalize_path(path: str) -> tuple[str, list[dict]]:
    """
    Normalize a URL path and return (pattern, path_params).

    /api/v1/users/42/posts/abc123  →  /api/v1/users/{id}/posts/{hash}
    """
    clean = path.split("?")[0].rstrip("/") or "/"
    segments = clean.split("/")
    normalized = []
    path_params: list[dict] = []
    idx = 0
    for seg in segments:
        normed, ptype = _normalize_segment(seg)
        normalized.append(normed)
        if ptype:
            path_params.append({"name": f"param{idx}", "type": ptype, "sample": seg})
            idx += 1
    return "/".join(normalized), path_params


def _extract_query_params(url: str) -> list[dict]:
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        params = []
        for k, vals in qs.items():
            sample = vals[0] if vals else ""
            ptype = "integer" if _INT_RE.match(sample) else ("uuid" if _UUID_RE.match(sample) else "string")
            params.append({"name": k, "type": ptype, "sample": sample[:64]})
        return params
    except Exception:
        return []


def _extract_body_params(body: str | None, content_type: str | None) -> list[dict]:
    if not body or not content_type:
        return []
    ct = content_type.lower()
    params: list[dict] = []
    try:
        if "json" in ct:
            data = json.loads(body[:8192])
            if isinstance(data, dict):
                for k, v in list(data.items())[:30]:
                    sample = str(v)[:64]
                    ptype = (
                        "integer" if isinstance(v, int)
                        else "boolean" if isinstance(v, bool)
                        else "uuid" if isinstance(v, str) and _UUID_RE.match(v)
                        else "string"
                    )
                    params.append({"name": k, "type": ptype, "sample": sample})
        elif "x-www-form-urlencoded" in ct:
            pairs = body[:4096].split("&")
            for pair in pairs:
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    params.append({"name": k, "type": "string", "sample": v[:64]})
    except Exception:
        pass
    return params


def _compute_flags(
    method: str,
    path_params: list[dict],
    auth_headers: set[str],
    response_body: str | None,
    request_body: str | None,
) -> set[str]:
    flags: set[str] = set()
    if any(p["type"] in ("integer", "uuid") for p in path_params):
        flags.add("idor_candidate")
    if auth_headers:
        flags.add("auth_required")
    if method in _SENSITIVE_METHODS:
        flags.add("sensitive_method")
    combined = (response_body or "") + (request_body or "")
    if _PII_RE.search(combined[:4096]):
        flags.add("pii_likely")
    return flags


# ── Mapper ────────────────────────────────────────────────────────────────────

class EndpointMapper:
    """Thread-safe (GIL-only) per-session endpoint map."""

    def __init__(self) -> None:
        # session_id → host → pattern → MappedEndpoint
        self._maps: dict[int, dict[str, dict[str, MappedEndpoint]]] = {}

    def update(self, session_id: int, flow: dict) -> None:
        host = flow.get("host", "")
        if not host or host in _SKIP_HOSTS:
            return

        url = flow.get("url", "")
        path = flow.get("path", "") or urlparse(url).path or "/"
        method = (flow.get("method") or "GET").upper()
        req_headers: dict = flow.get("request_headers") or {}
        if isinstance(req_headers, str):
            try:
                req_headers = json.loads(req_headers)
            except Exception:
                req_headers = {}

        content_type = flow.get("content_type") or ""
        req_body = flow.get("request_body")
        resp_body = flow.get("response_body")
        status = flow.get("response_status")

        pattern, path_params = normalize_path(path)
        query_params = _extract_query_params(url)
        body_params = _extract_body_params(req_body, content_type)

        auth_hdrs = {
            k.lower() for k in req_headers
            if k.lower() in _AUTH_HEADER_NAMES
        }
        flags = _compute_flags(method, path_params, auth_hdrs, resp_body, req_body)

        now = datetime.now(timezone.utc).isoformat()

        host_map = self._maps.setdefault(session_id, {})
        endpoint_map = host_map.setdefault(host, {})

        if pattern not in endpoint_map:
            ep = MappedEndpoint(pattern=pattern, host=host, first_seen=now)
            ep._methods = set()
            ep._auth_headers = set()
            ep._flags = set()
            ep._response_codes = set()
            endpoint_map[pattern] = ep
        else:
            ep = endpoint_map[pattern]

        ep._methods.add(method)
        ep._auth_headers.update(auth_hdrs)
        ep._flags.update(flags)
        if status:
            ep._response_codes.add(status)

        ep.count += 1
        ep.last_seen = now
        if not ep.sample_url:
            ep.sample_url = url

        # Merge params — keep first seen, avoid duplicates by name
        existing_pp = {p["name"] for p in ep.path_params}
        for p in path_params:
            if p["name"] not in existing_pp:
                ep.path_params.append(p)
                existing_pp.add(p["name"])

        existing_qp = {p["name"] for p in ep.query_params}
        for p in query_params:
            if p["name"] not in existing_qp:
                ep.query_params.append(p)
                existing_qp.add(p["name"])

        existing_bp = {p["name"] for p in ep.body_params}
        for p in body_params:
            if p["name"] not in existing_bp:
                ep.body_params.append(p)
                existing_bp.add(p["name"])

    def get_map(self, session_id: int) -> dict:
        host_map = self._maps.get(session_id, {})
        result: dict[str, list] = {}
        for host, endpoint_map in host_map.items():
            result[host] = [ep.to_dict() for ep in endpoint_map.values()]
        return result

    def set_feature(self, session_id: int, host: str, pattern: str, feature: str | None) -> bool:
        try:
            self._maps[session_id][host][pattern].feature = feature or None
            return True
        except KeyError:
            return False

    def clear(self, session_id: int) -> None:
        self._maps.pop(session_id, None)

    def stats(self, session_id: int) -> dict:
        host_map = self._maps.get(session_id, {})
        total_endpoints = sum(len(eps) for eps in host_map.values())
        idor_count = sum(
            1 for eps in host_map.values()
            for ep in eps.values()
            if "idor_candidate" in ep._flags
        )
        return {
            "hosts": len(host_map),
            "endpoints": total_endpoints,
            "idor_candidates": idor_count,
        }
