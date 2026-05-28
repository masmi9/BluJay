"""
Live IDOR/BOLA interceptor.

After each proxied flow is captured, if IDOR testing is enabled for that session
the flow is evaluated as a candidate (has numeric/UUID path segment or id-like
params), then enqueued.  A per-session background worker replays the request
under a second (attacker) auth token and compares responses.

Confirmed findings are saved to the ScanFinding table (scan_type="idor") and
also kept in-memory for low-latency API reads.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

import httpx
import structlog

logger = structlog.get_logger()

# ── Patterns ──────────────────────────────────────────────────────────────────

_INT_SEGMENT_RE = re.compile(r"(^|/)\d+(/|$)")
_UUID_SEGMENT_RE = re.compile(
    r"(^|/)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(/|$)",
    re.IGNORECASE,
)
_IDOR_PARAM_NAMES = re.compile(
    r"^(id|user_?id|account_?id|object_?id|resource_?id|item_?id|post_?id|"
    r"doc_?id|file_?id|customer_?id|order_?id|message_?id|profile_?id|"
    r"uid|pid|aid|oid|rid|entity_?id|record_?id|subject_?id)$",
    re.IGNORECASE,
)
_STATIC_EXT_RE = re.compile(
    r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|pdf)(\?|$)",
    re.IGNORECASE,
)
_INTERNAL_HOST_RE = re.compile(
    r"^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1)",
    re.IGNORECASE,
)
_AUTH_HEADER_NAMES = frozenset({
    "authorization", "x-auth-token", "x-api-key",
    "x-access-token", "x-session-token", "cookie",
})
_HOP_BY_HOP = frozenset({
    "host", "content-length", "transfer-encoding",
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "upgrade",
})

# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class IDORConfig:
    enabled: bool = False
    victim_auth: str = ""
    victim_auth_header: str = "Authorization"
    attacker_auth: str = ""
    attacker_auth_header: str = "Authorization"
    cooldown_seconds: float = 0.3
    max_queue: int = 200
    # If True, also replay with zero auth headers (tests anonymous access)
    test_unauthenticated: bool = True


@dataclass
class _QueueItem:
    flow_id: str
    session_id: int
    url: str
    method: str
    headers: dict
    body: bytes
    victim_status: int
    victim_body: str
    queued_at: float = field(default_factory=time.monotonic)


@dataclass
class IDORFinding:
    id: str
    session_id: int
    timestamp: str
    url: str
    method: str
    victim_status: int
    attacker_status: int
    confidence: str        # high | medium | low
    detail: str
    victim_snippet: str
    attacker_snippet: str
    attacker_mode: str     # "second_user" | "unauthenticated"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "url": self.url,
            "method": self.method,
            "victim_status": self.victim_status,
            "attacker_status": self.attacker_status,
            "confidence": self.confidence,
            "detail": self.detail,
            "victim_snippet": self.victim_snippet,
            "attacker_snippet": self.attacker_snippet,
            "attacker_mode": self.attacker_mode,
        }


# ── Comparison helpers ────────────────────────────────────────────────────────

def _extract_leaf_values(obj, depth: int = 0) -> list:
    """Recursively collect primitive values from parsed JSON (max depth 4)."""
    if depth > 4:
        return []
    if isinstance(obj, (str, int, float)) and obj != "" and obj is not None:
        return [obj]
    if isinstance(obj, dict):
        vals = []
        for v in obj.values():
            vals.extend(_extract_leaf_values(v, depth + 1))
        return vals
    if isinstance(obj, list):
        vals = []
        for item in obj[:20]:
            vals.extend(_extract_leaf_values(item, depth + 1))
        return vals
    return []


def _victim_ids_leaked(victim_json, attacker_body_raw: str) -> list:
    """Return victim leaf values that appear verbatim in the attacker response body."""
    try:
        victim_vals = _extract_leaf_values(victim_json)
    except Exception:
        return []
    leaked = []
    ab_lower = attacker_body_raw.lower()
    for v in victim_vals:
        sv = str(v)
        # Only check values that look like IDs or emails — skip generic strings < 4 chars
        if len(sv) < 4:
            continue
        if sv.lower() in ab_lower:
            leaked.append(sv[:64])
    return leaked[:5]


def _compare(
    victim_status: int,
    victim_body: str,
    attacker_status: int,
    attacker_body: str,
    mode: str,
) -> dict:
    """
    Return {"is_idor": bool, "confidence": str, "reason": str, "score": int}.
    """
    # Attacker correctly denied → no IDOR
    if attacker_status in (401, 403):
        return {"is_idor": False, "confidence": "none",
                "reason": f"Attacker got {attacker_status} — access correctly denied"}

    # Victim also got an error → not a useful signal
    if victim_status >= 400:
        return {"is_idor": False, "confidence": "none",
                "reason": f"Victim also got {victim_status} — skipping"}

    score = 0
    reasons: list[str] = []

    if attacker_status == 200 and victim_status == 200:
        # Try JSON structural comparison
        try:
            v_json = json.loads(victim_body)
            a_json = json.loads(attacker_body)

            if isinstance(v_json, dict) and isinstance(a_json, dict):
                v_keys = set(v_json.keys())
                a_keys = set(a_json.keys())
                overlap = len(v_keys & a_keys) / max(len(v_keys), 1)
                if overlap >= 0.7:
                    score += 2
                    reasons.append(f"Same JSON schema ({overlap:.0%} key overlap)")

            leaked = _victim_ids_leaked(v_json, attacker_body)
            if leaked:
                score += 3
                reasons.append(f"Victim data leaked to attacker: {leaked}")
        except (json.JSONDecodeError, ValueError):
            # Non-JSON: body-length similarity
            vl, al = len(victim_body), len(attacker_body)
            if vl > 0 and al > 0:
                ratio = min(vl, al) / max(vl, al)
                if ratio >= 0.85:
                    score += 1
                    reasons.append(f"Similar response size (ratio {ratio:.2f})")

    elif attacker_status == 200 and victim_status not in (200,):
        # Attacker gets data that victim didn't — at minimum suspicious
        score += 2
        reasons.append(
            f"Attacker received 200 while victim got {victim_status} "
            f"({'unauthenticated' if mode == 'unauthenticated' else 'different user'})"
        )

    if score == 0:
        return {"is_idor": False, "confidence": "none",
                "reason": f"No significant difference (victim={victim_status} attacker={attacker_status})"}

    confidence = "high" if score >= 4 else "medium" if score >= 2 else "low"
    label = "unauthenticated" if mode == "unauthenticated" else "second-user"
    return {
        "is_idor": True,
        "confidence": confidence,
        "reason": f"[{label}] {'; '.join(reasons)}",
        "score": score,
    }


# ── Candidate detection ───────────────────────────────────────────────────────

def _is_candidate(flow: dict) -> bool:
    url = flow.get("url", "")
    method = (flow.get("method") or "GET").upper()
    host = flow.get("host", "")
    path = flow.get("path", "") or urlparse(url).path

    # Skip internal services
    if _INTERNAL_HOST_RE.match(host.split(":")[0]):
        return False

    # Skip static resources
    if _STATIC_EXT_RE.search(path):
        return False

    # Must be a data method
    if method not in ("GET", "PUT", "PATCH", "DELETE", "POST"):
        return False

    # Path has numeric or UUID segment
    if _INT_SEGMENT_RE.search(path) or _UUID_SEGMENT_RE.search(path):
        return True

    # Query string has ID-like param name
    try:
        qs = parse_qs(urlparse(url).query)
        if any(_IDOR_PARAM_NAMES.match(k) for k in qs):
            return True
    except Exception:
        pass

    # Request body has id-like key
    body = flow.get("request_body") or ""
    if body:
        try:
            data = json.loads(body[:4096])
            if isinstance(data, dict) and any(_IDOR_PARAM_NAMES.match(k) for k in data):
                return True
        except Exception:
            pass

    return False


def _build_attacker_headers(original_headers: dict, config: IDORConfig, mode: str) -> dict:
    """Strip victim auth, inject attacker auth (or nothing for unauthenticated mode)."""
    clean = {k: v for k, v in original_headers.items()
             if k.lower() not in _AUTH_HEADER_NAMES and k.lower() not in _HOP_BY_HOP}
    if mode == "second_user" and config.attacker_auth:
        clean[config.attacker_auth_header] = config.attacker_auth
    # unauthenticated: no auth headers at all
    return clean


def _host_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc or url
    except Exception:
        return url


def _path_from_url(url: str) -> str:
    try:
        return urlparse(url).path or "/"
    except Exception:
        return url


# ── Interceptor ───────────────────────────────────────────────────────────────

class IDORInterceptor:
    def __init__(self) -> None:
        self._configs: dict[int, IDORConfig] = {}
        self._queues: dict[int, asyncio.Queue] = {}
        self._workers: dict[int, asyncio.Task] = {}
        self._findings: dict[int, list[IDORFinding]] = {}
        # Track (method, normalized_url) pairs to avoid re-testing
        self._seen: dict[int, set[str]] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def configure(self, session_id: int, config: IDORConfig) -> None:
        self._configs[session_id] = config
        if config.enabled:
            if session_id not in self._queues:
                self._queues[session_id] = asyncio.Queue(maxsize=config.max_queue)
            if session_id not in self._workers or self._workers[session_id].done():
                task = asyncio.create_task(self._worker_loop(session_id))
                self._workers[session_id] = task
        else:
            self._stop_worker(session_id)

    def get_config(self, session_id: int) -> IDORConfig:
        return self._configs.get(session_id, IDORConfig())

    def enqueue(self, session_id: int, flow: dict) -> bool:
        config = self._configs.get(session_id)
        if not config or not config.enabled:
            return False
        if not _is_candidate(flow):
            return False

        # Dedup by method + url (skip query string variations for now)
        url = flow.get("url", "")
        key = f"{flow.get('method','GET').upper()}:{urlparse(url)._replace(query='').geturl()}"
        seen = self._seen.setdefault(session_id, set())
        if key in seen:
            return False
        seen.add(key)

        headers = flow.get("request_headers") or {}
        if isinstance(headers, str):
            try:
                headers = json.loads(headers)
            except Exception:
                headers = {}

        item = _QueueItem(
            flow_id=flow.get("id", ""),
            session_id=session_id,
            url=url,
            method=(flow.get("method") or "GET").upper(),
            headers=headers,
            body=(flow.get("request_body") or "").encode(errors="replace"),
            victim_status=flow.get("response_status") or 0,
            victim_body=(flow.get("response_body") or "")[:10000],
        )
        q = self._queues.setdefault(session_id, asyncio.Queue(maxsize=config.max_queue))
        try:
            q.put_nowait(item)
            return True
        except asyncio.QueueFull:
            return False

    def get_findings(self, session_id: int) -> list[dict]:
        return [f.to_dict() for f in self._findings.get(session_id, [])]

    def get_stats(self, session_id: int) -> dict:
        config = self._configs.get(session_id, IDORConfig())
        q = self._queues.get(session_id)
        return {
            "enabled": config.enabled,
            "queue_depth": q.qsize() if q else 0,
            "tested": len(self._seen.get(session_id, set())),
            "findings": len(self._findings.get(session_id, [])),
            "has_attacker_auth": bool(config.attacker_auth),
            "has_victim_auth": bool(config.victim_auth),
        }

    def clear(self, session_id: int) -> None:
        self._stop_worker(session_id)
        self._configs.pop(session_id, None)
        self._queues.pop(session_id, None)
        self._findings.pop(session_id, None)
        self._seen.pop(session_id, None)

    # ── Worker ────────────────────────────────────────────────────────────────

    def _stop_worker(self, session_id: int) -> None:
        task = self._workers.pop(session_id, None)
        if task and not task.done():
            task.cancel()

    async def _worker_loop(self, session_id: int) -> None:
        while True:
            try:
                config = self._configs.get(session_id)
                if not config or not config.enabled:
                    break
                q = self._queues.get(session_id)
                if q is None:
                    break
                try:
                    item: _QueueItem = await asyncio.wait_for(q.get(), timeout=5.0)
                except asyncio.TimeoutError:
                    continue
                await self._test_item(item)
                await asyncio.sleep(config.cooldown_seconds)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("IDOR worker error", session_id=session_id, error=str(e))

    async def _test_item(self, item: _QueueItem) -> None:
        config = self._configs.get(item.session_id)
        if not config:
            return

        modes = []
        if config.attacker_auth:
            modes.append("second_user")
        if config.test_unauthenticated:
            modes.append("unauthenticated")

        for mode in modes:
            attacker_headers = _build_attacker_headers(item.headers, config, mode)
            try:
                async with httpx.AsyncClient(verify=False, timeout=15) as client:
                    resp = await client.request(
                        method=item.method,
                        url=item.url,
                        headers=attacker_headers,
                        content=item.body or b"",
                    )
                attacker_status = resp.status_code
                attacker_body = resp.text[:10000]
            except Exception as e:
                logger.debug("IDOR replay failed", url=item.url, mode=mode, error=str(e))
                continue

            result = _compare(
                victim_status=item.victim_status,
                victim_body=item.victim_body,
                attacker_status=attacker_status,
                attacker_body=attacker_body,
                mode=mode,
            )

            if result["is_idor"]:
                finding_id = f"idor-{item.flow_id}-{mode}-{int(time.time())}"
                finding = IDORFinding(
                    id=finding_id,
                    session_id=item.session_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    url=item.url,
                    method=item.method,
                    victim_status=item.victim_status,
                    attacker_status=attacker_status,
                    confidence=result["confidence"],
                    detail=result["reason"],
                    victim_snippet=item.victim_body[:500],
                    attacker_snippet=attacker_body[:500],
                    attacker_mode=mode,
                )
                self._findings.setdefault(item.session_id, []).insert(0, finding)
                asyncio.create_task(self._persist(item.session_id, finding))
                logger.warning(
                    "IDOR detected",
                    url=item.url,
                    method=item.method,
                    confidence=result["confidence"],
                    mode=mode,
                )

    async def _persist(self, session_id: int, finding: IDORFinding) -> None:
        try:
            from database import AsyncSessionLocal
            from models.scanner import ScanFinding
            async with AsyncSessionLocal() as db:
                sf = ScanFinding(
                    session_id=session_id,
                    flow_id=finding.id,
                    scan_type="idor",
                    check_name="idor-bola",
                    severity="high" if finding.confidence == "high" else "medium",
                    url=finding.url,
                    host=_host_from_url(finding.url),
                    title=f"IDOR/BOLA — {finding.method} {_path_from_url(finding.url)}",
                    detail=finding.detail,
                    evidence=json.dumps({
                        "victim_status": finding.victim_status,
                        "attacker_status": finding.attacker_status,
                        "attacker_mode": finding.attacker_mode,
                        "victim_snippet": finding.victim_snippet,
                        "attacker_snippet": finding.attacker_snippet,
                        "confidence": finding.confidence,
                    }),
                    remediation=(
                        "Implement object-level authorization on every endpoint that accesses "
                        "user-owned resources. Verify the requesting user owns the referenced "
                        "object ID before returning or mutating data. Never rely on obscure IDs "
                        "alone for access control (OWASP API1:2023 — BOLA)."
                    ),
                )
                db.add(sf)
                await db.commit()
        except Exception as e:
            logger.warning("Failed to persist IDOR finding", error=str(e))
