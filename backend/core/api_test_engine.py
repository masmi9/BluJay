"""
API test execution engine.

Runs four test types:
  auth_strip      — verifies authentication is enforced
  idor_sweep      — enumerates ID parameters for cross-user data disclosure
  token_replay    — checks whether tokens are server-side invalidated on logout
  cross_user_auth — swaps tokens between accounts to detect BOLA/IDOR

Progress is streamed to subscribers via asyncio.Queue (fed to WebSocket).
Results are persisted as ApiTestResult rows after each request.
"""
from __future__ import annotations

import asyncio
import json
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
import structlog

logger = structlog.get_logger()

# Per-test progress queues keyed by test_id
_queues: dict[int, asyncio.Queue] = {}

# Auth header names to strip/detect
_AUTH_HEADERS: frozenset[str] = frozenset({
    "x-tt-token", "authorization", "cookie",
    "x-session-token", "x-auth-token", "x-api-key",
    "x-access-token", "x-user-token", "x-device-token",
})

# Hop-by-hop headers that must not be forwarded
_HOP_BY_HOP: frozenset[str] = frozenset({
    "host", "content-length", "transfer-encoding",
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "upgrade",
})


# ── Queue management ─────────────────────────────────────────────────────────

def register_test_queue(test_id: int) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=1000)
    _queues[test_id] = q
    return q


def get_test_queue(test_id: int) -> asyncio.Queue | None:
    return _queues.get(test_id)


def _deregister(test_id: int) -> None:
    _queues.pop(test_id, None)


async def _emit(test_id: int, msg: dict) -> None:
    q = _queues.get(test_id)
    if q:
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            pass


# ── HTTP request helper ──────────────────────────────────────────────────────

async def _request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None,
    timeout: float = 20.0,
) -> dict:
    """Send one HTTP request; return a normalised result dict."""
    clean_headers = {
        k: v for k, v in headers.items()
        if k.lower() not in _HOP_BY_HOP
    }
    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=timeout,
        ) as client:
            resp = await client.request(
                method=method,
                url=url,
                headers=clean_headers,
                content=body.encode() if body else None,
            )
            duration_ms = int((time.monotonic() - t0) * 1000)
            raw = await resp.aread()
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": raw[:50_000].decode(errors="replace"),
                "duration_ms": duration_ms,
                "error": None,
            }
    except Exception as exc:
        return {
            "status_code": None,
            "headers": {},
            "body": "",
            "duration_ms": int((time.monotonic() - t0) * 1000),
            "error": str(exc),
        }


# ── Response analysis helpers ────────────────────────────────────────────────

def _looks_like_data(body: str, status: int | None) -> bool:
    """Heuristic: does the response carry real payload (not an auth error)?"""
    if status is None or status >= 400:
        return False
    if len(body) < 20:
        return False
    try:
        obj = json.loads(body)
        if isinstance(obj, dict):
            # ByteDance pattern: status_code 0 = success
            sc = obj.get("status_code")
            if sc is not None and sc != 0:
                return False
            # Must have some content key
            return bool(obj.get("data") or obj.get("result") or obj.get("user")
                        or obj.get("creator") or obj.get("report") or obj.get("config")
                        or obj.get("items") or len(obj) > 2)
        return isinstance(obj, (list,)) and len(obj) > 0
    except Exception:
        return len(body) > 100


def _diff_summary(a: str, b: str) -> str:
    if a == b:
        return "Identical response bodies"
    if not b:
        return "Empty response"
    pct = abs(len(a) - len(b)) / max(len(a), 1) * 100
    if pct < 3:
        return f"Nearly identical ({pct:.1f}% size difference)"
    return f"Responses differ — baseline {len(a):,}B vs test {len(b):,}B ({pct:.0f}% difference)"


# ── Result persistence ───────────────────────────────────────────────────────

async def _save_result(
    db_factory,
    test_id: int,
    label: str,
    req: dict,
    resp: dict,
    is_vuln: bool,
    finding: str | None,
    severity: str | None,
    diff: str | None,
) -> None:
    from models.api_testing import ApiTestResult

    async with db_factory() as db:
        r = ApiTestResult(
            test_id=test_id,
            label=label,
            request_method=req["method"],
            request_url=req["url"],
            request_headers_json=json.dumps(req["headers"]),
            request_body=req.get("body"),
            response_status=resp["status_code"],
            response_headers_json=json.dumps(resp["headers"]),
            response_body=resp["body"],
            duration_ms=resp["duration_ms"],
            is_vulnerable=is_vuln,
            finding=finding,
            severity=severity,
            diff_summary=diff,
        )
        db.add(r)
        await db.commit()


# ── Test entry point ─────────────────────────────────────────────────────────

async def run_test(test_id: int, db_factory) -> None:
    """Load test from DB, dispatch to the right runner, update status."""
    from models.api_testing import ApiTest

    async with db_factory() as db:
        test = await db.get(ApiTest, test_id)
        if not test:
            return
        test.status = "running"
        await db.commit()

    try:
        tt = test.test_type
        if tt == "auth_strip":
            await _auth_strip(test_id, db_factory)
        elif tt == "idor_sweep":
            await _idor_sweep(test_id, db_factory)
        elif tt == "token_replay":
            await _token_replay(test_id, db_factory)
        elif tt == "cross_user_auth":
            await _cross_user_auth(test_id, db_factory)
        else:
            await _emit(test_id, {"type": "error", "message": f"Unknown test type: {tt}"})
            async with db_factory() as db:
                t = await db.get(ApiTest, test_id)
                if t:
                    t.status = "failed"
                    await db.commit()
            return
    except Exception as exc:
        logger.error("api_test_failed", test_id=test_id, error=str(exc))
        async with db_factory() as db:
            t = await db.get(ApiTest, test_id)
            if t:
                t.status = "failed"
                await db.commit()
    finally:
        await _emit(test_id, {"type": "done"})
        _deregister(test_id)


# ── Test runners ─────────────────────────────────────────────────────────────

async def _auth_strip(test_id: int, db_factory) -> None:
    """
    Auth Strip — verify the endpoint requires valid session credentials.
    Sends three variants:
      1. Baseline (all original headers — authenticated)
      2. Auth headers stripped entirely
      3. Auth headers set to an invalid value
    """
    from models.api_testing import ApiTest

    async with db_factory() as db:
        test = await db.get(ApiTest, test_id)
        headers: dict = json.loads(test.headers_json or "{}")
        config: dict = json.loads(test.config_json or "{}")

    # Determine which headers carry credentials
    auth_names: list[str] = config.get(
        "auth_headers",
        [k for k in headers if k.lower() in _AUTH_HEADERS],
    )

    vuln_count = 0

    # ── 1. Baseline ──
    await _emit(test_id, {"type": "progress", "message": "Baseline request (authenticated)…"})
    base_resp = await _request(test.method, test.url, headers, test.body)
    await _save_result(db_factory, test_id, "baseline_auth",
        {"method": test.method, "url": test.url, "headers": headers, "body": test.body},
        base_resp, False, None, None, None)
    await _emit(test_id, {"type": "result", "label": "baseline_auth",
                          "status": base_resp["status_code"], "vulnerable": False})

    # ── 2. No auth headers ──
    stripped = {k: v for k, v in headers.items() if k not in auth_names}
    await _emit(test_id, {"type": "progress", "message": "Stripping auth headers…"})
    noauth_resp = await _request(test.method, test.url, stripped, test.body)

    is_vuln = _looks_like_data(noauth_resp["body"], noauth_resp["status_code"]) \
              and _looks_like_data(base_resp["body"], base_resp["status_code"])
    diff = _diff_summary(base_resp["body"], noauth_resp["body"])

    if is_vuln:
        vuln_count += 1
        finding = (
            f"Endpoint returns data with no authentication. "
            f"Unauthenticated response: HTTP {noauth_resp['status_code']} "
            f"({len(noauth_resp['body']):,}B). "
            f"Auth headers stripped: {', '.join(auth_names) or 'none detected'}."
        )
        severity = "critical"
    else:
        finding = f"Server rejected unauthenticated request: HTTP {noauth_resp['status_code']}."
        severity = None

    await _save_result(db_factory, test_id, "stripped_auth",
        {"method": test.method, "url": test.url, "headers": stripped, "body": test.body},
        noauth_resp, is_vuln, finding, severity, diff)
    await _emit(test_id, {"type": "result", "label": "stripped_auth",
                          "status": noauth_resp["status_code"], "vulnerable": is_vuln})

    # ── 3. Mangled auth (set to invalid value) ──
    mangled = {**headers, **{k: "INVALID_TOKEN_TEST_BLUJAY" for k in auth_names}}
    await _emit(test_id, {"type": "progress", "message": "Sending mangled auth token…"})
    mangled_resp = await _request(test.method, test.url, mangled, test.body)

    is_vuln_m = _looks_like_data(mangled_resp["body"], mangled_resp["status_code"]) \
                and _looks_like_data(base_resp["body"], base_resp["status_code"])
    if is_vuln_m:
        vuln_count += 1

    await _save_result(db_factory, test_id, "mangled_auth",
        {"method": test.method, "url": test.url, "headers": mangled, "body": test.body},
        mangled_resp, is_vuln_m,
        f"Endpoint accepted an invalid token: HTTP {mangled_resp['status_code']}." if is_vuln_m else None,
        "high" if is_vuln_m else None,
        _diff_summary(base_resp["body"], mangled_resp["body"]))
    await _emit(test_id, {"type": "result", "label": "mangled_auth",
                          "status": mangled_resp["status_code"], "vulnerable": is_vuln_m})

    async with db_factory() as db:
        t = await db.get(ApiTest, test_id)
        if t:
            t.status = "complete"
            t.run_count = (t.run_count or 0) + 1
            t.vulnerable_count = vuln_count
            await db.commit()


async def _idor_sweep(test_id: int, db_factory) -> None:
    """
    IDOR Sweep — enumerate a named ID parameter with collected/sequential values.

    Sends:
      1. Baseline with original ID + auth
      2. Baseline with original ID, no auth (if enabled) → unauthenticated IDOR
      3. Each collected foreign ID with auth → cross-user IDOR
    """
    from models.api_testing import ApiTest

    async with db_factory() as db:
        test = await db.get(ApiTest, test_id)
        headers: dict = json.loads(test.headers_json or "{}")
        config: dict = json.loads(test.config_json or "{}")

    param_name: str = config.get("param_name", "id")
    param_type: str = config.get("param_type", "query")  # query | path
    base_value: str = config.get("base_value", "")
    collected: list[str] = config.get("collected_ids", [])
    test_no_auth: bool = config.get("test_no_auth", True)

    # All unique IDs to sweep; base first, then foreign
    all_ids: list[str] = list(dict.fromkeys([base_value] + collected)) if base_value else collected[:25]
    foreign_ids: list[str] = [i for i in all_ids if i != base_value]

    stripped = {k: v for k, v in headers.items() if k.lower() not in _AUTH_HEADERS}

    def _sub_id(url: str, val: str) -> str:
        if param_type == "query":
            p = urlparse(url)
            params = parse_qs(p.query, keep_blank_values=True)
            params[param_name] = [val]
            return urlunparse(p._replace(query=urlencode(params, doseq=True)))
        # path substitution: replace last numeric segment
        import re as _re
        return _re.sub(r"/(\d+)(?=[/?#]|$)", f"/{val}", url, count=1)

    vuln_count = 0

    # ── 1. Baseline with own ID ──
    base_url = _sub_id(test.url, base_value) if base_value else test.url
    await _emit(test_id, {"type": "progress", "message": f"Baseline: {param_name}={base_value} (authenticated)…"})
    base_resp = await _request(test.method, base_url, headers, test.body)
    await _save_result(db_factory, test_id, f"baseline_{base_value}",
        {"method": test.method, "url": base_url, "headers": headers, "body": test.body},
        base_resp, False, None, None, None)
    await _emit(test_id, {"type": "result", "label": f"baseline_{base_value}",
                          "status": base_resp["status_code"], "vulnerable": False})

    # ── 2. No-auth with own ID ──
    if test_no_auth and base_value:
        await _emit(test_id, {"type": "progress", "message": f"Unauthenticated: {param_name}={base_value}…"})
        noauth_resp = await _request(test.method, base_url, stripped, test.body)
        is_vuln = (_looks_like_data(noauth_resp["body"], noauth_resp["status_code"])
                   and _looks_like_data(base_resp["body"], base_resp["status_code"]))
        if is_vuln:
            vuln_count += 1
        await _save_result(db_factory, test_id, f"no_auth_{base_value}",
            {"method": test.method, "url": base_url, "headers": stripped, "body": test.body},
            noauth_resp, is_vuln,
            f"Unauthenticated IDOR confirmed: {param_name}={base_value} → HTTP {noauth_resp['status_code']} "
            f"({len(noauth_resp['body']):,}B without any credentials)." if is_vuln else None,
            "critical" if is_vuln else None,
            _diff_summary(base_resp["body"], noauth_resp["body"]))
        await _emit(test_id, {"type": "result", "label": f"no_auth_{base_value}",
                              "status": noauth_resp["status_code"], "vulnerable": is_vuln})

    # ── 3. Foreign IDs (cross-user) ──
    for idx, id_val in enumerate(foreign_ids[:25]):
        await _emit(test_id, {
            "type": "progress",
            "message": f"Sweeping {param_name}={id_val} ({idx + 1}/{len(foreign_ids[:25])})…",
        })
        sweep_url = _sub_id(test.url, id_val)
        sweep_resp = await _request(test.method, sweep_url, headers, test.body)

        data_in_sweep = _looks_like_data(sweep_resp["body"], sweep_resp["status_code"])
        data_in_base = _looks_like_data(base_resp["body"], base_resp["status_code"])
        is_vuln = data_in_sweep and sweep_resp["body"] != base_resp["body"] and data_in_base
        if is_vuln:
            vuln_count += 1

        await _save_result(db_factory, test_id, f"id_{id_val}",
            {"method": test.method, "url": sweep_url, "headers": headers, "body": test.body},
            sweep_resp, is_vuln,
            f"Cross-user data returned for {param_name}={id_val}: HTTP {sweep_resp['status_code']} "
            f"({len(sweep_resp['body']):,}B, different from own baseline)." if is_vuln else None,
            "high" if is_vuln else None,
            _diff_summary(base_resp["body"], sweep_resp["body"]))
        await _emit(test_id, {"type": "result", "label": f"id_{id_val}",
                              "status": sweep_resp["status_code"], "vulnerable": is_vuln})

        await asyncio.sleep(0.15)  # modest pacing to avoid triggering rate limits

    async with db_factory() as db:
        t = await db.get(ApiTest, test_id)
        if t:
            t.status = "complete"
            t.run_count = (t.run_count or 0) + 1
            t.vulnerable_count = vuln_count
            await db.commit()


async def _token_replay(test_id: int, db_factory) -> None:
    """
    Token Replay — confirm the server invalidates a session token on logout.

    Phase 1: Immediate replay → confirms token is currently valid.
    Phase 2: Post-logout replay → checks whether server accepted or rejected.

    The test pauses between phases and emits a "waiting" event so the
    frontend can prompt the user to log out before continuing.
    """
    from models.api_testing import ApiTest

    async with db_factory() as db:
        test = await db.get(ApiTest, test_id)
        headers: dict = json.loads(test.headers_json or "{}")
        config: dict = json.loads(test.config_json or "{}")

    token_header: str = config.get("token_header", "X-Tt-Token")
    token_value: str = config.get("token_value", "") or headers.get(token_header, "")
    replay_headers = {**headers, token_header: token_value}

    # ── Phase 1: immediate replay ──
    await _emit(test_id, {"type": "progress", "message": "Phase 1: Replaying token (pre-logout)…"})
    resp1 = await _request(test.method, test.url, replay_headers, test.body)
    valid1 = _looks_like_data(resp1["body"], resp1["status_code"])
    await _save_result(db_factory, test_id, "pre_logout_replay",
        {"method": test.method, "url": test.url, "headers": replay_headers, "body": test.body},
        resp1, False,
        f"Token valid pre-logout: HTTP {resp1['status_code']}." if valid1 else f"Token already rejected: HTTP {resp1['status_code']}.",
        None, None)
    await _emit(test_id, {"type": "result", "label": "pre_logout_replay",
                          "status": resp1["status_code"], "token_valid": valid1, "vulnerable": False})

    # ── Pause — signal UI to prompt user to log out ──
    await _emit(test_id, {
        "type": "waiting",
        "message": (
            "Log out of the app now. "
            "Once logout is complete, the test will automatically continue "
            "and replay the token to check for server-side invalidation."
        ),
    })
    # Give the user time to log out (15 seconds wait; they can also click Resume in the UI)
    await asyncio.sleep(15)

    # ── Phase 2: post-logout replay ──
    await _emit(test_id, {"type": "progress", "message": "Phase 2: Replaying token (post-logout)…"})
    resp2 = await _request(test.method, test.url, replay_headers, test.body)
    valid2 = _looks_like_data(resp2["body"], resp2["status_code"])
    is_vuln = valid2

    if is_vuln:
        finding = (
            f"Token remains valid after logout — no server-side invalidation detected. "
            f"Post-logout response: HTTP {resp2['status_code']} ({len(resp2['body']):,}B). "
            f"Header: {token_header}."
        )
        severity = "high"
    else:
        finding = f"Token correctly invalidated by the server after logout: HTTP {resp2['status_code']}."
        severity = None

    await _save_result(db_factory, test_id, "post_logout_replay",
        {"method": test.method, "url": test.url, "headers": replay_headers, "body": test.body},
        resp2, is_vuln, finding, severity,
        _diff_summary(resp1["body"], resp2["body"]))
    await _emit(test_id, {"type": "result", "label": "post_logout_replay",
                          "status": resp2["status_code"], "vulnerable": is_vuln, "token_valid": valid2})

    async with db_factory() as db:
        t = await db.get(ApiTest, test_id)
        if t:
            t.status = "complete"
            t.run_count = (t.run_count or 0) + 1
            t.vulnerable_count = 1 if is_vuln else 0
            await db.commit()


async def _cross_user_auth(test_id: int, db_factory) -> None:
    """
    Cross-User Auth — replay Account A's request with Account B's token.
    If Account B receives Account A's data, the endpoint has BOLA/IDOR.
    """
    from models.api_testing import ApiTest

    async with db_factory() as db:
        test = await db.get(ApiTest, test_id)
        headers: dict = json.loads(test.headers_json or "{}")
        config: dict = json.loads(test.config_json or "{}")

    account_a: dict = config.get("account_a", {})
    account_b: dict = config.get("account_b", {})

    # ── Account A (baseline) ──
    await _emit(test_id, {
        "type": "progress",
        "message": f"Baseline: {account_a.get('label', 'Account A')} (own resource)…",
    })
    resp_a = await _request(test.method, test.url, headers, test.body)
    await _save_result(db_factory, test_id, f"account_a_{account_a.get('label', 'A')}",
        {"method": test.method, "url": test.url, "headers": headers, "body": test.body},
        resp_a, False, None, None, None)
    await _emit(test_id, {"type": "result",
                          "label": f"account_a_{account_a.get('label', 'A')}",
                          "status": resp_a["status_code"], "vulnerable": False})

    # ── Account B's token substituted ──
    b_headers = dict(headers)
    b_hdr = account_b.get("header_name", "")
    b_val = account_b.get("header_value", "")
    if b_hdr and b_val:
        # Replace matching header (case-insensitive)
        for k in list(b_headers.keys()):
            if k.lower() == b_hdr.lower():
                del b_headers[k]
        b_headers[b_hdr] = b_val
    elif b_val:
        # Fallback: replace any auth header
        for k in list(b_headers.keys()):
            if k.lower() in _AUTH_HEADERS:
                b_headers[k] = b_val
                break

    await _emit(test_id, {
        "type": "progress",
        "message": f"Cross-user replay: {account_b.get('label', 'Account B')} token on Account A's resource…",
    })
    resp_b = await _request(test.method, test.url, b_headers, test.body)

    data_a = _looks_like_data(resp_a["body"], resp_a["status_code"])
    data_b = _looks_like_data(resp_b["body"], resp_b["status_code"])
    diff = _diff_summary(resp_a["body"], resp_b["body"])

    # Vulnerable: B gets meaningful data that differs from A (different user's resource)
    is_vuln = data_a and data_b and resp_b["body"] != resp_a["body"]

    if is_vuln:
        finding = (
            f"{account_b.get('label', 'Account B')} received a data response "
            f"({resp_b['status_code']}, {len(resp_b['body']):,}B) for a resource belonging to "
            f"{account_a.get('label', 'Account A')} — broken object-level authorization (BOLA/IDOR)."
        )
        severity = "high"
    elif resp_b["status_code"] in (401, 403):
        finding = f"Access correctly denied for cross-user request: HTTP {resp_b['status_code']}."
        severity = None
    else:
        finding = f"Response: HTTP {resp_b['status_code']}. Manual review recommended."
        severity = None

    await _save_result(db_factory, test_id, f"account_b_{account_b.get('label', 'B')}",
        {"method": test.method, "url": test.url, "headers": b_headers, "body": test.body},
        resp_b, is_vuln, finding, severity, diff)
    await _emit(test_id, {"type": "result",
                          "label": f"account_b_{account_b.get('label', 'B')}",
                          "status": resp_b["status_code"], "vulnerable": is_vuln})

    async with db_factory() as db:
        t = await db.get(ApiTest, test_id)
        if t:
            t.status = "complete"
            t.run_count = (t.run_count or 0) + 1
            t.vulnerable_count = 1 if is_vuln else 0
            await db.commit()
