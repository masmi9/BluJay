"""Infrastructure exposure probes for AI agent targets.

Each probe function is async, takes an httpx.AsyncClient and base URL,
and returns a list of finding dicts (matching AIAgentFinding fields).
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import httpx


def _base(url: str) -> str:
    """Return scheme + host + port, no trailing slash."""
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _finding(
    probe_id: str,
    category: str,
    severity: str,
    title: str,
    detail: str,
    evidence: str | None = None,
    request_payload: str | None = None,
    raw_response: str | None = None,
    confirmed: bool = True,
) -> dict:
    return {
        "probe_id": probe_id,
        "category": category,
        "severity": severity,
        "title": title,
        "detail": detail,
        "evidence": evidence,
        "request_payload": request_payload,
        "raw_response": raw_response,
        "confirmed": confirmed,
    }


async def check_agent_json_exposed(client: httpx.AsyncClient, base: str) -> list[dict]:
    findings = []
    for path in ("/.well-known/agent.json", "/agent.json"):
        try:
            r = await client.get(f"{base}{path}", timeout=8)
            if r.status_code == 200 and ("agent" in r.text.lower() or r.headers.get("content-type", "").startswith("application/json")):
                findings.append(_finding(
                    probe_id="infra-agent-json-exposed",
                    category="infra",
                    severity="critical",
                    title="Agent card publicly accessible",
                    detail=f"GET {path} returned HTTP 200 with agent metadata. Attackers can enumerate agent identity, capabilities, and endpoints without authentication.",
                    evidence=r.text[:500],
                    request_payload=f"GET {base}{path}",
                    raw_response=r.text[:1000],
                ))
                break
        except Exception:
            pass
    return findings


async def check_models_no_auth(client: httpx.AsyncClient, base: str) -> list[dict]:
    try:
        r = await client.get(f"{base}/v1/models", timeout=8, headers={"Accept": "application/json"})
        if r.status_code == 200:
            return [_finding(
                probe_id="infra-models-no-auth",
                category="infra",
                severity="high",
                title="Model listing endpoint requires no authentication",
                detail="GET /v1/models returned HTTP 200 without an Authorization header. This exposes the deployed model names and configuration.",
                evidence=r.text[:500],
                request_payload=f"GET {base}/v1/models (no Authorization header)",
                raw_response=r.text[:1000],
            )]
    except Exception:
        pass
    return []


async def check_chat_no_auth(client: httpx.AsyncClient, base: str) -> list[dict]:
    payload = '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"ping"}]}'
    try:
        r = await client.post(
            f"{base}/v1/chat/completions",
            content=payload,
            headers={"Content-Type": "application/json"},
            timeout=12,
        )
        if r.status_code == 200:
            return [_finding(
                probe_id="infra-chat-no-auth",
                category="infra",
                severity="high",
                title="Chat completions endpoint requires no authentication",
                detail="POST /v1/chat/completions succeeded (HTTP 200) without an Authorization header. Unauthenticated users can send arbitrary prompts to the agent.",
                evidence=r.text[:500],
                request_payload=payload,
                raw_response=r.text[:1000],
            )]
    except Exception:
        pass
    return []


async def check_task_no_auth(client: httpx.AsyncClient, base: str) -> list[dict]:
    payload = '{"task":"ping","params":{}}'
    for path in ("/tasks/send", "/a2a/message", "/task"):
        try:
            r = await client.post(
                f"{base}{path}",
                content=payload,
                headers={"Content-Type": "application/json"},
                timeout=8,
            )
            if r.status_code not in (401, 403, 404, 405):
                return [_finding(
                    probe_id="infra-task-no-auth",
                    category="infra",
                    severity="critical",
                    title=f"Task submission endpoint {path} requires no authentication",
                    detail=f"POST {path} returned HTTP {r.status_code} without authorization. Unauthenticated callers can submit tasks directly to the agent.",
                    evidence=r.text[:500],
                    request_payload=payload,
                    raw_response=r.text[:1000],
                )]
        except Exception:
            pass
    return []


async def check_cors_misconfigured(client: httpx.AsyncClient, base: str) -> list[dict]:
    try:
        r = await client.options(
            f"{base}/v1/chat/completions",
            headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "POST"},
            timeout=8,
        )
        acao = r.headers.get("access-control-allow-origin", "")
        if acao in ("*", "https://evil.com"):
            return [_finding(
                probe_id="infra-cors-misconfigured",
                category="infra",
                severity="medium",
                title="CORS policy allows arbitrary origins",
                detail=f"OPTIONS /v1/chat/completions with Origin: https://evil.com returned Access-Control-Allow-Origin: {acao}. Cross-origin browser requests to this agent are permitted from any domain.",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                request_payload="OPTIONS /v1/chat/completions (Origin: https://evil.com)",
                raw_response=str(dict(r.headers))[:500],
            )]
    except Exception:
        pass
    return []


async def check_missing_security_headers(client: httpx.AsyncClient, base: str) -> list[dict]:
    findings = []
    try:
        r = await client.get(f"{base}/", timeout=8)
        missing = []
        headers = {k.lower(): v for k, v in r.headers.items()}
        if "strict-transport-security" not in headers:
            missing.append("Strict-Transport-Security")
        if "content-security-policy" not in headers:
            missing.append("Content-Security-Policy")
        if "x-frame-options" not in headers:
            missing.append("X-Frame-Options")
        if "x-content-type-options" not in headers:
            missing.append("X-Content-Type-Options")
        if missing:
            findings.append(_finding(
                probe_id="infra-missing-security-headers",
                category="infra",
                severity="low",
                title="Missing HTTP security headers",
                detail=f"The following security headers are absent: {', '.join(missing)}. These headers reduce exposure to XSS, clickjacking, and MIME sniffing attacks.",
                evidence=f"Missing: {', '.join(missing)}",
                request_payload=f"GET {base}/",
                raw_response=str(dict(r.headers))[:500],
                confirmed=True,
            ))
    except Exception:
        pass
    return findings


async def check_rate_limit_absent(client: httpx.AsyncClient, base: str) -> list[dict]:
    payload = '{"model":"test","messages":[{"role":"user","content":"x"}]}'
    got_429 = False
    try:
        tasks = [
            client.post(
                f"{base}/v1/chat/completions",
                content=payload,
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            for _ in range(20)
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for resp in responses:
            if isinstance(resp, httpx.Response) and resp.status_code == 429:
                got_429 = True
                break
    except Exception:
        return []

    if not got_429:
        return [_finding(
            probe_id="infra-rate-limit-absent",
            category="infra",
            severity="medium",
            title="No rate limiting detected on chat completions endpoint",
            detail="20 concurrent requests to /v1/chat/completions received no HTTP 429 response. Without rate limiting, the endpoint is vulnerable to prompt flooding and abuse.",
            evidence="20 requests sent, 0 HTTP 429 responses received",
            request_payload="20 × POST /v1/chat/completions",
            confirmed=False,
        )]
    return []


async def check_debug_endpoints(client: httpx.AsyncClient, base: str) -> list[dict]:
    findings = []
    debug_paths = ["/debug", "/healthz", "/metrics", "/docs", "/openapi.json", "/redoc", "/swagger", "/__debug__"]
    for path in debug_paths:
        try:
            r = await client.get(f"{base}{path}", timeout=5)
            if r.status_code == 200 and len(r.text) > 20:
                findings.append(_finding(
                    probe_id="infra-debug-endpoint-exposed",
                    category="infra",
                    severity="info",
                    title=f"Debug/introspection endpoint exposed: {path}",
                    detail=f"GET {path} returned HTTP 200 with content. Exposed debug endpoints may leak internal routes, schemas, or configuration.",
                    evidence=r.text[:300],
                    request_payload=f"GET {base}{path}",
                    raw_response=r.text[:500],
                    confirmed=True,
                ))
        except Exception:
            pass
    return findings


async def run_all(target_url: str, cancelled_flag: list[bool]) -> list[dict]:
    """Run all infrastructure checks against target_url. cancelled_flag is a 1-element list used as a mutable bool."""
    base = _base(target_url)
    findings: list[dict] = []

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        probes = [
            check_agent_json_exposed(client, base),
            check_models_no_auth(client, base),
            check_chat_no_auth(client, base),
            check_task_no_auth(client, base),
            check_cors_misconfigured(client, base),
            check_missing_security_headers(client, base),
            check_rate_limit_absent(client, base),
            check_debug_endpoints(client, base),
        ]
        for probe_coro in probes:
            if cancelled_flag[0]:
                break
            try:
                results = await probe_coro
                findings.extend(results)
            except Exception:
                pass

    return findings
