"""
WebSocket security testing — connect, send payloads, detect misconfigs.
"""
import asyncio
import json
import time
from typing import Any

import httpx
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class WsTestRequest(BaseModel):
    url: str                          # ws:// or wss://
    headers: dict[str, str] = {}
    payloads: list[str] = []          # messages to send; empty = default probe set
    timeout: float = 10.0
    test_auth_strip: bool = True      # also try without auth headers


_DEFAULT_PAYLOADS = [
    '{"type":"ping"}',
    '{"action":"subscribe","channel":"admin"}',
    '{"cmd":"whoami"}',
    '{"__proto__":{"admin":true}}',
    '<script>alert(1)</script>',
    "' OR 1=1--",
    '{"id":1,"method":"system.listMethods"}',
    '{"jsonrpc":"2.0","method":"eth_accounts","id":1}',
]


async def _probe_ws(url: str, headers: dict[str, str], payloads: list[str], timeout: float) -> list[dict]:
    results = []
    try:
        import websockets
        async with websockets.connect(url, extra_headers=headers, open_timeout=timeout) as ws:
            connected = True
            for payload in payloads:
                try:
                    await asyncio.wait_for(ws.send(payload), timeout=5.0)
                    try:
                        resp = await asyncio.wait_for(ws.recv(), timeout=5.0)
                        results.append({"payload": payload, "response": str(resp)[:500], "error": None})
                    except asyncio.TimeoutError:
                        results.append({"payload": payload, "response": None, "error": "recv timeout"})
                except Exception as e:
                    results.append({"payload": payload, "response": None, "error": str(e)})
    except Exception as e:
        results.append({"payload": "__connect__", "response": None, "error": str(e)})
    return results


def _analyze_results(results: list[dict], auth_stripped: bool) -> list[dict]:
    findings = []
    errors = [r for r in results if r.get("error") and r["payload"] != "__connect__"]
    connected = not any(r["payload"] == "__connect__" and r["error"] for r in results)

    if not connected:
        return []

    if auth_stripped and connected:
        findings.append({
            "severity": "high",
            "title": "WebSocket accepts connections without authentication",
            "detail": "The WebSocket endpoint accepted a connection with no Authorization headers.",
        })

    for r in results:
        resp = r.get("response") or ""
        payload = r.get("payload", "")

        if any(x in resp.lower() for x in ["error", "exception", "traceback", "syntax", "unexpected"]):
            findings.append({
                "severity": "medium",
                "title": "Verbose error in WebSocket response",
                "detail": f"Payload `{payload[:80]}` triggered a verbose error: {resp[:200]}",
            })

        if "<script>" in payload and ("<script>" in resp or "alert" in resp):
            findings.append({
                "severity": "high",
                "title": "Possible XSS reflection in WebSocket",
                "detail": f"Script payload was reflected in response: {resp[:200]}",
            })

        if "__proto__" in payload and ("admin" in resp or "true" in resp):
            findings.append({
                "severity": "critical",
                "title": "Prototype pollution via WebSocket",
                "detail": f"Prototype pollution payload returned: {resp[:200]}",
            })

        if "eth_accounts" in payload and '"result"' in resp:
            findings.append({
                "severity": "high",
                "title": "Unauthenticated JSON-RPC endpoint (blockchain/web3)",
                "detail": "eth_accounts call succeeded without auth.",
            })

    return findings


@router.post("/test")
async def test_websocket(req: WsTestRequest):
    try:
        import websockets  # noqa: F401
    except ImportError:
        return {"error": "websockets package not installed. Run: pip install websockets"}

    payloads = req.payloads or _DEFAULT_PAYLOADS
    results_with_auth = await _probe_ws(req.url, req.headers, payloads, req.timeout)

    results_no_auth = []
    auth_stripped_connected = False
    if req.test_auth_strip and req.headers:
        no_auth_headers = {k: v for k, v in req.headers.items()
                          if k.lower() not in ("authorization", "cookie", "x-auth-token")}
        results_no_auth = await _probe_ws(req.url, no_auth_headers, payloads[:3], req.timeout)
        auth_stripped_connected = not any(
            r["payload"] == "__connect__" and r["error"] for r in results_no_auth
        )

    findings = _analyze_results(results_with_auth, auth_stripped_connected)

    return {
        "url": req.url,
        "connected": not any(r["payload"] == "__connect__" and r["error"] for r in results_with_auth),
        "probes": results_with_auth,
        "probes_no_auth": results_no_auth,
        "findings": findings,
        "finding_count": len(findings),
    }
