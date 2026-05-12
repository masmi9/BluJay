"""
HTTP Repeater — craft, send, and replay arbitrary HTTP/HTTPS requests.

Endpoints:
  POST   /repeater/send           — execute a request (optionally save to history)
  POST   /repeater/raw            — parse raw HTTP text → structured request, then send
  GET    /repeater/history        — list saved request/response pairs
  POST   /repeater/history        — manually save a pair (e.g. from proxy)
  DELETE /repeater/history/{id}   — delete one entry
  DELETE /repeater/history        — clear all history
"""

import json
import os
import re
import time
from datetime import datetime
from urllib.parse import urlparse

import httpx
import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = structlog.get_logger()
router = APIRouter()

# ── Persistence ────────────────────────────────────────────────────────────

_DATA_DIR    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
_HISTORY_FILE = os.path.join(_DATA_DIR, "repeater_history.json")

_history: list[dict] = []
_id_counter: int = 0


def _load_history() -> list[dict]:
    try:
        with open(_HISTORY_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _persist_history() -> None:
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        tmp = _HISTORY_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_history, f)
        os.replace(tmp, _HISTORY_FILE)
    except Exception as e:
        logger.warning("repeater_persist_failed", error=str(e))


_history = _load_history()
_id_counter = max((e["id"] for e in _history), default=0)


# ── Schemas ────────────────────────────────────────────────────────────────

class ReplaceRule(BaseModel):
    find: str
    replace: str
    target: str = "all"   # "url" | "headers" | "body" | "all"


class RepeaterRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str | None = None
    follow_redirects: bool = True
    verify_ssl: bool = False
    timeout: float = 30.0
    save: bool = True
    rules: list[ReplaceRule] = []


class SaveRequest(BaseModel):
    request: dict
    response: dict


# ── Match-and-replace ──────────────────────────────────────────────────────

def _apply_rules(req: RepeaterRequest) -> RepeaterRequest:
    """Apply match-and-replace rules to url, headers, and body."""
    if not req.rules:
        return req

    url     = req.url
    headers = dict(req.headers)
    body    = req.body or ""

    for rule in req.rules:
        try:
            pattern = re.compile(rule.find)
        except re.error:
            pattern = None

        def sub(text: str) -> str:
            if pattern:
                return pattern.sub(rule.replace, text)
            return text.replace(rule.find, rule.replace)

        t = rule.target
        if t in ("url", "all"):
            url = sub(url)
        if t in ("body", "all"):
            body = sub(body)
        if t in ("headers", "all"):
            headers = {k: sub(v) for k, v in headers.items()}

    return req.model_copy(update={"url": url, "headers": headers, "body": body or None})


# ── Raw HTTP parser ────────────────────────────────────────────────────────

def _parse_raw_http(raw: str, base_url: str = "") -> RepeaterRequest:
    """
    Parse a raw HTTP message (as seen in Burp) into a RepeaterRequest.
    Requires Host header or base_url to reconstruct the full URL.
    """
    lines = raw.replace("\r\n", "\n").split("\n")
    if not lines:
        raise ValueError("Empty request")

    # Request line
    parts = lines[0].strip().split(" ", 2)
    if len(parts) < 2:
        raise ValueError(f"Invalid request line: {lines[0]!r}")
    method = parts[0].upper()
    path   = parts[1]

    # Headers
    headers: dict[str, str] = {}
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, _, v = lines[i].partition(":")
            headers[k.strip()] = v.strip()
        i += 1

    # Body (everything after blank line)
    body = "\n".join(lines[i + 1:]).strip() or None

    # Reconstruct URL
    host = headers.get("Host") or headers.get("host") or ""
    if base_url:
        parsed = urlparse(base_url)
        scheme = parsed.scheme or "http"
        host   = host or parsed.netloc
    else:
        scheme = "https" if "443" in host else "http"

    url = f"{scheme}://{host}{path}" if host else path

    return RepeaterRequest(method=method, url=url, headers=headers, body=body)


# ── HTTP send ──────────────────────────────────────────────────────────────

async def _execute(req: RepeaterRequest) -> dict:
    req = _apply_rules(req)

    content = req.body.encode() if req.body else None
    t0 = time.perf_counter()

    try:
        async with httpx.AsyncClient(
            follow_redirects=req.follow_redirects,
            verify=req.verify_ssl,
            timeout=req.timeout,
        ) as client:
            resp = await client.request(
                method=req.method.upper(),
                url=req.url,
                headers=req.headers,
                content=content,
            )
    except httpx.TimeoutException:
        raise HTTPException(504, "Request timed out")
    except httpx.ConnectError as e:
        raise HTTPException(502, f"Connection failed: {e}")
    except Exception as e:
        raise HTTPException(500, f"Request error: {e}")

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

    try:
        body_text = resp.text
    except Exception:
        body_text = resp.content.decode("latin-1", errors="replace")

    response_dict = {
        "status_code": resp.status_code,
        "reason":      resp.reason_phrase,
        "headers":     dict(resp.headers),
        "body":        body_text,
        "elapsed_ms":  elapsed_ms,
        "size_bytes":  len(resp.content),
        "url":         str(resp.url),
        "redirects":   [str(r.url) for r in resp.history],
    }

    return response_dict


def _new_entry(request_dict: dict, response_dict: dict) -> dict:
    global _id_counter
    _id_counter += 1
    return {
        "id":         _id_counter,
        "saved_at":   datetime.utcnow().isoformat(),
        "request":    request_dict,
        "response":   response_dict,
    }


# ── Routes ─────────────────────────────────────────────────────────────────

@router.post("/send", summary="Send an HTTP request")
async def send_request(req: RepeaterRequest):
    response_dict = await _execute(req)

    request_dict = req.model_dump()
    entry = None
    if req.save:
        entry = _new_entry(request_dict, response_dict)
        _history.insert(0, entry)
        _persist_history()

    return {
        "id":       entry["id"] if entry else None,
        "request":  request_dict,
        "response": response_dict,
    }


@router.post("/raw", summary="Parse raw HTTP text and send")
async def send_raw(payload: dict):
    raw      = payload.get("raw", "")
    base_url = payload.get("base_url", "")
    save     = payload.get("save", True)
    rules    = [ReplaceRule(**r) for r in payload.get("rules", [])]

    try:
        req = _parse_raw_http(raw, base_url)
    except ValueError as e:
        raise HTTPException(400, str(e))

    req = req.model_copy(update={"save": save, "rules": rules})
    response_dict = await _execute(req)

    request_dict = req.model_dump()
    entry = None
    if save:
        entry = _new_entry(request_dict, response_dict)
        _history.insert(0, entry)
        _persist_history()

    return {
        "id":       entry["id"] if entry else None,
        "request":  request_dict,
        "response": response_dict,
    }


@router.get("/history", summary="List saved request/response pairs")
async def list_history():
    return [
        {
            "id":        e["id"],
            "saved_at":  e["saved_at"],
            "method":    e["request"].get("method", "GET"),
            "url":       e["request"].get("url", ""),
            "status":    e["response"].get("status_code"),
            "elapsed_ms": e["response"].get("elapsed_ms"),
            "size_bytes": e["response"].get("size_bytes"),
        }
        for e in _history
    ]


@router.get("/history/{entry_id}", summary="Get a full history entry")
async def get_history_entry(entry_id: int):
    for e in _history:
        if e["id"] == entry_id:
            return e
    raise HTTPException(404, f"Entry {entry_id} not found")


@router.post("/history", summary="Save a request/response pair (e.g. from proxy)")
async def save_history(payload: SaveRequest):
    entry = _new_entry(payload.request, payload.response)
    _history.insert(0, entry)
    _persist_history()
    return {"id": entry["id"], "saved_at": entry["saved_at"]}


@router.delete("/history/{entry_id}", summary="Delete one history entry")
async def delete_history_entry(entry_id: int):
    global _history
    before = len(_history)
    _history = [e for e in _history if e["id"] != entry_id]
    if len(_history) == before:
        raise HTTPException(404, f"Entry {entry_id} not found")
    _persist_history()
    return {"status": "deleted", "id": entry_id}


@router.delete("/history", summary="Clear all history")
async def clear_history():
    _history.clear()
    _persist_history()
    return {"status": "cleared"}
