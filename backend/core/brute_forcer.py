"""
Credential brute-force engine.
Detects login endpoints from proxy flows and attempts credentials
from a wordlist using httpx with configurable concurrency and rate limiting.
"""
from __future__ import annotations

import asyncio
import base64
import re
import time
from pathlib import Path
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_LOGIN_PATH_RE = re.compile(r"login|auth|signin|token|session", re.IGNORECASE)
_CRED_BODY_RE = re.compile(r"username|password|email|passwd|pass\b", re.IGNORECASE)
_SUCCESS_TOKEN_RE = re.compile(r"token|access_token|Set-Cookie", re.IGNORECASE)
_FAILURE_RE = re.compile(r"invalid|incorrect|failed|unauthorized|wrong|bad credentials", re.IGNORECASE)

DEFAULT_WORDLIST = Path(__file__).parent.parent / "wordlists" / "top_passwords.txt"


def detect_login_endpoints(flows: list[Any]) -> list[dict]:
    """Heuristically identify login endpoints from proxy flows."""
    candidates = []
    seen: set[str] = set()
    for flow in flows:
        if flow.method.upper() != "POST":
            continue
        if not _LOGIN_PATH_RE.search(flow.url):
            continue
        body_text = ""
        if flow.request_body:
            body_text = flow.request_body.decode(errors="replace") if isinstance(flow.request_body, bytes) else flow.request_body
        if not _CRED_BODY_RE.search(body_text):
            continue
        if flow.url in seen:
            continue
        seen.add(flow.url)

        # Detect auth type and field names
        auth_type = "form"
        import json as _json
        try:
            _json.loads(body_text)
            auth_type = "json"
        except Exception:
            pass

        username_field = "username"
        password_field = "password"
        for candidate in ("username", "email", "user", "login"):
            if candidate in body_text.lower():
                username_field = candidate
                break
        for candidate in ("password", "passwd", "pass", "secret"):
            if candidate in body_text.lower():
                password_field = candidate
                break

        try:
            import json as _j
            headers = _j.loads(flow.request_headers or "{}")
        except Exception:
            headers = {}

        candidates.append({
            "url": flow.url,
            "auth_type": auth_type,
            "username_field": username_field,
            "password_field": password_field,
            "sample_body": body_text[:500],
            "headers": headers,
        })
    return candidates


def _is_success(status: int, body: bytes, headers: dict) -> bool:
    body_text = body[:2048].decode(errors="replace")
    headers_text = " ".join(f"{k}:{v}" for k, v in headers.items())
    combined = body_text + " " + headers_text
    if status not in (200, 201, 302):
        return False
    if _FAILURE_RE.search(body_text):
        return False
    return bool(_SUCCESS_TOKEN_RE.search(combined))


async def run_brute_force_job(
    job_id: int,
    target_url: str,
    auth_type: str,
    username_field: str,
    password_field: str,
    username: str,
    wordlist_path: str,
    concurrency: int,
    rate_limit_rps: float,
    request_headers: dict,
    db_factory,
    progress_queue: asyncio.Queue | None,
) -> None:
    from models.brute_force import BruteForceJob, BruteForceAttempt

    def _push(msg: dict):
        if progress_queue:
            try:
                progress_queue.put_nowait(msg)
            except Exception:
                pass

    wl = Path(wordlist_path)
    if not wl.exists():
        async with db_factory() as db:
            job = await db.get(BruteForceJob, job_id)
            if job:
                job.status = "error"
                job.error = f"Wordlist not found: {wordlist_path}"
                await db.commit()
        return

    passwords = wl.read_text(errors="replace").splitlines()

    async with db_factory() as db:
        job = await db.get(BruteForceJob, job_id)
        if not job:
            return
        job.status = "running"
        await db.commit()

    sem = asyncio.Semaphore(concurrency)
    delay = 1.0 / rate_limit_rps if rate_limit_rps > 0 else 0
    attempts_made = 0
    found_credentials: list[dict] = []

    async def _try_password(client: httpx.AsyncClient, password: str) -> bool:
        nonlocal attempts_made
        async with sem:
            # Rate limit
            if delay > 0:
                await asyncio.sleep(delay)

            # Check pause/stop
            async with db_factory() as db:
                job = await db.get(BruteForceJob, job_id)
                if not job or job.status in ("paused", "stopped"):
                    return True  # signal stop

            if auth_type == "json":
                import json as _j
                body = _j.dumps({username_field: username, password_field: password}).encode()
                hdrs = {**request_headers, "Content-Type": "application/json"}
            elif auth_type == "basic":
                token = base64.b64encode(f"{username}:{password}".encode()).decode()
                hdrs = {**request_headers, "Authorization": f"Basic {token}"}
                body = b""
            else:  # form
                from urllib.parse import urlencode
                body = urlencode({username_field: username, password_field: password}).encode()
                hdrs = {**request_headers, "Content-Type": "application/x-www-form-urlencoded"}

            try:
                resp = await client.post(target_url, content=body, headers=hdrs,
                                         follow_redirects=False, timeout=10)
                status = resp.status_code
                resp_body = resp.content
                resp_headers = dict(resp.headers)
            except Exception:
                status = 0
                resp_body = b""
                resp_headers = {}

            success = _is_success(status, resp_body, resp_headers)
            attempts_made += 1

            async with db_factory() as db:
                db.add(BruteForceAttempt(
                    job_id=job_id,
                    username=username,
                    password=password,
                    status_code=status,
                    success=success,
                ))
                if attempts_made % 100 == 0:
                    job = await db.get(BruteForceJob, job_id)
                    if job:
                        job.attempts_made = attempts_made
                await db.commit()

            _push({"type": "progress", "attempts": attempts_made, "total": len(passwords), "password": password})

            if success:
                found_credentials.append({"username": username, "password": password})
                _push({"type": "found", "username": username, "password": password})
                return True  # stop after first find
            return False

    async with httpx.AsyncClient(verify=False) as client:
        for password in passwords:
            password = password.strip()
            if not password:
                continue
            stop = await _try_password(client, password)
            if stop and found_credentials:
                break

    import json as _j
    async with db_factory() as db:
        job = await db.get(BruteForceJob, job_id)
        if job:
            job.status = "complete"
            job.attempts_made = attempts_made
            job.credentials_found = _j.dumps(found_credentials)
            await db.commit()

    _push({"type": "done", "attempts": attempts_made, "found": len(found_credentials)})
