"""
API Fuzzing — extracts endpoints from proxy flows / static JADX output,
then runs configurable attack types against them.
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

# Retrofit annotation regex
_RETROFIT_RE = re.compile(
    r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*"([^"]+)"\s*\)'
)

# "Interesting" response heuristics
_INTERESTING_BODY = re.compile(
    r"SQL|syntax error|exception|stack trace|ORA-|traceback|mysqli_|pg_query",
    re.IGNORECASE,
)


@dataclass
class EndpointSpec:
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: bytes | None = None
    source: str = "proxy"  # proxy | static


def extract_endpoints_from_flows(flows: list[Any]) -> list[EndpointSpec]:
    seen: set[tuple[str, str]] = set()
    specs: list[EndpointSpec] = []
    for flow in flows:
        key = (flow.method.upper(), flow.url)
        if key in seen:
            continue
        seen.add(key)
        try:
            import json
            headers = json.loads(flow.request_headers or "{}")
        except Exception:
            headers = {}
        specs.append(EndpointSpec(
            method=flow.method.upper(),
            url=flow.url,
            headers=headers,
            body=flow.request_body,
            source="proxy",
        ))
    return specs


def extract_endpoints_from_static(jadx_path: str | None, base_url: str = "") -> list[EndpointSpec]:
    if not jadx_path:
        return []
    from pathlib import Path
    specs: list[EndpointSpec] = []
    seen: set[tuple[str, str]] = set()
    jp = Path(jadx_path)
    for java_file in jp.rglob("*.java"):
        try:
            text = java_file.read_text(errors="replace")
        except OSError:
            continue
        for m in _RETROFIT_RE.finditer(text):
            method = m.group(1).upper()
            path = m.group(2)
            url = base_url.rstrip("/") + "/" + path.lstrip("/") if base_url else path
            key = (method, url)
            if key not in seen:
                seen.add(key)
                specs.append(EndpointSpec(method=method, url=url, source="static"))
    return specs


def _is_interesting(baseline_status: int, status: int, body: bytes) -> tuple[bool, str]:
    body_text = body[:4096].decode(errors="replace") if body else ""
    reasons = []
    if abs(status - baseline_status) >= 100:
        reasons.append(f"status changed {baseline_status}→{status}")
    if status >= 500:
        reasons.append(f"server error {status}")
    if _INTERESTING_BODY.search(body_text):
        reasons.append("error string in body")
    return bool(reasons), "; ".join(reasons)


async def _send(client: httpx.AsyncClient, method: str, url: str,
                headers: dict, body: bytes | None) -> tuple[int, bytes, float]:
    start = time.monotonic()
    try:
        resp = await client.request(
            method, url,
            headers=headers,
            content=body,
            follow_redirects=False,
            timeout=10,
        )
        elapsed = (time.monotonic() - start) * 1000
        return resp.status_code, resp.content, elapsed
    except Exception:
        return 0, b"", (time.monotonic() - start) * 1000


async def fuzz_idor(client: httpx.AsyncClient, spec: EndpointSpec) -> list[dict]:
    results = []
    # Replace numeric path segments with ±1 / 0 / large number
    url = spec.url
    for orig, replacement in [
        (re.search(r"/(\d+)(/|$)", url), None)
    ]:
        if not orig:
            continue
        base_num = int(orig.group(1))
        for test_id in {0, 1, base_num + 1, base_num - 1, 99999, -1}:
            test_url = url[:orig.start(1)] + str(test_id) + url[orig.end(1):]
            status, body, ms = await _send(client, spec.method, test_url, spec.headers, spec.body)
            interesting, notes = _is_interesting(200, status, body)
            results.append({
                "attack_type": "idor",
                "method": spec.method,
                "url": test_url,
                "response_status": status,
                "response_body": body[:1024].decode(errors="replace"),
                "duration_ms": ms,
                "is_interesting": interesting,
                "notes": f"IDOR test id={test_id}" + (f": {notes}" if notes else ""),
            })
    return results


async def fuzz_verb_tampering(client: httpx.AsyncClient, spec: EndpointSpec) -> list[dict]:
    results = []
    verbs = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]
    baseline_status, _, _ = await _send(client, spec.method, spec.url, spec.headers, spec.body)
    for verb in verbs:
        if verb == spec.method:
            continue
        status, body, ms = await _send(client, verb, spec.url, spec.headers, spec.body)
        interesting, notes = _is_interesting(baseline_status, status, body)
        results.append({
            "attack_type": "verb_tampering",
            "method": verb,
            "url": spec.url,
            "response_status": status,
            "response_body": body[:512].decode(errors="replace"),
            "duration_ms": ms,
            "is_interesting": interesting,
            "notes": f"Verb tamper {spec.method}→{verb}" + (f": {notes}" if notes else ""),
        })
    return results


async def fuzz_auth_bypass_headers(client: httpx.AsyncClient, spec: EndpointSpec) -> list[dict]:
    results = []
    bypass_headers = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"Authorization": "Bearer null"},
        {"Authorization": "Bearer undefined"},
    ]
    baseline_status, _, _ = await _send(client, spec.method, spec.url, spec.headers, spec.body)
    for extra in bypass_headers:
        merged = {**spec.headers, **extra}
        status, body, ms = await _send(client, spec.method, spec.url, merged, spec.body)
        interesting, notes = _is_interesting(baseline_status, status, body)
        header_desc = list(extra.keys())[0]
        results.append({
            "attack_type": "auth_bypass",
            "method": spec.method,
            "url": spec.url,
            "response_status": status,
            "response_body": body[:512].decode(errors="replace"),
            "duration_ms": ms,
            "is_interesting": interesting,
            "notes": f"Auth bypass header: {header_desc}" + (f": {notes}" if notes else ""),
        })
    return results


async def fuzz_rate_limit(client: httpx.AsyncClient, spec: EndpointSpec) -> list[dict]:
    results = []
    statuses = []
    for _ in range(50):
        status, body, ms = await _send(client, spec.method, spec.url, spec.headers, spec.body)
        statuses.append(status)
    got_429 = any(s == 429 for s in statuses)
    interesting = not got_429
    results.append({
        "attack_type": "rate_limit",
        "method": spec.method,
        "url": spec.url,
        "response_status": statuses[-1] if statuses else 0,
        "response_body": "",
        "duration_ms": 0,
        "is_interesting": interesting,
        "notes": "No rate limiting detected (50 requests, 0 x 429)" if interesting else f"Rate limited after {statuses.count(429)} requests",
    })
    return results


ATTACK_MAP = {
    "idor": fuzz_idor,
    "verb_tampering": fuzz_verb_tampering,
    "auth_bypass": fuzz_auth_bypass_headers,
    "rate_limit": fuzz_rate_limit,
}


async def run_fuzz_job(
    job_id: int,
    specs: list[EndpointSpec],
    attacks: list[str],
    db_factory,
    progress_queue: asyncio.Queue | None,
) -> None:
    from models.fuzzing import FuzzJob, FuzzResult

    def _push(msg: dict):
        if progress_queue:
            try:
                progress_queue.put_nowait(msg)
            except Exception:
                pass

    async with db_factory() as db:
        job = await db.get(FuzzJob, job_id)
        if not job:
            return
        job.status = "running"
        await db.commit()

    sem = asyncio.Semaphore(10)
    total = len(specs) * len(attacks)
    done = 0

    async with httpx.AsyncClient(verify=False) as client:
        async def _run_one(spec: EndpointSpec, attack: str):
            nonlocal done
            async with sem:
                fn = ATTACK_MAP.get(attack)
                if not fn:
                    return
                try:
                    results = await fn(client, spec)
                except Exception as exc:
                    logger.warning("fuzz attack error", attack=attack, url=spec.url, error=str(exc))
                    results = []

                async with db_factory() as db:
                    for r in results:
                        db.add(FuzzResult(job_id=job_id, **r))
                    await db.commit()

                done += 1
                _push({"type": "progress", "done": done, "total": total, "url": spec.url, "attack": attack})

        tasks = [_run_one(spec, attack) for spec in specs for attack in attacks]
        await asyncio.gather(*tasks)

    async with db_factory() as db:
        job = await db.get(FuzzJob, job_id)
        if job:
            job.status = "complete"
            await db.commit()

    _push({"type": "done", "done": done, "total": total})
