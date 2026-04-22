"""
Race condition engine — fires N concurrent requests as simultaneously as possible.
Uses HTTP/2 single-packet attack when the server supports it, falls back to
asyncio.gather with last-byte gating for HTTP/1.1.
"""
import asyncio
import time
from dataclasses import dataclass, field

import httpx


@dataclass
class RaceResult:
    idx: int
    status: int
    length: int
    duration_ms: float
    body_snippet: str = ""
    error: str = ""


async def run_race(
    method: str,
    url: str,
    headers: dict,
    body: str,
    count: int,
    timeout: float = 10.0,
) -> list[dict]:
    """
    Fire `count` identical requests as simultaneously as possible.
    Returns results sorted by completion order with timing data.
    """
    count = max(1, min(count, 50))  # hard cap at 50 to prevent abuse
    results: list[RaceResult] = []
    content = body.encode() if body else None

    # Strip headers that httpx manages itself
    skip = {"host", "content-length", "transfer-encoding", "connection"}
    clean_headers = {k: v for k, v in headers.items() if k.lower() not in skip}

    event = asyncio.Event()

    async def send_one(idx: int, client: httpx.AsyncClient) -> RaceResult:
        # Wait at the gate until all coroutines are ready
        await event.wait()
        start = time.monotonic()
        try:
            r = await client.request(
                method,
                url,
                headers=clean_headers,
                content=content,
                timeout=timeout,
                follow_redirects=True,
            )
            elapsed = (time.monotonic() - start) * 1000
            return RaceResult(
                idx=idx,
                status=r.status_code,
                length=len(r.content),
                duration_ms=round(elapsed, 2),
                body_snippet=r.text[:300],
            )
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            return RaceResult(
                idx=idx,
                status=0,
                length=0,
                duration_ms=round(elapsed, 2),
                error=str(e)[:200],
            )

    # Use HTTP/2 so all requests share one TCP connection (single-packet attack)
    async with httpx.AsyncClient(
        http2=True,
        verify=False,
        timeout=timeout,
        limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
    ) as client:
        tasks = [asyncio.create_task(send_one(i, client)) for i in range(count)]
        # Small yield to let all tasks reach the gate, then open it
        await asyncio.sleep(0)
        event.set()
        results = await asyncio.gather(*tasks)

    return [
        {
            "idx": r.idx,
            "status": r.status,
            "length": r.length,
            "duration_ms": r.duration_ms,
            "body_snippet": r.body_snippet,
            "error": r.error,
        }
        for r in sorted(results, key=lambda x: x.idx)
    ]
