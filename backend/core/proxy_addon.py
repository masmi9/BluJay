"""
mitmproxy addon script — executed by mitmdump subprocess.
Captures completed flows and POSTs them to the BluJay backend
so they can be persisted and fanned-out to WebSocket subscribers.
"""
import os
from datetime import datetime

import httpx
from mitmproxy import http

SESSION_ID = int(os.environ.get("BLUJAY_SESSION_ID", "0"))
BACKEND_URL = os.environ.get("BLUJAY_BACKEND_URL", "http://127.0.0.1:8000")


class BluJayCapture:
    async def response(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        resp = flow.response
        if not resp:
            return

        try:
            duration_ms = None
            if resp.timestamp_end and req.timestamp_start:
                duration_ms = round((resp.timestamp_end - req.timestamp_start) * 1000, 1)

            data = {
                "id": flow.id,
                "session_id": SESSION_ID,
                "timestamp": datetime.utcnow().isoformat(),
                "method": req.method,
                "url": req.pretty_url,
                "host": req.pretty_host,
                "path": req.path,
                "request_headers": dict(req.headers),
                "request_body": (req.content or b"").decode(errors="replace")[:4096],
                "response_status": resp.status_code,
                "response_headers": dict(resp.headers),
                "response_body": (resp.content or b"").decode(errors="replace")[:10000],
                "tls": req.scheme == "https",
                "content_type": resp.headers.get("content-type"),
                "duration_ms": duration_ms,
            }

            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{BACKEND_URL}/api/v1/proxy/internal/flow",
                    json=data,
                    timeout=5,
                )
        except Exception:
            pass


addons = [BluJayCapture()]
