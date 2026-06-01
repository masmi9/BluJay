"""
Locust — WebSocket Connection Load Test
Scenario: concurrent WebSocket connections sending/receiving messages.
Measures connection establishment latency, message round-trip time,
and server stability under simultaneous long-lived connections.

Requires websocket-client (installed automatically by the BluJay Locust runner).

Env vars:
  TARGET_URL       used to derive WS_URL if not set explicitly (required)
  WS_URL           full WebSocket URL — overrides TARGET_URL derivation
  AUTH_TOKEN       Bearer token to send in Upgrade headers (optional)
  MESSAGE_PAYLOAD  JSON string to send each tick (default {"type":"ping"})
  RECV_TIMEOUT     seconds to wait for a reply before timing out (default 5)
"""
import os
import time
from urllib.parse import urlparse

from locust import User, between, events, task

TARGET_URL   = os.getenv("TARGET_URL", "ws://localhost:8000/ws/test")
_ws_url_raw  = os.getenv("WS_URL", "")
AUTH_TOKEN   = os.getenv("AUTH_TOKEN", "")
MSG_PAYLOAD  = os.getenv("MESSAGE_PAYLOAD", '{"type":"ping"}')
RECV_TIMEOUT = float(os.getenv("RECV_TIMEOUT", "5"))

# Derive WS URL from TARGET_URL if WS_URL not explicitly set
if _ws_url_raw:
    WS_URL = _ws_url_raw
else:
    _p = urlparse(TARGET_URL)
    _scheme = "wss" if _p.scheme == "https" else "ws"
    WS_URL = f"{_scheme}://{_p.netloc}{_p.path}"


def _fire(name: str, elapsed_ms: float, length: int, exc=None):
    events.request.fire(
        request_type="WS",
        name=name,
        response_time=elapsed_ms,
        response_length=length,
        exception=exc,
        context={},
    )


class WebSocketUser(User):
    wait_time = between(0.8, 2)
    _ws = None

    def on_start(self):
        self._connect()

    def _connect(self):
        import websocket as ws_lib  # installed by runner for this scenario

        t0 = time.perf_counter()
        try:
            extra_headers = {}
            if AUTH_TOKEN:
                extra_headers["Authorization"] = f"Bearer {AUTH_TOKEN}"
            sock = ws_lib.WebSocket()
            sock.connect(WS_URL, header=extra_headers)
            self._ws = sock
            _fire("connect", (time.perf_counter() - t0) * 1000, 0)
        except Exception as exc:
            _fire("connect", (time.perf_counter() - t0) * 1000, 0, exc)
            self._ws = None

    @task
    def send_and_recv(self):
        if self._ws is None:
            self._connect()
            if self._ws is None:
                return

        t0 = time.perf_counter()
        try:
            self._ws.send(MSG_PAYLOAD)
            self._ws.settimeout(RECV_TIMEOUT)
            reply = self._ws.recv()
            _fire("send/recv", (time.perf_counter() - t0) * 1000, len(reply) if reply else 0)
        except Exception as exc:
            _fire("send/recv", (time.perf_counter() - t0) * 1000, 0, exc)
            try:
                self._ws.close()
            except Exception:
                pass
            self._ws = None

    def on_stop(self):
        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass
            self._ws = None
