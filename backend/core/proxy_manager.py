"""
mitmproxy integration — runs mitmdump as a subprocess with a custom addon.
The addon POSTs captured flows to /api/v1/proxy/internal/flow, which persists
them and fans them out to WebSocket subscribers.
"""
import asyncio
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import structlog

logger = structlog.get_logger()

ADDON_SCRIPT = Path(__file__).parent / "proxy_addon.py"


@dataclass
class _ProxySession:
    session_id: int
    port: int
    proc: subprocess.Popen | None = None
    flow_queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    subscribers: list[asyncio.Queue] = field(default_factory=list)


class ProxyManager:
    def __init__(self, db_session_factory):
        self._factory = db_session_factory
        self._sessions: dict[int, _ProxySession] = {}

    async def start(self, session_id: int, port: int) -> None:
        if session_id in self._sessions:
            return

        from config import settings
        cert_dir = settings.mitmproxy_cert_dir

        # Find mitmdump in the same venv as the running Python
        mitmdump = Path(sys.executable).parent / "mitmdump.exe"
        if not mitmdump.exists():
            mitmdump = Path(sys.executable).parent / "mitmdump"
        if not mitmdump.exists():
            raise RuntimeError("mitmdump not found — is mitmproxy installed in this venv?")

        sess = _ProxySession(session_id=session_id, port=port)
        self._sessions[session_id] = sess

        env = {
            **os.environ,
            "BLUJAY_SESSION_ID": str(session_id),
            "BLUJAY_BACKEND_URL": "http://127.0.0.1:8000",
        }

        proc = subprocess.Popen(
            [
                str(mitmdump),
                "--listen-host", "0.0.0.0",
                "--listen-port", str(port),
                "--set", f"confdir={cert_dir}",
                "--quiet",
                "-s", str(ADDON_SCRIPT),
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        sess.proc = proc

        # Log stderr from mitmdump in the background
        asyncio.create_task(self._log_stderr(session_id, proc))
        asyncio.create_task(self._fanout(session_id, sess))

        logger.info("Proxy started", session_id=session_id, port=port, pid=proc.pid)

    async def _log_stderr(self, session_id: int, proc: subprocess.Popen) -> None:
        loop = asyncio.get_event_loop()
        while True:
            line = await loop.run_in_executor(None, proc.stderr.readline)
            if not line:
                break
            text = line.decode(errors="replace").strip()
            if text:
                logger.debug("mitmdump", session_id=session_id, msg=text)

    async def _fanout(self, session_id: int, sess: _ProxySession) -> None:
        while session_id in self._sessions:
            try:
                msg = await asyncio.wait_for(sess.flow_queue.get(), timeout=1.0)
                for q in list(sess.subscribers):
                    try:
                        q.put_nowait(msg)
                    except asyncio.QueueFull:
                        pass
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

    def push_flow(self, session_id: int, flow_data: dict) -> None:
        """Called by the internal flow endpoint to fan-out a captured flow."""
        sess = self._sessions.get(session_id)
        if sess:
            try:
                sess.flow_queue.put_nowait({"type": "flow_captured", "data": flow_data})
            except asyncio.QueueFull:
                pass

    def subscribe(self, session_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        if session_id in self._sessions:
            self._sessions[session_id].subscribers.append(q)
        return q

    def unsubscribe(self, session_id: int, queue: asyncio.Queue) -> None:
        if session_id in self._sessions:
            try:
                self._sessions[session_id].subscribers.remove(queue)
            except ValueError:
                pass

    async def stop(self, session_id: int) -> None:
        sess = self._sessions.pop(session_id, None)
        if sess and sess.proc:
            sess.proc.terminate()
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, sess.proc.wait)
            except Exception:
                pass
        logger.info("Proxy stopped", session_id=session_id)

    async def stop_all(self) -> None:
        for sid in list(self._sessions.keys()):
            await self.stop(sid)

    def get_cert_path(self) -> Path:
        from config import settings
        return settings.mitmproxy_cert_dir / "mitmproxy-ca-cert.pem"
