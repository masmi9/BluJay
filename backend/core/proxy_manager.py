"""
mitmproxy integration using the Python library (addon pattern).
Captures flows, persists to DB, fans out to WebSocket subscribers.
"""
import asyncio
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime

import structlog
from mitmproxy import http, options
from mitmproxy.tools import dump

logger = structlog.get_logger()


@dataclass
class _ProxySession:
    session_id: int
    port: int
    master: "dump.DumpMaster | None" = None
    thread: threading.Thread | None = None
    flow_queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    subscribers: list[asyncio.Queue] = field(default_factory=list)
    loop: asyncio.AbstractEventLoop | None = None


class FlowCaptureAddon:
    def __init__(self, session_id: int, db_session_factory, flow_queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
        self._session_id = session_id
        self._factory = db_session_factory
        self._queue = flow_queue
        self._loop = loop

    def response(self, flow: http.HTTPFlow) -> None:
        """Called by mitmproxy when a full request+response is captured."""
        import json as _json
        from models.session import ProxyFlow

        req = flow.request
        resp = flow.response

        duration_ms = None
        if flow.request.timestamp_end and flow.request.timestamp_start:
            duration_ms = (flow.response.timestamp_end - flow.request.timestamp_start) * 1000 if resp else None

        pf_data = {
            "id": flow.id,
            "session_id": self._session_id,
            "timestamp": datetime.utcnow(),
            "method": req.method,
            "url": req.pretty_url,
            "host": req.pretty_host,
            "path": req.path,
            "request_headers": _json.dumps(dict(req.headers)),
            "request_body": req.content or b"",
            "response_status": resp.status_code if resp else None,
            "response_headers": _json.dumps(dict(resp.headers)) if resp else None,
            "response_body": resp.content if resp else None,
            "tls": req.scheme == "https",
            "content_type": (resp.headers.get("content-type") if resp else None),
            "duration_ms": duration_ms,
        }

        # DB write (synchronous — runs in mitmproxy's thread)
        try:
            import sqlalchemy
            from sqlalchemy.orm import Session
            from sqlalchemy import create_engine
            from config import settings

            # Use synchronous SQLite connection for thread safety
            engine = create_engine(f"sqlite:///{settings.db_path}", connect_args={"check_same_thread": False})
            with Session(engine) as db_sync:
                db_sync.add(ProxyFlow(**pf_data))
                db_sync.commit()
        except Exception as e:
            logger.error("Failed to persist flow", error=str(e))

        # Fan-out to WebSocket subscribers (cross-thread)
        summary = {k: v for k, v in pf_data.items() if k not in ("request_body", "response_body", "request_headers", "response_headers")}
        summary["request_headers"] = pf_data["request_headers"]
        summary["response_headers"] = pf_data["response_headers"]
        summary["timestamp"] = pf_data["timestamp"].isoformat()

        asyncio.run_coroutine_threadsafe(
            self._queue.put({"type": "flow_captured", "data": summary, "ts": datetime.utcnow().timestamp()}),
            self._loop,
        )


class ProxyManager:
    def __init__(self, db_session_factory):
        self._factory = db_session_factory
        self._sessions: dict[int, _ProxySession] = {}

    async def start(self, session_id: int, port: int) -> None:
        """
        Start a proxy instance for session_id on port.
        session_id=0 is the "standalone" mode (no DynamicSession required).
        """
        if session_id in self._sessions:
            return

        loop = asyncio.get_event_loop()
        sess = _ProxySession(session_id=session_id, port=port, loop=loop)
        self._sessions[session_id] = sess

        from config import settings
        cert_dir = settings.mitmproxy_cert_dir

        addon = FlowCaptureAddon(session_id, self._factory, sess.flow_queue, loop)

        def _run_proxy():
            import asyncio as _asyncio
            proxy_loop = _asyncio.new_event_loop()
            _asyncio.set_event_loop(proxy_loop)

            # DumpMaster.__init__ calls asyncio.get_running_loop() internally,
            # so it must be constructed inside a coroutine running on the loop.
            async def _run():
                opts = options.Options(
                    listen_host="0.0.0.0",
                    listen_port=port,
                    ssl_insecure=False,
                    confdir=str(cert_dir),
                )
                master = dump.DumpMaster(opts, with_termlog=False, with_dumper=False)
                master.addons.add(addon)
                sess.master = master
                await master.run()

            try:
                proxy_loop.run_until_complete(_run())
            except Exception:
                pass
            finally:
                proxy_loop.close()

        t = threading.Thread(target=_run_proxy, daemon=True, name=f"proxy-{session_id}")
        sess.thread = t
        t.start()

        # Start fan-out task
        asyncio.create_task(self._fanout(session_id, sess))
        logger.info("Proxy started", session_id=session_id, port=port)

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
        if sess and sess.master:
            sess.master.shutdown()
        logger.info("Proxy stopped", session_id=session_id)

    async def stop_all(self) -> None:
        for sid in list(self._sessions.keys()):
            await self.stop(sid)

    def get_cert_path(self):
        from config import settings
        return settings.mitmproxy_cert_dir / "mitmproxy-ca-cert.pem"
