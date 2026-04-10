"""
Frida session and script lifecycle manager.
frida's on_message callback fires in Frida's internal thread,
so we use run_coroutine_threadsafe to dispatch back to FastAPI's event loop.
"""
import asyncio
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import structlog

logger = structlog.get_logger()

SCRIPTS_DIR = Path(__file__).parent.parent / "frida_scripts"

BUILTIN_SCRIPTS = {
    "ssl_pinning_bypass": {
        "name": "SSL Pinning Bypass",
        "filename": "ssl_pinning_bypass.js",
        "description": "Bypasses TrustManager, OkHttp CertificatePinner, and Flutter BoringSSL certificate pinning",
        "hooks": ["TrustManager", "OkHttp CertificatePinner", "BoringSSL (Flutter)"],
    },
    "root_detection_bypass": {
        "name": "Root Detection Bypass",
        "filename": "root_detection_bypass.js",
        "description": "Bypasses RootBeer, SafetyNet, and common file/binary root checks",
        "hooks": ["RootBeer", "SafetyNet", "Build.TAGS", "su/busybox file checks"],
    },
    "method_tracer": {
        "name": "Method Tracer",
        "filename": "method_tracer.js",
        "description": "Hooks all overloads of a specified class method and logs arguments and return values",
        "hooks": ["Configurable via send()"],
    },
    "crypto_hooks": {
        "name": "Crypto Hooks",
        "filename": "crypto_hooks.js",
        "description": "Hooks javax.crypto.Cipher, SecretKey, and Mac to log algorithm, keys, and plaintext/ciphertext",
        "hooks": ["javax.crypto.Cipher", "javax.crypto.Mac", "javax.crypto.SecretKeyFactory"],
    },
    # iOS scripts
    "ios_ssl_pinning_bypass": {
        "name": "iOS SSL Pinning Bypass",
        "filename": "ios_ssl_pinning_bypass.js",
        "description": "Bypasses SecTrustEvaluate, SecTrustEvaluateWithError, and NSURLSessionDelegate pinning on iOS",
        "hooks": ["SecTrustEvaluate", "SecTrustEvaluateWithError", "NSURLSessionDelegate"],
        "platform": "ios",
    },
    "ios_jailbreak_bypass": {
        "name": "iOS Jailbreak Bypass",
        "filename": "ios_jailbreak_bypass.js",
        "description": "Hides common jailbreak paths from NSFileManager and canOpenURL checks",
        "hooks": ["NSFileManager fileExistsAtPath:", "UIApplication canOpenURL:"],
        "platform": "ios",
    },
}


@dataclass
class _LoadedScript:
    script_id: str
    name: str
    frida_script: object  # frida.core.Script


@dataclass
class _FridaSession:
    db_session_id: int
    device_serial: str
    package_name: str
    frida_session: object  # frida.core.Session
    scripts: dict[str, _LoadedScript] = field(default_factory=dict)
    event_queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    subscribers: list[asyncio.Queue] = field(default_factory=list)
    loop: asyncio.AbstractEventLoop = None


class FridaManager:
    def __init__(self, db_session_factory):
        self._factory = db_session_factory
        self._sessions: dict[int, _FridaSession] = {}

    async def attach(self, db_session_id: int, device_serial: str, package_name: str) -> dict:
        import frida

        loop = asyncio.get_event_loop()
        try:
            device = frida.get_device(device_serial)
        except Exception as e:
            raise RuntimeError(f"Cannot get device {device_serial}: {e}")

        try:
            session = device.attach(package_name)
        except frida.ProcessNotFoundError:
            # App not running — spawn it
            try:
                pid = device.spawn([package_name])
                session = device.attach(pid)
                device.resume(pid)
            except Exception as e:
                raise RuntimeError(f"Cannot attach to {package_name}: {e}")

        frida_sess = _FridaSession(
            db_session_id=db_session_id,
            device_serial=device_serial,
            package_name=package_name,
            frida_session=session,
            loop=loop,
        )
        self._sessions[db_session_id] = frida_sess

        asyncio.create_task(self._fanout(db_session_id, frida_sess))
        logger.info("Frida attached", session_id=db_session_id, package=package_name)

        # Update DB
        await self._update_db_frida_attached(db_session_id, True)
        return {"status": "attached", "package": package_name}

    async def load_script(self, db_session_id: int, name: str, source: str) -> str:
        sess = self._sessions.get(db_session_id)
        if not sess:
            raise RuntimeError(f"No Frida session for {db_session_id}")

        script_id = str(uuid.uuid4())[:8]
        frida_script = sess.frida_session.create_script(source)
        frida_script.on("message", lambda msg, data: self._on_message(db_session_id, name, msg, data))
        frida_script.load()

        sess.scripts[script_id] = _LoadedScript(script_id=script_id, name=name, frida_script=frida_script)
        logger.info("Frida script loaded", session_id=db_session_id, script=name, id=script_id)
        return script_id

    async def load_builtin(self, db_session_id: int, builtin_name: str) -> str:
        meta = BUILTIN_SCRIPTS.get(builtin_name)
        if not meta:
            raise ValueError(f"Unknown builtin script: {builtin_name}")
        script_path = SCRIPTS_DIR / meta["filename"]
        if not script_path.exists():
            raise FileNotFoundError(f"Script file not found: {script_path}")
        source = script_path.read_text()
        return await self.load_script(db_session_id, meta["name"], source)

    async def unload_script(self, db_session_id: int, script_id: str) -> None:
        sess = self._sessions.get(db_session_id)
        if not sess:
            return
        loaded = sess.scripts.pop(script_id, None)
        if loaded:
            try:
                loaded.frida_script.unload()
            except Exception:
                pass

    async def detach(self, db_session_id: int) -> None:
        sess = self._sessions.pop(db_session_id, None)
        if not sess:
            return
        for loaded in sess.scripts.values():
            try:
                loaded.frida_script.unload()
            except Exception:
                pass
        try:
            sess.frida_session.detach()
        except Exception:
            pass
        await self._update_db_frida_attached(db_session_id, False)
        logger.info("Frida detached", session_id=db_session_id)

    async def detach_all(self) -> None:
        for sid in list(self._sessions.keys()):
            await self.detach(sid)

    def _on_message(self, db_session_id: int, script_name: str, message: dict, data: bytes | None) -> None:
        """Called from Frida's internal thread."""
        sess = self._sessions.get(db_session_id)
        if not sess:
            return

        msg_type = message.get("type", "unknown")
        if msg_type == "send":
            payload = message.get("payload", {})
            event_type = "send"
        elif msg_type == "error":
            payload = {"error": message.get("description", ""), "stack": message.get("stack", "")}
            event_type = "error"
        else:
            payload = message
            event_type = "log"

        event = {
            "type": "frida_event",
            "data": {
                "session_id": db_session_id,
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": event_type,
                "script_name": script_name,
                "payload": json.dumps(payload) if not isinstance(payload, str) else payload,
            },
            "ts": datetime.utcnow().timestamp(),
        }

        # Persist to DB
        asyncio.run_coroutine_threadsafe(
            self._persist_event(db_session_id, event["data"]),
            sess.loop,
        )
        # Fan-out to WebSocket queue
        asyncio.run_coroutine_threadsafe(
            sess.event_queue.put(event),
            sess.loop,
        )

    async def _persist_event(self, db_session_id: int, data: dict) -> None:
        from models.session import FridaEvent
        async with self._factory() as db:
            db.add(FridaEvent(
                session_id=db_session_id,
                event_type=data["event_type"],
                script_name=data.get("script_name"),
                payload=data["payload"],
            ))
            await db.commit()

    async def _update_db_frida_attached(self, db_session_id: int, attached: bool) -> None:
        from models.session import DynamicSession
        from sqlalchemy import select
        async with self._factory() as db:
            result = await db.execute(select(DynamicSession).where(DynamicSession.id == db_session_id))
            sess = result.scalar_one_or_none()
            if sess:
                sess.frida_attached = attached
                await db.commit()

    async def _fanout(self, db_session_id: int, sess: _FridaSession) -> None:
        while db_session_id in self._sessions:
            try:
                msg = await asyncio.wait_for(sess.event_queue.get(), timeout=1.0)
                for q in list(sess.subscribers):
                    try:
                        q.put_nowait(msg)
                    except asyncio.QueueFull:
                        pass
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

    def subscribe(self, db_session_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        if db_session_id in self._sessions:
            self._sessions[db_session_id].subscribers.append(q)
        return q

    def unsubscribe(self, db_session_id: int, queue: asyncio.Queue) -> None:
        if db_session_id in self._sessions:
            try:
                self._sessions[db_session_id].subscribers.remove(queue)
            except ValueError:
                pass
