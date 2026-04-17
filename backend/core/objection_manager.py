"""
Objection session manager.

Spawns objection as a subprocess (subprocess.Popen + reader thread) and fans
out its output to WebSocket subscribers. Uses threads instead of asyncio
subprocesses to work correctly on Windows, where asyncio.create_subprocess_exec
requires ProactorEventLoop which uvicorn does not always use.

Requires objection to be installed:
  pip install "objection==1.12.0" --no-deps
  pip install click prompt_toolkit watchdog requests packaging
"""
import asyncio
import shutil
import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime

import structlog

logger = structlog.get_logger()


def _resolve_objection() -> str | None:
    return shutil.which("objection")


@dataclass
class _ObjectionSession:
    session_id: str
    gadget: str
    process: subprocess.Popen
    loop: asyncio.AbstractEventLoop
    output_queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=2000))
    subscribers: list[asyncio.Queue] = field(default_factory=list)


class ObjectionManager:
    def __init__(self):
        self._sessions: dict[str, _ObjectionSession] = {}

    async def start(self, gadget: str, device_serial: str | None = None) -> str:
        """
        Spawn an objection explore session for the given gadget (bundle ID / package name).
        device_serial is the Frida device ID (USB UDID for iOS, ADB serial for Android).
        Returns the session_id.
        """
        obj = _resolve_objection()
        if not obj:
            raise RuntimeError(
                "objection not found — install it with: "
                "pip install objection==1.12.0 --no-deps && "
                "pip install click prompt_toolkit watchdog requests packaging"
            )

        # objection CLI flags (from objection --help):
        #   -n / --name    : bundle ID or package name to attach to
        #   -S / --serial  : device serial (uppercase S — lowercase -s means --spawn)
        #   start          : start a new interactive session
        cmd = [obj, "--name", gadget]
        if device_serial:
            cmd += ["-S", device_serial]
        cmd += ["start"]

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
        except Exception as e:
            raise RuntimeError(f"Failed to start objection: {e}")

        session_id = str(uuid.uuid4())[:8]
        loop = asyncio.get_event_loop()
        sess = _ObjectionSession(
            session_id=session_id,
            gadget=gadget,
            process=proc,
            loop=loop,
        )
        self._sessions[session_id] = sess

        # Reader thread: pushes lines into the asyncio queue from a background thread
        t = threading.Thread(
            target=self._reader_thread,
            args=(session_id, sess),
            daemon=True,
        )
        t.start()

        asyncio.create_task(self._fanout(session_id, sess))
        logger.info("Objection session started", session_id=session_id, gadget=gadget)
        return session_id

    def _reader_thread(self, session_id: str, sess: _ObjectionSession) -> None:
        """Background thread: reads stdout lines and schedules them onto the event loop."""
        try:
            for raw in sess.process.stdout:
                text = raw.decode(errors="replace")
                msg = {
                    "type": "output",
                    "data": text,
                    "ts": datetime.utcnow().timestamp(),
                }
                asyncio.run_coroutine_threadsafe(
                    sess.output_queue.put(msg), sess.loop
                )
        except Exception as e:
            logger.warning("Objection reader error", session_id=session_id, error=str(e))
        finally:
            rc = sess.process.wait()
            exit_msg = {
                "type": "exit",
                "data": f"\n[objection exited with code {rc}]\n",
                "ts": datetime.utcnow().timestamp(),
            }
            asyncio.run_coroutine_threadsafe(
                sess.output_queue.put(exit_msg), sess.loop
            )

    async def send_command(self, session_id: str, command: str) -> None:
        """Write a command line to the objection REPL stdin."""
        sess = self._sessions.get(session_id)
        if not sess or sess.process.stdin is None:
            raise RuntimeError(f"No active objection session: {session_id}")
        if sess.process.poll() is not None:
            raise RuntimeError(f"Objection session {session_id} has already exited")
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: (sess.process.stdin.write((command + "\n").encode()),
                     sess.process.stdin.flush()),
        )

    async def stop(self, session_id: str) -> None:
        sess = self._sessions.pop(session_id, None)
        if not sess:
            return
        try:
            sess.process.terminate()
            sess.process.wait(timeout=5)
        except Exception:
            try:
                sess.process.kill()
            except Exception:
                pass
        logger.info("Objection session stopped", session_id=session_id)

    def list_sessions(self) -> list[dict]:
        return [
            {
                "session_id": sid,
                "gadget": sess.gadget,
                "running": sess.process.poll() is None,
            }
            for sid, sess in self._sessions.items()
        ]

    def subscribe(self, session_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        sess = self._sessions.get(session_id)
        if sess:
            sess.subscribers.append(q)
        return q

    def unsubscribe(self, session_id: str, queue: asyncio.Queue) -> None:
        sess = self._sessions.get(session_id)
        if sess:
            try:
                sess.subscribers.remove(queue)
            except ValueError:
                pass

    async def _fanout(self, session_id: str, sess: _ObjectionSession) -> None:
        """Fan out queued messages to all WebSocket subscribers."""
        while session_id in self._sessions:
            try:
                msg = await asyncio.wait_for(sess.output_queue.get(), timeout=1.0)
                for q in list(sess.subscribers):
                    try:
                        q.put_nowait(msg)
                    except asyncio.QueueFull:
                        pass
                if msg.get("type") == "exit":
                    break
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
