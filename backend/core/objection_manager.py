"""
Objection session manager.

Uses `objection run <command>` (non-interactive) instead of the REPL to avoid
prompt_toolkit's NoConsoleScreenBufferError on Windows when spawned as a
headless subprocess. Each command spawns a fresh objection process; the
session just persists the connection config (host, gadget, serial, spawn flag).

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


def _build_base_cmd(obj: str, gadget: str, host: str | None, device_serial: str | None, spawn: bool) -> list[str]:
    """Build the objection CLI prefix (everything before the subcommand)."""
    cmd = [obj]
    if host:
        cmd += ["-N", "-h", host]
    cmd += ["-n", gadget]
    if device_serial and not host:
        cmd += ["-S", device_serial]
    if spawn:
        cmd += ["-s", "-p"]
    return cmd


@dataclass
class _ObjectionSession:
    session_id: str
    gadget: str
    host: str | None
    device_serial: str | None
    spawn: bool
    loop: asyncio.AbstractEventLoop
    output_queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=2000))
    subscribers: list[asyncio.Queue] = field(default_factory=list)


class ObjectionManager:
    def __init__(self):
        self._sessions: dict[str, _ObjectionSession] = {}

    async def start(
        self,
        gadget: str,
        device_serial: str | None = None,
        host: str | None = None,
        spawn: bool = False,
    ) -> str:
        """
        Create an objection session — stores connection config only.
        No subprocess is spawned until a command is sent.

        host enables network mode (-N -h <host>) instead of USB.
        spawn=True adds -s -p to each command invocation.
        """
        obj = _resolve_objection()
        if not obj:
            raise RuntimeError(
                "objection not found — install it with: "
                "pip install objection==1.12.0 --no-deps && "
                "pip install click prompt_toolkit watchdog requests packaging"
            )

        session_id = str(uuid.uuid4())[:8]
        loop = asyncio.get_event_loop()
        sess = _ObjectionSession(
            session_id=session_id,
            gadget=gadget,
            host=host,
            device_serial=device_serial,
            spawn=spawn,
            loop=loop,
        )
        self._sessions[session_id] = sess
        asyncio.create_task(self._fanout(session_id, sess))
        logger.info("Objection session created", session_id=session_id, gadget=gadget, host=host, spawn=spawn)
        return session_id

    async def send_command(self, session_id: str, command: str) -> None:
        """
        Run a single objection command via `objection run <command>`.
        Spawns a fresh process, streams its output, then exits.
        """
        sess = self._sessions.get(session_id)
        if not sess:
            raise RuntimeError(f"No active objection session: {session_id}")

        obj = _resolve_objection()
        if not obj:
            raise RuntimeError("objection not found on PATH")

        # Never pass spawn flags to `run` — spawn relaunches the app on every command
        cmd = _build_base_cmd(obj, sess.gadget, sess.host, sess.device_serial, spawn=False)
        cmd += ["run", command]

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
        except Exception as e:
            raise RuntimeError(f"Failed to run objection command: {e}")

        t = threading.Thread(
            target=self._run_reader_thread,
            args=(session_id, sess, proc, command),
            daemon=True,
        )
        t.start()

    def _run_reader_thread(
        self,
        session_id: str,
        sess: _ObjectionSession,
        proc: subprocess.Popen,
        command: str,
    ) -> None:
        """Stream output from a single `objection run` process into the session queue."""
        try:
            for raw in proc.stdout:
                text = raw.decode(errors="replace")
                msg = {"type": "output", "data": text, "ts": datetime.utcnow().timestamp()}
                asyncio.run_coroutine_threadsafe(sess.output_queue.put(msg), sess.loop)
        except Exception as e:
            logger.warning("Objection run reader error", session_id=session_id, error=str(e))
        finally:
            rc = proc.wait()
            done_msg = {
                "type": "output",
                "data": f"\n[command finished (exit {rc})]\n",
                "ts": datetime.utcnow().timestamp(),
            }
            asyncio.run_coroutine_threadsafe(sess.output_queue.put(done_msg), sess.loop)

    async def stop(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        logger.info("Objection session stopped", session_id=session_id)

    def list_sessions(self) -> list[dict]:
        return [
            {
                "session_id": sid,
                "gadget": sess.gadget,
                "running": True,
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
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
