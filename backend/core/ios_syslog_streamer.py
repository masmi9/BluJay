"""
Fan-out broadcaster: one idevicesyslog subprocess feeds N WebSocket connections.
Mirrors logcat_streamer.py but for iOS devices via idevicesyslog.
"""
import asyncio
import shutil
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class _Session:
    udid: str
    stop_event: asyncio.Event = field(default_factory=asyncio.Event)
    reader_task: asyncio.Task | None = None
    subscribers: list[asyncio.Queue] = field(default_factory=list)


class IosSyslogStreamer:
    def __init__(self):
        self._sessions: dict[int, _Session] = {}

    async def start(self, session_id: int, udid: str) -> None:
        if session_id in self._sessions:
            return
        sess = _Session(udid=udid)
        self._sessions[session_id] = sess
        sess.reader_task = asyncio.create_task(self._reader(session_id, sess))

    async def _reader(self, session_id: int, sess: _Session) -> None:
        tool = shutil.which("idevicesyslog") or "idevicesyslog"
        cmd = [tool, "-u", sess.udid]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            assert proc.stdout
            while not sess.stop_event.is_set():
                try:
                    raw = await asyncio.wait_for(proc.stdout.readline(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip()
                if not line:
                    continue
                msg = {"ts": datetime.utcnow().isoformat(), "message": line}
                for q in list(sess.subscribers):
                    try:
                        q.put_nowait(msg)
                    except asyncio.QueueFull:
                        pass  # slow subscriber — drop
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                proc.kill()
        except Exception:
            pass

    def subscribe(self, session_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
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
        if sess:
            sess.stop_event.set()
            if sess.reader_task:
                sess.reader_task.cancel()
                try:
                    await sess.reader_task
                except asyncio.CancelledError:
                    pass


# Global instance
ios_syslog_streamer = IosSyslogStreamer()
