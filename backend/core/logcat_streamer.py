"""
Fan-out broadcaster: one adb logcat subprocess feeds N WebSocket connections.
"""
import asyncio
from dataclasses import dataclass, field

from core import adb_manager
from schemas.adb import LogcatLine


@dataclass
class _Session:
    serial: str
    package: str | None
    stop_event: asyncio.Event = field(default_factory=asyncio.Event)
    reader_task: asyncio.Task | None = None
    subscribers: list[asyncio.Queue] = field(default_factory=list)


class LogcatStreamer:
    def __init__(self):
        self._sessions: dict[int, _Session] = {}

    async def start(self, session_id: int, serial: str, package: str | None = None) -> None:
        if session_id in self._sessions:
            return
        sess = _Session(serial=serial, package=package)
        self._sessions[session_id] = sess
        sess.reader_task = asyncio.create_task(self._reader(session_id, sess))

    async def _reader(self, session_id: int, sess: _Session) -> None:
        try:
            async for line in adb_manager.stream_logcat(sess.serial, sess.package, sess.stop_event):
                msg = line.model_dump()
                for q in list(sess.subscribers):
                    try:
                        q.put_nowait(msg)
                    except asyncio.QueueFull:
                        pass  # slow subscriber — drop
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
logcat_streamer = LogcatStreamer()
