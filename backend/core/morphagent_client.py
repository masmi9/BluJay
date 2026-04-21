"""
Client for MobileMorphAgent's ServerSocketService (port 31415).
Uses ADB port-forwarding so the device doesn't need to be on the same Wi-Fi.

Wire protocol (same as Drozer-compatible format):
  Request:  JSON line  {"command": "<type>", "args": {...}}
  Response: JSON line  {"status": "success"|"error", "data": ..., "error": "..."}

Usage:
    async with MorphAgentClient(serial) as client:
        result = await client.run("manifest_analysis", {"package": "com.example"})
"""
import asyncio
import json
import time
import functools
import subprocess
from typing import Any

import structlog

logger = structlog.get_logger()

AGENT_PORT = 31415
CONNECT_TIMEOUT = 10.0
CMD_TIMEOUT = 60.0


def _adb_forward_sync(serial: str, local_port: int, remote_port: int) -> bool:
    """Set up ADB port forward. Blocking — run in executor."""
    try:
        result = subprocess.run(
            ["adb", "-s", serial, "forward", f"tcp:{local_port}", f"tcp:{remote_port}"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _adb_forward_remove_sync(serial: str, local_port: int) -> None:
    try:
        subprocess.run(
            ["adb", "-s", serial, "forward", "--remove", f"tcp:{local_port}"],
            capture_output=True,
            timeout=5,
        )
    except Exception:
        pass


class MorphAgentClient:
    """Async context manager that manages ADB forwarding + TCP socket to the agent."""

    def __init__(self, serial: str, local_port: int = AGENT_PORT):
        self._serial = serial
        self._local_port = local_port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def __aenter__(self):
        loop = asyncio.get_event_loop()
        ok = await loop.run_in_executor(
            None, functools.partial(_adb_forward_sync, self._serial, self._local_port, AGENT_PORT)
        )
        if not ok:
            raise RuntimeError(
                f"adb forward tcp:{self._local_port} tcp:{AGENT_PORT} failed — "
                "is the device connected and MobileMorphAgent running?"
            )

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self._local_port),
                timeout=CONNECT_TIMEOUT,
            )
        except (ConnectionRefusedError, asyncio.TimeoutError) as e:
            raise RuntimeError(
                f"Cannot connect to MobileMorphAgent on port {self._local_port}. "
                "Ensure the agent APK is installed and the service is running on the device. "
                f"({e})"
            )
        logger.info("MorphAgent connected", serial=self._serial, port=self._local_port)
        return self

    async def __aexit__(self, *_):
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        # Do NOT remove the ADB forward — leave it persistent so subsequent commands
        # and the status-check ping can reuse it without re-establishing the tunnel.

    async def run(self, command: str, args: dict | None = None, timeout: float = CMD_TIMEOUT) -> dict:
        """Send a command and return the parsed response dict."""
        if not self._writer or not self._reader:
            raise RuntimeError("Not connected")

        payload = json.dumps({"command": command, "args": args or {}}) + "\n"
        self._writer.write(payload.encode())
        await self._writer.drain()

        try:
            raw = await asyncio.wait_for(self._reader.readline(), timeout=timeout)
        except asyncio.TimeoutError:
            raise RuntimeError(f"Command '{command}' timed out after {timeout}s")

        if not raw:
            raise RuntimeError("Agent closed the connection")

        try:
            return json.loads(raw.decode(errors="replace"))
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON from agent: {e}")


# ── High-level command helpers ────────────────────────────────────────────────

SUPPORTED_COMMANDS = [
    "manifest_analysis",
    "permission_audit",
    "package_enum",
    "exploit_provider",
    "exploit_intent",
    "exploit_ipc",
    "exploit_webview",
    "shell",
    "ping",
]


async def ping_agent(serial: str) -> bool:
    """
    Returns True if the agent is reachable and can process commands.
    Sends a real 'ping' command and expects a 'pong' response — this fully
    exercises the ServerSocket → ClientHandler → handleCommand path, and avoids
    the bare connect-disconnect that consumed an accept() slot without sending data
    (causing the next real command to race against the ClientHandler reading EOF).
    """
    loop = asyncio.get_event_loop()
    ok = await loop.run_in_executor(
        None, functools.partial(_adb_forward_sync, serial, AGENT_PORT, AGENT_PORT)
    )
    if not ok:
        return False
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", AGENT_PORT),
            timeout=3.0,
        )
        payload = json.dumps({"command": "ping", "args": {}}) + "\n"
        writer.write(payload.encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.readline(), timeout=3.0)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        if raw:
            resp = json.loads(raw.decode(errors="replace"))
            return resp.get("data") == "pong" or resp.get("status") == "success"
        return False
    except Exception:
        return False


async def _try_restart_service(serial: str) -> None:
    """Attempt to restart the ServerSocketService via ADB if the connection dropped."""
    import subprocess
    package = "com.mobilemorph.agent"
    service = f"{package}/.services.ServerSocketService"
    try:
        subprocess.run(
            ["adb", "-s", serial, "shell", "am", "start-foreground-service", "-n", service],
            capture_output=True, timeout=10,
        )
        await asyncio.sleep(2)  # Give the service time to bind its ServerSocket
    except Exception:
        pass


async def run_command(
    serial: str,
    command: str,
    args: dict | None = None,
    timeout: float = CMD_TIMEOUT,
) -> dict:
    """
    One-shot helper: forward port, run command, close.
    Retries once if the agent closes the connection (e.g. service was restarted by the OS).
    Returns {"status": "success"|"error", "data": ..., "duration_ms": float}
    """
    t0 = time.monotonic()
    for attempt in range(2):
        try:
            async with MorphAgentClient(serial) as client:
                result = await client.run(command, args, timeout=timeout)
            result["duration_ms"] = (time.monotonic() - t0) * 1000
            return result
        except RuntimeError as e:
            err = str(e)
            if attempt == 0 and "closed the connection" in err:
                logger.warning("Agent closed connection — attempting service restart", serial=serial)
                await _try_restart_service(serial)
                continue
            return {
                "status": "error",
                "error": err,
                "duration_ms": (time.monotonic() - t0) * 1000,
            }
    return {"status": "error", "error": "Agent unreachable after restart attempt",
            "duration_ms": (time.monotonic() - t0) * 1000}
