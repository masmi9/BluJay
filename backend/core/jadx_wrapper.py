import asyncio
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

from config import settings


@dataclass
class DecompileResult:
    success: bool
    output_path: Path | None
    error: str | None


class JadxWrapper:
    def __init__(self):
        self._jadx = self._resolve_path()

    def _resolve_path(self) -> str | None:
        configured = settings.jadx_path
        if configured.exists():
            return str(configured)
        found = shutil.which("jadx")
        return found

    def available(self) -> bool:
        return self._jadx is not None

    async def decompile(
        self,
        apk_path: Path,
        output_dir: Path,
        progress_queue: asyncio.Queue | None = None,
    ) -> DecompileResult:
        if not self._jadx:
            return DecompileResult(success=False, output_path=None, error="jadx not found")

        cmd = [
            self._jadx,
            "-d", str(output_dir),
            "--show-bad-code",
            str(apk_path),
        ]

        loop = asyncio.get_event_loop()
        done_event = asyncio.Event()
        result_holder: list = []

        def _run():
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                lines: list[str] = []
                for raw in proc.stdout:
                    line = raw.decode(errors="replace").rstrip()
                    lines.append(line)
                    if progress_queue:
                        asyncio.run_coroutine_threadsafe(
                            progress_queue.put({"type": "tool_output", "tool": "jadx", "line": line}),
                            loop,
                        )
                proc.wait()
                result_holder.append((proc.returncode, lines))
            except FileNotFoundError:
                result_holder.append((-1, ["jadx binary not found"]))
            except Exception as exc:
                result_holder.append((-1, [str(exc)]))
            finally:
                loop.call_soon_threadsafe(done_event.set)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        await done_event.wait()

        returncode, lines = result_holder[0]
        if returncode != 0:
            # jadx exits non-zero on partial decompile — check if output was produced
            if output_dir.exists() and any(output_dir.iterdir()):
                return DecompileResult(success=True, output_path=output_dir, error=None)
            return DecompileResult(success=False, output_path=None, error="\n".join(lines[-20:]))
        return DecompileResult(success=True, output_path=output_dir, error=None)

    async def get_version(self) -> str | None:
        if not self._jadx:
            return None
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    [self._jadx, "--version"],
                    capture_output=True,
                    timeout=15,
                ),
            )
            return result.stdout.decode(errors="replace").strip()
        except Exception:
            return None
