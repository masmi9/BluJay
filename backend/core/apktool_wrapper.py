import asyncio
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


class ApktoolWrapper:
    def __init__(self):
        self._jar = str(settings.apktool_jar)
        self._java = settings.java_path

    async def decompile(
        self,
        apk_path: Path,
        output_dir: Path,
        progress_queue: asyncio.Queue | None = None,
    ) -> DecompileResult:
        cmd = [
            self._java, "-jar", self._jar,
            "d", str(apk_path),
            "-o", str(output_dir),
            "-f",  # force overwrite
            "--no-debug-info",
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
                            progress_queue.put({"type": "tool_output", "tool": "apktool", "line": line}),
                            loop,
                        )
                proc.wait()
                result_holder.append((proc.returncode, lines))
            except FileNotFoundError:
                result_holder.append((-1, ["Java not found — check your java_path setting"]))
            except Exception as exc:
                result_holder.append((-1, [str(exc)]))
            finally:
                loop.call_soon_threadsafe(done_event.set)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        await done_event.wait()

        returncode, lines = result_holder[0]
        if returncode != 0:
            return DecompileResult(success=False, output_path=None, error="\n".join(lines[-20:]))
        return DecompileResult(success=True, output_path=output_dir, error=None)

    async def get_version(self) -> str | None:
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    [self._java, "-jar", self._jar, "--version"],
                    capture_output=True,
                    timeout=15,
                ),
            )
            return result.stdout.decode(errors="replace").strip()
        except Exception:
            return None
