import asyncio
import re
import shutil
import subprocess
from pathlib import Path
from typing import TypedDict

from config import settings


class ToolStatus(TypedDict):
    name: str
    found: bool
    path: str | None
    version: str | None
    required: bool
    install_hint: str


def _run_sync(cmd: list[str]) -> tuple[int, str, str]:
    """Blocking subprocess call — safe to use from run_in_executor."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=10,
        )
        return result.returncode, result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return -1, "", ""
    except Exception:
        return -1, "", ""


async def _run(cmd: list[str]) -> tuple[int, str, str]:
    """Async wrapper — uses run_in_executor so it works with any event loop type."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _run_sync, cmd)


def _resolve(configured: Path, fallback_name: str) -> str | None:
    if configured.exists():
        return str(configured)
    found = shutil.which(fallback_name)
    return found


async def check_java() -> ToolStatus:
    path = shutil.which(settings.java_path) or settings.java_path
    rc, _, stderr = await _run([settings.java_path, "-version"])
    version = None
    if rc == 0:
        m = re.search(r'version "([^"]+)"', stderr)
        version = m.group(1) if m else "unknown"
    return ToolStatus(
        name="Java",
        found=rc == 0,
        path=str(path),
        version=version,
        required=True,
        install_hint="Install Java 11+ JRE from https://adoptium.net",
    )


async def check_apktool() -> ToolStatus:
    jar = str(settings.apktool_jar)
    exists = Path(jar).exists()
    version = None
    if exists:
        rc, stdout, _ = await _run([settings.java_path, "-jar", jar, "--version"])
        if rc == 0:
            version = stdout.strip()
    return ToolStatus(
        name="apktool",
        found=exists,
        path=jar if exists else None,
        version=version,
        required=True,
        install_hint="Run scripts/setup_windows.ps1 or scripts/setup_linux.sh to download apktool",
    )


async def check_jadx() -> ToolStatus:
    path = _resolve(settings.jadx_path, "jadx")
    if path is None:
        return ToolStatus(
            name="jadx",
            found=False,
            path=None,
            version=None,
            required=False,
            install_hint="Run scripts/setup_windows.ps1 or scripts/setup_linux.sh to download jadx",
        )
    rc, stdout, _ = await _run([path, "--version"])
    version = stdout.strip() if rc == 0 else None
    return ToolStatus(
        name="jadx",
        found=rc == 0,
        path=path,
        version=version,
        required=False,
        install_hint="Run scripts/setup_windows.ps1 or scripts/setup_linux.sh to download jadx",
    )


async def check_adb() -> ToolStatus:
    path = _resolve(settings.adb_path, "adb")
    if path is None:
        return ToolStatus(
            name="adb",
            found=False,
            path=None,
            version=None,
            required=True,
            install_hint="Run scripts/setup_windows.ps1 or scripts/setup_linux.sh to download platform-tools",
        )
    rc, stdout, _ = await _run([path, "version"])
    version = None
    if rc == 0:
        m = re.search(r"Android Debug Bridge version (.+)", stdout)
        version = m.group(1).strip() if m else "unknown"
    return ToolStatus(
        name="adb",
        found=rc == 0,
        path=path,
        version=version,
        required=True,
        install_hint="Run scripts/setup_windows.ps1 or scripts/setup_linux.sh to download platform-tools",
    )


async def check_all() -> dict[str, ToolStatus]:
    java, apktool, jadx, adb = await asyncio.gather(
        check_java(), check_apktool(), check_jadx(), check_adb()
    )
    return {
        "java": java,
        "apktool": apktool,
        "jadx": jadx,
        "adb": adb,
    }
