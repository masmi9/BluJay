"""
Manages building the MobileMorphAgent APK via Gradle.
Runs gradlew assembleDebug in a daemon thread and streams output
into an in-memory log so the frontend can poll for progress.

Handles the common case where gradle-wrapper.jar is missing from the
repo (not committed) by downloading it automatically before building.
"""
import asyncio
import shutil
import subprocess
import sys
import threading
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import structlog

logger = structlog.get_logger()

BuildStatus = Literal["idle", "building", "success", "failed"]

# gradle-wrapper.jar is a static bootstrap binary — same file regardless of
# Gradle version.  Sourced from the official Gradle GitHub release.
_WRAPPER_JAR_URL = (
    "https://raw.githubusercontent.com/gradle/gradle/v8.6.0/"
    "gradle/wrapper/gradle-wrapper.jar"
)


@dataclass
class BuildState:
    status: BuildStatus = "idle"
    log_lines: list[str] = field(default_factory=list)
    apk_path: str | None = None
    error: str | None = None


# Single global state — only one build at a time
_state = BuildState()
_lock = threading.Lock()


def get_state() -> BuildState:
    return _state


def _ensure_wrapper_jar(project_dir: Path, append) -> bool:
    """
    Check that gradle/wrapper/gradle-wrapper.jar exists.
    If missing, download it from GitHub. Returns True on success.
    """
    jar = project_dir / "gradle" / "wrapper" / "gradle-wrapper.jar"
    if jar.exists():
        return True

    append("⚠ gradle-wrapper.jar not found — downloading…")
    jar.parent.mkdir(parents=True, exist_ok=True)
    try:
        urllib.request.urlretrieve(_WRAPPER_JAR_URL, jar)
        append(f"✓ Downloaded gradle-wrapper.jar ({jar.stat().st_size // 1024} KB)")
        return True
    except Exception as exc:
        append(f"✗ Failed to download gradle-wrapper.jar: {exc}")
        append("  Tip: commit gradle/wrapper/gradle-wrapper.jar to the repo, or run")
        append("       'gradle wrapper' manually in the android_agent directory.")
        return False


def _gradlew_cmd(project_dir: Path) -> list[str]:
    """Return the correct gradlew invocation for the current platform."""
    if sys.platform == "win32":
        bat = project_dir / "gradlew.bat"
        if bat.exists():
            return [str(bat), "assembleDebug", "--no-daemon"]
        # Fallback: use cmd.exe to run the bat file
        return ["cmd", "/c", "gradlew.bat", "assembleDebug", "--no-daemon"]

    # Linux / WSL — use the shell script
    gradlew = project_dir / "gradlew"
    gradlew.chmod(0o755)  # ensure executable
    return [str(gradlew), "assembleDebug", "--no-daemon"]


def _run_build(project_dir: Path, apk_output: Path, loop: asyncio.AbstractEventLoop) -> None:
    global _state

    def _append(line: str) -> None:
        with _lock:
            _state.log_lines.append(line)
        logger.debug("gradle", line=line)

    try:
        # Step 1 — ensure wrapper jar
        if not _ensure_wrapper_jar(project_dir, _append):
            with _lock:
                _state.status = "failed"
                _state.error = "gradle-wrapper.jar missing and download failed"
            return

        # Step 2 — run the build
        cmd = _gradlew_cmd(project_dir)
        _append(f"$ {' '.join(cmd)}")

        proc = subprocess.Popen(
            cmd,
            cwd=str(project_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        for raw in proc.stdout:
            _append(raw.rstrip())
        proc.wait()

        # Find actual APK — glob the debug output dir in case the filename differs
        apk_dir = apk_output.parent
        found = sorted(apk_dir.glob("*.apk")) if apk_dir.exists() else []
        actual = found[0] if found else (apk_output if apk_output.exists() else None)

        if proc.returncode == 0 and actual:
            with _lock:
                _state.status = "success"
                _state.apk_path = str(actual)
                _state.error = None
            _append(f"✓ Build succeeded → {actual}")
        else:
            with _lock:
                _state.status = "failed"
                _state.error = f"Gradle exited with code {proc.returncode}"
            _append(f"✗ Build failed (exit {proc.returncode})")

    except Exception as exc:
        with _lock:
            _state.status = "failed"
            _state.error = str(exc)
        _append(f"✗ Exception: {exc}")


def start_build(project_dir: str, apk_output: str) -> bool:
    """
    Kick off a Gradle build in a daemon thread.
    Returns False if a build is already running.
    """
    global _state
    with _lock:
        if _state.status == "building":
            return False
        _state = BuildState(status="building")

    loop = asyncio.get_event_loop()
    t = threading.Thread(
        target=_run_build,
        args=(Path(project_dir), Path(apk_output), loop),
        daemon=True,
    )
    t.start()
    logger.info("Gradle build started", project=project_dir)
    return True
