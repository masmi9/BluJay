"""
Download APKs from the Google Play Store via apkeep.
apkeep binary: https://github.com/EFForg/apkeep/releases
Place in tools/apkeep[.exe] or ensure it is on PATH.

Credentials are only needed for paid/region-locked apps.
Free apps can be downloaded with --google-username / --google-password or device-only mode.
"""
import asyncio
import shutil
from pathlib import Path

from config import settings


def _apkeep_bin() -> str:
    # Check tools/ dir first, then PATH
    local = Path(__file__).parent.parent.parent / "tools" / "apkeep.exe"
    if local.exists():
        return str(local)
    local_nix = Path(__file__).parent.parent.parent / "tools" / "apkeep"
    if local_nix.exists():
        return str(local_nix)
    found = shutil.which("apkeep")
    if found:
        return found
    raise FileNotFoundError(
        "apkeep not found. Download from https://github.com/EFForg/apkeep/releases "
        "and place in tools/ or add to PATH."
    )


async def download(
    package_name: str,
    email: str | None = None,
    password: str | None = None,
) -> Path:
    """
    Download APK for package_name into uploads_dir.
    Returns path to the downloaded APK file.
    """
    out_dir = settings.uploads_dir / "playstore"
    out_dir.mkdir(parents=True, exist_ok=True)

    bin_path = _apkeep_bin()

    cmd = [bin_path, "-a", package_name, str(out_dir)]
    if email and password:
        cmd += ["-d", "google-play", "--google-username", email, "--google-password", password]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

    if proc.returncode != 0:
        raise RuntimeError(
            f"apkeep exited {proc.returncode}: {stderr.decode(errors='replace').strip()}"
        )

    # apkeep writes <package>.apk or <package>-<version>.apk
    candidates = sorted(out_dir.glob(f"{package_name}*.apk"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        raise RuntimeError(f"apkeep succeeded but no APK found in {out_dir}")

    return candidates[0]
