"""
Download IPAs from the Apple App Store via ipatool.
ipatool CLI: https://github.com/majd/ipatool
Place binary in tools/ipatool[.exe] or ensure it is on PATH.

Usage requires an Apple ID with a purchase record for the app (free apps are fine).
"""
import asyncio
import shutil
from pathlib import Path

from config import settings


def _ipatool_bin() -> str:
    for candidate in [
        Path(__file__).parent.parent.parent / "tools" / "ipatool.exe",
        Path(__file__).parent.parent.parent / "tools" / "ipatool",
    ]:
        if candidate.exists():
            return str(candidate)
    found = shutil.which("ipatool")
    if found:
        return found
    raise FileNotFoundError(
        "ipatool not found. Download from https://github.com/majd/ipatool/releases "
        "and place in tools/ or add to PATH."
    )


async def download(
    bundle_id: str,
    email: str,
    password: str,
    purchase: bool = False,
) -> Path:
    """
    Download an IPA for bundle_id from the App Store.
    Returns the path to the downloaded IPA file.
    purchase=True adds --purchase flag for apps not previously bought.
    """
    out_dir = settings.uploads_dir / "appstore"
    out_dir.mkdir(parents=True, exist_ok=True)

    bin_path = _ipatool_bin()

    cmd = [
        bin_path, "download",
        "--bundle-identifier", bundle_id,
        "--email", email,
        "--password", password,
        "--output", str(out_dir / f"{bundle_id}.ipa"),
    ]
    if purchase:
        cmd.append("--purchase")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)

    if proc.returncode != 0:
        err = stderr.decode(errors="replace").strip()
        raise RuntimeError(f"ipatool exited {proc.returncode}: {err}")

    out_path = out_dir / f"{bundle_id}.ipa"
    if not out_path.exists():
        # ipatool may use a different filename
        candidates = sorted(out_dir.glob("*.ipa"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not candidates:
            raise RuntimeError("ipatool completed but no IPA found")
        out_path = candidates[0]

    return out_path
