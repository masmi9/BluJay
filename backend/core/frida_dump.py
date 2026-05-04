"""
Frida-based IPA extraction for jailbroken iOS devices.

Architecture (avoids Frida transport saturation and V8 heap exhaustion):
  Phase 1 – Frida (tiny data only):
    • Get bundlePath / execName from NSBundle — no file I/O.
    • Parse the Mach-O header *from memory* (module base already mapped by iOS)
      to locate the LC_ENCRYPTION_INFO load command.
    • If encrypted: read ONLY the encrypted segment from process memory
      (already decrypted by iOS's FairPlay engine) and write it to /tmp on
      the device as a small "patch file".  This is a device-local write that
      never crosses the host↔device Frida socket.
    • Send a single small JSON message with bundle metadata + patch location.
  Phase 2 – SSH/SFTP (bulk transfer):
    • iproxy USB tunnel → paramiko SFTP downloads the full .app bundle.
    • If a patch file exists, download it too (just the encrypted segment,
      not the whole binary), apply it to the on-disk binary on the host,
      and zero out crypt_id so downstream tools see it as decrypted.
  Phase 3 – Package:
    • Zip everything into a valid IPA (Payload/<App>.app/…).
"""
import asyncio
import functools
import random
import socket
import stat
import subprocess
import threading
import time
import zipfile
from pathlib import Path

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Frida JS — sends ONLY a small JSON object, never binary blobs
# ---------------------------------------------------------------------------

_DUMP_JS = r"""
"use strict";
(function () {
    if (!ObjC.available) {
        send({ type: 'error', message: 'ObjC runtime not available — is frida-server running?' });
        return;
    }

    var bundle     = ObjC.classes.NSBundle.mainBundle();
    var bundlePath = bundle.bundlePath().toString();
    var execPath   = bundle.executablePath().toString();
    var execName   = execPath.split('/').pop();

    var patchPath = null;
    var cryptoff  = 0;
    var cryptsize = 0;
    var patchAt   = -1;

    function tryWritePatch() {
        // Locate the module that was loaded from the app's executable
        var mod = null;
        Process.enumerateModules().forEach(function (m) {
            if (!mod && (m.name === execName || m.path === execPath)) mod = m;
        });
        if (!mod) return;

        // Read the Mach-O header directly from process memory — no file I/O
        var base    = mod.base;
        var MAGIC64 = 0xFEEDFACF;
        var is64    = (base.readU32() === MAGIC64);
        var ncmds   = base.add(16).readU32();
        var hdrSize = is64 ? 32 : 28;
        var LC_ENC  = is64 ? 0x2C : 0x21;  // LC_ENCRYPTION_INFO_64 / LC_ENCRYPTION_INFO

        var cryptid = 0;
        var off = hdrSize;
        for (var i = 0; i < ncmds; i++) {
            var cmd = base.add(off).readU32();
            var sz  = base.add(off + 4).readU32();
            if (!sz || sz > 0x40000) break;
            if (cmd === LC_ENC) {
                cryptoff  = base.add(off + 8).readU32();
                cryptsize = base.add(off + 12).readU32();
                cryptid   = base.add(off + 16).readU32();
                patchAt   = off + 16;
            }
            off += sz;
        }

        // crypt_id == 0 means "not encrypted" (or already decrypted)
        if (cryptid === 0 || patchAt < 0 || cryptsize === 0) return;

        // Read ONLY the encrypted segment from memory.
        // iOS's FairPlay engine has already decrypted it in-process,
        // so this data is the plaintext we need — no whole-file read.
        var decrypted = base.add(cryptoff).readByteArray(cryptsize);
        if (!decrypted) return;

        // Write to a temp file on the device.
        // This is a direct syscall from within the target process;
        // the bytes never cross the host↔frida-server socket.
        var tmp = '/tmp/' + execName + '_patch.bin';
        try {
            var f = new File(tmp, 'wb');
            f.write(decrypted);
            f.flush();
            f.close();
            patchPath = tmp;
        } catch (e) {
            send({ type: 'error', message: 'patch write failed: ' + e.message });
        }
    }

    tryWritePatch();

    // One small JSON message — no binary payloads
    send({
        type:      'bundle_info',
        bundlePath: bundlePath,
        execPath:   execPath,
        execName:   execName,
        patchPath:  patchPath,
        cryptoff:   cryptoff,
        cryptsize:  cryptsize,
        patchAt:    patchAt,
    });
    send({ type: 'done' });
})();
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _wait_for_port(port: int, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.25)
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def dump_ipa(udid: str, bundle_id: str, output_dir: Path) -> Path:
    """
    Pull a (decrypted) IPA from a jailbroken iOS device.

    Phase 1 – Frida  : find bundle path; if FairPlay-encrypted, write just the
                       decrypted encrypted segment (~30-80 MB) to /tmp on the
                       device.  No full binary read, no Frida message blobs.
    Phase 2 – SFTP   : iproxy USB tunnel + paramiko downloads the full .app
                       bundle and the small patch file.
    Phase 3 – Package: apply the patch on the host and zip as a valid IPA.

    Host requirements : frida-tools, paramiko, iproxy (libimobiledevice)
    Device requirements: frida-server (matching version), OpenSSH on port 22,
                         default credentials root/alpine
    """
    try:
        import frida  # noqa: F401
    except ImportError:
        raise RuntimeError("frida not installed — run: pip install frida-tools")
    try:
        import paramiko  # noqa: F401
    except ImportError:
        raise RuntimeError("paramiko not installed — run: pip install paramiko")

    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{bundle_id}_frida.ipa"

    def _run_sync() -> Path:
        try:
            return _do_dump()
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"Frida dump unexpected error: {exc}") from exc

    def _do_dump() -> Path:
        import frida
        import paramiko

        # ── Phase 1: Frida — locate bundle + write patch file ─────────────
        device = None
        mgr = frida.get_device_manager()
        try:
            device = mgr.get_device(udid, timeout=8)
        except Exception:
            pass
        if device is None:
            try:
                device = frida.get_usb_device(timeout=8)
            except Exception as exc:
                raise RuntimeError(
                    f"Cannot connect to device: {exc}. "
                    "Ensure frida-server is running on the device."
                )

        spawned = False
        pid = None
        session = None
        try:
            session = device.attach(bundle_id)
        except Exception as exc:
            msg = str(exc).lower()
            if not any(k in msg for k in ('not found', 'unable to find', 'no process', 'timeout')):
                raise RuntimeError(f"Failed to attach to {bundle_id}: {exc}")

        if session is None:
            try:
                pid = device.spawn([bundle_id])
                spawned = True
                time.sleep(2)
                session = device.attach(pid)
            except Exception as exc:
                raise RuntimeError(f"Failed to spawn/attach to {bundle_id}: {exc}")

        bundle_info: dict = {}
        errors: list[str] = []
        done_evt = threading.Event()

        def on_message(msg, data):  # noqa: ARG001
            if msg['type'] == 'error':
                errors.append(msg.get('description') or str(msg))
                done_evt.set()
                return
            if msg['type'] != 'send':
                return
            payload = msg['payload']
            t = payload.get('type')
            if t == 'bundle_info':
                bundle_info.update(payload)
            elif t == 'done':
                done_evt.set()
            elif t == 'error':
                errors.append(payload.get('message', 'unknown script error'))
                done_evt.set()

        script = session.create_script(_DUMP_JS)
        script.on('message', on_message)
        script.load()

        if spawned:
            device.resume(pid)

        # Timeout is generous because writing the patch file can take a moment
        # for large encrypted segments (up to ~80 MB) on older devices.
        finished = done_evt.wait(timeout=60)

        for fn in [script.unload, session.detach]:
            try:
                fn()
            except Exception:
                pass
        if spawned:
            try:
                device.kill(pid)
            except Exception:
                pass

        if errors:
            raise RuntimeError(f"Frida script error: {errors[0]}")
        if not finished:
            raise RuntimeError(
                "Frida timed out — the app may have crashed or frida-server "
                "was killed by jailbreak detection"
            )
        if not bundle_info or 'bundlePath' not in bundle_info:
            raise RuntimeError(
                f"No bundle info received — ensure frida-server is running "
                f"and '{bundle_id}' is installed on the device"
            )

        bundle_path = bundle_info['bundlePath']
        exec_name   = bundle_info['execName']
        patch_path  = bundle_info.get('patchPath')          # /tmp/<name>_patch.bin or None
        crypt_off   = int(bundle_info.get('cryptoff', 0))
        crypt_size  = int(bundle_info.get('cryptsize', 0))
        patch_at    = int(bundle_info.get('patchAt', -1))

        logger.info("frida_phase1_done",
                    bundle=bundle_id, bundle_path=bundle_path,
                    encrypted=bool(patch_path), patch_bytes=crypt_size)

        # ── Phase 2: SSH/SFTP via iproxy ──────────────────────────────────
        from core.ios_device_manager import _resolve_tool  # type: ignore[import]

        iproxy = _resolve_tool("iproxy")
        if not iproxy:
            raise RuntimeError(
                "iproxy not found — install libimobiledevice to enable SFTP transfer"
            )

        local_port = random.randint(49152, 65530)
        proxy_proc = subprocess.Popen(
            [iproxy, str(local_port), "22", udid],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            if not _wait_for_port(local_port, timeout=8):
                raise RuntimeError(
                    "iproxy tunnel did not open — is OpenSSH installed on the device?"
                )

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connected = False
            last_err: Exception | None = None
            for user, pw in [("root", "alpine"), ("mobile", "alpine"), ("root", "")]:
                try:
                    ssh.connect(
                        "127.0.0.1", port=local_port,
                        username=user, password=pw,
                        timeout=10, banner_timeout=12,
                        look_for_keys=False, allow_agent=False,
                    )
                    connected = True
                    break
                except Exception as e:
                    last_err = e

            if not connected:
                raise RuntimeError(
                    f"SSH auth failed ({last_err}). "
                    "The default root password on most jailbreaks is 'alpine'. "
                    "If you changed it, SSH key auth is not yet supported."
                )

            sftp = ssh.open_sftp()
            file_map: dict[str, bytes] = {}
            files_downloaded = 0

            def _sftp_walk(remote_dir: str, prefix: str) -> None:
                nonlocal files_downloaded
                try:
                    entries = sftp.listdir_attr(remote_dir)
                except Exception:
                    return
                for entry in entries:
                    rpath = remote_dir.rstrip('/') + '/' + entry.filename
                    lrel  = (prefix + '/' + entry.filename).lstrip('/')
                    if entry.st_mode and stat.S_ISDIR(entry.st_mode):
                        _sftp_walk(rpath, lrel)
                    else:
                        try:
                            with sftp.open(rpath, 'rb') as fh:
                                file_map[lrel] = fh.read()
                            files_downloaded += 1
                        except Exception:
                            pass  # sockets / special files — skip silently

            _sftp_walk(bundle_path, "")

            # Download the patch file (just the encrypted segment, not whole binary)
            patch_bytes: bytes | None = None
            if patch_path:
                try:
                    with sftp.open(patch_path, 'rb') as fh:
                        patch_bytes = fh.read()
                    try:
                        sftp.remove(patch_path)
                    except Exception:
                        pass
                    logger.info("patch_downloaded", size=len(patch_bytes or b''))
                except Exception as e:
                    logger.warning("patch_download_failed", error=str(e))

            sftp.close()
            ssh.close()

        finally:
            proxy_proc.terminate()

        logger.info("sftp_done", files=files_downloaded, bundle=bundle_id)

        if not file_map:
            raise RuntimeError(
                "No files transferred via SFTP — the bundle directory may be "
                "empty or the SSH user lacks read permission"
            )

        # ── Phase 3: Apply patch + package as IPA ─────────────────────────
        # Apply the decryption patch to the on-disk binary on the host.
        # The on-disk binary has crypt_id != 0 and the encrypted section is
        # ciphertext.  We overlay the in-memory plaintext (patch_bytes) at
        # crypt_off and zero crypt_id so tools see an unencrypted binary.
        if (patch_bytes and exec_name in file_map
                and crypt_off > 0 and crypt_size > 0 and patch_at >= 0):
            try:
                binary = bytearray(file_map[exec_name])
                binary[crypt_off : crypt_off + crypt_size] = patch_bytes[:crypt_size]
                binary[patch_at  : patch_at  + 4]         = b'\x00\x00\x00\x00'
                file_map[exec_name] = bytes(binary)
                logger.info("patch_applied", exec=exec_name,
                            crypt_off=crypt_off, crypt_size=crypt_size)
            except Exception as e:
                logger.warning("patch_apply_failed", error=str(e))

        app_dir        = bundle_path.rstrip('/').split('/')[-1]  # e.g. TikTok.app
        payload_prefix = f"Payload/{app_dir}/"

        with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            if exec_name in file_map:
                zf.writestr(payload_prefix + exec_name, file_map[exec_name])
            for rel, data in file_map.items():
                if rel == exec_name:
                    continue
                zf.writestr(payload_prefix + rel, data)

        if not out_path.exists() or out_path.stat().st_size < 512:
            raise RuntimeError("IPA packaging produced an unexpectedly small file")

        logger.info("ipa_packaged", path=str(out_path), size=out_path.stat().st_size)
        return out_path

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, functools.partial(_run_sync))
