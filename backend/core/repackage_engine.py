"""
APK repackage + resign engine.

Workflow:
  1. decode  — apktool d  (may already exist from static analysis)
  2. patch   — apply selected patches to decoded output
  3. build   — apktool b
  4. sign    — jarsigner / apksigner with generated debug keystore

Patches:
  ssl_bypass      — inject/replace network_security_config.xml to trust all CAs
  root_bypass     — comment out common root-check strings in smali
  debuggable      — set android:debuggable="true" in AndroidManifest.xml
  backup_enabled  — set android:allowBackup="true"
"""

import asyncio
import re
import shutil
import subprocess
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

import structlog

from config import settings

logger = structlog.get_logger()

# ── Network Security Config that trusts all CAs including user-installed ──────
_NSC_XML = textwrap.dedent("""\
    <?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
        <base-config cleartextTrafficPermitted="true">
            <trust-anchors>
                <certificates src="system" />
                <certificates src="user" />
            </trust-anchors>
        </base-config>
        <debug-overrides>
            <trust-anchors>
                <certificates src="system" />
                <certificates src="user" />
            </trust-anchors>
        </debug-overrides>
    </network-security-config>
""")

# Smali patterns that often gate root checks — comment them out
_ROOT_SMALI_PATTERNS = [
    (r'(const-string[^\n]*"(?:su|/su|/sbin/su|/system/bin/su|/system/xbin/su|RootBeer|rootbeer)[^\n]*)', r'# PATCHED: \1'),
    (r'(invoke-virtual \{[^}]+\}, Ljava/io/File;->exists\(\)Z\s*\n\s*move-result v\d+)', r'# PATCHED root-exists\n    const/4 v0, 0x0'),
]

# Common root-detection smali method names
_ROOT_METHOD_PATTERNS = [
    "isRooted", "checkRoot", "isDeviceRooted", "detectRoot",
    "isRootAvailable", "checkRootMethod", "checkForBinary",
]


@dataclass
class PatchOptions:
    ssl_bypass: bool = True
    root_bypass: bool = False
    debuggable: bool = True
    backup_enabled: bool = False
    custom_smali: dict[str, str] = field(default_factory=dict)  # {relative_path: smali_content}


@dataclass
class RepackageResult:
    success: bool
    output_apk: Path | None = None
    signed_apk: Path | None = None
    error: str | None = None
    patches_applied: list[str] = field(default_factory=list)


async def _run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(cwd) if cwd else None,
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def _patch_manifest_debuggable(manifest_path: Path) -> None:
    content = manifest_path.read_text(encoding="utf-8")
    if "android:debuggable" in content:
        content = re.sub(r'android:debuggable="false"', 'android:debuggable="true"', content)
    else:
        content = content.replace(
            "<application",
            '<application android:debuggable="true"',
            1,
        )
    manifest_path.write_text(content, encoding="utf-8")


def _patch_manifest_backup(manifest_path: Path) -> None:
    content = manifest_path.read_text(encoding="utf-8")
    if "android:allowBackup" in content:
        content = re.sub(r'android:allowBackup="false"', 'android:allowBackup="true"', content)
    else:
        content = content.replace(
            "<application",
            '<application android:allowBackup="true"',
            1,
        )
    manifest_path.write_text(content, encoding="utf-8")


def _patch_nsc(manifest_path: Path, decoded_dir: Path) -> None:
    content = manifest_path.read_text(encoding="utf-8")
    nsc_dir = decoded_dir / "res" / "xml"
    nsc_dir.mkdir(parents=True, exist_ok=True)
    nsc_file = nsc_dir / "network_security_config.xml"
    nsc_file.write_text(_NSC_XML, encoding="utf-8")

    nsc_ref = '@xml/network_security_config'
    if "networkSecurityConfig" in content:
        content = re.sub(r'android:networkSecurityConfig="[^"]*"', f'android:networkSecurityConfig="{nsc_ref}"', content)
    else:
        content = content.replace(
            "<application",
            f'<application android:networkSecurityConfig="{nsc_ref}"',
            1,
        )
    manifest_path.write_text(content, encoding="utf-8")


def _patch_root_bypass(decoded_dir: Path) -> int:
    smali_dirs = list(decoded_dir.glob("smali*"))
    patched = 0
    for smali_dir in smali_dirs:
        for smali_file in smali_dir.rglob("*.smali"):
            original = smali_file.read_text(encoding="utf-8", errors="replace")
            content = original
            for method in _ROOT_METHOD_PATTERNS:
                if method in content:
                    # Find the method and replace its return with const/4 0
                    content = re.sub(
                        rf'(\.method[^\n]*{method}[^\n]*\n(?:(?!\.end method)[^\n]*\n)*)',
                        lambda m: _stub_boolean_method(m.group(0)),
                        content,
                    )
            if content != original:
                smali_file.write_text(content, encoding="utf-8")
                patched += 1
    return patched


def _stub_boolean_method(method_block: str) -> str:
    lines = method_block.splitlines()
    stub_lines = []
    in_body = False
    for line in lines:
        stub_lines.append(line)
        if line.strip().startswith(".method"):
            in_body = True
            stub_lines.append("    const/4 v0, 0x0")
            stub_lines.append("    return v0")
            stub_lines.append("    # PATCHED: root-check stubbed")
        if ".end method" in line:
            break
    return "\n".join(stub_lines) + "\n"


async def _ensure_keystore(keystore_path: Path) -> bool:
    if keystore_path.exists():
        return True
    rc, _, err = await _run([
        settings.java_path, "-jar",
        # Use keytool from java home
        "keytool",
        "-genkey", "-v",
        "-keystore", str(keystore_path),
        "-alias", "blujay",
        "-keyalg", "RSA", "-keysize", "2048",
        "-validity", "10000",
        "-storepass", "blujay123",
        "-keypass", "blujay123",
        "-dname", "CN=BluJay,OU=Security,O=BluJay,L=US,S=US,C=US",
    ])
    if rc != 0:
        # Try keytool directly on PATH
        rc2, _, _ = await _run([
            "keytool",
            "-genkey", "-v",
            "-keystore", str(keystore_path),
            "-alias", "blujay",
            "-keyalg", "RSA", "-keysize", "2048",
            "-validity", "10000",
            "-storepass", "blujay123",
            "-keypass", "blujay123",
            "-dname", "CN=BluJay,OU=Security,O=BluJay,L=US,S=US,C=US",
        ])
        return rc2 == 0
    return True


async def repackage(
    analysis_id: int,
    apk_path: Path,
    existing_decoded_dir: Path | None,
    opts: PatchOptions,
) -> RepackageResult:
    ws = settings.workspace_dir.expanduser() / "repackage" / str(analysis_id)
    ws.mkdir(parents=True, exist_ok=True)

    decoded_dir = ws / "decoded"
    patches_applied: list[str] = []

    # Step 1: decode
    if existing_decoded_dir and existing_decoded_dir.exists():
        if decoded_dir.exists():
            shutil.rmtree(decoded_dir)
        shutil.copytree(existing_decoded_dir, decoded_dir)
        logger.info("repackage: using existing decoded dir", analysis_id=analysis_id)
    else:
        rc, out, err = await _run([
            settings.java_path, "-jar", str(settings.apktool_jar),
            "d", str(apk_path), "-o", str(decoded_dir), "-f", "--no-debug-info",
        ])
        if rc != 0:
            return RepackageResult(success=False, error=f"apktool decode failed: {err[-500:]}")

    manifest_path = decoded_dir / "AndroidManifest.xml"
    if not manifest_path.exists():
        return RepackageResult(success=False, error="AndroidManifest.xml not found in decoded APK")

    # Step 2: patches
    if opts.ssl_bypass:
        try:
            _patch_nsc(manifest_path, decoded_dir)
            patches_applied.append("ssl_bypass")
        except Exception as e:
            logger.warning("ssl_bypass patch failed", error=str(e))

    if opts.debuggable:
        try:
            _patch_manifest_debuggable(manifest_path)
            patches_applied.append("debuggable")
        except Exception as e:
            logger.warning("debuggable patch failed", error=str(e))

    if opts.backup_enabled:
        try:
            _patch_manifest_backup(manifest_path)
            patches_applied.append("backup_enabled")
        except Exception as e:
            logger.warning("backup_enabled patch failed", error=str(e))

    if opts.root_bypass:
        try:
            n = _patch_root_bypass(decoded_dir)
            if n:
                patches_applied.append(f"root_bypass ({n} files patched)")
        except Exception as e:
            logger.warning("root_bypass patch failed", error=str(e))

    for rel_path, content in opts.custom_smali.items():
        try:
            target = decoded_dir / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            patches_applied.append(f"custom_smali:{rel_path}")
        except Exception as e:
            logger.warning("custom_smali patch failed", path=rel_path, error=str(e))

    # Step 3: build
    built_apk = ws / "dist" / "output.apk"
    rc, out, err = await _run([
        settings.java_path, "-jar", str(settings.apktool_jar),
        "b", str(decoded_dir), "-o", str(built_apk),
    ])
    if rc != 0:
        return RepackageResult(
            success=False, error=f"apktool build failed: {err[-500:]}",
            patches_applied=patches_applied,
        )

    # Step 4: sign
    keystore_path = settings.workspace_dir.expanduser() / "blujay-debug.keystore"
    await _ensure_keystore(keystore_path)

    signed_apk = ws / "dist" / "output-signed.apk"
    rc, _, err = await _run([
        "jarsigner",
        "-verbose",
        "-sigalg", "SHA256withRSA",
        "-digestalg", "SHA-256",
        "-keystore", str(keystore_path),
        "-storepass", "blujay123",
        "-keypass", "blujay123",
        "-signedjar", str(signed_apk),
        str(built_apk),
        "blujay",
    ])
    if rc != 0:
        logger.warning("jarsigner failed, returning unsigned APK", error=err[:200])
        return RepackageResult(
            success=True,
            output_apk=built_apk,
            signed_apk=built_apk,
            error="jarsigner not found — APK is unsigned",
            patches_applied=patches_applied,
        )

    return RepackageResult(
        success=True,
        output_apk=built_apk,
        signed_apk=signed_apk,
        patches_applied=patches_applied,
    )
