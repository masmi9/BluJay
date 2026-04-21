"""
IPAExtractor – unpacks an IPA and runs iOS analysis tools.

Tools invoked (all optional; gracefully skipped if absent):
  - unzip          : IPA extraction (IPA is a ZIP archive)
  - otool          : Mach-O binary analysis (headers, libraries, load commands)
  - nm             : Symbol table (checks for stack canary symbols)
  - strings        : String extraction from binary
  - class-dump     : ObjC class interface extraction
  - jtool2         : Mach-O analysis (fallback/supplement to otool)
  - codesign       : Code signing info + entitlements
  - lipo           : Architecture inspection
  - plutil         : Plist conversion to JSON
"""
from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.logging_config import get_logger
from core.ipa.ipa_context import IPAContext

logger = get_logger(__name__)

# Maximum bytes to read for string extraction (10 MB)
_MAX_BINARY_SIZE = int(os.environ.get("IODS_STATIC_MAX_FILE_SIZE", str(10 * 1024 * 1024)))
_TOOL_TIMEOUT = int(os.environ.get("IODS_TOOL_TIMEOUT", "60"))


def _run_tool(args: List[str], capture: bool = True, timeout: int = _TOOL_TIMEOUT) -> Tuple[int, str, str]:
    """Run an external tool and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            args,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except FileNotFoundError:
        return -1, "", f"Tool not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", f"Tool timed out: {args[0]}"
    except Exception as e:
        return -3, "", str(e)


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


class IPAExtractor:
    """Extracts and decompiles an IPA file, populating IPAContext."""

    def __init__(self, ipa_ctx: IPAContext) -> None:
        self.ctx = ipa_ctx

    def extract(self) -> bool:
        """Full extraction pipeline. Returns True on success."""
        self.ctx.setup_workspace()
        logger.info("Extracting IPA", ipa=str(self.ctx.ipa_path))

        if not self._unzip_ipa():
            return False

        if not self._locate_app_bundle():
            return False

        self._parse_info_plist()
        self._locate_binary()
        self._extract_entitlements()
        self._run_otool()
        self._run_nm()
        self._run_strings()
        self._run_classdump()
        self._set_source_files()

        logger.info("Extraction complete", bundle_id=self.ctx.bundle_id, binary=str(self.ctx.binary_path))
        return True

    # ------------------------------------------------------------------
    # Internal steps
    # ------------------------------------------------------------------

    def _unzip_ipa(self) -> bool:
        """Unzip the IPA into the extraction directory."""
        try:
            with zipfile.ZipFile(self.ctx.ipa_path, "r") as zf:
                zf.extractall(self.ctx.extracted_dir)
            return True
        except zipfile.BadZipFile as e:
            logger.error("IPA is not a valid ZIP", error=str(e))
            return False
        except Exception as e:
            logger.error("IPA extraction failed", error=str(e))
            return False

    def _locate_app_bundle(self) -> bool:
        """Find the .app bundle inside Payload/."""
        payload_dir = self.ctx.extracted_dir / "Payload"
        if not payload_dir.exists():
            logger.error("No Payload/ directory found in IPA")
            return False
        app_bundles = list(payload_dir.glob("*.app"))
        if not app_bundles:
            logger.error("No .app bundle found in Payload/")
            return False
        self.ctx.app_bundle_dir = app_bundles[0]
        logger.info("Located app bundle", bundle=str(self.ctx.app_bundle_dir))
        return True

    def _parse_info_plist(self) -> None:
        """Parse Info.plist from the app bundle."""
        if self.ctx.app_bundle_dir is None:
            return
        plist_path = self.ctx.app_bundle_dir / "Info.plist"
        if not plist_path.exists():
            logger.warning("Info.plist not found")
            return
        try:
            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)
            self.ctx.info_plist = plist
            self.ctx.bundle_id = plist.get("CFBundleIdentifier", "")
            self.ctx.display_name = plist.get("CFBundleDisplayName") or plist.get("CFBundleName", "")
            self.ctx.bundle_version = plist.get("CFBundleVersion", "")
            self.ctx.short_version = plist.get("CFBundleShortVersionString", "")
            self.ctx.minimum_os_version = plist.get("MinimumOSVersion", "")

            # Save JSON copy for plugins to read easily
            out = self.ctx.plist_dir / "Info.plist.json"
            out.write_text(json.dumps(plist, default=str, indent=2))
        except Exception as e:
            logger.warning("Failed to parse Info.plist", error=str(e))
            # Try plutil as fallback
            self._parse_info_plist_plutil(plist_path)

    def _parse_info_plist_plutil(self, plist_path: Path) -> None:
        """Use plutil to convert binary plist to JSON."""
        rc, out, err = _run_tool(["plutil", "-convert", "json", "-o", "-", str(plist_path)])
        if rc == 0 and out:
            try:
                plist = json.loads(out)
                self.ctx.info_plist = plist
                self.ctx.bundle_id = plist.get("CFBundleIdentifier", "")
                self.ctx.display_name = plist.get("CFBundleDisplayName") or plist.get("CFBundleName", "")
                self.ctx.bundle_version = plist.get("CFBundleVersion", "")
                self.ctx.short_version = plist.get("CFBundleShortVersionString", "")
                self.ctx.minimum_os_version = plist.get("MinimumOSVersion", "")
            except json.JSONDecodeError:
                logger.warning("plutil JSON output invalid")

    def _locate_binary(self) -> None:
        """Find the main executable binary."""
        if self.ctx.app_bundle_dir is None:
            return
        exec_name = self.ctx.info_plist.get("CFBundleExecutable", self.ctx.app_bundle_dir.stem)
        candidate = self.ctx.app_bundle_dir / exec_name
        if candidate.exists():
            self.ctx.binary_path = candidate
        else:
            # Search for any Mach-O binary
            for f in self.ctx.app_bundle_dir.iterdir():
                if f.is_file() and not f.suffix:
                    self.ctx.binary_path = f
                    break

    def _extract_entitlements(self) -> None:
        """Extract entitlements using codesign."""
        if self.ctx.app_bundle_dir is None:
            return
        out_file = self.ctx.entitlements_dir / "entitlements.plist"
        rc, out, err = _run_tool([
            "codesign", "-d", "--entitlements", str(out_file),
            "--xml", str(self.ctx.app_bundle_dir)
        ])
        if rc != 0:
            rc, out, err = _run_tool([
                "codesign", "-d", "--entitlements", ":-",
                str(self.ctx.app_bundle_dir)
            ])
            if rc == 0 and out:
                out_file.write_text(out)

        # Also try jtool2
        if not out_file.exists() and _tool_available("jtool2"):
            rc2, out2, _ = _run_tool(["jtool2", "--ent", str(self.ctx.binary_path or self.ctx.app_bundle_dir)])
            if rc2 == 0 and out2:
                out_file.write_text(out2)

        # Parse entitlements plist
        if out_file.exists():
            try:
                with open(out_file, "rb") as f:
                    self.ctx.entitlements = plistlib.load(f)
            except Exception:
                try:
                    self.ctx.entitlements = plistlib.loads(out_file.read_bytes())
                except Exception:
                    pass

    def _run_otool(self) -> None:
        """Run otool for Mach-O header + library analysis."""
        if self.ctx.binary_path is None:
            return
        # Header info
        rc, out, _ = _run_tool(["otool", "-hv", str(self.ctx.binary_path)])
        if rc == 0:
            (self.ctx.otool_dir / "header.txt").write_text(out)
            self._parse_otool_header(out)

        # Load commands
        rc, out, _ = _run_tool(["otool", "-l", str(self.ctx.binary_path)])
        if rc == 0:
            (self.ctx.otool_dir / "load_commands.txt").write_text(out)

        # Linked libraries
        rc, out, _ = _run_tool(["otool", "-L", str(self.ctx.binary_path)])
        if rc == 0:
            (self.ctx.otool_dir / "libraries.txt").write_text(out)

        # Objective-C metadata
        rc, out, _ = _run_tool(["otool", "-ov", str(self.ctx.binary_path)])
        if rc == 0:
            (self.ctx.otool_dir / "objc_metadata.txt").write_text(out)

    def _parse_otool_header(self, header_text: str) -> None:
        """Extract binary security flags from otool -hv output."""
        # PIE flag
        self.ctx.has_pie = "PIE" in header_text

        # ARC: look for objc_release in load commands
        lc_file = self.ctx.otool_dir / "load_commands.txt"
        if lc_file.exists():
            lc_text = lc_file.read_text()
            self.ctx.has_arc = "_objc_release" in lc_text or "__arc_" in lc_text

        # Bitcode
        self.ctx.bitcode_enabled = "__LLVM" in header_text or "bitcode" in header_text.lower()

    def _run_nm(self) -> None:
        """Run nm for symbol table analysis (stack canary detection)."""
        if self.ctx.binary_path is None:
            return
        rc, out, _ = _run_tool(["nm", str(self.ctx.binary_path)])
        if rc == 0:
            (self.ctx.otool_dir / "symbols.txt").write_text(out)
            # Stack canary: __stack_chk_fail or __stack_chk_guard
            self.ctx.has_stack_canary = (
                "__stack_chk_fail" in out or "__stack_chk_guard" in out
            )
            # Symbols stripped check
            self.ctx.symbols_stripped = out.strip() == "" or all(
                line.endswith("(undefined)") for line in out.splitlines() if line.strip()
            )

    def _run_strings(self) -> None:
        """Extract printable strings from the binary."""
        if self.ctx.binary_path is None:
            return
        # Use system strings tool or pure Python fallback
        rc, out, _ = _run_tool(["strings", str(self.ctx.binary_path)], timeout=120)
        if rc == 0:
            (self.ctx.strings_dir / "binary_strings.txt").write_text(out)
        else:
            # Python fallback
            self._extract_strings_python()

    def _extract_strings_python(self) -> None:
        """Python-based printable string extraction (ASCII 4+ chars)."""
        if self.ctx.binary_path is None:
            return
        try:
            data = self.ctx.binary_path.read_bytes()[:_MAX_BINARY_SIZE]
            strings: List[str] = []
            current: List[int] = []
            for byte in data:
                if 0x20 <= byte < 0x7F:
                    current.append(byte)
                else:
                    if len(current) >= 4:
                        strings.append(bytes(current).decode("ascii"))
                    current = []
            if len(current) >= 4:
                strings.append(bytes(current).decode("ascii"))
            (self.ctx.strings_dir / "binary_strings.txt").write_text("\n".join(strings))
        except Exception as e:
            logger.warning("Python string extraction failed", error=str(e))

    def _run_classdump(self) -> None:
        """Run class-dump or jtool2 to extract ObjC class interfaces."""
        if self.ctx.binary_path is None:
            return
        for tool in ["class-dump", "class-dump-z", "jtool2"]:
            if not _tool_available(tool):
                continue
            if tool == "jtool2":
                args = ["jtool2", "-d", "objc", "--analyze", str(self.ctx.binary_path)]
            else:
                args = [tool, str(self.ctx.binary_path)]
            rc, out, _ = _run_tool(args, timeout=120)
            if rc == 0 and out:
                (self.ctx.classdump_dir / f"classdump_{tool}.h").write_text(out)
                break

    def _set_source_files(self) -> None:
        """Configure lazy source file loader to point at the app bundle."""
        if self.ctx.app_bundle_dir:
            self.ctx.source_files.set_base_dir(self.ctx.app_bundle_dir)
