"""
core.native_decompiler.ghidra_bridge - Ghidra headless decompilation bridge.

Wraps Ghidra's analyzeHeadless CLI to decompile native .so binaries into
pseudo-C functions. Each function can then be scored by the C/C++ ML
vulnerability detection model.

Requirements:
- Java 11+ (21 recommended)
- Ghidra 10.x or 11.x installation
- AODS_GHIDRA_PATH environment variable pointing to Ghidra install dir,
  or analyzeHeadless on PATH

Graceful degradation: when Ghidra is not available, is_available() returns
False and decompile() returns empty results. The native binary plugin falls
back to string/symbol analysis.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)


@dataclass
class DecompiledFunction:
    """A single decompiled function from a native binary."""
    name: str
    code: str  # Pseudo-C source
    address: str = ""  # Hex address in binary
    size: int = 0  # Function size in bytes
    source_binary: str = ""  # Original .so file name


@dataclass
class DecompilationResult:
    """Result of decompiling a native binary."""
    binary_path: str
    functions: List[DecompiledFunction] = field(default_factory=list)
    architecture: str = ""
    elapsed_seconds: float = 0.0
    error: Optional[str] = None
    ghidra_available: bool = False


class GhidraBridge:
    """Bridge to Ghidra headless decompilation.

    Manages Ghidra project lifecycle, runs analyzeHeadless, and parses
    decompiled output. Thread-safe for concurrent use.

    Args:
        ghidra_path: Path to Ghidra installation directory.
            Falls back to AODS_GHIDRA_PATH env var, then PATH search.
        timeout: Maximum seconds for decompilation per binary.
    """

    def __init__(
        self,
        ghidra_path: Optional[str] = None,
        timeout: int = 300,
    ) -> None:
        self._ghidra_path = self._resolve_ghidra_path(ghidra_path)
        self._timeout = timeout
        self._available: Optional[bool] = None

    @staticmethod
    def _resolve_ghidra_path(explicit_path: Optional[str] = None) -> Optional[Path]:
        """Find the Ghidra installation directory."""
        # Explicit path
        if explicit_path:
            p = Path(explicit_path)
            if p.exists():
                return p

        # Environment variable
        env_path = os.environ.get("AODS_GHIDRA_PATH", "")
        if env_path:
            p = Path(env_path)
            if p.exists():
                return p

        # Search common locations
        search_paths = [
            Path("/opt/ghidra"),
            Path.home() / "ghidra",
            Path("/usr/local/ghidra"),
        ]
        # Also check for versioned directories
        for base in [Path("/opt"), Path.home()]:
            if base.exists():
                for d in sorted(base.glob("ghidra*"), reverse=True):
                    if d.is_dir() and (d / "support" / "analyzeHeadless").exists():
                        return d

        for p in search_paths:
            if p.exists() and (p / "support" / "analyzeHeadless").exists():
                return p

        # Check if analyzeHeadless is on PATH
        if shutil.which("analyzeHeadless"):
            return None  # On PATH, no explicit dir needed

        return None

    def _get_analyze_headless(self) -> Optional[str]:
        """Get path to analyzeHeadless script."""
        if self._ghidra_path:
            script = self._ghidra_path / "support" / "analyzeHeadless"
            if script.exists():
                return str(script)

        # Try PATH
        which = shutil.which("analyzeHeadless")
        if which:
            return which

        return None

    def is_available(self) -> bool:
        """Check if Ghidra is available for decompilation.

        Caches the result after first check.
        """
        if self._available is not None:
            return self._available

        script = self._get_analyze_headless()
        if script is None:
            self._available = False
            logger.debug("ghidra_not_available", reason="analyzeHeadless not found")
            return False

        # Verify Java is available
        try:
            result = subprocess.run(
                ["java", "-version"],
                capture_output=True, timeout=10,
            )
            if result.returncode != 0:
                self._available = False
                logger.debug("ghidra_not_available", reason="java not working")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self._available = False
            return False

        self._available = True
        logger.info("ghidra_available", path=str(self._ghidra_path or "PATH"))
        return True

    def get_status(self) -> Dict[str, Any]:
        """Get detailed Ghidra status for health checks and user verification.

        Returns a dict with:
            available: bool
            ghidra_path: str or None
            analyze_headless: str or None
            java_version: str or None
            ghidra_version: str or None (extracted from installation)
            install_hint: str (if not available)
            search_paths_checked: list of paths that were searched
        """
        status: Dict[str, Any] = {
            "available": False,
            "ghidra_path": None,
            "analyze_headless": None,
            "java_version": None,
            "ghidra_version": None,
            "install_hint": "",
            "search_paths_checked": [],
        }

        # Record search paths
        search_locations = [
            str(Path("/opt/ghidra")),
            str(Path.home() / "ghidra"),
            str(Path("/usr/local/ghidra")),
        ]
        env_path = os.environ.get("AODS_GHIDRA_PATH", "")
        if env_path:
            search_locations.insert(0, f"$AODS_GHIDRA_PATH={env_path}")
        search_locations.append("$PATH (analyzeHeadless)")
        # Add versioned dirs found
        for base in [Path("/opt"), Path.home()]:
            if base.exists():
                for d in sorted(base.glob("ghidra*"), reverse=True):
                    if d.is_dir():
                        search_locations.append(str(d))
        status["search_paths_checked"] = search_locations

        # Check Ghidra
        if self._ghidra_path:
            status["ghidra_path"] = str(self._ghidra_path)

        # Check Java first (useful to report even if Ghidra missing)
        java_ok = False
        try:
            result = subprocess.run(
                ["java", "-version"],
                capture_output=True, timeout=10,
            )
            stderr = result.stderr.decode("utf-8", errors="replace")
            for line in stderr.split("\n"):
                if "version" in line.lower():
                    status["java_version"] = line.strip()
                    break
            java_ok = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Now check Ghidra
        script = self._get_analyze_headless()
        if script:
            status["analyze_headless"] = script
        else:
            hints = []
            if not java_ok and not status.get("java_version"):
                hints.append(
                    "Java not found. Ghidra requires Java 11+ (17 or 21 recommended). "
                    "Install with: apt install default-jre"
                )
            hints.append(
                "Ghidra not found. Install Ghidra 10.x+ from "
                "https://ghidra-sre.org/ and either:\n"
                "  1. Set AODS_GHIDRA_PATH=/path/to/ghidra\n"
                "  2. Install to /opt/ghidra/ or ~/ghidra/\n"
                "  3. Add analyzeHeadless to your PATH"
            )
            status["install_hint"] = "\n".join(hints)
            return status

        if not java_ok:
            status["install_hint"] = "Java is not working correctly - Ghidra requires Java 11+"
            return status

        # Try to detect Ghidra version
        if self._ghidra_path:
            version_file = self._ghidra_path / "Ghidra" / "application.properties"
            if not version_file.exists():
                version_file = self._ghidra_path / "application.properties"
            if version_file.exists():
                try:
                    for line in version_file.read_text().split("\n"):
                        if line.startswith("application.version="):
                            status["ghidra_version"] = line.split("=", 1)[1].strip()
                            break
                except Exception:
                    pass

        status["available"] = True
        return status

    def decompile(self, binary_path: str) -> DecompilationResult:
        """Decompile a native binary (.so) to pseudo-C functions.

        Args:
            binary_path: Path to the .so file.

        Returns:
            DecompilationResult with decompiled functions, or error.
        """
        start = time.monotonic()
        bp = Path(binary_path)

        result = DecompilationResult(
            binary_path=binary_path,
            ghidra_available=self.is_available(),
        )

        if not bp.exists():
            result.error = f"Binary not found: {binary_path}"
            return result

        if not self.is_available():
            result.error = "Ghidra not available"
            result.elapsed_seconds = round(time.monotonic() - start, 2)
            return result

        analyze_headless = self._get_analyze_headless()
        if not analyze_headless:
            result.error = "analyzeHeadless not found"
            return result

        # Create temporary project directory
        project_dir = tempfile.mkdtemp(prefix="ghidra_aods_")
        output_dir = tempfile.mkdtemp(prefix="ghidra_output_")

        try:
            # Build Ghidra command
            cmd = [
                analyze_headless,
                project_dir, "aods_project",
                "-import", str(bp),
                "-postScript", "DecompileAllFunctions.java",
                "-scriptPath", str(Path(__file__).parent / "scripts"),
                "-deleteProject",  # Clean up project after analysis
            ]

            # Set output directory via property
            env = os.environ.copy()
            env["GHIDRA_DECOMPILE_OUTPUT"] = output_dir

            logger.info("ghidra_decompile_start", binary=bp.name, timeout=self._timeout)

            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self._timeout,
                env=env,
                cwd=project_dir,
            )

            if proc.returncode != 0:
                stderr = proc.stderr.decode("utf-8", errors="replace")[:500]
                result.error = f"Ghidra exited with code {proc.returncode}: {stderr}"
                logger.warning("ghidra_decompile_failed", binary=bp.name, exit_code=proc.returncode)
            else:
                # Parse decompiled output
                result.functions = self._parse_decompiled_output(output_dir, bp.name)
                logger.info(
                    "ghidra_decompile_complete",
                    binary=bp.name,
                    functions=len(result.functions),
                )

        except subprocess.TimeoutExpired:
            result.error = f"Ghidra timed out after {self._timeout}s"
            logger.warning("ghidra_decompile_timeout", binary=bp.name, timeout=self._timeout)
        except Exception as exc:
            result.error = f"Decompilation error: {type(exc).__name__}"
            logger.error("ghidra_decompile_error", binary=bp.name, error=str(exc))
        finally:
            # Cleanup temp dirs
            shutil.rmtree(project_dir, ignore_errors=True)
            shutil.rmtree(output_dir, ignore_errors=True)

        result.elapsed_seconds = round(time.monotonic() - start, 2)
        return result

    def _parse_decompiled_output(
        self, output_dir: str, source_binary: str,
    ) -> List[DecompiledFunction]:
        """Parse decompiled C files from Ghidra output directory.

        Ghidra exports one file per function or a single combined file.
        We handle both formats.
        """
        functions: List[DecompiledFunction] = []
        out_path = Path(output_dir)

        # Look for .c files in output
        c_files = sorted(out_path.glob("*.c"))
        if not c_files:
            # Try looking for a combined decompilation output
            for txt_file in out_path.glob("*.txt"):
                functions.extend(
                    self._parse_combined_decompilation(txt_file, source_binary)
                )
            return functions

        for c_file in c_files:
            try:
                code = c_file.read_text(encoding="utf-8", errors="replace")
                if len(code.strip()) < 10:
                    continue
                func_name = c_file.stem
                functions.append(DecompiledFunction(
                    name=func_name,
                    code=code,
                    source_binary=source_binary,
                ))
            except Exception:
                continue

        return functions

    def _parse_combined_decompilation(
        self, file_path: Path, source_binary: str,
    ) -> List[DecompiledFunction]:
        """Parse a combined decompilation file with multiple functions."""
        functions: List[DecompiledFunction] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return functions

        # Split by function boundaries (common Ghidra output format)
        # Pattern: function starts with return type + name + (
        current_func: Optional[str] = None
        current_code: List[str] = []
        current_addr = ""

        for line in content.split("\n"):
            # Detect function header (simplified: type name(...) {)
            stripped = line.strip()
            if (
                stripped
                and not stripped.startswith("//")
                and not stripped.startswith("/*")
                and "(" in stripped
                and "{" in stripped
                and not stripped.startswith("if")
                and not stripped.startswith("for")
                and not stripped.startswith("while")
            ):
                # Save previous function
                if current_func and current_code:
                    functions.append(DecompiledFunction(
                        name=current_func,
                        code="\n".join(current_code),
                        address=current_addr,
                        source_binary=source_binary,
                    ))

                # Extract function name
                paren_idx = stripped.index("(")
                name_part = stripped[:paren_idx].strip().split()
                current_func = name_part[-1] if name_part else "unknown"
                current_code = [line]
                current_addr = ""

                # Check for address comment above
                # // Function at 0x12345
                if current_code and "//" in current_code[0]:
                    addr_parts = current_code[0].split("0x")
                    if len(addr_parts) > 1:
                        current_addr = "0x" + addr_parts[1].split()[0]
            elif current_func:
                current_code.append(line)

        # Save last function
        if current_func and current_code:
            functions.append(DecompiledFunction(
                name=current_func,
                code="\n".join(current_code),
                address=current_addr,
                source_binary=source_binary,
            ))

        return functions

    def decompile_all(self, binary_paths: List[str]) -> List[DecompilationResult]:
        """Decompile multiple binaries sequentially.

        Args:
            binary_paths: List of paths to .so files.

        Returns:
            List of DecompilationResult, one per binary.
        """
        results = []
        for bp in binary_paths:
            results.append(self.decompile(bp))
        return results
