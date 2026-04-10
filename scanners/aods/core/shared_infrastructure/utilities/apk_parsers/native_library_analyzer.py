"""Native library security analysis for APK files."""

import os
import re
import hashlib
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple
from dataclasses import dataclass, field
import zipfile

from ._types import ArchitectureType

logger = logging.getLogger(__name__)


@dataclass
class NativeLibraryInfo:
    """Container for native library information."""

    name: str
    path: str
    architecture: ArchitectureType
    file_size: int
    file_hash: str
    is_stripped: bool
    exports: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)


class NativeLibraryAnalyzer:
    """
    Full native library security analysis.

    Provides detailed analysis of native libraries (.so files) in APKs including
    architecture detection, symbol analysis, and security issue identification.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.security_functions = {
            "crypto": ["AES_encrypt", "RSA_encrypt", "MD5_Init", "SHA1_Init"],
            "network": ["socket", "connect", "send", "recv"],
            "filesystem": ["fopen", "fwrite", "fread", "unlink"],
            "process": ["fork", "exec", "system", "popen"],
            "dangerous": ["gets", "strcpy", "sprintf", "strcat"],
        }

    def analyze_apk_native_libraries(self, apk_path: Path) -> List[NativeLibraryInfo]:
        """
        Analyze all native libraries in an APK.

        Args:
            apk_path: Path to APK file

        Returns:
            List of NativeLibraryInfo objects for all native libraries found
        """
        libraries = []

        try:
            with zipfile.ZipFile(apk_path, "r") as apk_zip:
                # Find all native libraries
                lib_files = [f for f in apk_zip.namelist() if f.startswith("lib/") and f.endswith(".so")]

                for lib_file in lib_files:
                    try:
                        lib_data = apk_zip.read(lib_file)
                        lib_info = self._analyze_native_library(lib_file, lib_data)
                        if lib_info:
                            libraries.append(lib_info)
                    except Exception as e:
                        self.logger.warning(f"Failed to analyze native library {lib_file}: {e}")

        except Exception as e:
            self.logger.error(f"Failed to analyze native libraries in {apk_path}: {e}")

        return libraries

    def _analyze_native_library(self, lib_path: str, lib_data: bytes) -> Optional[NativeLibraryInfo]:
        """Analyze individual native library file."""
        try:
            # Extract basic information
            lib_name = os.path.basename(lib_path)
            file_size = len(lib_data)
            file_hash = hashlib.sha256(lib_data).hexdigest()

            # Determine architecture from path
            architecture = self._determine_architecture(lib_path)

            # Check if stripped
            is_stripped = self._is_library_stripped(lib_data)

            # Extract symbols if possible
            exports, imports = self._extract_symbols(lib_data)

            # Identify security issues
            security_issues = self._identify_security_issues(exports + imports)

            return NativeLibraryInfo(
                name=lib_name,
                path=lib_path,
                architecture=architecture,
                file_size=file_size,
                file_hash=file_hash,
                is_stripped=is_stripped,
                exports=exports,
                imports=imports,
                security_issues=security_issues,
            )

        except Exception as e:
            self.logger.error(f"Failed to analyze native library: {e}")
            return None

    def _determine_architecture(self, lib_path: str) -> ArchitectureType:
        """Determine architecture from library path."""
        path_lower = lib_path.lower()

        if "/arm64-v8a/" in path_lower:
            return ArchitectureType.ARM64
        elif "/armeabi-v7a/" in path_lower or "/armeabi/" in path_lower:
            return ArchitectureType.ARM
        elif "/x86_64/" in path_lower:
            return ArchitectureType.X86_64
        elif "/x86/" in path_lower:
            return ArchitectureType.X86
        elif "/mips64/" in path_lower:
            return ArchitectureType.MIPS64
        elif "/mips/" in path_lower:
            return ArchitectureType.MIPS
        else:
            return ArchitectureType.UNKNOWN

    def _is_library_stripped(self, lib_data: bytes) -> bool:
        """Check if native library is stripped."""
        try:
            # Look for ELF header
            if len(lib_data) < 64:
                return True

            # Check ELF magic
            if lib_data[:4] != b"\x7fELF":
                return True

            # Simple heuristic: look for common debug symbols
            debug_indicators = [b".debug_", b".symtab", b".strtab"]
            for indicator in debug_indicators:
                if indicator in lib_data:
                    return False

            return True

        except Exception:
            return True

    def _extract_symbols(self, lib_data: bytes) -> Tuple[List[str], List[str]]:
        """Extract exported and imported symbols from library."""
        exports = []
        imports = []

        try:
            # Use readelf if available
            if shutil.which("readelf"):
                with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as temp_file:
                    temp_file.write(lib_data)
                    temp_path = temp_file.name

                try:
                    # Extract exports
                    cmd = ["readelf", "--dyn-syms", temp_path]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        exports = self._parse_readelf_symbols(result.stdout, "export")

                    # Extract imports
                    cmd = ["readelf", "--dyn-syms", "--use-dynamic", temp_path]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        imports = self._parse_readelf_symbols(result.stdout, "import")

                finally:
                    os.unlink(temp_path)

            # Fallback: basic string extraction
            if not exports and not imports:
                exports, imports = self._extract_symbols_fallback(lib_data)

        except Exception as e:
            self.logger.debug(f"Symbol extraction failed: {e}")

        return exports[:100], imports[:100]  # Limit to prevent excessive memory usage

    def _parse_readelf_symbols(self, output: str, symbol_type: str) -> List[str]:
        """Parse readelf output to extract symbols."""
        symbols = []

        try:
            lines = output.split("\n")
            for line in lines:
                # Look for symbol definitions
                if re.search(r"\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+(\w+)", line):
                    match = re.search(r"\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+(\w+)", line)
                    if match:
                        symbol = match.group(1)
                        if symbol and symbol != "UND":
                            symbols.append(symbol)

        except Exception as e:
            self.logger.debug(f"Failed to parse readelf output: {e}")

        return symbols

    def _extract_symbols_fallback(self, lib_data: bytes) -> Tuple[List[str], List[str]]:
        """Fallback symbol extraction using string analysis."""
        exports = []
        imports = []

        try:
            # Extract printable strings
            strings = re.findall(b"[\x20-\x7e]{4,}", lib_data)

            for string_bytes in strings[:500]:  # Limit analysis
                try:
                    string = string_bytes.decode("ascii")
                    # Look for function-like names
                    if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", string):
                        if any(func in string for func_list in self.security_functions.values() for func in func_list):
                            imports.append(string)
                        elif len(string) > 3 and not string.isupper():
                            exports.append(string)
                except UnicodeDecodeError:
                    continue

        except Exception as e:
            self.logger.debug(f"Fallback symbol extraction failed: {e}")

        return exports[:50], imports[:50]

    def _identify_security_issues(self, symbols: List[str]) -> List[str]:
        """Identify security issues based on symbol analysis."""
        issues = []

        for category, functions in self.security_functions.items():
            found_functions = [func for func in functions if any(func in symbol for symbol in symbols)]
            if found_functions:
                if category == "dangerous":
                    issues.append(f"Dangerous functions detected: {', '.join(found_functions)}")
                else:
                    issues.append(f"{category.title()} functions detected: {len(found_functions)} functions")

        return issues
