"""DEX file analysis and inspection."""

import os
import re
import hashlib
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import zipfile

logger = logging.getLogger(__name__)


@dataclass
class DEXInfo:
    """Container for DEX file information."""

    file_path: str
    file_size: int
    file_hash: str
    classes_count: int
    methods_count: int
    strings_count: int
    api_level: int
    security_issues: List[str] = field(default_factory=list)
    obfuscation_detected: bool = False
    encryption_detected: bool = False


class DEXAnalyzer:
    """
    Full DEX file analysis and inspection.

    Provides detailed DEX file analysis including class enumeration, method analysis,
    obfuscation detection, and security issue identification.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.obfuscation_patterns = [
            r"[a-z]{1,2}",  # Single/double character class names
            r"[A-Z][a-z]?",  # Proguard-style names
            r"[0-9]+",  # Numeric class names
            r"[a-zA-Z0-9]{32,}",  # Very long random names
        ]

        # Security-related class patterns
        self.security_patterns = {
            "crypto": [r"javax\.crypto\.", r"java\.security\.", r"android\.security\."],
            "network": [r"java\.net\.", r"android\.net\.", r"org\.apache\.http\."],
            "reflection": [r"java\.lang\.reflect\.", r"java\.lang\.Class"],
            "native": [r"java\.lang\.System\.loadLibrary", r"java\.lang\.Runtime\.exec"],
        }

    def analyze_apk_dex_files(self, apk_path: Path) -> List[DEXInfo]:
        """
        Analyze all DEX files in an APK.

        Args:
            apk_path: Path to APK file

        Returns:
            List of DEXInfo objects for all DEX files found
        """
        dex_files = []

        try:
            with zipfile.ZipFile(apk_path, "r") as apk_zip:
                # Find all DEX files
                dex_file_names = [f for f in apk_zip.namelist() if f.endswith(".dex")]

                for dex_file in dex_file_names:
                    try:
                        dex_data = apk_zip.read(dex_file)
                        dex_info = self._analyze_dex_data(dex_file, dex_data)
                        if dex_info:
                            dex_files.append(dex_info)
                    except Exception as e:
                        self.logger.warning(f"Failed to analyze DEX file {dex_file}: {e}")

        except Exception as e:
            self.logger.error(f"Failed to analyze DEX files in {apk_path}: {e}")

        return dex_files

    def detect_obfuscation(self, dex_info: DEXInfo, class_names: List[str]) -> Dict[str, Any]:
        """
        Detect obfuscation in DEX file based on class names and structure.

        Args:
            dex_info: DEX file information
            class_names: List of class names extracted from DEX

        Returns:
            Obfuscation analysis results
        """
        if not class_names:
            return {"obfuscated": False, "confidence": 0.0, "indicators": []}

        indicators = []
        obfuscated_count = 0

        for class_name in class_names:
            # Remove package prefix for analysis
            simple_name = class_name.split(".")[-1] if "." in class_name else class_name

            for pattern in self.obfuscation_patterns:
                if re.fullmatch(pattern, simple_name):
                    obfuscated_count += 1
                    break

        obfuscation_ratio = obfuscated_count / len(class_names)

        # Determine obfuscation level
        if obfuscation_ratio > 0.7:
            indicators.append("High ratio of obfuscated class names")
            confidence = 0.9
            obfuscated = True
        elif obfuscation_ratio > 0.4:
            indicators.append("Medium ratio of obfuscated class names")
            confidence = 0.6
            obfuscated = True
        elif obfuscation_ratio > 0.1:
            indicators.append("Low ratio of obfuscated class names")
            confidence = 0.3
            obfuscated = False
        else:
            confidence = 0.0
            obfuscated = False

        # Additional heuristics
        avg_name_length = sum(len(name.split(".")[-1]) for name in class_names) / len(class_names)
        if avg_name_length < 3:
            indicators.append("Very short class names detected")
            confidence += 0.2
            obfuscated = True

        return {
            "obfuscated": obfuscated,
            "confidence": min(confidence, 1.0),
            "obfuscation_ratio": obfuscation_ratio,
            "indicators": indicators,
            "total_classes": len(class_names),
            "obfuscated_classes": obfuscated_count,
        }

    def analyze_security_patterns(self, class_names: List[str]) -> Dict[str, List[str]]:
        """
        Analyze security-related patterns in class names.

        Args:
            class_names: List of class names to analyze

        Returns:
            Dictionary mapping security categories to found patterns
        """
        security_findings = {category: [] for category in self.security_patterns}

        for class_name in class_names:
            for category, patterns in self.security_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, class_name):
                        if class_name not in security_findings[category]:
                            security_findings[category].append(class_name)

        return security_findings

    def _analyze_dex_data(self, file_path: str, dex_data: bytes) -> Optional[DEXInfo]:
        """Analyze DEX file data and extract information."""
        try:
            # Calculate basic metrics
            file_size = len(dex_data)
            file_hash = hashlib.sha256(dex_data).hexdigest()

            # Try to parse DEX header
            dex_info = self._parse_dex_header(dex_data)
            if not dex_info:
                return None

            # Enhanced analysis using external tools if available
            enhanced_info = self._enhanced_dex_analysis(file_path, dex_data)
            if enhanced_info:
                dex_info.update(enhanced_info)

            return DEXInfo(
                file_path=file_path,
                file_size=file_size,
                file_hash=file_hash,
                classes_count=dex_info.get("classes_count", 0),
                methods_count=dex_info.get("methods_count", 0),
                strings_count=dex_info.get("strings_count", 0),
                api_level=dex_info.get("api_level", 1),
                security_issues=dex_info.get("security_issues", []),
                obfuscation_detected=dex_info.get("obfuscation_detected", False),
                encryption_detected=dex_info.get("encryption_detected", False),
            )

        except Exception as e:
            self.logger.error(f"Failed to analyze DEX data: {e}")
            return None

    def _parse_dex_header(self, dex_data: bytes) -> Optional[Dict[str, Any]]:
        """Parse DEX file header to extract basic information."""
        try:
            if len(dex_data) < 112:  # Minimum DEX header size
                return None

            # Check DEX magic number
            magic = dex_data[:8]
            if not magic.startswith(b"dex\n"):
                return None

            # Extract version
            version = magic[4:7].decode("ascii")

            # Parse header fields (little-endian)
            import struct

            # File size (offset 32)
            file_size = struct.unpack("<I", dex_data[32:36])[0]

            # String IDs size (offset 56)
            string_ids_size = struct.unpack("<I", dex_data[56:60])[0]

            # Type IDs size (offset 64)
            _type_ids_size = struct.unpack("<I", dex_data[64:68])[0]  # noqa: F841

            # Proto IDs size (offset 72)
            _proto_ids_size = struct.unpack("<I", dex_data[72:76])[0]  # noqa: F841

            # Field IDs size (offset 80)
            _field_ids_size = struct.unpack("<I", dex_data[80:84])[0]  # noqa: F841

            # Method IDs size (offset 88)
            method_ids_size = struct.unpack("<I", dex_data[88:92])[0]

            # Class defs size (offset 96)
            class_defs_size = struct.unpack("<I", dex_data[96:100])[0]

            return {
                "version": version,
                "file_size": file_size,
                "strings_count": string_ids_size,
                "classes_count": class_defs_size,
                "methods_count": method_ids_size,
                "api_level": 1,  # Default, would need more parsing to determine
                "security_issues": [],
                "obfuscation_detected": False,
                "encryption_detected": False,
            }

        except Exception as e:
            self.logger.warning(f"Failed to parse DEX header: {e}")
            return None

    def _enhanced_dex_analysis(self, file_path: str, dex_data: bytes) -> Optional[Dict[str, Any]]:
        """Enhanced DEX analysis using external tools if available."""
        enhanced_info = {}

        # Try using dexdump if available
        if shutil.which("dexdump"):
            try:
                with tempfile.NamedTemporaryFile(suffix=".dex", delete=False) as temp_file:
                    temp_file.write(dex_data)
                    temp_path = temp_file.name

                try:
                    cmd = ["dexdump", "-d", temp_path]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                    if result.returncode == 0:
                        enhanced_info.update(self._parse_dexdump_output(result.stdout))

                finally:
                    os.unlink(temp_path)

            except Exception as e:
                self.logger.debug(f"Enhanced DEX analysis failed: {e}")

        # Basic heuristic analysis
        enhanced_info.update(self._heuristic_dex_analysis(dex_data))

        return enhanced_info if enhanced_info else None

    def _parse_dexdump_output(self, output: str) -> Dict[str, Any]:
        """Parse dexdump output to extract additional information."""
        info = {}

        try:
            # Extract class information
            class_matches = re.findall(r"Class descriptor\s*:\s*\'([^\']+)\'", output)
            if class_matches:
                info["class_names"] = class_matches

                # Analyze obfuscation
                obfuscation_analysis = self.detect_obfuscation(None, class_matches)
                info["obfuscation_detected"] = obfuscation_analysis["obfuscated"]

                # Analyze security patterns
                security_patterns = self.analyze_security_patterns(class_matches)
                security_issues = []
                for category, findings in security_patterns.items():
                    if findings:
                        security_issues.append(f"{category.title()} API usage detected: {len(findings)} classes")
                info["security_issues"] = security_issues

            # Extract method information
            method_matches = re.findall(r"name\s*:\s*\'([^\']+)\'", output)
            if method_matches:
                info["method_names"] = method_matches

        except Exception as e:
            self.logger.warning(f"Failed to parse dexdump output: {e}")

        return info

    def _heuristic_dex_analysis(self, dex_data: bytes) -> Dict[str, Any]:
        """Heuristic analysis of DEX file without external tools."""
        info = {}

        try:
            # Check for encryption/packing indicators
            entropy = self._calculate_entropy(dex_data[:1024])  # Check first 1KB
            if entropy > 7.5:  # High entropy suggests encryption/packing
                info["encryption_detected"] = True
                info["security_issues"] = info.get("security_issues", []) + ["High entropy suggests encryption/packing"]

            # Look for common obfuscation/packing strings
            obfuscation_indicators = [b"ProGuard", b"DexGuard", b"allatori", b"zelix", b"dasho"]

            for indicator in obfuscation_indicators:
                if indicator in dex_data:
                    info["obfuscation_detected"] = True
                    info["security_issues"] = info.get("security_issues", []) + [
                        f'Obfuscation tool detected: {indicator.decode("ascii", errors="ignore")}'
                    ]
                    break

        except Exception as e:
            self.logger.debug(f"Heuristic DEX analysis failed: {e}")

        return info

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        import math
        from collections import Counter

        # Count byte frequencies
        byte_counts = Counter(data)
        data_len = len(data)

        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy
