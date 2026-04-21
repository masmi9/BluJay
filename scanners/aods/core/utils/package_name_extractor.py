#!/usr/bin/env python3
"""
AODS Automatic Package Name Detection - Core Extractor
======================================================

Unified package name extraction utility providing multiple extraction methods
with intelligent fallbacks and confidence scoring for reliable APK analysis.

Features:
- Multiple extraction methods (AAPT, manifest parsing, filename patterns)
- Confidence scoring for intelligent decision making
- Graceful fallbacks and error handling
- Integration with existing AODS infrastructure
- Support for vulnerable apps and standard APKs
"""

import logging
import re
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger(__name__)


@dataclass
class PackageExtractionResult:
    """Result of package name extraction with metadata."""

    success: bool
    package_name: Optional[str] = None
    confidence: float = 0.0  # 0.0 to 1.0
    method: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    app_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None


class PackageNameExtractor:
    """
    Unified package name extraction for AODS framework.

    Provides multiple extraction methods with intelligent fallbacks and
    confidence scoring for reliable package name detection from APK files.

    Extraction Methods (in priority order):
    1. AAPT dump badging - Most reliable, extracts compiled metadata
    2. AAPT dump xmltree - Reliable, parses manifest structure
    3. Direct manifest parsing - Moderate reliability, XML parsing
    4. Filename pattern matching - Low reliability, educated guessing

    Confidence Scoring:
    - 0.95: AAPT badging successful extraction
    - 0.85: AAPT xmltree successful extraction
    - 0.75: Direct manifest parsing successful
    - 0.60: Known vulnerable app pattern match
    - 0.30: Generated from filename
    """

    def __init__(self, timeout: int = 30):
        """
        Initialize package name extractor.

        Args:
            timeout: Timeout in seconds for extraction operations
        """
        self.logger = logging.getLogger(__name__)
        self.timeout = timeout

        # Remove known vulnerable app patterns to avoid hardcoded package detection
        self.known_app_patterns = {}

    def extract_package_name(self, apk_path: str) -> PackageExtractionResult:
        """
        Extract package name using multiple methods with confidence scoring.

        Tries extraction methods in order of reliability and returns the best
        result based on method confidence and success rate.

        Args:
            apk_path: Path to APK file

        Returns:
            PackageExtractionResult with extraction details and confidence
        """
        apk_path = Path(apk_path).resolve()

        # Validate APK file existence
        if not apk_path.exists():
            return PackageExtractionResult(success=False, error=f"APK file not found: {apk_path}")

        if not apk_path.is_file():
            return PackageExtractionResult(success=False, error=f"Path is not a file: {apk_path}")

        # Try extraction methods in order of reliability
        extraction_methods = [
            (self._extract_with_aapt_badging, "aapt_badging", 0.95),
            (self._extract_with_aapt_xmltree, "aapt_xmltree", 0.85),
            (self._extract_with_manifest_parsing, "manifest_parsing", 0.75),
            (self._extract_with_filename_patterns, "filename_patterns", 0.30),
        ]

        self.logger.debug(f"Starting package extraction for: {apk_path}")

        for method, method_name, base_confidence in extraction_methods:
            try:
                self.logger.debug(f"Trying extraction method: {method_name}")
                result = method(apk_path)

                if result.success and result.package_name:
                    # Apply base confidence but preserve any higher confidence from method
                    result.confidence = max(base_confidence, result.confidence)
                    result.method = method_name

                    self.logger.info(
                        f"Package extracted via {method_name}: {result.package_name} "
                        f"({result.confidence:.0%} confidence)"
                    )
                    return result

            except Exception as e:
                self.logger.debug(f"Method {method_name} failed: {e}")
                continue

        # All methods failed
        return PackageExtractionResult(
            success=False, error="All extraction methods failed - could not determine package name"
        )

    def _extract_with_aapt_badging(self, apk_path: Path) -> PackageExtractionResult:
        """
        Primary extraction method using aapt dump badging.

        This is the most reliable method as it reads compiled APK metadata
        directly from the APK's binary resources.
        """
        try:
            cmd = ["aapt", "dump", "badging", str(apk_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)

            if result.returncode != 0:
                return PackageExtractionResult(
                    success=False, error=f"aapt badging failed (exit {result.returncode}): {result.stderr.strip()}"
                )

            output = result.stdout

            # Parse AAPT badging output with metadata extraction
            package_match = re.search(r"package: name='([^']+)'", output)
            app_label_match = re.search(r"application-label:'([^']+)'", output)
            version_name_match = re.search(r"versionName='([^']+)'", output)
            version_code_match = re.search(r"versionCode='([^']+)'", output)
            min_sdk_match = re.search(r"sdkVersion:'([^']+)'", output)
            target_sdk_match = re.search(r"targetSdkVersion:'([^']+)'", output)

            if package_match:
                package_name = package_match.group(1)

                # Validate package name format
                if self._validate_package_name(package_name):
                    return PackageExtractionResult(
                        success=True,
                        package_name=package_name,
                        confidence=0.95,
                        method="aapt_badging",
                        metadata={
                            "app_name": app_label_match.group(1) if app_label_match else None,
                            "version_name": version_name_match.group(1) if version_name_match else None,
                            "version_code": int(version_code_match.group(1)) if version_code_match else None,
                            "min_sdk": int(min_sdk_match.group(1)) if min_sdk_match else None,
                            "target_sdk": int(target_sdk_match.group(1)) if target_sdk_match else None,
                            "extraction_output_lines": len(output.split("\n")),
                        },
                        app_name=app_label_match.group(1) if app_label_match else None,
                        version_name=version_name_match.group(1) if version_name_match else None,
                        version_code=int(version_code_match.group(1)) if version_code_match else None,
                        min_sdk=int(min_sdk_match.group(1)) if min_sdk_match else None,
                        target_sdk=int(target_sdk_match.group(1)) if target_sdk_match else None,
                    )
                else:
                    return PackageExtractionResult(
                        success=False, error=f"Invalid package name format extracted: {package_name}"
                    )

            return PackageExtractionResult(success=False, error="No package name found in aapt badging output")

        except subprocess.TimeoutExpired:
            return PackageExtractionResult(success=False, error=f"aapt badging timed out after {self.timeout} seconds")
        except FileNotFoundError:
            return PackageExtractionResult(
                success=False, error="aapt tool not found - please install Android SDK build-tools"
            )
        except Exception as e:
            return PackageExtractionResult(success=False, error=f"aapt badging extraction failed: {e}")

    def _extract_with_aapt_xmltree(self, apk_path: Path) -> PackageExtractionResult:
        """
        Secondary extraction method using aapt dump xmltree.

        This method parses the AndroidManifest.xml structure and extracts
        the package attribute from the manifest root element.
        """
        try:
            cmd = ["aapt", "dump", "xmltree", str(apk_path), "AndroidManifest.xml"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)

            if result.returncode != 0:
                return PackageExtractionResult(
                    success=False, error=f"aapt xmltree failed (exit {result.returncode}): {result.stderr.strip()}"
                )

            # Parse xmltree output for package attribute
            for line in result.stdout.split("\n"):
                if "A: package=" in line:
                    match = re.search(r'package="([^"]+)"', line)
                    if match:
                        package_name = match.group(1)

                        if self._validate_package_name(package_name):
                            return PackageExtractionResult(
                                success=True,
                                package_name=package_name,
                                confidence=0.85,
                                method="aapt_xmltree",
                                metadata={
                                    "extraction_line": line.strip(),
                                    "total_output_lines": len(result.stdout.split("\n")),
                                },
                            )
                        else:
                            return PackageExtractionResult(
                                success=False, error=f"Invalid package name format from xmltree: {package_name}"
                            )

            return PackageExtractionResult(success=False, error="No package attribute found in AndroidManifest.xml")

        except subprocess.TimeoutExpired:
            return PackageExtractionResult(success=False, error=f"aapt xmltree timed out after {self.timeout} seconds")
        except FileNotFoundError:
            return PackageExtractionResult(
                success=False, error="aapt tool not found - please install Android SDK build-tools"
            )
        except Exception as e:
            return PackageExtractionResult(success=False, error=f"aapt xmltree extraction failed: {e}")

    def _extract_with_manifest_parsing(self, apk_path: Path) -> PackageExtractionResult:
        """
        Tertiary extraction method using direct manifest parsing.

        This method extracts AndroidManifest.xml from the APK and attempts
        to parse it directly. Works only if the manifest is in text format.
        """
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                manifest_path = Path(temp_dir) / "AndroidManifest.xml"

                # Extract manifest from APK
                with zipfile.ZipFile(apk_path, "r") as apk:
                    try:
                        apk.extract("AndroidManifest.xml", temp_dir)
                    except KeyError:
                        return PackageExtractionResult(success=False, error="AndroidManifest.xml not found in APK")

                # Try to parse as text (if decompiled or uncompiled)
                try:
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        content = f.read()

                    # Look for package attribute in manifest element
                    package_match = re.search(r'<manifest[^>]*package="([^"]+)"', content)
                    if package_match:
                        package_name = package_match.group(1)

                        if self._validate_package_name(package_name):
                            return PackageExtractionResult(
                                success=True,
                                package_name=package_name,
                                confidence=0.75,
                                method="manifest_parsing",
                                metadata={"manifest_size_bytes": len(content), "is_text_manifest": True},
                            )
                        else:
                            return PackageExtractionResult(
                                success=False, error=f"Invalid package name format from manifest: {package_name}"
                            )
                    else:
                        return PackageExtractionResult(
                            success=False, error="No package attribute found in manifest XML"
                        )

                except UnicodeDecodeError:
                    # Binary manifest - cannot parse directly
                    return PackageExtractionResult(
                        success=False, error="Manifest is in binary format, cannot parse directly"
                    )

        except Exception as e:
            return PackageExtractionResult(success=False, error=f"Manifest parsing failed: {e}")

    def _extract_with_filename_patterns(self, apk_path: Path) -> PackageExtractionResult:
        """
        Fallback method using filename pattern matching.

        This method attempts to match known vulnerable app patterns or
        generates a reasonable package name from the APK filename.
        """
        filename = apk_path.stem.lower()

        # Do not map filenames to specific known packages in production

        # Generate generic package name from filename
        clean_name = re.sub(r"[^a-zA-Z0-9]", "", filename)
        if clean_name and len(clean_name) >= 3:
            generated_package = f"com.analyzed.{clean_name}"

            return PackageExtractionResult(
                success=True,
                package_name=generated_package,
                confidence=0.30,  # Low confidence for generated names
                method="filename_generation",
                metadata={"original_filename": apk_path.name, "cleaned_name": clean_name, "generated": True},
            )

        return PackageExtractionResult(success=False, error="Could not generate valid package name from filename")

    def _validate_package_name(self, package_name: str) -> bool:
        """
        Validate package name format.

        Args:
            package_name: Package name to validate

        Returns:
            True if valid package name format
        """
        if not package_name or not isinstance(package_name, str):
            return False

        # Basic validation: must contain at least one dot and have valid characters
        if "." not in package_name:
            return False

        # Check for valid Java package name format
        parts = package_name.split(".")
        if len(parts) < 2:
            return False

        # Each part should start with letter and contain only letters, digits, underscores
        for part in parts:
            if not part or not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", part):
                return False

        return True

    def get_extraction_methods(self) -> List[Tuple[str, str, float]]:
        """
        Get available extraction methods with their confidence levels.

        Returns:
            List of (method_name, description, base_confidence) tuples
        """
        return [
            ("aapt_badging", "AAPT dump badging - Primary method", 0.95),
            ("aapt_xmltree", "AAPT dump xmltree - Secondary method", 0.85),
            ("manifest_parsing", "Direct manifest parsing - Tertiary method", 0.75),
            ("filename_patterns", "Filename pattern matching - Fallback method", 0.30),
        ]

    def check_aapt_availability(self) -> Tuple[bool, Optional[str]]:
        """
        Check if AAPT tool is available on the system.

        Returns:
            (is_available, error_message)
        """
        try:
            result = subprocess.run(["aapt", "version"], capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                return True, None
            else:
                return False, f"aapt returned exit code {result.returncode}"

        except FileNotFoundError:
            return False, "aapt tool not found - please install Android SDK build-tools"
        except subprocess.TimeoutExpired:
            return False, "aapt version check timed out"
        except Exception as e:
            return False, f"Error checking aapt availability: {e}"


# Convenience functions for easy integration


def extract_package_name(apk_path: str, timeout: int = 30) -> PackageExtractionResult:
    """
    Convenience function to extract package name from APK.

    Args:
        apk_path: Path to APK file
        timeout: Timeout in seconds for extraction operations

    Returns:
        PackageExtractionResult with extraction details
    """
    extractor = PackageNameExtractor(timeout=timeout)
    return extractor.extract_package_name(apk_path)


def quick_extract_package_name(apk_path: str) -> Optional[str]:
    """
    Quick extraction function that returns just the package name or None.

    Args:
        apk_path: Path to APK file

    Returns:
        Package name if successful, None if failed
    """
    result = extract_package_name(apk_path)
    return result.package_name if result.success else None


def check_aapt_availability() -> bool:
    """
    Quick check if AAPT tool is available.

    Returns:
        True if AAPT is available, False otherwise
    """
    extractor = PackageNameExtractor()
    is_available, _ = extractor.check_aapt_availability()
    return is_available
