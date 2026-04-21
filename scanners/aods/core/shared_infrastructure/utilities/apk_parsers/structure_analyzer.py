"""APK structure and integrity analysis."""

import os
import re
import hashlib
import logging
import time
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, field
import zipfile

logger = logging.getLogger(__name__)


@dataclass
class APKStructureInfo:
    """Container for APK structure analysis information."""

    total_files: int
    total_size: int
    compression_ratio: float
    file_types: Dict[str, int]
    directory_structure: Dict[str, Any]
    integrity_issues: List[str] = field(default_factory=list)
    suspicious_files: List[str] = field(default_factory=list)
    manifest_present: bool = True
    certificates_present: bool = True
    resources_present: bool = True


class APKStructureAnalyzer:
    """
    Full APK structure and integrity analysis.

    Provides detailed analysis of APK file structure, integrity validation,
    and detection of structural anomalies that may indicate tampering or malicious activity.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.suspicious_file_patterns = [
            r"\.(?:exe|dll|bat|cmd|scr|pif)$",  # Windows executables
            r"\.(?:sh|bash|zsh)$",  # Shell scripts
            r"\.(?:jar|war|ear)$",  # Java archives
            r"META-INF/.*\.(?:jar|zip)$",  # Nested archives in META-INF
            r"classes\d*\.dex\..*",  # Modified DEX files
            r"lib/.*\.(?:a|lib)$",  # Static libraries
        ]

        self.expected_directories = {"META-INF", "res", "assets", "lib", "classes.dex", "AndroidManifest.xml"}

        self.file_type_extensions = {
            "dex": [".dex"],
            "native": [".so"],
            "resource": [".xml", ".png", ".jpg", ".jpeg", ".gif", ".webp"],
            "asset": [],  # Files in assets/ directory
            "certificate": [".rsa", ".dsa", ".ec"],
            "manifest": ["AndroidManifest.xml"],
            "other": [],
        }

    def analyze_apk_structure(self, apk_path: Path) -> APKStructureInfo:
        """
        Analyze APK file structure and integrity.

        Args:
            apk_path: Path to APK file

        Returns:
            APKStructureInfo object with full structure analysis
        """
        try:
            with zipfile.ZipFile(apk_path, "r") as apk_zip:
                # Get file listing
                file_list = apk_zip.namelist()

                # Calculate basic metrics
                total_files = len(file_list)
                total_size = sum(apk_zip.getinfo(f).file_size for f in file_list)
                compressed_size = sum(apk_zip.getinfo(f).compress_size for f in file_list)
                compression_ratio = compressed_size / total_size if total_size > 0 else 0

                # Analyze file types
                file_types = self._categorize_files(file_list)

                # Build directory structure
                directory_structure = self._build_directory_structure(file_list)

                # Check for integrity issues
                integrity_issues = self._check_integrity_issues(apk_zip, file_list)

                # Identify suspicious files
                suspicious_files = self._identify_suspicious_files(file_list)

                # Check for required components
                manifest_present = "AndroidManifest.xml" in file_list
                certificates_present = any(
                    f.startswith("META-INF/") and any(f.endswith(ext) for ext in [".RSA", ".DSA", ".EC"])
                    for f in file_list
                )
                resources_present = any(f.startswith("res/") for f in file_list)

                return APKStructureInfo(
                    total_files=total_files,
                    total_size=total_size,
                    compression_ratio=compression_ratio,
                    file_types=file_types,
                    directory_structure=directory_structure,
                    integrity_issues=integrity_issues,
                    suspicious_files=suspicious_files,
                    manifest_present=manifest_present,
                    certificates_present=certificates_present,
                    resources_present=resources_present,
                )

        except Exception as e:
            self.logger.error(f"Failed to analyze APK structure: {e}")
            return APKStructureInfo(
                total_files=0,
                total_size=0,
                compression_ratio=0.0,
                file_types={},
                directory_structure={},
                integrity_issues=[f"Analysis failed: {str(e)}"],
                suspicious_files=[],
                manifest_present=False,
                certificates_present=False,
                resources_present=False,
            )

    def validate_apk_integrity(self, apk_path: Path) -> Dict[str, Any]:
        """
        Validate APK file integrity and detect tampering.

        Args:
            apk_path: Path to APK file

        Returns:
            Integrity validation results
        """
        validation = {"is_valid": True, "integrity_score": 100, "issues": [], "warnings": []}

        try:
            with zipfile.ZipFile(apk_path, "r") as apk_zip:
                # Test ZIP integrity
                bad_files = apk_zip.testzip()
                if bad_files:
                    validation["is_valid"] = False
                    validation["integrity_score"] -= 50
                    validation["issues"].append(f"Corrupted files detected: {bad_files}")

                # Check for required files
                file_list = apk_zip.namelist()

                if "AndroidManifest.xml" not in file_list:
                    validation["is_valid"] = False
                    validation["integrity_score"] -= 40
                    validation["issues"].append("Missing AndroidManifest.xml")

                if not any(f.endswith(".dex") for f in file_list):
                    validation["is_valid"] = False
                    validation["integrity_score"] -= 30
                    validation["issues"].append("No DEX files found")

                # Check certificate presence
                cert_files = [
                    f
                    for f in file_list
                    if f.startswith("META-INF/") and any(f.endswith(ext) for ext in [".RSA", ".DSA", ".EC"])
                ]
                if not cert_files:
                    validation["integrity_score"] -= 20
                    validation["warnings"].append("No certificates found - unsigned APK")

                # Check for duplicate files (potential tampering)
                duplicate_check = self._check_duplicate_files(apk_zip, file_list)
                if duplicate_check["duplicates"]:
                    validation["integrity_score"] -= 15
                    validation["warnings"].append(f"Duplicate files detected: {len(duplicate_check['duplicates'])}")

        except zipfile.BadZipFile:
            validation["is_valid"] = False
            validation["integrity_score"] = 0
            validation["issues"].append("Invalid ZIP file format")
        except Exception as e:
            validation["is_valid"] = False
            validation["integrity_score"] = 0
            validation["issues"].append(f"Integrity check failed: {str(e)}")

        return validation

    def _categorize_files(self, file_list: List[str]) -> Dict[str, int]:
        """Categorize files by type."""
        file_types = {category: 0 for category in self.file_type_extensions}

        for file_path in file_list:
            categorized = False

            # Check special cases first
            if file_path == "AndroidManifest.xml":
                file_types["manifest"] += 1
                categorized = True
            elif file_path.startswith("assets/"):
                file_types["asset"] += 1
                categorized = True
            elif file_path.startswith("META-INF/"):
                for ext in self.file_type_extensions["certificate"]:
                    if file_path.upper().endswith(ext.upper()):
                        file_types["certificate"] += 1
                        categorized = True
                        break

            # Check by extension if not categorized
            if not categorized:
                for category, extensions in self.file_type_extensions.items():
                    if category in ["manifest", "asset", "certificate"]:
                        continue

                    for ext in extensions:
                        if file_path.lower().endswith(ext):
                            file_types[category] += 1
                            categorized = True
                            break

                    if categorized:
                        break

            # Default to 'other' if not categorized
            if not categorized:
                file_types["other"] += 1

        return file_types

    def _build_directory_structure(self, file_list: List[str]) -> Dict[str, Any]:
        """Build hierarchical directory structure."""
        structure = {}

        for file_path in file_list:
            parts = file_path.split("/")
            current = structure

            for part in parts[:-1]:  # Directories
                if part not in current:
                    current[part] = {}
                current = current[part]

            # File
            if parts:
                filename = parts[-1]
                if filename:  # Avoid empty strings
                    current[filename] = "file"

        return structure

    def _check_integrity_issues(self, apk_zip: zipfile.ZipFile, file_list: List[str]) -> List[str]:
        """Check for various integrity issues."""
        issues = []

        # Check for files with suspicious compression ratios
        for file_path in file_list:
            try:
                file_info = apk_zip.getinfo(file_path)
                if file_info.file_size > 0:
                    compression_ratio = file_info.compress_size / file_info.file_size
                    if compression_ratio > 1.1:  # Compressed size larger than original
                        issues.append(f"Suspicious compression ratio in {file_path}")
                    elif compression_ratio < 0.1 and file_info.file_size > 1000:  # Very high compression
                        issues.append(f"Unusually high compression in {file_path}")
            except Exception:
                issues.append(f"Cannot read file info for {file_path}")

        # Check for files with unusual timestamps
        current_time = time.time()
        for file_path in file_list:
            try:
                file_info = apk_zip.getinfo(file_path)
                file_time = time.mktime(file_info.date_time + (0, 0, -1))

                # Check for future timestamps
                if file_time > current_time + 86400:  # More than 1 day in future
                    issues.append(f"Future timestamp detected in {file_path}")

                # Check for very old timestamps (before Android existed)
                if file_time < time.mktime((2007, 1, 1, 0, 0, 0, 0, 0, -1)):
                    issues.append(f"Suspiciously old timestamp in {file_path}")

            except Exception:
                continue

        return issues

    def _identify_suspicious_files(self, file_list: List[str]) -> List[str]:
        """Identify potentially suspicious files."""
        suspicious = []

        for file_path in file_list:
            for pattern in self.suspicious_file_patterns:
                if re.search(pattern, file_path, re.IGNORECASE):
                    suspicious.append(file_path)
                    break

            # Check for hidden files (starting with dot)
            filename = os.path.basename(file_path)
            if filename.startswith(".") and len(filename) > 1:
                suspicious.append(file_path)

            # Check for very long filenames (potential evasion)
            if len(filename) > 100:
                suspicious.append(file_path)

        return suspicious

    def _check_duplicate_files(self, apk_zip: zipfile.ZipFile, file_list: List[str]) -> Dict[str, Any]:
        """Check for duplicate files based on content hash."""
        file_hashes = {}
        duplicates = []

        try:
            for file_path in file_list[:100]:  # Limit to prevent excessive processing
                try:
                    content = apk_zip.read(file_path)
                    content_hash = hashlib.md5(content).hexdigest()

                    if content_hash in file_hashes:
                        duplicates.append(
                            {"original": file_hashes[content_hash], "duplicate": file_path, "hash": content_hash}
                        )
                    else:
                        file_hashes[content_hash] = file_path

                except Exception:
                    continue

        except Exception as e:
            self.logger.debug(f"Duplicate file check failed: {e}")

        return {"duplicates": duplicates, "total_unique_hashes": len(file_hashes)}
