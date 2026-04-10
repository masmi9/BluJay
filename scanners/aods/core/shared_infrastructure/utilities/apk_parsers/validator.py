"""Full APK validation system."""

import logging
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Dict, Union, Any

from core.xml_safe import safe_fromstring as _safe_fromstring

from ._types import APKValidationResult

logger = logging.getLogger(__name__)


class APKValidator:
    """
    Full APK validation system for security and integrity checks.

    Provides detailed validation of APK structure, signatures, manifest,
    and security characteristics. Used across AODS plugins for consistent
    APK validation logic.
    """

    def __init__(self):
        """Initialize APK validator."""
        self.logger = logging.getLogger(__name__)

        # Tool availability
        self.aapt_available = shutil.which("aapt") is not None
        self.keytool_available = shutil.which("keytool") is not None
        self.jarsigner_available = shutil.which("jarsigner") is not None

        # Validation patterns
        self.required_files = {"AndroidManifest.xml", "classes.dex"}
        self.suspicious_patterns = {
            "debug_keys": ["debug.keystore", "testkey"],
            "malicious_files": ["payload.dex", "exploit.so", "backdoor"],
            "development_artifacts": [".git", ".svn", "debug.apk"],
        }

        self.logger.info("APK validator initialized")

    def validate_apk(self, apk_path: Union[str, Path]) -> APKValidationResult:
        """
        Perform full APK validation.

        Args:
            apk_path: Path to APK file

        Returns:
            APKValidationResult indicating validation status
        """
        apk_path = Path(apk_path)

        try:
            # Check file existence and basic properties
            if not apk_path.exists():
                self.logger.error(f"APK file not found: {apk_path}")
                return APKValidationResult.INVALID_STRUCTURE

            if not apk_path.is_file():
                self.logger.error(f"Path is not a file: {apk_path}")
                return APKValidationResult.INVALID_STRUCTURE

            # Check file size (must be > 1KB)
            if apk_path.stat().st_size < 1024:
                self.logger.error(f"APK file too small: {apk_path.stat().st_size} bytes")
                return APKValidationResult.CORRUPTED

            # Validate ZIP structure
            if not self._validate_zip_structure(apk_path):
                return APKValidationResult.INVALID_STRUCTURE

            # Validate required APK files
            if not self._validate_required_files(apk_path):
                return APKValidationResult.MISSING_MANIFEST

            # Validate manifest structure
            if not self._validate_manifest_structure(apk_path):
                return APKValidationResult.MISSING_MANIFEST

            # Check for signature
            signature_status = self._validate_signatures(apk_path)
            if signature_status != APKValidationResult.VALID:
                return signature_status

            # Check for suspicious content
            if not self._check_security_indicators(apk_path):
                self.logger.warning(f"Suspicious content detected in APK: {apk_path}")
                # Continue validation but log warning

            return APKValidationResult.VALID

        except Exception as e:
            self.logger.error(f"APK validation failed: {e}")
            return APKValidationResult.CORRUPTED

    def validate_apk_structure(self, apk_path: Union[str, Path]) -> APKValidationResult:
        """Alias for validate_apk for backward compatibility."""
        return self.validate_apk(apk_path)

    def _validate_zip_structure(self, apk_path: Path) -> bool:
        """Validate APK ZIP file structure."""
        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                # Test ZIP integrity
                bad_file = apk.testzip()
                if bad_file is not None:
                    self.logger.error(f"Corrupted file in APK: {bad_file}")
                    return False

                # Check for empty APK
                if len(apk.namelist()) == 0:
                    self.logger.error("APK contains no files")
                    return False

                return True

        except zipfile.BadZipFile:
            self.logger.error(f"Invalid ZIP file: {apk_path}")
            return False
        except Exception as e:
            self.logger.error(f"ZIP validation error: {e}")
            return False

    def _validate_required_files(self, apk_path: Path) -> bool:
        """Validate presence of required APK files."""
        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                file_list = set(apk.namelist())

                # Check for required files
                missing_files = self.required_files - file_list
                if missing_files:
                    self.logger.error(f"Missing required files: {missing_files}")
                    return False

                return True

        except Exception as e:
            self.logger.error(f"Required files validation error: {e}")
            return False

    def _validate_manifest_structure(self, apk_path: Path) -> bool:
        """Validate AndroidManifest.xml structure."""
        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                # Read manifest
                manifest_data = apk.read("AndroidManifest.xml")

                # Check manifest size (must be > 100 bytes)
                if len(manifest_data) < 100:
                    self.logger.error("AndroidManifest.xml too small")
                    return False

                # Basic manifest validation using AAPT if available
                if self.aapt_available:
                    return self._validate_manifest_with_aapt(apk_path)

                # Basic binary XML check
                if manifest_data.startswith(b"\x03\x00"):
                    return True  # Binary XML format

                # Try parsing as text XML
                try:
                    _safe_fromstring(manifest_data.decode("utf-8"))
                    return True
                except Exception:
                    # Binary XML that we can't parse without AAPT
                    self.logger.warning("Binary manifest found but AAPT not available")
                    return True  # Assume valid

        except Exception as e:
            self.logger.error(f"Manifest validation error: {e}")
            return False

    def _validate_manifest_with_aapt(self, apk_path: Path) -> bool:
        """Validate manifest using AAPT tool."""
        try:
            result = subprocess.run(
                ["aapt", "dump", "badging", str(apk_path)], capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                self.logger.error(f"AAPT validation failed: {result.stderr}")
                return False

            # Check for required manifest elements
            output = result.stdout
            if "package:" not in output:
                self.logger.error("No package information in manifest")
                return False

            return True

        except subprocess.TimeoutExpired:
            self.logger.error("AAPT validation timeout")
            return False
        except Exception as e:
            self.logger.error(f"AAPT validation error: {e}")
            return False

    def _validate_signatures(self, apk_path: Path) -> APKValidationResult:
        """Validate APK signatures."""
        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                file_list = apk.namelist()

                # Check for META-INF directory
                meta_inf_files = [f for f in file_list if f.startswith("META-INF/")]
                if not meta_inf_files:
                    return APKValidationResult.UNSIGNED

                # Check for signature files
                signature_files = [f for f in meta_inf_files if f.endswith((".RSA", ".DSA", ".EC"))]
                if not signature_files:
                    return APKValidationResult.UNSIGNED

                # Check for certificate files
                cert_files = [f for f in meta_inf_files if f.endswith(".SF")]
                if not cert_files:
                    return APKValidationResult.INVALID_SIGNATURE

                # Validate signature using jarsigner if available
                if self.jarsigner_available:
                    return self._validate_signature_with_jarsigner(apk_path)

                return APKValidationResult.VALID

        except Exception as e:
            self.logger.error(f"Signature validation error: {e}")
            return APKValidationResult.INVALID_SIGNATURE

    def _validate_signature_with_jarsigner(self, apk_path: Path) -> APKValidationResult:
        """Validate signature using jarsigner tool."""
        try:
            result = subprocess.run(["jarsigner", "-verify", str(apk_path)], capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                return APKValidationResult.VALID
            else:
                self.logger.error(f"Signature verification failed: {result.stderr}")
                return APKValidationResult.INVALID_SIGNATURE

        except subprocess.TimeoutExpired:
            self.logger.error("Signature validation timeout")
            return APKValidationResult.INVALID_SIGNATURE
        except Exception as e:
            self.logger.error(f"Signature validation error: {e}")
            return APKValidationResult.INVALID_SIGNATURE

    def _check_security_indicators(self, apk_path: Path) -> bool:
        """Check for security indicators and suspicious content."""
        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                file_list = apk.namelist()

                # Check for suspicious files
                for category, patterns in self.suspicious_patterns.items():
                    for pattern in patterns:
                        suspicious_files = [f for f in file_list if pattern.lower() in f.lower()]
                        if suspicious_files:
                            self.logger.warning(f"Suspicious {category} detected: {suspicious_files}")
                            return False

                return True

        except Exception as e:
            self.logger.error(f"Security check error: {e}")
            return False

    def get_validation_details(self, apk_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Get detailed validation information.

        Args:
            apk_path: Path to APK file

        Returns:
            Dictionary with detailed validation results
        """
        apk_path = Path(apk_path)
        details = {
            "file_exists": apk_path.exists(),
            "file_size": apk_path.stat().st_size if apk_path.exists() else 0,
            "zip_valid": False,
            "required_files_present": False,
            "manifest_valid": False,
            "signature_status": "unknown",
            "suspicious_content": [],
            "validation_result": APKValidationResult.INVALID_STRUCTURE,
        }

        try:
            # Basic file validation
            if not details["file_exists"]:
                return details

            # ZIP structure
            details["zip_valid"] = self._validate_zip_structure(apk_path)
            if not details["zip_valid"]:
                return details

            # Required files
            details["required_files_present"] = self._validate_required_files(apk_path)

            # Manifest validation
            details["manifest_valid"] = self._validate_manifest_structure(apk_path)

            # Signature validation
            signature_result = self._validate_signatures(apk_path)
            details["signature_status"] = signature_result.value

            # Security checks
            security_ok = self._check_security_indicators(apk_path)
            if not security_ok:
                with zipfile.ZipFile(apk_path, "r") as apk:
                    file_list = apk.namelist()
                    for category, patterns in self.suspicious_patterns.items():
                        for pattern in patterns:
                            suspicious_files = [f for f in file_list if pattern.lower() in f.lower()]
                            if suspicious_files:
                                details["suspicious_content"].extend(suspicious_files)

            # Overall validation
            details["validation_result"] = self.validate_apk(apk_path)

        except Exception as e:
            self.logger.error(f"Validation details error: {e}")
            details["error"] = str(e)

        return details
