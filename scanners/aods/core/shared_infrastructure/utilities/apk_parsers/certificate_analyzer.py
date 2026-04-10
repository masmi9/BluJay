"""Certificate analysis and validation for APK signing certificates."""

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

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    x509 = None
    default_backend = None


logger = logging.getLogger(__name__)


@dataclass
class CertificateInfo:
    """Container for certificate information."""

    subject: str
    issuer: str
    serial_number: str
    version: int
    signature_algorithm: str
    not_before: str
    not_after: str
    is_self_signed: bool
    key_size: int
    fingerprint_md5: str
    fingerprint_sha1: str
    fingerprint_sha256: str
    extensions: Dict[str, Any] = field(default_factory=dict)
    is_valid: bool = True
    validation_errors: List[str] = field(default_factory=list)


class CertificateAnalyzer:
    """
    Full certificate analysis and validation.

    Provides detailed certificate inspection, validation, and security analysis
    for APK signing certificates with enhanced security assessment capabilities.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.crypto_available = CRYPTOGRAPHY_AVAILABLE

        # Security thresholds
        self.min_key_size = 2048
        self.weak_algorithms = {"md5", "sha1", "md2", "md4"}
        self.deprecated_algorithms = {"sha1withRSA", "md5withRSA", "md2withRSA"}

    def analyze_apk_certificates(self, apk_path: Path) -> List[CertificateInfo]:
        """
        Analyze all certificates in an APK file.

        Args:
            apk_path: Path to APK file

        Returns:
            List of CertificateInfo objects for all certificates found
        """
        certificates = []

        try:
            with zipfile.ZipFile(apk_path, "r") as apk_zip:
                # Look for certificate files in META-INF
                cert_files = [
                    f
                    for f in apk_zip.namelist()
                    if f.startswith("META-INF/") and (f.endswith(".RSA") or f.endswith(".DSA") or f.endswith(".EC"))
                ]

                for cert_file in cert_files:
                    try:
                        cert_data = apk_zip.read(cert_file)
                        cert_info = self._parse_certificate_data(cert_data)
                        if cert_info:
                            certificates.append(cert_info)
                    except Exception as e:
                        self.logger.warning(f"Failed to parse certificate {cert_file}: {e}")

        except Exception as e:
            self.logger.error(f"Failed to analyze certificates in {apk_path}: {e}")

        return certificates

    def validate_certificate_security(self, cert_info: CertificateInfo) -> Dict[str, Any]:
        """
        Validate certificate security properties.

        Args:
            cert_info: Certificate information to validate

        Returns:
            Security validation results
        """
        validation = {"is_secure": True, "security_score": 100, "issues": [], "recommendations": []}

        # Check key size
        if cert_info.key_size < self.min_key_size:
            validation["is_secure"] = False
            validation["security_score"] -= 30
            validation["issues"].append(f"Weak key size: {cert_info.key_size} bits")
            validation["recommendations"].append(f"Use at least {self.min_key_size}-bit keys")

        # Check signature algorithm
        algorithm = cert_info.signature_algorithm.lower()
        if any(weak in algorithm for weak in self.weak_algorithms):
            validation["is_secure"] = False
            validation["security_score"] -= 40
            validation["issues"].append(f"Weak signature algorithm: {cert_info.signature_algorithm}")
            validation["recommendations"].append("Use SHA-256 or stronger signature algorithms")

        elif algorithm in self.deprecated_algorithms:
            validation["security_score"] -= 20
            validation["issues"].append(f"Deprecated signature algorithm: {cert_info.signature_algorithm}")
            validation["recommendations"].append("Migrate to SHA-256 or stronger algorithms")

        # Check certificate validity period
        try:
            import datetime

            not_after = datetime.datetime.strptime(cert_info.not_after, "%Y-%m-%d %H:%M:%S")
            days_until_expiry = (not_after - datetime.datetime.now()).days

            if days_until_expiry < 0:
                validation["is_secure"] = False
                validation["security_score"] -= 50
                validation["issues"].append("Certificate has expired")
                validation["recommendations"].append("Renew the certificate immediately")
            elif days_until_expiry < 30:
                validation["security_score"] -= 15
                validation["issues"].append(f"Certificate expires soon: {days_until_expiry} days")
                validation["recommendations"].append("Plan certificate renewal")
        except Exception:
            validation["issues"].append("Could not validate certificate expiry")

        # Check for self-signed certificates
        if cert_info.is_self_signed:
            validation["security_score"] -= 10
            validation["issues"].append("Certificate is self-signed")
            validation["recommendations"].append("Consider using CA-signed certificates for production")

        return validation

    def _parse_certificate_data(self, cert_data: bytes) -> Optional[CertificateInfo]:
        """Parse certificate data and extract information."""
        if not self.crypto_available:
            return self._parse_certificate_fallback(cert_data)

        try:
            # Try to parse as PKCS#7/PKCS#12 first
            from cryptography.hazmat.primitives.serialization import pkcs7

            try:
                # Try PKCS#7 format first
                cert_collection = pkcs7.load_der_pkcs7_certificates(cert_data)
                if cert_collection:
                    certificate = cert_collection[0]
                else:
                    return None
            except Exception:
                # Try direct certificate parsing
                try:
                    certificate = x509.load_der_x509_certificate(cert_data, default_backend())
                except Exception:
                    # Try PEM format
                    try:
                        certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
                    except Exception:
                        return None

            return self._extract_certificate_info(certificate)

        except Exception as e:
            self.logger.warning(f"Failed to parse certificate: {e}")
            return self._parse_certificate_fallback(cert_data)

    def _extract_certificate_info(self, certificate) -> CertificateInfo:
        """Extract information from a parsed certificate."""
        try:
            from cryptography.hazmat.primitives import serialization

            # Basic certificate information
            subject = certificate.subject.rfc4514_string()
            issuer = certificate.issuer.rfc4514_string()
            serial_number = str(certificate.serial_number)
            version = certificate.version.value
            signature_algorithm = certificate.signature_algorithm_oid._name

            # Validity period
            not_before = certificate.not_valid_before.strftime("%Y-%m-%d %H:%M:%S")
            not_after = certificate.not_valid_after.strftime("%Y-%m-%d %H:%M:%S")

            # Check if self-signed
            is_self_signed = subject == issuer

            # Extract public key information
            public_key = certificate.public_key()
            key_size = public_key.key_size if hasattr(public_key, "key_size") else 0

            # Generate fingerprints
            cert_der = certificate.public_bytes(serialization.Encoding.DER)
            fingerprint_md5 = hashlib.md5(cert_der).hexdigest()
            fingerprint_sha1 = hashlib.sha1(cert_der).hexdigest()
            fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()

            # Extract extensions
            extensions = {}
            for ext in certificate.extensions:
                try:
                    extensions[ext.oid._name] = str(ext.value)
                except Exception:
                    extensions[ext.oid._name] = "Could not parse extension"

            return CertificateInfo(
                subject=subject,
                issuer=issuer,
                serial_number=serial_number,
                version=version,
                signature_algorithm=signature_algorithm,
                not_before=not_before,
                not_after=not_after,
                is_self_signed=is_self_signed,
                key_size=key_size,
                fingerprint_md5=fingerprint_md5,
                fingerprint_sha1=fingerprint_sha1,
                fingerprint_sha256=fingerprint_sha256,
                extensions=extensions,
            )

        except Exception as e:
            self.logger.error(f"Failed to extract certificate info: {e}")
            return None

    def _parse_certificate_fallback(self, cert_data: bytes) -> Optional[CertificateInfo]:
        """Fallback certificate parsing when cryptography library is unavailable."""
        try:
            # Basic parsing using openssl command if available
            if shutil.which("openssl"):
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file.write(cert_data)
                    temp_path = temp_file.name

                try:
                    # Extract certificate info using openssl
                    cmd = ["openssl", "pkcs7", "-inform", "DER", "-in", temp_path, "-print_certs", "-text"]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

                    if result.returncode == 0:
                        return self._parse_openssl_output(result.stdout)

                finally:
                    os.unlink(temp_path)

            # Minimal fallback - just compute hashes
            return CertificateInfo(
                subject="Unknown (parsing failed)",
                issuer="Unknown (parsing failed)",
                serial_number="Unknown",
                version=0,
                signature_algorithm="Unknown",
                not_before="Unknown",
                not_after="Unknown",
                is_self_signed=False,
                key_size=0,
                fingerprint_md5=hashlib.md5(cert_data).hexdigest(),
                fingerprint_sha1=hashlib.sha1(cert_data).hexdigest(),
                fingerprint_sha256=hashlib.sha256(cert_data).hexdigest(),
                is_valid=False,
                validation_errors=["Certificate parsing failed - cryptography library unavailable"],
            )

        except Exception as e:
            self.logger.error(f"Fallback certificate parsing failed: {e}")
            return None

    def _parse_openssl_output(self, output: str) -> Optional[CertificateInfo]:
        """Parse openssl command output to extract certificate information."""
        try:
            # Extract basic information using regex
            subject_match = re.search(r"Subject:\s*(.+)", output)
            issuer_match = re.search(r"Issuer:\s*(.+)", output)
            serial_match = re.search(r"Serial Number:\s*([a-fA-F0-9:]+)", output)
            algorithm_match = re.search(r"Signature Algorithm:\s*(.+)", output)
            not_before_match = re.search(r"Not Before:\s*(.+)", output)
            not_after_match = re.search(r"Not After:\s*(.+)", output)

            subject = subject_match.group(1).strip() if subject_match else "Unknown"
            issuer = issuer_match.group(1).strip() if issuer_match else "Unknown"

            return CertificateInfo(
                subject=subject,
                issuer=issuer,
                serial_number=serial_match.group(1) if serial_match else "Unknown",
                version=3,  # Assume X.509 v3
                signature_algorithm=algorithm_match.group(1) if algorithm_match else "Unknown",
                not_before=not_before_match.group(1) if not_before_match else "Unknown",
                not_after=not_after_match.group(1) if not_after_match else "Unknown",
                is_self_signed=subject == issuer,
                key_size=0,  # Cannot determine from openssl text output
                fingerprint_md5="",
                fingerprint_sha1="",
                fingerprint_sha256="",
                is_valid=True,
                validation_errors=["Limited parsing - using openssl fallback"],
            )

        except Exception as e:
            self.logger.error(f"Failed to parse openssl output: {e}")
            return None
