#!/usr/bin/env python3
"""
Full Secret Management Implementation for AODS Security Framework

Migrated from EnhancedSecretExtractor with full capabilities:
- Multi-method extraction (decompiled, ZIP, binary strings, SQLite, DEX)
- Full pattern library for all major secret types
- Entropy-based validation and context analysis
- Credit card detection with Luhn algorithm validation
- Performance-optimized analysis with duration limits and resource management
"""

import logging
import os
import re
import time
import math
import zipfile
import sqlite3
import subprocess
import tempfile
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict

# MIGRATED: Add unified timeout manager support - removed signal/contextlib imports
from core.timeout import UnifiedTimeoutManager, TimeoutType

logger = logging.getLogger(__name__)


class SecretType(Enum):
    API_KEY = "api_key"
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    FIREBASE_KEY = "firebase_key"
    GOOGLE_API_KEY = "google_api_key"
    GITHUB_TOKEN = "github_token"
    JWT_TOKEN = "jwt_token"
    BEARER_TOKEN = "bearer_token"
    PRIVATE_KEY = "private_key"
    CERTIFICATE = "certificate"
    DATABASE_URL = "database_url"
    PASSWORD = "password"
    CREDIT_CARD = "credit_card"
    TEST_CREDENTIALS = "test_credentials"


class SecretSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecretFinding:
    title: str
    description: str
    secret_type: SecretType
    severity: SecretSeverity
    confidence: float
    location: Dict[str, Any]
    context: Dict[str, Any]
    exposure_risk: str
    entropy: float
    remediation: str
    validation_status: str = "unverified"
    extraction_method: str = "pattern_matching"


class ComprehensiveSecretManager:
    """
    Full secret detection with all EnhancedSecretExtractor capabilities.

    DUAL EXCELLENCE: Maximum secret detection + Maximum accuracy
    """

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Initialize patterns and validators
        self._init_secret_patterns()
        self._init_validators()

        # Statistics tracking
        self.stats = {
            "secrets_detected": 0,
            "files_processed": 0,
            "strings_analyzed": 0,
            "validation_performed": 0,
            "analysis_time_total": 0.0,
        }

        self.total_secrets_found = 0

        # MIGRATED: Initialize unified timeout manager
        self._timeout_manager = UnifiedTimeoutManager()

    def _init_secret_patterns(self):
        """Initialize full secret detection patterns."""
        self.secret_patterns = {
            SecretType.API_KEY: [
                r"(?i)(?:api[_-]?key|apikey)[\"'\s]*[:=][\"'\s]*([a-z0-9\-_]{20,100})",
                r"(?i)(?:key|token)[\"'\s]*[:=][\"'\s]*([a-z0-9\-_]{20,100})",
                r"\b[a-zA-Z0-9]{32}\b",
                r"\b[a-zA-Z0-9]{40}\b",
                r"(?i)API_KEY\s*[:=]\s*['\"`]?([a-zA-Z0-9\-_+/]{16,100})['\"`]?",
            ],
            SecretType.AWS_ACCESS_KEY: [
                r"AKIA[0-9A-Z]{16}",
                r"ASIA[0-9A-Z]{16}",
                r"AROA[0-9A-Z]{16}",
                r"(?i)aws[_-]?access[_-]?key[\"'\s]*[:=][\"'\s]*([A-Z0-9]{20})",
                r"(?i)AWS_ACCESS_KEY_ID[\"'\s]*[:=][\"'\s]*([A-Z0-9]{20})",
            ],
            SecretType.AWS_SECRET_KEY: [
                r"(?i)aws[_-]?secret[_-]?key[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{40})",
                r"\b[A-Za-z0-9/+=]{40}\b",
                r"(?i)AWS_SECRET_ACCESS_KEY[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{40})",
            ],
            SecretType.FIREBASE_KEY: [
                r"AIza[0-9A-Za-z\-_]{35}",
                r"(?i)firebase[_-]?key[\"'\s]*[:=][\"'\s]*([a-z0-9\-_]{20,})",
                r"https://([a-zA-Z0-9\-_]+)\.firebaseio\.com",
            ],
            SecretType.GITHUB_TOKEN: [
                r"ghp_[A-Za-z0-9]{36}",
                r"ghs_[A-Za-z0-9]{36}",
                r"github_pat_[A-Za-z0-9_]{82}",
                r"(?i)github[_-]?token[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9_]{40,})",
            ],
            SecretType.JWT_TOKEN: [
                r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
                r"(?i)jwt[_-]?token[\"'\s]*[:=][\"'\s]*([a-z0-9\-_.]{20,})",
            ],
            SecretType.PRIVATE_KEY: [
                r"-----BEGIN (RSA )?PRIVATE KEY-----",
                r"-----BEGIN ENCRYPTED PRIVATE KEY-----",
                r"-----BEGIN EC PRIVATE KEY-----",
                r"-----BEGIN OPENSSH PRIVATE KEY-----",
            ],
            SecretType.DATABASE_URL: [
                r"(?i)(mongodb|mysql|postgresql|postgres|sqlite)://[^\s\"'<>]+",
                r"(?i)database[_-]?url[\"'\s]*[:=][\"'\s]*([^\"'\s<>{}()]+)",
                r"jdbc:(mysql|postgresql|oracle|sqlserver)://[^\s\"'<>]+",
            ],
            SecretType.PASSWORD: [
                r"(?i)password[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{8,50})",
                r"(?i)passwd[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{8,50})",
                r"(?i)admin[_-]?password[\"'\s]*[:=][\"'\s]*([^\"'\s;,<>{}()]{8,50})",
            ],
            SecretType.CREDIT_CARD: [
                r"\b4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b",  # Visa
                r"\b5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b",  # MasterCard
                r"\b3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}\b",  # AmEx
            ],
            SecretType.TEST_CREDENTIALS: [
                r"\b(?:test123|admin123|password123|secret123|debug123)\b",
                r"\b(?:testuser|testpass|debugpass|devpass)\b",
            ],
        }

        # Compile patterns for performance
        self.compiled_patterns = {}
        for secret_type, patterns in self.secret_patterns.items():
            self.compiled_patterns[secret_type] = []
            for pattern in patterns:
                try:
                    self.compiled_patterns[secret_type].append(re.compile(pattern, re.MULTILINE | re.IGNORECASE))
                except re.error as e:
                    self.logger.warning(f"Failed to compile pattern {pattern}: {e}")

    def _init_validators(self):
        """Initialize validation functions."""
        self.validators = {
            SecretType.CREDIT_CARD: self._validate_credit_card_luhn,
            SecretType.AWS_ACCESS_KEY: self._validate_aws_key_format,
            SecretType.FIREBASE_KEY: self._validate_firebase_key,
            SecretType.JWT_TOKEN: self._validate_jwt_token,
        }

    # MIGRATED: Replaced custom signal-based timeout with UnifiedTimeoutManager

    def detect_secrets(self, target: Any, context: Any) -> List[SecretFinding]:
        """Full secret detection with multiple extraction methods."""
        analysis_start = time.time()
        findings = []

        try:
            if isinstance(target, str):
                if target.endswith(".apk"):
                    findings = self._extract_from_apk(target)
                elif os.path.isfile(target):
                    findings = self._extract_from_file(target)
                else:
                    findings = self._extract_from_content(target, "string_content")
            elif isinstance(target, dict):
                findings = self._extract_from_analysis_results(target)

            # Validate and filter findings
            validated_findings = self._validate_and_filter_findings(findings)

            # Update statistics
            analysis_time = time.time() - analysis_start
            self._update_stats(validated_findings, analysis_time)

            self.logger.info(
                f"🔑 Secret detection completed: {len(validated_findings)} secrets found in {analysis_time:.2f}s"
            )

        except Exception as e:
            self.logger.error(f"Secret detection failed: {e}")
            validated_findings = []

        return validated_findings

    def _extract_from_content(self, content: str, location: str) -> List[SecretFinding]:
        """Extract secrets from content string using pattern matching."""
        findings = []

        for secret_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                matches = pattern.finditer(content)
                for match in matches:
                    secret_value = match.group(1) if match.groups() else match.group(0)

                    # Skip if too short/long
                    if len(secret_value) < 8 or len(secret_value) > 200:
                        continue

                    # Calculate entropy
                    entropy = self._calculate_entropy(secret_value)

                    # Skip low-entropy secrets for certain types
                    if entropy < 4.0 and secret_type not in [SecretType.CREDIT_CARD, SecretType.TEST_CREDENTIALS]:
                        continue

                    # Create finding
                    finding = self._create_secret_finding(
                        secret_type=secret_type,
                        secret_value=secret_value,
                        location={"source": location, "position": match.start()},
                        entropy=entropy,
                        context={"matched_pattern": pattern.pattern, "full_match": match.group(0)},
                    )

                    findings.append(finding)
                    self.total_secrets_found += 1

                    # Limit for performance
                    if self.total_secrets_found >= 100:
                        break

        return findings

    def _extract_from_apk(self, apk_path: str) -> List[SecretFinding]:
        """Extract secrets from APK using multiple methods."""
        all_findings = []

        try:
            # Method 1: ZIP analysis
            zip_findings = self._extract_from_zip(apk_path)
            all_findings.extend(zip_findings)

            # Method 2: Binary strings
            binary_findings = self._extract_using_strings_command(apk_path)
            all_findings.extend(binary_findings)

            # Method 3: SQLite databases
            sqlite_findings = self._extract_from_sqlite_in_apk(apk_path)
            all_findings.extend(sqlite_findings)

        except Exception as e:
            self.logger.error(f"APK analysis failed: {e}")

        return all_findings

    def _extract_from_zip(self, apk_path: str) -> List[SecretFinding]:
        """Extract secrets from APK ZIP structure."""
        findings = []

        try:
            with zipfile.ZipFile(apk_path, "r") as apk_zip:
                for file_info in apk_zip.infolist():
                    if self._should_skip_file(file_info.filename, file_info.file_size):
                        continue

                    try:
                        # MIGRATED: Use unified timeout manager for per-file timeout protection
                        with self._timeout_manager.timeout_context(
                            operation_name="secret_analysis_apk", timeout_type=TimeoutType.ANALYSIS, timeout_seconds=5
                        ):
                            file_content = apk_zip.read(file_info.filename).decode("utf-8", errors="ignore")
                            file_findings = self._extract_from_content(file_content, file_info.filename)
                            findings.extend(file_findings)
                    except (UnicodeDecodeError, TimeoutError, zipfile.BadZipFile):
                        continue

        except Exception as e:
            self.logger.error(f"ZIP analysis failed: {e}")

        return findings

    def _extract_using_strings_command(self, apk_path: str) -> List[SecretFinding]:
        """Extract secrets using system 'strings' command."""
        findings = []

        try:
            # MIGRATED: Route subprocess duration limit through UnifiedTimeoutManager
            with self._timeout_manager.timeout_context(
                operation_name="strings_binary_analysis", timeout_type=TimeoutType.EXTERNAL, timeout_seconds=30
            ):
                result = subprocess.run(["strings", apk_path], capture_output=True, text=True, errors="ignore")

            if result.returncode == 0:
                content = result.stdout
                findings = self._extract_from_content(content, f"binary_strings:{apk_path}")

        except (TimeoutError, FileNotFoundError):
            pass

        return findings

    def _extract_from_sqlite_in_apk(self, apk_path: str) -> List[SecretFinding]:
        """Extract secrets from SQLite databases within APK."""
        findings = []

        try:
            with zipfile.ZipFile(apk_path, "r") as apk_zip:
                for file_info in apk_zip.infolist():
                    if file_info.filename.lower().endswith(".db"):
                        try:
                            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as temp_db:
                                temp_db.write(apk_zip.read(file_info.filename))
                                temp_db_path = temp_db.name

                            db_findings = self._extract_from_sqlite_db(temp_db_path, file_info.filename)
                            findings.extend(db_findings)

                            os.unlink(temp_db_path)

                        except Exception:
                            pass

        except Exception as e:
            self.logger.error(f"SQLite APK analysis failed: {e}")

        return findings

    def _extract_from_sqlite_db(self, db_path: str, source_name: str) -> List[SecretFinding]:
        """Extract secrets from SQLite database."""
        findings = []

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()

            for table in tables:
                table_name = table[0]
                # Sanitize table name from sqlite_master (defense-in-depth)
                import re as _re
                if not _re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', table_name):
                    continue
                try:
                    cursor.execute(f"SELECT * FROM [{table_name}]")
                    rows = cursor.fetchall()

                    for row in rows:
                        for value in row:
                            if isinstance(value, str) and len(value) > 8:
                                content_findings = self._extract_from_content(
                                    value, f"sqlite:{source_name}:{table_name}"
                                )
                                findings.extend(content_findings)

                except sqlite3.Error:
                    continue

            conn.close()

        except sqlite3.Error:
            pass

        return findings

    def _create_secret_finding(
        self,
        secret_type: SecretType,
        secret_value: str,
        location: Dict[str, Any],
        entropy: float,
        context: Dict[str, Any],
    ) -> SecretFinding:
        """Create standardized secret finding."""
        severity_mapping = {
            SecretType.PRIVATE_KEY: SecretSeverity.CRITICAL,
            SecretType.AWS_SECRET_KEY: SecretSeverity.CRITICAL,
            SecretType.API_KEY: SecretSeverity.HIGH,
            SecretType.AWS_ACCESS_KEY: SecretSeverity.HIGH,
            SecretType.FIREBASE_KEY: SecretSeverity.HIGH,
            SecretType.GITHUB_TOKEN: SecretSeverity.HIGH,
            SecretType.DATABASE_URL: SecretSeverity.HIGH,
            SecretType.CREDIT_CARD: SecretSeverity.HIGH,
            SecretType.JWT_TOKEN: SecretSeverity.MEDIUM,
            SecretType.PASSWORD: SecretSeverity.MEDIUM,
            SecretType.TEST_CREDENTIALS: SecretSeverity.LOW,
        }

        severity = severity_mapping.get(secret_type, SecretSeverity.MEDIUM)
        confidence = self._calculate_confidence(secret_type, secret_value, entropy)
        exposure_risk = "high" if severity in [SecretSeverity.CRITICAL, SecretSeverity.HIGH] else "medium"
        remediation = self._generate_remediation(secret_type)

        return SecretFinding(
            title=f"{secret_type.value.replace('_', ' ').title()} Detected",
            description=f"Potential {secret_type.value} found in application",
            secret_type=secret_type,
            severity=severity,
            confidence=confidence,
            location=location,
            context=context,
            exposure_risk=exposure_risk,
            entropy=entropy,
            remediation=remediation,
        )

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy."""
        if not text:
            return 0.0

        char_counts = defaultdict(int)
        for char in text:
            char_counts[char] += 1

        text_len = len(text)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)

        return entropy

    def _calculate_confidence(self, secret_type: SecretType, secret_value: str, entropy: float) -> float:
        """Calculate confidence score."""
        base_confidence = 0.7

        # Adjust for entropy
        if entropy >= 4.5:
            base_confidence += 0.2
        elif entropy >= 4.0:
            base_confidence += 0.1
        elif entropy < 3.0:
            base_confidence -= 0.2

        # Validate using specific validators
        if secret_type in self.validators:
            if self.validators[secret_type](secret_value):
                base_confidence += 0.1
            else:
                base_confidence -= 0.2

        return min(1.0, max(0.0, base_confidence))

    def _validate_credit_card_luhn(self, card_number: str) -> bool:
        """Validate credit card using Luhn algorithm."""
        card_number = re.sub(r"[\s\-]", "", card_number)

        if not card_number.isdigit() or len(card_number) < 13:
            return False

        total = 0
        reverse_digits = card_number[::-1]

        for i, digit in enumerate(reverse_digits):
            n = int(digit)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n = n // 10 + n % 10
            total += n

        return total % 10 == 0

    def _validate_aws_key_format(self, key: str) -> bool:
        """Validate AWS access key format."""
        return len(key) == 20 and key.startswith(("AKIA", "ASIA", "AROA", "AIDA"))

    def _validate_firebase_key(self, key: str) -> bool:
        """Validate Firebase API key format."""
        return key.startswith("AIza") and len(key) == 39

    def _validate_jwt_token(self, token: str) -> bool:
        """Validate JWT token format."""
        parts = token.split(".")
        return len(parts) >= 2 and all(len(part) > 0 for part in parts[:2])

    def _generate_remediation(self, secret_type: SecretType) -> str:
        """Generate remediation advice."""
        remediation_mapping = {
            SecretType.API_KEY: "Move API key to secure configuration",
            SecretType.AWS_ACCESS_KEY: "Rotate AWS credentials and use IAM roles",
            SecretType.PRIVATE_KEY: "Remove private key from code",
            SecretType.PASSWORD: "Remove hardcoded password",
            SecretType.DATABASE_URL: "Move to secure configuration",
            SecretType.CREDIT_CARD: "Remove and implement PCI-compliant storage",
            SecretType.GITHUB_TOKEN: "Revoke token and use GitHub Secrets",
        }

        return remediation_mapping.get(secret_type, "Remove hardcoded secret")

    def _should_skip_file(self, file_path: str, file_size: int = 0) -> bool:
        """Determine if file should be skipped."""
        # Skip large files
        if file_size > 1024 * 1024:  # 1MB
            return True

        # Skip binary files
        skip_extensions = {".png", ".jpg", ".jpeg", ".gif", ".so", ".a", ".o"}
        if any(file_path.lower().endswith(ext) for ext in skip_extensions):
            return True

        # Skip framework directories
        framework_patterns = ["com/google/android/gms/", "androidx/", "kotlin/"]
        file_lower = file_path.lower().replace("\\", "/")
        return any(pattern in file_lower for pattern in framework_patterns)

    def _validate_and_filter_findings(self, findings: List[SecretFinding]) -> List[SecretFinding]:
        """Validate and filter findings."""
        validated_findings = []

        for finding in findings:
            # Apply validation if available
            if finding.secret_type in self.validators:
                secret_value = finding.context.get("full_match", "")
                if self.validators[finding.secret_type](secret_value):
                    finding.validation_status = "valid"
                    finding.confidence = min(1.0, finding.confidence + 0.1)
                else:
                    finding.validation_status = "invalid"
                    finding.confidence = max(0.0, finding.confidence - 0.2)

            # Apply confidence threshold
            if finding.confidence >= 0.5:
                validated_findings.append(finding)

        return validated_findings

    def _extract_from_analysis_results(self, analysis_results: Dict[str, Any]) -> List[SecretFinding]:
        """Extract secrets from analysis results."""
        findings = []

        security_findings = analysis_results.get("security_findings", [])
        for finding in security_findings:
            description = finding.get("description", "").lower()
            if any(keyword in description for keyword in ["secret", "key", "token", "password"]):
                secret_finding = SecretFinding(
                    title="Secret in Security Finding",
                    description=finding.get("description", ""),
                    secret_type=SecretType.API_KEY,
                    severity=SecretSeverity.MEDIUM,
                    confidence=0.6,
                    location=finding.get("location", {}),
                    context={"source": "security_analysis"},
                    exposure_risk="medium",
                    entropy=3.5,
                    remediation="Review and secure identified secret",
                )
                findings.append(secret_finding)

        return findings

    def _extract_from_file(self, file_path: str) -> List[SecretFinding]:
        """Extract secrets from file."""
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                findings = self._extract_from_content(content, file_path)
        except Exception:
            pass

        return findings

    def _update_stats(self, findings: List[SecretFinding], analysis_time: float):
        """Update statistics."""
        self.stats["secrets_detected"] += len(findings)
        self.stats["files_processed"] += 1
        self.stats["analysis_time_total"] += analysis_time
        validated_count = len([f for f in findings if f.validation_status != "unverified"])
        self.stats["validation_performed"] += validated_count
