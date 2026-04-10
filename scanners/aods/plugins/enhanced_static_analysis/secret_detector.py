"""
Enhanced Static Analysis - Secret Detector Component

This module provides advanced secret detection capabilities using entropy analysis,
pattern matching, and machine learning techniques for identifying hardcoded credentials.
"""

import logging
import re
import math
from typing import Dict, List, Optional
from pathlib import Path

from .data_structures import (
    SecretAnalysis,
    SecretType,
    RiskLevel,
    AnalysisConfiguration,
    SecurityFinding,
    SeverityLevel,
    FindingCategory,
)
from .confidence_calculator import StaticAnalysisConfidenceCalculator


class SecretDetector:
    """Advanced secret detector using entropy analysis and pattern matching."""

    def __init__(self, config: Optional[AnalysisConfiguration] = None):
        """Initialize the secret detector with configuration."""
        self.config = config or AnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
        self.secret_patterns = {}
        self.compiled_patterns = {}
        self.confidence_calculator = StaticAnalysisConfidenceCalculator(config)
        self._load_secret_patterns()

    def _load_secret_patterns(self) -> None:
        """Load and compile secret detection patterns."""
        self.secret_patterns = {
            "api_key": {
                "patterns": [
                    r'(?i)api[_-]?key[\'"\s]*[=:][\'"\s]*([a-zA-Z0-9\-_]{10,})',
                    r'(?i)apikey[\'"\s]*[=:][\'"\s]*([a-zA-Z0-9\-_]{10,})',
                    r'(?i)api[_-]?secret[\'"\s]*[=:][\'"\s]*([a-zA-Z0-9\-_]{10,})',
                    r'(?i)client[_-]?secret[\'"\s]*[=:][\'"\s]*([a-zA-Z0-9\-_]{10,})',
                ],
                "min_entropy": 4.0,
                "risk_level": RiskLevel.HIGH,
            },
            "private_key": {
                "patterns": [
                    r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
                    r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----",
                    r"-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----",
                    r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
                ],
                "min_entropy": 5.0,
                "risk_level": RiskLevel.CRITICAL,
            },
            "database_url": {
                "patterns": [
                    r'(?i)(jdbc|mysql|postgresql|oracle|mongodb)://[^\s\'";]+',
                    r'(?i)database[_-]?url[\'"\s]*[=:][\'"\s]*([^\s\'";]+)',
                    r'(?i)db[_-]?url[\'"\s]*[=:][\'"\s]*([^\s\'";]+)',
                    r'(?i)connection[_-]?string[\'"\s]*[=:][\'"\s]*([^\s\'";]+)',
                ],
                "min_entropy": 3.5,
                "risk_level": RiskLevel.HIGH,
            },
            "password": {
                "patterns": [
                    r'(?i)password[\'"\s]*[=:][\'"\s]*([^\s\'";]{6,})',
                    r'(?i)passwd[\'"\s]*[=:][\'"\s]*([^\s\'";]{6,})',
                    r'(?i)pwd[\'"\s]*[=:][\'"\s]*([^\s\'";]{6,})',
                    r'(?i)secret[\'"\s]*[=:][\'"\s]*([^\s\'";]{8,})',
                ],
                "min_entropy": 3.0,
                "risk_level": RiskLevel.HIGH,
            },
            "token": {
                "patterns": [
                    r'(?i)token[\'"\s]*[=:][\'"\s]*([a-zA-Z0-9\-_\.]{20,})',
                    r'(?i)access[_-]?token[\'"\s]*[=:][\'"\s]*([a-zA-Z0-9\-_\.]{20,})',
                    r'(?i)auth[_-]?token[\'"\s]*[=:][\'"\s]*([a-zA-Z0-9\-_\.]{20,})',
                    r'(?i)bearer[\'"\s]*[=:][\'"\s]*([a-zA-Z0-9\-_\.]{20,})',
                ],
                "min_entropy": 4.5,
                "risk_level": RiskLevel.HIGH,
            },
            "certificate": {
                "patterns": [
                    r"-----BEGIN\s+CERTIFICATE-----",
                    r"-----BEGIN\s+PUBLIC\s+KEY-----",
                    r"-----BEGIN\s+X509\s+CERTIFICATE-----",
                ],
                "min_entropy": 5.0,
                "risk_level": RiskLevel.MEDIUM,
            },
            "generic": {
                "patterns": [
                    r'(?i)secret[\'"\s]*[=:][\'"\s]*([a-zA-Z0-9\-_\.]{15,})',
                    r'(?i)key[\'"\s]*[=:][\'"\s]*([a-zA-Z0-9\-_\.]{15,})',
                    r'(?i)credential[\'"\s]*[=:][\'"\s]*([a-zA-Z0-9\-_\.]{15,})',
                ],
                "min_entropy": 4.0,
                "risk_level": RiskLevel.MEDIUM,
            },
        }

        # Compile patterns for performance
        for secret_type, pattern_info in self.secret_patterns.items():
            self.compiled_patterns[secret_type] = []
            for pattern in pattern_info["patterns"]:
                try:
                    compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                    self.compiled_patterns[secret_type].append(compiled_pattern)
                except re.error as e:
                    self.logger.warning(f"Failed to compile pattern {pattern}: {e}")

    def analyze_content(self, content: str, file_path: str) -> List[SecretAnalysis]:
        """Analyze content for secrets using pattern matching and entropy analysis."""
        secrets = []

        if not content:
            return secrets

        # Apply secret detection patterns
        for secret_type, patterns in self.compiled_patterns.items():
            pattern_info = self.secret_patterns[secret_type]

            for pattern in patterns:
                matches = pattern.finditer(content)
                for match in matches:
                    # Extract the secret value
                    secret_value = match.group(1) if match.groups() else match.group(0)

                    # Skip if value is too short or common
                    if len(secret_value) < 6 or self._is_common_value(secret_value):
                        continue

                    # Calculate entropy
                    entropy = self.calculate_entropy(secret_value)

                    # Skip if entropy is too low
                    if entropy < pattern_info["min_entropy"]:
                        continue

                    # Calculate confidence
                    confidence = self._calculate_secret_confidence(secret_type, secret_value, entropy, file_path)

                    # Skip if confidence is below threshold
                    if confidence < self.config.secret_confidence_threshold:
                        continue

                    # Get line number
                    line_number = content[: match.start()].count("\n") + 1

                    # Create secret analysis
                    secret = SecretAnalysis(
                        id=f"secret_{secret_type}_{hash(secret_value)}_{line_number}",
                        value=secret_value,
                        pattern_type=SecretType(secret_type),
                        confidence=confidence,
                        entropy=entropy,
                        file_path=file_path,
                        line_number=line_number,
                        risk_level=pattern_info["risk_level"],
                        context=self._extract_context(content, match.start(), match.end()),
                    )

                    secrets.append(secret)

        # Additional entropy-based detection for high-entropy strings
        entropy_secrets = self._detect_high_entropy_secrets(content, file_path)
        secrets.extend(entropy_secrets)

        # IoC deobfuscation pass - detect obfuscated URLs, IPs, domains
        deobfuscated = self._deobfuscate_and_scan(content, file_path)
        secrets.extend(deobfuscated)

        # Remove duplicates and sort by confidence
        secrets = self._deduplicate_secrets(secrets)
        secrets.sort(key=lambda x: x.confidence, reverse=True)

        return secrets

    def _detect_high_entropy_secrets(self, content: str, file_path: str) -> List[SecretAnalysis]:
        """Detect high-entropy strings that might be secrets."""
        secrets = []

        # Pattern for potential secrets (alphanumeric strings)
        potential_secrets = re.finditer(r'["\']([a-zA-Z0-9\-_\.]{15,})["\']', content)

        for match in potential_secrets:
            secret_value = match.group(1)
            entropy = self.calculate_entropy(secret_value)

            # Check if entropy is high enough
            if entropy >= self.config.entropy_threshold:
                # Skip common patterns
                if self._is_common_value(secret_value):
                    continue

                # Calculate confidence based on entropy and context
                confidence = self._calculate_entropy_confidence(secret_value, entropy, file_path)

                if confidence >= self.config.secret_confidence_threshold:
                    line_number = content[: match.start()].count("\n") + 1

                    secret = SecretAnalysis(
                        id=f"high_entropy_{hash(secret_value)}_{line_number}",
                        value=secret_value,
                        pattern_type=SecretType.GENERIC,
                        confidence=confidence,
                        entropy=entropy,
                        file_path=file_path,
                        line_number=line_number,
                        risk_level=RiskLevel.MEDIUM,
                        context=self._extract_context(content, match.start(), match.end()),
                    )

                    secrets.append(secret)

        return secrets

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0

        # Count frequency of each character
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in char_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)

        return entropy

    def _calculate_secret_confidence(self, secret_type: str, value: str, entropy: float, file_path: str) -> float:
        """Calculate confidence score for a detected secret."""
        # Create a dummy finding for professional confidence calculation
        dummy_finding = SecurityFinding(
            id=f"secret_{secret_type}_{hash(value)}",
            title=f"{secret_type.replace('_', ' ').title()} Secret",
            description=f"Potential {secret_type} secret detected",
            severity=SeverityLevel.MEDIUM,
            category=FindingCategory.SECURITY_VULNERABILITY,
            file_path=file_path,
            line_number=1,
            confidence=0.0,  # Will be calculated
        )

        # Calculate professional confidence if available
        if hasattr(self, "confidence_calculator") and self.confidence_calculator:
            try:
                context = {
                    "secret_type": secret_type,
                    "entropy_score": entropy,
                    "value_length": len(value),
                    "file_extension": Path(file_path).suffix,
                    "file_type": self._determine_file_type(file_path),
                    "is_test_file": "test" in file_path.lower(),
                    "is_example_file": "example" in file_path.lower(),
                }
                return self.confidence_calculator.calculate_confidence(dummy_finding, context)
            except Exception as e:
                self.logger.warning(f"Professional confidence calculation failed: {e}")

        # Fallback to simple confidence calculation
        base_confidence = 0.5

        # Entropy-based confidence
        if entropy > 5.0:
            base_confidence += 0.3
        elif entropy > 4.0:
            base_confidence += 0.2
        elif entropy > 3.0:
            base_confidence += 0.1

        # Length-based confidence
        if len(value) > 30:
            base_confidence += 0.2
        elif len(value) > 20:
            base_confidence += 0.1

        # Pattern-specific adjustments
        if secret_type == "private_key":
            base_confidence += 0.3
        elif secret_type == "api_key":
            base_confidence += 0.2
        elif secret_type == "database_url":
            base_confidence += 0.2

        # File type adjustments
        if file_path.endswith(".properties"):
            base_confidence += 0.2
        elif file_path.endswith(".json"):
            base_confidence += 0.1
        elif "test" in file_path.lower():
            base_confidence -= 0.3
        elif "example" in file_path.lower():
            base_confidence -= 0.4

        # Character diversity check
        if self._has_good_character_diversity(value):
            base_confidence += 0.1

        return max(0.1, min(1.0, base_confidence))

    def _determine_file_type(self, file_path: str) -> str:
        """Determine the type of file for confidence calculation."""
        path = Path(file_path)
        extension = path.suffix.lower()

        if extension in [".java", ".kt", ".scala"]:
            return "source_code"
        elif extension in [".xml"]:
            return "manifest_files" if "manifest" in path.name.lower() else "resource_files"
        elif extension in [".properties", ".config", ".ini"]:
            return "config_files"
        elif extension in [".gradle", ".pro", ".cmake"]:
            return "build_files"
        elif extension in [".md", ".txt", ".rst"]:
            return "documentation"
        elif "test" in str(path):
            return "test_files"
        else:
            return "resource_files"

    def _calculate_entropy_confidence(self, value: str, entropy: float, file_path: str) -> float:
        """Calculate confidence for entropy-based detection."""
        # Base confidence from entropy
        base_confidence = (entropy - 3.0) / 3.0  # Normalize entropy to 0-1

        # Length penalty for very short strings
        if len(value) < 20:
            base_confidence *= 0.7

        # File type adjustments
        if "test" in file_path.lower():
            base_confidence *= 0.5
        elif "example" in file_path.lower():
            base_confidence *= 0.3

        return max(0.1, min(1.0, base_confidence))

    def _has_good_character_diversity(self, value: str) -> bool:
        """Check if string has good character diversity."""
        unique_chars = len(set(value))
        total_chars = len(value)

        # Good diversity if unique characters are > 50% of total
        return unique_chars / total_chars > 0.5

    def _is_common_value(self, value: str) -> bool:
        """Check if value is a common non-secret string."""
        common_values = {
            "password",
            "secret",
            "token",
            "apikey",
            "database",
            "localhost",
            "example",
            "test",
            "demo",
            "sample",
            "default",
            "admin",
            "user",
            "guest",
            "public",
            "private",
            "key",
            "value",
            "string",
            "data",
            "application",
            "service",
            "client",
            "server",
            "android",
            "google",
            "facebook",
            "twitter",
            "123456",
            "abcdef",
            "qwerty",
            "password123",
        }

        # Check if value is in common values (case insensitive)
        if value.lower() in common_values:
            return True

        # Check if value is all same character
        if len(set(value)) == 1:
            return True

        # Check if value is simple pattern
        if re.match(r"^[a-zA-Z]+$", value) and len(value) < 10:
            return True

        # Check if value is incremental (123456, abcdef)
        if self._is_incremental_pattern(value):
            return True

        return False

    def _is_incremental_pattern(self, value: str) -> bool:
        """Check if value follows an incremental pattern."""
        if len(value) < 4:
            return False

        # Check for numeric incremental
        if value.isdigit():
            digits = [int(c) for c in value]
            for i in range(1, len(digits)):
                if digits[i] != digits[i - 1] + 1:
                    break
            else:
                return True

        # Check for alphabetic incremental
        if value.isalpha():
            chars = [ord(c.lower()) for c in value]
            for i in range(1, len(chars)):
                if chars[i] != chars[i - 1] + 1:
                    break
            else:
                return True

        return False

    def _extract_context(self, content: str, start: int, end: int) -> str:
        """Extract context around a detected secret."""
        # Get 50 characters before and after
        context_start = max(0, start - 50)
        context_end = min(len(content), end + 50)

        context = content[context_start:context_end]

        # PERMANENT FIX: Disable redaction to reveal actual secret values
        # User requested to see actual password/secret values instead of [REDACTED]
        # No redaction applied - return full context with actual secret values

        return context.strip()

    # ------------------------------------------------------------------
    # IoC deobfuscation
    # ------------------------------------------------------------------

    # Pre-compiled patterns shared by all deobfuscation passes
    _IOC_URL_RE = re.compile(r"https?://[^\s'\"<>]{4,}", re.IGNORECASE)
    _IOC_IP_RE = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
    )
    _IOC_DOMAIN_RE = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|info|biz|xyz|top|ru|cn|tk|cc|pw|ws)\b",
        re.IGNORECASE,
    )

    # Regex for base64 candidates (min 20 chars to cut noise)
    _BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

    # Hex escape sequences  e.g. \x68\x74\x74\x70
    _HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")

    # Continuous hex string (even-length, >= 8 hex chars = 4 bytes)
    _HEX_CONTINUOUS_RE = re.compile(r"\b([0-9a-fA-F]{8,})\b")

    # Reversed URL prefixes we look for
    _REVERSED_PREFIXES = ("://ptth", "://sptth")

    def _deobfuscate_and_scan(self, content: str, file_path: str) -> List[SecretAnalysis]:
        """Run deobfuscation passes over *content* and return findings for hidden IoCs.

        Delegates to the shared ``DeobfuscationEngine`` (11 techniques) and filters
        results through IoC detection (URLs, IPs, domains).  This gives the secret
        detector all engine techniques (base64, hex, hex_escape, XOR single/multi-byte,
        ROT13, reverse, char_array, StringBuilder, unicode, string_concat) without
        duplicating code.
        """
        findings: List[SecretAnalysis] = []

        if not content:
            return findings

        try:
            from core.ml.deobfuscation import DeobfuscationEngine
        except ImportError:
            return findings

        engine = DeobfuscationEngine(max_results=50)
        deob_results = engine.deobfuscate_strings(content)

        for deob in deob_results:
            # Filter to IoC-relevant decoded strings (URLs, IPs, domains)
            if not self._contains_ioc(deob.decoded):
                continue

            line_number = self._line_number_at(content, deob.position) if deob.position >= 0 else 0
            findings.append(
                self._make_deobfuscation_finding(
                    original=deob.original,
                    decoded=deob.decoded,
                    method=deob.method,
                    confidence=deob.confidence,
                    file_path=file_path,
                    line_number=line_number,
                )
            )

        if findings:
            self.logger.info(
                "IoC deobfuscation: %d hidden indicator(s) found in %s",
                len(findings),
                file_path,
            )

        return findings

    # --- helpers for deobfuscation findings ----------------------------

    def _contains_ioc(self, text: str) -> bool:
        """Return True if *text* contains a URL, IP address, or domain."""
        if self._IOC_URL_RE.search(text):
            return True
        if self._IOC_IP_RE.search(text):
            return True
        if self._IOC_DOMAIN_RE.search(text):
            return True
        return False

    def _extract_ioc_value(self, text: str) -> str:
        """Return the first IoC (URL > IP > domain) found in *text*."""
        m = self._IOC_URL_RE.search(text)
        if m:
            return m.group(0)
        m = self._IOC_IP_RE.search(text)
        if m:
            return m.group(0)
        m = self._IOC_DOMAIN_RE.search(text)
        if m:
            return m.group(0)
        return text[:100]

    def _make_deobfuscation_finding(
        self,
        *,
        original: str,
        decoded: str,
        method: str,
        confidence: float,
        file_path: str,
        line_number: int,
        extra_meta: Optional[Dict] = None,
    ) -> SecretAnalysis:
        """Build a ``SecretAnalysis`` for a deobfuscated IoC."""
        truncated_original = original[:100]
        ioc_value = self._extract_ioc_value(decoded)
        meta = {
            "obfuscation_method": method,
            "original_obfuscated": truncated_original,
            "decoded_value": decoded[:200],
        }
        if extra_meta:
            meta.update(extra_meta)

        return SecretAnalysis(
            id=f"deobfuscated_{method}_{hash(ioc_value)}_{line_number}",
            value=ioc_value,
            pattern_type=SecretType.UNKNOWN,
            confidence=confidence,
            entropy=self.calculate_entropy(ioc_value),
            file_path=file_path,
            line_number=line_number,
            risk_level=RiskLevel.HIGH,
            context=f"[{method}] {truncated_original}",
            metadata=meta,
        )

    def _line_number_at(self, content: str, pos: int) -> int:
        """Return the 1-based line number for byte offset *pos*."""
        return content[:pos].count("\n") + 1

    def _deduplicate_secrets(self, secrets: List[SecretAnalysis]) -> List[SecretAnalysis]:
        """Remove duplicate secrets using unified deduplication framework."""
        if not secrets:
            return []

        try:
            # Import unified deduplication framework
            from core.unified_deduplication_framework import deduplicate_findings, DeduplicationStrategy

            # Convert secrets to dictionaries for unified deduplication
            dict_findings = []
            for secret in secrets:
                dict_finding = {
                    "title": f"Secret Detected: {secret.pattern_type.value}",
                    "file_path": secret.file_path,
                    "line_number": secret.line_number,
                    "severity": secret.risk_level.value if hasattr(secret, "risk_level") else "HIGH",
                    "category": "secret_detection",
                    "description": f"Potential {secret.pattern_type.value} found in file",
                    "secret_value": secret.value,
                    "pattern_type": secret.pattern_type.value,
                    "id": id(secret),
                }
                dict_findings.append(dict_finding)

            # Use unified deduplication framework with PRESERVATION strategy for secrets
            result = deduplicate_findings(dict_findings, DeduplicationStrategy.PRESERVATION)

            # Map deduplicated results back to original secrets
            unique_secret_ids = {f["id"] for f in result.unique_findings}
            unique_secrets = [s for s in secrets if id(s) in unique_secret_ids]

            # Log deduplication results for transparency
            if len(secrets) != len(unique_secrets):
                removed_count = len(secrets) - len(unique_secrets)
                logging.getLogger(__name__).info(
                    f"Unified deduplication: {len(secrets)} -> {len(unique_secrets)} "
                    f"({removed_count} duplicate secrets removed)"
                )

            return unique_secrets

        except Exception as e:
            # Fallback to original simple deduplication
            logging.getLogger(__name__).warning(f"Unified deduplication failed, using fallback: {e}")
            return self._deduplicate_secrets_fallback(secrets)

    def _deduplicate_secrets_fallback(self, secrets: List[SecretAnalysis]) -> List[SecretAnalysis]:
        """Fallback deduplication method (original logic)."""
        seen = set()
        unique_secrets = []

        for secret in secrets:
            # Create a unique identifier
            identifier = (secret.value, secret.file_path, secret.line_number)

            if identifier not in seen:
                seen.add(identifier)
                unique_secrets.append(secret)

        return unique_secrets

    def get_secret_summary(self, secrets: List[SecretAnalysis]) -> Dict[str, any]:
        """Generate summary of detected secrets."""
        summary = {
            "total_secrets": len(secrets),
            "by_type": {},
            "by_risk_level": {},
            "high_confidence_secrets": 0,
            "files_with_secrets": set(),
        }

        for secret in secrets:
            # Count by type
            secret_type = secret.pattern_type.value
            summary["by_type"][secret_type] = summary["by_type"].get(secret_type, 0) + 1

            # Count by risk level
            risk_level = secret.risk_level.value
            summary["by_risk_level"][risk_level] = summary["by_risk_level"].get(risk_level, 0) + 1

            # Count high confidence secrets
            if secret.confidence >= 0.8:
                summary["high_confidence_secrets"] += 1

            # Track files with secrets
            summary["files_with_secrets"].add(secret.file_path)

        summary["files_with_secrets"] = len(summary["files_with_secrets"])
        return summary
