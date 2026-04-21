#!/usr/bin/env python3
"""
Crypto Analysis Components - Modular Implementation
==================================================

Modular components for crypto analysis following Interface Segregation principle.
These components provide specialized functionality for pattern matching,
vulnerability assessment, and finding enrichment.

Migrates and enhances component functionality from CryptographicSecurityAnalyzer
while maintaining clean separation of concerns.
"""

import re
import logging
import time
from typing import Dict, List, Any, Optional, Tuple

from core.execution.interfaces.crypto_interfaces import (
    ICryptoPatternMatcher,
    ICryptoVulnerabilityAssessor,
    ICryptoFindingEnricher,
    CryptoPattern,
    CryptoFinding,
    CryptoContext,
    CryptoVulnerabilityType,
    CryptoSeverityLevel,
    CryptoAnalysisException,
)

logger = logging.getLogger(__name__)


class CryptoPatternLibrary:
    """
    Full library of cryptographic patterns.

    Migrates pattern definitions from CryptographicSecurityAnalyzer._initialize_vulnerability_patterns
    with enhanced organization and maintainability.
    """

    @staticmethod
    def get_all_patterns() -> Dict[str, List[CryptoPattern]]:
        """Get all crypto patterns organized by category."""
        return {
            "cipher": CryptoPatternLibrary.get_cipher_patterns(),
            "hash": CryptoPatternLibrary.get_hash_patterns(),
            "key_management": CryptoPatternLibrary.get_key_patterns(),
            "ssl_tls": CryptoPatternLibrary.get_ssl_patterns(),
            "randomness": CryptoPatternLibrary.get_randomness_patterns(),
            "secrets": CryptoPatternLibrary.get_secret_patterns(),
            "certificates": CryptoPatternLibrary.get_certificate_patterns(),
            "custom_crypto": CryptoPatternLibrary.get_custom_crypto_patterns(),
        }

    @staticmethod
    def get_cipher_patterns() -> List[CryptoPattern]:
        """Get cipher-related patterns (migrated from original)."""
        return [
            CryptoPattern(
                name="cipher_getInstance",
                pattern=r'Cipher\.getInstance\s*\(\s*["\']([^"\']+)["\']\s*\)',
                vulnerability_type=CryptoVulnerabilityType.WEAK_CIPHER,
                severity=CryptoSeverityLevel.HIGH,
                description="Cipher instantiation detected",
                recommendation="Verify strong cipher algorithm is used",
            ),
            CryptoPattern(
                name="des_usage",
                pattern=r'(?:Cipher|SecretKeyFactory)\.getInstance\s*\(\s*["\'](?:DES|DESede|3DES|TripleDES)[/"\']',
                vulnerability_type=CryptoVulnerabilityType.WEAK_CIPHER,
                severity=CryptoSeverityLevel.CRITICAL,
                description="Deprecated DES cipher detected",
                recommendation="Replace with AES-256",
            ),
            CryptoPattern(
                name="rc4_usage",
                pattern=r'(?:Cipher\.getInstance\s*\(\s*["\'](?:RC4|ARC4|ARCFOUR)["\']|new\s+RC4\s*\()',
                vulnerability_type=CryptoVulnerabilityType.WEAK_CIPHER,
                severity=CryptoSeverityLevel.CRITICAL,
                description="Insecure RC4 cipher detected",
                recommendation="Replace with AES or ChaCha20",
            ),
            CryptoPattern(
                name="ecb_mode",
                pattern=r'Cipher\.getInstance\s*\(\s*["\'][^"\']*ECB[^"\']*["\']\s*\)',
                vulnerability_type=CryptoVulnerabilityType.CIPHER_MODE_ISSUE,
                severity=CryptoSeverityLevel.HIGH,
                description="Insecure ECB mode detected",
                recommendation="Use GCM, CBC, or CTR mode",
            ),
        ]

    @staticmethod
    def get_hash_patterns() -> List[CryptoPattern]:
        """Get hash-related patterns (migrated from original)."""
        return [
            CryptoPattern(
                name="md5_usage",
                pattern=r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']\s*\)',
                vulnerability_type=CryptoVulnerabilityType.WEAK_HASH,
                severity=CryptoSeverityLevel.CRITICAL,
                description="Insecure MD5 hash detected",
                recommendation="Replace with SHA-256 or SHA-3",
            ),
            CryptoPattern(
                name="sha1_usage",
                pattern=r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']\s*\)',
                vulnerability_type=CryptoVulnerabilityType.WEAK_HASH,
                severity=CryptoSeverityLevel.HIGH,
                description="Deprecated SHA-1 hash detected",
                recommendation="Replace with SHA-256 or stronger",
            ),
            CryptoPattern(
                name="message_digest",
                pattern=r'MessageDigest\.getInstance\s*\(\s*["\']([^"\']+)["\']\s*\)',
                vulnerability_type=CryptoVulnerabilityType.WEAK_HASH,
                severity=CryptoSeverityLevel.MEDIUM,
                description="Hash algorithm usage detected",
                recommendation="Verify strong hash algorithm",
            ),
        ]

    @staticmethod
    def get_key_patterns() -> List[CryptoPattern]:
        """Get key management patterns."""
        return [
            CryptoPattern(
                name="hardcoded_key",
                pattern=r'(?:key|password|secret)\s*[:=]\s*["\']([a-zA-Z0-9+/=]{16,})["\']\s*',
                vulnerability_type=CryptoVulnerabilityType.HARDCODED_SECRET,
                severity=CryptoSeverityLevel.CRITICAL,
                description="Hardcoded cryptographic key detected",
                recommendation="Use secure key storage",
            ),
            CryptoPattern(
                name="key_generator",
                pattern=r'KeyGenerator\.getInstance\s*\(\s*["\']([^"\']+)["\']\s*\)',
                vulnerability_type=CryptoVulnerabilityType.WEAK_KEY,
                severity=CryptoSeverityLevel.MEDIUM,
                description="Key generation detected",
                recommendation="Verify strong key generation",
            ),
        ]

    @staticmethod
    def get_ssl_patterns() -> List[CryptoPattern]:
        """Get SSL/TLS patterns."""
        return [
            CryptoPattern(
                name="ssl_context",
                pattern=r'SSLContext\.getInstance\s*\(\s*["\']([^"\']+)["\']\s*\)',
                vulnerability_type=CryptoVulnerabilityType.INSECURE_SSL,
                severity=CryptoSeverityLevel.HIGH,
                description="SSL context configuration detected",
                recommendation="Use TLS 1.2 or higher",
            )
        ]

    @staticmethod
    def get_randomness_patterns() -> List[CryptoPattern]:
        """Get randomness patterns."""
        return [
            CryptoPattern(
                name="weak_random",
                pattern=r"Math\.random\(\)",
                vulnerability_type=CryptoVulnerabilityType.POOR_RANDOMNESS,
                severity=CryptoSeverityLevel.MEDIUM,
                description="Weak random number generation",
                recommendation="Use SecureRandom",
            )
        ]

    @staticmethod
    def get_secret_patterns() -> List[CryptoPattern]:
        """Get secret detection patterns."""
        return [
            CryptoPattern(
                name="api_key",
                pattern=r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']\s*',
                vulnerability_type=CryptoVulnerabilityType.HARDCODED_SECRET,
                severity=CryptoSeverityLevel.HIGH,
                description="Hardcoded API key detected",
                recommendation="Use secure configuration",
            )
        ]

    @staticmethod
    def get_certificate_patterns() -> List[CryptoPattern]:
        """Get certificate validation patterns."""
        return [
            CryptoPattern(
                name="trust_all_certs",
                pattern=r"TrustAllCerts|X509TrustManager.*checkClientTrusted.*\{\s*\}",
                vulnerability_type=CryptoVulnerabilityType.CERTIFICATE_ISSUE,
                severity=CryptoSeverityLevel.CRITICAL,
                description="Certificate validation bypass",
                recommendation="Implement proper certificate validation",
            )
        ]

    @staticmethod
    def get_custom_crypto_patterns() -> List[CryptoPattern]:
        """Get custom crypto implementation patterns."""
        return [
            CryptoPattern(
                name="custom_cipher",
                pattern=r"class\s+\w*(?:Cipher|Crypto|Encrypt)\w*",
                vulnerability_type=CryptoVulnerabilityType.CUSTOM_CRYPTO_FLAW,
                severity=CryptoSeverityLevel.MEDIUM,
                description="Custom crypto implementation detected",
                recommendation="Use well-tested libraries",
            )
        ]


class CryptoPatternMatcher(ICryptoPatternMatcher):
    """
    Pattern matcher for cryptographic vulnerabilities.

    Migrates pattern matching logic from CryptographicSecurityAnalyzer
    with enhanced performance and accuracy.
    """

    def __init__(self):
        """Initialize crypto pattern matcher."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._compiled_patterns: Dict[str, re.Pattern] = {}

    def match_patterns(self, content: str, patterns: List[CryptoPattern]) -> List[Tuple[CryptoPattern, re.Match]]:
        """
        Match patterns against content.

        Migrates pattern matching from original analyzer with performance optimizations.
        """
        matches = []

        for pattern in patterns:
            try:
                # Compile and cache pattern
                compiled_pattern = self._get_compiled_pattern(pattern)

                # Find all matches
                for match in compiled_pattern.finditer(content):
                    # Validate match context if required
                    if pattern.context_required and not self._validate_context(content, match, pattern):
                        continue

                    matches.append((pattern, match))

            except Exception as e:
                self.logger.warning(f"Pattern matching failed for {pattern.name}: {e}")

        self.logger.debug(f"Found {len(matches)} pattern matches")
        return matches

    def extract_context(self, content: str, match: re.Match, lines_before: int = 2, lines_after: int = 2) -> str:
        """
        Extract context around a match.

        Migrates context extraction from CryptographicSecurityAnalyzer._extract_context_around_match.
        """
        try:
            lines = content.split("\n")
            match_line = content[: match.start()].count("\n")

            start_line = max(0, match_line - lines_before)
            end_line = min(len(lines), match_line + lines_after + 1)

            context_lines = lines[start_line:end_line]

            # Highlight the match line
            if match_line - start_line < len(context_lines):
                match_line_idx = match_line - start_line
                context_lines[match_line_idx] = f">>> {context_lines[match_line_idx]}"

            return "\n".join(context_lines)

        except Exception as e:
            self.logger.warning(f"Context extraction failed: {e}")
            return match.group(0)

    def _get_compiled_pattern(self, pattern: CryptoPattern) -> re.Pattern:
        """Get compiled pattern with caching."""
        pattern_key = f"{pattern.name}_{hash(str(pattern.pattern))}"

        if pattern_key not in self._compiled_patterns:
            try:
                self._compiled_patterns[pattern_key] = pattern.compile_pattern()
            except Exception as e:
                self.logger.error(f"Pattern compilation failed for {pattern.name}: {e}")
                raise CryptoAnalysisException(f"Pattern compilation failed: {e}")

        return self._compiled_patterns[pattern_key]

    def _validate_context(self, content: str, match: re.Match, pattern: CryptoPattern) -> bool:
        """Validate that match occurs in appropriate context."""
        # Extract surrounding context
        context = self.extract_context(content, match, lines_before=5, lines_after=5)
        context_lower = context.lower()

        # Check for crypto-related keywords
        crypto_keywords = ["crypto", "encrypt", "decrypt", "cipher", "hash", "key", "ssl", "tls"]

        return any(keyword in context_lower for keyword in crypto_keywords)


class CryptoVulnerabilityAssessor(ICryptoVulnerabilityAssessor):
    """
    Vulnerability assessor for cryptographic findings.

    Migrates vulnerability assessment logic from CryptographicSecurityAnalyzer
    with enhanced confidence calculation and severity assessment.
    """

    def __init__(self):
        """Initialize crypto vulnerability assessor."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # Algorithm risk mappings (migrated from original)
        self.algorithm_risks = {
            "critical": ["des", "3des", "md5", "sha1", "rc4"],
            "high": ["sha-1", "rsa-1024"],
            "medium": ["aes-128", "rsa-2048"],
            "low": ["aes-256", "rsa-4096", "sha-256", "sha-512"],
        }

    def assess_vulnerability(
        self, pattern: CryptoPattern, match: re.Match, context: str, full_content: str
    ) -> Tuple[CryptoSeverityLevel, float]:
        """
        Assess vulnerability severity and confidence.

        Migrates assessment logic from various analyzer methods with enhancements.
        """
        try:
            # Start with pattern defaults
            severity = pattern.severity
            confidence = pattern.confidence_base

            # Extract algorithm if available
            algorithm = self._extract_algorithm_from_match(match)

            # Adjust based on algorithm risk
            if algorithm:
                severity, confidence = self._adjust_for_algorithm_risk(algorithm, severity, confidence)

            # Adjust based on context
            context_confidence = self._assess_context_confidence(context, match, pattern)
            confidence *= context_confidence

            # Adjust based on file context
            file_confidence = self._assess_file_context_confidence(full_content)
            confidence *= file_confidence

            # Ensure confidence is within bounds
            confidence = max(0.0, min(1.0, confidence))

            self.logger.debug(f"Assessed {pattern.name}: {severity.value}, confidence={confidence:.2f}")

            return severity, confidence

        except Exception as e:
            self.logger.warning(f"Vulnerability assessment failed: {e}")
            return pattern.severity, pattern.confidence_base

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence score based on evidence.

        Migrates confidence calculation from CryptographicSecurityAnalyzer._calculate_secret_confidence.
        """
        base_confidence = evidence.get("base_confidence", 0.5)

        # Adjust based on evidence factors
        confidence_adjustments = 0.0

        # Algorithm evidence
        if "algorithm" in evidence:
            algorithm = evidence["algorithm"].lower()
            if algorithm in self.algorithm_risks["critical"]:
                confidence_adjustments += 0.3
            elif algorithm in self.algorithm_risks["high"]:
                confidence_adjustments += 0.2
            elif algorithm in self.algorithm_risks["medium"]:
                confidence_adjustments += 0.1

        # Context evidence
        if "context_score" in evidence:
            confidence_adjustments += evidence["context_score"] * 0.2

        # Pattern match quality
        if "match_quality" in evidence:
            confidence_adjustments += evidence["match_quality"] * 0.1

        final_confidence = base_confidence + confidence_adjustments
        return max(0.0, min(1.0, final_confidence))

    def _extract_algorithm_from_match(self, match: re.Match) -> Optional[str]:
        """Extract algorithm name from match."""
        # Try capture groups first
        for group in match.groups():
            if group and isinstance(group, str):
                algorithm = group.strip().strip("'\"")
                if algorithm and len(algorithm) > 1:
                    return algorithm.lower()

        # Fallback to pattern analysis
        match_text = match.group(0).lower()
        for risk_level, algorithms in self.algorithm_risks.items():
            for algorithm in algorithms:
                if algorithm in match_text:
                    return algorithm

        return None

    def _adjust_for_algorithm_risk(
        self, algorithm: str, base_severity: CryptoSeverityLevel, base_confidence: float
    ) -> Tuple[CryptoSeverityLevel, float]:
        """Adjust severity and confidence based on algorithm risk."""
        algorithm_lower = algorithm.lower()

        # Check risk levels
        if algorithm_lower in self.algorithm_risks["critical"]:
            return CryptoSeverityLevel.CRITICAL, min(base_confidence + 0.3, 1.0)
        elif algorithm_lower in self.algorithm_risks["high"]:
            return CryptoSeverityLevel.HIGH, min(base_confidence + 0.2, 1.0)
        elif algorithm_lower in self.algorithm_risks["medium"]:
            return CryptoSeverityLevel.MEDIUM, min(base_confidence + 0.1, 1.0)
        elif algorithm_lower in self.algorithm_risks["low"]:
            return CryptoSeverityLevel.LOW, base_confidence

        return base_severity, base_confidence

    def _assess_context_confidence(self, context: str, match: re.Match, pattern: CryptoPattern) -> float:
        """Assess confidence based on surrounding context."""
        context_lower = context.lower()
        confidence_multiplier = 1.0

        # Positive indicators
        positive_keywords = ["crypto", "encrypt", "decrypt", "cipher", "security", "password", "key"]
        positive_count = sum(1 for keyword in positive_keywords if keyword in context_lower)
        confidence_multiplier += positive_count * 0.1

        # Negative indicators
        negative_keywords = ["test", "example", "demo", "sample", "comment"]
        negative_count = sum(1 for keyword in negative_keywords if keyword in context_lower)
        confidence_multiplier -= negative_count * 0.2

        return max(0.1, confidence_multiplier)

    def _assess_file_context_confidence(self, full_content: str) -> float:
        """Assess confidence based on overall file context."""
        content_lower = full_content.lower()
        confidence_multiplier = 1.0

        # Check for crypto imports/packages
        crypto_imports = ["javax.crypto", "java.security", "org.bouncycastle"]
        if any(imp in content_lower for imp in crypto_imports):
            confidence_multiplier += 0.2

        # Check for test files
        if any(test_indicator in content_lower for test_indicator in ["test", "junit", "@test"]):
            confidence_multiplier -= 0.3

        return max(0.1, confidence_multiplier)


class CryptoFindingEnricher(ICryptoFindingEnricher):
    """
    Finding enricher for cryptographic vulnerabilities.

    Enhances findings with additional metadata, CWE mappings, and remediation guidance.
    """

    def __init__(self):
        """Initialize crypto finding enricher."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # CWE mappings for crypto vulnerabilities
        self.cwe_mappings = {
            CryptoVulnerabilityType.WEAK_CIPHER: "CWE-327",
            CryptoVulnerabilityType.WEAK_HASH: "CWE-328",
            CryptoVulnerabilityType.WEAK_KEY: "CWE-326",
            CryptoVulnerabilityType.INSECURE_SSL: "CWE-326",
            CryptoVulnerabilityType.POOR_RANDOMNESS: "CWE-338",
            CryptoVulnerabilityType.HARDCODED_SECRET: "CWE-798",
            CryptoVulnerabilityType.CERTIFICATE_ISSUE: "CWE-295",
            CryptoVulnerabilityType.CUSTOM_CRYPTO_FLAW: "CWE-327",
        }

        # OWASP category mappings
        self.owasp_mappings = {
            CryptoVulnerabilityType.WEAK_CIPHER: "A02:2021 – Cryptographic Failures",
            CryptoVulnerabilityType.WEAK_HASH: "A02:2021 – Cryptographic Failures",
            CryptoVulnerabilityType.HARDCODED_SECRET: "A07:2021 – Identification and Authentication Failures",
        }

    def enrich_finding(self, finding: CryptoFinding, context: CryptoContext) -> CryptoFinding:
        """Enrich finding with additional metadata and recommendations."""
        try:
            # Add CWE mapping
            finding.cwe_id = self.cwe_mappings.get(finding.vulnerability_type)

            # Add OWASP category
            finding.owasp_category = self.owasp_mappings.get(finding.vulnerability_type)

            # Enhance metadata
            finding.metadata.update(
                {
                    "file_type": self._detect_file_type(context.file_path),
                    "language": context.language,
                    "framework": context.framework,
                    "analysis_timestamp": time.time(),
                }
            )

            # Add remediation guidance
            finding = self.add_remediation_guidance(finding)

            self.logger.debug(f"Enriched finding: {finding.title}")

            return finding

        except Exception as e:
            self.logger.warning(f"Finding enrichment failed: {e}")
            return finding

    def add_remediation_guidance(self, finding: CryptoFinding) -> CryptoFinding:
        """Add detailed remediation guidance to finding."""
        vulnerability_type = finding.vulnerability_type
        algorithm = finding.algorithm.lower() if finding.algorithm else ""

        # Generate specific remediation based on vulnerability type and algorithm
        if vulnerability_type == CryptoVulnerabilityType.WEAK_CIPHER:
            if "des" in algorithm:
                finding.recommendation = "Replace DES with AES-256-GCM for symmetric encryption"
            elif "rc4" in algorithm:
                finding.recommendation = "Replace RC4 with AES-256 or ChaCha20-Poly1305"
            else:
                finding.recommendation = "Use strong cipher algorithms like AES-256-GCM"

        elif vulnerability_type == CryptoVulnerabilityType.WEAK_HASH:
            if "md5" in algorithm:
                finding.recommendation = "Replace MD5 with SHA-256 or SHA-3 for cryptographic hashing"
            elif "sha1" in algorithm or "sha-1" in algorithm:
                finding.recommendation = "Replace SHA-1 with SHA-256, SHA-512, or SHA-3"
            else:
                finding.recommendation = "Use strong hash algorithms like SHA-256 or SHA-3"

        elif vulnerability_type == CryptoVulnerabilityType.HARDCODED_SECRET:
            finding.recommendation = (
                "Remove hardcoded secrets. Use secure key storage mechanisms "
                "like Android Keystore or encrypted configuration files"
            )

        # Add implementation examples
        finding.metadata["remediation_examples"] = self._get_remediation_examples(vulnerability_type, algorithm)

        return finding

    def _detect_file_type(self, file_path: str) -> str:
        """Detect file type from path."""
        if file_path.endswith(".java"):
            return "java"
        elif file_path.endswith(".kt"):
            return "kotlin"
        elif file_path.endswith(".xml"):
            return "xml"
        elif file_path.endswith(".js"):
            return "javascript"
        else:
            return "unknown"

    def _get_remediation_examples(self, vulnerability_type: CryptoVulnerabilityType, algorithm: str) -> List[str]:
        """Get code examples for remediation."""
        examples = []

        if vulnerability_type == CryptoVulnerabilityType.WEAK_CIPHER:
            examples.append('// Use AES-256-GCM instead\nCipher cipher = Cipher.getInstance("AES/GCM/NoPadding");')

        elif vulnerability_type == CryptoVulnerabilityType.WEAK_HASH:
            examples.append('// Use SHA-256 instead\nMessageDigest digest = MessageDigest.getInstance("SHA-256");')

        elif vulnerability_type == CryptoVulnerabilityType.HARDCODED_SECRET:
            examples.append('// Use Android Keystore\nKeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");')

        return examples
