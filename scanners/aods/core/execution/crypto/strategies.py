#!/usr/bin/env python3
"""
Crypto Analysis Strategies - Modular Implementation
==================================================

Strategy implementations for cryptographic analysis following the Strategy pattern.
Migrates complex crypto analysis logic from CryptographicSecurityAnalyzer (1960 lines)
while maintaining modular architecture principles.

Each strategy handles a specific type of crypto analysis with enhanced
error handling, performance optimization, and testability.
"""

import re
import time
import logging
from typing import List, Optional, Tuple
from abc import abstractmethod

from core.execution.interfaces.crypto_interfaces import (
    ICryptoAnalysisStrategy,
    CryptoAnalysisType,
    CryptoContext,
    CryptoAnalysisResult,
    CryptoFinding,
    CryptoPattern,
    CryptoVulnerabilityType,
    CryptoSeverityLevel,
    CryptoAnalysisException,
)

logger = logging.getLogger(__name__)


class BaseCryptoStrategy(ICryptoAnalysisStrategy):
    """Base class for crypto analysis strategies with common functionality."""

    def __init__(self):
        """Initialize base crypto strategy."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._patterns = self._initialize_patterns()

    @abstractmethod
    def _initialize_patterns(self) -> List[CryptoPattern]:
        """Initialize patterns for this strategy."""

    @property
    def supported_patterns(self) -> List[CryptoPattern]:
        """Get the patterns this strategy can analyze."""
        return self._patterns

    def validate_context(self, context: CryptoContext) -> bool:
        """Validate that the context is suitable for this analysis."""
        return bool(context.content and context.file_path)

    def analyze(self, context: CryptoContext) -> CryptoAnalysisResult:
        """Perform cryptographic analysis on the given context."""
        start_time = time.time()

        try:
            if not self.validate_context(context):
                raise CryptoAnalysisException(f"Invalid context for {self.analysis_type}")

            self.logger.debug(f"Starting {self.analysis_type} analysis on {context.file_path}")

            result = CryptoAnalysisResult(analysis_type=self.analysis_type, files_analyzed=1)

            # Analyze patterns
            for pattern in self._patterns:
                matches = self._find_pattern_matches(context.content, pattern)
                for match in matches:
                    finding = self._analyze_match(pattern, match, context)
                    if finding:
                        result.add_finding(finding)

            result.processing_time = time.time() - start_time

            self.logger.info(
                f"Completed {self.analysis_type} analysis: "
                f"{len(result.findings)} findings in {result.processing_time:.3f}s"
            )

            return result

        except Exception as e:
            processing_time = time.time() - start_time
            self.logger.error(f"Analysis failed after {processing_time:.2f}s: {e}")
            raise CryptoAnalysisException(f"{self.analysis_type} analysis failed: {e}")

    def _find_pattern_matches(self, content: str, pattern: CryptoPattern) -> List[re.Match]:
        """Find all matches for a pattern in content."""
        try:
            compiled_pattern = pattern.compile_pattern()
            return list(compiled_pattern.finditer(content))
        except Exception as e:
            self.logger.warning(f"Pattern matching failed for {pattern.name}: {e}")
            return []

    # Algorithms that are secure and should NOT generate findings
    _SAFE_ALGORITHMS = frozenset({
        "sha-256", "sha256", "sha-384", "sha384", "sha-512", "sha512",
        "sha-3", "sha3", "sha3-256", "sha3-384", "sha3-512",
        "aes", "aes-128", "aes-256", "aes/gcm/nopadding", "aes/cbc/pkcs5padding",
        "hmacsha256", "hmacsha384", "hmacsha512",
        "pbkdf2withhmacsha256", "pbkdf2withhmacsha512",
        "tlsv1.2", "tlsv1.3", "tls",
        "rsa", "ec", "ecdsa", "ed25519",
    })

    def _analyze_match(
        self, pattern: CryptoPattern, match: re.Match, context: CryptoContext
    ) -> Optional[CryptoFinding]:
        """Analyze a pattern match and create finding if vulnerable."""
        try:
            # Extract algorithm or relevant information
            algorithm = self._extract_algorithm_from_match(match)

            # Skip findings for secure algorithms
            if algorithm and algorithm.lower() in self._SAFE_ALGORITHMS:
                return None

            # Assess vulnerability
            severity, confidence = self._assess_vulnerability(pattern, match, algorithm, context)

            if confidence < 0.3:  # Skip low-confidence findings
                return None

            # Create finding
            finding = CryptoFinding(
                vulnerability_type=pattern.vulnerability_type,
                title=self._generate_title(pattern, algorithm),
                description=self._generate_description(pattern, algorithm, match),
                severity=severity,
                confidence=confidence,
                file_path=context.file_path,
                line_number=self._get_line_number(context.content, match.start()),
                code_snippet=match.group(0),
                algorithm=algorithm or "unknown",
                recommendation=self._generate_recommendation(pattern, algorithm),
                evidence={
                    "pattern_name": pattern.name,
                    "match_text": match.group(0),
                    "algorithm": algorithm,
                    "context": self._extract_context(context.content, match),
                },
            )

            return finding

        except Exception as e:
            self.logger.warning(f"Match analysis failed: {e}")
            return None

    def _extract_algorithm_from_match(self, match: re.Match) -> Optional[str]:
        """Extract algorithm name from match."""
        # Try to extract from capture groups
        for group in match.groups():
            if group and isinstance(group, str):
                # Clean up the algorithm name
                algorithm = group.strip().strip("'\"")
                if algorithm and len(algorithm) > 1:
                    return algorithm

        # Fallback to full match analysis
        match_text = match.group(0)
        # Look for common algorithm patterns
        algorithm_patterns = [
            r"AES",
            r"DES",
            r"3DES",
            r"RSA",
            r"DSA",
            r"ECDSA",
            r"MD5",
            r"SHA1",
            r"SHA-1",
            r"SHA256",
            r"SHA-256",
            r"HMAC",
            r"PBKDF2",
            r"scrypt",
            r"bcrypt",
        ]

        for alg_pattern in algorithm_patterns:
            if re.search(alg_pattern, match_text, re.IGNORECASE):
                return alg_pattern.upper()

        return None

    def _assess_vulnerability(
        self, pattern: CryptoPattern, match: re.Match, algorithm: Optional[str], context: CryptoContext
    ) -> Tuple[CryptoSeverityLevel, float]:
        """Assess vulnerability severity and confidence."""
        # Base assessment from pattern
        severity = pattern.severity
        confidence = pattern.confidence_base

        # Adjust based on algorithm
        if algorithm:
            severity, confidence = self._adjust_for_algorithm(algorithm, severity, confidence)

        # Adjust based on context
        if pattern.context_required:
            context_confidence = self._assess_context_confidence(context.content, match)
            confidence *= context_confidence

        return severity, min(confidence, 1.0)

    def _adjust_for_algorithm(
        self, algorithm: str, base_severity: CryptoSeverityLevel, base_confidence: float
    ) -> Tuple[CryptoSeverityLevel, float]:
        """Adjust severity and confidence based on algorithm."""
        algorithm_lower = algorithm.lower()

        # Critical algorithms (use exact match to avoid "des" matching "aes")
        _CRITICAL_ALGOS = {"des", "3des", "tripledes", "desede", "md5", "sha1", "rc4", "arc4", "arcfour", "md2", "md4"}
        if algorithm_lower in _CRITICAL_ALGOS:
            return CryptoSeverityLevel.CRITICAL, min(base_confidence + 0.2, 1.0)

        # High-risk algorithms
        _HIGH_ALGOS = {"sha-1"}
        if algorithm_lower in _HIGH_ALGOS:
            return CryptoSeverityLevel.HIGH, min(base_confidence + 0.1, 1.0)

        # Medium-risk patterns (mode-based, checked via substring since they appear in cipher strings)
        if any(medium in algorithm_lower for medium in ["/ecb/", "ecb"]) and algorithm_lower != "ecb":
            return CryptoSeverityLevel.MEDIUM, base_confidence
        if algorithm_lower == "ecb":
            return CryptoSeverityLevel.HIGH, base_confidence

        return base_severity, base_confidence

    def _assess_context_confidence(self, content: str, match: re.Match) -> float:
        """Assess confidence based on surrounding context."""
        context = self._extract_context(content, match, lines_before=3, lines_after=3)
        context_lower = context.lower()

        confidence_multiplier = 1.0

        # Positive indicators
        if any(indicator in context_lower for indicator in ["crypto", "encrypt", "decrypt", "cipher"]):
            confidence_multiplier += 0.2

        if any(indicator in context_lower for indicator in ["security", "password", "key"]):
            confidence_multiplier += 0.1

        # Negative indicators
        if any(indicator in context_lower for indicator in ["test", "example", "demo"]):
            confidence_multiplier -= 0.3

        if any(indicator in context_lower for indicator in ["comment", "//", "/*"]):
            confidence_multiplier -= 0.2

        return max(confidence_multiplier, 0.1)

    def _extract_context(self, content: str, match: re.Match, lines_before: int = 2, lines_after: int = 2) -> str:
        """Extract context around a match."""
        lines = content.split("\n")
        start_line = content[: match.start()].count("\n")

        context_start = max(0, start_line - lines_before)
        context_end = min(len(lines), start_line + lines_after + 1)

        return "\n".join(lines[context_start:context_end])

    def _get_line_number(self, content: str, position: int) -> int:
        """Get line number for a position in content."""
        return content[:position].count("\n") + 1

    def _generate_title(self, pattern: CryptoPattern, algorithm: Optional[str]) -> str:
        """Generate finding title."""
        if algorithm:
            return f"Weak Cryptographic Algorithm: {algorithm}"
        return pattern.description

    def _generate_description(self, pattern: CryptoPattern, algorithm: Optional[str], match: re.Match) -> str:
        """Generate finding description."""
        base_desc = pattern.description
        if algorithm:
            return f"{base_desc}. Detected algorithm: {algorithm}"
        return base_desc

    def _generate_recommendation(self, pattern: CryptoPattern, algorithm: Optional[str]) -> str:
        """Generate recommendation for finding."""
        base_rec = pattern.recommendation
        if algorithm and algorithm.lower() in ["des", "md5", "sha1"]:
            return f"{base_rec} Replace {algorithm} with a stronger alternative (AES-256, SHA-256, etc.)"
        return base_rec


class CipherAnalysisStrategy(BaseCryptoStrategy):
    """
    Strategy for analyzing cipher-related vulnerabilities.

    Migrates cipher detection logic from CryptographicSecurityAnalyzer._detect_cipher_vulnerabilities
    with enhanced pattern matching and vulnerability assessment.
    """

    @property
    def analysis_type(self) -> CryptoAnalysisType:
        """Get analysis type."""
        return CryptoAnalysisType.CIPHER_ANALYSIS

    def _initialize_patterns(self) -> List[CryptoPattern]:
        """Initialize cipher analysis patterns (migrated from original)."""
        return [
            CryptoPattern(
                name="cipher_instantiation",
                pattern=r'Cipher\.getInstance\s*\(\s*["\']([^"\']+)["\']\s*\)',
                vulnerability_type=CryptoVulnerabilityType.WEAK_CIPHER,
                severity=CryptoSeverityLevel.HIGH,
                description="Potentially weak cipher algorithm detected",
                recommendation="Use strong cipher algorithms like AES-256-GCM",
                confidence_base=0.8,
            ),
            CryptoPattern(
                name="cipher_factory",
                pattern=r'CipherFactory\.create\s*\(\s*["\']([^"\']+)["\']\s*\)',
                vulnerability_type=CryptoVulnerabilityType.WEAK_CIPHER,
                severity=CryptoSeverityLevel.HIGH,
                description="Cipher factory usage with potentially weak algorithm",
                recommendation="Ensure cipher factory creates strong algorithms",
                confidence_base=0.7,
            ),
            CryptoPattern(
                name="des_cipher",
                pattern=r'(?:Cipher|SecretKeyFactory)\.getInstance\s*\(\s*["\'](?:DES|DESede|3DES|TripleDES)[/"\']',
                vulnerability_type=CryptoVulnerabilityType.WEAK_CIPHER,
                severity=CryptoSeverityLevel.CRITICAL,
                description="Deprecated DES/3DES cipher algorithm detected",
                recommendation="Replace with AES-256 encryption",
                confidence_base=0.9,
            ),
            CryptoPattern(
                name="rc4_cipher",
                pattern=r'(?:Cipher\.getInstance\s*\(\s*["\'](?:RC4|ARC4|ARCFOUR)["\']|new\s+RC4\s*\()',
                vulnerability_type=CryptoVulnerabilityType.WEAK_CIPHER,
                severity=CryptoSeverityLevel.CRITICAL,
                description="Insecure RC4 cipher algorithm detected",
                recommendation="Replace with AES-256 or ChaCha20",
                confidence_base=0.95,
            ),
            CryptoPattern(
                name="ecb_mode",
                pattern=r'Cipher\.getInstance\s*\(\s*["\'][^"\']*ECB[^"\']*["\']\s*\)',
                vulnerability_type=CryptoVulnerabilityType.CIPHER_MODE_ISSUE,
                severity=CryptoSeverityLevel.HIGH,
                description="Insecure ECB cipher mode detected",
                recommendation="Use CBC, GCM, or CTR mode instead of ECB",
                confidence_base=0.85,
            ),
        ]


class HashAnalysisStrategy(BaseCryptoStrategy):
    """
    Strategy for analyzing hash-related vulnerabilities.

    Migrates hash detection logic from CryptographicSecurityAnalyzer._detect_hash_vulnerabilities
    with enhanced pattern matching and vulnerability assessment.
    """

    @property
    def analysis_type(self) -> CryptoAnalysisType:
        """Get analysis type."""
        return CryptoAnalysisType.HASH_ANALYSIS

    def _initialize_patterns(self) -> List[CryptoPattern]:
        """Initialize hash analysis patterns (migrated from original)."""
        return [
            CryptoPattern(
                name="message_digest",
                pattern=r'MessageDigest\.getInstance\s*\(\s*["\']([^"\']+)["\']\s*\)',
                vulnerability_type=CryptoVulnerabilityType.WEAK_HASH,
                severity=CryptoSeverityLevel.MEDIUM,
                description="Hash algorithm usage detected",
                recommendation="Use SHA-256 or stronger hash algorithms",
                confidence_base=0.8,
            ),
            CryptoPattern(
                name="md5_hash",
                pattern=r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']\s*\)',
                vulnerability_type=CryptoVulnerabilityType.WEAK_HASH,
                severity=CryptoSeverityLevel.CRITICAL,
                description="Insecure MD5 hash algorithm detected",
                recommendation="Replace MD5 with SHA-256 or SHA-3",
                confidence_base=0.95,
            ),
            CryptoPattern(
                name="sha1_hash",
                pattern=r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']\s*\)',
                vulnerability_type=CryptoVulnerabilityType.WEAK_HASH,
                severity=CryptoSeverityLevel.HIGH,
                description="Deprecated SHA-1 hash algorithm detected",
                recommendation="Replace SHA-1 with SHA-256 or stronger",
                confidence_base=0.9,
            ),
            CryptoPattern(
                name="digest_utils",
                pattern=r"DigestUtils\.([a-zA-Z0-9]+)\s*\(",
                vulnerability_type=CryptoVulnerabilityType.WEAK_HASH,
                severity=CryptoSeverityLevel.MEDIUM,
                description="Hash utility usage detected",
                recommendation="Verify strong hash algorithm is used",
                confidence_base=0.6,
            ),
        ]


class KeyManagementStrategy(BaseCryptoStrategy):
    """
    Strategy for analyzing key management vulnerabilities.

    Migrates key detection logic from CryptographicSecurityAnalyzer._detect_key_vulnerabilities
    with enhanced pattern matching and vulnerability assessment.
    """

    @property
    def analysis_type(self) -> CryptoAnalysisType:
        """Get analysis type."""
        return CryptoAnalysisType.KEY_MANAGEMENT

    def _initialize_patterns(self) -> List[CryptoPattern]:
        """Initialize key management patterns (migrated from original)."""
        return [
            CryptoPattern(
                name="key_generator",
                pattern=r'KeyGenerator\.getInstance\s*\(\s*["\']([^"\']+)["\']\s*\)',
                vulnerability_type=CryptoVulnerabilityType.WEAK_KEY,
                severity=CryptoSeverityLevel.MEDIUM,
                description="Key generation algorithm detected",
                recommendation="Use strong key generation algorithms",
                confidence_base=0.7,
            ),
            CryptoPattern(
                name="hardcoded_key",
                pattern=r'(?:key|password|secret)\s*=\s*["\']([a-zA-Z0-9+/=]{16,})["\']\s*',
                vulnerability_type=CryptoVulnerabilityType.HARDCODED_SECRET,
                severity=CryptoSeverityLevel.CRITICAL,
                description="Hardcoded cryptographic key or secret detected",
                recommendation="Use secure key storage and key derivation",
                confidence_base=0.8,
            ),
            CryptoPattern(
                name="weak_key_derivation",
                pattern=r"PBKDF2WithHmac([A-Za-z0-9]+)",
                vulnerability_type=CryptoVulnerabilityType.KEY_DERIVATION_ISSUE,
                severity=CryptoSeverityLevel.MEDIUM,
                description="Key derivation function detected",
                recommendation="Use strong KDF with sufficient iterations",
                confidence_base=0.6,
            ),
        ]


class SSLTLSAnalysisStrategy(BaseCryptoStrategy):
    """
    Strategy for analyzing SSL/TLS vulnerabilities.

    Migrates SSL detection logic from CryptographicSecurityAnalyzer._detect_ssl_vulnerabilities
    with enhanced pattern matching and vulnerability assessment.
    """

    @property
    def analysis_type(self) -> CryptoAnalysisType:
        """Get analysis type."""
        return CryptoAnalysisType.SSL_TLS_ANALYSIS

    def _initialize_patterns(self) -> List[CryptoPattern]:
        """Initialize SSL/TLS analysis patterns (migrated from original)."""
        return [
            CryptoPattern(
                name="ssl_context",
                pattern=r'SSLContext\.getInstance\s*\(\s*["\']([^"\']+)["\']\s*\)',
                vulnerability_type=CryptoVulnerabilityType.INSECURE_SSL,
                severity=CryptoSeverityLevel.HIGH,
                description="SSL/TLS context configuration detected",
                recommendation="Use TLS 1.2 or higher",
                confidence_base=0.8,
            ),
            CryptoPattern(
                name="trust_all_certs",
                pattern=r"TrustAllCerts|X509TrustManager.*checkClientTrusted.*\{\s*\}",
                vulnerability_type=CryptoVulnerabilityType.CERTIFICATE_ISSUE,
                severity=CryptoSeverityLevel.CRITICAL,
                description="Certificate validation bypass detected",
                recommendation="Implement proper certificate validation",
                confidence_base=0.95,
            ),
        ]


class RandomnessAnalysisStrategy(BaseCryptoStrategy):
    """Strategy for analyzing randomness-related vulnerabilities."""

    @property
    def analysis_type(self) -> CryptoAnalysisType:
        return CryptoAnalysisType.RANDOMNESS_ANALYSIS

    def _initialize_patterns(self) -> List[CryptoPattern]:
        return [
            CryptoPattern(
                name="weak_random",
                pattern=r"Math\.random\(\)|Random\(\)",
                vulnerability_type=CryptoVulnerabilityType.POOR_RANDOMNESS,
                severity=CryptoSeverityLevel.MEDIUM,
                description="Weak random number generation detected",
                recommendation="Use SecureRandom for cryptographic purposes",
                confidence_base=0.7,
            )
        ]


class SecretDetectionStrategy(BaseCryptoStrategy):
    """Strategy for detecting hardcoded secrets."""

    @property
    def analysis_type(self) -> CryptoAnalysisType:
        return CryptoAnalysisType.SECRET_DETECTION

    def _initialize_patterns(self) -> List[CryptoPattern]:
        return [
            CryptoPattern(
                name="api_key",
                pattern=r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']\s*',
                vulnerability_type=CryptoVulnerabilityType.HARDCODED_SECRET,
                severity=CryptoSeverityLevel.HIGH,
                description="Hardcoded API key detected",
                recommendation="Use secure configuration management",
                confidence_base=0.8,
            )
        ]


class CertificateValidationStrategy(BaseCryptoStrategy):
    """Strategy for analyzing certificate validation issues."""

    @property
    def analysis_type(self) -> CryptoAnalysisType:
        return CryptoAnalysisType.CERTIFICATE_VALIDATION

    def _initialize_patterns(self) -> List[CryptoPattern]:
        return [
            CryptoPattern(
                name="hostname_verifier",
                pattern=r"setHostnameVerifier.*ALLOW_ALL",
                vulnerability_type=CryptoVulnerabilityType.CERTIFICATE_ISSUE,
                severity=CryptoSeverityLevel.HIGH,
                description="Hostname verification disabled",
                recommendation="Enable proper hostname verification",
                confidence_base=0.9,
            )
        ]


class CustomCryptoStrategy(BaseCryptoStrategy):
    """Strategy for detecting custom crypto implementations."""

    @property
    def analysis_type(self) -> CryptoAnalysisType:
        return CryptoAnalysisType.CUSTOM_CRYPTO

    def _initialize_patterns(self) -> List[CryptoPattern]:
        return [
            CryptoPattern(
                name="custom_cipher",
                pattern=r"class\s+\w*(?:Cipher|Crypto|Encrypt)\w*",
                vulnerability_type=CryptoVulnerabilityType.CUSTOM_CRYPTO_FLAW,
                severity=CryptoSeverityLevel.MEDIUM,
                description="Custom cryptographic implementation detected",
                recommendation="Use well-tested cryptographic libraries",
                confidence_base=0.6,
            )
        ]
