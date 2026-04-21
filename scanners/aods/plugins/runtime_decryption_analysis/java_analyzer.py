#!/usr/bin/env python3
"""
Java Decryption Pattern Analyzer

Specialized analyzer for detecting runtime decryption patterns in Java source code.
Performs semantic analysis of decompiled Java files to identify cryptographic
implementations, key management issues, and runtime decryption vulnerabilities.

Analysis Capabilities:
- Cryptographic API usage detection
- Runtime key derivation analysis
- Weak encryption algorithm identification
- Custom cryptographic implementation detection
- Hardcoded cryptographic material detection

Author: AODS Development Team
Version: 2.0.0
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from .data_structures import (
    RuntimeDecryptionFinding,
    DecryptionType,
    DetectionMethod,
    VulnerabilitySeverity,
    RuntimeDecryptionConfig,
)


class JavaDecryptionAnalyzer:
    """
    Specialized analyzer for detecting decryption patterns in Java source code.

    Performs analysis of decompiled Java files to identify
    runtime decryption vulnerabilities and cryptographic implementation issues.
    """

    def __init__(self, config: RuntimeDecryptionConfig):
        """Initialize the Java decryption analyzer."""
        self.config = config
        self.logger = logger
        self.processed_files: Set[str] = set()
        # PERMANENT REGRESSION FIX: Add missing files_analyzed attribute
        self.files_analyzed: int = 0
        self.analysis_stats = {"files_processed": 0, "patterns_matched": 0, "total_findings": 0}

        # Initialize cryptographic patterns
        self._initialize_crypto_patterns()

        self.logger.info("Java decryption analyzer initialized")

    def _extract_jadx_path(self, jadx_output_dir) -> str:
        """Extract JADX directory path from either string or APKContext object."""
        if hasattr(jadx_output_dir, "decompiled_apk_dir"):
            # APKContext object - use the correct decompiled directory path
            jadx_dir_str = str(jadx_output_dir.decompiled_apk_dir)
            self.logger.info(f"APKContext received - using decompiled APK directory: {jadx_dir_str}")
            return jadx_dir_str
        elif hasattr(jadx_output_dir, "apk_path"):
            # Fallback: APKContext without decompiled_apk_dir - construct path from APK path
            apk_path = str(jadx_output_dir.apk_path)
            # Construct expected JADX output directory path
            apk_basename = os.path.splitext(os.path.basename(apk_path))[0]
            jadx_dir_str = os.path.join(os.path.dirname(apk_path), f"{apk_basename}_decompiled")
            self.logger.info(f"APKContext received - using constructed JADX path: {jadx_dir_str}")
            return jadx_dir_str
        else:
            # String path - use as-is
            return str(jadx_output_dir)

    def _initialize_crypto_patterns(self):
        """Initialize cryptographic detection patterns."""
        # High-confidence crypto API patterns
        self.crypto_api_patterns = {
            "javax_crypto_cipher": {
                "pattern": r"javax\.crypto\.Cipher",
                "type": DecryptionType.CRYPTO_IMPLEMENTATION,
                "severity": VulnerabilitySeverity.HIGH,
                "confidence_base": 0.9,
            },
            "cipher_decrypt": {
                "pattern": r"\.decrypt\s*\(",
                "type": DecryptionType.RUNTIME_DECRYPTION,
                "severity": VulnerabilitySeverity.CRITICAL,
                "confidence_base": 0.85,
            },
            "cipher_dofinal": {
                "pattern": r"cipher\.doFinal\s*\(",
                "type": DecryptionType.RUNTIME_DECRYPTION,
                "severity": VulnerabilitySeverity.HIGH,
                "confidence_base": 0.8,
            },
            "aes_decrypt": {
                "pattern": r"AES.*decrypt",
                "type": DecryptionType.CRYPTO_IMPLEMENTATION,
                "severity": VulnerabilitySeverity.HIGH,
                "confidence_base": 0.9,
            },
            "des_decrypt": {
                "pattern": r"DES.*decrypt",
                "type": DecryptionType.WEAK_CRYPTO,
                "severity": VulnerabilitySeverity.CRITICAL,
                "confidence_base": 0.95,
            },
            "rsa_decrypt": {
                "pattern": r"RSA.*decrypt",
                "type": DecryptionType.CRYPTO_IMPLEMENTATION,
                "severity": VulnerabilitySeverity.MEDIUM,
                "confidence_base": 0.85,
            },
        }

        # Key management patterns
        self.key_management_patterns = {
            "keystore_access": {
                "pattern": r"KeyStore\.|keystore\.",
                "type": DecryptionType.KEY_MANAGEMENT,
                "severity": VulnerabilitySeverity.MEDIUM,
                "confidence_base": 0.75,
            },
            "hardcoded_key": {
                "pattern": r'(private|secret).*key.*=.*"[A-Za-z0-9+/=]{16,}"',
                "type": DecryptionType.HARDCODED_CRYPTO,
                "severity": VulnerabilitySeverity.CRITICAL,
                "confidence_base": 0.95,
            },
            "key_derivation": {
                "pattern": r"deriveKey|generateKey|KeyGenerator",
                "type": DecryptionType.KEY_MANAGEMENT,
                "severity": VulnerabilitySeverity.MEDIUM,
                "confidence_base": 0.7,
            },
            "android_keystore": {
                "pattern": r"android\.security\.keystore",
                "type": DecryptionType.KEY_MANAGEMENT,
                "severity": VulnerabilitySeverity.LOW,
                "confidence_base": 0.6,
            },
        }

        # Weak crypto patterns
        self.weak_crypto_patterns = {
            "md5_usage": {
                "pattern": r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
                "type": DecryptionType.WEAK_CRYPTO,
                "severity": VulnerabilitySeverity.HIGH,
                "confidence_base": 0.9,
            },
            "sha1_usage": {
                "pattern": r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']',
                "type": DecryptionType.WEAK_CRYPTO,
                "severity": VulnerabilitySeverity.MEDIUM,
                "confidence_base": 0.8,
            },
            "des_algorithm": {
                "pattern": r'Cipher\.getInstance\s*\(\s*["\']DES',
                "type": DecryptionType.WEAK_CRYPTO,
                "severity": VulnerabilitySeverity.CRITICAL,
                "confidence_base": 0.95,
            },
            "ecb_mode": {
                "pattern": r"AES/ECB",
                "type": DecryptionType.WEAK_CRYPTO,
                "severity": VulnerabilitySeverity.HIGH,
                "confidence_base": 0.85,
            },
        }

        # Custom crypto implementation patterns
        self.custom_crypto_patterns = {
            "custom_encrypt_method": {
                "pattern": r"(private|public).*encrypt\s*\([^)]*\)",
                "type": DecryptionType.CUSTOM_CRYPTO,
                "severity": VulnerabilitySeverity.HIGH,
                "confidence_base": 0.7,
            },
            "custom_decrypt_method": {
                "pattern": r"(private|public).*decrypt\s*\([^)]*\)",
                "type": DecryptionType.CUSTOM_CRYPTO,
                "severity": VulnerabilitySeverity.HIGH,
                "confidence_base": 0.75,
            },
            "xor_operations": {
                "pattern": r"[\s\w\d]\s*\^\s*[\s\w\d].*=",
                "type": DecryptionType.CUSTOM_CRYPTO,
                "severity": VulnerabilitySeverity.MEDIUM,
                "confidence_base": 0.6,
            },
            "bit_shifting": {
                "pattern": r"<<|>>.*=",
                "type": DecryptionType.CUSTOM_CRYPTO,
                "severity": VulnerabilitySeverity.LOW,
                "confidence_base": 0.4,
            },
        }

    def analyze(self, jadx_output_dir) -> List[RuntimeDecryptionFinding]:
        """
        Analyze Java source files for runtime decryption patterns.

        Args:
            jadx_output_dir: Directory containing decompiled Java source files OR APKContext object

        Returns:
            List[RuntimeDecryptionFinding]: Detected vulnerabilities
        """
        # PERMANENT REGRESSION FIX: Handle both string paths and APKContext objects
        jadx_dir_str = self._extract_jadx_path(jadx_output_dir)

        self.logger.info(f"Starting Java decryption analysis in: {jadx_dir_str}")

        findings: List[RuntimeDecryptionFinding] = []
        java_files = self._discover_java_files(jadx_dir_str)

        if not java_files:
            self.logger.warning("No Java files found for analysis")
            return findings

        # Limit files if configured
        if self.config.max_files_per_type > 0:
            java_files = java_files[: self.config.max_files_per_type]

        self.logger.info(f"Analyzing {len(java_files)} Java files...")

        # Parallel processing if enabled
        if self.config.enable_parallel_processing:
            findings = self._analyze_files_parallel(java_files, jadx_dir_str)
        else:
            findings = self._analyze_files_sequential(java_files, jadx_dir_str)

        self.analysis_stats["files_processed"] = len(self.processed_files)
        self.analysis_stats["total_findings"] = len(findings)
        # PERMANENT REGRESSION FIX: Update files_analyzed attribute
        self.files_analyzed = len(self.processed_files)

        self.logger.info(f"Java analysis completed: {len(findings)} findings from {len(self.processed_files)} files")

        return findings

    def _discover_java_files(self, jadx_dir: str) -> List[str]:
        """Discover all Java source files in the decompiled directory."""
        java_files = []

        try:
            for root, dirs, files in os.walk(jadx_dir):
                for file in files:
                    if file.endswith(".java"):
                        file_path = os.path.join(root, file)
                        file_size = os.path.getsize(file_path) / (1024 * 1024)  # MB

                        # Skip files that are too large
                        if file_size <= self.config.max_file_size_mb:
                            java_files.append(file_path)
                        else:
                            self.logger.debug(f"Skipping large file: {file} ({file_size:.1f}MB)")

        except Exception as e:
            self.logger.error(f"Error discovering Java files: {e}")

        return java_files

    def _analyze_files_parallel(self, java_files: List[str], base_dir: str) -> List[RuntimeDecryptionFinding]:
        """Analyze Java files using parallel processing."""
        all_findings = []

        with ThreadPoolExecutor(max_workers=self.config.max_worker_threads) as executor:
            # Submit all analysis tasks
            future_to_file = {
                executor.submit(self._analyze_single_file, file_path, base_dir): file_path for file_path in java_files
            }

            # Collect results with timeout
            for future in future_to_file:
                try:
                    findings = future.result(timeout=self.config.timeout_per_file_seconds)
                    if findings:
                        all_findings.extend(findings)

                except FutureTimeoutError:
                    file_path = future_to_file[future]
                    self.logger.warning(f"Analysis timeout for file: {file_path}")

                except Exception as e:
                    file_path = future_to_file[future]
                    self.logger.error(f"Error analyzing file {file_path}: {e}")

        return all_findings

    def _analyze_files_sequential(self, java_files: List[str], base_dir: str) -> List[RuntimeDecryptionFinding]:
        """Analyze Java files sequentially."""
        all_findings = []

        for file_path in java_files:
            try:
                findings = self._analyze_single_file(file_path, base_dir)
                if findings:
                    all_findings.extend(findings)

            except Exception as e:
                self.logger.error(f"Error analyzing file {file_path}: {e}")

        return all_findings

    def _analyze_single_file(self, file_path: str, base_dir: str) -> List[RuntimeDecryptionFinding]:
        """Analyze a single Java file for decryption patterns."""
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Track processed file
            self.processed_files.add(file_path)
            relative_path = os.path.relpath(file_path, base_dir)

            # Extract class name from file path
            class_name = self._extract_class_name(file_path, content)

            # Apply all pattern categories
            findings.extend(self._find_crypto_api_patterns(content, relative_path, class_name))
            findings.extend(self._find_key_management_patterns(content, relative_path, class_name))
            findings.extend(self._find_weak_crypto_patterns(content, relative_path, class_name))
            findings.extend(self._find_custom_crypto_patterns(content, relative_path, class_name))

            # Perform semantic analysis for additional context
            findings = self._enhance_with_semantic_analysis(findings, content, class_name)

        except Exception as e:
            self.logger.debug(f"Error analyzing Java file {file_path}: {e}")

        return findings

    def _extract_class_name(self, file_path: str, content: str) -> str:
        """Extract class name from file path and content."""
        # Try to extract from file name first
        file_name = Path(file_path).stem

        # Validate with content analysis
        class_pattern = r"class\s+(\w+)"
        match = re.search(class_pattern, content)

        if match and match.group(1) == file_name:
            return match.group(1)
        elif match:
            return match.group(1)
        else:
            return file_name

    def _find_crypto_api_patterns(
        self, content: str, file_path: str, class_name: str
    ) -> List[RuntimeDecryptionFinding]:
        """Find cryptographic API usage patterns."""
        findings = []

        for pattern_name, pattern_info in self.crypto_api_patterns.items():
            matches = re.finditer(pattern_info["pattern"], content, re.IGNORECASE)

            for match in matches:
                # Extract method context
                method_name = self._extract_method_context(content, match.start())
                line_number = content[: match.start()].count("\n") + 1

                finding = RuntimeDecryptionFinding(
                    finding_type=f"Java Crypto API: {pattern_name}",
                    description=f"Detected cryptographic API usage: {match.group(0)}",
                    severity=pattern_info["severity"],
                    confidence=pattern_info["confidence_base"],
                    location=f"{file_path}:{line_number}",
                    class_name=class_name,
                    method_name=method_name,
                    line_number=line_number,
                    file_path=file_path,
                    pattern_type=pattern_info["type"],
                    detection_method=DetectionMethod.PATTERN_MATCHING,
                    matched_pattern=pattern_info["pattern"],
                    evidence=[f"Pattern match: {match.group(0)}"],
                    context={"java_analysis": True, "api_usage": True},
                )

                findings.append(finding)
                self.analysis_stats["patterns_matched"] += 1

        return findings

    def _find_key_management_patterns(
        self, content: str, file_path: str, class_name: str
    ) -> List[RuntimeDecryptionFinding]:
        """Find key management related patterns."""
        findings = []

        for pattern_name, pattern_info in self.key_management_patterns.items():
            matches = re.finditer(pattern_info["pattern"], content, re.IGNORECASE)

            for match in matches:
                method_name = self._extract_method_context(content, match.start())
                line_number = content[: match.start()].count("\n") + 1

                finding = RuntimeDecryptionFinding(
                    finding_type=f"Java Key Management: {pattern_name}",
                    description=f"Detected key management pattern: {match.group(0)}",
                    severity=pattern_info["severity"],
                    confidence=pattern_info["confidence_base"],
                    location=f"{file_path}:{line_number}",
                    class_name=class_name,
                    method_name=method_name,
                    line_number=line_number,
                    file_path=file_path,
                    pattern_type=pattern_info["type"],
                    detection_method=DetectionMethod.PATTERN_MATCHING,
                    matched_pattern=pattern_info["pattern"],
                    evidence=[f"Key management pattern: {match.group(0)}"],
                    context={"java_analysis": True, "key_management": True},
                )

                findings.append(finding)
                self.analysis_stats["patterns_matched"] += 1

        return findings

    def _find_weak_crypto_patterns(
        self, content: str, file_path: str, class_name: str
    ) -> List[RuntimeDecryptionFinding]:
        """Find weak cryptographic implementation patterns."""
        findings = []

        for pattern_name, pattern_info in self.weak_crypto_patterns.items():
            matches = re.finditer(pattern_info["pattern"], content, re.IGNORECASE)

            for match in matches:
                method_name = self._extract_method_context(content, match.start())
                line_number = content[: match.start()].count("\n") + 1

                finding = RuntimeDecryptionFinding(
                    finding_type=f"Java Weak Crypto: {pattern_name}",
                    description=f"Detected weak cryptographic implementation: {match.group(0)}",
                    severity=pattern_info["severity"],
                    confidence=pattern_info["confidence_base"],
                    location=f"{file_path}:{line_number}",
                    class_name=class_name,
                    method_name=method_name,
                    line_number=line_number,
                    file_path=file_path,
                    pattern_type=pattern_info["type"],
                    detection_method=DetectionMethod.PATTERN_MATCHING,
                    matched_pattern=pattern_info["pattern"],
                    evidence=[f"Weak crypto pattern: {match.group(0)}"],
                    context={"java_analysis": True, "weak_crypto": True},
                )

                findings.append(finding)
                self.analysis_stats["patterns_matched"] += 1

        return findings

    def _find_custom_crypto_patterns(
        self, content: str, file_path: str, class_name: str
    ) -> List[RuntimeDecryptionFinding]:
        """Find custom cryptographic implementation patterns."""
        findings = []

        for pattern_name, pattern_info in self.custom_crypto_patterns.items():
            matches = re.finditer(pattern_info["pattern"], content, re.IGNORECASE)

            for match in matches:
                method_name = self._extract_method_context(content, match.start())
                line_number = content[: match.start()].count("\n") + 1

                finding = RuntimeDecryptionFinding(
                    finding_type=f"Java Custom Crypto: {pattern_name}",
                    description=f"Detected custom cryptographic implementation: {match.group(0)}",
                    severity=pattern_info["severity"],
                    confidence=pattern_info["confidence_base"],
                    location=f"{file_path}:{line_number}",
                    class_name=class_name,
                    method_name=method_name,
                    line_number=line_number,
                    file_path=file_path,
                    pattern_type=pattern_info["type"],
                    detection_method=DetectionMethod.PATTERN_MATCHING,
                    matched_pattern=pattern_info["pattern"],
                    evidence=[f"Custom crypto pattern: {match.group(0)}"],
                    context={"java_analysis": True, "custom_crypto": True},
                )

                findings.append(finding)
                self.analysis_stats["patterns_matched"] += 1

        return findings

    def _extract_method_context(self, content: str, position: int) -> str:
        """Extract method name context around a pattern match."""
        # Look backwards for method declaration
        before_match = content[:position]

        # Find the last method declaration before this position
        method_pattern = r"(public|private|protected)?\s*\w+\s+(\w+)\s*\("
        matches = list(re.finditer(method_pattern, before_match))

        if matches:
            last_match = matches[-1]
            return last_match.group(2)  # Method name

        return "unknown_method"

    def _enhance_with_semantic_analysis(
        self, findings: List[RuntimeDecryptionFinding], content: str, class_name: str
    ) -> List[RuntimeDecryptionFinding]:
        """Enhance findings with semantic analysis."""
        for finding in findings:
            # Add semantic context
            if "crypto" in class_name.lower() or "security" in class_name.lower():
                finding.context["semantic_context"] = "crypto_class"
                finding.confidence *= 1.1  # Boost confidence for crypto-related classes

            # Check for imports
            if "javax.crypto" in content:
                finding.context["crypto_imports"] = True
                finding.confidence *= 1.05

            # Check for error handling
            if "try" in content and "catch" in content:
                finding.context["error_handling"] = True
                finding.confidence *= 1.02

            # Ensure confidence doesn't exceed ceiling
            finding.confidence = min(finding.confidence, 0.95)

        return findings

    def get_processed_files(self) -> Set[str]:
        """Get set of processed file paths."""
        return self.processed_files.copy()

    def get_analysis_statistics(self) -> Dict[str, int]:
        """Get analysis statistics."""
        return self.analysis_stats.copy()
