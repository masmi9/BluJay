#!/usr/bin/env python3
"""
Source File Validator
=====================

This module provides validation for source file attributions in vulnerability reports.
It ensures that vulnerabilities are only attributed to files that actually exist and contain relevant code.

CRITICAL: This prevents incorrect file attribution that was causing manifest issues
to be attributed to random source files.
"""

import os
import logging
from typing import Dict, Any, Optional

# MIGRATED: Import unified caching infrastructure
from core.shared_infrastructure.performance.caching_consolidation import get_unified_cache_manager, CacheType


class SourceFileValidator:
    """
    Validates and corrects source file attributions for vulnerability findings.

    This validator ensures that:
    1. Files actually exist before attribution
    2. Files contain relevant code for the vulnerability type
    3. Confidence scores reflect attribution quality
    4. Fallback handling for legitimate findings without clear attribution

    CRITICAL FIX: Prevents log spam by tracking processed vulnerabilities
    and using rate-limited logging for common correction patterns.

    BROADER AODS SCOPE CONSIDERATIONS:
    - Maintains detailed logging for unique correction cases
    - Provides summary statistics for bulk corrections
    - Integrates with AODS performance monitoring
    - Supports debugging without overwhelming log systems
    """

    def __init__(self, decompiled_source_dir: str = None):
        """Initialize the source file validator."""
        self.logger = logging.getLogger(__name__)
        self.decompiled_source_dir = decompiled_source_dir
        # MIGRATED: Use unified caching infrastructure for file validation caches
        self.cache_manager = get_unified_cache_manager()
        self._cache_namespace = "source_file_validator"

        # AODS FIX: Add deduplication and rate limiting for log spam prevention
        self._processed_corrections = set()  # Track processed vulnerability corrections
        self._correction_stats = {}  # Track correction statistics by type
        self._log_rate_limiter = {}  # Rate limit repeated log messages
        self._max_logs_per_pattern = 5  # Maximum logs per correction pattern

        self.logger.info("🔍 **SOURCE FILE VALIDATOR INITIALIZED**")

    def validate_vulnerability_attribution(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and correct the file attribution for a vulnerability.

        Args:
            vulnerability: Vulnerability dictionary with file_path attribution

        Returns:
            Updated vulnerability with validated attribution and confidence score
        """
        original_file_path = vulnerability.get("file_path", "")

        if not original_file_path:
            return self._handle_missing_file_path(vulnerability)

        # **CRITICAL CHECK**: Validate file attribution based on vulnerability type
        validation_result = self._validate_file_attribution(vulnerability)

        if validation_result["is_valid"]:
            # File attribution is correct
            vulnerability["attribution_confidence"] = validation_result["confidence"]
            vulnerability["attribution_validation"] = "validated"
            return vulnerability
        else:
            # File attribution is incorrect - fix it
            return self._correct_file_attribution(vulnerability, validation_result)

    def _validate_file_attribution(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate if the file attribution is correct for this vulnerability type.

        Returns:
            Validation result with is_valid, confidence, and reasons
        """
        file_path = vulnerability.get("file_path", "")
        title = vulnerability.get("title", "").lower()
        vulnerability.get("vulnerable_pattern", "")

        # **MANIFEST VULNERABILITY DETECTION**: These should be attributed to AndroidManifest.xml
        manifest_indicators = [
            "target sdk",
            "backup enabled",
            "exported",
            "minimum sdk",
            "debug",
            "clear text traffic",
            "permission",
            "component",
            "allowbackup",
            "uses-permission",
            "application",
            "activity",
            "service",
            "receiver",
        ]

        is_manifest_vulnerability = any(indicator in title for indicator in manifest_indicators)

        if is_manifest_vulnerability:
            if file_path == "AndroidManifest.xml":
                return {"is_valid": True, "confidence": 0.95, "reason": "manifest_vulnerability_correctly_attributed"}
            else:
                return {
                    "is_valid": False,
                    "confidence": 0.1,
                    "reason": "manifest_vulnerability_wrong_file",
                    "correct_file": "AndroidManifest.xml",
                }

        # **SOURCE CODE VULNERABILITY VALIDATION**: Check if file exists and is relevant
        if not self._file_exists(file_path):
            return {"is_valid": False, "confidence": 0.0, "reason": "file_does_not_exist", "correct_file": None}

        # **CONTENT RELEVANCE CHECK**: Verify file contains relevant code
        relevance_score = self._check_content_relevance(file_path, vulnerability)

        # ACCURACY FIX: More lenient validation for app files vs third-party libraries
        # App package files should be considered more relevant than third-party code
        is_app_package = self._is_likely_app_package_file(file_path, vulnerability)

        # Adjust thresholds based on file type
        if is_app_package:
            valid_threshold = 0.2  # Lower threshold for app package files
            partial_threshold = 0.1  # Very low threshold for partial relevance
        else:
            valid_threshold = 0.5  # Higher threshold for third-party files
            partial_threshold = 0.3  # Standard threshold for partial relevance

        if relevance_score >= valid_threshold:
            return {
                "is_valid": True,
                "confidence": min(0.95, relevance_score + (0.3 if is_app_package else 0.0)),
                "reason": "file_exists_and_relevant",
            }
        elif relevance_score >= partial_threshold:
            return {
                "is_valid": True,
                "confidence": min(0.8, relevance_score + (0.2 if is_app_package else 0.0)),
                "reason": "file_exists_partially_relevant",
            }
        else:
            # Even for low relevance, don't completely reject app package files
            if is_app_package and relevance_score > 0.0:
                return {
                    "is_valid": True,
                    "confidence": 0.6,  # Medium confidence for app files with any relevance
                    "reason": "file_exists_app_package_fallback",
                }
            else:
                return {
                    "is_valid": False,
                    "confidence": relevance_score,
                    "reason": "file_exists_but_not_relevant",
                    "correct_file": None,
                }

    def _correct_file_attribution(
        self, vulnerability: Dict[str, Any], validation_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Correct incorrect file attribution based on validation results.

        CRITICAL FIX: Uses rate-limited logging to prevent log spam
        while maintaining detailed debugging for unique cases.

        BROADER AODS SCOPE CONSIDERATIONS:
        - Maintains correction statistics for system monitoring
        - Provides summary reporting for bulk operations
        - Prevents log system overwhelm during large scans
        - Preserves debugging capability for unique correction cases
        """
        original_file = vulnerability.get("file_path", "")
        title = vulnerability.get("title", "")

        # AODS FIX: Create unique correction identifier for deduplication
        correction_key = f"{title[:30]}_{original_file}_{validation_result['reason']}"

        # Track correction statistics for AODS monitoring
        reason = validation_result["reason"]
        if reason not in self._correction_stats:
            self._correction_stats[reason] = {"count": 0, "examples": [], "corrected_files": set()}

        self._correction_stats[reason]["count"] += 1

        # AODS FIX: Rate-limited logging to prevent spam
        should_log = self._should_log_correction(correction_key, reason)

        if should_log:
            self.logger.info("🔧 **CORRECTING FILE ATTRIBUTION**:")
            self.logger.info(f"   - Vulnerability: {title[:50]}")
            self.logger.info(f"   - Original file: {original_file}")
            self.logger.info(f"   - Reason: {reason}")

            # Add rate limiting notice for common patterns
            if self._correction_stats[reason]["count"] > self._max_logs_per_pattern:
                self.logger.info(
                    f"   - Note: Similar corrections occurring (total: {self._correction_stats[reason]['count']})"
                )

        if validation_result.get("correct_file"):
            # We have a specific correct file to use
            corrected_file = validation_result["correct_file"]
            vulnerability["file_path"] = corrected_file
            vulnerability["attribution_confidence"] = 0.9
            vulnerability["attribution_validation"] = "corrected"

            # Track corrected file statistics
            self._correction_stats[reason]["corrected_files"].add(corrected_file)

            # Update related fields for manifest corrections
            if corrected_file == "AndroidManifest.xml":
                vulnerability["line_number"] = 1
                vulnerability["class_name"] = "Manifest Configuration"
                vulnerability["method_name"] = ""

            if should_log:
                self.logger.info(f"   - Corrected file: {corrected_file}")

        else:
            # No clear correct file - mark as uncategorized with low confidence
            vulnerability["file_path"] = "unknown"
            vulnerability["attribution_confidence"] = 0.1
            vulnerability["attribution_validation"] = "failed"
            vulnerability["line_number"] = 0
            vulnerability["class_name"] = "Unknown"
            vulnerability["method_name"] = ""

            if should_log:
                self.logger.debug("   - No correct file found - marked as unknown")

        # Store example for statistics if we don't have many yet
        if len(self._correction_stats[reason]["examples"]) < 3:
            self._correction_stats[reason]["examples"].append(
                {
                    "title": title[:30],
                    "original_file": original_file,
                    "corrected_file": validation_result.get("correct_file", "unknown"),
                }
            )

        return vulnerability

    def _should_log_correction(self, correction_key: str, reason: str) -> bool:
        """
        Determine if a correction should be logged based on rate limiting.

        AODS COMPATIBILITY: Ensures critical corrections are always logged
        while preventing spam for repetitive patterns.
        """
        # Always log the first few occurrences of each correction reason
        if self._correction_stats[reason]["count"] <= self._max_logs_per_pattern:
            return True

        # Always log unique correction keys (different vulnerability + file combinations)
        if correction_key not in self._processed_corrections:
            self._processed_corrections.add(correction_key)
            return True

        # Log every 50th occurrence for high-volume patterns (for monitoring)
        if self._correction_stats[reason]["count"] % 50 == 0:
            return True

        # Don't log repetitive corrections
        return False

    def get_correction_statistics(self) -> Dict[str, Any]:
        """
        Get correction statistics for AODS system monitoring and reporting.

        BROADER AODS SCOPE: Provides insights for system optimization
        and helps identify patterns in file attribution issues.
        """
        total_corrections = sum(stats["count"] for stats in self._correction_stats.values())

        return {
            "total_corrections": total_corrections,
            "correction_reasons": dict(self._correction_stats),
            "unique_correction_patterns": len(self._processed_corrections),
            "most_common_reason": (
                max(self._correction_stats.items(), key=lambda x: x[1]["count"])[0] if self._correction_stats else None
            ),
        }

    def _handle_missing_file_path(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle vulnerabilities that don't have a file_path specified.
        """
        title = vulnerability.get("title", "").lower()

        # Try to infer file path from vulnerability characteristics
        if any(indicator in title for indicator in ["target sdk", "backup", "exported", "permission"]):
            vulnerability["file_path"] = "AndroidManifest.xml"
            vulnerability["attribution_confidence"] = 0.8
            vulnerability["attribution_validation"] = "inferred_manifest"
            vulnerability["line_number"] = 1
            vulnerability["class_name"] = "Manifest Configuration"

            self.logger.info(f"🔧 **INFERRED MANIFEST ATTRIBUTION**: {title[:50]}")

        else:
            vulnerability["file_path"] = "unknown"
            vulnerability["attribution_confidence"] = 0.1
            vulnerability["attribution_validation"] = "no_attribution"
            vulnerability["line_number"] = 0
            vulnerability["class_name"] = "Unknown"

            self.logger.warning(f"⚠️ **NO FILE ATTRIBUTION**: {title[:50]}")

        return vulnerability

    def _file_exists(self, file_path: str) -> bool:
        """
        Check if a file exists, considering both absolute and relative paths.
        """
        cached_result = self.cache_manager.retrieve(f"{self._cache_namespace}:exists:{file_path}", CacheType.GENERAL)
        if cached_result is not None:
            return cached_result

        exists = False

        # Check common locations for the file
        possible_paths = [
            file_path,  # Absolute or relative path as given
            os.path.join(self.decompiled_source_dir or "", file_path) if self.decompiled_source_dir else None,
            os.path.join("sources", file_path),
            os.path.join("jadx-output", "sources", file_path),
        ]

        for path in possible_paths:
            if path and os.path.isfile(path):
                exists = True
                break

        # Special case: AndroidManifest.xml is always considered to exist
        if file_path == "AndroidManifest.xml":
            exists = True

        self.cache_manager.store(
            f"{self._cache_namespace}:exists:{file_path}",
            exists,
            CacheType.GENERAL,
            ttl_hours=1,
            tags=[self._cache_namespace],
        )
        return exists

    def _check_content_relevance(self, file_path: str, vulnerability: Dict[str, Any]) -> float:
        """
        Check how relevant the file content is to the vulnerability.

        Returns:
            Relevance score between 0.0 and 1.0
        """
        cached_content = self.cache_manager.retrieve(f"{self._cache_namespace}:content:{file_path}", CacheType.GENERAL)
        if cached_content is not None:
            return cached_content.get("relevance", 0.0)

        try:
            # Read file content for analysis
            content = self._read_file_safely(file_path)
            if not content:
                return 0.0

            # Analyze content relevance based on vulnerability pattern
            relevance_score = self._calculate_content_relevance(content, vulnerability)

            # Cache the result
            self.cache_manager.store(
                f"{self._cache_namespace}:content:{file_path}",
                {"relevance": relevance_score, "content_length": len(content), "analyzed": True},
                CacheType.GENERAL,
                ttl_hours=2,
                tags=[self._cache_namespace],
            )

            return relevance_score

        except Exception as e:
            self.logger.warning(f"Failed to analyze content relevance for {file_path}: {e}")
            return 0.3  # Default moderate relevance for unanalyzable files

    def _read_file_safely(self, file_path: str) -> Optional[str]:
        """
        Safely read file content with proper error handling.
        """
        try:
            # Find the actual file path
            actual_path = None
            possible_paths = [
                file_path,
                os.path.join(self.decompiled_source_dir or "", file_path) if self.decompiled_source_dir else None,
                os.path.join("sources", file_path),
                os.path.join("jadx-output", "sources", file_path),
            ]

            for path in possible_paths:
                if path and os.path.isfile(path):
                    actual_path = path
                    break

            if not actual_path:
                return None

            with open(actual_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()

        except Exception as e:
            self.logger.debug(f"Could not read file {file_path}: {e}")
            return None

    def _calculate_content_relevance(self, content: str, vulnerability: Dict[str, Any]) -> float:
        """
        Calculate how relevant the file content is to the vulnerability.
        """
        if not content:
            return 0.0

        content_lower = content.lower()
        title = vulnerability.get("title", "").lower()
        pattern = vulnerability.get("vulnerable_pattern", "").lower()
        evidence = vulnerability.get("evidence", "").lower()

        relevance_score = 0.0

        # Check for direct pattern matches in content
        if pattern and pattern in content_lower:
            relevance_score += 0.4

        # Check for evidence presence in content
        if evidence and evidence in content_lower:
            relevance_score += 0.3

        # Check for title-related keywords
        title_keywords = title.split()
        keyword_matches = sum(1 for keyword in title_keywords if keyword in content_lower)
        if title_keywords:
            relevance_score += (keyword_matches / len(title_keywords)) * 0.3

        return min(1.0, relevance_score)

    def _is_likely_app_package_file(self, file_path: str, vulnerability: Dict[str, Any]) -> bool:
        """
        Determine if a file is likely part of the main app package vs a third-party library.
        App package files should be treated more leniently in validation.
        """
        if not file_path:
            return False

        # Get app context from vulnerability or framework filtering
        app_package = vulnerability.get("app_package", "")
        if not app_package:
            # Try to extract from file path
            # Most app packages follow structure: com/company/appname or org/company/appname
            path_parts = file_path.replace("\\", "/").split("/")
            if len(path_parts) >= 3:
                app_package = ".".join(path_parts[-4:-1]) if len(path_parts) >= 4 else ".".join(path_parts[-3:])

        file_path_normalized = file_path.replace("\\", "/").lower()

        # Check if this looks like app package code vs third-party
        app_indicators = [
            "/src/main/",  # Main source directory
            "/java/",  # Java source
            "/kotlin/",  # Kotlin source
        ]

        # Third-party library indicators (should be treated more strictly)
        library_indicators = [
            "/com/google/",
            "/com/facebook/",
            "/com/android/",
            "/androidx/",
            "/org/apache/",
            "/com/squareup/",
            "/retrofit/",
            "/okhttp/",
            "/com/admarvel/",  # Ad library (from the logs)
            "/ads/",
            "/analytics/",
            "/tracking/",
        ]

        # Check for app indicators
        app_score = sum(1 for indicator in app_indicators if indicator in file_path_normalized)

        # Check for library indicators
        library_score = sum(1 for indicator in library_indicators if indicator in file_path_normalized)

        # If the file is in the app package, treat it as app code
        if app_package and app_package.replace(".", "/") in file_path_normalized:
            return True

        # If it has more library indicators, treat as third-party
        if library_score > app_score:
            return False

        # Default: if it has any app indicators or no strong library indicators, treat as app
        return app_score > 0 or library_score == 0

    def get_validation_statistics(self) -> Dict[str, Any]:
        """
        Get validation statistics.
        """
        # Statistics: unified cache manager returns overall stats; detailed per-key stats omitted for performance
        stats = self.cache_manager.get_cache_statistics().get("overall_metrics", {})
        return {
            "files_checked": stats.get("entries_count", 0),
            "files_exist": 0,
            "content_analyzed": stats.get("entries_count", 0),
            "average_relevance": 0.0,
        }


def validate_vulnerability_file_attribution(vulnerability: Dict[str, Any], source_dir: str = None) -> Dict[str, Any]:
    """
    Convenience function to validate a single vulnerability's file attribution.

    Args:
        vulnerability: Vulnerability dictionary to validate
        source_dir: Optional decompiled source directory path

    Returns:
        Validated vulnerability with corrected attribution
    """
    validator = SourceFileValidator(source_dir)
    return validator.validate_vulnerability_attribution(vulnerability)
