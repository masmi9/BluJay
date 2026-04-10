#!/usr/bin/env python3
"""
Modular Crypto Analysis Manager - Orchestration Implementation
=============================================================

Orchestrates cryptographic analysis using strategy pattern and dependency injection.
Provides a clean interface for crypto analysis while maintaining full modularity and testability.

This manager replaces the monolithic CryptographicSecurityAnalyzer (1960 lines)
with a flexible, component-based architecture while preserving all functionality.
"""

import logging
import time
from typing import Dict, List, Any, Optional, Type
from dataclasses import dataclass

from core.execution.interfaces.crypto_interfaces import (
    ICryptoAnalysisStrategy,
    ICryptoAnalysisManager,
    ICryptoAnalysisFactory,
    ICryptoPatternMatcher,
    ICryptoVulnerabilityAssessor,
    ICryptoFindingEnricher,
    CryptoAnalysisType,
    CryptoContext,
    CryptoAnalysisResult,
    CryptoAnalysisException,
)

from .strategies import (
    CipherAnalysisStrategy,
    HashAnalysisStrategy,
    KeyManagementStrategy,
    SSLTLSAnalysisStrategy,
    RandomnessAnalysisStrategy,
    SecretDetectionStrategy,
    CertificateValidationStrategy,
    CustomCryptoStrategy,
)

from .components import CryptoPatternMatcher, CryptoVulnerabilityAssessor, CryptoFindingEnricher

logger = logging.getLogger(__name__)


@dataclass
class CryptoAnalysisConfig:
    """Configuration for crypto analysis manager."""

    enable_cipher_analysis: bool = True
    enable_hash_analysis: bool = True
    enable_key_management: bool = True
    enable_ssl_analysis: bool = True
    enable_randomness_analysis: bool = True
    enable_secret_detection: bool = True
    enable_certificate_analysis: bool = True
    enable_custom_crypto_detection: bool = True

    # Analysis depth settings
    analysis_depth: str = "full"  # "basic", "standard", "full"
    confidence_threshold: float = 0.3
    max_findings_per_type: int = 100

    # Performance settings
    enable_parallel_analysis: bool = False
    max_file_size_mb: int = 10
    timeout_seconds: int = 300


class CryptoAnalysisFactory(ICryptoAnalysisFactory):
    """Factory for creating crypto analysis components."""

    def __init__(self):
        """Initialize crypto analysis factory."""
        self._strategies: Dict[CryptoAnalysisType, Type[ICryptoAnalysisStrategy]] = {
            CryptoAnalysisType.CIPHER_ANALYSIS: CipherAnalysisStrategy,
            CryptoAnalysisType.HASH_ANALYSIS: HashAnalysisStrategy,
            CryptoAnalysisType.KEY_MANAGEMENT: KeyManagementStrategy,
            CryptoAnalysisType.SSL_TLS_ANALYSIS: SSLTLSAnalysisStrategy,
            CryptoAnalysisType.RANDOMNESS_ANALYSIS: RandomnessAnalysisStrategy,
            CryptoAnalysisType.SECRET_DETECTION: SecretDetectionStrategy,
            CryptoAnalysisType.CERTIFICATE_VALIDATION: CertificateValidationStrategy,
            CryptoAnalysisType.CUSTOM_CRYPTO: CustomCryptoStrategy,
        }
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def create_strategy(self, analysis_type: CryptoAnalysisType) -> ICryptoAnalysisStrategy:
        """Create analysis strategy based on type."""
        if analysis_type not in self._strategies:
            raise ValueError(f"Unknown crypto analysis type: {analysis_type}")

        strategy_class = self._strategies[analysis_type]
        return strategy_class()

    def create_pattern_matcher(self) -> ICryptoPatternMatcher:
        """Create pattern matcher instance."""
        return CryptoPatternMatcher()

    def create_vulnerability_assessor(self) -> ICryptoVulnerabilityAssessor:
        """Create vulnerability assessor instance."""
        return CryptoVulnerabilityAssessor()

    def create_finding_enricher(self) -> ICryptoFindingEnricher:
        """Create finding enricher instance."""
        return CryptoFindingEnricher()

    def register_custom_strategy(
        self, analysis_type: CryptoAnalysisType, strategy_class: Type[ICryptoAnalysisStrategy]
    ):
        """Register a custom analysis strategy."""
        self._strategies[analysis_type] = strategy_class
        self.logger.info(f"Registered custom strategy: {analysis_type}")


class ModularCryptoAnalysisManager(ICryptoAnalysisManager):
    """
    Modular crypto analysis manager with dependency injection.

    Orchestrates crypto analysis using pluggable components:
    - Strategy pattern for different analysis approaches
    - Pluggable pattern matching, assessment, and enrichment
    - Enhanced error handling and logging
    - Performance monitoring and metrics
    - Full compatibility with original CryptographicSecurityAnalyzer
    """

    def __init__(
        self,
        config: Optional[CryptoAnalysisConfig] = None,
        factory: Optional[ICryptoAnalysisFactory] = None,
        pattern_matcher: Optional[ICryptoPatternMatcher] = None,
        vulnerability_assessor: Optional[ICryptoVulnerabilityAssessor] = None,
        finding_enricher: Optional[ICryptoFindingEnricher] = None,
    ):
        """Initialize modular crypto analysis manager.

        Args:
            config: Analysis configuration
            factory: Factory for creating strategies
            pattern_matcher: Custom pattern matcher (optional)
            vulnerability_assessor: Custom assessor (optional)
            finding_enricher: Custom enricher (optional)
        """
        self.config = config or CryptoAnalysisConfig()
        self.factory = factory or CryptoAnalysisFactory()

        # Create components with dependency injection
        self.pattern_matcher = pattern_matcher or self.factory.create_pattern_matcher()
        self.vulnerability_assessor = vulnerability_assessor or self.factory.create_vulnerability_assessor()
        self.finding_enricher = finding_enricher or self.factory.create_finding_enricher()

        # Initialize strategies based on configuration
        self._strategies: Dict[CryptoAnalysisType, ICryptoAnalysisStrategy] = {}
        self._initialize_strategies()

        # Performance tracking (migrated from original)
        self.analysis_metrics = {
            "total_analyses": 0,
            "successful_analyses": 0,
            "failed_analyses": 0,
            "total_findings": 0,
            "average_processing_time": 0.0,
            "files_analyzed": 0,
        }

        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.logger.info(f"Modular crypto analysis manager initialized with {len(self._strategies)} strategies")

    def register_strategy(self, strategy: ICryptoAnalysisStrategy) -> None:
        """Register a crypto analysis strategy."""
        self._strategies[strategy.analysis_type] = strategy
        self.logger.info(f"Registered strategy: {strategy.analysis_type}")

    def analyze_comprehensive(self, context: CryptoContext) -> List[CryptoAnalysisResult]:
        """
        Perform full crypto analysis using all registered strategies.

        This is the main entry point that replaces CryptographicSecurityAnalyzer.analyze
        with enhanced modularity and capability preservation.

        Args:
            context: Analysis context with content and metadata

        Returns:
            List[CryptoAnalysisResult]: Results from all strategies

        Raises:
            CryptoAnalysisException: If analysis fails
        """
        start_time = time.time()

        try:
            self.logger.info(f"🔐 Starting full crypto analysis of {context.file_path}")

            # Validate context
            if not self._validate_context(context):
                raise CryptoAnalysisException("Invalid analysis context")

            # Run all enabled strategies
            results = []
            total_findings = 0

            for analysis_type, strategy in self._strategies.items():
                if self._is_analysis_enabled(analysis_type):
                    try:
                        result = strategy.analyze(context)

                        # Enrich findings
                        enriched_findings = []
                        for finding in result.findings:
                            enriched_finding = self.finding_enricher.enrich_finding(finding, context)

                            # Apply confidence threshold
                            if enriched_finding.confidence >= self.config.confidence_threshold:
                                enriched_findings.append(enriched_finding)

                        result.findings = enriched_findings[: self.config.max_findings_per_type]
                        results.append(result)
                        total_findings += len(result.findings)

                        self.logger.debug(f"✅ {analysis_type}: {len(result.findings)} findings")

                    except Exception as e:
                        self.logger.warning(f"❌ {analysis_type} analysis failed: {e}")
                        # Continue with other analyses

            processing_time = time.time() - start_time

            # Update metrics
            self._update_metrics(results, success=True, processing_time=processing_time)

            self.logger.info(
                f"🎉 Full crypto analysis completed: " f"{total_findings} findings in {processing_time:.2f}s"
            )

            return results

        except Exception as e:
            processing_time = time.time() - start_time
            self._update_metrics([], success=False, processing_time=processing_time)

            self.logger.error(f"❌ Full crypto analysis failed after {processing_time:.2f}s: {e}")
            raise CryptoAnalysisException(f"Full crypto analysis failed: {e}")

    def analyze_specific(
        self, context: CryptoContext, analysis_types: List[CryptoAnalysisType]
    ) -> List[CryptoAnalysisResult]:
        """
        Perform specific types of crypto analysis.

        Args:
            context: Analysis context
            analysis_types: Types of analysis to perform

        Returns:
            List[CryptoAnalysisResult]: Results from specified analyses
        """
        start_time = time.time()

        try:
            self.logger.info(f"🔐 Starting specific crypto analysis: {analysis_types}")

            results = []

            for analysis_type in analysis_types:
                if analysis_type in self._strategies:
                    strategy = self._strategies[analysis_type]
                    result = strategy.analyze(context)

                    # Enrich findings
                    enriched_findings = []
                    for finding in result.findings:
                        enriched_finding = self.finding_enricher.enrich_finding(finding, context)
                        if enriched_finding.confidence >= self.config.confidence_threshold:
                            enriched_findings.append(enriched_finding)

                    result.findings = enriched_findings
                    results.append(result)
                else:
                    self.logger.warning(f"Strategy not available: {analysis_type}")

            processing_time = time.time() - start_time
            self.logger.info(f"✅ Specific crypto analysis completed in {processing_time:.2f}s")

            return results

        except Exception as e:
            processing_time = time.time() - start_time
            self.logger.error(f"❌ Specific crypto analysis failed: {e}")
            raise CryptoAnalysisException(f"Specific crypto analysis failed: {e}")

    def get_analysis_metrics(self) -> Dict[str, Any]:
        """
        Get overall analysis metrics.

        Migrates metrics functionality from CryptographicSecurityAnalyzer.get_analysis_metrics.
        """
        return self.analysis_metrics.copy()

    def _initialize_strategies(self):
        """Initialize strategies based on configuration."""
        strategy_configs = [
            (CryptoAnalysisType.CIPHER_ANALYSIS, self.config.enable_cipher_analysis),
            (CryptoAnalysisType.HASH_ANALYSIS, self.config.enable_hash_analysis),
            (CryptoAnalysisType.KEY_MANAGEMENT, self.config.enable_key_management),
            (CryptoAnalysisType.SSL_TLS_ANALYSIS, self.config.enable_ssl_analysis),
            (CryptoAnalysisType.RANDOMNESS_ANALYSIS, self.config.enable_randomness_analysis),
            (CryptoAnalysisType.SECRET_DETECTION, self.config.enable_secret_detection),
            (CryptoAnalysisType.CERTIFICATE_VALIDATION, self.config.enable_certificate_analysis),
            (CryptoAnalysisType.CUSTOM_CRYPTO, self.config.enable_custom_crypto_detection),
        ]

        for analysis_type, enabled in strategy_configs:
            if enabled:
                try:
                    strategy = self.factory.create_strategy(analysis_type)
                    self._strategies[analysis_type] = strategy
                except Exception as e:
                    self.logger.warning(f"Failed to initialize {analysis_type}: {e}")

    def _validate_context(self, context: CryptoContext) -> bool:
        """Validate analysis context."""
        if not context.content:
            self.logger.error("Analysis context missing content")
            return False

        if not context.file_path:
            self.logger.warning("Analysis context missing file path")

        # Check file size limit
        content_size_mb = len(context.content.encode("utf-8")) / (1024 * 1024)
        if content_size_mb > self.config.max_file_size_mb:
            self.logger.error(f"File too large: {content_size_mb:.1f}MB > {self.config.max_file_size_mb}MB")
            return False

        return True

    def _is_analysis_enabled(self, analysis_type: CryptoAnalysisType) -> bool:
        """Check if analysis type is enabled."""
        config_mapping = {
            CryptoAnalysisType.CIPHER_ANALYSIS: self.config.enable_cipher_analysis,
            CryptoAnalysisType.HASH_ANALYSIS: self.config.enable_hash_analysis,
            CryptoAnalysisType.KEY_MANAGEMENT: self.config.enable_key_management,
            CryptoAnalysisType.SSL_TLS_ANALYSIS: self.config.enable_ssl_analysis,
            CryptoAnalysisType.RANDOMNESS_ANALYSIS: self.config.enable_randomness_analysis,
            CryptoAnalysisType.SECRET_DETECTION: self.config.enable_secret_detection,
            CryptoAnalysisType.CERTIFICATE_VALIDATION: self.config.enable_certificate_analysis,
            CryptoAnalysisType.CUSTOM_CRYPTO: self.config.enable_custom_crypto_detection,
        }

        return config_mapping.get(analysis_type, True)

    def _update_metrics(self, results: List[CryptoAnalysisResult], success: bool, processing_time: float):
        """Update analysis metrics."""
        self.analysis_metrics["total_analyses"] += 1

        if success:
            self.analysis_metrics["successful_analyses"] += 1

            # Update findings count
            total_findings = sum(len(result.findings) for result in results)
            self.analysis_metrics["total_findings"] += total_findings

            # Update files analyzed
            self.analysis_metrics["files_analyzed"] += 1

            # Update average processing time
            current_avg = self.analysis_metrics["average_processing_time"]
            total_successful = self.analysis_metrics["successful_analyses"]
            new_avg = ((current_avg * (total_successful - 1)) + processing_time) / total_successful
            self.analysis_metrics["average_processing_time"] = new_avg
        else:
            self.analysis_metrics["failed_analyses"] += 1

    def update_config(self, new_config: CryptoAnalysisConfig):
        """Update analysis configuration and reinitialize strategies."""
        old_config = self.config
        self.config = new_config

        # Reinitialize strategies if configuration changed significantly
        if self._config_requires_reinitialization(old_config, new_config):
            self._strategies.clear()
            self._initialize_strategies()
            self.logger.info("Strategies reinitialized due to configuration change")

    def _config_requires_reinitialization(
        self, old_config: CryptoAnalysisConfig, new_config: CryptoAnalysisConfig
    ) -> bool:
        """Check if configuration change requires strategy reinitialization."""
        strategy_flags = [
            "enable_cipher_analysis",
            "enable_hash_analysis",
            "enable_key_management",
            "enable_ssl_analysis",
            "enable_randomness_analysis",
            "enable_secret_detection",
            "enable_certificate_analysis",
            "enable_custom_crypto_detection",
        ]

        for flag in strategy_flags:
            if getattr(old_config, flag) != getattr(new_config, flag):
                return True

        return False


# Factory function for easy instantiation


def create_crypto_analysis_manager(config: Optional[CryptoAnalysisConfig] = None) -> ModularCryptoAnalysisManager:
    """Create a crypto analysis manager with default configuration.

    Args:
        config: Optional crypto analysis configuration

    Returns:
        ModularCryptoAnalysisManager: Configured crypto analysis manager
    """
    return ModularCryptoAnalysisManager(config or CryptoAnalysisConfig())


# Convenience function for quick analysis


def analyze_crypto_content(
    content: str, file_path: str = "", analysis_types: Optional[List[CryptoAnalysisType]] = None
) -> List[CryptoAnalysisResult]:
    """Convenience function for quick crypto analysis.

    Args:
        content: Content to analyze
        file_path: File path for context
        analysis_types: Specific analysis types (None for full)

    Returns:
        List[CryptoAnalysisResult]: Analysis results
    """
    context = CryptoContext(content=content, file_path=file_path)
    manager = create_crypto_analysis_manager()

    if analysis_types:
        return manager.analyze_specific(context, analysis_types)
    else:
        return manager.analyze_comprehensive(context)
