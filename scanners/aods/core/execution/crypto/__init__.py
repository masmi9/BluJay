#!/usr/bin/env python3
"""
Modular Crypto Analysis Module - Enhanced Architecture
=====================================================

Modular cryptographic analysis system with interface-driven design.
Migrates and enhances capabilities from the deprecated CryptographicSecurityAnalyzer
(1960 lines) while maintaining full capability preservation.

This module implements:
- Strategy pattern for different crypto analysis approaches
- Interface segregation for clean component separation
- Dependency injection for testable, configurable components
- Enhanced pattern matching and vulnerability assessment
- Full crypto security analysis with zero functionality loss
"""

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

from .components import CryptoPatternMatcher, CryptoVulnerabilityAssessor, CryptoFindingEnricher, CryptoPatternLibrary

from .crypto_manager import ModularCryptoAnalysisManager, CryptoAnalysisFactory, create_crypto_analysis_manager

__all__ = [
    # Strategies
    "CipherAnalysisStrategy",
    "HashAnalysisStrategy",
    "KeyManagementStrategy",
    "SSLTLSAnalysisStrategy",
    "RandomnessAnalysisStrategy",
    "SecretDetectionStrategy",
    "CertificateValidationStrategy",
    "CustomCryptoStrategy",
    # Components
    "CryptoPatternMatcher",
    "CryptoVulnerabilityAssessor",
    "CryptoFindingEnricher",
    "CryptoPatternLibrary",
    # Manager
    "ModularCryptoAnalysisManager",
    "CryptoAnalysisFactory",
    "create_crypto_analysis_manager",
]
