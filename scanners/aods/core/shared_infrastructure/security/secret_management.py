#!/usr/bin/env python3
"""
Unified Secret Management for AODS Security Framework

Consolidated secret detection and management capabilities.
"""

import logging
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class SecretType(Enum):
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    PRIVATE_KEY = "private_key"


class SecretSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecretManagementConfig:
    comprehensive_detection: bool = True
    preserve_potential_secrets: bool = True
    enable_context_analysis: bool = True


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


@dataclass
class SecretContext:
    file_type: str
    context_lines: List[str]
    metadata: Dict[str, Any]


class UnifiedSecretManager:
    def __init__(self, config: SecretManagementConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Import implementation
        from .secret_management_comprehensive import ComprehensiveSecretManager

        self._comprehensive_engine = ComprehensiveSecretManager(config)

        self.logger.info("✅ Unified Secret Manager initialized with detection")

    def detect_secrets(self, target: Any, context: Any) -> List[SecretFinding]:
        """Delegate to full secret detection engine."""
        return self._comprehensive_engine.detect_secrets(target, context)
