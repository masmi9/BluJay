#!/usr/bin/env python3
"""
Unified Threat Intelligence for AODS Security Framework

Consolidated threat intelligence and risk scoring capabilities.
"""

import logging
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IOCType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"


@dataclass
class ThreatIntelligenceConfig:
    enable_ioc_matching: bool = True
    enable_reputation_checking: bool = True
    feed_update_interval: int = 6


@dataclass
class ThreatIndicator:
    ioc_type: IOCType
    value: str
    threat_level: ThreatLevel
    confidence: float


@dataclass
class ThreatContext:
    source: str
    timestamp: str
    metadata: Dict[str, Any]


class UnifiedThreatIntelligence:
    def __init__(self, config: ThreatIntelligenceConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Import implementation
        from .threat_intelligence_comprehensive import ComprehensiveThreatIntelligence

        self._comprehensive_engine = ComprehensiveThreatIntelligence(config)

        self.logger.info("✅ Unified Threat Intelligence initialized with full IOC matching")

    def correlate_threats(self, analysis_results: Dict[str, Any], context: Any) -> List[ThreatIndicator]:
        """Delegate to full threat intelligence engine."""
        return self._comprehensive_engine.correlate_threats(analysis_results, context)
