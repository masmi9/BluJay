#!/usr/bin/env python3
"""
AODS Unified Threat Intelligence System
======================================

Consolidated threat intelligence framework that unifies all existing
threat intelligence capabilities into a single, coherent system.

This replaces and consolidates:
- core/threat_intelligence_engine.py (Basic Engine)
- core/shared_infrastructure/security/threat_intelligence.py (Unified System)
- core/external_data/threat_intel.py (Phase 15 Pipeline)
- Multiple runtime discovery threat intel components

Features:
- Unified data structures and APIs
- Multi-source threat feed integration (CVE/NVD, MITRE, commercial feeds)
- Real-time IOC detection and correlation
- AI-powered threat analysis and prediction
- Integration with AODS core vulnerability detection
- Performance-optimized with intelligent caching
"""

import asyncio
import logging
import threading
from datetime import datetime, UTC
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

# Import Phase 15 external data components
from .external_data.cve_nvd_client import CVENVDClient, CVEData
from .external_data.vulnerability_database import VulnerabilityDatabase
from .external_data.threat_intel import ThreatIntelligenceProcessor, ThreatIntelligence as Phase15ThreatIntel
from .external_data.pipeline_manager import ExternalDataPipelineManager

# MIGRATED: Import unified caching infrastructure
from core.shared_infrastructure.performance.caching_consolidation import get_unified_cache_manager

logger = logging.getLogger(__name__)

# Unified Enums (consolidating all existing enums)


class ThreatLevel(Enum):
    """Unified threat severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ThreatType(Enum):
    """Unified threat type classification."""

    VULNERABILITY = "vulnerability"
    MALWARE = "malware"
    APT = "apt"
    IOC = "ioc"
    CAMPAIGN = "campaign"
    TECHNIQUE = "technique"
    ACTOR = "actor"
    INFRASTRUCTURE = "infrastructure"


class IOCType(Enum):
    """Unified IOC type classification."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_HASH = "file_hash"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"


class ConfidenceLevel(Enum):
    """Unified confidence levels."""

    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


# Unified Data Structures


@dataclass
class UnifiedThreatIndicator:
    """Unified threat indicator combining all existing indicator types."""

    indicator_id: str
    value: str
    ioc_type: IOCType
    threat_level: ThreatLevel
    confidence: ConfidenceLevel
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    related_indicators: List[str] = field(default_factory=list)


@dataclass
class UnifiedThreatIntelligence:
    """Unified threat intelligence record consolidating all existing formats."""

    threat_id: str
    title: str
    description: str
    threat_type: ThreatType
    threat_level: ThreatLevel
    confidence: ConfidenceLevel
    source: str
    published_date: datetime
    modified_date: datetime

    # Vulnerability-specific fields
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None

    # Threat intelligence fields
    indicators: List[UnifiedThreatIndicator] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)

    # Correlation and analysis
    risk_score: float = 0.0
    correlation_confidence: float = 0.0
    recommended_actions: List[str] = field(default_factory=list)

    # Metadata
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def calculate_risk_score(self) -> float:
        """Calculate unified risk score based on multiple factors."""
        base_score = 5.0  # Neutral baseline

        # Threat level factor
        level_multipliers = {
            ThreatLevel.CRITICAL: 2.0,
            ThreatLevel.HIGH: 1.5,
            ThreatLevel.MEDIUM: 1.0,
            ThreatLevel.LOW: 0.7,
            ThreatLevel.INFORMATIONAL: 0.5,
        }
        base_score *= level_multipliers.get(self.threat_level, 1.0)

        # Confidence factor
        confidence_multipliers = {
            ConfidenceLevel.CONFIRMED: 1.2,
            ConfidenceLevel.HIGH: 1.1,
            ConfidenceLevel.MEDIUM: 1.0,
            ConfidenceLevel.LOW: 0.8,
            ConfidenceLevel.UNKNOWN: 0.6,
        }
        base_score *= confidence_multipliers.get(self.confidence, 1.0)

        # CVSS score factor (if available)
        if self.cvss_score:
            base_score = (base_score + self.cvss_score) / 2

        # IOC availability factor
        if self.indicators:
            base_score *= 1.2

        # Recency factor
        age_days = (datetime.now(UTC) - self.published_date).days
        if age_days <= 7:
            base_score *= 1.3  # Recent threats are more relevant
        elif age_days <= 30:
            base_score *= 1.1
        elif age_days > 365:
            base_score *= 0.8  # Older threats are less relevant

        self.risk_score = min(10.0, max(0.0, base_score))
        return self.risk_score


@dataclass
class ThreatCorrelationResult:
    """Unified threat correlation result."""

    vulnerability_id: str
    matched_threats: List[UnifiedThreatIntelligence]
    correlation_confidence: float
    risk_assessment: str
    recommended_actions: List[str]
    correlation_reasoning: str
    enrichment_data: Dict[str, Any] = field(default_factory=dict)


class UnifiedThreatIntelligenceSystem:
    """
    Unified threat intelligence system consolidating all AODS threat intelligence capabilities.

    This system replaces and unifies:
    - Basic threat intelligence engine
    - Enhanced threat platform
    - Shared infrastructure threat intelligence
    - Phase 15 external data pipeline
    - Runtime discovery threat intelligence

    Implements singleton pattern to ensure single instance across AODS.
    """

    _instance = None
    _lock = threading.Lock()
    _initialized = False

    def __new__(cls, config: Optional[Dict[str, Any]] = None):
        """Enforce singleton pattern for unified threat intelligence."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize unified threat intelligence system (singleton-safe)."""
        # Prevent re-initialization of singleton
        if self._initialized:
            return

        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Initialize Phase 15 external data pipeline
        self.external_pipeline: Optional[ExternalDataPipelineManager] = None
        self.cve_client: Optional[CVENVDClient] = None
        self.vuln_db: Optional[VulnerabilityDatabase] = None
        self.threat_processor: Optional[ThreatIntelligenceProcessor] = None

        # MIGRATED: Use unified cache manager; keep complex objects in-memory, persist metadata only
        self.cache_manager = get_unified_cache_manager()
        self._cache_namespace = "unified_threat_intelligence"
        self.threat_cache: Dict[str, UnifiedThreatIntelligence] = {}
        self.ioc_cache: Dict[str, List[UnifiedThreatIndicator]] = {}

        # Performance metrics
        self.metrics = {
            "total_threats": 0,
            "total_iocs": 0,
            "correlations_found": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "last_update": None,
        }

        # Initialize system
        self._initialize_system()

        # Mark as initialized (singleton pattern)
        self._initialized = True

        self.logger.info("🚀 Unified Threat Intelligence System initialized (singleton)")

    def _initialize_system(self) -> None:
        """Initialize the unified threat intelligence system."""
        try:
            # Initialize external data pipeline components
            pipeline_config = self.config.get("external_data", {})

            # Initialize CVE/NVD client
            cve_config = pipeline_config.get("cve_nvd", {})
            self.cve_client = CVENVDClient(cve_config)

            # Initialize vulnerability database
            vuln_db_config = pipeline_config.get("vulnerability_database", {})
            db_path = vuln_db_config.get("db_path", "data/unified_threat_intelligence.db")
            self.vuln_db = VulnerabilityDatabase(db_path)

            # Initialize threat intelligence processor
            threat_config = pipeline_config.get("threat_intelligence", {})
            self.threat_processor = ThreatIntelligenceProcessor(threat_config)

            self.logger.info("✅ External data components initialized")

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize external data components: {e}")
            # Continue with basic functionality

    async def initialize_async(self) -> None:
        """Initialize async components of the system."""
        try:
            if self.external_pipeline:
                await self.external_pipeline.initialize_components()
                await self.external_pipeline.start_pipeline()

            self.logger.info("✅ Async components initialized")

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize async components: {e}")

    async def correlate_with_vulnerability(self, vulnerability_data: Dict[str, Any]) -> ThreatCorrelationResult:
        """
        Correlate vulnerability with unified threat intelligence.

        This is the main integration point with AODS vulnerability detection.
        """
        vuln_id = vulnerability_data.get("id", "unknown")

        try:
            matched_threats = []
            correlation_confidence = 0.0
            enrichment_data = {}

            # Extract indicators from vulnerability
            indicators = self._extract_indicators_from_vulnerability(vulnerability_data)

            # Correlate with cached threat intelligence
            for indicator in indicators:
                threat_matches = await self._lookup_threat_by_indicator(indicator)
                matched_threats.extend(threat_matches)

            # Correlate with CVE/NVD data if available
            if self.cve_client:
                cve_matches = await self._correlate_with_cve_data(vulnerability_data)
                matched_threats.extend(cve_matches)

            # Correlate with external threat intelligence
            if self.threat_processor:
                intel_matches = await self._correlate_with_external_intel(vulnerability_data)
                matched_threats.extend(intel_matches)

            # Remove duplicates and calculate correlation confidence
            unique_threats = self._deduplicate_threats(matched_threats)
            correlation_confidence = self._calculate_correlation_confidence(unique_threats, indicators)

            # Generate risk assessment and recommendations
            risk_assessment = self._assess_risk(unique_threats, vulnerability_data)
            recommendations = self._generate_recommendations(unique_threats, vulnerability_data)

            # Create enrichment data
            enrichment_data = {
                "total_threats_found": len(unique_threats),
                "highest_risk_score": max([t.risk_score for t in unique_threats], default=0.0),
                "threat_types": list(set([t.threat_type.value for t in unique_threats])),
                "sources": list(set([t.source for t in unique_threats])),
                "mitre_techniques": list(set([tech for t in unique_threats for tech in t.mitre_techniques])),
                "correlation_timestamp": datetime.now(UTC).isoformat(),
            }

            # Update metrics
            self.metrics["correlations_found"] += 1

            result = ThreatCorrelationResult(
                vulnerability_id=vuln_id,
                matched_threats=unique_threats,
                correlation_confidence=correlation_confidence,
                risk_assessment=risk_assessment,
                recommended_actions=recommendations,
                correlation_reasoning=f"Correlated {len(unique_threats)} threats based on {len(indicators)} indicators",
                enrichment_data=enrichment_data,
            )

            self.logger.info(f"🔗 Correlated vulnerability {vuln_id} with {len(unique_threats)} threats")
            return result

        except Exception as e:
            self.logger.error(f"❌ Failed to correlate vulnerability {vuln_id}: {e}")

            # Return empty result on error
            return ThreatCorrelationResult(
                vulnerability_id=vuln_id,
                matched_threats=[],
                correlation_confidence=0.0,
                risk_assessment="UNKNOWN",
                recommended_actions=["Manual review recommended due to correlation error"],
                correlation_reasoning=f"Correlation failed: {str(e)}",
            )

    def _extract_indicators_from_vulnerability(self, vulnerability_data: Dict[str, Any]) -> List[str]:
        """Extract potential threat indicators from vulnerability data."""
        indicators = []

        # Extract from description and details
        text_fields = [
            vulnerability_data.get("description", ""),
            vulnerability_data.get("details", ""),
            vulnerability_data.get("evidence", ""),
            str(vulnerability_data.get("metadata", {})),
        ]

        combined_text = " ".join(text_fields)

        # Extract common indicators using regex patterns
        import re

        # IP addresses
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        indicators.extend(re.findall(ip_pattern, combined_text))

        # Domains
        domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
        indicators.extend(re.findall(domain_pattern, combined_text))

        # File hashes (MD5, SHA1, SHA256)
        hash_pattern = r"\b[a-fA-F0-9]{32,64}\b"
        indicators.extend(re.findall(hash_pattern, combined_text))

        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        indicators.extend(re.findall(url_pattern, combined_text))

        # Extract from specific vulnerability fields
        if "package_name" in vulnerability_data:
            indicators.append(vulnerability_data["package_name"])

        if "file_path" in vulnerability_data:
            indicators.append(vulnerability_data["file_path"])

        return list(set(indicators))  # Remove duplicates

    async def _lookup_threat_by_indicator(self, indicator: str) -> List[UnifiedThreatIntelligence]:
        """Look up threats by indicator in cached data."""
        threats = []

        # Check IOC cache first
        cached_iocs = self.ioc_cache.get(indicator)
        if cached_iocs is not None:
            self.metrics["cache_hits"] += 1
            # Convert cached IOCs to threat intelligence
            for ioc in cached_iocs:
                threat = self._convert_ioc_to_threat(ioc, indicator)
                if threat:
                    threats.append(threat)
        else:
            self.metrics["cache_misses"] += 1

            # Look up in threat processor if available
            if self.threat_processor:
                processor_results = self.threat_processor.lookup_ioc(indicator)
                for result in processor_results:
                    unified_threat = self._convert_phase15_to_unified(result)
                    threats.append(unified_threat)

        return threats

    async def _correlate_with_cve_data(self, vulnerability_data: Dict[str, Any]) -> List[UnifiedThreatIntelligence]:
        """Correlate with CVE/NVD data."""
        threats = []

        if not self.cve_client:
            return threats

        try:
            # Look for CVE IDs in vulnerability data
            cve_ids = []

            # Extract CVE IDs from description
            import re

            cve_pattern = r"CVE-\d{4}-\d{4,7}"
            text_to_search = f"{vulnerability_data.get('description', '')} {vulnerability_data.get('details', '')}"
            cve_ids.extend(re.findall(cve_pattern, text_to_search))

            # Look up each CVE ID
            for cve_id in cve_ids:
                cve_data = self.cve_client.get_cve_by_id(cve_id)
                if cve_data:
                    unified_threat = self._convert_cve_to_unified(cve_data)
                    threats.append(unified_threat)

            # Also search by severity and recent CVEs
            if vulnerability_data.get("severity") in ["HIGH", "CRITICAL"]:
                recent_cves = self.cve_client.query_cves(severity=vulnerability_data["severity"], limit=10)
                for cve_data in recent_cves:
                    unified_threat = self._convert_cve_to_unified(cve_data)
                    threats.append(unified_threat)

        except Exception as e:
            self.logger.error(f"❌ Failed to correlate with CVE data: {e}")

        return threats

    async def _correlate_with_external_intel(
        self, vulnerability_data: Dict[str, Any]
    ) -> List[UnifiedThreatIntelligence]:
        """Correlate with external threat intelligence."""
        threats = []

        if not self.threat_processor:
            return threats

        try:
            # Search threat intelligence by keywords
            search_terms = [
                vulnerability_data.get("title", ""),
                vulnerability_data.get("category", ""),
                vulnerability_data.get("plugin_name", ""),
            ]

            for term in search_terms:
                if term:
                    search_results = self.threat_processor.search_intelligence(term, min_confidence=0.5)
                    for result in search_results:
                        unified_threat = self._convert_phase15_to_unified(result)
                        threats.append(unified_threat)

        except Exception as e:
            self.logger.error(f"❌ Failed to correlate with external intelligence: {e}")

        return threats

    def _convert_phase15_to_unified(self, phase15_intel: Phase15ThreatIntel) -> UnifiedThreatIntelligence:
        """Convert Phase 15 threat intelligence to unified format."""
        # Map Phase 15 enums to unified enums
        threat_type_mapping = {
            "malware": ThreatType.MALWARE,
            "apt": ThreatType.APT,
            "vulnerability": ThreatType.VULNERABILITY,
            "ioc": ThreatType.IOC,
            "campaign": ThreatType.CAMPAIGN,
            "technique": ThreatType.TECHNIQUE,
            "actor": ThreatType.ACTOR,
            "infrastructure": ThreatType.INFRASTRUCTURE,
        }

        threat_level_mapping = {
            "CRITICAL": ThreatLevel.CRITICAL,
            "HIGH": ThreatLevel.HIGH,
            "MEDIUM": ThreatLevel.MEDIUM,
            "LOW": ThreatLevel.LOW,
            "INFO": ThreatLevel.INFORMATIONAL,
        }

        # Convert confidence to enum
        if phase15_intel.confidence >= 0.9:
            confidence = ConfidenceLevel.CONFIRMED
        elif phase15_intel.confidence >= 0.7:
            confidence = ConfidenceLevel.HIGH
        elif phase15_intel.confidence >= 0.5:
            confidence = ConfidenceLevel.MEDIUM
        elif phase15_intel.confidence >= 0.3:
            confidence = ConfidenceLevel.LOW
        else:
            confidence = ConfidenceLevel.UNKNOWN

        # Convert IOCs to unified indicators
        indicators = []
        for ioc in phase15_intel.iocs:
            ioc_type_str = ioc.get("type", "").lower()
            ioc_type = None

            # Map IOC types
            ioc_type_mapping = {
                "ip_address": IOCType.IP_ADDRESS,
                "domain": IOCType.DOMAIN,
                "url": IOCType.URL,
                "email": IOCType.EMAIL,
                "file_hash": IOCType.FILE_HASH,
                "registry_key": IOCType.REGISTRY_KEY,
                "file_path": IOCType.FILE_PATH,
                "mutex": IOCType.MUTEX,
                "user_agent": IOCType.USER_AGENT,
            }

            ioc_type = ioc_type_mapping.get(ioc_type_str, IOCType.FILE_HASH)

            indicator = UnifiedThreatIndicator(
                indicator_id=f"{phase15_intel.id}_{len(indicators)}",
                value=ioc.get("value", ""),
                ioc_type=ioc_type,
                threat_level=threat_level_mapping.get(phase15_intel.severity, ThreatLevel.MEDIUM),
                confidence=confidence,
                source=phase15_intel.source,
                first_seen=phase15_intel.published_date,
                last_seen=phase15_intel.modified_date,
                context=ioc,
            )
            indicators.append(indicator)

        unified_threat = UnifiedThreatIntelligence(
            threat_id=phase15_intel.id,
            title=phase15_intel.title,
            description=phase15_intel.description,
            threat_type=threat_type_mapping.get(phase15_intel.threat_type.value, ThreatType.IOC),
            threat_level=threat_level_mapping.get(phase15_intel.severity, ThreatLevel.MEDIUM),
            confidence=confidence,
            source=phase15_intel.source,
            published_date=phase15_intel.published_date,
            modified_date=phase15_intel.modified_date,
            indicators=indicators,
            mitre_techniques=phase15_intel.mitre_techniques,
            threat_actors=phase15_intel.threat_actors,
            campaigns=phase15_intel.campaigns,
            references=phase15_intel.references,
            tags=phase15_intel.tags,
            raw_data=phase15_intel.raw_data,
        )

        # Calculate risk score
        unified_threat.calculate_risk_score()

        return unified_threat

    def _convert_cve_to_unified(self, cve_data: CVEData) -> UnifiedThreatIntelligence:
        """Convert CVE data to unified threat intelligence format."""
        # Map CVE severity to threat level
        severity_mapping = {
            "CRITICAL": ThreatLevel.CRITICAL,
            "HIGH": ThreatLevel.HIGH,
            "MEDIUM": ThreatLevel.MEDIUM,
            "LOW": ThreatLevel.LOW,
        }

        unified_threat = UnifiedThreatIntelligence(
            threat_id=cve_data.cve_id,
            title=f"CVE {cve_data.cve_id}",
            description=cve_data.description,
            threat_type=ThreatType.VULNERABILITY,
            threat_level=severity_mapping.get(cve_data.severity, ThreatLevel.MEDIUM),
            confidence=ConfidenceLevel.CONFIRMED,  # CVE data is always confirmed
            source="CVE/NVD",
            published_date=cve_data.published_date,
            modified_date=cve_data.modified_date,
            cve_ids=[cve_data.cve_id],
            cwe_ids=cve_data.cwe_ids,
            cvss_score=cve_data.cvss_score,
            references=cve_data.references,
            tags=["cve", "nvd", "vulnerability"],
        )

        # Calculate risk score
        unified_threat.calculate_risk_score()

        return unified_threat

    def _convert_ioc_to_threat(
        self, ioc: UnifiedThreatIndicator, indicator_value: str
    ) -> Optional[UnifiedThreatIntelligence]:
        """Convert IOC to threat intelligence record."""
        return UnifiedThreatIntelligence(
            threat_id=f"IOC_{ioc.indicator_id}",
            title=f"Threat Indicator: {indicator_value}",
            description=f"Threat indicator of type {ioc.ioc_type.value}",
            threat_type=ThreatType.IOC,
            threat_level=ioc.threat_level,
            confidence=ioc.confidence,
            source=ioc.source,
            published_date=ioc.first_seen,
            modified_date=ioc.last_seen,
            indicators=[ioc],
            tags=ioc.tags,
        )

    def _deduplicate_threats(self, threats: List[UnifiedThreatIntelligence]) -> List[UnifiedThreatIntelligence]:
        """Remove duplicate threats based on threat_id and content similarity."""
        seen_ids = set()
        unique_threats = []

        for threat in threats:
            if threat.threat_id not in seen_ids:
                seen_ids.add(threat.threat_id)
                unique_threats.append(threat)

        return unique_threats

    def _calculate_correlation_confidence(
        self, threats: List[UnifiedThreatIntelligence], indicators: List[str]
    ) -> float:
        """Calculate correlation confidence based on threat matches and indicators."""
        if not threats or not indicators:
            return 0.0

        # Base confidence on number of matches
        base_confidence = min(len(threats) / 10.0, 1.0)  # Max confidence at 10+ threats

        # Boost confidence based on threat confidence levels
        avg_threat_confidence = sum(
            [
                {"confirmed": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4, "unknown": 0.2}[threat.confidence.value]
                for threat in threats
            ]
        ) / len(threats)

        # Boost confidence based on indicator matches
        indicator_factor = min(len(indicators) / 5.0, 1.0)  # Max boost at 5+ indicators

        final_confidence = (base_confidence + avg_threat_confidence + indicator_factor) / 3.0
        return min(final_confidence, 1.0)

    def _assess_risk(self, threats: List[UnifiedThreatIntelligence], vulnerability_data: Dict[str, Any]) -> str:
        """Assess overall risk based on matched threats."""
        if not threats:
            return "LOW"

        # Get highest risk score
        max_risk = max([threat.risk_score for threat in threats])

        # Count critical/high threats
        critical_count = sum(1 for t in threats if t.threat_level == ThreatLevel.CRITICAL)
        high_count = sum(1 for t in threats if t.threat_level == ThreatLevel.HIGH)

        if critical_count > 0 or max_risk >= 8.0:
            return "CRITICAL"
        elif high_count > 0 or max_risk >= 6.0:
            return "HIGH"
        elif max_risk >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_recommendations(
        self, threats: List[UnifiedThreatIntelligence], vulnerability_data: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations based on threat intelligence."""
        recommendations = []

        if not threats:
            recommendations.append("Monitor for emerging threats related to this vulnerability")
            return recommendations

        # Analyze threat types
        threat_types = [t.threat_type for t in threats]

        if ThreatType.MALWARE in threat_types:
            recommendations.append("Implement anti-malware scanning and monitoring")
            recommendations.append("Review network traffic for malware communication patterns")

        if ThreatType.APT in threat_types:
            recommendations.append("Enhance monitoring for advanced persistent threat indicators")
            recommendations.append("Implement behavioral analysis for APT detection")

        if ThreatType.VULNERABILITY in threat_types:
            recommendations.append("Apply security patches immediately if available")
            recommendations.append("Implement compensating controls until patches are available")

        # Check for active exploitation
        active_threats = [t for t in threats if t.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]]
        if active_threats:
            recommendations.append("Prioritize immediate remediation due to active threat indicators")
            recommendations.append("Consider temporary isolation of affected systems")

        # MITRE ATT&CK recommendations
        all_techniques = [tech for t in threats for tech in t.mitre_techniques]
        if all_techniques:
            recommendations.append(f"Review MITRE ATT&CK techniques: {', '.join(set(all_techniques[:5]))}")

        return recommendations

    async def update_threat_intelligence(self) -> Dict[str, Any]:
        """Update threat intelligence from all sources."""
        update_results = {
            "status": "success",
            "sources_updated": 0,
            "threats_added": 0,
            "threats_updated": 0,
            "errors": [],
        }

        try:
            # Update CVE/NVD data
            if self.cve_client:
                try:
                    cve_stats = await self.cve_client.sync_cve_database(days=7)
                    update_results["sources_updated"] += 1
                    update_results["threats_added"] += cve_stats.new_cves
                    update_results["threats_updated"] += cve_stats.updated_cves
                except Exception as e:
                    update_results["errors"].append(f"CVE update failed: {e}")

            # Update external threat intelligence
            if self.threat_processor:
                try:
                    intel_results = await self.threat_processor.update_all_feeds()
                    update_results["sources_updated"] += len(intel_results)

                    for source_id, result in intel_results.items():
                        if result.get("status") == "success":
                            update_results["threats_added"] += result.get("records_processed", 0)
                        else:
                            update_results["errors"].append(
                                f"Intel source {source_id} failed: {result.get('error', 'Unknown error')}"
                            )

                except Exception as e:
                    update_results["errors"].append(f"Threat intelligence update failed: {e}")

            # Update metrics
            self.metrics["last_update"] = datetime.now(UTC)
            # Cache statistics (in-memory cache sizes)
            self.metrics["total_threats"] = len(self.threat_cache)

            self.logger.info(
                f"✅ Threat intelligence updated: {update_results['sources_updated']} sources, "
                f"{update_results['threats_added']} new threats"
            )

        except Exception as e:
            update_results["status"] = "error"
            update_results["errors"].append(f"Update failed: {e}")
            self.logger.error(f"❌ Threat intelligence update failed: {e}")

        return update_results

    def get_system_status(self) -> Dict[str, Any]:
        """Get unified threat intelligence system status."""
        return {
            "system_status": "operational",
            "components": {
                "cve_client": "available" if self.cve_client else "unavailable",
                "vulnerability_database": "available" if self.vuln_db else "unavailable",
                "threat_processor": "available" if self.threat_processor else "unavailable",
                "external_pipeline": "available" if self.external_pipeline else "unavailable",
            },
            "metrics": self.metrics.copy(),
            "cache_stats": {
                "threat_cache_size": len(self.threat_cache),
                "ioc_cache_size": sum(len(v) for v in self.ioc_cache.values()),
            },
            "last_update": self.metrics.get("last_update"),
        }

    def get_legacy_adapter(self):
        """
        Provide legacy ThreatIntelligenceEngine interface for backward compatibility.

        Returns an adapter that implements the legacy interface while routing
        all calls through the unified system.
        """
        return LegacyThreatIntelligenceAdapter(self)

    def get_advanced_adapter(self):
        """
        Provide legacy AdvancedIntelligenceEngine interface for backward compatibility.

        Returns an adapter that implements the legacy interface while routing
        all calls through the unified system.
        """
        return AdvancedIntelligenceAdapter(self)


# Legacy Compatibility Adapters
class LegacyThreatIntelligenceAdapter:
    """
    Adapter providing legacy ThreatIntelligenceEngine interface.

    Routes all calls through the unified threat intelligence system
    while maintaining backward compatibility with existing code.
    """

    def __init__(self, unified_system: UnifiedThreatIntelligenceSystem):
        self.unified_system = unified_system
        self.logger = logging.getLogger(__name__)

    def correlate_threats(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """Legacy threat correlation interface."""
        # Route through unified system
        correlation_result = asyncio.run(self.unified_system.correlate_with_vulnerability(vulnerability_data))

        # Convert to legacy format
        return {
            "threats_found": len(correlation_result.matched_threats),
            "correlation_confidence": correlation_result.correlation_confidence,
            "risk_level": correlation_result.risk_assessment,
            "recommendations": correlation_result.recommended_actions,
            "threat_details": [
                {
                    "threat_id": threat.threat_id,
                    "threat_type": threat.threat_type.value,
                    "severity": threat.severity.value,
                    "confidence": threat.confidence_score,
                    "description": threat.description,
                }
                for threat in correlation_result.matched_threats
            ],
        }

    def get_threat_score(self, indicators: List[str]) -> float:
        """Legacy threat scoring interface."""
        # Use unified system's threat scoring
        total_score = 0.0
        for indicator in indicators:
            iocs = asyncio.run(self.unified_system.detect_iocs([indicator]))
            if iocs:
                total_score += max(ioc.confidence_score for ioc in iocs)

        return min(total_score / len(indicators) if indicators else 0.0, 1.0)


class AdvancedIntelligenceAdapter:
    """
    Adapter providing legacy AdvancedIntelligenceEngine interface.

    Routes all calls through the unified threat intelligence system
    while maintaining backward compatibility with existing code.
    """

    def __init__(self, unified_system: UnifiedThreatIntelligenceSystem):
        self.unified_system = unified_system
        self.logger = logging.getLogger(__name__)

    async def analyze_with_advanced_intelligence(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Legacy advanced intelligence analysis interface."""
        # Route through unified system
        correlation_result = await self.unified_system.correlate_with_vulnerability(vulnerability)

        # Convert to legacy enhanced classification result format
        return {
            "is_vulnerability": True,
            "confidence": correlation_result.correlation_confidence,
            "vulnerability_type": vulnerability.get("type", "unknown"),
            "severity": correlation_result.risk_assessment,
            "reasoning": correlation_result.correlation_reasoning,
            "ml_enabled": True,
            "threat_intelligence": {
                "threats_found": len(correlation_result.matched_threats),
                "correlation_confidence": correlation_result.correlation_confidence,
                "threat_details": correlation_result.matched_threats,
            },
            "exploit_prediction": 0.8 if correlation_result.matched_threats else 0.2,
            "remediation_priority": "HIGH" if correlation_result.correlation_confidence > 0.7 else "MEDIUM",
            "anomaly_score": 0.5,  # Placeholder for legacy compatibility
            "behavioral_indicators": [],  # Placeholder for legacy compatibility
            "zero_day_likelihood": 0.1,  # Placeholder for legacy compatibility
        }

    def get_intelligence_metrics(self) -> Dict[str, Any]:
        """Legacy intelligence metrics interface."""
        status = self.unified_system.get_system_status()
        return {
            "total_analyzed": status["metrics"].get("correlations_found", 0),
            "threat_intel_correlations": status["metrics"].get("correlations_found", 0),
            "zero_day_detections": 0,  # Placeholder for legacy compatibility
            "pattern_recognitions": 0,  # Placeholder for legacy compatibility
            "ml_enhancements": 0,  # Placeholder for legacy compatibility
            "accuracy_improvements": 0.0,  # Placeholder for legacy compatibility
        }


# Global instance for AODS integration
_unified_threat_intelligence: Optional[UnifiedThreatIntelligenceSystem] = None


def get_unified_threat_intelligence(config: Optional[Dict[str, Any]] = None) -> UnifiedThreatIntelligenceSystem:
    """
    Get the unified threat intelligence system (singleton).

    This is the ONLY recommended way to access threat intelligence in AODS.
    All other threat intelligence engines are deprecated.
    """
    # The UnifiedThreatIntelligenceSystem class implements singleton pattern
    # so we can just create an instance and it will return the same one
    return UnifiedThreatIntelligenceSystem(config)


async def initialize_unified_threat_intelligence(
    config: Optional[Dict[str, Any]] = None,
) -> UnifiedThreatIntelligenceSystem:
    """Initialize the unified threat intelligence system with async components."""
    system = get_unified_threat_intelligence(config)
    await system.initialize_async()
    return system
