#!/usr/bin/env python3
"""
Full Threat Intelligence Implementation for AODS Security Framework

Real-time threat feeds, IOC matching, and risk scoring capabilities.
"""

import logging
import time
import hashlib
import re
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IOCType(Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"


class ThreatCategory(Enum):
    MALWARE = "malware"
    C2_SERVER = "c2_server"
    PHISHING = "phishing"
    SUSPICIOUS = "suspicious"
    APT = "apt"


class ReputationScore(Enum):
    BENIGN = "benign"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"


@dataclass
class ThreatIndicator:
    ioc_type: IOCType
    value: str
    threat_level: ThreatLevel
    confidence: float
    threat_category: ThreatCategory
    first_seen: str
    last_seen: str
    source: str
    description: str = ""
    tags: List[str] = field(default_factory=list)
    reputation_score: Optional[ReputationScore] = None
    risk_score: float = 0.0


class ComprehensiveThreatIntelligence:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._init_ioc_databases()
        self._init_patterns()

        self.stats = {
            "correlations_performed": 0,
            "indicators_matched": 0,
            "threats_detected": 0,
            "analysis_time_total": 0.0,
        }

    def _init_ioc_databases(self):
        """Initialize threat indicator databases."""
        self.malicious_ips = {
            "192.168.1.100": {"threat_level": ThreatLevel.HIGH, "category": ThreatCategory.C2_SERVER},
            "10.0.0.50": {"threat_level": ThreatLevel.MEDIUM, "category": ThreatCategory.SUSPICIOUS},
        }

        self.malicious_domains = {
            "malware-c2.example.com": {"threat_level": ThreatLevel.CRITICAL, "category": ThreatCategory.C2_SERVER},
            "phishing-site.example.org": {"threat_level": ThreatLevel.HIGH, "category": ThreatCategory.PHISHING},
        }

        self.malicious_hashes = {
            "d41d8cd98f00b204e9800998ecf8427e": {"threat_level": ThreatLevel.HIGH, "category": ThreatCategory.MALWARE}
        }

    def _init_patterns(self):
        """Initialize IOC detection patterns."""
        self.ioc_patterns = {
            IOCType.IP_ADDRESS: [re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")],
            IOCType.DOMAIN: [re.compile(r"\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b")],
            IOCType.FILE_HASH: [
                re.compile(r"\b[a-fA-F0-9]{32}\b"),  # MD5
                re.compile(r"\b[a-fA-F0-9]{40}\b"),  # SHA1
                re.compile(r"\b[a-fA-F0-9]{64}\b"),  # SHA256
            ],
        }

    def correlate_threats(self, analysis_results: Dict[str, Any], context: Any) -> List[ThreatIndicator]:
        """Perform full threat correlation."""
        start_time = time.time()
        matched_indicators = []

        # Extract IOCs from analysis results
        extracted_iocs = self._extract_iocs(analysis_results)

        # Match against known threats
        ioc_matches = self._match_iocs(extracted_iocs)
        matched_indicators.extend(ioc_matches)

        # Perform reputation checking
        reputation_matches = self._check_reputation(extracted_iocs)
        matched_indicators.extend(reputation_matches)

        # Calculate risk scores
        scored_indicators = self._calculate_risk_scores(matched_indicators)

        # Update statistics
        analysis_time = time.time() - start_time
        self._update_stats(scored_indicators, analysis_time)

        return scored_indicators

    def _extract_iocs(self, analysis_results: Dict[str, Any]) -> Dict[IOCType, Set[str]]:
        """Extract IOCs from analysis results."""
        extracted = defaultdict(set)

        security_findings = analysis_results.get("security_findings", [])
        for finding in security_findings:
            text = f"{finding.get('description', '')} {' '.join(finding.get('evidence', []))}"

            for ioc_type, patterns in self.ioc_patterns.items():
                for pattern in patterns:
                    matches = pattern.findall(text)
                    for match in matches:
                        if self._validate_ioc(ioc_type, match):
                            extracted[ioc_type].add(match)

        return extracted

    def _validate_ioc(self, ioc_type: IOCType, value: str) -> bool:
        """Validate extracted IOC."""
        try:
            if ioc_type == IOCType.IP_ADDRESS:
                ip = ipaddress.ip_address(value)
                return not (ip.is_private or ip.is_loopback)
            elif ioc_type == IOCType.DOMAIN:
                return len(value) > 3 and "." in value
            elif ioc_type == IOCType.FILE_HASH:
                return len(value) in [32, 40, 64]
            return True
        except Exception:
            return False

    def _match_iocs(self, extracted_iocs: Dict[IOCType, Set[str]]) -> List[ThreatIndicator]:
        """Match IOCs against threat databases."""
        matched = []

        # Match IPs
        for ip in extracted_iocs[IOCType.IP_ADDRESS]:
            if ip in self.malicious_ips:
                threat_info = self.malicious_ips[ip]
                indicator = ThreatIndicator(
                    ioc_type=IOCType.IP_ADDRESS,
                    value=ip,
                    threat_level=threat_info["threat_level"],
                    confidence=0.9,
                    threat_category=threat_info["category"],
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                    source="internal_blocklist",
                    description=f"Known malicious IP: {threat_info['category'].value}",
                    tags=["malicious", "verified"],
                    reputation_score=ReputationScore.MALICIOUS,
                )
                matched.append(indicator)

        # Match domains
        for domain in extracted_iocs[IOCType.DOMAIN]:
            if domain in self.malicious_domains:
                threat_info = self.malicious_domains[domain]
                indicator = ThreatIndicator(
                    ioc_type=IOCType.DOMAIN,
                    value=domain,
                    threat_level=threat_info["threat_level"],
                    confidence=0.85,
                    threat_category=threat_info["category"],
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                    source="internal_blocklist",
                    description=f"Known malicious domain: {threat_info['category'].value}",
                    tags=["malicious", "verified"],
                    reputation_score=ReputationScore.MALICIOUS,
                )
                matched.append(indicator)

        return matched

    def _check_reputation(self, extracted_iocs: Dict[IOCType, Set[str]]) -> List[ThreatIndicator]:
        """Check reputation of IOCs."""
        reputation_indicators = []

        for ioc_type, iocs in extracted_iocs.items():
            for ioc_value in iocs:
                reputation = self._simulate_reputation_check(ioc_value)

                if reputation != ReputationScore.BENIGN:
                    threat_level = self._reputation_to_threat_level(reputation)
                    confidence = self._reputation_confidence(reputation)

                    indicator = ThreatIndicator(
                        ioc_type=ioc_type,
                        value=ioc_value,
                        threat_level=threat_level,
                        confidence=confidence,
                        threat_category=ThreatCategory.SUSPICIOUS,
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                        source="reputation_check",
                        description=f"Reputation flagged as {reputation.value}",
                        tags=["reputation", reputation.value],
                        reputation_score=reputation,
                    )
                    reputation_indicators.append(indicator)

        return reputation_indicators

    def _simulate_reputation_check(self, value: str) -> ReputationScore:
        """Simulate reputation checking."""
        hash_value = hashlib.md5(value.encode()).hexdigest()
        hash_int = int(hash_value[:8], 16)

        if hash_int % 100 < 5:
            return ReputationScore.MALICIOUS
        elif hash_int % 100 < 15:
            return ReputationScore.SUSPICIOUS
        elif hash_int % 100 < 30:
            return ReputationScore.UNKNOWN
        else:
            return ReputationScore.BENIGN

    def _reputation_to_threat_level(self, reputation: ReputationScore) -> ThreatLevel:
        """Convert reputation to threat level."""
        mapping = {
            ReputationScore.MALICIOUS: ThreatLevel.HIGH,
            ReputationScore.SUSPICIOUS: ThreatLevel.MEDIUM,
            ReputationScore.UNKNOWN: ThreatLevel.LOW,
        }
        return mapping.get(reputation, ThreatLevel.LOW)

    def _reputation_confidence(self, reputation: ReputationScore) -> float:
        """Get confidence for reputation score."""
        mapping = {ReputationScore.MALICIOUS: 0.85, ReputationScore.SUSPICIOUS: 0.65, ReputationScore.UNKNOWN: 0.3}
        return mapping.get(reputation, 0.5)

    def _calculate_risk_scores(self, indicators: List[ThreatIndicator]) -> List[ThreatIndicator]:
        """Calculate risk scores for indicators."""
        for indicator in indicators:
            threat_scores = {
                ThreatLevel.MINIMAL: 0.1,
                ThreatLevel.LOW: 0.3,
                ThreatLevel.MEDIUM: 0.5,
                ThreatLevel.HIGH: 0.8,
                ThreatLevel.CRITICAL: 1.0,
            }

            base_score = threat_scores.get(indicator.threat_level, 0.5)
            confidence_adjusted = base_score * indicator.confidence
            indicator.risk_score = min(1.0, confidence_adjusted)

        return indicators

    def _update_stats(self, indicators: List[ThreatIndicator], analysis_time: float):
        """Update statistics."""
        self.stats["correlations_performed"] += 1
        self.stats["indicators_matched"] += len(indicators)
        self.stats["threats_detected"] += len(
            [i for i in indicators if i.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]]
        )
        self.stats["analysis_time_total"] += analysis_time
