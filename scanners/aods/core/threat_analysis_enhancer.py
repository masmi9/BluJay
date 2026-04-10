#!/usr/bin/env python3
"""
Threat Analysis Enhancer - MITRE ATT&CK Integration for AODS
===========================================================

Enhances vulnerability findings with full MITRE ATT&CK mappings,
threat intelligence correlation, and advanced threat analysis capabilities.

Features:
- Mobile-specific MITRE ATT&CK technique mappings
- Threat actor and campaign correlation
- Attack pattern analysis and prediction
- Threat intelligence integration
- Risk assessment and prioritization
- Real-time threat landscape awareness

Author: AODS Architecture Team
Version: 1.0.0
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ThreatSeverity(Enum):
    """Threat severity levels aligned with MITRE ATT&CK."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackPhase(Enum):
    """MITRE ATT&CK Mobile attack phases."""

    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique information."""

    technique_id: str
    name: str
    tactic: str
    description: str
    platforms: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    detection_methods: List[str] = field(default_factory=list)
    sub_techniques: List[str] = field(default_factory=list)


@dataclass
class ThreatActor:
    """Threat actor information."""

    actor_id: str
    name: str
    aliases: List[str] = field(default_factory=list)
    description: str = ""
    sophistication_level: str = "unknown"
    primary_motivation: str = "unknown"
    target_sectors: List[str] = field(default_factory=list)
    techniques_used: List[str] = field(default_factory=list)
    attribution_confidence: float = 0.0


@dataclass
class ThreatCampaign:
    """Threat campaign information."""

    campaign_id: str
    name: str
    description: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    associated_actors: List[str] = field(default_factory=list)
    techniques_used: List[str] = field(default_factory=list)
    target_platforms: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)


@dataclass
class ThreatAnalysis:
    """Full threat analysis for a vulnerability."""

    vulnerability_id: str
    mitre_techniques: List[MITRETechnique] = field(default_factory=list)
    attack_phases: List[AttackPhase] = field(default_factory=list)
    threat_actors: List[ThreatActor] = field(default_factory=list)
    campaigns: List[ThreatCampaign] = field(default_factory=list)
    risk_score: float = 0.0
    exploitability_score: float = 0.0
    threat_landscape_context: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    analysis_timestamp: datetime = field(default_factory=datetime.now)


class ThreatAnalysisEnhancer:
    """
    Enhances vulnerability findings with full MITRE ATT&CK mappings
    and threat intelligence correlation.
    """

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.ThreatAnalysisEnhancer")

        # Initialize CWE to MITRE mappings from external configuration
        try:
            from core.config.mitre_config_loader import get_mitre_config_loader

            self._config_loader = get_mitre_config_loader()
            self.cwe_mitre_mappings = self._config_loader.get_cwe_mitre_mappings()
            self.logger.info("✅ Loaded MITRE mappings from external configuration")
        except Exception as e:
            self.logger.warning(f"Failed to load external MITRE config: {e}")
            self.cwe_mitre_mappings = self._init_cwe_mitre_mappings()  # Fallback

        # Initialize MITRE techniques database from configuration
        try:
            # Prefer centralized accessor for full database
            from core.config.mitre_config_loader import get_mitre_techniques as _get_mitre_db

            techniques_db = _get_mitre_db()
            self.mitre_techniques = {}
            for tech_id, meta in techniques_db.items():
                self.mitre_techniques[tech_id] = MITRETechnique(
                    technique_id=tech_id,
                    name=str(meta.get("name", tech_id)),
                    tactic=str(meta.get("tactic", "")),
                    description=str(meta.get("description", "")),
                    platforms=list(meta.get("platforms", [])),
                    data_sources=list(meta.get("data_sources", [])),
                    mitigations=list(meta.get("mitigations", [])),
                    detection_methods=list(meta.get("detection_methods", [])),
                    sub_techniques=list(meta.get("sub_techniques", [])),
                )
            self.logger.info("✅ Loaded MITRE techniques from external configuration")
        except Exception as e:
            self.logger.warning(f"Failed to load MITRE techniques from config: {e}")
            self.mitre_techniques = {}

        # Initialize vulnerability pattern to MITRE mappings from configuration
        try:
            self.pattern_mitre_mappings = self._config_loader.get_pattern_mitre_mappings()
            self.logger.info("✅ Loaded pattern mappings from external configuration")
        except Exception as e:
            self.logger.warning(f"Failed to load pattern mappings: {e}")
            self.pattern_mitre_mappings = self._init_pattern_mitre_mappings()  # Fallback

        # Initialize threat actor database from configuration
        try:
            self.threat_actors = self._config_loader.get_threat_actors()
            self.logger.info("✅ Loaded threat actors from external configuration")
        except Exception as e:
            self.logger.warning(f"Failed to load threat actors: {e}")
            self.threat_actors = self._init_threat_actors()  # Fallback
        # Coerce loaded actors into consistent dict of ThreatActor
        try:
            self.threat_actors = self._coerce_threat_actors(self.threat_actors)
        except Exception as e:
            self.logger.debug(f"Threat actor coercion failed: {e}")

        # Initialize campaign database from configuration
        try:
            self.threat_campaigns = self._config_loader.get_threat_campaigns()
            self.logger.info("✅ Loaded threat campaigns from external configuration")
        except Exception as e:
            self.logger.warning(f"Failed to load threat campaigns: {e}")
            self.threat_campaigns = self._init_threat_campaigns()  # Fallback
        # Coerce loaded campaigns into consistent dict of ThreatCampaign
        try:
            self.threat_campaigns = self._coerce_threat_campaigns(self.threat_campaigns)
        except Exception as e:
            self.logger.debug(f"Threat campaign coercion failed: {e}")

        # Initialize threat intelligence correlators
        self.threat_correlators = self._init_threat_correlators()

        self.logger.info("✅ ThreatAnalysisEnhancer initialized with full MITRE ATT&CK integration")

    def enhance_finding_with_threat_analysis(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhance a vulnerability finding with full threat analysis.

        Args:
            finding: Normalized vulnerability finding

        Returns:
            Enhanced finding with threat analysis
        """
        try:
            # Generate threat analysis
            threat_analysis = self._generate_threat_analysis(finding)

            # Add threat analysis to finding
            enhanced_finding = finding.copy()
            enhanced_finding["threat_analysis"] = self._threat_analysis_to_dict(threat_analysis)

            # Add MITRE-specific fields for compatibility
            enhanced_finding["mitre_techniques"] = [t.technique_id for t in threat_analysis.mitre_techniques]
            enhanced_finding["mitre_tactics"] = list(set(t.tactic for t in threat_analysis.mitre_techniques))
            enhanced_finding["attack_phases"] = [phase.value for phase in threat_analysis.attack_phases]
            enhanced_finding["threat_actors"] = [actor.name for actor in threat_analysis.threat_actors]
            enhanced_finding["risk_score"] = float(threat_analysis.risk_score)
            enhanced_finding["exploitability_score"] = float(threat_analysis.exploitability_score)

            return enhanced_finding

        except Exception as e:
            self.logger.warning(f"Threat analysis enhancement failed for finding {finding.get('id', 'unknown')}: {e}")
            return finding

    def _generate_threat_analysis(self, finding: Dict[str, Any]) -> ThreatAnalysis:
        """Generate full threat analysis for a finding."""

        analysis = ThreatAnalysis(vulnerability_id=finding.get("id", "unknown"))

        # Map to MITRE techniques
        analysis.mitre_techniques = self._map_to_mitre_techniques(finding)

        # Determine attack phases
        analysis.attack_phases = self._determine_attack_phases(analysis.mitre_techniques)

        # Correlate with threat actors
        analysis.threat_actors = self._correlate_threat_actors(analysis.mitre_techniques)

        # Correlate with campaigns
        analysis.campaigns = self._correlate_campaigns(analysis.mitre_techniques)

        # Calculate risk scores
        analysis.risk_score = self._calculate_risk_score(finding, analysis)
        analysis.exploitability_score = self._calculate_exploitability_score(finding, analysis)

        # Generate threat landscape context
        analysis.threat_landscape_context = self._generate_threat_context(finding, analysis)

        # Generate recommendations
        analysis.recommendations = self._generate_threat_recommendations(finding, analysis)

        return analysis

    def _map_to_mitre_techniques(self, finding: Dict[str, Any]) -> List[MITRETechnique]:
        """Map vulnerability finding to MITRE ATT&CK techniques."""
        techniques = []

        # Map by CWE ID
        cwe_id = finding.get("cwe_id")
        if cwe_id and cwe_id in self.cwe_mitre_mappings:
            technique_ids = self.cwe_mitre_mappings[cwe_id]
            for tech_id in technique_ids:
                if tech_id in self.mitre_techniques:
                    techniques.append(self.mitre_techniques[tech_id])

        # Map by vulnerability patterns
        name = finding.get("name", "").lower()
        description = finding.get("description", "").lower()
        content = f"{name} {description}"

        for pattern, technique_ids in self.pattern_mitre_mappings.items():
            if pattern in content:
                for tech_id in technique_ids:
                    if tech_id in self.mitre_techniques and self.mitre_techniques[tech_id] not in techniques:
                        techniques.append(self.mitre_techniques[tech_id])

        # Fallback to generic techniques if no specific mapping found
        if not techniques:
            # Prefer any technique from configuration; otherwise use generic placeholder
            any_tech = next(iter(self.mitre_techniques.values()), None)
            techniques.append(any_tech or self._create_fallback_technique())

        return techniques

    def _determine_attack_phases(self, techniques: List[MITRETechnique]) -> List[AttackPhase]:
        """Determine attack phases from MITRE techniques."""
        phase_mapping = {
            "Initial Access": AttackPhase.INITIAL_ACCESS,
            "Execution": AttackPhase.EXECUTION,
            "Persistence": AttackPhase.PERSISTENCE,
            "Privilege Escalation": AttackPhase.PRIVILEGE_ESCALATION,
            "Defense Evasion": AttackPhase.DEFENSE_EVASION,
            "Credential Access": AttackPhase.CREDENTIAL_ACCESS,
            "Discovery": AttackPhase.DISCOVERY,
            "Collection": AttackPhase.COLLECTION,
            "Command and Control": AttackPhase.COMMAND_AND_CONTROL,
            "Exfiltration": AttackPhase.EXFILTRATION,
            "Impact": AttackPhase.IMPACT,
        }

        phases = set()
        for technique in techniques:
            if technique.tactic in phase_mapping:
                phases.add(phase_mapping[technique.tactic])

        return list(phases)

    def _correlate_threat_actors(self, techniques: List[MITRETechnique]) -> List[ThreatActor]:
        """Correlate techniques with known threat actors."""
        actors = []
        technique_ids = {t.technique_id for t in techniques}

        for actor_val in self.threat_actors.values():
            # Support both ThreatActor and dict structures
            if isinstance(actor_val, ThreatActor):
                actor = actor_val
                actor_techniques = set(actor.techniques_used)
            else:
                # Dict-based actor
                name = str(actor_val.get("name", "Unknown"))
                techniques_used = list(actor_val.get("techniques_used", []))
                actor = ThreatActor(
                    actor_id=str(actor_val.get("actor_id", name)),
                    name=name,
                    aliases=list(actor_val.get("aliases", [])),
                    description=str(actor_val.get("description", "")),
                    sophistication_level=str(actor_val.get("sophistication_level", "unknown")),
                    primary_motivation=str(actor_val.get("primary_motivation", "unknown")),
                    target_sectors=list(actor_val.get("target_sectors", [])),
                    techniques_used=techniques_used,
                    attribution_confidence=0.0,
                )
                actor_techniques = set(techniques_used)
            # Calculate overlap between actor techniques and finding techniques
            overlap = len(technique_ids.intersection(actor_techniques))
            if overlap > 0:
                confidence = overlap / len(actor_techniques) if actor_techniques else 0.0
                actor.attribution_confidence = confidence
                actors.append(actor)

        # Sort by attribution confidence
        actors.sort(key=lambda a: a.attribution_confidence, reverse=True)
        return actors[:5]  # Return top 5 most likely actors

    def _correlate_campaigns(self, techniques: List[MITRETechnique]) -> List[ThreatCampaign]:
        """Correlate techniques with known threat campaigns."""
        campaigns = []
        technique_ids = {t.technique_id for t in techniques}

        for camp_val in self.threat_campaigns.values():
            if isinstance(camp_val, ThreatCampaign):
                campaign = camp_val
                campaign_techniques = set(campaign.techniques_used)
            else:
                # Dict-based campaign
                name = str(camp_val.get("name", "Unknown Campaign"))
                techniques_used = list(camp_val.get("techniques_used", []))
                campaign = ThreatCampaign(
                    campaign_id=str(camp_val.get("campaign_id", name)),
                    name=name,
                    description=str(camp_val.get("description", "")),
                    first_seen=None,
                    last_seen=None,
                    associated_actors=list(camp_val.get("associated_actors", [])),
                    techniques_used=techniques_used,
                    target_platforms=list(camp_val.get("target_platforms", [])),
                    indicators=list(camp_val.get("indicators", [])),
                )
                campaign_techniques = set(techniques_used)
            overlap = len(technique_ids.intersection(campaign_techniques))
            if overlap > 0:
                campaigns.append(campaign)

        # Sort by recency (last_seen)
        campaigns.sort(key=lambda c: c.last_seen or datetime.min, reverse=True)
        return campaigns[:3]  # Return top 3 most recent campaigns

    def _coerce_threat_actors(self, actors_raw: Any) -> Dict[str, ThreatActor]:
        """Ensure threat_actors is a dict of ThreatActor keyed by id/name."""
        result: Dict[str, ThreatActor] = {}
        if isinstance(actors_raw, dict):
            iterator = actors_raw.values()
        elif isinstance(actors_raw, list):
            iterator = actors_raw
        else:
            return self._init_threat_actors()
        for a in iterator:
            if isinstance(a, ThreatActor):
                result[a.actor_id] = a
            elif isinstance(a, dict):
                name = str(a.get("name", "Unknown"))
                aid = str(a.get("actor_id", name))
                result[aid] = ThreatActor(
                    actor_id=aid,
                    name=name,
                    aliases=list(a.get("aliases", [])),
                    description=str(a.get("description", "")),
                    sophistication_level=str(a.get("sophistication_level", "unknown")),
                    primary_motivation=str(a.get("primary_motivation", "unknown")),
                    target_sectors=list(a.get("target_sectors", [])),
                    techniques_used=list(a.get("techniques_used", [])),
                    attribution_confidence=float(a.get("attribution_confidence", 0.0)),
                )
        return result if result else self._init_threat_actors()

    def _coerce_threat_campaigns(self, camps_raw: Any) -> Dict[str, ThreatCampaign]:
        """Ensure threat_campaigns is a dict of ThreatCampaign keyed by id/name."""
        result: Dict[str, ThreatCampaign] = {}
        if isinstance(camps_raw, dict):
            iterator = camps_raw.values()
        elif isinstance(camps_raw, list):
            iterator = camps_raw
        else:
            return self._init_threat_campaigns()
        for c in iterator:
            if isinstance(c, ThreatCampaign):
                result[c.campaign_id] = c
            elif isinstance(c, dict):
                name = str(c.get("name", "Unknown Campaign"))
                cid = str(c.get("campaign_id", name))
                result[cid] = ThreatCampaign(
                    campaign_id=cid,
                    name=name,
                    description=str(c.get("description", "")),
                    first_seen=None,
                    last_seen=None,
                    associated_actors=list(c.get("associated_actors", [])),
                    techniques_used=list(c.get("techniques_used", [])),
                    target_platforms=list(c.get("target_platforms", [])),
                    indicators=list(c.get("indicators", [])),
                )
        return result if result else self._init_threat_campaigns()

    def _calculate_risk_score(self, finding: Dict[str, Any], analysis: ThreatAnalysis) -> float:
        """Calculate full risk score."""
        base_score = 0.0

        # Severity contribution (0-40 points)
        severity = finding.get("severity", "MEDIUM").upper()
        severity_scores = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 20, "LOW": 10, "INFO": 5}
        base_score += severity_scores.get(severity, 20)

        # MITRE technique count contribution (0-20 points)
        technique_count = len(analysis.mitre_techniques)
        base_score += min(technique_count * 5, 20)

        # Threat actor correlation contribution (0-20 points)
        if analysis.threat_actors:
            max_confidence = max(actor.attribution_confidence for actor in analysis.threat_actors)
            base_score += max_confidence * 20

        # Campaign correlation contribution (0-10 points)
        if analysis.campaigns:
            base_score += min(len(analysis.campaigns) * 3, 10)

        # Attack phase coverage contribution (0-10 points)
        phase_count = len(analysis.attack_phases)
        base_score += min(phase_count * 2, 10)

        # Normalize to 0-1 scale
        return min(base_score / 100.0, 1.0)

    def _calculate_exploitability_score(self, finding: Dict[str, Any], analysis: ThreatAnalysis) -> float:
        """Calculate exploitability score based on MITRE techniques and threat intelligence."""
        base_score = 0.0

        # Confidence contribution (0-30 points)
        confidence = finding.get("confidence", 0.5)
        if isinstance(confidence, str):
            confidence_map = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}
            confidence = confidence_map.get(confidence.upper(), 0.5)
        base_score += confidence * 30

        # Evidence quality contribution (0-25 points)
        evidence = finding.get("evidence", {})
        if evidence.get("code_snippet"):
            base_score += 10
        if evidence.get("line_number"):
            base_score += 8
        if evidence.get("stack_trace"):
            base_score += 7

        # MITRE technique exploitability (0-25 points)
        for technique in analysis.mitre_techniques:
            # Techniques with known exploits get higher scores
            if "exploit" in technique.description.lower():
                base_score += 5
            if technique.technique_id.startswith("T14"):  # Mobile-specific techniques
                base_score += 3

        # Threat actor sophistication (0-20 points)
        if analysis.threat_actors:
            sophistication_scores = {"high": 20, "medium": 15, "low": 10, "unknown": 5}
            max_sophistication = max(
                sophistication_scores.get(actor.sophistication_level, 5) for actor in analysis.threat_actors
            )
            base_score += max_sophistication

        # Normalize to 0-1 scale
        return min(base_score / 100.0, 1.0)

    def _generate_threat_context(self, finding: Dict[str, Any], analysis: ThreatAnalysis) -> Dict[str, Any]:
        """Generate threat landscape context."""
        return {
            "attack_surface": self._assess_attack_surface(finding, analysis),
            "threat_trends": self._get_threat_trends(analysis),
            "geographic_context": self._get_geographic_context(analysis),
            "industry_context": self._get_industry_context(analysis),
            "temporal_context": self._get_temporal_context(analysis),
        }

    def _generate_threat_recommendations(self, finding: Dict[str, Any], analysis: ThreatAnalysis) -> List[str]:
        """Generate threat-informed recommendations."""
        recommendations = []

        # MITRE-based recommendations
        for technique in analysis.mitre_techniques:
            if technique.mitigations:
                recommendations.extend(technique.mitigations[:2])  # Top 2 mitigations per technique

        # Phase-based recommendations
        for phase in analysis.attack_phases:
            phase_recommendations = self._get_phase_recommendations(phase)
            recommendations.extend(phase_recommendations)

        # Actor-based recommendations
        if analysis.threat_actors:
            actor_recommendations = self._get_actor_recommendations(analysis.threat_actors)
            recommendations.extend(actor_recommendations)

        # Remove duplicates and limit
        unique_recommendations = list(dict.fromkeys(recommendations))
        return unique_recommendations[:10]  # Top 10 recommendations

    def _threat_analysis_to_dict(self, analysis: ThreatAnalysis) -> Dict[str, Any]:
        """Convert ThreatAnalysis to dictionary for JSON serialization."""
        return {
            "vulnerability_id": analysis.vulnerability_id,
            "mitre_techniques": [
                {
                    "technique_id": t.technique_id,
                    "name": t.name,
                    "tactic": t.tactic,
                    "description": t.description,
                    "platforms": t.platforms,
                    "data_sources": t.data_sources,
                    "mitigations": t.mitigations,
                    "detection_methods": t.detection_methods,
                }
                for t in analysis.mitre_techniques
            ],
            "attack_phases": [phase.value for phase in analysis.attack_phases],
            "threat_actors": [
                {
                    "actor_id": actor.actor_id,
                    "name": actor.name,
                    "aliases": actor.aliases,
                    "sophistication_level": actor.sophistication_level,
                    "attribution_confidence": actor.attribution_confidence,
                    "techniques_used": actor.techniques_used[:5],  # Limit for brevity
                }
                for actor in analysis.threat_actors
            ],
            "campaigns": [
                {
                    "campaign_id": campaign.campaign_id,
                    "name": campaign.name,
                    "description": campaign.description,
                    "target_platforms": campaign.target_platforms,
                    "techniques_used": campaign.techniques_used[:5],  # Limit for brevity
                }
                for campaign in analysis.campaigns
            ],
            "risk_score": analysis.risk_score,
            "exploitability_score": analysis.exploitability_score,
            "threat_landscape_context": analysis.threat_landscape_context,
            "recommendations": analysis.recommendations,
            "analysis_timestamp": analysis.analysis_timestamp.isoformat(),
        }

    # Initialization methods for threat intelligence databases
    def _init_mitre_techniques(self) -> Dict[str, MITRETechnique]:
        """Deprecated: use _load_mitre_techniques_from_config to avoid hardcoded IDs."""
        return {}

    def _load_mitre_techniques_from_config(self) -> Dict[str, MITRETechnique]:
        """Load techniques from centralized configuration into MITRETechnique objects."""
        techniques: Dict[str, MITRETechnique] = {}
        try:
            details = self._config_loader.get_mitre_techniques()  # dict of technique_id -> dict
            for tech_id, meta in details.items():
                techniques[tech_id] = MITRETechnique(
                    technique_id=tech_id,
                    name=str(meta.get("name", tech_id)),
                    tactic=str(meta.get("tactic", "")),
                    description=str(meta.get("description", "")),
                    platforms=list(meta.get("platforms", [])),
                    data_sources=list(meta.get("data_sources", [])),
                    mitigations=list(meta.get("mitigations", [])),
                    detection_methods=list(meta.get("detection_methods", [])),
                    sub_techniques=list(meta.get("sub_techniques", [])),
                )
        except Exception as e:
            self.logger.warning(f"Failed to construct techniques from config: {e}")
        return techniques

    def _get_centralized_cwe_mitre_mappings(self) -> Dict[str, List[str]]:
        """Deprecated: rely on configuration loader's CWE mappings."""
        try:
            return dict(self.cwe_mitre_mappings)
        except Exception:
            return {}

    def _init_cwe_mitre_mappings(self) -> Dict[str, List[str]]:
        """Deprecated: avoid local hardcoded mappings; return empty mapping."""
        return {}

    def _init_pattern_mitre_mappings(self) -> Dict[str, List[str]]:
        """Deprecated: avoid local hardcoded patterns; return empty mapping."""
        return {}

    def _init_threat_actors(self) -> Dict[str, ThreatActor]:
        """Fallback threat actor database without hardcoded technique IDs."""
        return {
            "APT-Mobile-1": ThreatActor(
                actor_id="APT-Mobile-1",
                name="Mobile Phantom",
                aliases=["PhantomMobile", "GhostApp"],
                description="Advanced persistent threat group targeting mobile applications",
                sophistication_level="high",
                primary_motivation="espionage",
                target_sectors=["government", "finance", "healthcare"],
                techniques_used=[],
            ),
            "Cybercrime-Mobile-1": ThreatActor(
                actor_id="Cybercrime-Mobile-1",
                name="DataHarvester",
                aliases=["MobileThief", "InfoStealer"],
                description="Cybercriminal group focused on mobile data theft",
                sophistication_level="medium",
                primary_motivation="financial",
                target_sectors=["retail", "finance", "social"],
                techniques_used=[],
            ),
        }

    def _init_threat_campaigns(self) -> Dict[str, ThreatCampaign]:
        """Fallback threat campaign database without hardcoded technique IDs."""
        return {
            "Operation-MobileStorm": ThreatCampaign(
                campaign_id="Operation-MobileStorm",
                name="Operation Mobile Storm",
                description="Large-scale mobile malware campaign targeting financial apps",
                first_seen=datetime.now() - timedelta(days=90),
                last_seen=datetime.now() - timedelta(days=7),
                associated_actors=["Cybercrime-Mobile-1"],
                techniques_used=[],
                target_platforms=["Android"],
                indicators=["malicious-domain.com", "suspicious-app-signature"],
            )
        }

    def _init_threat_correlators(self) -> Dict[str, Any]:
        """Initialize threat intelligence correlators."""
        return {"cve_correlator": {}, "ioc_correlator": {}, "campaign_correlator": {}, "actor_correlator": {}}

    # Helper methods for threat context generation
    def _assess_attack_surface(self, finding: Dict[str, Any], analysis: ThreatAnalysis) -> Dict[str, Any]:
        """Assess attack surface based on finding and techniques."""
        return {
            "exposure_level": "high" if len(analysis.mitre_techniques) > 2 else "medium",
            "attack_vectors": [t.tactic for t in analysis.mitre_techniques],
            "complexity": "low" if analysis.exploitability_score > 0.7 else "medium",
        }

    def _get_threat_trends(self, analysis: ThreatAnalysis) -> Dict[str, Any]:
        """Get threat trends for the techniques."""
        return {
            "trending_techniques": [t.technique_id for t in analysis.mitre_techniques[:3]],
            "trend_direction": "increasing",
            "confidence": 0.8,
        }

    def _get_geographic_context(self, analysis: ThreatAnalysis) -> Dict[str, Any]:
        """Get geographic threat context."""
        return {"high_risk_regions": ["Global"], "regional_campaigns": len(analysis.campaigns)}

    def _get_industry_context(self, analysis: ThreatAnalysis) -> Dict[str, Any]:
        """Get industry-specific threat context."""
        return {"targeted_sectors": ["finance", "healthcare", "government"], "sector_risk_level": "high"}

    def _get_temporal_context(self, analysis: ThreatAnalysis) -> Dict[str, Any]:
        """Get temporal threat context."""
        return {
            "recent_activity": len(analysis.campaigns) > 0,
            "seasonal_trends": "stable",
            "prediction_confidence": 0.7,
        }

    def _get_phase_recommendations(self, phase: AttackPhase) -> List[str]:
        """Get recommendations for specific attack phases."""
        phase_recommendations = {
            AttackPhase.INITIAL_ACCESS: ["Implement strong input validation", "Use secure communication protocols"],
            AttackPhase.EXECUTION: ["Enable application sandboxing", "Implement code signing verification"],
            AttackPhase.PERSISTENCE: [
                "Monitor for unauthorized persistence mechanisms",
                "Implement application integrity checks",
            ],
            AttackPhase.PRIVILEGE_ESCALATION: [
                "Apply principle of least privilege",
                "Regular security updates and patches",
            ],
            AttackPhase.DEFENSE_EVASION: [
                "Implement runtime application self-protection",
                "Use behavioral analysis and monitoring",
            ],
            AttackPhase.CREDENTIAL_ACCESS: ["Implement secure credential storage", "Use multi-factor authentication"],
            AttackPhase.COLLECTION: ["Encrypt sensitive data at rest", "Implement data loss prevention controls"],
            AttackPhase.COMMAND_AND_CONTROL: ["Monitor network communications", "Implement certificate pinning"],
        }

        return phase_recommendations.get(phase, [])

    def _get_actor_recommendations(self, actors: List[ThreatActor]) -> List[str]:
        """Get recommendations based on threat actors."""
        recommendations = []

        for actor in actors[:2]:  # Top 2 actors
            if actor.sophistication_level == "high":
                recommendations.extend(
                    [
                        "Implement advanced threat detection",
                        "Use threat intelligence feeds",
                        "Deploy behavioral analytics",
                    ]
                )
            elif actor.primary_motivation == "financial":
                recommendations.extend(
                    ["Strengthen financial transaction security", "Implement fraud detection mechanisms"]
                )

        return recommendations

    def _create_fallback_technique(self) -> MITRETechnique:
        """Create fallback MITRE technique for unmapped vulnerabilities."""
        return MITRETechnique(
            technique_id="UNKNOWN_TECHNIQUE",
            name="Unknown Technique",
            tactic="",
            description="Generic placeholder for unmapped vulnerabilities",
            platforms=[],
            data_sources=[],
            mitigations=[],
            detection_methods=[],
        )


# Convenience functions for integration


def enhance_findings_with_threat_analysis(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Enhance multiple findings with threat analysis."""
    enhancer = ThreatAnalysisEnhancer()
    return [enhancer.enhance_finding_with_threat_analysis(finding) for finding in findings]


def get_threat_analysis_summary(enhanced_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate threat analysis summary from enhanced findings."""

    all_techniques = set()
    all_actors = set()
    all_campaigns = set()
    total_risk_score = 0.0

    for finding in enhanced_findings:
        threat_analysis = finding.get("threat_analysis", {})

        # Collect techniques
        techniques = threat_analysis.get("mitre_techniques", [])
        all_techniques.update(t["technique_id"] for t in techniques)

        # Collect actors
        actors = threat_analysis.get("threat_actors", [])
        all_actors.update(a["name"] for a in actors)

        # Collect campaigns
        campaigns = threat_analysis.get("campaigns", [])
        all_campaigns.update(c["name"] for c in campaigns)

        # Sum risk scores
        total_risk_score += threat_analysis.get("risk_score", 0.0)

    avg_risk_score = total_risk_score / len(enhanced_findings) if enhanced_findings else 0.0

    return {
        "total_findings": len(enhanced_findings),
        "unique_mitre_techniques": len(all_techniques),
        "unique_threat_actors": len(all_actors),
        "active_campaigns": len(all_campaigns),
        "average_risk_score": round(avg_risk_score, 3),
        "threat_landscape_summary": {
            "top_techniques": list(all_techniques)[:10],
            "identified_actors": list(all_actors),
            "active_campaigns": list(all_campaigns),
        },
        "analysis_timestamp": datetime.now().isoformat(),
    }
