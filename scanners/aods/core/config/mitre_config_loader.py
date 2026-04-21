#!/usr/bin/env python3
"""
MITRE Configuration Loader - Centralized MITRE ATT&CK Data Management
====================================================================

Loads and validates MITRE ATT&CK mappings from external configuration files.
Provides centralized, versioned, and validated access to threat intelligence data.

Features:
- YAML-based configuration management
- Schema validation and integrity checks
- Caching and performance optimization
- Version compatibility checking
- Configuration hot-reloading support

Author: AODS Architecture Team
Version: 1.0.0
"""

import os
import yaml
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
import hashlib

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


@dataclass
class MITREConfigMetadata:
    """MITRE configuration metadata."""

    version: str
    schema_version: str
    last_updated: str
    description: str
    maintainer: str
    file_hash: str = ""
    load_timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class MITREConfiguration:
    """Complete MITRE configuration data."""

    metadata: MITREConfigMetadata
    cwe_mitre_mappings: Dict[str, Dict[str, Any]]
    mitre_techniques: Dict[str, Dict[str, Any]]
    pattern_mitre_mappings: Dict[str, List[str]]
    threat_actors: Dict[str, Dict[str, Any]]
    threat_campaigns: Dict[str, Dict[str, Any]]
    validation_schema: Dict[str, Any]


class MITREConfigLoader:
    """
    Centralized loader for MITRE ATT&CK configuration data.

    Provides validated, cached access to MITRE mappings and threat intelligence
    from external YAML configuration files.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.logger = logger

        # Default configuration path
        if not config_path:
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config", "mitre_attack_mappings.yaml"
            )

        self.config_path = Path(config_path)
        self._config_cache: Optional[MITREConfiguration] = None
        self._cache_timestamp: Optional[datetime] = None
        self._file_hash: Optional[str] = None

        self.logger.info("MITREConfigLoader initialized", config_path=str(self.config_path))

    def load_configuration(self, force_reload: bool = False) -> MITREConfiguration:
        """
        Load MITRE configuration from YAML file with caching and validation.

        Args:
            force_reload: Force reload even if cached version is available

        Returns:
            MITREConfiguration with validated data
        """
        try:
            # Check if reload is needed
            if not force_reload and self._is_cache_valid():
                self.logger.debug("Using cached MITRE configuration")
                return self._config_cache

            self.logger.info(f"Loading MITRE configuration from: {self.config_path}")

            # Validate file exists
            if not self.config_path.exists():
                raise FileNotFoundError(f"MITRE configuration file not found: {self.config_path}")

            # Load YAML configuration
            with open(self.config_path, "r", encoding="utf-8") as f:
                config_data = yaml.safe_load(f)

            # Calculate file hash for cache validation
            file_hash = self._calculate_file_hash()

            # Validate configuration structure
            self._validate_configuration_structure(config_data)

            # Create configuration object
            metadata = MITREConfigMetadata(
                version=config_data["metadata"]["version"],
                schema_version=config_data["metadata"]["schema_version"],
                last_updated=config_data["metadata"]["last_updated"],
                description=config_data["metadata"]["description"],
                maintainer=config_data["metadata"]["maintainer"],
                file_hash=file_hash,
                load_timestamp=datetime.now(),
            )

            configuration = MITREConfiguration(
                metadata=metadata,
                cwe_mitre_mappings=config_data["cwe_mitre_mappings"],
                mitre_techniques=config_data["mitre_techniques"],
                pattern_mitre_mappings=config_data["pattern_mitre_mappings"],
                threat_actors=config_data["threat_actors"],
                threat_campaigns=config_data["threat_campaigns"],
                validation_schema=config_data["validation"],
            )

            # Validate configuration content
            self._validate_configuration_content(configuration)

            # Update cache
            self._config_cache = configuration
            self._cache_timestamp = datetime.now()
            self._file_hash = file_hash

            self.logger.info(
                "MITRE configuration loaded successfully",
                version=metadata.version,
                cwe_mappings=len(configuration.cwe_mitre_mappings),
                mitre_techniques=len(configuration.mitre_techniques),
                threat_actors=len(configuration.threat_actors),
                threat_campaigns=len(configuration.threat_campaigns),
            )

            return configuration

        except Exception as e:
            self.logger.error(f"Failed to load MITRE configuration: {e}")
            raise

    def get_cwe_mitre_mappings(self) -> Dict[str, List[str]]:
        """Get CWE to MITRE technique mappings."""
        config = self.load_configuration()

        # Convert to simple CWE -> techniques mapping
        mappings = {}
        for cwe_id, mapping_data in config.cwe_mitre_mappings.items():
            mappings[cwe_id] = mapping_data.get("techniques", [])

        return mappings

    def get_mitre_technique_details(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information for a specific MITRE technique."""
        config = self.load_configuration()
        return config.mitre_techniques.get(technique_id)

    def get_pattern_mitre_mappings(self) -> Dict[str, List[str]]:
        """Get vulnerability pattern to MITRE technique mappings."""
        config = self.load_configuration()
        return config.pattern_mitre_mappings

    def get_threat_actors(self) -> Dict[str, Dict[str, Any]]:
        """Get threat actor database."""
        config = self.load_configuration()
        return config.threat_actors

    def get_threat_campaigns(self) -> Dict[str, Dict[str, Any]]:
        """Get threat campaign database."""
        config = self.load_configuration()
        return config.threat_campaigns

    def get_techniques_for_cwe(self, cwe_id: str) -> Tuple[List[str], float]:
        """
        Get MITRE techniques for a specific CWE with confidence score.

        Args:
            cwe_id: CWE identifier (e.g., 'CWE-89')

        Returns:
            Tuple of (techniques, confidence_score)
        """
        config = self.load_configuration()

        mapping_data = config.cwe_mitre_mappings.get(cwe_id, {})
        techniques = mapping_data.get("techniques", [])
        confidence = mapping_data.get("confidence", 0.5)

        return techniques, confidence

    def search_techniques_by_pattern(self, pattern: str) -> List[str]:
        """Search for MITRE techniques by vulnerability pattern."""
        config = self.load_configuration()

        techniques = set()
        pattern_lower = pattern.lower()

        # Search in pattern mappings
        for pattern_key, pattern_techniques in config.pattern_mitre_mappings.items():
            if pattern_key in pattern_lower:
                techniques.update(pattern_techniques)

        return list(techniques)

    def validate_technique_id(self, technique_id: str) -> bool:
        """Validate if a technique ID exists in the configuration."""
        config = self.load_configuration()
        return technique_id in config.mitre_techniques

    def get_configuration_metadata(self) -> MITREConfigMetadata:
        """Get configuration metadata."""
        config = self.load_configuration()
        return config.metadata

    def _is_cache_valid(self) -> bool:
        """Check if cached configuration is still valid."""
        if not self._config_cache or not self._cache_timestamp:
            return False

        # Check if file has been modified
        try:
            current_hash = self._calculate_file_hash()
            return current_hash == self._file_hash
        except Exception:
            return False

    def _calculate_file_hash(self) -> str:
        """Calculate SHA-256 hash of configuration file."""
        try:
            with open(self.config_path, "rb") as f:
                file_content = f.read()
            return hashlib.sha256(file_content).hexdigest()
        except Exception as e:
            self.logger.warning(f"Failed to calculate file hash: {e}")
            return ""

    def _validate_configuration_structure(self, config_data: Dict[str, Any]) -> None:
        """Validate basic configuration structure."""
        required_sections = [
            "metadata",
            "cwe_mitre_mappings",
            "mitre_techniques",
            "pattern_mitre_mappings",
            "threat_actors",
            "threat_campaigns",
            "validation",
        ]

        for section in required_sections:
            if section not in config_data:
                raise ValueError(f"Missing required configuration section: {section}")

        # Validate metadata
        metadata = config_data["metadata"]
        required_metadata = ["version", "schema_version", "last_updated", "description", "maintainer"]

        for field in required_metadata:  # noqa: F402
            if field not in metadata:
                raise ValueError(f"Missing required metadata field: {field}")

    def _validate_configuration_content(self, config: MITREConfiguration) -> None:
        """Validate configuration content against schema."""
        try:
            validation_schema = config.validation_schema

            # Validate CWE mappings
            required_cwe_fields = validation_schema.get("required_fields", {}).get("cwe_mitre_mappings", [])
            for cwe_id, mapping in config.cwe_mitre_mappings.items():
                for field in required_cwe_fields:  # noqa: F402
                    if field not in mapping:
                        self.logger.warning(f"CWE mapping {cwe_id} missing required field: {field}")

                # Validate confidence range
                confidence = mapping.get("confidence", 0.5)
                conf_range = validation_schema.get("confidence_range", [0.0, 1.0])
                if not (conf_range[0] <= confidence <= conf_range[1]):
                    self.logger.warning(f"CWE mapping {cwe_id} confidence out of range: {confidence}")

            # Validate MITRE techniques
            required_technique_fields = validation_schema.get("required_fields", {}).get("mitre_techniques", [])
            valid_tactics = set(validation_schema.get("valid_tactics", []))
            valid_platforms = set(validation_schema.get("valid_platforms", []))

            for technique_id, technique in config.mitre_techniques.items():
                for field in required_technique_fields:
                    if field not in technique:
                        self.logger.warning(f"MITRE technique {technique_id} missing required field: {field}")

                # Validate tactic
                tactic = technique.get("tactic", "")
                if tactic and tactic not in valid_tactics:
                    self.logger.warning(f"MITRE technique {technique_id} has invalid tactic: {tactic}")

                # Validate platforms
                platforms = technique.get("platforms", [])
                for platform in platforms:
                    if platform not in valid_platforms:
                        self.logger.warning(f"MITRE technique {technique_id} has invalid platform: {platform}")

            self.logger.info("Configuration content validation completed")

        except Exception as e:
            self.logger.warning(f"Configuration content validation failed: {e}")


# Global configuration loader instance
_global_config_loader: Optional[MITREConfigLoader] = None


def get_mitre_config_loader(config_path: Optional[str] = None) -> MITREConfigLoader:
    """Get global MITRE configuration loader instance."""
    global _global_config_loader

    if _global_config_loader is None or config_path:
        _global_config_loader = MITREConfigLoader(config_path)

    return _global_config_loader


def load_mitre_configuration(force_reload: bool = False) -> MITREConfiguration:
    """Convenience function to load MITRE configuration."""
    loader = get_mitre_config_loader()
    return loader.load_configuration(force_reload)


def get_cwe_mitre_mappings() -> Dict[str, List[str]]:
    """Convenience function to get CWE to MITRE mappings."""
    loader = get_mitre_config_loader()
    return loader.get_cwe_mitre_mappings()


def get_mitre_techniques() -> Dict[str, Dict[str, Any]]:
    """Convenience function to get MITRE techniques database."""
    config = load_mitre_configuration()
    return config.mitre_techniques


def get_threat_actors() -> Dict[str, Dict[str, Any]]:
    """Convenience function to get threat actors database."""
    loader = get_mitre_config_loader()
    return loader.get_threat_actors()


def get_threat_campaigns() -> Dict[str, Dict[str, Any]]:
    """Convenience function to get threat campaigns database."""
    loader = get_mitre_config_loader()
    return loader.get_threat_campaigns()


# Configuration validation and testing
if __name__ == "__main__":
    logger.info("Testing MITRE Configuration Loader")

    try:
        # Test configuration loading
        loader = MITREConfigLoader()
        config = loader.load_configuration()

        logger.info(
            "Configuration loaded successfully",
            version=config.metadata.version,
            cwe_mappings=len(config.cwe_mitre_mappings),
            mitre_techniques=len(config.mitre_techniques),
        )

        # Test specific lookups
        cwe_mappings = loader.get_cwe_mitre_mappings()
        logger.info("CWE mappings loaded", entries=len(cwe_mappings))

        # Test technique lookup
        technique_details = loader.get_mitre_technique_details("T1575")
        if technique_details:
            logger.info("T1575 details loaded", name=technique_details["name"])

        # Test pattern search
        injection_techniques = loader.search_techniques_by_pattern("injection")
        logger.info("Injection techniques found", techniques=injection_techniques)

        logger.info("MITRE Configuration Loader test completed successfully")

    except Exception as e:
        logger.error("MITRE Configuration Loader test failed", error=str(e))
        import traceback

        traceback.print_exc()
