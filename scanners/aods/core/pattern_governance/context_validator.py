#!/usr/bin/env python3
"""
Pattern Context Validator for AODS
==================================

Implements context validation for vulnerability patterns to reduce false positives
by requiring actual evidence before classifying findings.

Key Features:
- Network evidence validation for SSRF/GDPR patterns
- Android framework exclusion patterns
- Context-aware pattern matching
- Pattern versioning and rollback capabilities
"""

import re
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import yaml

logger = logging.getLogger(__name__)


@dataclass
class ContextValidationResult:
    """Result of context validation for a pattern match."""

    is_valid: bool
    confidence_adjustment: float
    evidence_found: List[str]
    excluded_patterns_matched: List[str]
    reasoning: str


class PatternContextValidator:
    """
    Validates pattern matches against context requirements to reduce false positives.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(f"{__name__}.PatternContextValidator")
        self.config_path = config_path or "config/vulnerability_patterns.yaml"
        self.context_rules = {}
        self.framework_exclusions = set()
        self._load_context_rules()

    def _load_context_rules(self):
        """Load context validation rules from configuration."""
        try:
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f)

            # Load global exclusions
            global_exclusions = config.get("global_exclusions", [])
            for pattern in global_exclusions:
                self.framework_exclusions.add(re.compile(pattern))

            # Load SSRF context validation
            ssrf_config = config.get("ssrf_vulnerabilities", {}).get("context_validation", {})
            if ssrf_config:
                self.context_rules["ssrf"] = {
                    "required_network_evidence": [
                        re.compile(pattern["pattern"]) for pattern in ssrf_config.get("required_network_evidence", [])
                    ],
                    "excluded_android_patterns": [
                        re.compile(pattern["pattern"]) for pattern in ssrf_config.get("excluded_android_patterns", [])
                    ],
                }

            # Load GDPR context validation
            gdpr_config = config.get("gdpr_compliance_violations", {}).get("context_validation", {})
            if gdpr_config:
                self.context_rules["gdpr"] = {
                    "required_network_evidence": [
                        re.compile(pattern["pattern"]) for pattern in gdpr_config.get("required_network_evidence", [])
                    ],
                    "excluded_local_patterns": [
                        re.compile(pattern["pattern"]) for pattern in gdpr_config.get("excluded_local_patterns", [])
                    ],
                }

            self.logger.info(f"Loaded context validation rules for {len(self.context_rules)} categories")

        except Exception as e:
            self.logger.warning(f"Failed to load context rules: {e}")
            self.context_rules = {}

    def validate_ssrf_context(self, content: str, file_path: str) -> ContextValidationResult:
        """
        Validate SSRF pattern match against context requirements.

        Args:
            content: The content that matched the SSRF pattern
            file_path: Path to the file containing the content

        Returns:
            ContextValidationResult with validation outcome
        """
        # Check if file should be excluded by framework patterns
        for exclusion_pattern in self.framework_exclusions:
            # Use search for robustness; patterns may not be anchored
            if exclusion_pattern.search(file_path):
                return ContextValidationResult(
                    is_valid=False,
                    confidence_adjustment=-1.0,
                    evidence_found=[],
                    excluded_patterns_matched=[exclusion_pattern.pattern],
                    reasoning=f"File {file_path} matches framework exclusion pattern",
                )

        # Check for required network evidence
        evidence_found = []
        excluded_patterns_matched = []

        if "ssrf" in self.context_rules:
            rules = self.context_rules["ssrf"]

            # Check for required network evidence
            for pattern in rules["required_network_evidence"]:
                if pattern.search(content):
                    evidence_found.append(pattern.pattern)

            # Check for excluded Android patterns
            for pattern in rules["excluded_android_patterns"]:
                if pattern.search(content):
                    excluded_patterns_matched.append(pattern.pattern)

        # Determine validity based on evidence
        if excluded_patterns_matched:
            return ContextValidationResult(
                is_valid=False,
                confidence_adjustment=-0.8,
                evidence_found=evidence_found,
                excluded_patterns_matched=excluded_patterns_matched,
                reasoning="Content matches excluded Android patterns (activity constructors, lifecycle methods)",
            )

        if not evidence_found:
            return ContextValidationResult(
                is_valid=False,
                confidence_adjustment=-0.6,
                evidence_found=evidence_found,
                excluded_patterns_matched=excluded_patterns_matched,
                reasoning="No network evidence found for SSRF classification",
            )

        # Valid SSRF with network evidence
        return ContextValidationResult(
            is_valid=True,
            confidence_adjustment=0.0,
            evidence_found=evidence_found,
            excluded_patterns_matched=excluded_patterns_matched,
            reasoning="Valid SSRF pattern with network evidence",
        )

    def validate_gdpr_context(self, content: str, file_path: str) -> ContextValidationResult:
        """
        Validate GDPR pattern match against context requirements.

        Args:
            content: The content that matched the GDPR pattern
            file_path: Path to the file containing the content

        Returns:
            ContextValidationResult with validation outcome
        """
        # Check if file should be excluded by framework patterns
        for exclusion_pattern in self.framework_exclusions:
            if exclusion_pattern.search(file_path):
                return ContextValidationResult(
                    is_valid=False,
                    confidence_adjustment=-1.0,
                    evidence_found=[],
                    excluded_patterns_matched=[exclusion_pattern.pattern],
                    reasoning=f"File {file_path} matches framework exclusion pattern",
                )

        # Check for required network evidence
        evidence_found = []
        excluded_patterns_matched = []

        if "gdpr" in self.context_rules:
            rules = self.context_rules["gdpr"]

            # Check for required network evidence
            for pattern in rules["required_network_evidence"]:
                if pattern.search(content):
                    evidence_found.append(pattern.pattern)

            # Check for excluded local patterns
            for pattern in rules["excluded_local_patterns"]:
                if pattern.search(content):
                    excluded_patterns_matched.append(pattern.pattern)

        # Determine validity based on evidence
        if excluded_patterns_matched:
            return ContextValidationResult(
                is_valid=False,
                confidence_adjustment=-0.8,
                evidence_found=evidence_found,
                excluded_patterns_matched=excluded_patterns_matched,
                reasoning="Content matches excluded local patterns (no actual network transfer)",
            )

        if not evidence_found:
            return ContextValidationResult(
                is_valid=False,
                confidence_adjustment=-0.6,
                evidence_found=evidence_found,
                excluded_patterns_matched=excluded_patterns_matched,
                reasoning="No network evidence found for cross-border transfer claim",
            )

        # Valid GDPR with network evidence
        return ContextValidationResult(
            is_valid=True,
            confidence_adjustment=0.0,
            evidence_found=evidence_found,
            excluded_patterns_matched=excluded_patterns_matched,
            reasoning="Valid GDPR pattern with network evidence",
        )

    def validate_pattern_context(self, pattern_category: str, content: str, file_path: str) -> ContextValidationResult:
        """
        Validate pattern match against context requirements based on category.

        Args:
            pattern_category: Category of the pattern (ssrf, gdpr, etc.)
            content: The content that matched the pattern
            file_path: Path to the file containing the content

        Returns:
            ContextValidationResult with validation outcome
        """
        if pattern_category.lower() == "ssrf":
            return self.validate_ssrf_context(content, file_path)
        elif pattern_category.lower() == "gdpr":
            return self.validate_gdpr_context(content, file_path)
        else:
            # Default validation - just check framework exclusions
            for exclusion_pattern in self.framework_exclusions:
                if exclusion_pattern.search(file_path):
                    return ContextValidationResult(
                        is_valid=False,
                        confidence_adjustment=-1.0,
                        evidence_found=[],
                        excluded_patterns_matched=[exclusion_pattern.pattern],
                        reasoning=f"File {file_path} matches framework exclusion pattern",
                    )

            return ContextValidationResult(
                is_valid=True,
                confidence_adjustment=0.0,
                evidence_found=[],
                excluded_patterns_matched=[],
                reasoning="No specific context validation rules for this category",
            )

    def get_validation_stats(self) -> Dict[str, Any]:
        """Get statistics about context validation rules."""
        return {
            "framework_exclusions": len(self.framework_exclusions),
            "context_rules_categories": list(self.context_rules.keys()),
            "ssrf_network_patterns": len(self.context_rules.get("ssrf", {}).get("required_network_evidence", [])),
            "ssrf_excluded_patterns": len(self.context_rules.get("ssrf", {}).get("excluded_android_patterns", [])),
            "gdpr_network_patterns": len(self.context_rules.get("gdpr", {}).get("required_network_evidence", [])),
            "gdpr_excluded_patterns": len(self.context_rules.get("gdpr", {}).get("excluded_local_patterns", [])),
        }


# ---------------------------------------------------------------------------
# Registry lookup helpers
# ---------------------------------------------------------------------------

_registry_cache: Optional[Dict[str, Any]] = None


def load_registry(registry_path: Optional[str] = None) -> Dict[str, Any]:
    """Load the pattern registry YAML and return a dict keyed by pattern id.

    The result is cached after the first successful load.
    """
    global _registry_cache
    if _registry_cache is not None:
        return _registry_cache

    rp = Path(registry_path) if registry_path else Path("patterns/registry.yaml")
    if not rp.exists():
        logger.warning("Pattern registry not found at %s", rp)
        return {}

    try:
        with open(rp, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as exc:
        logger.warning("Failed to parse registry %s: %s", rp, exc)
        return {}

    if not isinstance(data, dict):
        return {}

    patterns = data.get("patterns", [])
    by_id: Dict[str, Any] = {}
    for entry in patterns:
        if isinstance(entry, dict) and entry.get("id"):
            by_id[entry["id"]] = entry

    _registry_cache = by_id
    logger.info("Loaded pattern registry with %d entries from %s", len(by_id), rp)
    return by_id


def validate_pattern_by_id(
    pattern_id: str,
    content: str,
    file_path: str,
    registry_path: Optional[str] = None,
    validator: Optional[PatternContextValidator] = None,
) -> ContextValidationResult:
    """Look up a pattern in the registry and dispatch context validation.

    If the pattern's category maps to a known validator (ssrf, gdpr), that
    validator is used.  Otherwise the generic framework-exclusion check runs.
    """
    registry = load_registry(registry_path)
    entry = registry.get(pattern_id)
    if entry is None:
        return ContextValidationResult(
            is_valid=True,
            confidence_adjustment=0.0,
            evidence_found=[],
            excluded_patterns_matched=[],
            reasoning=f"Pattern {pattern_id} not in registry; accepting by default",
        )

    raw_category = str(entry.get("category", "")).lower()

    # Normalise registry categories to the short names the validator expects
    if "ssrf" in raw_category:
        category = "ssrf"
    elif "gdpr" in raw_category:
        category = "gdpr"
    else:
        category = raw_category

    if validator is None:
        validator = PatternContextValidator()

    return validator.validate_pattern_context(category, content, file_path)
