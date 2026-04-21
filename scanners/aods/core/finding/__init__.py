#!/usr/bin/env python3
"""
AODS Canonical Finding Schema Package
====================================

This package provides the canonical finding schema v1 and related utilities
for unified vulnerability data management across AODS plugins.

Components:
- canonical_schema_v1: The unified vulnerability data structure
- normalization_utilities: Convert legacy formats to canonical schema

Version: 1.0
Author: AODS Development Team
Date: 2025-01-04
"""

# Import main components
from .canonical_schema_v1 import (
    CanonicalFinding,
    VulnerabilityEvidence,
    EvidenceLocation,
    SecurityTaxonomy,
    RemediationGuidance,
    SeverityLevel,
    ConfidenceLevel,
    VulnerabilityCategory,
    DetectionMethod,
)

from .normalization_utilities import FindingNormalizer, normalize_finding, normalize_findings_batch

__all__ = [
    # Schema components
    "CanonicalFinding",
    "VulnerabilityEvidence",
    "EvidenceLocation",
    "SecurityTaxonomy",
    "RemediationGuidance",
    "SeverityLevel",
    "ConfidenceLevel",
    "VulnerabilityCategory",
    "DetectionMethod",
    # Normalization utilities
    "FindingNormalizer",
    "normalize_finding",
    "normalize_findings_batch",
]
