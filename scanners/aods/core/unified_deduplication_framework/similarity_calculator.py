#!/usr/bin/env python3
"""
Unified Deduplication Framework - Similarity Calculator
======================================================

This module contains the unified similarity calculation algorithms that
consolidate the best features from both existing deduplication engines.

Features:
- Multiple similarity calculation methods
- Configurable thresholds and weights
- Performance-optimized comparisons
- Detailed similarity breakdown
- Optional semantic similarity via embeddings (Track 14)

"""

import os
import re
import difflib
from typing import Any, Dict, List, Optional

from .data_structures import SimilarityScore, SimilarityLevel

# ---------------------------------------------------------------------------
# Semantic Similarity Integration (Track 14)
# ---------------------------------------------------------------------------

# Semantic weight (proportionally reduces other weights when enabled)
SEMANTIC_WEIGHT = 0.15

# Embedder availability cache
_embedder_available: Optional[bool] = None


def _is_embedder_available() -> bool:
    """
    Check if the embedding module is available for semantic similarity.

    This is cached after first check for performance.
    """
    global _embedder_available

    if _embedder_available is not None:
        return _embedder_available

    # Check if embeddings are disabled via environment
    if os.environ.get("AODS_DISABLE_EMBEDDINGS", "0") == "1":
        _embedder_available = False
        return False

    try:
        from core.vector_db.embedder import is_embedder_available

        _embedder_available = is_embedder_available()
    except ImportError:
        _embedder_available = False

    return _embedder_available


def _compute_semantic_similarity(finding1: Dict[str, Any], finding2: Dict[str, Any]) -> float:
    """
    Compute semantic similarity between two findings using embeddings.

    Returns 0.0 if embedder is unavailable.
    """
    if not _is_embedder_available():
        return 0.0

    try:
        from core.vector_db.embedder import (
            compute_finding_embedding,
            compute_cosine_similarity,
        )

        emb1 = compute_finding_embedding(finding1)
        emb2 = compute_finding_embedding(finding2)

        if emb1 is None or emb2 is None:
            return 0.0

        return compute_cosine_similarity(emb1, emb2)

    except Exception:
        return 0.0


# PERMANENT REGRESSION-PREVENTION UTILITY: Safe string conversion


def _safe_string_lower(value):
    """
    Safely convert any object to lowercase string to prevent 'Text' object has no attribute 'lower' errors.

    Args:
        value: Any value that needs to be converted to lowercase string

    Returns:
        Lowercase string representation, empty string if conversion fails
    """
    import logging

    if value is None:
        return ""

    # Handle Rich Text objects (most common regression cause)
    if hasattr(value, "plain"):
        try:
            return str(value.plain).lower()
        except (AttributeError, TypeError):
            return str(value).lower()

    # Handle regular strings
    if isinstance(value, str):
        return value.lower()

    # Handle other objects - convert to string first
    try:
        return str(value).lower()
    except (TypeError, AttributeError) as e:
        # Ultimate fallback - log warning and return empty string
        logging.getLogger(__name__).warning(
            f"Failed to convert {type(value)} to lowercase string: {e}. " f"Value: {repr(value)[:100]}..."
        )
        return ""


class UnifiedSimilarityCalculator:
    """
    Unified similarity calculator that consolidates similarity algorithms
    from both existing deduplication engines.

    Supports optional semantic similarity via embeddings (Track 14).
    When embeddings are available, weights are automatically renormalized
    to include semantic as a component without distorting existing ratios.
    """

    # Base weights for non-semantic components (sum to 1.0)
    BASE_WEIGHTS = {
        "content": 0.35,  # Title + description content
        "location": 0.20,  # File location similarity
        "evidence": 0.15,  # Evidence overlap
        "pattern": 0.15,  # Pattern/structure similarity
        "cwe": 0.15,  # CWE-based similarity (exact match only)
    }

    def __init__(self, similarity_thresholds: Dict[str, float]):
        """Initialize the similarity calculator with thresholds."""
        self.thresholds = similarity_thresholds
        self._semantic_enabled: Optional[bool] = None

        # Initialize component weights (will be recalculated on first use)
        self.component_weights = self._calculate_effective_weights()

    def _is_semantic_enabled(self) -> bool:
        """Check if semantic similarity is enabled and available."""
        if self._semantic_enabled is None:
            self._semantic_enabled = _is_embedder_available()
        return self._semantic_enabled

    def _calculate_effective_weights(self) -> Dict[str, float]:
        """
        Calculate effective weights based on semantic availability.

        When semantic is enabled, all base weights are proportionally
        reduced to make room for the semantic component.
        This ensures weights always sum to 1.0 without distortion.
        """
        if self._is_semantic_enabled():
            # Proportionally reduce base weights to add semantic
            factor = 1.0 - SEMANTIC_WEIGHT
            weights = {k: v * factor for k, v in self.BASE_WEIGHTS.items()}
            weights["semantic"] = SEMANTIC_WEIGHT
            return weights
        else:
            # Use original base weights (no semantic)
            return self.BASE_WEIGHTS.copy()

    def calculate_similarity(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> SimilarityScore:
        """
        Calculate full similarity between two findings.

        Args:
            finding1: First finding to compare
            finding2: Second finding to compare

        Returns:
            SimilarityScore with detailed breakdown
        """
        # Recalculate effective weights (handles lazy embedder init)
        self.component_weights = self._calculate_effective_weights()

        # Calculate individual similarity components
        content_sim = self._calculate_content_similarity(finding1, finding2)
        location_sim = self._calculate_location_similarity(finding1, finding2)
        evidence_sim = self._calculate_evidence_similarity(finding1, finding2)
        pattern_sim = self._calculate_pattern_similarity(finding1, finding2)
        cwe_sim = self._calculate_cwe_similarity(finding1, finding2)

        # Calculate semantic similarity if enabled
        semantic_sim = 0.0
        if self._is_semantic_enabled():
            semantic_sim = _compute_semantic_similarity(finding1, finding2)

        # Calculate weighted overall similarity
        overall_score = (
            content_sim * self.component_weights["content"]
            + location_sim * self.component_weights["location"]
            + evidence_sim * self.component_weights["evidence"]
            + pattern_sim * self.component_weights["pattern"]
            + cwe_sim * self.component_weights["cwe"]
        )

        # Add semantic component if enabled
        if self._is_semantic_enabled():
            overall_score += semantic_sim * self.component_weights.get("semantic", 0.0)

        # Determine similarity level
        similarity_level = self._determine_similarity_level(overall_score)

        # Create detailed comparison
        comparison_details = {
            "content_similarity": content_sim,
            "location_similarity": location_sim,
            "evidence_similarity": evidence_sim,
            "pattern_similarity": pattern_sim,
            "cwe_similarity": cwe_sim,
            "semantic_similarity": semantic_sim,
            "semantic_enabled": self._is_semantic_enabled(),
            "weights_used": self.component_weights.copy(),
            "thresholds_applied": self.thresholds.copy(),
        }

        return SimilarityScore(
            overall_score=overall_score,
            content_similarity=content_sim,
            location_similarity=location_sim,
            evidence_similarity=evidence_sim,
            pattern_similarity=pattern_sim,
            semantic_similarity=semantic_sim,
            similarity_level=similarity_level,
            comparison_details=comparison_details,
        )

    def _calculate_content_similarity(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> float:
        """Calculate similarity between finding titles and descriptions."""
        # Extract text content
        # PERMANENT REGRESSION FIX: Use safe string conversion to prevent 'Text' object errors
        title1 = _safe_string_lower(finding1.get("title", "")).strip()
        title2 = _safe_string_lower(finding2.get("title", "")).strip()
        desc1 = _safe_string_lower(finding1.get("description", "")).strip()
        desc2 = _safe_string_lower(finding2.get("description", "")).strip()

        # Combine title and description
        content1 = f"{title1} {desc1}".strip()
        content2 = f"{title2} {desc2}".strip()

        if not content1 or not content2:
            return 0.0

        # Use multiple similarity measures
        sequence_sim = self._sequence_similarity(content1, content2)
        token_sim = self._token_similarity(content1, content2)
        fuzzy_sim = self._fuzzy_similarity(content1, content2)

        # Weighted combination
        return sequence_sim * 0.4 + token_sim * 0.3 + fuzzy_sim * 0.3

    def _calculate_location_similarity(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> float:
        """Calculate similarity between finding locations."""
        # Extract location information
        # PERMANENT REGRESSION FIX: Use safe string conversion to prevent 'Text' object errors
        file1 = _safe_string_lower(finding1.get("file_path", ""))
        file2 = _safe_string_lower(finding2.get("file_path", ""))
        line1 = finding1.get("line_number", 0)
        line2 = finding2.get("line_number", 0)

        # File path similarity
        if file1 and file2:
            file_sim = self._path_similarity(file1, file2)
        else:
            file_sim = 1.0 if file1 == file2 else 0.0

        # Line number proximity
        if line1 and line2 and line1 > 0 and line2 > 0:
            line_diff = abs(line1 - line2)
            if line_diff == 0:
                line_sim = 1.0
            elif line_diff <= 5:
                line_sim = 0.8
            elif line_diff <= 20:
                line_sim = 0.5
            else:
                line_sim = 0.0
        else:
            line_sim = 1.0 if line1 == line2 else 0.0

        # Combine file and line similarities
        return file_sim * 0.7 + line_sim * 0.3

    def _calculate_evidence_similarity(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> float:
        """Calculate similarity between finding evidence."""
        evidence1 = set(finding1.get("evidence", []))
        evidence2 = set(finding2.get("evidence", []))

        if not evidence1 and not evidence2:
            return 1.0  # Both have no evidence

        if not evidence1 or not evidence2:
            return 0.0  # One has evidence, other doesn't

        # Calculate Jaccard similarity
        intersection = len(evidence1.intersection(evidence2))
        union = len(evidence1.union(evidence2))

        return intersection / union if union > 0 else 0.0

    def _calculate_pattern_similarity(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> float:
        """Calculate similarity between finding patterns and structure."""
        # Extract pattern indicators
        # PERMANENT REGRESSION FIX: Use safe string conversion to prevent 'Text' object errors
        severity1 = _safe_string_lower(finding1.get("severity", ""))
        severity2 = _safe_string_lower(finding2.get("severity", ""))
        type1 = _safe_string_lower(finding1.get("type", ""))
        type2 = _safe_string_lower(finding2.get("type", ""))
        category1 = _safe_string_lower(finding1.get("category", ""))
        category2 = _safe_string_lower(finding2.get("category", ""))

        similarities = []

        # Severity similarity
        if severity1 and severity2:
            similarities.append(1.0 if severity1 == severity2 else 0.0)

        # Type similarity
        if type1 and type2:
            similarities.append(self._fuzzy_similarity(type1, type2))

        # Category similarity
        if category1 and category2:
            similarities.append(self._fuzzy_similarity(category1, category2))

        # Pattern in content (vulnerability signatures)
        # PERMANENT REGRESSION FIX: Use safe string conversion to prevent 'Text' object errors
        content1_parts = f"{finding1.get('title', '')} {finding1.get('description', '')}"
        content2_parts = f"{finding2.get('title', '')} {finding2.get('description', '')}"
        content1 = _safe_string_lower(content1_parts)
        content2 = _safe_string_lower(content2_parts)

        pattern_sim = self._pattern_similarity_analysis(content1, content2)
        similarities.append(pattern_sim)

        return sum(similarities) / len(similarities) if similarities else 0.0

    def _calculate_cwe_similarity(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> float:
        """Calculate CWE-based semantic similarity (exact match only).

        Returns:
            1.0 if both have the same CWE (or both lack CWE)
            0.0 if only one has CWE or CWEs differ
        """
        cwe1 = str(finding1.get("cwe_id", "") or finding1.get("cwe", "") or "").upper().replace("CWE-", "").strip()
        cwe2 = str(finding2.get("cwe_id", "") or finding2.get("cwe", "") or "").upper().replace("CWE-", "").strip()

        # Both missing CWE = equivalent (both lack classification, so they match)
        if not cwe1 and not cwe2:
            return 1.0

        # Only one missing CWE = not equivalent
        if not cwe1 or not cwe2:
            return 0.0

        # Exact CWE match only - no family/category matching
        return 1.0 if cwe1 == cwe2 else 0.0

    def _sequence_similarity(self, text1: str, text2: str) -> float:
        """Calculate sequence similarity using difflib."""
        if not text1 or not text2:
            return 0.0

        sequence_matcher = difflib.SequenceMatcher(None, text1, text2)
        return sequence_matcher.ratio()

    def _token_similarity(self, text1: str, text2: str) -> float:
        """Calculate token-based similarity."""
        if not text1 or not text2:
            return 0.0

        # Tokenize and normalize
        tokens1 = set(self._tokenize(text1))
        tokens2 = set(self._tokenize(text2))

        if not tokens1 and not tokens2:
            return 1.0

        if not tokens1 or not tokens2:
            return 0.0

        # Jaccard similarity
        intersection = len(tokens1.intersection(tokens2))
        union = len(tokens1.union(tokens2))

        return intersection / union if union > 0 else 0.0

    def _fuzzy_similarity(self, text1: str, text2: str) -> float:
        """Calculate fuzzy string similarity."""
        if not text1 or not text2:
            return 0.0

        if text1 == text2:
            return 1.0

        # Implement fuzzy matching using character-level comparison
        max_len = max(len(text1), len(text2))
        if max_len == 0:
            return 1.0

        # Count character differences
        differences = 0
        for i in range(max_len):
            char1 = text1[i] if i < len(text1) else ""
            char2 = text2[i] if i < len(text2) else ""
            if char1 != char2:
                differences += 1

        return 1.0 - (differences / max_len)

    def _path_similarity(self, path1: str, path2: str) -> float:
        """Calculate file path similarity."""
        if path1 == path2:
            return 1.0

        # Split paths into components
        parts1 = path1.split("/")
        parts2 = path2.split("/")

        # Calculate component overlap
        common_parts = 0
        max_parts = max(len(parts1), len(parts2))

        for i in range(min(len(parts1), len(parts2))):
            if parts1[i] == parts2[i]:
                common_parts += 1
            else:
                break  # Stop at first difference in path hierarchy

        return common_parts / max_parts if max_parts > 0 else 0.0

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text for similarity comparison."""
        # Remove special characters and split on whitespace
        # PERMANENT REGRESSION FIX: Use safe string conversion to prevent 'Text' object errors
        cleaned = re.sub(r"[^\w\s]", " ", _safe_string_lower(text))
        tokens = cleaned.split()

        # Filter out very short tokens
        return [token for token in tokens if len(token) > 2]

    def _pattern_similarity_analysis(self, content1: str, content2: str) -> float:
        """Analyze pattern similarity in vulnerability descriptions."""
        # Common vulnerability patterns
        vulnerability_patterns = [
            r"sql.{0,10}injection",
            r"cross.{0,10}site.{0,10}scripting",
            r"buffer.{0,10}overflow",
            r"path.{0,10}traversal",
            r"command.{0,10}injection",
            r"hardcoded.{0,10}(password|secret|key)",
            r"weak.{0,10}encryption",
            r"insecure.{0,10}storage",
            r"exported.{0,10}(activity|service|receiver)",
            r"permission.{0,10}(dangerous|sensitive)",
        ]

        patterns1 = []
        patterns2 = []

        for pattern in vulnerability_patterns:
            if re.search(pattern, content1, re.IGNORECASE):
                patterns1.append(pattern)
            if re.search(pattern, content2, re.IGNORECASE):
                patterns2.append(pattern)

        if not patterns1 and not patterns2:
            return 0.5  # Neutral score if no patterns found

        if not patterns1 or not patterns2:
            return 0.0  # One has patterns, other doesn't

        # Calculate pattern overlap
        common_patterns = len(set(patterns1).intersection(set(patterns2)))
        total_patterns = len(set(patterns1).union(set(patterns2)))

        return common_patterns / total_patterns if total_patterns > 0 else 0.0

    def _determine_similarity_level(self, score: float) -> SimilarityLevel:
        """Determine similarity level based on score."""
        if score >= self.thresholds.get("exact_match", 1.0):
            return SimilarityLevel.EXACT_MATCH
        elif score >= self.thresholds.get("high_similarity", 0.95):
            return SimilarityLevel.HIGH_SIMILARITY
        elif score >= self.thresholds.get("moderate_similarity", 0.85):
            return SimilarityLevel.MODERATE_SIMILARITY
        elif score >= self.thresholds.get("low_similarity", 0.7):
            return SimilarityLevel.LOW_SIMILARITY
        else:
            return SimilarityLevel.UNRELATED

    def update_thresholds(self, new_thresholds: Dict[str, float]):
        """Update similarity thresholds."""
        self.thresholds.update(new_thresholds)

    def update_weights(self, new_weights: Dict[str, float]):
        """Update component weights."""
        self.component_weights.update(new_weights)

    def get_configuration(self) -> Dict[str, Any]:
        """Get current calculator configuration."""
        return {"thresholds": self.thresholds.copy(), "weights": self.component_weights.copy()}
