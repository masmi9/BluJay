"""Utility methods used by all other mixins - must be first in MRO."""

from typing import Dict, List, Any
from collections import Counter


class UtilsMixin:
    """Safe extraction helpers, ID generation, severity/confidence stats."""

    def _safe_extract(self, data: Dict, key: str, default=None, expected_type=None):
        """Safely extract data from dictionaries with type validation and fallbacks"""
        if not isinstance(data, dict):
            return default

        value = data.get(key, default)

        # Type validation if expected_type is specified
        if expected_type is not None:
            # If value is None, return sensible default for the expected type
            if value is None:
                if expected_type == list:
                    return default or []
                if expected_type == dict:
                    return default or {}
                if expected_type == str:
                    return default or ""
                return default
            # Coerce or fallback when type mismatches
            if expected_type == str and not isinstance(value, str):
                return str(value) if value is not None else (default or "")
            elif expected_type == list and not isinstance(value, list):
                return [value] if value is not None else (default or [])
            elif expected_type == dict and not isinstance(value, dict):
                return default or {}
            elif not isinstance(value, expected_type):
                return default

        return value

    def _safe_extract_nested(self, data: Dict, keys_path: str, default=None, expected_type=None):
        """Safely extract nested data using dot notation (e.g., 'pattern_info.severity')"""
        if not isinstance(data, dict):
            return default

        keys = keys_path.split(".")
        current = data

        for key in keys:
            if not isinstance(current, dict) or key not in current:
                return default
            current = current[key]

        # Apply type validation to final value
        if expected_type is not None and current is not None:
            if expected_type == str and not isinstance(current, str):
                return str(current) if current else default
            elif expected_type == list and not isinstance(current, list):
                return [current] if current else (default or [])
            elif expected_type == dict and not isinstance(current, dict):
                return default or {}
            elif not isinstance(current, expected_type):
                return default

        return current

    def _generate_unique_vulnerability_id(self, finding: Dict, index: int) -> str:
        """
        **DUPLICATE DETECTION FIX**: Generate unique vulnerability ID with collision prevention.

        Args:
            finding: The vulnerability finding data
            index: The index of this vulnerability in the current batch

        Returns:
            Unique vulnerability ID string
        """
        import time
        import hashlib

        # Try to get existing ID first
        existing_id = finding.get("id", "")
        if existing_id and existing_id.strip():
            # If there's already a unique ID, verify it's not a duplicate
            if not hasattr(self, "_used_vulnerability_ids"):
                self._used_vulnerability_ids = set()

            if existing_id not in self._used_vulnerability_ids:
                self._used_vulnerability_ids.add(existing_id)
                return existing_id

        # Generate new unique ID
        if not hasattr(self, "_used_vulnerability_ids"):
            self._used_vulnerability_ids = set()
        if not hasattr(self, "_id_counter"):
            self._id_counter = 0

        # Create base hash from finding content
        content_hash = hash(str(finding))

        # Add uniqueness factors: timestamp, index, counter
        timestamp = int(time.time() * 1000000)  # Microsecond precision
        self._id_counter += 1

        # Create unique ID with collision protection
        unique_string = f"{content_hash}_{index}_{timestamp}_{self._id_counter}"
        unique_hash = hashlib.md5(unique_string.encode()).hexdigest()[:16]

        # Format as enhanced_[unique_hash] to maintain existing format
        candidate_id = f"enhanced_{unique_hash}"

        # Final collision check and resolution
        counter = 0
        final_id = candidate_id
        while final_id in self._used_vulnerability_ids:
            counter += 1
            final_id = f"{candidate_id}_{counter}"

            # Safety check to prevent infinite loops
            if counter > 1000:
                final_id = f"enhanced_{int(time.time())}_{self._id_counter}"
                break

        # Track the ID to prevent future duplicates
        self._used_vulnerability_ids.add(final_id)

        return final_id

    def _get_severity_breakdown(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get severity breakdown for QA validation."""
        severities = [vuln.get("severity", "UNKNOWN") for vuln in vulnerabilities]
        return dict(Counter(severities))

    def _get_confidence_distribution(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get confidence distribution for QA validation."""
        distributions = {"high": 0, "medium": 0, "low": 0}

        for vuln in vulnerabilities:
            confidence = vuln.get("confidence", 0)
            if confidence >= 0.8:
                distributions["high"] += 1
            elif confidence >= 0.6:
                distributions["medium"] += 1
            else:
                distributions["low"] += 1

        return distributions
