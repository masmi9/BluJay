"""
iOS False-Positive Reducer – heuristic and threshold-based FP reduction.

Stage 3 of the pipeline (after pattern detection and ML classifier).
"""
from __future__ import annotations

from typing import Any, Dict, List

_ALWAYS_KEEP = {"critical", "high"}

_INFO_NOISE_PATTERNS = [
    "excessive_nslog",       # Low value if no sensitive data
    "no_universal_links",    # Informational only
    "general_pasteboard",    # Common usage
]


class IOSFalsePositiveReducer:
    """Applies heuristic rules to suppress likely false positives."""

    def __init__(self, threshold: float = 0.15, app_profile: str = "production") -> None:
        self.threshold = threshold
        self.app_profile = app_profile

    def filter(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter findings based on heuristics and confidence thresholds."""
        result = []
        for f in findings:
            if self._should_keep(f):
                result.append(f)
        return result

    def _should_keep(self, finding: Dict[str, Any]) -> bool:
        severity = finding.get("severity", "info").lower()
        confidence = float(finding.get("confidence", 1.0))
        finding_id = finding.get("finding_id", "")

        # Always keep critical and high
        if severity in _ALWAYS_KEEP:
            return True

        # Suppress below threshold
        if confidence < self.threshold:
            return False

        # Suppress known low-value informational patterns for production apps
        if self.app_profile == "production" and severity == "info":
            if any(noise in finding_id for noise in _INFO_NOISE_PATTERNS):
                return False

        return True
