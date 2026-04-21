#!/usr/bin/env python3
"""
Noise Source Dampener - Targeted FP Reducer for Noisy Plugins
=============================================================

Adjusts confidence scores for borderline findings from historically noisy
plugin sources.  Runs first in the FP coordinator chain so downstream systems
(ML ensemble, eliminators) receive better-informed confidence values.

Rules:
- Only dampen findings with confidence in a configurable range (default 0.70–0.85)
- CRITICAL severity is never dampened
- Dampening strength is proportional to the plugin's historical FP rate
- Findings dampened below ``drop_threshold`` (default 0.50) are removed
- Configuration loaded from ``artifacts/ml_thresholds.json`` → ``dampening`` key
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default configuration - used when artifacts/ml_thresholds.json is missing
# or does not contain a ``dampening`` section.
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": True,
    "range": [0.70, 0.85],
    "base_factor": 0.15,
    "drop_threshold": 0.50,
    # Plugin FP weights - validated against 10,476-sample real dataset (2026-03-15).
    # Only plugins with TP rate < 50% are dampened. TP rate > 50% means the
    # majority of findings are real and dampening would drop true positives.
    "noisy_plugins": {
        "apk_signing_certificate_analyzer": 0.625,   # TP=37.5% - justified
        "advanced_ssl_tls_analyzer": 0.583,           # TP=41.7% - justified
        # jadx_static_analysis: REMOVED - TP=54.8%, dampening drops real findings
        # webview_security_analysis: REMOVED - TP=63.2%, majority are real
        # network_cleartext_traffic: REMOVED - TP=65.9%, majority are real
    },
    "noisy_cwes": {
        "CWE-329": 0.50,     # TP=50.0% - borderline, keep light dampening
        # CWE-732: REMOVED - TP=86.2%, almost all are real vulnerabilities
        # CWE-749: REMOVED - TP=60.0%, majority are real
    },
    "protected_severities": ["CRITICAL", "HIGH"],
}


class NoiseSourceDampener:
    """Targeted confidence dampener for noisy plugin/CWE sources.

    Implements the ``reduce_false_positives(findings) -> list`` interface
    used by :class:`UnifiedFalsePositiveCoordinator` (Pattern 1 dispatch).
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self._cfg = self._load_config(config)
        self._stats: Dict[str, int] = {"dampened": 0, "dropped": 0, "skipped": 0}
        logger.info("Noise Source Dampener initialized (enabled=%s)", self._cfg.get("enabled", True))

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------

    @staticmethod
    def _load_config(override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Load dampening config from ml_thresholds.json, with hardcoded fallback."""
        if override is not None:
            merged = dict(_DEFAULT_CONFIG)
            merged.update(override)
            return merged

        try:
            from core.ml.thresholds_loader import load_thresholds
            data = load_thresholds()
            dampening = data.get("dampening")
            if isinstance(dampening, dict) and dampening:
                merged = dict(_DEFAULT_CONFIG)
                merged.update(dampening)
                return merged
        except Exception as exc:
            logger.debug("Could not load thresholds: %s - using defaults", exc)

        return dict(_DEFAULT_CONFIG)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def reduce_false_positives(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Dampen confidence of borderline findings from noisy sources.

        Returns a new list - findings dampened below *drop_threshold* are
        removed; others have their ``confidence`` adjusted in-place and
        are annotated with ``_noise_dampened = True``.
        """
        if not self._cfg.get("enabled", True):
            return findings

        conf_lo, conf_hi = self._cfg.get("range", [0.70, 0.85])
        base_factor: float = self._cfg.get("base_factor", 0.15)
        drop_threshold: float = self._cfg.get("drop_threshold", 0.50)
        noisy_plugins: Dict[str, float] = self._cfg.get("noisy_plugins", {})
        noisy_cwes: Dict[str, float] = self._cfg.get("noisy_cwes", {})
        protected = {s.upper() for s in self._cfg.get("protected_severities", ["CRITICAL"])}

        result: List[Dict[str, Any]] = []

        for finding in findings:
            severity = str(finding.get("severity", "")).upper()
            if severity in protected:
                self._stats["skipped"] += 1
                result.append(finding)
                continue

            confidence = float(finding.get("confidence", 0.0))
            if confidence < conf_lo or confidence > conf_hi:
                self._stats["skipped"] += 1
                result.append(finding)
                continue

            # Determine FP-rate weight from plugin or CWE
            plugin_name = str(finding.get("plugin_name", finding.get("source", "")))
            cwe = str(finding.get("cwe", finding.get("cwe_id", "")))

            fp_weight = noisy_plugins.get(plugin_name, 0.0)
            if not fp_weight:
                fp_weight = noisy_cwes.get(cwe, 0.0)

            if not fp_weight:
                self._stats["skipped"] += 1
                result.append(finding)
                continue

            # Apply dampening
            new_conf = confidence - base_factor * fp_weight

            # Severity floor: MEDIUM findings are never dropped by dampening.
            # They can lose confidence but stay above drop_threshold so the ML
            # ensemble makes the final call on real data, not dampener weights.
            if severity == "MEDIUM" and new_conf < drop_threshold:
                new_conf = drop_threshold + 0.01
                logger.debug(
                    "Medium finding floor applied (plugin=%s, cwe=%s, conf=%.3f→%.3f)",
                    plugin_name, cwe, confidence, new_conf,
                )

            if new_conf < drop_threshold:
                self._stats["dropped"] += 1
                logger.debug(
                    "Dropped finding (plugin=%s, cwe=%s, conf=%.3f→%.3f < %.2f)",
                    plugin_name, cwe, confidence, new_conf, drop_threshold,
                )
                continue

            finding["confidence"] = round(new_conf, 4)
            finding["_noise_dampened"] = True
            self._stats["dampened"] += 1
            result.append(finding)

        total_affected = self._stats["dampened"] + self._stats["dropped"]
        if total_affected:
            logger.info(
                "Noise dampener: %d dampened, %d dropped out of %d findings",
                self._stats["dampened"], self._stats["dropped"], len(findings),
            )

        return result

    def get_statistics(self) -> Dict[str, int]:
        """Return dampened/dropped/skipped counts since instantiation."""
        return dict(self._stats)
