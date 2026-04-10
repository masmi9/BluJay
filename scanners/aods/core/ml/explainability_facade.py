"""
AODS Unified Explainability Facade

Consolidates multiple explainability systems into a single canonical API:
- core/ml/explainability.py (SHAP/LIME engine)
- core/ml/vulnerability_scorer.py (vulnerability explanations)
- core/ml_confidence_scoring_engine.py (confidence explanations)

Usage:
    facade = ExplainabilityFacade()
    result = facade.explain_finding(finding_dict)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)


@dataclass
class UnifiedExplanation:
    """Canonical explanation format returned by all explain methods."""

    finding_id: str
    summary: str
    method: str  # "shap", "lime", "heuristic", "rule-based", "confidence"
    confidence: float = 0.0
    contributing_factors: List[Dict[str, Any]] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)
    mitigating_factors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "summary": self.summary,
            "method": self.method,
            "confidence": self.confidence,
            "contributing_factors": self.contributing_factors,
            "risk_factors": self.risk_factors,
            "mitigating_factors": self.mitigating_factors,
            "metadata": self.metadata,
        }


class ExplainabilityFacade:
    """Unified facade for all AODS explainability systems.

    Routes explanation requests to the appropriate subsystem based on
    what information is available in the finding.
    """

    def __init__(self) -> None:
        self._shap_lime_engine = None
        self._engine_initialized = False

    def _get_engine(self):
        """Lazy-load the SHAP/LIME engine, using trained model if available."""
        if not self._engine_initialized:
            self._engine_initialized = True
            try:
                from pathlib import Path

                bundle_path = Path("models/vulnerability_detection/explainability_model.pkl")
                if bundle_path.exists():
                    from core.ml.safe_pickle import safe_load as _safe_pickle_load

                    with open(bundle_path, "rb") as f:
                        bundle = _safe_pickle_load(f)
                    model = bundle["model"]
                    feature_names = bundle["feature_names"]
                    background_data = bundle.get("background_data")
                    from core.ml.explainability import ExplainabilityEngine

                    self._shap_lime_engine = ExplainabilityEngine(
                        model=model,
                        feature_names=feature_names,
                        background_data=background_data,
                    )
                else:
                    from core.ml.explainability import ExplainabilityEngine

                    self._shap_lime_engine = ExplainabilityEngine()
            except Exception as exc:
                logger.debug("SHAP/LIME engine not available: %s", exc)
        return self._shap_lime_engine

    def explain_finding(self, finding: Dict[str, Any]) -> UnifiedExplanation:
        """Generate an explanation for a vulnerability finding.

        Tries multiple explanation strategies in order:
        1. SHAP/LIME if ML features are available (pre-computed)
        2. Extract features from finding attributes → engine (SHAP/LIME/heuristic)
        3. Confidence-based explanation from scoring metadata
        4. Rule-based explanation from finding attributes

        Args:
            finding: Dictionary with finding data. Expected keys vary by source:
                - 'id' or 'vulnerability_id': finding identifier
                - 'confidence' or 'confidence_score': confidence value
                - 'ml_features': numpy array of ML features (for SHAP/LIME)
                - 'severity': severity level
                - 'category': vulnerability category
                - 'description': finding description
                - 'evidence': evidence details
                - 'plugin': source plugin name
                - 'confidence_factors': dict of factor names to scores

        Returns:
            UnifiedExplanation with consolidated explanation.
        """
        finding_id = finding.get("vulnerability_id") or finding.get("id") or finding.get("finding_id") or "unknown"

        # Strategy 1: SHAP/LIME if ML features exist
        ml_features = finding.get("ml_features")
        if ml_features is not None:
            result = self._explain_with_ml(finding_id, ml_features, finding)
            if result is not None:
                return result

        # Strategy 2: Extract features from finding attributes and use engine
        engine = self._get_engine()
        if engine is not None and engine.model is not None:
            extracted = self._extract_finding_features(finding)
            if extracted is not None:
                result = self._explain_with_ml(finding_id, extracted, finding)
                if result is not None:
                    return result

        # Strategy 3: Confidence factors explanation
        confidence_factors = finding.get("confidence_factors")
        if confidence_factors:
            return self._explain_from_confidence(finding_id, confidence_factors, finding)

        # Strategy 4: Rule-based explanation from finding attributes
        return self._explain_from_attributes(finding_id, finding)

    def _extract_finding_features(self, finding: Dict[str, Any]) -> Optional[List[float]]:
        """Extract a 15-element feature vector from finding attributes.

        Maps finding fields to the feature vector expected by the
        explainability model (matches ExplainabilityEngine.DEFAULT_FEATURE_NAMES).
        Returns None if the finding lacks enough data.
        """
        import math

        description = str(finding.get("description", ""))
        if not description:
            return None

        words = description.split()
        word_count = max(len(words), 1)

        # Severity lookup
        severity_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}
        severity = str(finding.get("severity", "")).lower()
        severity_score = severity_map.get(severity, 0.5)

        # Keyword density - vulnerability-related keywords
        vuln_keywords = {
            "vulnerability",
            "exploit",
            "injection",
            "overflow",
            "xss",
            "sqli",
            "rce",
            "bypass",
            "insecure",
            "leak",
            "exposure",
            "unauthorized",
            "malicious",
            "attack",
            "risk",
            "unsafe",
        }
        keyword_hits = sum(1 for w in words if w.lower().strip(".,;:()") in vuln_keywords)
        keyword_density = keyword_hits / word_count

        # Confidence
        confidence_raw = float(finding.get("confidence", finding.get("confidence_score", 0.5)))

        # Code pattern presence
        evidence = finding.get("evidence", {})
        has_code_pattern = 1.0 if isinstance(evidence, dict) and evidence.get("code_snippet") else 0.0

        # Shannon entropy of description characters
        if description:
            freq = {}
            for ch in description:
                freq[ch] = freq.get(ch, 0) + 1
            total = len(description)
            entropy_score = -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)
            # Normalise to roughly [0, 1] (max ~6.6 for printable ASCII)
            entropy_score = min(entropy_score / 6.6, 1.0)
        else:
            entropy_score = 0.0

        # Source/category encodings (deterministic hash)
        plugin = str(finding.get("plugin", finding.get("source_plugin", "")))
        category = str(finding.get("category", ""))
        source_type_encoded = (hash(plugin) % 10) / 10.0 if plugin else 0.5
        category_encoded = (hash(category) % 10) / 10.0 if category else 0.5

        # TF-IDF proxies - keyword presence scores
        desc_lower = description.lower()

        def _keyword_score(terms: List[str]) -> float:
            hits = sum(1 for t in terms if t in desc_lower)
            return min(hits / max(len(terms), 1), 1.0)

        tfidf_vuln = _keyword_score(["vulnerability", "exploit", "injection", "overflow", "attack", "malicious"])
        tfidf_safe = _keyword_score(["safe", "secure", "protected", "validated", "sanitized", "encrypted"])
        tfidf_crypto = _keyword_score(["crypto", "cipher", "aes", "rsa", "hash", "encrypt", "decrypt", "key"])
        tfidf_network = _keyword_score(["http", "https", "ssl", "tls", "socket", "network", "dns", "url"])
        tfidf_storage = _keyword_score(["storage", "database", "sqlite", "file", "shared_preferences", "keystore"])

        return [
            float(len(description)),  # text_length
            keyword_density,  # keyword_density
            severity_score,  # severity_score
            confidence_raw,  # confidence_raw
            0.5,  # context_risk_level (no explicit field)
            has_code_pattern,  # has_code_pattern
            entropy_score,  # entropy_score
            0.0,  # pattern_match_count (no explicit field)
            source_type_encoded,  # source_type_encoded
            category_encoded,  # category_encoded
            tfidf_vuln,  # tfidf_vulnerability_terms
            tfidf_safe,  # tfidf_safe_terms
            tfidf_crypto,  # tfidf_crypto_terms
            tfidf_network,  # tfidf_network_terms
            tfidf_storage,  # tfidf_storage_terms
        ]

    def _explain_with_ml(
        self,
        finding_id: str,
        features,
        finding: Dict[str, Any],
    ) -> Optional[UnifiedExplanation]:
        """Try SHAP/LIME explanation on ML features."""
        engine = self._get_engine()
        if engine is None:
            return None

        try:
            import numpy as np

            features_arr = np.atleast_2d(np.array(features, dtype=float))
            explanation = engine.explain(finding_id, features_arr)

            contributing = []
            for c in explanation.contributions[:5]:
                contributing.append(
                    {
                        "factor": c.feature_name,
                        "value": c.feature_value,
                        "contribution": c.contribution,
                        "direction": c.direction,
                    }
                )

            risk = [c.feature_name for c in explanation.contributions[:3] if c.direction == "positive"]
            mitigating = [c.feature_name for c in explanation.contributions[:3] if c.direction == "negative"]

            return UnifiedExplanation(
                finding_id=finding_id,
                summary=explanation.summary,
                method=explanation.method,
                confidence=explanation.confidence,
                contributing_factors=contributing,
                risk_factors=risk,
                mitigating_factors=mitigating,
                metadata={
                    "base_value": explanation.base_value,
                    "prediction": explanation.prediction,
                    "predicted_class": explanation.predicted_class,
                    **explanation.metadata,
                },
            )
        except Exception as exc:
            logger.debug("ML explanation failed for %s: %s", finding_id, exc)
            return None

    def _explain_from_confidence(
        self,
        finding_id: str,
        confidence_factors: Dict[str, float],
        finding: Dict[str, Any],
    ) -> UnifiedExplanation:
        """Build explanation from confidence scoring factors."""
        sorted_factors = sorted(confidence_factors.items(), key=lambda x: abs(x[1]), reverse=True)

        contributing = []
        risk = []
        mitigating = []

        for name, score in sorted_factors[:10]:
            contributing.append(
                {
                    "factor": name,
                    "value": score,
                    "contribution": score,
                    "direction": "positive" if score > 0.5 else "negative",
                }
            )
            if score > 0.6:
                risk.append(name)
            elif score < 0.3:
                mitigating.append(name)

        confidence = finding.get("confidence", finding.get("confidence_score", 0.0))
        severity = finding.get("severity", "unknown")
        category = finding.get("category", "unknown")

        summary = (
            f"{severity.upper()} {category} finding "
            f"(confidence: {confidence:.0%}). "
            f"Top factors: {', '.join(f[0] for f in sorted_factors[:3])}."
        )

        return UnifiedExplanation(
            finding_id=finding_id,
            summary=summary,
            method="confidence",
            confidence=float(confidence) if isinstance(confidence, (int, float)) else 0.0,
            contributing_factors=contributing,
            risk_factors=risk[:5],
            mitigating_factors=mitigating[:5],
            metadata={
                "severity": severity,
                "category": category,
                "source": "confidence_scoring",
            },
        )

    def _explain_from_attributes(
        self,
        finding_id: str,
        finding: Dict[str, Any],
    ) -> UnifiedExplanation:
        """Build rule-based explanation from finding attributes."""
        factors = []
        risk = []
        mitigating = []

        severity = finding.get("severity", "unknown")
        confidence = finding.get("confidence", finding.get("confidence_score", 0.0))
        category = finding.get("category", "")
        finding.get("description", "")
        evidence = finding.get("evidence", {})
        plugin = finding.get("plugin", finding.get("source_plugin", ""))
        remediation = finding.get("remediation", "")

        # Severity factor
        severity_scores = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}
        sev_score = severity_scores.get(str(severity).lower(), 0.5)
        factors.append(
            {
                "factor": "severity",
                "value": severity,
                "contribution": sev_score,
                "direction": "positive" if sev_score >= 0.5 else "negative",
            }
        )
        if sev_score >= 0.7:
            risk.append(f"Severity rated {severity}")

        # Evidence quality
        if isinstance(evidence, dict):
            if evidence.get("code_snippet"):
                factors.append(
                    {
                        "factor": "code_evidence",
                        "value": "present",
                        "contribution": 0.8,
                        "direction": "positive",
                    }
                )
                risk.append("Direct code evidence found")
            if evidence.get("file_path"):
                factors.append(
                    {
                        "factor": "file_location",
                        "value": evidence["file_path"],
                        "contribution": 0.6,
                        "direction": "positive",
                    }
                )

        # Remediation available
        if remediation:
            mitigating.append("Remediation guidance available")

        # MASVS controls
        masvs = finding.get("masvs_controls", [])
        if masvs:
            factors.append(
                {
                    "factor": "masvs_mapping",
                    "value": masvs[:3] if isinstance(masvs, list) else str(masvs),
                    "contribution": 0.7,
                    "direction": "positive",
                }
            )
            risk.append(f"Maps to MASVS controls: {', '.join(masvs[:3]) if isinstance(masvs, list) else masvs}")

        # Plugin source
        if plugin:
            factors.append(
                {
                    "factor": "detection_source",
                    "value": plugin,
                    "contribution": 0.5,
                    "direction": "positive",
                }
            )

        # Build summary
        parts = []
        if category:
            parts.append(f"{category} vulnerability")
        if severity:
            parts.append(f"rated {severity}")
        if confidence:
            try:
                parts.append(f"({float(confidence):.0%} confidence)")
            except (TypeError, ValueError):
                pass

        summary = " ".join(parts) + "."
        if risk:
            summary += f" Key indicators: {'; '.join(risk[:2])}."
        if mitigating:
            summary += f" Mitigations: {'; '.join(mitigating[:2])}."

        return UnifiedExplanation(
            finding_id=finding_id,
            summary=summary,
            method="rule-based",
            confidence=float(confidence) if isinstance(confidence, (int, float)) else 0.0,
            contributing_factors=factors,
            risk_factors=risk[:5],
            mitigating_factors=mitigating[:5],
            metadata={
                "severity": severity,
                "category": category,
                "plugin": plugin,
                "source": "attribute_analysis",
            },
        )

    def get_available_methods(self) -> List[str]:
        """Return list of available explanation methods."""
        methods = ["rule-based", "confidence"]
        try:
            from core.ml.explainability import get_available_methods as _get

            methods.extend(_get())
        except Exception:
            methods.append("fallback")
        return list(dict.fromkeys(methods))  # deduplicate preserving order

    def get_status(self) -> Dict[str, Any]:
        """Return status of all explainability subsystems."""
        status = {
            "rule_based": True,
            "confidence_based": True,
            "shap": False,
            "lime": False,
        }
        try:
            from core.ml.explainability import SHAP_AVAILABLE, LIME_AVAILABLE

            status["shap"] = SHAP_AVAILABLE
            status["lime"] = LIME_AVAILABLE
        except Exception:
            pass

        status["available_methods"] = self.get_available_methods()
        return status
