#!/usr/bin/env python3
"""
AODS Explainable AI Module

Provides model explanations using SHAP and LIME for vulnerability predictions.
Helps users understand why a finding was classified as a vulnerability.

Features:
- SHAP (SHapley Additive exPlanations) for global and local explanations
- LIME (Local Interpretable Model-agnostic Explanations) for instance explanations
- Feature importance visualization
- Human-readable explanation generation

Dependencies (optional):
- shap>=0.44.0
- lime>=0.2.0.1
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

# Check for optional dependencies
try:
    import shap

    SHAP_AVAILABLE = True
except ImportError:
    shap = None  # type: ignore
    SHAP_AVAILABLE = False
    logger.debug("SHAP not available - install with: pip install shap")

try:
    import lime
    import lime.lime_tabular

    LIME_AVAILABLE = True
except ImportError:
    lime = None  # type: ignore
    LIME_AVAILABLE = False
    logger.debug("LIME not available - install with: pip install lime")


@dataclass
class FeatureContribution:
    """Represents a feature's contribution to a prediction."""

    feature_name: str
    feature_value: Any
    contribution: float
    direction: str  # "positive" or "negative"
    importance_rank: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature": self.feature_name,
            "value": self.feature_value,
            "contribution": self.contribution,
            "direction": self.direction,
            "rank": self.importance_rank,
        }


@dataclass
class Explanation:
    """Complete explanation for a prediction."""

    finding_id: str
    prediction: float
    predicted_class: int
    method: str  # "shap", "lime", or "fallback"
    base_value: float
    contributions: List[FeatureContribution]
    summary: str
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "prediction": self.prediction,
            "predicted_class": self.predicted_class,
            "method": self.method,
            "base_value": self.base_value,
            "contributions": [c.to_dict() for c in self.contributions],
            "summary": self.summary,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }

    def to_human_readable(self) -> str:
        """Generate a human-readable explanation."""
        lines = [
            f"Prediction: {'Vulnerability' if self.predicted_class == 1 else 'Not Vulnerability'}",
            f"Confidence: {self.confidence:.1%}",
            "",
            "Key factors contributing to this decision:",
        ]

        # Group by direction
        positive = [c for c in self.contributions[:5] if c.direction == "positive"]
        negative = [c for c in self.contributions[:5] if c.direction == "negative"]

        if self.predicted_class == 1:
            lines.append("\nIndicators suggesting vulnerability:")
            for c in positive[:3]:
                lines.append(f"  - {c.feature_name}: {c.contribution:+.3f}")
        else:
            lines.append("\nIndicators suggesting safe code:")
            for c in negative[:3]:
                lines.append(f"  - {c.feature_name}: {c.contribution:+.3f}")

        lines.append(f"\nExplanation method: {self.method.upper()}")
        return "\n".join(lines)


class ExplainabilityEngine:
    """Engine for generating model explanations."""

    # Default feature names for vulnerability detection
    DEFAULT_FEATURE_NAMES = [
        "text_length",
        "keyword_density",
        "severity_score",
        "confidence_raw",
        "context_risk_level",
        "has_code_pattern",
        "entropy_score",
        "pattern_match_count",
        "source_type_encoded",
        "category_encoded",
        # TF-IDF features (summarized)
        "tfidf_vulnerability_terms",
        "tfidf_safe_terms",
        "tfidf_crypto_terms",
        "tfidf_network_terms",
        "tfidf_storage_terms",
    ]

    def __init__(
        self, model: Any = None, feature_names: Optional[List[str]] = None, background_data: Optional[np.ndarray] = None
    ):
        """Initialize the explainability engine.

        Args:
            model: Trained model with predict/predict_proba methods
            feature_names: Names for each feature (for interpretation)
            background_data: Background dataset for SHAP (if available)
        """
        self.model = model
        self.feature_names = feature_names or self.DEFAULT_FEATURE_NAMES
        self.background_data = background_data

        self._shap_explainer: Optional[Any] = None
        self._lime_explainer: Optional[Any] = None

        self._initialize_explainers()

    def _initialize_explainers(self) -> None:
        """Initialize SHAP and LIME explainers if available."""
        if SHAP_AVAILABLE and self.model is not None:
            try:
                if self.background_data is not None:
                    self._shap_explainer = shap.Explainer(
                        self.model.predict_proba if hasattr(self.model, "predict_proba") else self.model.predict,
                        self.background_data,
                    )
                else:
                    # Use kernel explainer without background
                    self._shap_explainer = shap.KernelExplainer(
                        lambda x: (
                            self.model.predict_proba(x)[:, 1]
                            if hasattr(self.model, "predict_proba")
                            else self.model.predict(x)
                        ),
                        np.zeros((1, len(self.feature_names))),
                    )
                logger.info("SHAP explainer initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize SHAP explainer: {e}")
                self._shap_explainer = None

        if LIME_AVAILABLE and self.model is not None:
            try:
                # Create synthetic training data stats for LIME
                if self.background_data is not None:
                    training_data = self.background_data
                else:
                    # Use placeholder if no background data
                    training_data = np.random.randn(100, len(self.feature_names))

                self._lime_explainer = lime.lime_tabular.LimeTabularExplainer(
                    training_data,
                    feature_names=self.feature_names[: training_data.shape[1]],
                    class_names=["Not Vulnerability", "Vulnerability"],
                    mode="classification",
                )
                logger.info("LIME explainer initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize LIME explainer: {e}")
                self._lime_explainer = None

    def explain(
        self,
        finding_id: str,
        features: np.ndarray,
        prediction: Optional[float] = None,
        method: str = "auto",
        num_features: int = 10,
    ) -> Explanation:
        """Generate an explanation for a prediction.

        Args:
            finding_id: Unique identifier for the finding
            features: Feature vector for the instance
            prediction: Pre-computed prediction (optional)
            method: Explanation method ("shap", "lime", "auto", or "fallback")
            num_features: Number of top features to include

        Returns:
            Explanation object with contributions and summary
        """
        features = np.atleast_2d(features)

        # Get prediction if not provided
        if prediction is None and self.model is not None:
            if hasattr(self.model, "predict_proba"):
                prediction = float(self.model.predict_proba(features)[0, 1])
            else:
                prediction = float(self.model.predict(features)[0])

        predicted_class = 1 if prediction >= 0.5 else 0

        # Select method
        if method == "auto":
            if SHAP_AVAILABLE and self._shap_explainer is not None:
                method = "shap"
            elif LIME_AVAILABLE and self._lime_explainer is not None:
                method = "lime"
            else:
                method = "fallback"

        # Generate explanation
        if method == "shap" and self._shap_explainer is not None:
            return self._explain_shap(finding_id, features, prediction, predicted_class, num_features)
        elif method == "lime" and self._lime_explainer is not None:
            return self._explain_lime(finding_id, features, prediction, predicted_class, num_features)
        else:
            return self._explain_fallback(finding_id, features, prediction, predicted_class, num_features)

    def _explain_shap(
        self, finding_id: str, features: np.ndarray, prediction: float, predicted_class: int, num_features: int
    ) -> Explanation:
        """Generate SHAP-based explanation."""
        try:
            shap_values = self._shap_explainer(features)

            # Extract values (handle different SHAP output formats)
            if hasattr(shap_values, "values"):
                values = shap_values.values[0]
                if len(values.shape) > 1:
                    values = values[:, 1]  # Use positive class
                base = shap_values.base_values[0] if hasattr(shap_values, "base_values") else 0.5
            else:
                values = np.array(shap_values[0])
                base = 0.5

            # Create contributions
            contributions = self._create_contributions(features[0], values, num_features)

            summary = self._generate_summary(contributions, predicted_class, "SHAP")

            return Explanation(
                finding_id=finding_id,
                prediction=prediction,
                predicted_class=predicted_class,
                method="shap",
                base_value=float(base),
                contributions=contributions,
                summary=summary,
                confidence=abs(prediction - 0.5) * 2,
                metadata={"shap_version": getattr(shap, "__version__", "unknown")},
            )

        except Exception as e:
            logger.warning(f"SHAP explanation failed: {e}, falling back")
            return self._explain_fallback(finding_id, features, prediction, predicted_class, num_features)

    def _explain_lime(
        self, finding_id: str, features: np.ndarray, prediction: float, predicted_class: int, num_features: int
    ) -> Explanation:
        """Generate LIME-based explanation."""
        try:
            # Predict function for LIME
            def predict_fn(x):
                if hasattr(self.model, "predict_proba"):
                    return self.model.predict_proba(x)
                else:
                    preds = self.model.predict(x)
                    return np.column_stack([1 - preds, preds])

            exp = self._lime_explainer.explain_instance(features[0], predict_fn, num_features=num_features, labels=(1,))

            # Extract LIME contributions
            lime_list = exp.as_list(label=1)
            values = np.zeros(len(self.feature_names))

            for feature_exp, weight in lime_list:
                # Parse feature name from LIME's format
                for i, name in enumerate(self.feature_names):
                    if name in feature_exp:
                        values[i] = weight
                        break

            contributions = self._create_contributions(features[0], values, num_features)
            summary = self._generate_summary(contributions, predicted_class, "LIME")

            return Explanation(
                finding_id=finding_id,
                prediction=prediction,
                predicted_class=predicted_class,
                method="lime",
                base_value=0.5,
                contributions=contributions,
                summary=summary,
                confidence=abs(prediction - 0.5) * 2,
                metadata={"lime_version": getattr(lime, "__version__", "unknown")},
            )

        except Exception as e:
            logger.warning(f"LIME explanation failed: {e}, falling back")
            return self._explain_fallback(finding_id, features, prediction, predicted_class, num_features)

    def _explain_fallback(
        self, finding_id: str, features: np.ndarray, prediction: float, predicted_class: int, num_features: int
    ) -> Explanation:
        """Generate fallback explanation using feature importance heuristics."""
        # Use feature values as proxy for contribution
        # Higher absolute values suggest more influence
        feature_values = features[0]

        # Create pseudo-contributions based on deviation from mean
        pseudo_contributions = feature_values - np.mean(feature_values)

        # Scale by predicted class direction
        if predicted_class == 0:
            pseudo_contributions = -pseudo_contributions

        contributions = self._create_contributions(feature_values, pseudo_contributions, num_features)

        summary = self._generate_summary(contributions, predicted_class, "heuristic")

        return Explanation(
            finding_id=finding_id,
            prediction=prediction,
            predicted_class=predicted_class,
            method="fallback",
            base_value=0.5,
            contributions=contributions,
            summary=summary,
            confidence=abs(prediction - 0.5) * 2,
            metadata={"note": "Heuristic explanation - install shap/lime for accurate explanations"},
        )

    def _create_contributions(
        self, feature_values: np.ndarray, contribution_values: np.ndarray, num_features: int
    ) -> List[FeatureContribution]:
        """Create FeatureContribution objects from values."""
        contributions = []

        # Sort by absolute contribution
        indices = np.argsort(np.abs(contribution_values))[::-1]

        for rank, idx in enumerate(indices[:num_features]):
            if idx < len(self.feature_names):
                name = self.feature_names[idx]
            else:
                name = f"feature_{idx}"

            value = float(feature_values[idx]) if idx < len(feature_values) else 0.0
            contrib = float(contribution_values[idx])

            contributions.append(
                FeatureContribution(
                    feature_name=name,
                    feature_value=value,
                    contribution=contrib,
                    direction="positive" if contrib > 0 else "negative",
                    importance_rank=rank + 1,
                )
            )

        return contributions

    def _generate_summary(self, contributions: List[FeatureContribution], predicted_class: int, method: str) -> str:
        """Generate a human-readable summary."""
        if not contributions:
            return "Unable to determine key factors for this prediction."

        top_positive = [c for c in contributions[:3] if c.direction == "positive"]
        top_negative = [c for c in contributions[:3] if c.direction == "negative"]

        if predicted_class == 1:
            if top_positive:
                factors = ", ".join([c.feature_name for c in top_positive])
                return f"Classified as vulnerability primarily due to: {factors}"
            else:
                return "Classified as vulnerability but no strong positive indicators found."
        else:
            if top_negative:
                factors = ", ".join([c.feature_name for c in top_negative])
                return f"Classified as non-vulnerability due to absence of: {factors}"
            else:
                return "Classified as non-vulnerability based on overall feature pattern."

    def get_global_importance(self, X: np.ndarray, sample_size: int = 100) -> Dict[str, float]:
        """Calculate global feature importance across a dataset.

        Args:
            X: Feature matrix
            sample_size: Number of samples to use

        Returns:
            Dictionary mapping feature names to importance scores
        """
        if len(X) > sample_size:
            indices = np.random.choice(len(X), sample_size, replace=False)
            X = X[indices]

        if SHAP_AVAILABLE and self._shap_explainer is not None:
            try:
                shap_values = self._shap_explainer(X)
                if hasattr(shap_values, "values"):
                    importance = np.abs(shap_values.values).mean(axis=0)
                    if len(importance.shape) > 1:
                        importance = importance[:, 1]
                else:
                    importance = np.abs(np.array(shap_values)).mean(axis=0)

                return {
                    self.feature_names[i]: float(importance[i])
                    for i in range(min(len(self.feature_names), len(importance)))
                }
            except Exception as e:
                logger.warning(f"Global SHAP importance failed: {e}")

        # Fallback: use model feature importance if available
        if self.model is not None and hasattr(self.model, "feature_importances_"):
            importance = self.model.feature_importances_
            return {
                self.feature_names[i]: float(importance[i])
                for i in range(min(len(self.feature_names), len(importance)))
            }

        # Last resort: return placeholder
        return {name: 0.0 for name in self.feature_names}


def is_explainability_available() -> bool:
    """Check if explainability features are available."""
    return SHAP_AVAILABLE or LIME_AVAILABLE


def get_available_methods() -> List[str]:
    """Get list of available explanation methods."""
    methods = []
    if SHAP_AVAILABLE:
        methods.append("shap")
    if LIME_AVAILABLE:
        methods.append("lime")
    methods.append("fallback")
    return methods


# Convenience function for quick explanations
def explain_prediction(
    model: Any, features: np.ndarray, finding_id: str = "unknown", feature_names: Optional[List[str]] = None
) -> Explanation:
    """Quick function to generate an explanation.

    Args:
        model: Trained model
        features: Feature vector
        finding_id: Optional finding identifier
        feature_names: Optional feature names

    Returns:
        Explanation object
    """
    engine = ExplainabilityEngine(model, feature_names)
    return engine.explain(finding_id, features)
