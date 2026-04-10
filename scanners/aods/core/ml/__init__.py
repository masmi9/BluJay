#!/usr/bin/env python3
"""
AODS Unified ML Package
======================

Provides unified machine learning capabilities for AODS, including:
- False positive reduction
- Vulnerability classification
- Enhanced detection
- Confidence calibration

This package consolidates all ML functionality into a single,
coherent interface that integrates with the AODS
unified orchestration system.
"""

from .unified_pipeline import (
    UnifiedMLPipeline,
    MLPipelineConfig,
    MLEnhancementResult,
    MLEnhancementLevel,
    create_ml_pipeline,
)

# Explainability module (SHAP/LIME)
try:
    from .explainability import (
        ExplainabilityEngine,
        Explanation,
        FeatureContribution,
        explain_prediction,
        is_explainability_available,
        get_available_methods,
    )

    EXPLAINABILITY_AVAILABLE = True
except ImportError:
    EXPLAINABILITY_AVAILABLE = False
    ExplainabilityEngine = None  # type: ignore
    Explanation = None  # type: ignore
    FeatureContribution = None  # type: ignore
    explain_prediction = None  # type: ignore

    def is_explainability_available():
        return False  # type: ignore

    def get_available_methods():
        return ["fallback"]  # type: ignore


# Migration helpers: expose canonical unified pipeline accessors for consumers
try:
    from core.unified_ml_pipeline import (
        get_unified_ml_pipeline,
        reset_unified_ml_pipeline,
    )
except Exception:  # pragma: no cover - optional in some contexts

    def get_unified_ml_pipeline(*args, **kwargs):  # type: ignore
        raise ImportError("Unified ML pipeline accessors unavailable in this context")

    def reset_unified_ml_pipeline():  # type: ignore
        return None


# Version information
__version__ = "1.0.0"
__author__ = "AODS Development Team"

# Export main interface
__all__ = [
    "UnifiedMLPipeline",
    "MLPipelineConfig",
    "MLEnhancementResult",
    "MLEnhancementLevel",
    "create_ml_pipeline",
    # Canonical unified pipeline accessors
    "get_unified_ml_pipeline",
    "reset_unified_ml_pipeline",
    # Explainability
    "ExplainabilityEngine",
    "Explanation",
    "FeatureContribution",
    "explain_prediction",
    "is_explainability_available",
    "get_available_methods",
    "EXPLAINABILITY_AVAILABLE",
]
