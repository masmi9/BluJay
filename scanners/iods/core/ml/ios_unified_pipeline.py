"""
iOS ML Unified Pipeline – 3-stage false-positive reduction.

Stage 1: Confidence scoring (feature-based)
Stage 2: ML classifier (XGBoost if available, else heuristic fallback)
Stage 3: Heuristic rules (IOSFalsePositiveReducer)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logging_config import get_logger
from core.ml.ios_feature_extractor import IOSFeatureExtractor
from core.ml.ios_false_positive_reducer import IOSFalsePositiveReducer

logger = get_logger(__name__)


class IOSMLPipeline:
    """
    3-stage ML false-positive reduction pipeline for iOS findings.

    If XGBoost model artifact is available, uses it for scoring.
    Falls back to heuristic-only mode if ML dependencies are missing.
    """

    def __init__(self, threshold: float = 0.15, app_profile: str = "production") -> None:
        self.threshold = threshold
        self.app_profile = app_profile
        self.feature_extractor = IOSFeatureExtractor()
        self.fp_reducer = IOSFalsePositiveReducer(threshold=threshold, app_profile=app_profile)
        self._classifier = None
        self._ml_available = False
        self._load_classifier()

    def _load_classifier(self) -> None:
        """Attempt to load XGBoost classifier from disk."""
        model_path = Path("models/ios_classifier/model.pkl")
        if not model_path.exists():
            logger.debug("ML model not found – using heuristic mode", path=str(model_path))
            return
        try:
            import pickle
            with open(model_path, "rb") as f:
                self._classifier = pickle.load(f)
            self._ml_available = True
            logger.info("ML classifier loaded", path=str(model_path))
        except Exception as e:
            logger.warning("Failed to load ML classifier", error=str(e))

    def filter_findings(
        self, findings: List[Dict[str, Any]], ipa_ctx=None
    ) -> List[Dict[str, Any]]:
        """
        Apply 3-stage filtering pipeline.
        Returns filtered list with confidence scores potentially adjusted.
        """
        if not findings:
            return findings

        # Stage 1: Feature-based confidence adjustment
        findings = self._stage1_confidence_adjustment(findings, ipa_ctx)

        # Stage 2: ML classifier scoring (if available)
        if self._ml_available and self._classifier is not None:
            findings = self._stage2_ml_scoring(findings)

        # Stage 3: Heuristic FP rules
        findings = self.fp_reducer.filter(findings)

        logger.debug("ML pipeline complete", input=len(findings), output=len(findings))
        return findings

    def _stage1_confidence_adjustment(
        self, findings: List[Dict[str, Any]], ipa_ctx=None
    ) -> List[Dict[str, Any]]:
        """Adjust confidence scores based on contextual features."""
        for f in findings:
            base_conf = float(f.get("confidence", 0.8))
            # Boost confidence if we have a specific file path + line number
            if f.get("file_path") and f.get("line_number"):
                base_conf = min(1.0, base_conf + 0.05)
            # Boost if CWE and MASVS both present
            if f.get("cwe_id") and f.get("masvs_control"):
                base_conf = min(1.0, base_conf + 0.05)
            # Reduce for info-only with no file reference
            if f.get("severity") == "info" and not f.get("file_path"):
                base_conf = max(0.0, base_conf - 0.1)
            f["confidence"] = round(base_conf, 3)
        return findings

    def _stage2_ml_scoring(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply trained XGBoost classifier to adjust confidence."""
        try:
            import numpy as np
            feature_list = [
                list(self.feature_extractor.extract_single(f).values())
                for f in findings
            ]
            X = np.array(feature_list, dtype=float)
            scores = self._classifier.predict_proba(X)[:, 1]
            for f, score in zip(findings, scores):
                # Weighted blend: 70% original confidence, 30% ML score
                original = float(f.get("confidence", 0.8))
                f["confidence"] = round(0.7 * original + 0.3 * float(score), 3)
                f["ml_score"] = round(float(score), 3)
        except Exception as e:
            logger.warning("ML scoring failed, using original confidence", error=str(e))
        return findings
