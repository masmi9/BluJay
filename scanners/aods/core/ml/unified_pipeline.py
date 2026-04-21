#!/usr/bin/env python3
"""
Unified ML Enhancement Pipeline
==============================

Integrates all ML components with the unified orchestration system to provide
full ML-enhanced vulnerability detection and false positive reduction.

This pipeline consolidates:
- ML False Positive Reduction (core/ml_false_positive_reducer.py)
- Vulnerability Classification (core/ml_vulnerability_classifier.py)
- Full ML Classifier (core/comprehensive_vulnerability_ml_classifier.py)
- Enhanced Detection Engine (core/ai_ml/enhanced_vulnerability_detection_engine.py)

Key Features:
- Unified ML interface for all orchestration components
- Standardized ML result format compatible with CanonicalFinding
- Performance-optimized ML pipeline with caching
- Configurable ML enhancement levels
- Error handling and fallback mechanisms
"""

import logging as _stdlib_logging  # kept for per-instance logger
import warnings
import time
from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from enum import Enum
import json
import os

# Core AODS imports
from core.finding import CanonicalFinding

# ML Component imports with fallback handling
try:
    from ..ml_false_positive_reducer import OptimizedMLFalsePositiveReducer

    ML_FP_REDUCER_AVAILABLE = True
except ImportError:
    ML_FP_REDUCER_AVAILABLE = False

try:
    from ..comprehensive_vulnerability_ml_classifier import ComprehensiveVulnerabilityMLClassifier

    ML_CLASSIFIER_AVAILABLE = True
except ImportError:
    ML_CLASSIFIER_AVAILABLE = False

try:
    from ..ai_ml.enhanced_vulnerability_detection_engine import EnhancedVulnerabilityDetectionEngine

    ENHANCED_DETECTION_AVAILABLE = True
except ImportError:
    ENHANCED_DETECTION_AVAILABLE = False

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    logger = _stdlib_logging.getLogger(__name__)


class MLEnhancementLevel(Enum):
    """ML enhancement levels for different use cases."""

    DISABLED = "disabled"
    BASIC = "basic"  # False positive reduction only
    STANDARD = "standard"  # FP reduction + classification
    ADVANCED = "advanced"  # Full ML pipeline with enhanced detection
    MAXIMUM = "maximum"  # All ML features with maximum accuracy


@dataclass
class MLPipelineConfig:
    """Configuration for the unified ML pipeline."""

    enhancement_level: MLEnhancementLevel = MLEnhancementLevel.STANDARD
    enable_false_positive_reduction: bool = True
    enable_vulnerability_classification: bool = True
    enable_enhanced_detection: bool = False
    enable_confidence_calibration: bool = True
    # Calibrator retraining and AB gating
    enable_weekly_calibrator: bool = True
    calibrator_ab_percentage: float = 0.01
    # Classification thresholds and abstention
    classification_thresholds: Optional[Dict[str, float]] = None
    classification_abstain_margin: float = 0.05

    # Performance settings
    max_processing_time_seconds: int = 30
    enable_caching: bool = True
    cache_ttl_seconds: int = 3600

    # Quality thresholds
    min_confidence_threshold: float = 0.7
    false_positive_threshold: float = 0.15  # 15% FP threshold

    # Model paths
    model_base_dir: str = "models/unified_ml"
    cache_dir: str = "cache/ml_pipeline"


@dataclass
class MLEnhancementResult:
    """Result of ML enhancement processing."""

    original_findings: List[CanonicalFinding]
    enhanced_findings: List[CanonicalFinding]
    filtered_findings: List[CanonicalFinding]  # Findings marked as false positives

    # ML metrics
    false_positive_count: int = 0
    enhancement_count: int = 0
    confidence_improvements: int = 0

    # Performance metrics
    processing_time_seconds: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0

    # ML component results
    fp_reduction_results: Optional[Dict[str, Any]] = None
    classification_results: Optional[Dict[str, Any]] = None
    detection_results: Optional[Dict[str, Any]] = None


class UnifiedMLPipeline:
    """
    Unified ML Enhancement Pipeline for AODS

    Provides a single interface for all ML enhancement capabilities,
    integrating with the unified orchestration system.
    """

    def __init__(self, config: MLPipelineConfig):
        self.config = config
        self.logger = _stdlib_logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        # Deprecation notice: prefer core.unified_ml_pipeline APIs
        try:
            warnings.warn(
                "core.ml.unified_pipeline is deprecated; use core.unified_ml_pipeline or get_unified_ml_pipeline()",
                DeprecationWarning,
                stacklevel=2,
            )
        except Exception:
            pass

        # Initialize directories
        self.model_dir = Path(config.model_base_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        self.cache_dir = Path(config.cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Initialize ML components
        self.fp_reducer = None
        self.vulnerability_classifier = None
        self.enhanced_detector = None

        # Best-effort: unify cache and performance tracking infrastructure
        self.cache_manager = None
        self.performance_tracker = None
        self._CacheType = None
        try:
            from core.shared_infrastructure.performance.caching_consolidation import (
                get_unified_cache_manager,  # type: ignore
                CacheType,  # type: ignore
            )
            from core.shared_infrastructure.monitoring.performance_tracker import (
                get_unified_performance_tracker,  # type: ignore
            )

            self.cache_manager = get_unified_cache_manager()
            self._CacheType = CacheType
            self.performance_tracker = get_unified_performance_tracker()
        except Exception:
            # Fallback gracefully if unified infra is not present in this context
            self._CacheType = None

        # Performance tracking
        self.performance_stats = {
            "total_processed": 0,
            "total_enhanced": 0,
            "total_filtered": 0,
            "average_processing_time": 0.0,
        }
        # Simple calibration tracking (ECE-like) histograms
        self._hist_confidence: List[float] = []
        self._hist_fp_prob: List[float] = []

        self._initialize_ml_components()

        self.logger.info(f"Unified ML Pipeline initialized with enhancement level: {config.enhancement_level.value}")

    def _initialize_ml_components(self):
        """Initialize ML components based on configuration."""
        try:
            # Initialize False Positive Reducer
            if (
                self.config.enable_false_positive_reduction
                and ML_FP_REDUCER_AVAILABLE
                and self.config.enhancement_level != MLEnhancementLevel.DISABLED
            ):

                fp_config = {
                    "ml_enhancement": {
                        "model_dir": str(self.model_dir / "false_positive"),
                        "feedback_dir": str(self.model_dir / "feedback"),
                        "enable_advanced_features": self.config.enhancement_level
                        in [MLEnhancementLevel.ADVANCED, MLEnhancementLevel.MAXIMUM],
                    }
                }
                self.fp_reducer = OptimizedMLFalsePositiveReducer(fp_config)
                self.logger.info("✅ ML False Positive Reducer initialized")

            # Initialize Vulnerability Classifier
            if (
                self.config.enable_vulnerability_classification
                and ML_CLASSIFIER_AVAILABLE
                and self.config.enhancement_level
                in [MLEnhancementLevel.STANDARD, MLEnhancementLevel.ADVANCED, MLEnhancementLevel.MAXIMUM]
            ):
                try:
                    # Instantiate full classifier
                    self.vulnerability_classifier = ComprehensiveVulnerabilityMLClassifier()
                    self.logger.info("✅ ML Vulnerability Classifier initialized")
                except Exception as ce:
                    self.logger.warning(f"ML Vulnerability Classifier unavailable: {ce}")

            # Initialize Enhanced Detector
            if (
                self.config.enable_enhanced_detection
                and ENHANCED_DETECTION_AVAILABLE
                and self.config.enhancement_level in [MLEnhancementLevel.ADVANCED, MLEnhancementLevel.MAXIMUM]
            ):

                try:
                    self.enhanced_detector = EnhancedVulnerabilityDetectionEngine(
                        model_cache_dir=str(self.model_dir / "enhanced_detection"),
                        enable_deep_learning=False,
                        enable_ensemble=True,
                        enable_explainable_ai=False,
                    )
                    self.logger.info("✅ Enhanced ML Detector initialized")
                except Exception as de:
                    self.logger.warning(f"Enhanced ML Detector unavailable: {de}")

        except Exception as e:
            self.logger.error(f"Error initializing ML components: {e}")
            # Continue with available components

    def enhance_findings(
        self, findings: List[CanonicalFinding], context: Optional[Dict[str, Any]] = None
    ) -> MLEnhancementResult:
        """
        Apply ML enhancement to a list of canonical findings.

        Args:
            findings: List of canonical findings to enhance
            context: Optional context information (APK info, scan metadata, etc.)

        Returns:
            MLEnhancementResult with enhanced findings and metrics
        """
        start_time = time.time()

        if self.config.enhancement_level == MLEnhancementLevel.DISABLED:
            return MLEnhancementResult(
                original_findings=findings,
                enhanced_findings=findings,
                filtered_findings=[],
                processing_time_seconds=time.time() - start_time,
            )

        try:
            # Snapshot original confidences by finding_id for improvement metrics
            try:
                original_confidence_by_id = {f.finding_id: float(getattr(f, "confidence", 0.0)) for f in findings}
            except Exception:
                original_confidence_by_id = {}
            # Step 1: False Positive Reduction
            fp_filtered_findings, fp_results = self._apply_false_positive_reduction(findings, context)

            # Step 2: Vulnerability Classification Enhancement
            classified_findings, classification_results = self._apply_vulnerability_classification(
                fp_filtered_findings, context
            )

            # Step 3: Enhanced Detection (if enabled)
            final_findings, detection_results = self._apply_enhanced_detection(classified_findings, context)

            # Calculate metrics
            processing_time = time.time() - start_time
            false_positive_count = len(findings) - len(fp_filtered_findings)
            enhancement_count = sum(1 for f in final_findings if f.ml_enhanced)
            # Confidence improvement count (among survivors)
            confidence_improvements = 0
            try:
                for f in final_findings:
                    prev = original_confidence_by_id.get(getattr(f, "finding_id", ""), None)
                    if prev is None:
                        continue
                    try:
                        if float(getattr(f, "confidence", prev)) > float(prev) + 1e-9:
                            confidence_improvements += 1
                    except Exception:
                        continue
            except Exception:
                confidence_improvements = 0

            # Update performance stats
            self._update_performance_stats(processing_time, len(findings), enhancement_count, false_positive_count)

            result = MLEnhancementResult(
                original_findings=findings,
                enhanced_findings=final_findings,
                filtered_findings=[f for f in findings if f not in fp_filtered_findings],
                false_positive_count=false_positive_count,
                enhancement_count=enhancement_count,
                confidence_improvements=confidence_improvements,
                processing_time_seconds=processing_time,
                fp_reduction_results=fp_results,
                classification_results=classification_results,
                detection_results=detection_results,
            )

            self.logger.info(
                f"ML enhancement completed: {len(findings)} → {len(final_findings)} findings "
                f"({false_positive_count} filtered, {enhancement_count} enhanced) in {processing_time:.2f}s"
            )
            # Metrics accumulation
            try:
                for f in final_findings:
                    if hasattr(f, "confidence"):
                        self._hist_confidence.append(float(getattr(f, "confidence", 0.0)))
                    if hasattr(f, "false_positive_probability"):
                        self._hist_fp_prob.append(float(getattr(f, "false_positive_probability", 0.0)))
            except Exception:
                pass

            # Best-effort unified metrics
            try:
                if self.performance_tracker is not None:
                    self.performance_tracker.record_metric(
                        "ml_enhancement_duration_ms", processing_time * 1000.0, {"stage": "pipeline"}
                    )
                    self.performance_tracker.record_metric("ml_enhancement_filtered", false_positive_count, {})
                    self.performance_tracker.record_metric("ml_enhancement_confidence_lifts", enhancement_count, {})
            except Exception:
                pass

            return result

        except Exception as e:
            self.logger.error(f"Error in ML enhancement pipeline: {e}")
            # Return original findings on error
            return MLEnhancementResult(
                original_findings=findings,
                enhanced_findings=findings,
                filtered_findings=[],
                processing_time_seconds=time.time() - start_time,
            )

    def _apply_false_positive_reduction(
        self, findings: List[CanonicalFinding], context: Optional[Dict[str, Any]]
    ) -> Tuple[List[CanonicalFinding], Optional[Dict[str, Any]]]:
        """Apply false positive reduction using ML adapter with fingerprint-based caching."""
        if not self.config.enable_false_positive_reduction:
            return findings, None

        # If reducer unavailable, pass-through with metrics
        if not self.fp_reducer:
            self.logger.debug("FP reducer unavailable, skipping ML reduction (pass-through)")
            return findings, {"adapter": "noop", "filtered_count": 0, "cache_hits": 0, "cache_misses": 0}

        filtered_findings: List[CanonicalFinding] = []
        filtered_out: List[str] = []
        confidence_scores: List[float] = []
        cache_hits = 0
        cache_misses = 0

        # Simple JSON cache fallback (prefer unified cache if available)
        cache_file = self.cache_dir / "fp_cache.json"
        cache_data: Dict[str, Any] = {}
        if self.cache_manager is None:
            try:
                cache_data = json.loads(cache_file.read_text()) if cache_file.exists() else {}
            except Exception:
                cache_data = {}

        # Adaptive threshold: tighten when vendor/obfuscation-heavy
        adaptive_threshold = self.config.false_positive_threshold
        try:
            import os
            import re

            if os.getenv("AODS_ML_THRESHOLD_AUTO", "1") == "1":
                vendor_prefixes = (
                    "/androidx/",
                    "/android/support/",
                    "/com/google/",
                    "/org/apache/",
                    "/kotlin/",
                    "/kotlinx/",
                )
                vendor_hits = 0
                obfus_hits = 0
                total = max(1, len(findings))
                for f in findings:
                    fp = ""
                    try:
                        fp = (f.primary_location.file_path if getattr(f, "primary_location", None) else "") or ""
                    except Exception:
                        fp = ""
                    if any(p in fp for p in vendor_prefixes):
                        vendor_hits += 1
                    # simple obfuscation heuristic: path segments with 1-2 chars
                    if re.search(r"/[A-Za-z]{1,2}/", fp):
                        obfus_hits += 1
                ratio = (vendor_hits + obfus_hits) / float(total)
                # tighten threshold if ratio is high
                if ratio >= 0.6:
                    target = float(os.getenv("AODS_ML_THRESHOLD_VENDOR", "0.10"))
                    adaptive_threshold = min(adaptive_threshold, target)
                elif ratio >= 0.4:
                    target = float(os.getenv("AODS_ML_THRESHOLD_MIXED", "0.12"))
                    adaptive_threshold = min(adaptive_threshold, target)
        except Exception:
            pass

        for finding in findings:
            # Ensure fingerprint exists
            fingerprint = getattr(finding, "fingerprint", None) or ""
            cache_key = f"fp:{fingerprint}"

            cached = None
            if self.cache_manager is not None and self._CacheType is not None:
                try:
                    cached = self.cache_manager.retrieve(cache_key, self._CacheType.GENERAL)  # type: ignore
                except Exception:
                    cached = None
            else:
                cached = cache_data.get(cache_key)

            if cached and (
                not isinstance(cached, dict) or (time.time() - cached.get("ts", 0)) <= self.config.cache_ttl_seconds
            ):
                cache_hits += 1
                try:
                    fp_prob = float(cached.get("fp_prob", 0.0))  # type: ignore
                except Exception:
                    fp_prob = 0.0
                try:
                    conf = float(cached.get("conf", 0.5))  # type: ignore
                except Exception:
                    conf = 0.5
            else:
                cache_misses += 1
                # Adapter call: predict_false_positive expects content-like string; use title/description fallback
                content = finding.title or finding.description or ""
                ctx = {
                    "file_path": finding.primary_location.file_path if finding.primary_location else "",
                    "category": finding.category.value if hasattr(finding.category, "value") else str(finding.category),
                }
                try:
                    ml_result = self.fp_reducer.predict_false_positive(content, ctx)
                    fp_prob = float(getattr(ml_result, "false_positive_probability", 0.0))
                    conf = float(getattr(ml_result, "confidence", 0.5))
                except Exception as e:
                    self.logger.warning(f"FP reducer prediction failed: {e}")
                    fp_prob = 0.0
                    conf = finding.confidence

                # Write cache (prefer unified cache)
                try:
                    payload = {"fp_prob": fp_prob, "conf": conf, "ts": time.time()}
                    if self.cache_manager is not None and self._CacheType is not None:
                        try:
                            self.cache_manager.store(cache_key, payload, self._CacheType.GENERAL)  # type: ignore
                        except Exception:
                            pass
                    else:
                        cache_data[cache_key] = payload
                except Exception:
                    pass

            # Decision: keep if fp_prob < threshold; record enhancements
            if fp_prob < adaptive_threshold:
                finding.false_positive_probability = fp_prob
                # Update numeric confidence if ML provides higher calibrated confidence
                if conf is not None:
                    finding.confidence = max(0.0, min(1.0, conf))
                finding.ml_enhanced = True
                filtered_findings.append(finding)
            else:
                filtered_out.append(finding.finding_id)

            confidence_scores.append(conf)

        # Persist legacy cache if unified cache is not present
        if self.cache_manager is None:
            try:
                cache_file.write_text(json.dumps(cache_data))
            except Exception:
                pass

        self.logger.debug(
            f"False positive reduction: {len(findings)} → {len(filtered_findings)} (filtered {len(filtered_out)})"
        )
        return filtered_findings, {
            "adapter": "OptimizedMLFalsePositiveReducer",
            "filtered_count": len(filtered_out),
            "confidence_scores": confidence_scores,
            "cache_hits": cache_hits,
            "cache_misses": cache_misses,
        }

    def _apply_vulnerability_classification(
        self, findings: List[CanonicalFinding], context: Optional[Dict[str, Any]]
    ) -> Tuple[List[CanonicalFinding], Optional[Dict[str, Any]]]:
        """Apply ML-enhanced vulnerability classification."""
        if not self.config.enable_vulnerability_classification:
            return findings, None

        try:
            # If classifier not available, skip
            if self.vulnerability_classifier is None:
                return findings, {"adapter": "noop"}

            enhanced_findings: List[CanonicalFinding] = []
            reclassified = 0
            enhanced = 0
            abstained = 0

            # Per-category thresholds (conservative defaults)
            default_thresholds = {
                "injection": 0.75,
                "crypto_failures": 0.8,
                "network_security": 0.7,
                "broken_authentication": 0.8,
                "sensitive_data_exposure": 0.75,
            }
            category_thresholds = self.config.classification_thresholds or default_thresholds
            abstain_margin = float(getattr(self.config, "classification_abstain_margin", 0.05))

            for finding in findings:
                text = f"{finding.title}\n{finding.description}"
                try:
                    cls_result = self.vulnerability_classifier.classify_vulnerability(text, context or {})
                except Exception as e:
                    self.logger.debug(f"Classifier error: {e}")
                    enhanced_findings.append(finding)
                    continue

                # Extract prediction
                predicted_category = getattr(cls_result, "category", "unknown") or "unknown"
                confidence = float(getattr(cls_result, "confidence", finding.confidence))

                # Apply per-category threshold and abstention
                threshold = float(category_thresholds.get(predicted_category, 0.8))
                if confidence >= threshold + abstain_margin:
                    # Map to VulnerabilityCategory if possible
                    try:
                        from core.finding.canonical_schema_v1 import VulnerabilityCategory

                        mapped = None
                        pc = predicted_category.lower()
                        if "injection" in pc:
                            mapped = VulnerabilityCategory.INJECTION_VULNERABILITIES
                        elif "crypto" in pc:
                            mapped = VulnerabilityCategory.INSUFFICIENT_CRYPTOGRAPHY
                        elif "network" in pc:
                            mapped = VulnerabilityCategory.NETWORK_SECURITY
                        elif "authentication" in pc:
                            mapped = VulnerabilityCategory.INSECURE_AUTHENTICATION
                        elif "sensitive" in pc or "exposure" in pc:
                            mapped = VulnerabilityCategory.INSECURE_DATA_STORAGE
                        if mapped is not None:
                            finding.category = mapped
                            reclassified += 1
                    except Exception:
                        pass
                else:
                    # Count abstention when prediction exists but below threshold margin
                    try:
                        if predicted_category and predicted_category != "unknown":
                            abstained += 1
                    except Exception:
                        pass
                # Update confidence numerically and level (typed enum)
                finding.confidence = max(finding.confidence, min(1.0, max(0.0, confidence)))
                try:
                    from core.finding.canonical_schema_v1 import ConfidenceLevel as CFLevel

                    if finding.confidence >= 0.9:
                        level_enum = CFLevel.VERY_HIGH
                    elif finding.confidence >= 0.7:
                        level_enum = CFLevel.HIGH
                    elif finding.confidence >= 0.5:
                        level_enum = CFLevel.MEDIUM
                    elif finding.confidence >= 0.3:
                        level_enum = CFLevel.LOW
                    else:
                        level_enum = CFLevel.VERY_LOW
                    finding.confidence_level = level_enum
                except Exception:
                    # Fallback: leave existing level if enum import fails
                    pass
                finding.ml_enhanced = True
                enhanced += 1
                enhanced_findings.append(finding)

            self.logger.debug(
                f"Vulnerability classification enhanced {enhanced} findings, reclassified {reclassified}, abstained {abstained}"  # noqa: E501
            )
            return enhanced_findings, {
                "adapter": "ComprehensiveVulnerabilityMLClassifier",
                "enhanced_count": enhanced,
                "reclassified_count": reclassified,
                "abstained_count": abstained,
            }

        except Exception as e:
            self.logger.error(f"Error in vulnerability classification: {e}")
            return findings, None

    def _apply_enhanced_detection(
        self, findings: List[CanonicalFinding], context: Optional[Dict[str, Any]]
    ) -> Tuple[List[CanonicalFinding], Optional[Dict[str, Any]]]:
        """Apply enhanced ML detection for additional findings."""
        if not self.config.enable_enhanced_detection:
            return findings, None

        try:
            if not self.enhanced_detector:
                return findings, {"adapter": "noop"}

            from core.finding.canonical_schema_v1 import (
                CanonicalFinding,
                VulnerabilityEvidence,
                EvidenceLocation,
                VulnerabilityCategory,
                SeverityLevel,
            )

            enhanced_findings = list(findings)
            additional: List[CanonicalFinding] = []
            added = 0
            enhanced_existing = 0

            for f in findings:
                try:
                    content = f.description or f.title
                    det = self.enhanced_detector.detect_vulnerabilities_enhanced(
                        content=content,
                        title=f.title,
                        file_path=(f.primary_location.file_path if f.primary_location else ""),
                        context=context or {},
                    )
                except Exception as e:
                    self.logger.debug(f"Enhanced detection error: {e}")
                    continue

                # Enhance existing with flags
                if getattr(det, "is_vulnerability", False):
                    f.ml_enhanced = True
                    # Lift confidence if higher
                    f.confidence = max(f.confidence, float(getattr(det, "confidence", f.confidence)))
                    enhanced_existing += 1

                    # Optionally, add a new synthetic finding if pattern suggests separate issue
                    try:
                        loc = EvidenceLocation(
                            file_path=str(f.primary_location.file_path) if f.primary_location else "dynamic://enhanced"
                        )
                        ev = VulnerabilityEvidence(
                            evidence_type="enhanced_detection",
                            content=str(getattr(det, "explanation", "")),
                            location=loc,
                        )
                        cat = (
                            VulnerabilityCategory.NETWORK_SECURITY
                            if "network" in (getattr(det, "vulnerability_type", "").lower())
                            else f.category
                        )
                        sev = SeverityLevel.HIGH if float(getattr(det, "confidence", 0.0)) >= 0.8 else f.severity
                        nf = CanonicalFinding(
                            title=f"Enhanced: {getattr(det, 'vulnerability_type', 'Unknown')}",
                            description=str(getattr(det, "recommendation", "")),
                            category=cat,
                            severity=sev,
                            evidence=[ev],
                            detector_name="enhanced_detector",
                            package_name=context.get("package_name", ""),
                        )
                        nf.ml_enhanced = True
                        additional.append(nf)
                        added += 1
                    except Exception:
                        pass

            enhanced_findings.extend(additional)
            self.logger.debug(f"Enhanced detection added {added} findings and enhanced {enhanced_existing} existing")
            return enhanced_findings, {
                "adapter": "EnhancedVulnerabilityDetectionEngine",
                "additional_findings": added,
                "enhanced_existing": enhanced_existing,
            }

        except Exception as e:
            self.logger.error(f"Error in enhanced detection: {e}")
            return findings, None

    def _calibrate_confidence(self, original_confidence, ml_confidence: float):
        """Calibrate confidence level based on ML analysis."""
        # Placeholder kept for backward compatibility; numeric confidence mapping is primary
        if ml_confidence > 0.9:
            return "HIGH"
        elif ml_confidence > 0.7:
            return "MEDIUM"
            return "LOW"

    def _enhance_confidence_with_ml(self, finding: CanonicalFinding):
        """Enhance confidence level using ML analysis."""
        # Placeholder for ML-based confidence enhancement
        return "MEDIUM"  # Simplified

    def _update_performance_stats(
        self, processing_time: float, original_count: int, enhanced_count: int, filtered_count: int
    ):
        """Update performance statistics."""
        self.performance_stats["total_processed"] += original_count
        self.performance_stats["total_enhanced"] += enhanced_count
        self.performance_stats["total_filtered"] += filtered_count

        # Update rolling average
        current_avg = self.performance_stats["average_processing_time"]
        total_runs = self.performance_stats.get("total_runs", 0) + 1
        self.performance_stats["average_processing_time"] = (
            current_avg * (total_runs - 1) + processing_time
        ) / total_runs
        self.performance_stats["total_runs"] = total_runs

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics."""
        metrics = dict(self.performance_stats)
        # Add simple hist summaries and ECE/MCE approximations (bucketed)
        try:

            def _bucketize(vals: List[float], k: int = 10):
                buckets = [0] * k
                for v in vals:
                    idx = max(0, min(k - 1, int(v * k)))
                    buckets[idx] += 1
                return buckets

            metrics["confidence_histogram"] = _bucketize(self._hist_confidence)
            metrics["fp_prob_histogram"] = _bucketize(self._hist_fp_prob)
            # Placeholder ECE/MCE (no labels): report dispersion as proxy
            if self._hist_confidence:
                mean_conf = sum(self._hist_confidence) / len(self._hist_confidence)
                var_conf = sum((c - mean_conf) * (c - mean_conf) for c in self._hist_confidence) / len(
                    self._hist_confidence
                )
                metrics["confidence_variance"] = var_conf
                # Proxy ECE/MCE without labels: distance from 0.5 and max absolute deviation
                # These are bounded in [0,1]
                ece_proxy = min(1.0, max(0.0, abs(mean_conf - 0.5) * 2.0))
                mce_proxy = 0.0
                try:
                    mce_proxy = max((abs(c - 0.5) * 2.0) for c in self._hist_confidence)
                    mce_proxy = min(1.0, max(0.0, mce_proxy))
                except Exception:
                    mce_proxy = ece_proxy
                metrics["ece_proxy"] = ece_proxy
                metrics["mce_proxy"] = mce_proxy
            if self._hist_fp_prob:
                mean_fp = sum(self._hist_fp_prob) / len(self._hist_fp_prob)
                var_fp = sum((p - mean_fp) * (p - mean_fp) for p in self._hist_fp_prob) / len(self._hist_fp_prob)
                metrics["fp_probability_variance"] = var_fp
        except Exception:
            pass
        return metrics

    def is_available(self) -> bool:
        """Check if ML pipeline is available and functional."""
        return self.config.enhancement_level != MLEnhancementLevel.DISABLED and (
            self.fp_reducer is not None
            or self.vulnerability_classifier is not None
            or self.enhanced_detector is not None
        )


# Factory function for easy integration


def create_ml_pipeline(config: Optional[Dict[str, Any]] = None) -> UnifiedMLPipeline:
    """
    Create a unified ML pipeline with the given configuration.

    Args:
        config: Optional configuration dictionary

    Returns:
        Configured UnifiedMLPipeline instance
    """
    if config is None:
        config = {}

    # --- YAML-backed ML filtering defaults (env > YAML > code default) ---
    def _locate_patterns_yaml() -> Optional[Path]:
        # Priority 1: explicit env var
        env_path = os.getenv("AODS_VULN_PATTERNS_FILE")
        if env_path:
            p = Path(env_path)
            if p.exists():
                return p
        # Priority 2: cwd/config/vulnerability_patterns.yaml
        p = Path.cwd() / "config" / "vulnerability_patterns.yaml"
        if p.exists():
            return p
        # Priority 3: walk up from this file to find repo root/config
        here = Path(__file__).resolve()
        for i in range(1, 6):
            candidate = here.parents[i - 1] / "config" / "vulnerability_patterns.yaml"
            if candidate.exists():
                return candidate
        return None

    def _read_yaml_ml_threshold_default() -> Optional[float]:
        # If caller provided explicit value, don't override
        if "false_positive_threshold" in config and config.get("false_positive_threshold") is not None:
            try:
                return float(config.get("false_positive_threshold"))
            except Exception:
                pass

        # ENV override takes precedence
        for var in ("AODS_ML_FP_THRESHOLD", "AODS_ML_FALSE_POSITIVE_THRESHOLD"):
            val = os.getenv(var)
            if val is not None:
                try:
                    return float(val)
                except Exception:
                    continue

        # YAML fallback
        try:
            patterns_path = _locate_patterns_yaml()
            if not patterns_path:
                return None
            try:
                import yaml  # type: ignore
            except Exception:
                return None
            data = None
            with patterns_path.open("r", encoding="utf-8", errors="replace") as fh:
                data = yaml.safe_load(fh) or {}
            ml_ctrl = (data or {}).get("ml_filtering_control") or {}
            # Choose profile: default to 'production'
            app_profile = (os.getenv("AODS_APP_PROFILE") or "production").strip().lower()
            if app_profile in ("vulnerable", "test_vulnerable", "qa_vulnerable"):
                thr = ml_ctrl.get("vulnerable_app_ml_filtering_threshold")
            else:
                thr = ml_ctrl.get("production_app_ml_filtering_threshold")
            if thr is None:
                # Fallback to generic value if provided
                thr = ml_ctrl.get("vulnerable_app_ml_filtering_threshold") or ml_ctrl.get(
                    "vulnerable_ml_filtering_threshold"
                )
            if thr is not None:
                return float(thr)
        except Exception:
            return None
        return None

    resolved_fp_threshold = _read_yaml_ml_threshold_default()

    # Convert dict config to MLPipelineConfig
    pipeline_config = MLPipelineConfig(
        enhancement_level=MLEnhancementLevel(config.get("enhancement_level", "standard")),
        enable_false_positive_reduction=config.get("enable_false_positive_reduction", True),
        enable_vulnerability_classification=config.get("enable_vulnerability_classification", True),
        enable_enhanced_detection=config.get("enable_enhanced_detection", False),
        enable_confidence_calibration=config.get("enable_confidence_calibration", True),
        classification_thresholds=config.get("classification_thresholds"),
        classification_abstain_margin=config.get("classification_abstain_margin", 0.05),
        max_processing_time_seconds=config.get("max_processing_time_seconds", 30),
        enable_caching=config.get("enable_caching", True),
        min_confidence_threshold=config.get("min_confidence_threshold", 0.7),
        false_positive_threshold=(
            resolved_fp_threshold if resolved_fp_threshold is not None else config.get("false_positive_threshold", 0.15)
        ),
        model_base_dir=config.get("model_base_dir", "models/unified_ml"),
        cache_dir=config.get("cache_dir", "cache/ml_pipeline"),
    )

    return UnifiedMLPipeline(pipeline_config)


# Export key classes and functions
__all__ = ["UnifiedMLPipeline", "MLPipelineConfig", "MLEnhancementResult", "MLEnhancementLevel", "create_ml_pipeline"]
