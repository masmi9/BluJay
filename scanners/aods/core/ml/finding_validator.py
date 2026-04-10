#!/usr/bin/env python3
"""
ML-Based Finding Validator

Strategy B: Validates existing plugin findings by analyzing the associated
source code with ML models. Improves confidence scores and reduces false positives.

Integration Point: After VulnerabilityClassifier.classify_all_findings()
Location: dyna.py line 3341

Usage:
    from core.ml.finding_validator import FindingValidator

    validator = FindingValidator()
    enhanced_findings = validator.validate_findings(findings, apk_ctx)
"""

import logging
import re
import sys
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass

PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result from validating a finding."""

    original_confidence: float
    validated_confidence: float
    ml_confidence: float
    is_validated: bool
    evidence_found: bool
    validation_notes: str
    code_context: str = ""


class FindingValidator:
    """
    Validates vulnerability findings using ML models.

    This class analyzes the source code associated with findings to:
    1. Confirm the vulnerability exists (reduce false positives)
    2. Adjust confidence based on code evidence
    3. Add code context and explanations

    Integration:
        validator = FindingValidator()
        enhanced_findings = validator.validate_findings(findings, apk_ctx)
    """

    # Weight for combining classifier confidence with ML confidence
    CLASSIFIER_WEIGHT = 0.4
    ML_WEIGHT = 0.6

    # Confidence adjustment thresholds
    HIGH_CONFIDENCE_BOOST = 0.1  # Boost when ML strongly confirms
    LOW_CONFIDENCE_PENALTY = -0.15  # Penalty when ML doesn't confirm

    def __init__(self):
        self.scorer = None
        self._initialized = False
        self._source_cache = {}

    def _ensure_initialized(self) -> bool:
        """Lazy initialization of the scorer."""
        if self._initialized:
            return self.scorer is not None

        try:
            from core.ml.vulnerability_scorer import VulnerabilityScorer

            self.scorer = VulnerabilityScorer()
            self._initialized = True
            logger.info("Finding Validator initialized with VulnerabilityScorer")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Finding Validator: {e}")
            self._initialized = True
            return False

    def validate_findings(self, classification_results: Dict[str, Any], apk_ctx=None) -> Dict[str, Any]:
        """
        Validate all findings in classification results.

        Args:
            classification_results: Output from VulnerabilityClassifier.classify_all_findings()
            apk_ctx: Optional APKContext for source code access

        Returns:
            Enhanced classification results with validated confidence scores
        """
        if not self._ensure_initialized():
            logger.warning("Validator not initialized, returning original results")
            return classification_results

        # Load source files if apk_ctx provided
        source_dir = None
        if apk_ctx:
            source_dir = self._get_source_directory(apk_ctx)
            if source_dir:
                self._cache_source_files(source_dir)

        # Validate each vulnerability finding
        vulnerabilities = classification_results.get("vulnerabilities", [])
        validated_vulns = []

        for vuln in vulnerabilities:
            validated = self._validate_single_finding(vuln, source_dir)
            validated_vulns.append(validated)

        # Update statistics
        classification_results["vulnerabilities"] = validated_vulns
        classification_results["metadata"] = classification_results.get("metadata", {})
        classification_results["metadata"]["ml_validation"] = {
            "total_validated": len(validated_vulns),
            "confidence_increased": sum(
                1 for v in validated_vulns if v.get("ml_validation", {}).get("confidence_increased", False)
            ),
            "confidence_decreased": sum(
                1 for v in validated_vulns if v.get("ml_validation", {}).get("confidence_decreased", False)
            ),
        }

        return classification_results

    def _validate_single_finding(self, finding: Dict[str, Any], source_dir: Optional[Path]) -> Dict[str, Any]:
        """Validate a single finding."""
        # Get original confidence
        original_confidence = finding.get("classification", {}).get("confidence", 0.5)

        # Try to find associated source code
        code_context = self._find_code_context(finding, source_dir)

        if not code_context:
            # No code found - keep original confidence but mark as unvalidated
            finding["ml_validation"] = {
                "validated": False,
                "reason": "No associated source code found",
                "original_confidence": original_confidence,
                "validated_confidence": original_confidence,
            }
            return finding

        # Score the code with ML model
        try:
            result = self.scorer.score(code_context)

            # Calculate validated confidence
            validation_result = self._calculate_validated_confidence(
                original_confidence, result.confidence, result.is_vulnerable
            )

            finding["ml_validation"] = {
                "validated": True,
                "ml_vulnerable": result.is_vulnerable,
                "ml_confidence": result.confidence,
                "ml_types": result.vulnerability_types,
                "ml_explanation": result.explanation,
                "original_confidence": original_confidence,
                "validated_confidence": validation_result.validated_confidence,
                "confidence_increased": validation_result.validated_confidence > original_confidence,
                "confidence_decreased": validation_result.validated_confidence < original_confidence,
                "notes": validation_result.validation_notes,
            }

            # Update the finding's confidence
            if "classification" in finding:
                finding["classification"]["original_confidence"] = original_confidence
                finding["classification"]["confidence"] = validation_result.validated_confidence
                finding["classification"]["ml_validated"] = True

        except Exception as e:
            logger.debug(f"Error validating finding: {e}")
            finding["ml_validation"] = {
                "validated": False,
                "reason": f"Validation error: {str(e)}",
                "original_confidence": original_confidence,
                "validated_confidence": original_confidence,
            }

        return finding

    def _calculate_validated_confidence(
        self, classifier_conf: float, ml_conf: float, ml_vulnerable: bool
    ) -> ValidationResult:
        """Calculate the validated confidence score."""
        notes = []

        if ml_vulnerable:
            # ML confirms vulnerability
            if ml_conf > 0.8:
                # Strong ML confirmation - boost confidence
                validated = min(
                    1.0,
                    (classifier_conf * self.CLASSIFIER_WEIGHT + ml_conf * self.ML_WEIGHT + self.HIGH_CONFIDENCE_BOOST),
                )
                notes.append(f"ML strongly confirms vulnerability (conf: {ml_conf:.2f})")
            else:
                # Moderate ML confirmation - weighted average
                validated = classifier_conf * self.CLASSIFIER_WEIGHT + ml_conf * self.ML_WEIGHT
                notes.append(f"ML confirms vulnerability (conf: {ml_conf:.2f})")
        else:
            # ML doesn't find vulnerability
            if ml_conf < 0.3:
                # ML strongly disagrees - significant penalty
                validated = max(0.1, classifier_conf + self.LOW_CONFIDENCE_PENALTY)
                notes.append(f"ML does not confirm vulnerability (conf: {ml_conf:.2f})")
            else:
                # ML uncertain - slight penalty
                validated = max(0.2, classifier_conf * 0.8)
                notes.append(f"ML uncertain about vulnerability (conf: {ml_conf:.2f})")

        return ValidationResult(
            original_confidence=classifier_conf,
            validated_confidence=validated,
            ml_confidence=ml_conf,
            is_validated=True,
            evidence_found=ml_vulnerable,
            validation_notes="; ".join(notes),
        )

    def _find_code_context(self, finding: Dict[str, Any], source_dir: Optional[Path]) -> Optional[str]:
        """Find source code associated with a finding."""
        # Try to get code from finding itself
        evidence = finding.get("classification", {}).get("evidence", [])
        if evidence:
            code_evidence = [e for e in evidence if len(e) > 50 and "{" in e]
            if code_evidence:
                return code_evidence[0]

        # Try content field
        content = finding.get("content", "")
        if content and len(content) > 100:
            return content[:5000]  # Limit size

        # Try to find file from finding metadata
        file_path = finding.get("file_path") or finding.get("location", {}).get("file")
        if file_path and source_dir:
            return self._read_source_file(file_path, source_dir)

        # Try to extract from title/description
        finding.get("title", "")
        description = finding.get("description", finding.get("content", ""))

        # Look for code-like patterns
        code_pattern = r"```[\s\S]*?```|`[^`]+`"
        matches = re.findall(code_pattern, description)
        if matches:
            return "\n".join(matches)

        return None

    def _read_source_file(self, file_path: str, source_dir: Path) -> Optional[str]:
        """Read source file content."""
        # Check cache first
        if file_path in self._source_cache:
            return self._source_cache[file_path]

        # Try exact path
        full_path = source_dir / file_path
        if full_path.exists():
            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore")
                self._source_cache[file_path] = content
                return content
            except Exception:
                pass

        # Try finding file by name
        file_name = Path(file_path).name
        for cached_path, content in self._source_cache.items():
            if Path(cached_path).name == file_name:
                return content

        return None

    def _cache_source_files(self, source_dir: Path, max_files: int = 200):
        """Pre-cache source files for faster lookup."""
        if self._source_cache:
            return  # Already cached

        java_files = list(source_dir.rglob("*.java"))[:max_files]
        kotlin_files = list(source_dir.rglob("*.kt"))[: max_files // 2]

        for f in java_files + kotlin_files:
            try:
                rel_path = str(f.relative_to(source_dir))
                self._source_cache[rel_path] = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass

        logger.info(f"Cached {len(self._source_cache)} source files for validation")

    def _get_source_directory(self, apk_ctx) -> Optional[Path]:
        """Get the decompiled source directory from APK context."""
        if hasattr(apk_ctx, "jadx_output_dir"):
            jadx_dir = Path(apk_ctx.jadx_output_dir)
            sources_dir = jadx_dir / "sources"
            if sources_dir.exists():
                return sources_dir
            if jadx_dir.exists():
                return jadx_dir

        if hasattr(apk_ctx, "decompiled_apk_dir"):
            decompiled_dir = Path(apk_ctx.decompiled_apk_dir)
            if decompiled_dir.exists():
                return decompiled_dir

        return None

    def get_validation_summary(self, classification_results: Dict[str, Any]) -> Dict[str, Any]:
        """Get summary of validation results."""
        vulns = classification_results.get("vulnerabilities", [])

        validated = [v for v in vulns if v.get("ml_validation", {}).get("validated", False)]
        increased = [v for v in validated if v.get("ml_validation", {}).get("confidence_increased", False)]
        decreased = [v for v in validated if v.get("ml_validation", {}).get("confidence_decreased", False)]

        return {
            "total_findings": len(vulns),
            "ml_validated": len(validated),
            "confidence_increased": len(increased),
            "confidence_decreased": len(decreased),
            "unvalidated": len(vulns) - len(validated),
            "avg_original_confidence": sum(
                v.get("ml_validation", {}).get("original_confidence", 0.5) for v in validated
            )
            / max(len(validated), 1),
            "avg_validated_confidence": sum(
                v.get("ml_validation", {}).get("validated_confidence", 0.5) for v in validated
            )
            / max(len(validated), 1),
        }


# Convenience function for integration
def validate_classification_results(classification_results: Dict[str, Any], apk_ctx=None) -> Dict[str, Any]:
    """
    Validate classification results with ML models.

    This is the main integration function to be called from dyna.py.

    Args:
        classification_results: Output from VulnerabilityClassifier
        apk_ctx: Optional APKContext for source code access

    Returns:
        Enhanced classification results with ML validation
    """
    validator = FindingValidator()
    return validator.validate_findings(classification_results, apk_ctx)


if __name__ == "__main__":
    # Test with mock data
    logging.basicConfig(level=logging.INFO)

    mock_findings = {
        "vulnerabilities": [
            {
                "title": "SQL Injection Vulnerability",
                "content": """
                public void query(String userId) {
                    String sql = "SELECT * FROM users WHERE id = " + userId;
                    db.rawQuery(sql, null);
                }
                """,
                "classification": {
                    "is_vulnerability": True,
                    "severity": "HIGH",
                    "confidence": 0.7,
                    "category": "Injection",
                },
            },
            {
                "title": "Hardcoded API Key",
                "content": """
                public class Config {
                    private static final String API_KEY = "sk-12345abcdef";
                }
                """,
                "classification": {
                    "is_vulnerability": True,
                    "severity": "HIGH",
                    "confidence": 0.6,
                    "category": "Secrets",
                },
            },
        ],
        "metadata": {},
    }

    _logger = logging.getLogger(__name__)
    _logger.info("Testing Finding Validator")

    enhanced = validate_classification_results(mock_findings)

    for vuln in enhanced["vulnerabilities"]:
        val = vuln.get("ml_validation", {})
        _logger.info(
            "Validation result",
            title=vuln["title"],
            original_confidence=f"{val.get('original_confidence', 0):.2f}",
            validated_confidence=f"{val.get('validated_confidence', 0):.2f}",
            ml_confirms=val.get("ml_vulnerable", "N/A"),
            notes=val.get("notes", "N/A"),
        )

    validator = FindingValidator()
    summary = validator.get_validation_summary(enhanced)
    _logger.info("Validation summary", **summary)
