"""
Plugin Finding Validator - Track 9 Phase 9.1
=============================================

Validates that plugin findings conform to the canonical PluginFinding structure.
This is the keystone for ensuring structured finding data is preserved throughout
the pipeline and not lost when passing through adapters.

Critical Insight (from Track 9 analysis):
    Forcing v2 plugins through v1 interface loses structured finding data.
    This validator ensures the canonical PluginFinding contract is maintained.
"""

from dataclasses import fields, is_dataclass
from typing import Any, Dict, List, Optional, Tuple

from core.logging_config import get_logger

logger = get_logger(__name__)

# Canonical field definitions for PluginFinding
REQUIRED_FIELDS = {"finding_id", "title", "description", "severity", "confidence"}
OPTIONAL_FIELDS = {
    "file_path",
    "line_number",
    "code_snippet",
    "vulnerability_type",
    "cwe_id",
    "owasp_category",
    "masvs_control",
    "evidence",
    "remediation",
    "references",
    "detected_at",
    "plugin_version",
}
ALL_FIELDS = REQUIRED_FIELDS | OPTIONAL_FIELDS

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class FindingValidationResult:
    """Result of finding validation."""

    def __init__(self):
        self.is_valid: bool = True
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.missing_required: List[str] = []
        self.missing_recommended: List[str] = []
        self.type_mismatches: List[str] = []
        self.value_errors: List[str] = []

    def add_error(self, message: str):
        """Add an error (makes finding invalid)."""
        self.errors.append(message)
        self.is_valid = False

    def add_warning(self, message: str):
        """Add a warning (finding still valid but incomplete)."""
        self.warnings.append(message)

    def __bool__(self):
        return self.is_valid

    def __repr__(self):
        status = "VALID" if self.is_valid else "INVALID"
        return f"FindingValidationResult({status}, errors={len(self.errors)}, warnings={len(self.warnings)})"


class PluginFindingValidator:
    """
    Validates plugin findings against the canonical PluginFinding structure.

    This validator ensures that findings produced by plugins maintain the
    standardized structure needed for consistent processing throughout
    the AODS pipeline (deduplication, ML enrichment, reporting).

    Usage:
        validator = PluginFindingValidator()
        result = validator.validate_finding(finding)
        if not result.is_valid:
            logger.warning(f"Invalid finding: {result.errors}")
    """

    def __init__(self, strict_mode: bool = False):
        """
        Initialize the validator.

        Args:
            strict_mode: If True, missing recommended fields are errors.
                        If False (default), they are warnings.
        """
        self.strict_mode = strict_mode
        self.logger = get_logger(__name__)

        # Recommended fields for quality findings
        self.recommended_fields = {"cwe_id", "remediation", "evidence"}

    def validate_finding(self, finding: Any) -> FindingValidationResult:
        """
        Validate a single finding against the canonical structure.

        Args:
            finding: A PluginFinding dataclass, dict, or object with attributes

        Returns:
            FindingValidationResult with validation status and issues
        """
        result = FindingValidationResult()

        # Convert to dict for uniform processing
        finding_dict = self._to_dict(finding)
        if finding_dict is None:
            result.add_error(f"Cannot convert finding to dict: {type(finding)}")
            return result

        # Check required fields
        self._validate_required_fields(finding_dict, result)

        # Check field types and values
        self._validate_field_types(finding_dict, result)
        self._validate_field_values(finding_dict, result)

        # Check recommended fields (warnings or errors based on strict_mode)
        self._validate_recommended_fields(finding_dict, result)

        return result

    def validate_findings(self, findings: List[Any]) -> Tuple[List[FindingValidationResult], Dict[str, Any]]:
        """
        Validate a list of findings.

        Args:
            findings: List of findings to validate

        Returns:
            Tuple of (list of validation results, summary dict)
        """
        results = []
        valid_count = 0
        invalid_count = 0
        warning_count = 0

        for finding in findings:
            result = self.validate_finding(finding)
            results.append(result)

            if result.is_valid:
                valid_count += 1
                if result.warnings:
                    warning_count += 1
            else:
                invalid_count += 1

        summary = {
            "total": len(findings),
            "valid": valid_count,
            "invalid": invalid_count,
            "with_warnings": warning_count,
            "compliance_rate": valid_count / len(findings) if findings else 1.0,
        }

        return results, summary

    def _to_dict(self, finding: Any) -> Optional[Dict[str, Any]]:
        """Convert finding to dict for uniform processing."""
        if isinstance(finding, dict):
            return finding

        if is_dataclass(finding) and not isinstance(finding, type):
            # Dataclass instance
            return {f.name: getattr(finding, f.name) for f in fields(finding)}

        if hasattr(finding, "__dict__"):
            return finding.__dict__

        # Try common attribute access
        try:
            result = {}
            for field_name in ALL_FIELDS:
                if hasattr(finding, field_name):
                    result[field_name] = getattr(finding, field_name)
            return result if result else None
        except Exception:
            return None

    def _validate_required_fields(self, finding_dict: Dict[str, Any], result: FindingValidationResult):
        """Check that all required fields are present and non-empty."""
        for field_name in REQUIRED_FIELDS:
            if field_name not in finding_dict:
                result.add_error(f"Missing required field: {field_name}")
                result.missing_required.append(field_name)
            elif finding_dict[field_name] is None:
                result.add_error(f"Required field is None: {field_name}")
                result.missing_required.append(field_name)
            elif field_name in ("finding_id", "title", "description", "severity"):
                # String fields should not be empty
                if isinstance(finding_dict[field_name], str) and not finding_dict[field_name].strip():
                    result.add_error(f"Required field is empty: {field_name}")
                    result.missing_required.append(field_name)

    def _validate_field_types(self, finding_dict: Dict[str, Any], result: FindingValidationResult):
        """Validate that fields have correct types."""
        type_expectations = {
            "finding_id": str,
            "title": str,
            "description": str,
            "severity": str,
            "confidence": (int, float),
            "file_path": (str, type(None)),
            "line_number": (int, type(None)),
            "code_snippet": (str, type(None)),
            "vulnerability_type": (str, type(None)),
            "cwe_id": (str, type(None)),
            "owasp_category": (str, type(None)),
            "masvs_control": (str, type(None)),
            "evidence": (dict, type(None)),
            "remediation": (str, type(None)),
            "references": (list, type(None)),
            "detected_at": (int, float, type(None)),
            "plugin_version": (str, type(None)),
        }

        for field_name, expected_types in type_expectations.items():
            if field_name in finding_dict and finding_dict[field_name] is not None:
                value = finding_dict[field_name]
                if not isinstance(value, expected_types):
                    result.add_error(
                        f"Type mismatch for {field_name}: expected {expected_types}, got {type(value).__name__}"
                    )
                    result.type_mismatches.append(field_name)

    def _validate_field_values(self, finding_dict: Dict[str, Any], result: FindingValidationResult):
        """Validate that field values are within acceptable ranges."""
        # Validate severity
        severity = finding_dict.get("severity")
        if severity is not None:
            severity_lower = str(severity).lower()
            if severity_lower not in VALID_SEVERITIES:
                result.add_error(f"Invalid severity '{severity}': must be one of {VALID_SEVERITIES}")
                result.value_errors.append("severity")

        # Validate confidence
        confidence = finding_dict.get("confidence")
        if confidence is not None:
            try:
                conf_value = float(confidence)
                if not (0.0 <= conf_value <= 1.0):
                    result.add_error(f"Confidence {conf_value} out of range: must be 0.0-1.0")
                    result.value_errors.append("confidence")
            except (TypeError, ValueError):
                result.add_error(f"Confidence not numeric: {confidence}")
                result.value_errors.append("confidence")

        # Validate CWE ID format (if present)
        cwe_id = finding_dict.get("cwe_id")
        if cwe_id is not None and cwe_id:
            if not str(cwe_id).upper().startswith("CWE-"):
                result.add_warning(f"CWE ID '{cwe_id}' should start with 'CWE-'")

        # Validate line_number is positive
        line_number = finding_dict.get("line_number")
        if line_number is not None:
            try:
                if int(line_number) < 0:
                    result.add_warning(f"Line number should be positive: {line_number}")
            except (TypeError, ValueError):
                pass  # Already caught by type validation

    def _validate_recommended_fields(self, finding_dict: Dict[str, Any], result: FindingValidationResult):
        """Check recommended fields for quality findings."""
        for field_name in self.recommended_fields:
            value = finding_dict.get(field_name)
            is_missing = (
                value is None
                or (isinstance(value, str) and not value.strip())
                or (isinstance(value, dict) and not value)
            )

            if is_missing:
                result.missing_recommended.append(field_name)
                message = f"Recommended field missing or empty: {field_name}"

                if self.strict_mode:
                    result.add_error(message)
                else:
                    result.add_warning(message)


def validate_plugin_findings(findings: List[Any], strict: bool = False) -> Tuple[bool, Dict[str, Any]]:
    """
    Convenience function to validate a list of findings.

    Args:
        findings: List of findings to validate
        strict: If True, missing recommended fields are errors

    Returns:
        Tuple of (all_valid, summary_dict)
    """
    validator = PluginFindingValidator(strict_mode=strict)
    results, summary = validator.validate_findings(findings)
    all_valid = all(r.is_valid for r in results)
    return all_valid, summary


def normalize_finding_to_dict(finding: Any) -> Optional[Dict[str, Any]]:
    """
    Convert any finding format to canonical dict structure.

    This is useful for adapters that need to convert v1 findings to v2 format.

    Args:
        finding: PluginFinding, dict, or object with finding attributes

    Returns:
        Dict with canonical finding structure, or None if conversion fails
    """
    validator = PluginFindingValidator()
    return validator._to_dict(finding)
