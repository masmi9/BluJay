"""High-level APK analysis orchestrator."""

import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Union

from ._types import APKValidationResult
from .validator import APKValidator
from .parser import APKParser
from .manifest_parser import ManifestParser

logger = logging.getLogger(__name__)


class APKAnalyzer:
    """
    High-level APK analysis orchestrator for full APK security assessment.

    Provides simplified access to full APK analysis including validation,
    manifest parsing, certificate analysis, and security assessment. Acts as the
    main entry point for APK analysis in the shared infrastructure.
    """

    def __init__(self):
        """Initialize the APK analyzer."""
        self.logger = logging.getLogger(__name__)
        self.validator = APKValidator()
        self.parser = APKParser()
        self.manifest_parser = None  # Will be initialized when needed

        self.logger.info("APKAnalyzer initialized with analysis capabilities")

    def analyze(
        self,
        apk_path: Union[str, Path],
        include_manifest: bool = True,
        include_certificates: bool = True,
        include_security_analysis: bool = True,
        include_native_libraries: bool = True,
    ) -> Dict[str, Any]:
        """
        Perform full APK analysis with configurable components.

        Args:
            apk_path: Path to APK file
            include_manifest: Include detailed manifest analysis
            include_certificates: Include certificate analysis
            include_security_analysis: Include security assessment
            include_native_libraries: Include native library analysis

        Returns:
            Dict[str, Any]: Analysis results
        """
        apk_path = Path(apk_path)

        try:
            self.logger.info(f"Starting analysis of {apk_path.name}")
            start_time = time.time()

            result = {
                "apk_path": str(apk_path),
                "analysis_timestamp": time.time(),
                "analysis_components": {
                    "validation": True,
                    "basic_analysis": True,
                    "manifest_analysis": include_manifest,
                    "certificate_analysis": include_certificates,
                    "security_analysis": include_security_analysis,
                    "native_library_analysis": include_native_libraries,
                },
            }

            # Step 1: APK Validation
            validation_result = self.validator.validate_apk_structure(apk_path)
            result["validation"] = {
                "result": validation_result.value,
                "is_valid": validation_result == APKValidationResult.VALID,
            }

            if validation_result != APKValidationResult.VALID:
                self.logger.warning(f"APK validation failed: {validation_result.value}")
                result["analysis_time"] = time.time() - start_time
                return result

            # Step 2: Basic APK Analysis
            apk_analysis = self.parser.parse_apk(
                apk_path,
                extract_details=True,
                validate_signatures=include_certificates,
                analyze_native_libs=include_native_libraries,
            )

            result["basic_analysis"] = {
                "metadata": apk_analysis.metadata.to_dict() if apk_analysis.metadata else None,
                "permissions": [p.to_dict() for p in apk_analysis.permissions],
                "components": [c.to_dict() for c in apk_analysis.components],
                "dex_files": apk_analysis.dex_files,
                "assets": apk_analysis.assets[:20],  # Limit to first 20
                "resources": apk_analysis.resources[:20],  # Limit to first 20
            }

            if include_certificates:
                result["certificates"] = [cert.to_dict() for cert in apk_analysis.certificates]

            if include_native_libraries:
                result["native_libraries"] = [lib.to_dict() for lib in apk_analysis.native_libraries]

            # Step 3: Enhanced Manifest Analysis
            if include_manifest:
                if not self.manifest_parser:
                    self.manifest_parser = ManifestParser()

                manifest_analysis = self.manifest_parser.parse_manifest(apk_path)
                result["manifest_analysis"] = manifest_analysis

            # Step 4: Security Analysis
            if include_security_analysis:
                security_analysis = self._perform_security_analysis(result)
                result["security_analysis"] = security_analysis

            result["analysis_time"] = time.time() - start_time
            self.logger.info(f"APK analysis completed in {result['analysis_time']:.2f}s")

            return result

        except Exception as e:
            self.logger.error(f"APK analysis failed: {e}")
            return {
                "apk_path": str(apk_path),
                "analysis_timestamp": time.time(),
                "error": str(e),
                "analysis_time": time.time() - start_time if "start_time" in locals() else 0,
            }

    def quick_analyze(self, apk_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Perform quick APK analysis with essential information only.

        Args:
            apk_path: Path to APK file

        Returns:
            Dict[str, Any]: Essential analysis results
        """
        return self.analyze(
            apk_path,
            include_manifest=False,
            include_certificates=False,
            include_security_analysis=False,
            include_native_libraries=False,
        )

    def security_analyze(self, apk_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Perform security-focused APK analysis.

        Args:
            apk_path: Path to APK file

        Returns:
            Dict[str, Any]: Security-focused analysis results
        """
        return self.analyze(
            apk_path,
            include_manifest=True,
            include_certificates=True,
            include_security_analysis=True,
            include_native_libraries=False,
        )

    def validate_only(self, apk_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Validate APK structure only.

        Args:
            apk_path: Path to APK file

        Returns:
            Dict[str, Any]: Validation results
        """
        try:
            validation_result = self.validator.validate_apk_structure(Path(apk_path))
            return {
                "apk_path": str(apk_path),
                "validation_result": validation_result.value,
                "is_valid": validation_result == APKValidationResult.VALID,
                "validation_details": self.validator.get_validation_details(apk_path),
            }
        except Exception as e:
            return {"apk_path": str(apk_path), "validation_result": "error", "is_valid": False, "error": str(e)}

    def _perform_security_analysis(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform security analysis on APK data."""
        security_analysis = {
            "overall_risk_score": 0,
            "risk_level": "LOW",
            "security_issues": [],
            "recommendations": [],
            "analysis_summary": {},
        }

        try:
            # Analyze basic analysis data
            basic_analysis = analysis_data.get("basic_analysis", {})

            # Permission analysis
            permissions = basic_analysis.get("permissions", [])
            perm_score = self._analyze_permissions_risk(permissions)
            security_analysis["overall_risk_score"] += perm_score

            # Component analysis
            components = basic_analysis.get("components", [])
            comp_score = self._analyze_components_risk(components)
            security_analysis["overall_risk_score"] += comp_score

            # Certificate analysis
            if "certificates" in analysis_data:
                cert_score = self._analyze_certificates_risk(analysis_data["certificates"])
                security_analysis["overall_risk_score"] += cert_score

            # Manifest analysis
            if "manifest_analysis" in analysis_data:
                manifest_data = analysis_data["manifest_analysis"]
                if manifest_data and "security_analysis" in manifest_data:
                    manifest_score = manifest_data["security_analysis"].get("risk_score", 0)
                    security_analysis["overall_risk_score"] += manifest_score * 0.3  # Weight factor

                    # Add manifest issues
                    manifest_issues = manifest_data["security_analysis"].get("security_issues", [])
                    security_analysis["security_issues"].extend(manifest_issues)

                    # Add manifest recommendations
                    manifest_recs = manifest_data["security_analysis"].get("recommendations", [])
                    security_analysis["recommendations"].extend(manifest_recs)

            # Determine risk level
            total_score = security_analysis["overall_risk_score"]
            if total_score >= 70:
                security_analysis["risk_level"] = "CRITICAL"
            elif total_score >= 50:
                security_analysis["risk_level"] = "HIGH"
            elif total_score >= 25:
                security_analysis["risk_level"] = "MEDIUM"
            else:
                security_analysis["risk_level"] = "LOW"

            # Generate summary
            security_analysis["analysis_summary"] = {
                "total_permissions": len(permissions),
                "dangerous_permissions": len([p for p in permissions if p.get("is_dangerous", False)]),
                "total_components": len(components),
                "exported_components": len([c for c in components if c.get("exported", False)]),
                "certificate_count": len(analysis_data.get("certificates", [])),
                "has_manifest_analysis": "manifest_analysis" in analysis_data,
            }

            return security_analysis

        except Exception as e:
            self.logger.error(f"Security analysis failed: {e}")
            security_analysis["error"] = str(e)
            return security_analysis

    def _analyze_permissions_risk(self, permissions: List[Dict[str, Any]]) -> int:
        """Analyze permissions for security risk."""
        risk_score = 0
        dangerous_count = 0

        for perm in permissions:
            if perm.get("is_dangerous", False):
                dangerous_count += 1
                risk_score += 8

        # Additional risk for excessive permissions
        if dangerous_count > 10:
            risk_score += 15
        elif dangerous_count > 5:
            risk_score += 8

        return min(risk_score, 50)  # Cap at 50

    def _analyze_components_risk(self, components: List[Dict[str, Any]]) -> int:
        """Analyze components for security risk."""
        risk_score = 0
        exported_count = 0

        for comp in components:
            if comp.get("exported", False):
                exported_count += 1
                risk_score += 3

                # Higher risk if no permissions
                if not comp.get("permissions"):
                    risk_score += 5

        return min(risk_score, 30)  # Cap at 30

    def _analyze_certificates_risk(self, certificates: List[Dict[str, Any]]) -> int:
        """Analyze certificates for security risk."""
        risk_score = 0

        for cert in certificates:
            # Check for weak signature algorithms
            sig_alg = cert.get("signature_algorithm", "").lower()
            if "md5" in sig_alg or "sha1" in sig_alg:
                risk_score += 15

            # Check for debug certificates
            subject = cert.get("subject", "").lower()
            if "debug" in subject or "test" in subject:
                risk_score += 20

        return min(risk_score, 25)  # Cap at 25
