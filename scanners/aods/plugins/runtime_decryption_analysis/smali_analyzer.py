#!/usr/bin/env python3
"""
Smali Decryption Analyzer

Analyzes Smali bytecode for runtime decryption patterns and vulnerabilities.
"""

import re
from typing import Dict, List, Any, Optional
from pathlib import Path

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


class SmaliDecryptionAnalyzer:
    """Analyzes Smali bytecode for decryption patterns and security issues."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Smali decryption analyzer.

        CRITICAL FIX: Added files_analyzed attribute for AODS plugin interface compliance.
        """
        self.config = config or {}
        self.logger = logger

        # CRITICAL FIX: Add files_analyzed attribute for plugin interface compliance
        self.files_analyzed = 0

        # Smali decryption patterns
        self.decryption_patterns = {
            "aes_decrypt": [
                r"invoke-virtual.*Ljavax/crypto/Cipher;->doFinal",
                r'const-string.*"AES"',
                r"invoke-static.*Ljavax/crypto/Cipher;->getInstance",
            ],
            "des_decrypt": [r'const-string.*"DES"', r"invoke-virtual.*Ljavax/crypto/Cipher;->doFinal"],
            "rsa_decrypt": [r'const-string.*"RSA"', r"invoke-virtual.*Ljavax/crypto/Cipher;->doFinal"],
            "base64_decode": [
                r"invoke-static.*Landroid/util/Base64;->decode",
                r"invoke-virtual.*Ljava/util/Base64\$Decoder;->decode",
            ],
            "custom_decryption": [r"invoke-virtual.*decrypt", r"invoke-static.*decrypt", r"xor.*const"],
        }

    def analyze_smali_file(self, smali_file: Path) -> Dict[str, Any]:
        """Analyze a single Smali file for decryption patterns."""
        try:
            with open(smali_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            findings = []

            for pattern_name, patterns in self.decryption_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)

                    for match in matches:
                        line_number = content[: match.start()].count("\n") + 1

                        finding = {
                            "type": "smali_decryption_pattern",
                            "pattern_name": pattern_name,
                            "pattern": pattern,
                            "file": str(smali_file),
                            "line_number": line_number,
                            "matched_text": match.group(),
                            "severity": self._assess_severity(pattern_name),
                            "confidence": self._calculate_confidence(pattern_name, match.group()),
                        }
                        findings.append(finding)

            return {
                "file": str(smali_file),
                "findings": findings,
                "summary": {
                    "total_patterns": len(findings),
                    "unique_pattern_types": len(set(f["pattern_name"] for f in findings)),
                },
            }

        except Exception as e:
            self.logger.error(f"Error analyzing Smali file {smali_file}: {e}")
            return {"file": str(smali_file), "findings": [], "error": str(e)}

    def analyze_smali_directory(self, smali_dir: Path) -> List[Dict[str, Any]]:
        """Analyze all Smali files in a directory."""
        results = []

        if not smali_dir.exists():
            self.logger.warning(f"Smali directory does not exist: {smali_dir}")
            return results

        smali_files = list(smali_dir.rglob("*.smali"))
        self.logger.info(f"Found {len(smali_files)} Smali files to analyze")

        for smali_file in smali_files:
            result = self.analyze_smali_file(smali_file)
            if result["findings"]:  # Only include files with findings
                results.append(result)

        return results

    def _assess_severity(self, pattern_name: str) -> str:
        """Assess severity based on pattern type."""
        severity_map = {
            "custom_decryption": "HIGH",  # Custom crypto is often weak
            "des_decrypt": "HIGH",  # DES is deprecated
            "aes_decrypt": "MEDIUM",  # AES is good but check implementation
            "rsa_decrypt": "MEDIUM",  # RSA depends on usage
            "base64_decode": "LOW",  # Base64 is encoding, not encryption
        }
        return severity_map.get(pattern_name, "MEDIUM")

    def _calculate_confidence(self, pattern_name: str, matched_text: str) -> float:
        """Calculate confidence score for the finding."""
        base_confidence = 0.7

        # Increase confidence for specific patterns
        if "decrypt" in matched_text.lower():
            base_confidence += 0.2
        if "cipher" in matched_text.lower():
            base_confidence += 0.1
        if pattern_name == "custom_decryption" and "xor" in matched_text.lower():
            base_confidence += 0.1

        return min(1.0, base_confidence)

    def generate_analysis_report(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a analysis report."""
        total_files = len(results)
        total_findings = sum(len(result["findings"]) for result in results)

        # Group findings by pattern type
        pattern_summary = {}
        severity_summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for result in results:
            for finding in result["findings"]:
                pattern_name = finding["pattern_name"]
                severity = finding["severity"]

                if pattern_name not in pattern_summary:
                    pattern_summary[pattern_name] = 0
                pattern_summary[pattern_name] += 1

                severity_summary[severity] += 1

        # Calculate risk assessment
        risk_score = severity_summary["HIGH"] * 3 + severity_summary["MEDIUM"] * 2 + severity_summary["LOW"] * 1

        if risk_score == 0:
            risk_level = "NONE"
        elif risk_score <= 5:
            risk_level = "LOW"
        elif risk_score <= 15:
            risk_level = "MEDIUM"
        else:
            risk_level = "HIGH"

        return {
            "summary": {
                "files_analyzed": total_files,
                "total_findings": total_findings,
                "risk_level": risk_level,
                "risk_score": risk_score,
            },
            "pattern_breakdown": pattern_summary,
            "severity_breakdown": severity_summary,
            "recommendations": self._generate_recommendations(pattern_summary, severity_summary),
        }

    def _generate_recommendations(self, pattern_summary: Dict[str, int], severity_summary: Dict[str, int]) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []

        if pattern_summary.get("custom_decryption", 0) > 0:
            recommendations.append("Custom decryption implementations detected. Review for cryptographic weaknesses.")

        if pattern_summary.get("des_decrypt", 0) > 0:
            recommendations.append("DES encryption detected. Migrate to AES-256 or other modern algorithms.")

        if severity_summary["HIGH"] > 0:
            recommendations.append("High-severity cryptographic issues found. Immediate review recommended.")

        if pattern_summary.get("base64_decode", 0) > 5:
            recommendations.append("Excessive Base64 usage detected. Ensure sensitive data is properly encrypted.")

        if not recommendations:
            recommendations.append("No significant cryptographic issues detected in Smali analysis.")

        return recommendations

    def analyze(self, smali_input) -> List[Dict[str, Any]]:
        """
        Standard analyze method for AODS plugin interface compliance.

        CRITICAL FIX: Implements the missing 'analyze' method that was causing
        'SmaliDecryptionAnalyzer' object has no attribute 'analyze' errors.

        BROADER AODS SCOPE CONSIDERATIONS:
        - Provides standardized interface consistent with AODS plugin architecture
        - Supports both directory paths and APKContext objects
        - Integrates with AODS path resolution and error handling systems
        - Updates files_analyzed attribute for interface compliance
        - Maintains compatibility with existing Smali analysis workflows

        Args:
            smali_input: Directory path containing Smali files (string, Path, or APKContext)

        Returns:
            List[Dict[str, Any]]: Analysis results with findings and statistics
        """
        try:
            # CRITICAL FIX: Handle various input types (APKContext, Path, string)
            if hasattr(smali_input, "smali_dir"):
                # APKContext with smali_dir attribute
                smali_dir = Path(str(smali_input.smali_dir))
            elif hasattr(smali_input, "decompiled_source_dir"):
                # APKContext with decompiled source dir - look for smali subdirectory
                base_dir = Path(str(smali_input.decompiled_source_dir))
                smali_dir = base_dir / "smali" if (base_dir / "smali").exists() else base_dir
            elif hasattr(smali_input, "apk_path"):
                # APKContext - derive smali directory from APK path
                apk_path = Path(str(smali_input.apk_path))
                smali_dir = apk_path.parent / f"{apk_path.stem}_smali"
            else:
                # String or Path object
                smali_dir = Path(str(smali_input))

            self.logger.info(f"Starting Smali decryption analysis in: {smali_dir}")

            # Perform the analysis using existing directory analysis method
            results = self.analyze_smali_directory(smali_dir)

            # Update files_analyzed count for interface compliance
            self.files_analyzed = len([r for r in results if r.get("findings")])

            self.logger.info(
                f"Smali analysis completed: {len(results)} files analyzed, "
                f"{sum(len(r.get('findings', [])) for r in results)} findings"
            )

            return results

        except Exception as e:
            self.logger.error(f"Smali analyze method failed: {e}")
            # Return empty result structure for compatibility
            return [
                {
                    "file": "analysis_error",
                    "findings": [],
                    "error": str(e),
                    "summary": {"total_patterns": 0, "unique_pattern_types": 0},
                }
            ]
