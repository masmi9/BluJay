#!/usr/bin/env python3
"""
Enhanced Smali Analyzer
========================

Enhancement module for the existing anti_tampering_analysis plugin that adds
full smali bytecode analysis capabilities. This module extends
the existing plugin without duplicating functionality.

Features:
- Advanced smali bytecode pattern analysis
- Method modification detection
- Control flow analysis
- Security bypass pattern detection
- Code injection detection
- Return value manipulation detection
"""

import logging
import re
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class SmaliSecurityIssue:
    """Smali code security issue."""

    issue_type: str
    severity: str
    file_path: str
    line_number: int
    method_name: str
    class_name: str
    description: str
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.8


class EnhancedSmaliAnalyzer:
    """Enhanced smali bytecode analyzer for anti-tampering analysis."""

    def __init__(self):
        """Initialize enhanced smali analyzer."""
        self.logger = logger

        # Generic suspicious patterns for binary patching detection
        self.suspicious_patterns = {
            # Return value manipulation patterns
            "return_true_injection": {
                "pattern": r"const/4\s+v\d+,\s+0x1\s+return\s+v\d+",
                "description": "Hardcoded return true injection (binary patching indicator)",
                "severity": "HIGH",
                "confidence": 0.9,
            },
            "return_false_injection": {
                "pattern": r"const/4\s+v\d+,\s+0x0\s+return\s+v\d+",
                "description": "Hardcoded return false injection (binary patching indicator)",
                "severity": "HIGH",
                "confidence": 0.9,
            },
            # Security method bypass patterns (generic)
            "security_method_bypass": {
                "pattern": r"\.method.*(?:check|verify|validate|is[A-Z]\w*).*\n(?:.*\n)*?\s*const/4\s+v\d+,\s+0x1\s+return\s+v\d+",  # noqa: E501
                "description": "Security method bypass detected (generic pattern)",
                "severity": "HIGH",
                "confidence": 0.85,
            },
            # Exception handling bypass
            "exception_bypass": {
                "pattern": r"\.catch.*Exception.*\n(?:.*\n)*?\s*const/4\s+v\d+,\s+0x1\s+return\s+v\d+",
                "description": "Exception handling bypass",
                "severity": "MEDIUM",
                "confidence": 0.8,
            },
            # Conditional bypass patterns
            "if_bypass": {
                "pattern": r"if-(?:eq|ne|lt|le|gt|ge)\s+.*\n(?:.*\n)*?\s*goto\s+:\w+\s*\n\s*const/4\s+v\d+,\s+0x1",
                "description": "Conditional logic bypass",
                "severity": "MEDIUM",
                "confidence": 0.7,
            },
            # Suspicious string modifications
            "string_modification": {
                "pattern": r'const-string\s+v\d+,\s+"[^"]*(?:bypass|crack|patch|hack|mod)[^"]*"',
                "description": "Suspicious string indicating modification",
                "severity": "MEDIUM",
                "confidence": 0.8,
            },
            # Native method modifications
            "native_bypass": {
                "pattern": r"\.method.*native.*\n(?:.*\n)*?\s*const/4\s+v\d+,\s+0x1\s+return\s+v\d+",
                "description": "Native method bypass",
                "severity": "HIGH",
                "confidence": 0.9,
            },
            # Anti-debugging bypass (AndroGOAT style)
            "debug_bypass": {
                "pattern": r"\.method.*(?:isDebuggable|isDebuggerConnected).*\n(?:.*\n)*?\s*const/4\s+v\d+,\s+0x0\s+return\s+v\d+",  # noqa: E501
                "description": "Anti-debugging bypass",
                "severity": "HIGH",
                "confidence": 0.9,
            },
            # Signature verification bypass
            "signature_bypass": {
                "pattern": r"\.method.*(?:checkSignature|verifySignature).*\n(?:.*\n)*?\s*const/4\s+v\d+,\s+0x1\s+return\s+v\d+",  # noqa: E501
                "description": "Signature verification bypass",
                "severity": "HIGH",
                "confidence": 0.95,
            },
            # Emulator detection bypass (generic pattern)
            "emulator_bypass": {
                "pattern": r"\.method.*(?:isEmulator|detectEmulator).*\n(?:.*\n)*?\s*const/4\s+v\d+,\s+0x0\s+return\s+v\d+",  # noqa: E501
                "description": "Emulator detection bypass",
                "severity": "MEDIUM",
                "confidence": 0.8,
            },
        }

        # Generic security-related method patterns (organic detection)
        self.security_method_patterns = [
            r"is[A-Z]\w*",  # isAdmin, isRoot, isDebug, etc.
            r"check[A-Z]\w*",  # checkAdmin, checkRoot, etc.
            r"verify[A-Z]\w*",  # verifyLicense, verifySignature, etc.
            r"validate[A-Z]\w*",  # validateAdmin, validateLicense, etc.
            r"detect[A-Z]\w*",  # detectRoot, detectEmulator, etc.
        ]

    def enhance_tampering_analysis(self, apk_ctx) -> Dict[str, Any]:
        """
        Enhance existing anti-tampering analysis with advanced smali analysis.

        Args:
            apk_ctx: APK context containing smali files

        Returns:
            Dictionary containing enhanced smali analysis results
        """
        try:
            self.logger.info("Starting enhanced smali analysis for anti-tampering")

            # Find smali files
            smali_files = self._find_smali_files(apk_ctx)

            if not smali_files:
                return {"smali_analysis_enabled": False, "reason": "No smali files found", "enhanced_findings": []}

            # Analyze smali files
            analysis_results = self._analyze_smali_files(smali_files)

            # Generate enhanced findings
            enhanced_findings = self._generate_enhanced_findings(analysis_results)

            results = {
                "smali_analysis_enabled": True,
                "total_files_analyzed": len(smali_files),
                "total_methods_analyzed": analysis_results.get("total_methods", 0),
                "security_issues_found": len(enhanced_findings),
                "high_severity_issues": len([f for f in enhanced_findings if f.severity == "HIGH"]),
                "medium_severity_issues": len([f for f in enhanced_findings if f.severity == "MEDIUM"]),
                "low_severity_issues": len([f for f in enhanced_findings if f.severity == "LOW"]),
                "suspicious_patterns": analysis_results.get("suspicious_patterns", {}),
                "enhanced_findings": [self._finding_to_dict(f) for f in enhanced_findings],
            }

            self.logger.info(f"Enhanced smali analysis completed - {len(enhanced_findings)} security issues found")

            return results

        except Exception as e:
            self.logger.error(f"Enhanced smali analysis failed: {e}")
            return {"smali_analysis_enabled": False, "error": str(e), "enhanced_findings": []}

    def _find_smali_files(self, apk_ctx) -> List[Path]:
        """Find smali files in APK context."""
        smali_files = []

        try:
            # Try to get smali directory from APK context
            if hasattr(apk_ctx, "smali_dir") and apk_ctx.smali_dir:
                smali_dir = Path(apk_ctx.smali_dir)
                if smali_dir.exists():
                    smali_files.extend(smali_dir.rglob("*.smali"))

            # Try to find smali files relative to APK path
            if hasattr(apk_ctx, "apk_path") and apk_ctx.apk_path:
                apk_path = Path(apk_ctx.apk_path)

                # Look for smali directories
                possible_dirs = [
                    apk_path.parent / "smali",
                    apk_path.parent / "smali_classes2",
                    apk_path.parent / "smali_classes3",
                    apk_path.with_suffix("") / "smali",
                    apk_path.with_suffix("") / "smali_classes2",
                ]

                for smali_dir in possible_dirs:
                    if smali_dir.exists():
                        smali_files.extend(smali_dir.rglob("*.smali"))

            # Remove duplicates
            smali_files = list(set(smali_files))

            self.logger.info(f"Found {len(smali_files)} smali files for enhanced analysis")

        except Exception as e:
            self.logger.error(f"Failed to find smali files: {e}")

        return smali_files

    def _analyze_smali_files(self, smali_files: List[Path]) -> Dict[str, Any]:
        """Analyze list of smali files for security issues."""
        results = {"total_methods": 0, "suspicious_patterns": {}, "security_issues": []}

        for smali_file in smali_files[:50]:  # Limit for performance
            try:
                file_results = self._analyze_single_smali_file(smali_file)

                # Merge results
                results["total_methods"] += file_results.get("total_methods", 0)
                results["security_issues"].extend(file_results.get("security_issues", []))

                # Update pattern counts
                for pattern, count in file_results.get("suspicious_patterns", {}).items():
                    results["suspicious_patterns"][pattern] = results["suspicious_patterns"].get(pattern, 0) + count

            except Exception as e:
                self.logger.warning(f"Failed to analyze smali file {smali_file}: {e}")

        return results

    def _analyze_single_smali_file(self, smali_file: Path) -> Dict[str, Any]:
        """Analyze a single smali file for security issues."""
        results = {"total_methods": 0, "suspicious_patterns": {}, "security_issues": []}

        try:
            content = smali_file.read_text(encoding="utf-8", errors="ignore")

            # Extract class name
            class_match = re.search(r"\.class.*?L([^;]+);", content)
            class_name = class_match.group(1).replace("/", ".") if class_match else "Unknown"

            # Find methods
            methods = self._extract_methods(content)
            results["total_methods"] = len(methods)

            # Analyze each method
            for method_name, method_content, line_start in methods:
                method_issues = self._analyze_method_security(
                    method_content, method_name, class_name, str(smali_file), line_start
                )
                results["security_issues"].extend(method_issues)

            # Check for suspicious patterns in entire file
            file_issues = self._check_file_patterns(content, class_name, str(smali_file))
            results["security_issues"].extend(file_issues)

            # Count pattern occurrences
            for pattern_name, pattern_info in self.suspicious_patterns.items():
                matches = re.findall(pattern_info["pattern"], content, re.MULTILINE | re.IGNORECASE)
                if matches:
                    results["suspicious_patterns"][pattern_name] = len(matches)

        except Exception as e:
            self.logger.error(f"Failed to analyze smali file {smali_file}: {e}")

        return results

    def _extract_methods(self, content: str) -> List[Tuple[str, str, int]]:
        """Extract methods from smali content."""
        methods = []

        # Find all method definitions
        method_pattern = r"\.method\s+([^{]+?)\n(.*?)\.end method"
        matches = re.finditer(method_pattern, content, re.DOTALL)

        for match in matches:
            method_signature = match.group(1).strip()
            method_content = match.group(2)

            # Extract method name
            name_match = re.search(r"(\w+)\s*\(", method_signature)
            method_name = name_match.group(1) if name_match else "unknown"

            # Calculate line number
            line_start = content[: match.start()].count("\n") + 1

            methods.append((method_name, method_content, line_start))

        return methods

    def _analyze_method_security(
        self, method_content: str, method_name: str, class_name: str, file_path: str, line_start: int
    ) -> List[SmaliSecurityIssue]:
        """Analyze individual method for security issues."""
        issues = []

        # Check if this is a security-related method using organic patterns
        is_security_method = any(re.match(pattern, method_name) for pattern in self.security_method_patterns)

        # Look for suspicious return patterns in security methods
        if is_security_method:
            # Check for hardcoded return values (generic binary patching patterns)
            if re.search(r"const/4\s+v\d+,\s+0x1\s+return\s+v\d+", method_content):
                issues.append(
                    SmaliSecurityIssue(
                        issue_type="HARDCODED_RETURN_TRUE",
                        severity="HIGH",
                        file_path=file_path,
                        line_number=line_start,
                        method_name=method_name,
                        class_name=class_name,
                        description=f"Security method '{method_name}' has hardcoded return true (binary patching indicator)",  # noqa: E501
                        evidence=[f"Method: {method_name}", "Pattern: const/4 v*, 0x1; return v*"],
                        confidence=0.95,
                    )
                )

            if re.search(r"const/4\s+v\d+,\s+0x0\s+return\s+v\d+", method_content):
                issues.append(
                    SmaliSecurityIssue(
                        issue_type="HARDCODED_RETURN_FALSE",
                        severity="HIGH",
                        file_path=file_path,
                        line_number=line_start,
                        method_name=method_name,
                        class_name=class_name,
                        description=f"Security method '{method_name}' has hardcoded return false (binary patching indicator)",  # noqa: E501
                        evidence=[f"Method: {method_name}", "Pattern: const/4 v*, 0x0; return v*"],
                        confidence=0.95,
                    )
                )

        # Check for suspicious control flow modifications
        if self._has_suspicious_control_flow(method_content):
            issues.append(
                SmaliSecurityIssue(
                    issue_type="SUSPICIOUS_CONTROL_FLOW",
                    severity="MEDIUM",
                    file_path=file_path,
                    line_number=line_start,
                    method_name=method_name,
                    class_name=class_name,
                    description=f"Method '{method_name}' has suspicious control flow modifications",
                    evidence=[f"Method: {method_name}"],
                    confidence=0.7,
                )
            )

        # Check for exception handling bypass
        if self._has_exception_bypass(method_content):
            issues.append(
                SmaliSecurityIssue(
                    issue_type="EXCEPTION_BYPASS",
                    severity="MEDIUM",
                    file_path=file_path,
                    line_number=line_start,
                    method_name=method_name,
                    class_name=class_name,
                    description=f"Method '{method_name}' has exception handling bypass",
                    evidence=[f"Method: {method_name}"],
                    confidence=0.8,
                )
            )

        return issues

    def _check_file_patterns(self, content: str, class_name: str, file_path: str) -> List[SmaliSecurityIssue]:
        """Check for suspicious patterns in entire file."""
        issues = []

        for pattern_name, pattern_info in self.suspicious_patterns.items():
            matches = list(re.finditer(pattern_info["pattern"], content, re.MULTILINE | re.IGNORECASE))

            for match in matches:
                line_number = content[: match.start()].count("\n") + 1

                issues.append(
                    SmaliSecurityIssue(
                        issue_type=pattern_name.upper(),
                        severity=pattern_info["severity"],
                        file_path=file_path,
                        line_number=line_number,
                        method_name="unknown",
                        class_name=class_name,
                        description=pattern_info["description"],
                        evidence=[f"Pattern: {pattern_name}", f"Match: {match.group(0)[:100]}..."],
                        confidence=pattern_info["confidence"],
                    )
                )

        return issues

    def _has_suspicious_control_flow(self, method_content: str) -> bool:
        """Check for suspicious control flow modifications."""
        # Look for unusual goto patterns or conditional bypasses
        suspicious_patterns = [
            r"goto\s+:\w+\s*\n\s*const/4\s+v\d+,\s+0x1",  # Goto followed by return true
            r"if-\w+.*\n(?:.*\n)*?\s*goto\s+:\w+\s*\n\s*const/4\s+v\d+,\s+0x1",  # If bypass
        ]

        return any(re.search(pattern, method_content, re.MULTILINE) for pattern in suspicious_patterns)

    def _has_exception_bypass(self, method_content: str) -> bool:
        """Check for exception handling bypass."""
        # Look for try-catch blocks that always return success
        pattern = r"\.catch.*Exception.*\n(?:.*\n)*?\s*const/4\s+v\d+,\s+0x1\s+return\s+v\d+"
        return bool(re.search(pattern, method_content, re.MULTILINE))

    def _generate_enhanced_findings(self, analysis_results: Dict[str, Any]) -> List[SmaliSecurityIssue]:
        """Generate enhanced findings from analysis results."""
        return analysis_results.get("security_issues", [])

    def _finding_to_dict(self, finding: SmaliSecurityIssue) -> Dict[str, Any]:
        """Convert SmaliSecurityIssue to dictionary."""
        return {
            "issue_type": finding.issue_type,
            "severity": finding.severity,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "method_name": finding.method_name,
            "class_name": finding.class_name,
            "description": finding.description,
            "evidence": finding.evidence,
            "confidence": finding.confidence,
        }
