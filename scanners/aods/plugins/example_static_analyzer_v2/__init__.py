#!/usr/bin/env python3
"""
Example Static Analyzer Plugin v2
=================================

Demonstrates the BasePlugin v2 interface with full static analysis
capabilities. This serves as a reference implementation for migrating
legacy plugins to the new standardized interface.

Features:
- BasePlugin v2 compliant interface
- Metadata declaration
- Dependency validation
- Standardized finding generation
- Performance monitoring
- Error handling and logging
"""

import re
import time
from pathlib import Path
from typing import List, Optional  # noqa: F401

from core.plugins.base_plugin_v2 import (
    BasePluginV2,
    PluginMetadata,
    PluginResult,
    PluginFinding,
    PluginCapability,
    PluginStatus,
    PluginPriority,
    PluginDependency,
)


class ExampleStaticAnalyzerV2(BasePluginV2):
    """
    Example static analyzer plugin implementing BasePlugin v2 interface.

    Performs basic static analysis including:
    - Hardcoded string detection
    - Insecure API usage analysis
    - Basic manifest analysis
    - Resource file scanning
    """

    def get_metadata(self) -> PluginMetadata:
        """Get full plugin metadata."""
        return PluginMetadata(
            name="example_static_analyzer_v2",
            version="2.0.0",
            description="Example static analyzer demonstrating BasePlugin v2 interface",
            author="AODS Development Team",
            license="MIT",
            capabilities=[
                PluginCapability.STATIC_ANALYSIS,
                PluginCapability.VULNERABILITY_DETECTION,
                PluginCapability.MANIFEST_ANALYSIS,
                PluginCapability.RESOURCE_ANALYSIS,
            ],
            dependencies=[
                PluginDependency(name="re", description="Regular expressions for pattern matching", optional=False),
                PluginDependency(name="pathlib", description="Path manipulation utilities", optional=False),
            ],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            memory_limit_mb=256,
            tags=["static", "example", "v2", "demo"],
            categories=["security", "analysis"],
            security_level="standard",
            data_access_required=["filesystem"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        """Execute static analysis on the APK."""
        findings = []

        try:
            # Analyze manifest file
            manifest_findings = self._analyze_manifest(apk_ctx)
            findings.extend(manifest_findings)

            # Analyze source code (if available)
            if hasattr(apk_ctx, "decompiled_apk_dir") and apk_ctx.decompiled_apk_dir:
                code_findings = self._analyze_source_code(apk_ctx)
                findings.extend(code_findings)

            # Analyze resources
            resource_findings = self._analyze_resources(apk_ctx)
            findings.extend(resource_findings)

            # Create successful result
            return self.create_result(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    "files_analyzed": self._count_analyzed_files(apk_ctx),
                    "analysis_type": "comprehensive_static",
                },
                performance_metrics={
                    "findings_per_second": len(findings)
                    / max(0.001, self._execution_start_time and (time.time() - self._execution_start_time) or 0.001)
                },
            )

        except Exception as e:
            self.logger.error(f"Static analysis failed: {e}")
            return self.create_result(
                status=PluginStatus.FAILURE,
                error_message=str(e),
                findings=findings,  # Return partial findings even on failure
            )

    def _analyze_manifest(self, apk_ctx) -> List[PluginFinding]:
        """Analyze Android manifest for security issues."""
        findings = []

        try:
            if not hasattr(apk_ctx, "manifest_path") or not apk_ctx.manifest_path:
                return findings

            manifest_path = Path(apk_ctx.manifest_path)
            if not manifest_path.exists():
                return findings

            manifest_content = manifest_path.read_text(encoding="utf-8", errors="ignore")

            # Check for debuggable flag
            if 'android:debuggable="true"' in manifest_content:
                findings.append(
                    self.create_finding(
                        finding_id="MANIFEST_DEBUGGABLE_ENABLED",
                        title="Debug Mode Enabled",
                        description="Application has debug mode enabled, which can expose sensitive information",
                        severity="medium",
                        confidence=1.0,
                        file_path=str(manifest_path),
                        vulnerability_type="information_disclosure",
                        cwe_id="CWE-489",
                        owasp_category="M10",
                        remediation='Remove android:debuggable="true" from production builds',
                    )
                )

            # Check for backup allowed
            if 'android:allowBackup="true"' in manifest_content:
                findings.append(
                    self.create_finding(
                        finding_id="MANIFEST_BACKUP_ALLOWED",
                        title="Backup Allowed",
                        description="Application allows backup, which may expose sensitive data",
                        severity="low",
                        confidence=0.8,
                        file_path=str(manifest_path),
                        vulnerability_type="data_exposure",
                        cwe_id="CWE-200",
                        owasp_category="M2",
                        remediation='Set android:allowBackup="false" to prevent data exposure',
                    )
                )

            # Check for exported activities without permission
            exported_activities = re.findall(
                r'<activity[^>]*android:exported="true"[^>]*>.*?</activity>', manifest_content, re.DOTALL
            )

            for activity in exported_activities:
                if "android:permission" not in activity:
                    findings.append(
                        self.create_finding(
                            finding_id="MANIFEST_EXPORTED_ACTIVITY_NO_PERMISSION",
                            title="Exported Activity Without Permission",
                            description="Activity is exported but has no permission requirement",
                            severity="medium",
                            confidence=0.9,
                            file_path=str(manifest_path),
                            vulnerability_type="access_control",
                            cwe_id="CWE-200",
                            owasp_category="M6",
                            code_snippet=activity[:200] + "..." if len(activity) > 200 else activity,
                            remediation='Add android:permission attribute or set android:exported="false"',
                        )
                    )

        except Exception as e:
            self.logger.warning(f"Manifest analysis failed: {e}")

        return findings

    def _analyze_source_code(self, apk_ctx) -> List[PluginFinding]:
        """Analyze decompiled source code for security issues."""
        findings = []

        try:
            decompiled_dir = Path(apk_ctx.decompiled_apk_dir)
            if not decompiled_dir.exists():
                return findings

            # Find Java/Smali files
            source_files = list(decompiled_dir.rglob("*.java")) + list(decompiled_dir.rglob("*.smali"))

            for source_file in source_files[:50]:  # Limit to first 50 files for demo
                try:
                    content = source_file.read_text(encoding="utf-8", errors="ignore")
                    file_findings = self._analyze_source_file(source_file, content)
                    findings.extend(file_findings)
                except Exception as e:
                    self.logger.debug(f"Failed to analyze {source_file}: {e}")

        except Exception as e:
            self.logger.warning(f"Source code analysis failed: {e}")

        return findings

    def _analyze_source_file(self, file_path: Path, content: str) -> List[PluginFinding]:
        """Analyze a single source file."""
        findings = []
        lines = content.split("\n")

        # Pattern-based analysis
        patterns = {
            "hardcoded_password": {
                "pattern": r'(?i)(password|pwd|pass)\s*[=:]\s*["\'][^"\']{3,}["\']',
                "severity": "high",
                "title": "Hardcoded Password",
                "description": "Hardcoded password found in source code",
                "cwe": "CWE-798",
            },
            "hardcoded_api_key": {
                "pattern": r'(?i)(api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*["\'][^"\']{10,}["\']',
                "severity": "high",
                "title": "Hardcoded API Key",
                "description": "Hardcoded API key found in source code",
                "cwe": "CWE-798",
            },
            "sql_injection": {
                "pattern": r'(?i)(select|insert|update|delete).*\+.*["\']',
                "severity": "high",
                "title": "Potential SQL Injection",
                "description": "String concatenation in SQL query may lead to SQL injection",
                "cwe": "CWE-89",
            },
            "weak_crypto": {
                "pattern": r"(?i)(md5|sha1|des)(?!\w)",
                "severity": "medium",
                "title": "Weak Cryptographic Algorithm",
                "description": "Use of weak cryptographic algorithm detected",
                "cwe": "CWE-327",
            },
        }

        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_info in patterns.items():
                if re.search(pattern_info["pattern"], line):
                    findings.append(
                        self.create_finding(
                            finding_id=f"SOURCE_{pattern_name.upper()}_{file_path.stem}_{line_num}",
                            title=pattern_info["title"],
                            description=pattern_info["description"],
                            severity=pattern_info["severity"],
                            confidence=0.7,  # Pattern-based detection has moderate confidence
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip(),
                            vulnerability_type=pattern_name,
                            cwe_id=pattern_info["cwe"],
                            remediation=f"Review and secure the {pattern_info['title'].lower()}",
                        )
                    )

        return findings

    def _analyze_resources(self, apk_ctx) -> List[PluginFinding]:
        """Analyze resource files for security issues."""
        findings = []

        try:
            if not hasattr(apk_ctx, "decompiled_apk_dir") or not apk_ctx.decompiled_apk_dir:
                return findings

            resources_dir = Path(apk_ctx.decompiled_apk_dir) / "res"
            if not resources_dir.exists():
                return findings

            # Analyze strings.xml files
            string_files = list(resources_dir.rglob("strings.xml"))

            for string_file in string_files:
                try:
                    content = string_file.read_text(encoding="utf-8", errors="ignore")

                    # Look for potential secrets in strings
                    if re.search(r'(?i)(password|secret|key|token).*["\'][^"\']{8,}["\']', content):
                        findings.append(
                            self.create_finding(
                                finding_id=f"RESOURCE_POTENTIAL_SECRET_{string_file.stem}",
                                title="Potential Secret in Resources",
                                description="Potential secret or sensitive information found in string resources",
                                severity="medium",
                                confidence=0.6,
                                file_path=str(string_file),
                                vulnerability_type="information_disclosure",
                                cwe_id="CWE-200",
                                remediation="Review string resources and remove any sensitive information",
                            )
                        )

                except Exception as e:
                    self.logger.debug(f"Failed to analyze resource file {string_file}: {e}")

        except Exception as e:
            self.logger.warning(f"Resource analysis failed: {e}")

        return findings

    def _count_analyzed_files(self, apk_ctx) -> int:
        """Count the number of files analyzed."""
        count = 0

        # Count manifest
        if hasattr(apk_ctx, "manifest_path") and apk_ctx.manifest_path:
            count += 1

        # Count source files
        if hasattr(apk_ctx, "decompiled_apk_dir") and apk_ctx.decompiled_apk_dir:
            decompiled_dir = Path(apk_ctx.decompiled_apk_dir)
            if decompiled_dir.exists():
                source_files = list(decompiled_dir.rglob("*.java")) + list(decompiled_dir.rglob("*.smali"))
                count += min(len(source_files), 50)  # Limited to 50 for demo

                # Count resource files
                resources_dir = decompiled_dir / "res"
                if resources_dir.exists():
                    resource_files = list(resources_dir.rglob("strings.xml"))
                    count += len(resource_files)

        return count


# Plugin entry point for legacy compatibility


def run(apk_ctx):
    """Legacy entry point for backward compatibility."""
    plugin = ExampleStaticAnalyzerV2()
    result = plugin.execute(apk_ctx)

    # Convert to legacy format
    if result.findings:
        title = f"Static Analysis - {len(result.findings)} findings"
        description = f"Found {len(result.findings)} potential security issues"
        return title, description
    else:
        return "Static Analysis", "No security issues found"
