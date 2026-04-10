"""
core.cli.scanner_static - Static analysis functions extracted from AODSScanner (Track 50).
"""

import re
import yaml
from pathlib import Path

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from core.cli import REPO_ROOT
from core.cli.feature_flags import (
    WEBVIEW_SECURITY_AVAILABLE,
    ADVANCED_INTELLIGENCE_AVAILABLE,
    get_unified_threat_intelligence,
)


def execute_comprehensive_static_analysis(apk_ctx):
    """
    Execute full static analysis using vulnerability patterns.

    This function directly applies the vulnerability patterns from vulnerability_patterns.yaml
    to detect security issues when the plugin system fails.
    """
    import asyncio

    logger.info("Starting full static analysis")

    results = {}
    vulnerabilities_found = []

    try:
        # Load vulnerability patterns
        patterns_file = REPO_ROOT / "config" / "vulnerability_patterns.yaml"
        if not patterns_file.exists():
            logger.warning("Vulnerability patterns file not found", path=str(patterns_file))
            return {"comprehensive_analysis": ("No vulnerability patterns", [])}

        with open(patterns_file, "r") as f:
            patterns_config = yaml.safe_load(f)

        logger.info("Loaded vulnerability patterns", path=str(patterns_file))

        # Integrate WebView Security Analysis if available
        if WEBVIEW_SECURITY_AVAILABLE:
            try:
                logger.info("Running WebView Security Analysis")
                from core.shared_infrastructure.security.webview_security_analyzer import WebViewSecurityAnalyzer

                # Initialize WebView analyzer with APK context
                webview_analyzer = WebViewSecurityAnalyzer(apk_ctx)

                # Run WebView analysis
                webview_results = webview_analyzer.analyze_webview_security()

                if webview_results and webview_results.success:
                    logger.info("WebView analysis completed", finding_count=len(webview_results.webview_findings))

                    # Convert WebView findings to vulnerability format
                    for finding in webview_results.webview_findings:
                        vulnerabilities_found.append(
                            {
                                "type": "WebView Security",
                                "category": finding.vulnerability_type.value,
                                "severity": finding.severity.value,
                                "description": finding.description,
                                "file": finding.affected_component,
                                "line": 0,
                                "evidence": finding.evidence,
                                "recommendation": finding.remediation_advice,
                            }
                        )
                else:
                    logger.info("No vulnerabilities found for WebView analysis")

            except Exception as e:
                logger.warning("WebView analysis error", error=str(e))

        # Get analysis targets
        analysis_targets = []

        # 1. AndroidManifest.xml analysis
        manifest_path = None
        if hasattr(apk_ctx, "unpacked_apk_dir") and apk_ctx.unpacked_apk_dir:
            manifest_path = Path(apk_ctx.unpacked_apk_dir) / "AndroidManifest.xml"
            if manifest_path.exists():
                analysis_targets.append(("AndroidManifest.xml", manifest_path))
                logger.info("Found AndroidManifest.xml", path=str(manifest_path))

        # 2. Decompiled Java/Smali sources analysis
        source_files = []
        if hasattr(apk_ctx, "decompiled_apk_dir") and apk_ctx.decompiled_apk_dir:
            decompiled_path = Path(apk_ctx.decompiled_apk_dir)
            if decompiled_path.exists():
                # Find Java files
                java_files = list(decompiled_path.rglob("*.java"))
                smali_files = list(decompiled_path.rglob("*.smali"))
                source_files.extend(java_files)
                source_files.extend(smali_files)
                logger.info("Found source files", java_count=len(java_files), smali_count=len(smali_files))

        # Enhanced organic file prioritization: analyze application files before library files
        if len(source_files) > 200:
            logger.info("Applying enhanced organic prioritization", source_file_count=len(source_files))

            # Initialize organic detection systems
            app_package = getattr(apk_ctx, "package_name", "") if hasattr(apk_ctx, "package_name") else ""

            # Fallback: Try to extract package name from APK if not available
            if not app_package and hasattr(apk_ctx, "apk_path"):
                try:
                    from core.utils.package_name_extractor import PackageNameExtractor

                    extractor = PackageNameExtractor()
                    result = extractor.extract_package_name(str(apk_ctx.apk_path))
                    if result.success and result.package_name:
                        app_package = result.package_name
                        logger.info("Extracted package name for organic detection", package=app_package)
                except Exception as e:
                    logger.warning("Could not extract package name for organic detection", error=str(e))
            framework_filter = None

            # Try to use existing OptimizedFrameworkFilter for enhanced detection
            try:
                from core.optimized_framework_filter import OptimizedFrameworkFilter

                framework_filter = OptimizedFrameworkFilter()
                logger.debug("Using OptimizedFrameworkFilter for enhanced organic detection")
            except Exception as e:
                logger.warning("OptimizedFrameworkFilter unavailable, using basic organic detection", error=str(e))

            # Analyze file paths to organically determine application vs library code
            app_files = []
            lib_files = []

            for file_path in source_files:
                path_str = str(file_path)
                is_app_code = False

                # Enhanced detection: Use OptimizedFrameworkFilter if available
                if framework_filter:
                    try:
                        framework_result = framework_filter._analyze_framework_content("", path_str)
                        if framework_result and framework_result.get("confidence", 0) > 0.6:
                            # High confidence framework/library code
                            lib_files.append(file_path)
                            continue
                    except Exception:
                        pass  # Fall back to basic detection

                # Basic organic indicators for application code:

                # 1. Files in the main application package (strongest indicator)
                if app_package and app_package.replace(".", "/") in path_str:
                    is_app_code = True

                # 2. Files with Android app component patterns
                elif any(
                    component in path_str
                    for component in ["Activity", "Service", "Receiver", "Provider", "Fragment", "Application"]
                ):
                    is_app_code = True

                # 3. Files in shallow directory structures (app code typically less nested)
                elif path_str.count("/") <= 4 and not any(
                    marker in path_str for marker in ["com/", "org/", "net/", "io/"]
                ):
                    is_app_code = True

                # 4. Files with app-specific naming patterns
                elif any(
                    pattern in path_str.lower()
                    for pattern in ["main", "app", "ui", "view", "model", "controller", "activity", "fragment"]
                ):
                    # Exclude if it's clearly a library path
                    if not any(
                        lib_marker in path_str
                        for lib_marker in [
                            "com/google",
                            "androidx",
                            "kotlin",
                            "org/apache",
                            "retrofit",
                            "okhttp",
                            "gson",
                        ]
                    ):
                        is_app_code = True

                # 5. Files in root source directories (typically app code)
                elif "/sources/" in path_str and path_str.count("/") <= 6:
                    path_after_sources = path_str.split("/sources/")[-1]
                    if path_after_sources.count("/") <= 3:
                        is_app_code = True

                # 6. Manifest and resource files (app-specific)
                elif any(
                    app_file in path_str.lower()
                    for app_file in ["androidmanifest.xml", "strings.xml", "colors.xml", "styles.xml"]
                ):
                    is_app_code = True

                # 7. Custom application classes (not in standard library paths)
                elif path_str.endswith(".java") or path_str.endswith(".kt"):
                    # If not in known library paths, likely app code
                    if not any(
                        lib_path in path_str
                        for lib_path in [
                            "com/google/",
                            "androidx/",
                            "kotlin/",
                            "kotlinx/",
                            "org/apache/",
                            "okhttp3/",
                            "retrofit2/",
                            "com/squareup/",
                            "io/reactivex/",
                        ]
                    ):
                        is_app_code = True

                if is_app_code:
                    app_files.append(file_path)
                else:
                    lib_files.append(file_path)

            logger.info("Organic file classification complete", app_files=len(app_files), lib_files=len(lib_files))

            # Prioritize application files, then add library files if space allows
            prioritized_files = app_files[:200]  # Take all app files up to 200
            remaining_slots = 200 - len(prioritized_files)

            if remaining_slots > 0 and lib_files:
                prioritized_files.extend(lib_files[:remaining_slots])
                logger.info("Analyzing prioritized files", app_files=len(app_files), lib_files=remaining_slots)
            else:
                logger.info("Analyzing application files only", count=len(prioritized_files))

            source_files = prioritized_files
        else:
            logger.info("Analyzing all source files", count=len(source_files))

        for source_file in source_files:
            analysis_targets.append(("source", source_file))

        logger.info("Analyzing files", target_count=len(analysis_targets))

        # Apply patterns to each analysis target
        for target_type, file_path in analysis_targets:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # Apply manifest-specific patterns
                if target_type == "AndroidManifest.xml":
                    manifest_vulns = analyze_manifest_patterns(content, patterns_config, str(file_path))
                    vulnerabilities_found.extend(manifest_vulns)

                # Apply source code patterns
                elif target_type == "source":
                    source_vulns = analyze_source_patterns(content, patterns_config, str(file_path))
                    vulnerabilities_found.extend(source_vulns)

            except Exception as e:
                logger.warning("Error analyzing file", file_path=str(file_path), error=str(e))
                continue

        logger.info("Full static analysis complete", vulnerability_count=len(vulnerabilities_found))

        # Enhance vulnerabilities with Advanced Intelligence Engine if available
        if ADVANCED_INTELLIGENCE_AVAILABLE and vulnerabilities_found:
            try:
                logger.info("Enhancing vulnerabilities with Advanced Intelligence")
                enhanced_vulnerabilities = []

                for vuln in vulnerabilities_found:
                    # Convert vulnerability to format expected by intelligence engine
                    vuln_data = {
                        "title": vuln.get("type", "Unknown"),
                        "description": vuln.get("description", ""),
                        "category": vuln.get("category", "GENERAL"),
                        "severity": vuln.get("severity", "MEDIUM"),
                        "file_path": vuln.get("file", ""),
                        "evidence": vuln.get("evidence", ""),
                    }

                    # Analyze with unified threat intelligence system

                    # Get unified intelligence system instance
                    intelligence_system = get_unified_threat_intelligence()
                    enhanced_result = asyncio.run(intelligence_system.correlate_with_vulnerability(vuln_data))

                    # Merge enhanced analysis with original vulnerability
                    enhanced_vuln = vuln.copy()
                    enhanced_vuln.update(
                        {
                            "ml_confidence": enhanced_result.ml_confidence,
                            "threat_intelligence": (
                                enhanced_result.threat_intelligence.cve_id
                                if enhanced_result.threat_intelligence
                                else None
                            ),
                            "anomaly_score": enhanced_result.anomaly_score,
                            "zero_day_likelihood": enhanced_result.zero_day_likelihood,
                            "behavioral_indicators": enhanced_result.behavioral_indicators,
                            "enhanced_reasoning": enhanced_result.reasoning,
                            "ai_enhanced": True,
                        }
                    )

                    enhanced_vulnerabilities.append(enhanced_vuln)

                vulnerabilities_found = enhanced_vulnerabilities
                logger.info(
                    "Advanced Intelligence enhancement completed", vulnerability_count=len(vulnerabilities_found)
                )

            except Exception as e:
                logger.warning("Advanced Intelligence enhancement error", error=str(e))

        # Format results for compatibility with plugin system
        if vulnerabilities_found:
            results["comprehensive_static_analysis"] = (
                f"Security analysis - {len(vulnerabilities_found)} vulnerabilities detected",
                vulnerabilities_found,
            )
        else:
            results["comprehensive_static_analysis"] = (
                "Security analysis - No vulnerabilities detected",
                [],
            )

        return results

    except Exception as e:
        logger.error("Full static analysis failed", error=str(e))
        return {"comprehensive_analysis": ("Analysis failed", [])}


def analyze_manifest_patterns(content, patterns_config, file_path):
    """Analyze AndroidManifest.xml using manifest-specific patterns."""
    vulnerabilities = []

    manifest_patterns = patterns_config.get("manifest_security", {})

    for category, category_info in manifest_patterns.items():
        patterns = category_info.get("patterns", [])
        for pattern_info in patterns:
            pattern = pattern_info.get("pattern", "")
            if pattern and re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                vuln = {
                    "type": f"manifest_{category}",
                    "title": pattern_info.get("title", f"Manifest {category} issue"),
                    "description": pattern_info.get("description", "Manifest security issue detected"),
                    "severity": pattern_info.get("severity", "MEDIUM"),
                    "cwe_id": pattern_info.get("cwe_id", "CWE-200"),
                    "owasp_category": pattern_info.get("owasp_category", "M10: Extraneous Functionality"),
                    "file_path": file_path,
                    "remediation": pattern_info.get("remediation", "Review and fix the detected issue"),
                    "confidence": pattern_info.get("confidence_base", 0.8),
                }
                vulnerabilities.append(vuln)
                logger.info("Found manifest vulnerability", title=vuln["title"])

    return vulnerabilities


def analyze_source_patterns(content, patterns_config, file_path):
    """Analyze source code using patterns."""
    vulnerabilities = []

    # Categories to analyze (representative vulnerable patterns)
    categories_to_check = [
        ("input_validation", "Input Validation"),
        ("insecure_logging", "Insecure Logging"),
        ("storage_security", "Insecure Data Storage"),
        ("hardcoded_secrets", "Hardcoded Secrets"),
        ("detection_patterns", "Security Detection"),
        ("network_security", "Network Security"),
    ]

    for category_key, category_name in categories_to_check:
        category_patterns = patterns_config.get(category_key, {})

        # Handle nested pattern structure
        for subcategory, subcategory_info in category_patterns.items():
            patterns = subcategory_info.get("patterns", [])
            for pattern_info in patterns:
                pattern = pattern_info.get("pattern", "")
                if pattern:
                    try:
                        if re.search(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL):
                            vuln = {
                                "type": f"{category_key}_{subcategory}",
                                "title": pattern_info.get("title", f"{category_name} - {subcategory}"),
                                "description": pattern_info.get(
                                    "description", f"{category_name} vulnerability detected"
                                ),
                                "severity": pattern_info.get("severity", "MEDIUM"),
                                "cwe_id": pattern_info.get("cwe_id", "CWE-200"),
                                "owasp_category": pattern_info.get("owasp_category", "M7: Client Code Quality"),
                                "file_path": file_path,
                                "remediation": pattern_info.get("remediation", "Review and fix the detected issue"),
                                "confidence": pattern_info.get("confidence_base", 0.8),
                                "matched_pattern": pattern[:100] + "..." if len(pattern) > 100 else pattern,
                            }
                            vulnerabilities.append(vuln)
                            logger.info(
                                "Found source vulnerability",
                                category=category_name,
                                title=vuln["title"],
                                file=Path(file_path).name,
                            )
                    except re.error as e:
                        logger.warning(
                            "Invalid regex pattern", category=category_key, subcategory=subcategory, error=str(e)
                        )
                        continue

    return vulnerabilities
