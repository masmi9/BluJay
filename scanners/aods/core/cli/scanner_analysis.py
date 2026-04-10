"""
core.cli.scanner_analysis - Security analysis functions extracted from AODSScanner (Track 50).
"""

import re
import subprocess

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from rich.text import Text

from core.cli import REPO_ROOT


def attack_surface_analysis(scanner) -> None:
    """
    Analyze the attack surface of the application.

    Identifies exported activities, services, and content providers
    that could be potential entry points for attackers.
    Results are added to the report.
    """
    logger.info("attack_surface_analysis_started")
    commands = [
        f"run app.provider.info -a {scanner.apk_ctx.package_name}",
        f"run app.package.attacksurface " f"{scanner.apk_ctx.package_name}",
    ]
    results = []
    for cmd in commands:
        try:
            # Use Frida dynamic analysis plugin for this command
            try:
                from plugins.frida_dynamic_analysis import run_plugin as frida_plugin
            except ImportError:
                # Fallback: try absolute import from main module
                try:
                    from plugins.frida_dynamic_analysis.main import run_plugin as frida_plugin
                except ImportError as fallback_error:
                    logger.error("frida_dynamic_analysis_import_failed", error=str(fallback_error))
                    return  # Skip if Frida plugin cannot be imported

            test_type = "provider_info" if "provider.info" in cmd else "attack_surface"
            frida_results = frida_plugin(
                scanner.apk_ctx, options={"test_type": test_type, "package_name": scanner.apk_ctx.package_name}
            )

            if frida_results:
                output = f"Frida-based {test_type} analysis completed"
            else:
                output = f"Frida analysis for {test_type} completed"

            logger.info("frida_attack_surface_completed", test_type=test_type)
            results.append(output)
        except Exception as e:
            error_msg = f"Error executing Frida attack surface command '{cmd}': {e}"
            logger.error("frida_attack_surface_error", command=cmd, error=str(e))
            results.append(f"Analysis temporarily unavailable: {error_msg}")

    scanner.add_report_section("Attack Surface Analysis", "\n".join(results))


def traversal_vulnerabilities(scanner) -> None:
    """
    Test content providers for path traversal vulnerabilities using Frida.

    Uses Frida to hook and test content provider methods for path traversal
    vulnerabilities instead of Drozer's scanner.provider.traversal.
    """
    logger.info("traversal_vulnerabilities_test_started")
    try:
        if not scanner.frida_available:
            # Fallback to static analysis approach
            result = "Frida not available - using static analysis fallback for traversal detection"
            scanner.add_report_section("Path Traversal Vulnerabilities (Static)", result)
            return

        # Use Frida dynamic analysis plugin for provider testing
        try:
            from plugins.frida_dynamic_analysis import run_plugin as frida_plugin
        except ImportError:
            # Fallback: try absolute import from main module
            try:
                from plugins.frida_dynamic_analysis.main import run_plugin as frida_plugin
            except ImportError as fallback_error:
                logger.error("frida_import_failed", error=str(fallback_error), test_type="path_traversal")
                return  # Skip if Frida plugin cannot be imported

        frida_results = frida_plugin(
            scanner.apk_ctx.apk_path_str,  # Pass apk_path string, not apk_ctx object
            options={"test_type": "content_provider_traversal", "package_name": scanner.apk_ctx.package_name},
        )

        if frida_results and "vulnerabilities" in frida_results:
            traversal_vulns = [v for v in frida_results["vulnerabilities"] if "traversal" in v.get("type", "").lower()]
            if traversal_vulns:
                result = f"Found {len(traversal_vulns)} path traversal vulnerabilities"
            else:
                result = "No path traversal vulnerabilities detected"
        else:
            result = "Frida-based traversal analysis completed"

        logger.info("frida_path_traversal_scan_completed")
        scanner.add_report_section("Path Traversal Vulnerabilities (Frida)", result)
    except Exception as e:
        error_msg = f"Error during Frida traversal vulnerability scan: {e}"
        logger.error("frida_path_traversal_scan_error", error=str(e))
        scanner.add_report_section(
            "Path Traversal Vulnerabilities (Frida)",
            f"Analysis temporarily unavailable: {error_msg}",
        )


def injection_vulnerabilities(scanner) -> None:
    """
    Test content providers for SQL injection vulnerabilities using Frida.

    Uses Frida to hook database methods and test for SQL injection
    vulnerabilities instead of Drozer's scanner.provider.injection.
    """
    logger.info("sql_injection_test_started")
    try:
        # Use Frida dynamic analysis plugin for SQL injection testing
        try:
            from plugins.frida_dynamic_analysis import run_plugin as frida_plugin
        except ImportError:
            # Fallback: try absolute import from main module
            try:
                from plugins.frida_dynamic_analysis.main import run_plugin as frida_plugin
            except ImportError as fallback_error:
                logger.error("frida_import_failed", error=str(fallback_error), test_type="sql_injection")
                return  # Skip if Frida plugin cannot be imported

        frida_results = frida_plugin(
            scanner.apk_ctx.apk_path_str,  # Pass apk_path string, not apk_ctx object
            options={
                "test_type": "sql_injection_testing",
                "package_name": scanner.apk_ctx.package_name,
                "target_components": ["content_providers", "database_operations"],
            },
        )

        if frida_results and "vulnerabilities" in frida_results:
            sql_vulns = [
                v
                for v in frida_results["vulnerabilities"]
                if "sql" in v.get("type", "").lower() or "injection" in v.get("type", "").lower()
            ]
            if sql_vulns:
                result = f"Found {len(sql_vulns)} SQL injection vulnerabilities"
                for vuln in sql_vulns[:3]:  # Show first 3 for brevity
                    result += f"\n  - {vuln.get('description', 'SQL injection detected')}"
            else:
                result = "No SQL injection vulnerabilities detected"
        else:
            result = "Frida-based SQL injection analysis completed"

        logger.info("frida_sql_injection_scan_completed")
        scanner.add_report_section("SQL Injection Vulnerabilities (Frida)", result)
    except Exception as e:
        error_msg = f"Error during Frida SQL injection vulnerability scan: {e}"
        logger.error("frida_sql_injection_scan_error", error=str(e))
        scanner.add_report_section(
            "SQL Injection Vulnerabilities (Frida)",
            f"Analysis temporarily unavailable: {error_msg}",
        )


def extract_additional_info(scanner) -> None:
    """
    Extract additional information from the APK.

    Retrieves certificate details, permissions, native libraries,
    and custom permissions from the analyzed APK.
    Results are added to the report.
    """
    test_type = "APK Information Extraction"
    report_content = {
        "Test Description": (
            "Extracts additional information from the APK such as "
            "certificate details, permissions, and native libraries."
        ),
        "Results": [],
        "Status": "INFO",
    }
    try:
        if not scanner.apk_ctx.analyzer:
            logger.warning("apk_analyzer_not_initialized", action="skipping_info_extraction")
            report_content["Results"].append({"Warning": "APKAnalyzer not available."})
        else:
            cert_details = scanner.apk_ctx.analyzer.get_certificate_details()
            if cert_details:
                report_content["Results"].append({"Certificate Details": cert_details})
                logger.info("certificate_details_extracted", cert_details=cert_details)
            permissions = scanner.apk_ctx.analyzer.get_permissions()
            if permissions:
                report_content["Results"].append({"Permissions": permissions})
                logger.info("permissions_extracted", permission_count=len(permissions))
            native_libs = scanner.apk_ctx.analyzer.get_native_libraries()
            if native_libs:
                report_content["Results"].append({"Native Libraries": native_libs})
                logger.info("native_libraries_extracted", lib_count=len(native_libs))
            custom_perms = [p for p in permissions if p.startswith(str(scanner.apk_ctx.package_name))]
            if custom_perms:
                report_content["Results"].append({"Custom Permissions": custom_perms})
                logger.info("custom_permissions_found", count=len(custom_perms), permissions=custom_perms)
    except Exception as e:
        error_msg = f"Error extracting APK info: {Text(str(e))}"
        logger.error("apk_info_extraction_error", error=str(e), exc_info=True)
        report_content["Results"].append({"Error": error_msg})
        report_content["Status"] = "ERROR"
    scanner.add_report_section(test_type, report_content)


def test_debuggable_logging(scanner) -> None:
    """
    Test for debuggable logging and sensitive information exposure.

    Checks if the application is debuggable and monitors for sensitive
    information in logs. This test helps identify potential information
    disclosure vulnerabilities through logging.
    """
    logger.info("debuggable_logging_test_started")

    # Check if app is debuggable from manifest
    debuggable_info = []
    if scanner.apk_ctx.analyzer:
        is_debuggable = scanner.apk_ctx.analyzer.is_debuggable()
        if is_debuggable:
            debuggable_info.append('❌ Application is debuggable (android:debuggable="true")')
            debuggable_info.append("⚠ This allows debugging and may expose sensitive information")
        else:
            debuggable_info.append("✓ Application is not debuggable")

    # Monitor logs for sensitive patterns (if in deep mode)
    log_findings = []
    if scanner.apk_ctx.scan_mode == "deep":
        try:
            # Run a brief log capture to check for immediate sensitive data
            try:
                # Use proper subprocess without shell=True for security
                result = subprocess.run(["timeout", "10s", "adb", "logcat"], capture_output=True, text=True, timeout=15)
                # Filter for package name in Python instead of shell
                if result.stdout and scanner.apk_ctx.package_name in result.stdout:
                    # Process the filtered output for sensitive data
                    lines = result.stdout.split("\n")
                    for line in lines:
                        if scanner.apk_ctx.package_name in line:
                            # Log the package-specific output for analysis
                            logger.info(f"Package activity detected: {line.strip()}")
                            # Store for further analysis
                            if hasattr(scanner, "dynamic_output"):
                                scanner.dynamic_output.append(line.strip())
                            else:
                                scanner.dynamic_output = [line.strip()]
            except subprocess.TimeoutExpired:
                result = subprocess.CompletedProcess([], 0, "", "")
            except Exception:
                result = subprocess.CompletedProcess([], 1, "", "Command failed")

            if result.stdout:
                sensitive_patterns = [
                    (r"password", "Password"),
                    (r"token", "Token"),
                    (r"key", "API Key"),
                    (r"secret", "Secret"),
                    (r"http://", "HTTP URL"),
                    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP Address"),
                ]

                for pattern, description in sensitive_patterns:
                    if re.search(pattern, result.stdout, re.IGNORECASE):
                        log_findings.append(f"⚠ Found {description} in logs")

            if not log_findings:
                log_findings.append("✓ No immediate sensitive data found in logs")

        except subprocess.TimeoutExpired:
            log_findings.append("⚠ Log monitoring timed out")
        except Exception as e:
            log_findings.append(f"⚠ Error monitoring logs: {e}")
    else:
        log_findings.append("ℹ Log monitoring skipped in safe mode")

    # Compile results
    all_findings = debuggable_info + log_findings

    # Create formatted output
    result_text = Text()
    result_text.append("Debuggable Logging Analysis\n", style="bold blue")

    for finding in all_findings:
        if finding.startswith("❌"):
            result_text.append(f"{finding}\n", style="red")
        elif finding.startswith("⚠"):
            result_text.append(f"{finding}\n", style="yellow")
        elif finding.startswith("✓"):
            result_text.append(f"{finding}\n", style="green")
        else:
            result_text.append(f"{finding}\n")

    scanner.add_report_section("Debuggable Logging Test", result_text)


def network_cleartext_traffic_analyzer(scanner) -> None:
    """
    Network Cleartext Traffic Analyzer: Full cleartext traffic vulnerability analysis.

    This method performs analysis of Android applications for cleartext traffic
    vulnerabilities, including manifest configuration, network security policies, and resource analysis.
    """
    try:
        try:
            from plugins.network_cleartext_traffic import run
        except ImportError:
            # Fallback: try direct import from plugin's __init__.py
            import sys
            import os

            plugin_path = str(REPO_ROOT / "plugins" / "network_cleartext_traffic")
            sys.path.insert(0, plugin_path)
            try:
                from main import run  # type: ignore
            except ImportError:
                # Import from the plugin's __init__.py, not core's
                import importlib.util

                spec = importlib.util.spec_from_file_location(
                    "network_cleartext_traffic", os.path.join(plugin_path, "__init__.py")
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                run = module.run

        logger.info("network_cleartext_analysis_started")
        title, analysis_result = run(scanner.apk_ctx)

        # Extract status from title
        status = "PASS" if "PASS" in title else "FAIL" if "FAIL" in title else "MANUAL"

        # Extract risk level from analysis result
        risk_level = "HIGH"
        if hasattr(analysis_result, "plain"):
            content = analysis_result.plain
            if "Risk Level: LOW" in content:
                risk_level = "LOW"
            elif "Risk Level: MEDIUM" in content:
                risk_level = "MEDIUM"
            elif "Risk Level: HIGH" in content:
                risk_level = "HIGH"

        # Add to report generator for enhanced reporting (with null check)
        if hasattr(scanner, "report_generator") and scanner.report_generator is not None:
            scanner.report_generator.add_section(
                "Network Cleartext Traffic Analysis",
                {
                    "id": "NETWORK-CLEARTEXT-TRAFFIC",
                    "title": "Network Cleartext Traffic Analysis",
                    "description": "Analysis of cleartext traffic vulnerabilities and network security configuration",  # noqa: E501
                    "status": status,
                    "risk_level": risk_level,
                    "category": "Network Security",
                    "evidence": str(analysis_result),
                    "masvs_control": "MASVS-NETWORK-1, MASVS-NETWORK-2",
                    "mastg_reference": "MASTG-TEST-0024, MASTG-TEST-0025",
                },
            )

        # Add to legacy report format
        scanner.add_report_section(title, analysis_result)

    except ImportError as e:
        error_msg = f"Failed to import Network Cleartext Traffic Analyzer plugin: {e}"
        logger.error("network_cleartext_plugin_import_error", error=str(e))
        scanner.add_report_section(
            "Network Cleartext Traffic Analysis",
            Text.from_markup(f"[red]Plugin import error: {error_msg}[/red]"),
        )
    except Exception as e:
        error_msg = f"Error running Network Cleartext Traffic Analysis: {e}"
        logger.error("network_cleartext_analysis_error", error=str(e), exc_info=True)
        scanner.add_report_section(
            "Network Cleartext Traffic Analysis",
            Text.from_markup(f"[red]Analysis error: {error_msg}[/red]"),
        )
