#!/usr/bin/env python3
"""
Alternative Dynamic Analysis Plugin

This plugin provides dynamic analysis capabilities without relying on Frida,
specifically designed to work in environments where Frida hangs or is unavailable.
"""

import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class AlternativeDynamicAnalyzer:
    """
    Alternative dynamic analyzer that works without Frida.

    Uses ADB, logcat, and static analysis to provide dynamic security insights.
    """

    def __init__(self, package_name: str, config: Optional[Dict[str, Any]] = None):
        """Initialize the alternative analyzer."""
        self.package_name = package_name
        self.config = config or {}

    def analyze(self, apk_ctx: Any = None) -> Dict[str, Any]:
        """Perform alternative dynamic analysis."""
        logger.info(f"🔄 Starting alternative dynamic analysis for {self.package_name}")

        start_time = time.time()
        findings = []

        try:
            # Check device connectivity
            device_info = self._check_device_connectivity()

            if device_info.get("connected", False):
                logger.info("📱 Device connected - performing runtime checks")
                findings.extend(self._check_app_permissions())
                findings.extend(self._check_network_behavior())
                findings.extend(self._check_storage_access())
            else:
                logger.info("📱 No device - performing static-based dynamic analysis")
                if apk_ctx:
                    findings.extend(self._static_dynamic_analysis(apk_ctx))

            execution_time = time.time() - start_time

            return {
                "success": True,
                "plugin_name": "alternative_dynamic_analysis",
                "execution_time": execution_time,
                "findings": findings,
                "vulnerabilities": findings,
                "analysis_method": "alternative",
                "device_connected": device_info.get("connected", False),
                "total_findings": len(findings),
            }

        except Exception as e:
            logger.error(f"❌ Alternative analysis failed: {e}")
            return {"success": False, "error": str(e), "findings": [], "analysis_method": "alternative_failed"}

    def _check_device_connectivity(self) -> Dict[str, Any]:
        """Check if Android device is connected."""
        try:
            result = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                devices = [line for line in lines if "\tdevice" in line]
                return {"connected": len(devices) > 0, "device_count": len(devices)}
            else:
                return {"connected": False}

        except Exception:
            return {"connected": False}

    def _check_app_permissions(self) -> List[Dict[str, Any]]:
        """Check app permissions via ADB."""
        findings = []

        try:
            # Check if app is installed
            result = subprocess.run(
                ["adb", "shell", "pm", "list", "packages", self.package_name],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode == 0 and self.package_name in result.stdout:
                # App is installed - check permissions
                perm_result = subprocess.run(
                    ["adb", "shell", "dumpsys", "package", self.package_name],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )

                if perm_result.returncode == 0:
                    dangerous_perms = [
                        "android.permission.CAMERA",
                        "android.permission.RECORD_AUDIO",
                        "android.permission.ACCESS_FINE_LOCATION",
                        "android.permission.READ_CONTACTS",
                        "android.permission.READ_SMS",
                    ]

                    for perm in dangerous_perms:
                        if perm in perm_result.stdout and "granted=true" in perm_result.stdout:
                            findings.append(
                                {
                                    "vulnerability_type": "RUNTIME_PERMISSION",
                                    "title": f"Dangerous Permission: {perm}",
                                    "description": f"App has dangerous permission {perm}",
                                    "severity": "MEDIUM",
                                    "confidence": 0.8,
                                    "location": {"source": "runtime_permissions"},
                                    "recommendation": f"Review necessity of {perm}",
                                    "cwe_id": "CWE-250",
                                }
                            )

        except Exception as e:
            logger.debug(f"Permission check failed: {e}")

        return findings

    def _check_network_behavior(self) -> List[Dict[str, Any]]:
        """Check network behavior via netstat."""
        findings = []

        try:
            result = subprocess.run(["adb", "shell", "netstat", "-an"], capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                # Look for suspicious network connections
                lines = result.stdout.split("\n")
                for line in lines:
                    if ":80 " in line or ":443 " in line:
                        findings.append(
                            {
                                "vulnerability_type": "NETWORK_BEHAVIOR",
                                "title": "HTTP/HTTPS Connection Detected",
                                "description": f"Network connection detected: {line.strip()}",
                                "severity": "INFO",
                                "confidence": 0.6,
                                "location": {"source": "network_analysis"},
                                "recommendation": "Verify network connections are secure",
                                "cwe_id": "CWE-319",
                            }
                        )
                        break  # Only report one to avoid spam

        except Exception as e:
            logger.debug(f"Network check failed: {e}")

        return findings

    def _check_storage_access(self) -> List[Dict[str, Any]]:
        """Check storage access patterns."""
        findings = []

        try:
            # Check for world-readable files in app directory
            result = subprocess.run(
                ["adb", "shell", "ls", "-la", f"/data/data/{self.package_name}/"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                lines = result.stdout.split("\n")
                for line in lines:
                    if "rw-rw-rw-" in line or "rwxrwxrwx" in line:
                        findings.append(
                            {
                                "vulnerability_type": "STORAGE_SECURITY",
                                "title": "Insecure File Permissions",
                                "description": f"World-writable file detected: {line.strip()}",
                                "severity": "HIGH",
                                "confidence": 0.9,
                                "location": {"source": "file_permissions"},
                                "recommendation": "Restrict file permissions",
                                "cwe_id": "CWE-732",
                            }
                        )

        except Exception as e:
            logger.debug(f"Storage check failed: {e}")

        return findings

    def _static_dynamic_analysis(self, apk_ctx: Any) -> List[Dict[str, Any]]:
        """Perform static analysis that simulates dynamic findings."""
        findings = []

        if not hasattr(apk_ctx, "decompiled_path"):
            return findings

        try:
            decompiled_path = Path(apk_ctx.decompiled_path)
            if not decompiled_path.exists():
                return findings

            # Look for runtime security patterns in Java files
            java_files = list(decompiled_path.rglob("*.java"))

            for java_file in java_files[:20]:  # Limit to first 20 files
                try:
                    content = java_file.read_text(encoding="utf-8", errors="ignore")

                    # Check for logging patterns
                    if "Log.d(" in content or "Log.v(" in content:
                        findings.append(
                            {
                                "vulnerability_type": "RUNTIME_LOGGING",
                                "title": "Debug Logging Detected",
                                "description": "Application uses debug logging which may expose sensitive information",
                                "severity": "LOW",
                                "confidence": 0.7,
                                "location": {"source": "static_analysis", "file_path": str(java_file)},
                                "recommendation": "Remove debug logging in production builds",
                                "cwe_id": "CWE-532",
                            }
                        )

                    # Check for WebView security
                    if "setJavaScriptEnabled(true)" in content:
                        findings.append(
                            {
                                "vulnerability_type": "WEBVIEW_SECURITY",
                                "title": "JavaScript Enabled in WebView",
                                "description": "WebView has JavaScript enabled which may allow XSS attacks",
                                "severity": "MEDIUM",
                                "confidence": 0.8,
                                "location": {"source": "static_analysis", "file_path": str(java_file)},
                                "recommendation": "Disable JavaScript if not needed or implement proper validation",
                                "cwe_id": "CWE-79",
                            }
                        )

                    # Check for certificate validation
                    if "checkServerTrusted" in content or "X509TrustManager" in content:
                        findings.append(
                            {
                                "vulnerability_type": "CERTIFICATE_VALIDATION",
                                "title": "Custom Certificate Validation",
                                "description": "Application implements custom certificate validation",
                                "severity": "HIGH",
                                "confidence": 0.8,
                                "location": {"source": "static_analysis", "file_path": str(java_file)},
                                "recommendation": "Ensure proper certificate validation to prevent MITM attacks",
                                "cwe_id": "CWE-295",
                            }
                        )

                except Exception as e:
                    logger.debug(f"Failed to analyze {java_file}: {e}")

        except Exception as e:
            logger.warning(f"Static-dynamic analysis failed: {e}")

        return findings


def run_plugin(apk_path: str, output_dir: str = ".", options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Main plugin entry point for alternative dynamic analysis.

    Args:
        apk_path: Path to APK file or APKContext object
        output_dir: Output directory (unused)
        options: Optional configuration

    Returns:
        Analysis results
    """
    try:
        logger.info(f"Starting alternative dynamic analysis for {apk_path}")

        # Extract package name and context
        if hasattr(apk_path, "package_name"):
            package_name = apk_path.package_name or "unknown.package"
            apk_ctx = apk_path
        else:
            package_name = options.get("package_name", "unknown.package") if options else "unknown.package"
            apk_ctx = None

        # Create analyzer and run analysis
        analyzer = AlternativeDynamicAnalyzer(package_name, options)
        results = analyzer.analyze(apk_ctx)

        logger.info("Alternative dynamic analysis completed")
        return results

    except Exception as e:
        logger.error(f"Alternative dynamic analysis failed: {e}")
        return {"success": False, "error": str(e), "findings": []}


def run(apk_path: str, output_dir: str = ".", options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Alias for run_plugin."""
    return run_plugin(apk_path, output_dir, options)


if __name__ == "__main__":
    # Test the analyzer
    analyzer = AlternativeDynamicAnalyzer("com.test.app")

    print("🧪 Testing alternative dynamic analyzer...")
    results = analyzer.analyze()
    print(f"📊 Results: {json.dumps(results, indent=2)}")
