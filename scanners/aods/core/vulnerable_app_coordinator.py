#!/usr/bin/env python3
"""
AODS Vulnerable App Coordinator

Detects vulnerable/testing apps and coordinates appropriate filtering strategies
with the smart filtering integration system.
"""

import logging
import re
from typing import Dict, List, Any
from enum import Enum

logger = logging.getLogger(__name__)


class VulnerableAppType(Enum):
    SECURITY_TRAINING_APP = "security_training_app"
    VULNERABLE_TEST_APP = "vulnerable_test_app"
    PRODUCTION_APP = "production_app"


class VulnerableAppCoordinator:
    """Coordinates vulnerable app detection and smart filtering integration."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def _find_manifest_path(self, app_context) -> str:
        """Best-effort discovery of a decompiled AndroidManifest.xml for organic signals."""
        try:
            import os
            import glob

            # Prefer explicit context hint
            decompiled_dir = app_context.get("decompiled_apk_dir") or app_context.get("decompiled_path")
            if decompiled_dir:
                manifest = os.path.join(decompiled_dir, "AndroidManifest.xml")
                if os.path.exists(manifest):
                    return manifest
            # Search workspace decompiled dirs
            workspace_dir = os.path.join(os.getcwd(), "workspace")
            if os.path.exists(workspace_dir):
                for pattern in [
                    os.path.join(workspace_dir, "*_decompiled"),
                    os.path.join(workspace_dir, "*decompiled*"),
                    os.path.join(workspace_dir, "decompiled_*"),
                ]:
                    for path in glob.glob(pattern):
                        candidate = os.path.join(path, "AndroidManifest.xml")
                        if os.path.exists(candidate):
                            return candidate
        except Exception:
            pass
        return ""

    def _detect_organic_training_signals(self, app_context) -> bool:
        """Detect training/test builds using name-agnostic, organic signals."""
        manifest_path = self._find_manifest_path(app_context)
        signals = {"debuggable": False, "testOnly": False, "instrumentation": False}
        try:
            if manifest_path:
                with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().lower()
                    signals["debuggable"] = 'android:debuggable="true"' in content
                    signals["testOnly"] = 'android:testonly="true"' in content
                    signals["instrumentation"] = (
                        "<instrumentation" in content
                        or "androidx.test.runner" in content
                        or "android.test.runner" in content
                    )
        except Exception as e:
            self.logger.debug(f"Organic signal scan failed: {e}")
        # Simple policy: any two signals strongly indicate non-production test/training build
        score = sum(1 for v in signals.values() if v)
        if score >= 2:
            self.logger.info(f"✅ DETECTED SECURITY TRAINING APP (organic): signals={signals}")
            return True
        return False

    def detect_vulnerable_app(self, app_context):
        """Detect if app is vulnerable/testing app designed for security training"""

        package_name = app_context.get("package_name", "").lower()
        apk_path = app_context.get("apk_path", "").lower()

        # CRITICAL FIX: Enhanced logging and force detection
        self.logger.info("🔍 VULNERABLE APP DETECTION:")
        self.logger.info(f"   Package name: '{package_name}'")
        self.logger.info(f"   APK path: '{apk_path}'")

        # Force detection override
        if app_context.get("force_vulnerable", False):
            self.logger.info("🎯 FORCE DETECTION: Vulnerable app override enabled")
            return VulnerableAppType.SECURITY_TRAINING_APP

        # Organic, name-agnostic detection first (always enabled)
        try:
            if self._detect_organic_training_signals(app_context):
                return VulnerableAppType.SECURITY_TRAINING_APP
        except Exception as e:
            self.logger.debug(f"Organic detection error: {e}")

        # Load heuristic patterns organically from configuration if present (no hardcoding)
        vulnerable_training_patterns = []
        try:
            import yaml
            from pathlib import Path

            config_path = Path("config") / "vulnerable_app_heuristics.yaml"
            if config_path.exists():
                with open(config_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                    vulnerable_training_patterns = list(data.get("patterns", []))
        except Exception as e:
            self.logger.warning(f"Failed to load vulnerable app heuristics: {e}")

        combined_text = f"{package_name} {apk_path}".lower()
        self.logger.info(f"   Combined search text: '{combined_text}'")

        if vulnerable_training_patterns:
            for pattern in vulnerable_training_patterns:
                try:
                    if re.search(pattern, combined_text):
                        self.logger.info(f"✅ DETECTED SECURITY TRAINING APP (heuristic): '{pattern}' matched")
                        self.logger.info("   Switching to vulnerable app thresholds:")
                        self.logger.info("   - Confidence threshold: 0.1 (was 0.7)")
                        self.logger.info("   - Min severity: INFO (was MEDIUM)")
                        self.logger.info("   - Aggressive filtering: DISABLED")
                        return VulnerableAppType.SECURITY_TRAINING_APP
                except re.error:
                    continue

        self.logger.info("❌ No vulnerable app patterns matched - treating as production app")
        return VulnerableAppType.PRODUCTION_APP

    def apply_vulnerable_app_filtering(self, findings, app_context):
        """Apply vulnerable app filtering to reduce false positives"""

        app_type = self.detect_vulnerable_app(app_context)
        policy = self.get_filtering_policy(app_type)

        if app_type != VulnerableAppType.SECURITY_TRAINING_APP:
            self.logger.info("Production app detected - applying standard filtering")
            return findings

        self.logger.info("🎯 APPLYING VULNERABLE APP FILTERING:")
        self.logger.info(f"   Original findings: {len(findings)}")
        self.logger.info(f"   Policy: {policy}")

        # Apply smart filtering for vulnerable apps
        filtered_findings = []

        # Common false positive patterns for vulnerable apps
        false_positive_patterns = [
            # Over-detection patterns
            r"Network Security Cleartext Http.*library",
            r"Java Custom Crypto.*bit_shifting.*library",
            r"PASSWORD.*variable.*name",
            r"Children Data Protection.*generic",
            # Framework noise
            r"android\.support\.",
            r"androidx\.",
            r"com\.google\.",
            # Test/library code
            r"test.*package",
            r"example.*code",
        ]

        for finding in findings:
            # Keep high-confidence findings
            if finding.get("confidence", 0) >= 0.8:
                filtered_findings.append(finding)
                continue

            # Filter out common false positives
            finding_text = (
                f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('file_path', '')}".lower()
            )

            is_false_positive = False
            for pattern in false_positive_patterns:
                if re.search(pattern, finding_text, re.IGNORECASE):
                    is_false_positive = True
                    break

            if not is_false_positive:
                # Adjust confidence for vulnerable app context
                if finding.get("confidence", 0) < 0.5:
                    finding["confidence"] = min(0.7, finding.get("confidence", 0) + 0.2)
                filtered_findings.append(finding)

        reduction_percentage = ((len(findings) - len(filtered_findings)) / len(findings)) * 100 if findings else 0
        self.logger.info(f"   Filtered findings: {len(filtered_findings)}")
        self.logger.info(f"   Reduction: {reduction_percentage:.1f}%")

        return filtered_findings

    def get_filtering_policy(self, app_type):
        """Get appropriate filtering policy"""

        if app_type == VulnerableAppType.SECURITY_TRAINING_APP:
            return {
                "min_severity": "INFO",
                "confidence_threshold": 0.1,
                "max_reduction_percentage": 15.0,
                "enable_aggressive_filtering": False,
                "preserve_all_findings": True,
                "enable_smart_filtering": True,  # Enable smart filtering for vulnerable apps
                "vulnerable_app_mode": True,  # Mark as vulnerable app mode
            }
        else:
            return {
                "min_severity": "MEDIUM",
                "confidence_threshold": 0.7,
                "max_reduction_percentage": 70.0,
                "enable_aggressive_filtering": True,
                "preserve_all_findings": False,
                "enable_smart_filtering": True,
            }

    def should_bypass_aggressive_filtering(self, app_context):
        """Check if aggressive filtering should be bypassed for this app"""
        app_type = self.detect_vulnerable_app(app_context)
        policy = self.get_filtering_policy(app_type)

        should_bypass = not policy.get("enable_aggressive_filtering", True)

        if should_bypass:
            self.logger.info(f"🎯 Bypassing aggressive filtering for {app_type.value}")

        return should_bypass

    def apply_smart_filtering(self, findings: List[Dict[str, Any]], app_context: Dict[str, Any]):
        """Apply smart filtering using the integration system"""
        try:
            from core.smart_filtering_integration import apply_smart_filtering_for_vulnerable_apps

            package_name = app_context.get("package_name", "")
            result = apply_smart_filtering_for_vulnerable_apps(findings, package_name)

            self.logger.info("🎯 Smart filtering applied:")
            self.logger.info(f"   Strategy: {result['filtering_strategy']}")
            self.logger.info(f"   Original: {result['original_count']} findings")
            self.logger.info(f"   Kept: {result['kept_count']} findings")
            self.logger.info(f"   FP Rate: {result['false_positive_rate']:.1f}%")

            return result["filtered_findings"]

        except ImportError as e:
            self.logger.warning(f"Smart filtering integration unavailable: {e}")
            return findings

    def get_vulnerable_app_override(self, findings, app_context):
        """Get vulnerable app specific processing override"""
        app_type = self.detect_vulnerable_app(app_context)
        policy = self.get_filtering_policy(app_type)

        if app_type == VulnerableAppType.SECURITY_TRAINING_APP:
            # CRITICAL FIX: Respect enable_smart_filtering setting
            if policy.get("enable_smart_filtering", True):
                self.logger.info("🔧 Applying vulnerable-app-aware filtering (preserves real findings)")
                filtered_findings = self.apply_vulnerable_app_filtering(findings, app_context)
                final_count = len(filtered_findings)
            else:
                # PRESERVE ALL FINDINGS - no filtering for vulnerable apps
                self.logger.info("🔧 Smart filtering DISABLED - preserving all findings for vulnerable app")
                filtered_findings = findings  # Keep ALL findings
                final_count = len(filtered_findings)

            original_count = len(findings)
            reduction_percentage = (original_count - final_count) / original_count * 100 if original_count > 0 else 0

            self.logger.info("✅ Vulnerable app processing complete:")
            self.logger.info(f"   App Type: {app_type.value}")
            self.logger.info(f"   Original Findings: {original_count}")
            self.logger.info(f"   Final Findings: {final_count}")
            self.logger.info(f"   Reduction: {reduction_percentage:.1f}%")

            return {
                "override_active": True,
                "app_type": app_type.value,
                "original_count": original_count,
                "final_count": final_count,
                "filtered_findings": filtered_findings,
                "reduction_percentage": reduction_percentage,
                "smart_filtering_applied": policy.get("enable_smart_filtering", True),
            }
        else:
            return {"override_active": False, "app_type": app_type.value}


# Global coordinator instance
vulnerable_app_coordinator = VulnerableAppCoordinator()
