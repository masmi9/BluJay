#!/usr/bin/env python3
"""
semgrep_mastg_analyzer - Semgrep MASTG Security Analysis Plugin
================================================================

Runs Semgrep with OWASP MASTG security rules against JADX-decompiled
Android sources, providing standardized vulnerability findings.

Features:
- Integrates with existing JADX decompilation pipeline
- Extracts MSTG IDs from rule metadata and maps to MASVS controls
- Stores raw MSTG IDs in evidence["mstg_tests"] for audit trail
- Normalizes findings through IntegratedFindingNormalizer
- Supports profile-based rule filtering
- Graceful degradation when semgrep CLI unavailable

MSTG→MASVS Mapping:
- MSTG-* are test IDs (e.g., MSTG-AUTH-1)
- MASVS-* are control IDs (e.g., MASVS-AUTH-1)
- Mapping loaded from compliance/masvs_mstg/taxonomy.yaml
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Path setup for standalone execution
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from core.plugins.base_plugin_v2 import (
    BasePluginV2,
    PluginCapability,
    PluginDependency,
    PluginFinding,
    PluginMetadata,
    PluginPriority,
    PluginResult,
    PluginStatus,
)

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

# MSTG ID extraction regex
MSTG_RE = re.compile(r"\bMSTG-[A-Z]+-\d+\b")


class MSTGToMASVSMapper:
    """
    Maps MSTG test IDs to MASVS control IDs using taxonomy.yaml.

    The taxonomy file defines the relationship:
    - id: MSTG-AUTH-1 (test ID)
      control: MASVS-AUTH-1 (control ID)
    """

    def __init__(self, taxonomy_path: Optional[Path] = None):
        self._mapping: Dict[str, str] = {}
        self._loaded = False
        self._taxonomy_path = taxonomy_path

    def _load_taxonomy(self) -> None:
        """Load MSTG→MASVS mapping from taxonomy.yaml."""
        if self._loaded:
            return

        self._loaded = True

        if not YAML_AVAILABLE:
            logger.debug("PyYAML not available, using fallback mapping")
            self._mapping = self._get_fallback_mapping()
            return

        # Find taxonomy file
        if self._taxonomy_path and self._taxonomy_path.exists():
            taxonomy_file = self._taxonomy_path
        else:
            # Search in standard locations
            candidates = [
                Path(__file__).parent.parent.parent / "compliance/masvs_mstg/taxonomy.yaml",
                Path.cwd() / "compliance/masvs_mstg/taxonomy.yaml",
            ]
            taxonomy_file = None
            for candidate in candidates:
                if candidate.exists():
                    taxonomy_file = candidate
                    break

        if not taxonomy_file or not taxonomy_file.exists():
            logger.debug("taxonomy.yaml not found, using fallback mapping")
            self._mapping = self._get_fallback_mapping()
            return

        try:
            with open(taxonomy_file, "r") as f:
                data = yaml.safe_load(f)

            tests = data.get("tests", [])
            for test in tests:
                mstg_id = test.get("id", "")
                masvs_control = test.get("control", "")
                if mstg_id and masvs_control:
                    self._mapping[mstg_id] = masvs_control

            logger.debug(f"Loaded {len(self._mapping)} MSTG→MASVS mappings from {taxonomy_file}")

        except Exception as e:
            logger.warning(f"Failed to load taxonomy.yaml: {e}, using fallback")
            self._mapping = self._get_fallback_mapping()

    def _get_fallback_mapping(self) -> Dict[str, str]:
        """Fallback MSTG→MASVS mapping when taxonomy.yaml unavailable."""
        # Based on OWASP MASVS 2.0 structure
        return {
            # AUTH
            "MSTG-AUTH-1": "MASVS-AUTH-1",
            "MSTG-AUTH-2": "MASVS-AUTH-2",
            "MSTG-AUTH-3": "MASVS-AUTH-3",
            # STORAGE
            "MSTG-STORAGE-1": "MASVS-STORAGE-1",
            "MSTG-STORAGE-2": "MASVS-STORAGE-2",
            "MSTG-STORAGE-3": "MASVS-STORAGE-1",
            "MSTG-STORAGE-4": "MASVS-STORAGE-1",
            "MSTG-STORAGE-5": "MASVS-STORAGE-1",
            "MSTG-STORAGE-6": "MASVS-STORAGE-1",
            "MSTG-STORAGE-7": "MASVS-STORAGE-2",
            "MSTG-STORAGE-8": "MASVS-STORAGE-2",
            "MSTG-STORAGE-9": "MASVS-STORAGE-2",
            "MSTG-STORAGE-10": "MASVS-STORAGE-2",
            "MSTG-STORAGE-11": "MASVS-STORAGE-2",
            "MSTG-STORAGE-12": "MASVS-STORAGE-2",
            # CRYPTO
            "MSTG-CRYPTO-1": "MASVS-CRYPTO-1",
            "MSTG-CRYPTO-2": "MASVS-CRYPTO-1",
            "MSTG-CRYPTO-3": "MASVS-CRYPTO-2",
            "MSTG-CRYPTO-4": "MASVS-CRYPTO-1",
            "MSTG-CRYPTO-5": "MASVS-CRYPTO-2",
            "MSTG-CRYPTO-6": "MASVS-CRYPTO-2",
            # AUTH (additional)
            "MSTG-AUTH-3": "MASVS-AUTH-3",
            "MSTG-AUTH-5": "MASVS-AUTH-2",
            "MSTG-AUTH-8": "MASVS-AUTH-2",
            # NETWORK
            "MSTG-NETWORK-1": "MASVS-NETWORK-1",
            "MSTG-NETWORK-2": "MASVS-NETWORK-2",
            "MSTG-NETWORK-3": "MASVS-NETWORK-1",
            "MSTG-NETWORK-4": "MASVS-NETWORK-2",
            "MSTG-NETWORK-5": "MASVS-NETWORK-1",
            "MSTG-NETWORK-6": "MASVS-NETWORK-2",
            # PLATFORM
            "MSTG-PLATFORM-1": "MASVS-PLATFORM-1",
            "MSTG-PLATFORM-2": "MASVS-PLATFORM-2",
            "MSTG-PLATFORM-3": "MASVS-PLATFORM-3",
            "MSTG-PLATFORM-4": "MASVS-PLATFORM-1",
            "MSTG-PLATFORM-5": "MASVS-PLATFORM-2",
            "MSTG-PLATFORM-6": "MASVS-PLATFORM-2",
            "MSTG-PLATFORM-7": "MASVS-PLATFORM-2",
            "MSTG-PLATFORM-8": "MASVS-PLATFORM-3",
            "MSTG-PLATFORM-9": "MASVS-PLATFORM-1",
            "MSTG-PLATFORM-10": "MASVS-PLATFORM-2",
            "MSTG-PLATFORM-11": "MASVS-PLATFORM-2",
            # CODE
            "MSTG-CODE-1": "MASVS-CODE-1",
            "MSTG-CODE-2": "MASVS-CODE-2",
            "MSTG-CODE-3": "MASVS-CODE-3",
            "MSTG-CODE-4": "MASVS-CODE-4",
            "MSTG-CODE-5": "MASVS-CODE-1",
            "MSTG-CODE-6": "MASVS-CODE-2",
            "MSTG-CODE-7": "MASVS-CODE-3",
            "MSTG-CODE-8": "MASVS-CODE-4",
            "MSTG-CODE-9": "MASVS-CODE-4",
            # STORAGE (additional)
            "MSTG-STORAGE-12": "MASVS-STORAGE-2",
            # RESILIENCE
            "MSTG-RESILIENCE-1": "MASVS-RESILIENCE-1",
            "MSTG-RESILIENCE-2": "MASVS-RESILIENCE-2",
            "MSTG-RESILIENCE-3": "MASVS-RESILIENCE-3",
            "MSTG-RESILIENCE-4": "MASVS-RESILIENCE-4",
            "MSTG-RESILIENCE-5": "MASVS-RESILIENCE-1",
            "MSTG-RESILIENCE-6": "MASVS-RESILIENCE-3",
            "MSTG-RESILIENCE-12": "MASVS-RESILIENCE-4",
        }

    def map_to_masvs(self, mstg_id: str) -> Optional[str]:
        """Map an MSTG test ID to its corresponding MASVS control ID."""
        self._load_taxonomy()

        # Direct lookup
        if mstg_id in self._mapping:
            return self._mapping[mstg_id]

        # Try to infer from pattern (MSTG-CATEGORY-N → MASVS-CATEGORY-1)
        match = re.match(r"MSTG-([A-Z]+)-(\d+)", mstg_id)
        if match:
            category = match.group(1)
            # Default to control 1 for the category
            return f"MASVS-{category}-1"

        return None

    def map_multiple(self, mstg_ids: List[str]) -> Tuple[Optional[str], List[str]]:
        """
        Map multiple MSTG IDs to a single MASVS control.

        Returns:
            Tuple of (primary MASVS control, list of all mapped MASVS controls)
        """
        masvs_controls = []
        for mstg_id in mstg_ids:
            masvs = self.map_to_masvs(mstg_id)
            if masvs and masvs not in masvs_controls:
                masvs_controls.append(masvs)

        primary = masvs_controls[0] if masvs_controls else None
        return primary, masvs_controls


class SemgrepMastgAnalyzerV2(BasePluginV2):
    """
    Semgrep MASTG Analyzer - BasePluginV2 Implementation

    Runs Semgrep security rules against JADX-decompiled Android sources
    and produces standardized PluginFinding objects with MSTG→MASVS mapping.
    """

    # Known SDK/library path prefixes - findings in these paths are from
    # third-party libraries, not app code.  App developers cannot fix them.
    # NOTE: "com/android/" is NOT included because app packages like
    # "com/android/insecurebankv2/" would be incorrectly filtered.
    _LIBRARY_PATH_PREFIXES = (
        "android/",
        "androidx/",
        "com/google/",
        "com/android/support/",
        "com/android/internal/",
        "com/android/volley/",
        "com/android/billingclient/",
        "kotlin/",
        "kotlinx/",
        "com/squareup/",
        "io/reactivex/",
        "org/apache/",
        "com/facebook/",
        "com/bumptech/",
        "com/fasterxml/",
        "org/jetbrains/",
        "javax/",
        "java/",
        "okhttp3/",
        "retrofit2/",
        "com/airbnb/",
        "dagger/",
        "butterknife/",
        "org/greenrobot/",
        "com/tencent/",
        "com/bytedance/",
        # Ad / attribution SDKs
        "com/applovin/",
        "com/appsflyer/",
        "com/ironsource/",
        "com/mbridge/",
        "com/mintegral/",
        "com/unity3d/",
        "com/chartboost/",
        "com/vungle/",
        "com/inmobi/",
        "com/smaato/",
        "com/adjust/",
        "com/amazon/device/ads/",
        # ByteDance internal SDKs
        "com/ttnet/", "com/lynx/", "com/pgl/", "com/bef/",
        # I/O libraries
        "okio/",
    )

    # Regex to extract attribute name from MSTG-CODE-8 message
    # e.g., 'defines the attribute "f254667Fz" statically' → "f254667Fz"
    # Semgrep interpolates $V into the message; raw `lines` may be "requires login"
    _ATTRIBUTE_NAME_RE = re.compile(r'the attribute "([^"]+)"')

    # Obfuscation detection regex - matches ProGuard/R8-obfuscated names
    _OBFUSCATED_NAME_RE = re.compile(
        r"^(?:"
        r"[a-zA-Z]"                 # Single character (a, B, z)
        r"|[a-z]{2}"                # Two-char lowercase (ab, zz) - R8 dictionary
        r"|f[0-9a-fA-F]{4,}\w*"    # Hex-prefixed (f254667Fz)
        r"|\$\w+"                   # Dollar-prefixed ($values, $serializer)
        r"|lambda\$\w+"             # Synthetic lambda
        r")$"
    )

    # Severity mapping from Semgrep to AODS
    SEVERITY_MAP = {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low",
        "INVENTORY": "info",
    }

    # Confidence mapping from rule metadata to numeric value
    CONFIDENCE_MAP = {
        "HIGH": 0.9,
        "MEDIUM": 0.75,
        "LOW": 0.55,
    }

    def __init__(self, config=None):
        super().__init__(config)
        self._semgrep_path: Optional[str] = None
        self._rules_dir: Optional[Path] = None
        self._custom_rules_dir: Optional[Path] = None
        self._android14_rules_dir: Optional[Path] = None
        self._mstg_mapper = MSTGToMASVSMapper()
        # SARIF output configuration (opt-in via env var)
        self._emit_sarif = os.environ.get("AODS_SEMGREP_EMIT_SARIF", "0") == "1"
        self._sarif_output_dir: Optional[Path] = None
        # Profile configuration
        self._profile_config: Optional[Dict[str, Any]] = None
        self._current_profile: str = os.environ.get("AODS_SCAN_PROFILE", "standard")
        # Cached version info (avoid repeated subprocess calls)
        self._cached_semgrep_version: Optional[str] = None
        self._cached_rules_commit: Optional[str] = None

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="semgrep_mastg_analyzer",
            version="1.0.0",
            description="Semgrep MASTG security analysis for Android applications",
            author="AODS Team",
            capabilities=[
                PluginCapability.STATIC_ANALYSIS,
                PluginCapability.VULNERABILITY_DETECTION,
                PluginCapability.COMPLIANCE_CHECKING,
            ],
            dependencies=[
                PluginDependency(
                    name="semgrep",
                    version_min="1.90.0",
                    optional=True,  # Plugin SKIPs gracefully if missing
                    install_command="pip install semgrep>=1.90.0",
                    description="Semgrep CLI for semantic code analysis",
                )
            ],
            priority=PluginPriority.NORMAL,
            timeout_seconds=540,  # 9 minutes for large codebases (CapCut-class APKs)
            supported_platforms=["linux", "darwin", "win32"],
            tags=["semgrep", "mastg", "owasp", "compliance", "sast"],
            categories=["static_analysis", "compliance"],
        )

    def can_execute(self, apk_ctx) -> Tuple[bool, Optional[str]]:
        """Check if plugin can execute."""
        # Check explicit disable via environment variable
        if os.environ.get("AODS_DISABLE_SEMGREP", "0") == "1":
            return False, "Semgrep disabled via AODS_DISABLE_SEMGREP=1"

        # Check semgrep availability (PATH first, then venv bin dir)
        self._semgrep_path = shutil.which("semgrep")
        if not self._semgrep_path:
            # Fallback: check alongside the current Python interpreter (venv/bin/)
            venv_semgrep = Path(sys.executable).parent / "semgrep"
            if venv_semgrep.is_file() and os.access(venv_semgrep, os.X_OK):
                self._semgrep_path = str(venv_semgrep)
        if not self._semgrep_path:
            return False, "Semgrep CLI not found in PATH (install with: pip install semgrep)"

        # Check rules directory
        self._rules_dir = self._find_rules_directory()
        if not self._rules_dir or not self._rules_dir.exists():
            return (
                False,
                "Semgrep rules directory not found (compliance/semgrep_rules/mastg or external/semgrep-rules-android-security/rules)",  # noqa: E501
            )

        return True, None

    def _find_rules_directory(self) -> Optional[Path]:
        """Find the Semgrep MASTG rules directory."""
        # Check configured custom rules first
        if self._custom_rules_dir and self._custom_rules_dir.exists():
            return self._custom_rules_dir

        # Check environment variable
        env_rules = os.environ.get("AODS_SEMGREP_RULES_DIR")
        if env_rules:
            rules_path = Path(env_rules)
            if rules_path.exists():
                return rules_path

        # Check standard locations (vendored rules first for offline support)
        project_root = Path(__file__).parent.parent.parent
        candidates = [
            # Vendored rules (preferred - works offline)
            project_root / "compliance/semgrep_rules/mastg",
            # External clone (development/update workflow)
            project_root / "external/semgrep-rules-android-security/rules",
            project_root / "external/semgrep-rules-android-security",
            # Legacy path
            project_root / "compliance/semgrep_rules",
            # User-level rules
            Path.home() / ".semgrep/rules/android",
        ]

        for candidate in candidates:
            if candidate.exists():
                return candidate

        return None

    def _load_profile_config(self) -> Dict[str, Any]:
        """Load profile configuration for rule filtering."""
        if self._profile_config is not None:
            return self._profile_config

        # Default configuration
        default_config = {
            "profiles": {
                "lightning": {
                    "enabled_categories": ["storage", "crypto"],
                    "max_rules": 20,
                    "min_confidence": "HIGH",
                },
                "fast": {
                    "enabled_categories": ["storage", "crypto", "network", "auth"],
                    "max_rules": 35,
                    "min_confidence": "MEDIUM",
                },
                "standard": {
                    "enabled_categories": ["storage", "crypto", "network", "auth", "platform", "code", "resilience"],
                    "include_android14": True,
                    "max_rules": 60,
                    "min_confidence": "MEDIUM",
                    "max_findings_per_rule": 3,  # Cap noisy rules to reduce FPs
                },
                "deep": {
                    "enabled_categories": [
                        "storage",
                        "crypto",
                        "network",
                        "auth",
                        "platform",
                        "code",
                        "arch",
                        "resilience",
                    ],
                    "include_android14": True,
                    "include_info_severity": True,
                    "max_rules": None,
                    "min_confidence": None,  # No filtering - keep all findings
                    "max_findings_per_rule": 5,  # Cap noisy rules like MSTG-STORAGE-9
                },
            },
            "category_paths": {
                "storage": "storage/",
                "crypto": "crypto/",
                "network": "network/",
                "auth": "auth/",
                "platform": "platform/",
                "code": "code/",
                "arch": "arch/",
                "resilience": "resilience/",
            },
        }

        # Try to load from file
        if YAML_AVAILABLE:
            config_paths = [
                Path(__file__).parent.parent.parent / "compliance/semgrep_rules/profile_config.yaml",
                Path.cwd() / "compliance/semgrep_rules/profile_config.yaml",
            ]
            for config_path in config_paths:
                if config_path.exists():
                    try:
                        with open(config_path, "r", encoding="utf-8") as f:
                            self._profile_config = yaml.safe_load(f) or default_config
                            logger.debug(f"Loaded profile config from {config_path}")
                            return self._profile_config
                    except Exception as e:
                        logger.warning(f"Failed to load profile config: {e}")

        self._profile_config = default_config
        return self._profile_config

    def _get_enabled_rule_paths(self, apk_ctx=None) -> List[Path]:
        """Get list of rule paths enabled for current profile."""
        config = self._load_profile_config()
        profile = self._current_profile.lower()
        profile_settings = config.get("profiles", {}).get(profile, config["profiles"].get("standard", {}))
        category_paths = config.get("category_paths", {})

        enabled_categories = profile_settings.get("enabled_categories", list(category_paths.keys()))
        include_android14 = profile_settings.get("include_android14", False)

        rule_paths: List[Path] = []

        # Add category-specific rules from main rules dir
        if self._rules_dir and self._rules_dir.exists():
            for category in enabled_categories:
                category_path = category_paths.get(category, f"{category}/")
                full_path = self._rules_dir / category_path
                if full_path.exists():
                    rule_paths.append(full_path)

        # Add Android 14 rules if enabled and available
        if include_android14:
            android14_dir = Path(__file__).parent.parent.parent / "compliance/semgrep_rules/mastg"
            if android14_dir.exists():
                for category in enabled_categories:
                    category_path = android14_dir / category
                    if category_path.exists():
                        # Add individual yaml files
                        for yaml_file in category_path.glob("android-14-*.yaml"):
                            rule_paths.append(yaml_file)

        logger.debug(f"Profile '{profile}' enabled {len(rule_paths)} rule paths for categories: {enabled_categories}")
        return rule_paths

    def execute(self, apk_ctx) -> PluginResult:
        """Execute Semgrep MASTG analysis."""
        start_time = time.time()

        # Preflight checks
        can_exec, reason = self.can_execute(apk_ctx)
        if not can_exec:
            self.logger.info(f"Skipping Semgrep analysis: {reason}")
            return self.create_result(
                status=PluginStatus.SKIPPED,
                error_message=reason,
                metadata={"skip_reason": reason},
            )

        try:
            # Validate versions (warnings only, don't block execution)
            versions_valid, version_warnings, version_info = self._validate_versions()

            # Get JADX decompiled sources path
            sources_path = self._get_sources_path(apk_ctx)
            if not sources_path or not sources_path.exists():
                return self.create_result(
                    status=PluginStatus.SKIPPED,
                    error_message="No JADX decompiled sources available",
                    metadata={"skip_reason": "no_sources", **version_info},
                )

            # Run Semgrep with profile-based filtering
            semgrep_result = self._run_semgrep(sources_path, apk_ctx)

            if semgrep_result.get("status") == "error":
                return self.create_result(
                    status=PluginStatus.FAILURE,
                    error_message=semgrep_result.get("error", "Semgrep execution failed"),
                    metadata=semgrep_result,
                )

            # Convert findings to PluginFinding objects
            findings = self._convert_findings(semgrep_result, apk_ctx)

            # Collect covered MSTG/MASVS IDs
            mstg_ids_covered = set()
            masvs_controls_covered = set()
            for f in findings:
                evidence = f.evidence or {}
                mstg_ids_covered.update(evidence.get("mstg_tests", []))
                if f.masvs_control:
                    masvs_controls_covered.add(f.masvs_control)

            # Get profile info
            profile_config = self._load_profile_config()
            profile_settings = profile_config.get("profiles", {}).get(self._current_profile, {})

            # Build metadata
            metadata = {
                "execution_time": time.time() - start_time,
                "plugin_version": "1.0.0",
                "semgrep_version": self._get_semgrep_version(),
                "rules_path": str(self._rules_dir),
                "sources_path": str(sources_path),
                "raw_findings_count": len(semgrep_result.get("results", [])),
                "converted_findings_count": len(findings),
                "mstg_ids_covered": sorted(mstg_ids_covered),
                "masvs_controls_covered": sorted(masvs_controls_covered),
                # Version validation info
                "versions_valid": versions_valid,
                "version_warnings": version_warnings,
                **version_info,
                # Profile info
                "scan_profile": self._current_profile,
                "profile_categories": profile_settings.get("enabled_categories", []),
                "android14_rules_enabled": profile_settings.get("include_android14", False),
                # SARIF output (if enabled)
                "sarif_enabled": self._emit_sarif,
                "sarif_path": semgrep_result.get("sarif_path"),
            }

            return self.create_result(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata=metadata,
            )

        except Exception as e:
            self.logger.error(f"Semgrep MASTG analysis failed: {e}", exc_info=True)
            return self.create_result(
                status=PluginStatus.FAILURE,
                error_message=str(e),
                metadata={"execution_time": time.time() - start_time},
            )

    def _get_sources_path(self, apk_ctx) -> Optional[Path]:
        """Get path to JADX decompiled sources."""
        candidates = []

        # Standard APKContext locations
        if hasattr(apk_ctx, "jadx_output_dir") and apk_ctx.jadx_output_dir:
            jadx_dir = Path(apk_ctx.jadx_output_dir)
            candidates.append(jadx_dir / "sources")
            candidates.append(jadx_dir)

        if hasattr(apk_ctx, "decompiled_apk_dir") and apk_ctx.decompiled_apk_dir:
            decompiled = Path(apk_ctx.decompiled_apk_dir)
            candidates.append(decompiled / "sources")
            candidates.append(decompiled / "jadx_output" / "sources")
            candidates.append(decompiled)

        if hasattr(apk_ctx, "output_dir") and apk_ctx.output_dir:
            candidates.append(Path(apk_ctx.output_dir) / "sources")

        # Additional attribute names used in AODS
        if hasattr(apk_ctx, "jadx_sources_path") and apk_ctx.jadx_sources_path:
            jadx_path = Path(apk_ctx.jadx_sources_path)
            candidates.append(jadx_path / "sources")
            candidates.append(jadx_path)

        if hasattr(apk_ctx, "decompiled_dir") and apk_ctx.decompiled_dir:
            decompiled = Path(apk_ctx.decompiled_dir)
            candidates.append(decompiled / "sources")
            candidates.append(decompiled)

        # Check workspace directory for APK-named decompiled folders
        if hasattr(apk_ctx, "apk_path") and apk_ctx.apk_path:
            apk_name = Path(apk_ctx.apk_path).stem
            project_root = Path(__file__).parent.parent.parent
            workspace_candidates = [
                project_root / "workspace" / f"{apk_name}_decompiled",
                project_root / "workspace" / apk_name,
                project_root / f"workspace/{apk_name}_decompiled/sources",
            ]
            candidates.extend(workspace_candidates)

        # Check candidates - resolve() to follow symlinks (semgrep rejects
        # relative symlink paths with "Invalid scanning root")
        for candidate in candidates:
            if candidate.exists() and self._has_java_files(candidate):
                resolved = candidate.resolve()
                self.logger.debug(f"Found JADX sources at: {resolved}")
                return resolved

        self.logger.warning(f"No JADX sources found. Checked: {[str(c) for c in candidates[:5]]}...")
        return None

    def _has_java_files(self, path: Path) -> bool:
        """Check if directory contains Java files."""
        try:
            for _ in path.rglob("*.java"):
                return True
        except Exception:
            pass
        return False

    def _run_semgrep(self, sources_path: Path, apk_ctx=None) -> Dict[str, Any]:
        """Run Semgrep and return JSON results with profile-based filtering."""
        if not self._semgrep_path or not self._rules_dir:
            return {"status": "error", "error": "Semgrep or rules not configured", "results": []}

        # Get enabled rule paths based on profile
        rule_paths = self._get_enabled_rule_paths(apk_ctx)

        # Build command with multiple --config options for profile filtering
        cmd = [
            self._semgrep_path,
        ]

        # Add rule paths (use profile-based filtering if available, otherwise default)
        if rule_paths:
            for rule_path in rule_paths:
                cmd.extend(["--config", str(rule_path)])
            logger.info(f"Running Semgrep with {len(rule_paths)} rule paths (profile: {self._current_profile})")
        else:
            # Fallback to full rules directory
            cmd.extend(["--config", str(self._rules_dir)])
            logger.info("Running Semgrep with full rules directory (no profile filtering)")

        cmd.extend(
            [
                "--json",
                "--metrics=off",
                "--no-git-ignore",  # Scan all files, even if not in git or ignored
                "--timeout",
                "60",  # Per-rule timeout
                str(sources_path),
            ]
        )

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=480,  # Global timeout (large APKs need more time)
            )

            if result.stdout:
                try:
                    json_result = json.loads(result.stdout)

                    # Generate SARIF output if enabled
                    if self._emit_sarif:
                        sarif_path = self._generate_sarif_output(sources_path)
                        if sarif_path:
                            json_result["sarif_path"] = str(sarif_path)

                    return json_result
                except json.JSONDecodeError as e:
                    return {
                        "status": "error",
                        "error": f"Invalid JSON output: {e}",
                        "results": [],
                    }
            else:
                return {
                    "status": "error",
                    "error": result.stderr[:1000] if result.stderr else f"Exit code: {result.returncode}",
                    "results": [],
                }

        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "Semgrep execution timed out (240s)", "results": []}
        except Exception as e:
            return {"status": "error", "error": str(e), "results": []}

    def _generate_sarif_output(self, sources_path: Path) -> Optional[Path]:
        """Generate SARIF output file for CI/security dashboard integration."""
        if not self._semgrep_path or not self._rules_dir:
            return None

        # Determine output directory
        if self._sarif_output_dir:
            output_dir = self._sarif_output_dir
        else:
            project_root = Path(__file__).parent.parent.parent
            output_dir = project_root / "reports"

        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate timestamped filename
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        sarif_path = output_dir / f"semgrep_mastg_{timestamp}.sarif"

        cmd = [
            self._semgrep_path,
            "--config",
            str(self._rules_dir),
            "--sarif",
            "--metrics=off",
            "--no-git-ignore",
            "--timeout",
            "60",
            "-o",
            str(sarif_path),
            str(sources_path),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=480,
            )

            if sarif_path.exists():
                self.logger.info(f"SARIF output written to: {sarif_path}")
                return sarif_path
            else:
                self.logger.warning(
                    f"SARIF generation failed: {result.stderr[:500] if result.stderr else 'unknown error'}"
                )
                return None

        except subprocess.TimeoutExpired:
            self.logger.warning("SARIF generation timed out")
            return None
        except Exception as e:
            self.logger.warning(f"SARIF generation failed: {e}")
            return None

    def set_sarif_output_dir(self, output_dir: str) -> None:
        """Set custom SARIF output directory."""
        self._sarif_output_dir = Path(output_dir)

    # Minimum confidence thresholds (maps profile min_confidence → set of accepted levels)
    _CONFIDENCE_THRESHOLDS = {
        "HIGH": {"HIGH"},
        "MEDIUM": {"HIGH", "MEDIUM"},
        "LOW": {"HIGH", "MEDIUM", "LOW"},
    }

    def _convert_findings(self, semgrep_result: Dict[str, Any], apk_ctx) -> List[PluginFinding]:
        """Convert Semgrep JSON results to PluginFinding objects."""
        findings = []
        results = semgrep_result.get("results", [])
        library_skipped = 0
        obfuscation_skipped = 0
        confidence_skipped = 0
        rule_cap_skipped = 0

        # Load profile settings for confidence filtering
        profile_config = self._load_profile_config()
        profile_settings = profile_config.get("profiles", {}).get(
            self._current_profile, profile_config["profiles"].get("standard", {})
        )
        min_confidence = profile_settings.get("min_confidence")
        accepted_confidences = self._CONFIDENCE_THRESHOLDS.get(min_confidence) if min_confidence else None
        max_per_rule = profile_settings.get("max_findings_per_rule")

        # Deduplicate by (rule_id, path, line)
        seen_keys: Set[Tuple[str, str, int]] = set()
        # Per-rule finding counter (for max_findings_per_rule cap)
        rule_counts: Dict[str, int] = {}

        for i, result in enumerate(results):
            check_id = result.get("check_id", "")
            path = result.get("path", "")
            start = result.get("start", {})
            line = start.get("line", 0)

            # Dedup key
            key = (check_id, path, line)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            # Filter out SDK/library code findings
            sanitized_early = self._sanitize_path(path, apk_ctx)
            if any(sanitized_early.startswith(prefix) for prefix in self._LIBRARY_PATH_PREFIXES):
                library_skipped += 1
                continue

            # Overwrite path with already-sanitized version to avoid double work
            path = sanitized_early

            # Extract metadata
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})
            message = extra.get("message", "")
            severity_raw = extra.get("severity", "WARNING")
            lines = extra.get("lines", "")

            # Filter obfuscated field names in MSTG-CODE-8 findings
            # ProGuard/R8 obfuscation creates meaningless field names that trigger
            # MSTG-CODE-8 (memory management) rules as false positives.
            # Extract variable name from message (semgrep interpolates $V there;
            # raw `lines` may be "requires login" due to Semgrep Pro gating)
            if "MSTG-CODE-8" in check_id and message:
                attr_match = self._ATTRIBUTE_NAME_RE.search(message)
                if attr_match and self._is_obfuscated_field_name(attr_match.group(1)):
                    obfuscation_skipped += 1
                    continue

            # Confidence-based filtering: skip LOW confidence findings for non-deep profiles
            rule_confidence = str(metadata.get("confidence", "")).upper()
            if accepted_confidences and rule_confidence and rule_confidence not in accepted_confidences:
                confidence_skipped += 1
                continue

            # Per-rule finding cap (prevents noisy rules from dominating results)
            # HIGH-confidence rules are exempt - they represent reliable detections
            # that legitimately match across multiple files (e.g., MSTG-CRYPTO-4).
            if max_per_rule and rule_confidence != "HIGH":
                rule_counts[check_id] = rule_counts.get(check_id, 0) + 1
                if rule_counts[check_id] > max_per_rule:
                    rule_cap_skipped += 1
                    continue

            # Extract MSTG IDs
            mstg_ids = self._extract_mstg_ids(result)

            # Map MSTG to MASVS
            primary_masvs, all_masvs = self._mstg_mapper.map_multiple(mstg_ids)

            # Extract CWE IDs
            cwe_ids = self._extract_cwe_ids(metadata)

            # Map severity
            severity = self.SEVERITY_MAP.get(severity_raw.upper(), "medium")

            # Map confidence to numeric value (default 0.85 if not specified)
            confidence = self.CONFIDENCE_MAP.get(rule_confidence, 0.85)

            # Build finding (path already sanitized above for library filter)
            finding = PluginFinding(
                finding_id=f"semgrep_mastg_{i:04d}",
                title=self._build_title(check_id, mstg_ids, message),
                description=message,
                severity=severity,
                confidence=confidence,
                file_path=path,
                line_number=line,
                code_snippet=lines[:500] if lines and not self._is_placeholder_snippet(lines) else None,
                vulnerability_type=self._infer_vulnerability_type(check_id, message),
                cwe_id=cwe_ids[0] if cwe_ids else None,
                owasp_category=self._map_to_owasp_category(mstg_ids),
                masvs_control=primary_masvs,  # MASVS control, not MSTG ID
                evidence={
                    "rule_id": check_id,
                    "semgrep_severity": severity_raw,
                    "rule_confidence": rule_confidence,
                    "mstg_tests": mstg_ids,  # Store MSTG IDs here for audit
                    "masvs_controls": all_masvs,
                    "cwe_ids": cwe_ids,
                    "column": start.get("col", 0),
                    "end_line": result.get("end", {}).get("line", line),
                    "metadata": metadata,
                },
                remediation=metadata.get("fix", metadata.get("recommendation", "")),
                references=self._build_references(metadata, mstg_ids, cwe_ids),
            )

            findings.append(finding)

        # Log filtering stats
        if library_skipped:
            logger.info(f"Filtered {library_skipped} findings from SDK/library code paths")
        if obfuscation_skipped:
            logger.info(f"Filtered {obfuscation_skipped} MSTG-CODE-8 findings from obfuscated field names")
        if confidence_skipped:
            logger.info(
                f"Filtered {confidence_skipped} LOW-confidence findings "
                f"(profile={self._current_profile}, min_confidence={min_confidence})"
            )
        if rule_cap_skipped:
            logger.info(f"Capped {rule_cap_skipped} findings exceeding {max_per_rule}/rule limit")

        return findings

    def _extract_mstg_ids(self, result: Dict[str, Any]) -> List[str]:
        """Extract MSTG IDs from Semgrep result."""
        ids: Set[str] = set()

        # From metadata
        meta = result.get("extra", {}).get("metadata", {})
        for key in ("mastg_id", "mstg_id", "MSTG", "owasp-mastg"):
            val = meta.get(key)
            if isinstance(val, str):
                ids.update(MSTG_RE.findall(val))
            elif isinstance(val, list):
                for v in val:
                    if isinstance(v, str):
                        ids.update(MSTG_RE.findall(v))

        # From message
        message = result.get("extra", {}).get("message", "")
        ids.update(MSTG_RE.findall(message))

        # From check_id
        check_id = result.get("check_id", "")
        ids.update(MSTG_RE.findall(check_id))

        return sorted(ids)

    def _extract_cwe_ids(self, metadata: Dict[str, Any]) -> List[str]:
        """Extract CWE IDs from metadata."""
        cwe_ids = []
        cwe = metadata.get("cwe", [])

        if isinstance(cwe, str):
            match = re.search(r"CWE-?(\d+)", cwe, re.IGNORECASE)
            if match:
                cwe_ids.append(f"CWE-{match.group(1)}")
        elif isinstance(cwe, list):
            for c in cwe:
                if isinstance(c, str):
                    match = re.search(r"CWE-?(\d+)", c, re.IGNORECASE)
                    if match:
                        cwe_ids.append(f"CWE-{match.group(1)}")

        return cwe_ids

    @staticmethod
    def _is_placeholder_snippet(snippet: str) -> bool:
        """Reject non-code placeholder strings that semgrep sometimes returns."""
        s = snippet.strip().lower()
        return s in ("requires login", "login required", "") or len(s) < 3

    @staticmethod
    def _is_obfuscated_field_name(name: str) -> bool:
        """Check if a field/variable name looks like ProGuard/R8 obfuscation."""
        if not name:
            return False
        return bool(SemgrepMastgAnalyzerV2._OBFUSCATED_NAME_RE.match(name))

    def _build_title(self, check_id: str, mstg_ids: List[str], message: str = "") -> str:
        """Build a descriptive title from rule message, ID, and MSTG IDs."""
        # Prefer human-readable message from semgrep rule
        if message and len(message) > 10:
            # Use first sentence only for title brevity
            first_sentence = message.split(". ")[0].rstrip(".")
            name = first_sentence
            if len(name) > 70:
                # Truncate at word boundary to avoid mid-word cuts
                truncated = name[:67]
                last_space = truncated.rfind(" ")
                if last_space > 40:
                    truncated = truncated[:last_space]
                name = truncated + "..."
        else:
            # Fallback: convert rule ID to readable title
            parts = check_id.split(".")
            if parts:
                name = parts[-1].replace("-", " ").replace("_", " ").title()
            else:
                name = check_id

        if mstg_ids:
            return f"{mstg_ids[0]}: {name}"
        return name

    def _infer_vulnerability_type(self, check_id: str, message: str) -> str:
        """Infer vulnerability type from rule ID and message."""
        content = f"{check_id} {message}".lower()

        if "crypto" in content or "cipher" in content or "encrypt" in content:
            return "cryptographic_weakness"
        elif "sql" in content or "injection" in content:
            return "injection"
        elif "hardcoded" in content or "secret" in content or "key" in content:
            return "hardcoded_credentials"
        elif "network" in content or "cleartext" in content or "tls" in content:
            return "insecure_network"
        elif "storage" in content or "file" in content:
            return "insecure_storage"
        elif "webview" in content:
            return "webview_vulnerability"
        elif "auth" in content:
            return "authentication_weakness"

        return "security_misconfiguration"

    def _map_to_owasp_category(self, mstg_ids: List[str]) -> str:
        """Map to OWASP Mobile category based on MSTG IDs."""
        if not mstg_ids:
            return "MASVS-CODE"

        # Extract category from first MSTG ID
        match = re.match(r"MSTG-([A-Z]+)-", mstg_ids[0])
        if match:
            category = match.group(1)
            return f"MASVS-{category}"

        return "MASVS-CODE"

    def _sanitize_path(self, path: str, apk_ctx) -> str:
        """Sanitize file path to remove absolute path prefix."""
        if not path:
            return path

        # Remove common absolute path prefixes
        prefixes_to_remove = []

        if hasattr(apk_ctx, "jadx_output_dir") and apk_ctx.jadx_output_dir:
            prefixes_to_remove.append(str(apk_ctx.jadx_output_dir))
        if hasattr(apk_ctx, "decompiled_apk_dir") and apk_ctx.decompiled_apk_dir:
            prefixes_to_remove.append(str(apk_ctx.decompiled_apk_dir))
        if hasattr(apk_ctx, "output_dir") and apk_ctx.output_dir:
            prefixes_to_remove.append(str(apk_ctx.output_dir))

        # Add workspace-based prefixes if apk_path available
        if hasattr(apk_ctx, "apk_path") and apk_ctx.apk_path:
            apk_name = Path(apk_ctx.apk_path).stem
            project_root = Path(__file__).parent.parent.parent
            prefixes_to_remove.extend(
                [
                    str(project_root / "workspace" / f"{apk_name}_decompiled"),
                    str(project_root / "workspace" / apk_name),
                    str(project_root / "workspace"),
                ]
            )

        # Sort by length descending to match longest prefix first
        prefixes_to_remove.sort(key=len, reverse=True)

        for prefix in prefixes_to_remove:
            if path.startswith(prefix):
                path = path[len(prefix) :].lstrip("/\\")
                break

        # Also try to extract just the Java package path
        # e.g., /tmp/jadx/sources/com/example/App.java → com/example/App.java
        sources_idx = path.find("/sources/")
        if sources_idx != -1:
            path = path[sources_idx + len("/sources/") :]

        # Remove "resources/" prefix for AndroidManifest.xml etc.
        if path.startswith("resources/"):
            pass  # Keep resources/ prefix for clarity

        return path

    def _build_references(self, metadata: Dict[str, Any], mstg_ids: List[str], cwe_ids: List[str]) -> List[str]:
        """Build reference URLs."""
        refs = []

        # Add metadata references
        if "references" in metadata:
            ref_data = metadata["references"]
            if isinstance(ref_data, list):
                refs.extend(ref_data)
            elif isinstance(ref_data, str):
                refs.append(ref_data)

        # Add MSTG references
        for mstg_id in mstg_ids:
            refs.append(f"https://mas.owasp.org/MASTG/tests/{mstg_id}/")

        # Add CWE references
        for cwe_id in cwe_ids:
            num = cwe_id.replace("CWE-", "")
            refs.append(f"https://cwe.mitre.org/data/definitions/{num}.html")

        # Deduplicate while preserving order
        return list(dict.fromkeys(refs))

    def _get_semgrep_version(self) -> str:
        """Get Semgrep CLI version (cached after first call)."""
        if self._cached_semgrep_version is not None:
            return self._cached_semgrep_version
        if not self._semgrep_path:
            self._cached_semgrep_version = "unknown"
            return self._cached_semgrep_version
        try:
            result = subprocess.run(
                [self._semgrep_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self._cached_semgrep_version = result.stdout.strip().split("\n")[0]
        except Exception:
            self._cached_semgrep_version = "unknown"
        return self._cached_semgrep_version

    def _load_pinned_versions(self) -> Dict[str, Any]:
        """Load pinned versions from versions.yaml."""
        if not YAML_AVAILABLE:
            return {}

        project_root = Path(__file__).parent.parent.parent
        versions_file = project_root / "compliance/masvs_mstg/versions.yaml"

        if not versions_file.exists():
            return {}

        try:
            with open(versions_file, "r") as f:
                data = yaml.safe_load(f)
            return data.get("semgrep_rules", {})
        except Exception as e:
            self.logger.debug(f"Failed to load versions.yaml: {e}")
            return {}

    def _version_satisfies(self, current: str, minimum: str) -> bool:
        """Check if current version satisfies minimum requirement."""
        if current == "unknown":
            return False

        try:
            # Parse version strings (handle formats like "1.90.0" or "1.149.0")
            def parse_version(v: str) -> List[int]:
                # Extract just the version number part
                v = v.strip()
                # Handle formats like "1.90.0" or "semgrep 1.90.0"
                parts = v.split()
                version_str = parts[-1] if parts else v
                return [int(x) for x in version_str.split(".")[:3]]

            current_parts = parse_version(current)
            minimum_parts = parse_version(minimum)

            # Pad with zeros for comparison
            while len(current_parts) < 3:
                current_parts.append(0)
            while len(minimum_parts) < 3:
                minimum_parts.append(0)

            return current_parts >= minimum_parts
        except (ValueError, IndexError):
            # If we can't parse, assume it's OK
            return True

    def _get_rules_commit(self) -> Optional[str]:
        """Get git commit hash of rules directory if it's a git repo (cached)."""
        if self._cached_rules_commit is not None:
            return self._cached_rules_commit if self._cached_rules_commit != "" else None
        if not self._rules_dir:
            self._cached_rules_commit = ""
            return None

        # Check if rules dir is inside a git repo
        git_dir = self._rules_dir
        while git_dir != git_dir.parent:
            if (git_dir / ".git").exists():
                break
            git_dir = git_dir.parent
        else:
            # Not a git repo (vendored rules)
            self._cached_rules_commit = ""
            return None

        try:
            result = subprocess.run(
                ["git", "-C", str(git_dir), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                self._cached_rules_commit = result.stdout.strip()
                return self._cached_rules_commit
        except Exception:
            pass
        self._cached_rules_commit = ""
        return None

    def _validate_versions(self) -> Tuple[bool, List[str], Dict[str, Any]]:
        """
        Validate Semgrep CLI and rules versions against pinned requirements.

        Returns:
            Tuple of (is_valid, warnings, version_info)
            - is_valid: True if all versions match
            - warnings: List of warning messages for mismatches
            - version_info: Dict with version details for metadata
        """
        warnings = []
        pinned = self._load_pinned_versions()

        # Get current versions
        current_cli = self._get_semgrep_version()
        current_rules_commit = self._get_rules_commit()

        # Build version info for metadata
        version_info = {
            "semgrep_cli_version": current_cli,
            "rules_commit": current_rules_commit,
            "pinned_cli_version": pinned.get("semgrep_cli_version", "1.90.0"),
            "pinned_rules_commit": pinned.get("pinned_commit"),
            "rules_source": "vendored" if current_rules_commit is None else "external",
        }

        # Check CLI version
        min_version = pinned.get("semgrep_cli_version", "1.90.0")
        if not self._version_satisfies(current_cli, min_version):
            warnings.append(f"Semgrep CLI {current_cli} < {min_version} minimum required")

        # Check rules commit (only if using git-cloned rules, not vendored)
        pinned_commit = pinned.get("pinned_commit")
        if current_rules_commit and pinned_commit:
            if current_rules_commit != pinned_commit:
                warnings.append(f"Rules commit {current_rules_commit[:8]} != pinned {pinned_commit[:8]}")
                version_info["rules_commit_mismatch"] = True

        # Log warnings
        for warning in warnings:
            self.logger.warning(f"Version validation: {warning}")

        return len(warnings) == 0, warnings, version_info

    def set_custom_rules_dir(self, rules_dir: str) -> None:
        """Set custom rules directory."""
        self._custom_rules_dir = Path(rules_dir)


def create_plugin() -> SemgrepMastgAnalyzerV2:
    """Create plugin instance."""
    return SemgrepMastgAnalyzerV2()


__all__ = ["SemgrepMastgAnalyzerV2", "create_plugin"]
