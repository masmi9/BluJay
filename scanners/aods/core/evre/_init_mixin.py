"""Initialization methods - __init__, source discovery, indexing, manifest loading."""

import os
import re
import glob
from pathlib import Path
from typing import Dict, List, Any

from core.evre._dynamic_package_filter import DynamicPackageFilter


class InitMixin:
    """Engine initialization, source discovery, and indexing."""

    def __init__(self, apk_path: str, target_package: str = None):
        """
        Initialize the Enhanced Vulnerability Reporting Engine.

        Sets up the reporting engine with APK analysis context, initializes
        vulnerability detection patterns, remediation templates, and locates
        decompiled source files for analysis.

        Args:
            apk_path (str): Path to the APK file being analyzed.
            target_package (Optional[str]): Android package name (e.g., 'com.example.app').
        """
        self.apk_path = apk_path
        self.target_package = target_package or self._extract_package_from_apk()
        self.decompiled_path = ""
        self.source_files = {}
        self.manifest_content = ""

        # Initialize logger (structlog with stdlib fallback)
        try:
            from core.logging_config import get_logger

            self.logger = get_logger(__name__)
        except ImportError:
            import logging as stdlib_logging

            self.logger = stdlib_logging.getLogger(__name__)

        # Initialize patterns and templates
        self._init_vulnerability_patterns()
        self._init_remediation_templates()
        self._init_html_templates()

        # Find and index decompiled sources with enhanced discovery
        self._locate_decompiled_sources()
        self._locate_apk_context_sources()

        # **DUPLICATE DETECTION FIX**: Track used vulnerability IDs to ensure uniqueness
        self._used_vulnerability_ids = set()
        self._id_counter = 0

    def _extract_package_from_apk(self) -> str:
        """Extract package name from APK file path or content"""
        # Primary: Check if we have a proper package name from APK context
        if (
            hasattr(self, "apk_ctx")
            and self.apk_ctx
            and hasattr(self.apk_ctx, "package_name")
            and self.apk_ctx.package_name
        ):
            return self.apk_ctx.package_name

        # Secondary: Try to extract from APK manifest or metadata
        try:
            if hasattr(self, "apk_ctx") and self.apk_ctx and hasattr(self.apk_ctx, "analyzer"):
                analyzer = self.apk_ctx.analyzer
                if analyzer and hasattr(analyzer, "get_package_name"):
                    package_name = analyzer.get_package_name()
                    if package_name:
                        return package_name
        except Exception as e:
            self.logger.debug(f"Could not extract package name from APK: {e}")

        # Tertiary: Generate a generic package name based on APK filename
        apk_filename = os.path.basename(self.apk_path)
        clean_name = os.path.splitext(apk_filename)[0]
        clean_name = re.sub(r"[^a-zA-Z0-9]", "", clean_name).lower()

        if clean_name:
            return f"com.analyzed.{clean_name}"

        # Ultimate fallback
        return "com.analyzed.unknown"

    def _locate_decompiled_sources(self):
        """Find the decompiled source directory, prioritizing JADX Java sources over smali"""
        # Priority 1: Look for JADX Java sources in workspace (no /tmp heuristics)
        jadx_java_paths = []

        # Look for workspace decompiled directories with Java sources
        workspace_pattern = os.path.join(os.getcwd(), "workspace", "*_decompiled")
        for ws_dir in glob.glob(workspace_pattern):
            if os.path.isdir(ws_dir):
                java_count = sum(1 for root, _dirs, files in os.walk(ws_dir) for f in files if f.endswith(".java"))
                if java_count > 0:
                    jadx_java_paths.append((ws_dir, java_count))

        # Priority 2: Check workspace decompiled directories (smali fallback)
        workspace_smali_paths = []
        workspace_pattern = os.path.join(os.getcwd(), "workspace", "*_decompiled")
        for workspace_dir in glob.glob(workspace_pattern):
            if os.path.isdir(workspace_dir):
                smali_count = 0
                for root, dirs, files in os.walk(workspace_dir):
                    for file in files:
                        if file.endswith(".smali"):
                            full_path = os.path.join(root, file)
                            security_keywords = [
                                "insecure",
                                "storage",
                                "crypto",
                                "logging",
                                "sql",
                                "security",
                                "auth",
                                "network",
                                "session",
                                "password",
                                "secret",
                                "key",
                                "database",
                                "login",
                                "vulnerability",
                            ]
                            if any(keyword in full_path.lower() for keyword in security_keywords):
                                smali_count += 1
                            elif any(
                                pattern in file.lower() for pattern in ["activity", "service", "provider", "helper"]
                            ):
                                smali_count += 0.5
                if smali_count > 0:
                    workspace_smali_paths.append((workspace_dir, int(smali_count)))

        # Find the best JADX source path first
        best_path = None
        max_files = 0
        source_type = "unknown"

        # Prioritize JADX Java sources
        if jadx_java_paths:
            jadx_java_paths.sort(key=lambda x: x[1], reverse=True)
            for path, java_count in jadx_java_paths:
                security_file_count = 0
                try:
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            if file.endswith(".java"):
                                security_keywords = [
                                    "insecure",
                                    "storage",
                                    "crypto",
                                    "logging",
                                    "sql",
                                    "security",
                                    "auth",
                                    "network",
                                    "session",
                                    "password",
                                    "secret",
                                    "key",
                                    "database",
                                    "login",
                                    "vulnerability",
                                ]
                                if any(keyword in file.lower() for keyword in security_keywords):
                                    security_file_count += 1
                                elif any(
                                    pattern in file.lower() for pattern in ["activity", "service", "provider", "helper"]
                                ):
                                    security_file_count += 0.5
                        if len(root.split(os.sep)) - len(path.split(os.sep)) > 3:
                            break
                except Exception:
                    continue

                if security_file_count > max_files:
                    max_files = security_file_count
                    best_path = path
                    source_type = "Java (JADX)"

        # Fall back to workspace smali files if no Java sources found
        if not best_path and workspace_smali_paths:
            workspace_smali_paths.sort(key=lambda x: x[1], reverse=True)
            best_path = workspace_smali_paths[0][0]
            max_files = workspace_smali_paths[0][1]
            source_type = "Smali (workspace)"

        if best_path:
            self.decompiled_path = best_path
            self.logger.info(
                "Found decompiled sources",
                source_type=source_type,
                security_related_files=int(max_files),
                decompiled_path=self.decompiled_path,
            )
            self._index_source_files()
            self._load_manifest()
        else:
            self.logger.info("Decompiled sources not found - using content analysis mode")

    def _index_source_files(self, source_dir: str = None):
        """Index all Java/Kotlin/Smali source files for code extraction, prioritizing app files over library files"""
        target_dir = source_dir or self.decompiled_path
        if not target_dir:
            return

        java_files = 0
        smali_files = 0
        app_files = 0
        library_files = 0

        target_package_dirs = []
        if self.target_package:
            target_package_dirs = [
                self.target_package.replace(".", "/"),
                self.target_package.replace(".", "\\"),
                self.target_package.split(".")[-1],
            ]

        all_file_paths = []
        structure_stats = {"depths": [], "app_files": []}

        dynamic_filter = DynamicPackageFilter(
            target_package=self.target_package,
            app_structure={
                "common_prefixes": [],
                "app_keywords": [],
                "average_depth": 3,
                "depth_variance": 2,
                "main_clusters": [],
                "common_patterns": [],
                "package_hierarchy": {},
            },
            logger=self.logger,
        )

        for root, dirs, files in os.walk(target_dir):
            for file in files:
                if file.endswith((".java", ".kt", ".smali")):
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, target_dir).replace("\\", "/")

                    all_file_paths.append(relative_path)
                    structure_stats["depths"].append(relative_path.count("/"))

                    target_package_path = self.target_package.replace(".", "/")
                    if target_package_path in relative_path:
                        structure_stats["app_files"].append(relative_path)

                    file_classification = dynamic_filter.classify_file(file_path, relative_path)

                    category = file_classification["category"]
                    confidence = file_classification["confidence"]
                    should_include = file_classification["should_include"]

                    self.logger.debug(f"File: {relative_path}")
                    self.logger.debug(f"   Category: {category}, Confidence: {confidence:.2f}")
                    self.logger.debug(f"   Reasons: {', '.join(file_classification['reasons'])}")

                    if category == "cross_apk" and not should_include:
                        library_files += 1
                        self.logger.debug(f"Excluding low-confidence cross-APK file: {relative_path}")
                        continue

                    is_app_file = category == "app"
                    is_third_party_library = category == "library"
                    is_system_framework = category == "framework"
                    priority_score = file_classification["priority"]

                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()

                            file_info = {
                                "path": relative_path,
                                "full_path": file_path,
                                "content": content,
                                "lines": content.split("\n"),
                                "file_type": "java" if file.endswith((".java", ".kt")) else "smali",
                                "is_app_file": is_app_file,
                                "is_third_party_library": is_third_party_library,
                                "is_system_framework": is_system_framework,
                                "is_library_file": is_third_party_library or is_system_framework,
                                "priority_score": priority_score,
                                "classification": file_classification,
                            }

                            self.source_files[file] = file_info
                            self.source_files[relative_path] = file_info
                            self.source_files[file_path] = file_info

                            if file.endswith(".java"):
                                class_name = file.replace(".java", "")
                                self.source_files[class_name] = file_info

                                if any(
                                    target_pattern in relative_path
                                    for target_pattern in target_package_dirs
                                    if target_pattern
                                ):
                                    package_class = relative_path.replace("/", ".").replace(".java", "")
                                    self.source_files[package_class] = file_info

                            if file.endswith((".java", ".kt")):
                                java_files += 1
                            else:
                                smali_files += 1

                            if is_app_file:
                                app_files += 1

                    except Exception as e:
                        self.logger.warning("Could not read file", file_path=file_path, error=str(e))

        file_summary = []
        if java_files > 0:
            file_summary.append(f"{java_files} Java")
        if smali_files > 0:
            file_summary.append(f"{smali_files} Smali")

        if all_file_paths:
            enhanced_structure = self._build_enhanced_structure_from_stats(structure_stats, all_file_paths)
            dynamic_filter.app_structure.update(enhanced_structure)
            self.logger.debug(
                f"Enhanced structure analysis: {len(all_file_paths)} files, avg depth: {enhanced_structure.get('average_depth', 3):.1f}"  # noqa: E501
            )

        self.logger.info(
            "Indexed source files",
            total=len(self.source_files),
            file_types=", ".join(file_summary),
            app_files=app_files,
            library_files_filtered=library_files,
        )
        self.logger.info("Target package", target_package=self.target_package)

    def _load_manifest(self):
        """Load AndroidManifest.xml content"""
        if not self.decompiled_path:
            return

        manifest_paths = [
            os.path.join(os.path.dirname(self.decompiled_path), "AndroidManifest.xml"),
            os.path.join(self.decompiled_path, "AndroidManifest.xml"),
            os.path.join(self.decompiled_path, "..", "AndroidManifest.xml"),
        ]

        for manifest_path in manifest_paths:
            if os.path.exists(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
                        self.manifest_content = f.read()
                    self.logger.info("Loaded AndroidManifest.xml")
                    break
                except Exception as e:
                    self.logger.warning("Could not read manifest", manifest_path=manifest_path, error=str(e))

    def _has_fileprovider_configured(self) -> bool:
        """Return True if AndroidManifest declares a FileProvider provider."""
        try:
            manifest_text = self.manifest_content or ""
            if not isinstance(manifest_text, str) or not manifest_text:
                return False
            return bool(
                re.search(
                    r"<provider[^>]+android:name\s*=\s*['\"](?:androidx\.core\.content\.FileProvider|android\.support\.v4\.content\.FileProvider)['\"]",  # noqa: E501
                    manifest_text,
                    re.IGNORECASE,
                )
            )
        except Exception:
            return False

    def _locate_apk_context_sources(self):
        """
        **FIX**: Enhanced source discovery to find APKContext workspace sources
        """
        workspace_pattern = os.path.join(os.getcwd(), "workspace", "*_decompiled")
        for workspace_dir in glob.glob(workspace_pattern):
            if os.path.isdir(workspace_dir):
                java_count = 0
                for root, dirs, files in os.walk(workspace_dir):
                    for file in files:
                        if file.endswith(".java"):
                            java_count += 1

                if java_count > 0 and len(self.source_files) == 0:
                    self.logger.info("Found APKContext sources", java_count=java_count, workspace_dir=workspace_dir)
                    self.decompiled_path = workspace_dir
                    self._index_source_files(workspace_dir)
                    break

    def _build_enhanced_structure_from_stats(self, structure_stats: Dict, all_file_paths: List[str]) -> Dict[str, Any]:
        """
        **SIMPLIFIED STRUCTURE ENHANCEMENT**: Basic stats only for performance
        """
        enhanced_structure = {}

        try:
            depths = structure_stats.get("depths", [])
            if depths:
                enhanced_structure["average_depth"] = sum(depths) / len(depths)
                enhanced_structure["depth_variance"] = 2.0

            app_files = structure_stats.get("app_files", [])
            if app_files:
                enhanced_structure["app_file_count"] = len(app_files)

        except Exception as e:
            self.logger.warning(f"Structure enhancement failed: {e}")

        return enhanced_structure

    def _init_remediation_templates(self):
        """Initialize OWASP remediation templates from YAML config file."""
        import yaml

        config_path = Path(__file__).parent.parent.parent / "config" / "owasp_remediation_templates.yaml"
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                self.remediation_templates = yaml.safe_load(f)
            if not isinstance(self.remediation_templates, dict):
                self.remediation_templates = {}
        except Exception as e:
            self.logger.warning(f"Failed to load OWASP remediation templates: {e}")
            self.remediation_templates = {}

    def _init_html_templates(self):
        """Initialize HTML report template from external file."""
        template_path = Path(__file__).parent.parent.parent / "config" / "templates" / "enhanced_report.html"
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                content = f.read()
            if content.startswith("<!--"):
                content = content.split("\n", 1)[1]
            self.html_template = content
        except Exception as e:
            self.logger.warning(f"Failed to load HTML template: {e}")
            self.html_template = "<!DOCTYPE html><html><body><h1>{app_name}</h1>{content}</body></html>"
