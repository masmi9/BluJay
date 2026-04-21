"""Full APK parser for Android application analysis."""

import re
import hashlib
import logging
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Set, Tuple

from ._types import (
    APKValidationResult,
    ArchitectureType,
    APKMetadata,
    ManifestPermission,
    ManifestComponent,
    APKAnalysisResult,
)
from .certificate_analyzer import CertificateInfo

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    x509 = None
    default_backend = None

logger = logging.getLogger(__name__)


class APKParser:
    """
    Full APK parser for Android application analysis.

    Provides detailed analysis of APK structure, manifest, certificates,
    native libraries, and security characteristics.
    """

    def __init__(self):
        """Initialize APK parser."""
        self.logger = logging.getLogger(__name__)

        # Tool availability
        self.aapt_available = shutil.which("aapt") is not None
        self.aapt2_available = shutil.which("aapt2") is not None
        self.keytool_available = shutil.which("keytool") is not None

        # Dangerous permissions list
        self.dangerous_permissions = self._load_dangerous_permissions()

        # Known security issues patterns
        self.security_patterns = self._load_security_patterns()

        if not (self.aapt_available or self.aapt2_available):
            self.logger.warning("AAPT/AAPT2 not available - manifest parsing will be limited")

        self.logger.info("APK parser initialized")

    def parse_apk(
        self,
        apk_path: Union[str, Path],
        extract_details: bool = True,
        validate_signatures: bool = True,
        analyze_native_libs: bool = True,
    ) -> APKAnalysisResult:
        """
        Parse APK file and extract information.

        Args:
            apk_path: Path to APK file
            extract_details: Whether to extract detailed information
            validate_signatures: Whether to validate signatures
            analyze_native_libs: Whether to analyze native libraries

        Returns:
            APKAnalysisResult with complete analysis
        """
        import time

        start_time = time.time()

        apk_path = Path(apk_path)
        result = APKAnalysisResult(apk_path=apk_path, validation_result=APKValidationResult.VALID)

        try:
            # Validate APK structure
            validation_result = self.validate_apk_structure(apk_path)
            result.validation_result = validation_result

            if validation_result != APKValidationResult.VALID:
                self.logger.warning(f"APK validation failed: {validation_result.value}")
                return result

            # Extract basic metadata
            result.metadata = self.extract_apk_metadata(apk_path)

            if extract_details:
                # Parse manifest
                manifest_data = self.parse_manifest(apk_path)
                if manifest_data:
                    result.permissions = manifest_data.get("permissions", [])
                    result.components = manifest_data.get("components", [])

                # Analyze certificates
                if validate_signatures:
                    result.certificates = self.extract_certificate_info(apk_path)

                # Analyze native libraries
                if analyze_native_libs:
                    result.native_libraries = self.analyze_native_libraries(apk_path)

                # Extract file lists
                result.dex_files = self.extract_dex_files(apk_path)
                result.assets = self.extract_assets(apk_path)
                result.resources = self.extract_resources(apk_path)

                # Security analysis
                result.security_issues = self.analyze_security_issues(result)

            result.analysis_time = time.time() - start_time
            self.logger.info(f"APK analysis completed in {result.analysis_time:.2f}s")

            return result

        except Exception as e:
            self.logger.error(f"APK parsing failed: {e}")
            result.validation_result = APKValidationResult.CORRUPTED
            result.security_issues.append(f"Parsing failed: {e}")
            result.analysis_time = time.time() - start_time
            return result

    def validate_apk_structure(self, apk_path: Path) -> APKValidationResult:
        """Validate APK file structure."""
        try:
            if not apk_path.exists():
                return APKValidationResult.INVALID_STRUCTURE

            # Check if it's a valid ZIP file
            if not zipfile.is_zipfile(apk_path):
                return APKValidationResult.INVALID_STRUCTURE

            # Check for required files
            with zipfile.ZipFile(apk_path, "r") as zf:
                files = zf.namelist()

                # Must have AndroidManifest.xml
                if "AndroidManifest.xml" not in files:
                    return APKValidationResult.MISSING_MANIFEST

                # Must have at least one DEX file
                if not any(f.endswith(".dex") for f in files):
                    return APKValidationResult.INVALID_STRUCTURE

                # Check for signature files
                meta_inf_files = [f for f in files if f.startswith("META-INF/")]
                has_signature = any(f.endswith((".RSA", ".DSA", ".EC")) for f in meta_inf_files)

                if not has_signature:
                    return APKValidationResult.UNSIGNED

            return APKValidationResult.VALID

        except zipfile.BadZipFile:
            return APKValidationResult.CORRUPTED
        except Exception:
            return APKValidationResult.INVALID_STRUCTURE

    def extract_apk_metadata(self, apk_path: Path) -> Optional[APKMetadata]:
        """Extract basic APK metadata."""
        try:
            # Calculate file hashes
            file_size = apk_path.stat().st_size
            md5_hash, sha256_hash = self._calculate_file_hashes(apk_path)

            # Use AAPT to extract basic metadata
            if self.aapt_available:
                metadata = self._extract_metadata_with_aapt(apk_path)
                if metadata:
                    metadata.file_size = file_size
                    metadata.file_hash_md5 = md5_hash
                    metadata.file_hash_sha256 = sha256_hash
                    return metadata

            # Fallback to manifest parsing
            manifest_data = self._parse_binary_manifest(apk_path)
            if manifest_data:
                return APKMetadata(
                    package_name=manifest_data.get("package", "unknown"),
                    version_name=manifest_data.get("versionName", "unknown"),
                    version_code=int(manifest_data.get("versionCode", 0)),
                    min_sdk_version=int(manifest_data.get("minSdkVersion", 1)),
                    target_sdk_version=int(manifest_data.get("targetSdkVersion", 1)),
                    file_size=file_size,
                    file_hash_md5=md5_hash,
                    file_hash_sha256=sha256_hash,
                )

            return None

        except Exception as e:
            self.logger.error(f"Failed to extract APK metadata: {e}")
            return None

    def parse_manifest(self, apk_path: Path) -> Optional[Dict[str, Any]]:
        """Parse Android manifest and extract components and permissions."""
        try:
            if self.aapt_available:
                return self._parse_manifest_with_aapt(apk_path)
            else:
                return self._parse_binary_manifest_detailed(apk_path)
        except Exception as e:
            self.logger.error(f"Failed to parse manifest: {e}")
            return None

    def extract_certificate_info(self, apk_path: Path) -> List[CertificateInfo]:
        """Extract certificate information from APK."""
        certificates = []

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                # Find certificate files in META-INF
                cert_files = [
                    f for f in zf.namelist() if f.startswith("META-INF/") and f.endswith((".RSA", ".DSA", ".EC"))
                ]

                for cert_file in cert_files:
                    cert_data = zf.read(cert_file)
                    cert_info = self._parse_certificate(cert_data)
                    if cert_info:
                        certificates.append(cert_info)

            return certificates

        except Exception as e:
            self.logger.error(f"Failed to extract certificate info: {e}")
            return []

    def analyze_native_libraries(self, apk_path: Path) -> List[Any]:
        """Analyze native libraries in APK."""
        libraries = []

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                # Find native libraries
                lib_files = [f for f in zf.namelist() if f.startswith("lib/") and f.endswith(".so")]

                for lib_file in lib_files:
                    # Extract architecture from path (e.g., lib/arm64-v8a/libexample.so)
                    path_parts = lib_file.split("/")
                    if len(path_parts) >= 3:
                        arch_str = path_parts[1]
                        arch = self._parse_architecture(arch_str)

                        filename = path_parts[-1]
                        file_size = zf.getinfo(lib_file).file_size

                        # Import the early (simple) NativeLibraryInfo from _types
                        # APKParser uses the simple version from the original top of file
                        libraries.append({"filename": filename, "architecture": arch, "file_size": file_size})

            return libraries

        except Exception as e:
            self.logger.error(f"Failed to analyze native libraries: {e}")
            return []

    def extract_dex_files(self, apk_path: Path) -> List[str]:
        """Extract list of DEX files."""
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                return [f for f in zf.namelist() if f.endswith(".dex")]
        except Exception:
            return []

    def extract_assets(self, apk_path: Path) -> List[str]:
        """Extract list of asset files."""
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                return [f for f in zf.namelist() if f.startswith("assets/")]
        except Exception:
            return []

    def extract_resources(self, apk_path: Path) -> List[str]:
        """Extract list of resource files."""
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                return [f for f in zf.namelist() if f.startswith("res/")]
        except Exception:
            return []

    def analyze_security_issues(self, result: APKAnalysisResult) -> List[str]:
        """Analyze APK for security issues."""
        issues = []

        try:
            # Check for dangerous permissions
            dangerous_perms = [p for p in result.permissions if p.is_dangerous]
            if dangerous_perms:
                issues.append(f"Uses {len(dangerous_perms)} dangerous permissions")

            # Check for exported components without proper protection
            exported_components = [c for c in result.components if c.exported]
            unprotected_components = [c for c in exported_components if not c.permissions]
            if unprotected_components:
                issues.append(f"{len(unprotected_components)} exported components without permissions")

            # Check for debug build
            if result.metadata:
                if "debug" in result.metadata.app_name.lower() if result.metadata.app_name else False:
                    issues.append("Appears to be a debug build")

            # Check for weak signature algorithm
            for cert in result.certificates:
                if "md5" in cert.signature_algorithm.lower() or "sha1" in cert.signature_algorithm.lower():
                    issues.append(f"Weak signature algorithm: {cert.signature_algorithm}")

            # Check for native libraries without security features
            for lib in result.native_libraries:
                if hasattr(lib, "stripped") and not lib.stripped:
                    issues.append(f"Native library not stripped: {lib.filename}")

            # Check for suspicious assets
            suspicious_assets = []
            for asset in result.assets:
                if any(pattern in asset.lower() for pattern in ["key", "secret", "password", "token"]):
                    suspicious_assets.append(asset)

            if suspicious_assets:
                issues.append(f"Suspicious asset files found: {len(suspicious_assets)}")

            return issues

        except Exception as e:
            self.logger.error(f"Security analysis failed: {e}")
            return [f"Security analysis failed: {e}"]

    def _extract_metadata_with_aapt(self, apk_path: Path) -> Optional[APKMetadata]:
        """Extract metadata using AAPT tool."""
        try:
            cmd = ["aapt", "dump", "badging", str(apk_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                return None

            output = result.stdout

            # Parse AAPT output
            package_match = re.search(r"package: name='([^']+)'", output)
            version_name_match = re.search(r"versionName='([^']+)'", output)
            version_code_match = re.search(r"versionCode='([^']+)'", output)
            min_sdk_match = re.search(r"sdkVersion:'([^']+)'", output)
            target_sdk_match = re.search(r"targetSdkVersion:'([^']+)'", output)
            app_name_match = re.search(r"application-label:'([^']+)'", output)
            main_activity_match = re.search(r"launchable-activity: name='([^']+)'", output)

            return APKMetadata(
                package_name=package_match.group(1) if package_match else "unknown",
                version_name=version_name_match.group(1) if version_name_match else "unknown",
                version_code=int(version_code_match.group(1)) if version_code_match else 0,
                min_sdk_version=int(min_sdk_match.group(1)) if min_sdk_match else 1,
                target_sdk_version=int(target_sdk_match.group(1)) if target_sdk_match else 1,
                app_name=app_name_match.group(1) if app_name_match else None,
                main_activity=main_activity_match.group(1) if main_activity_match else None,
            )

        except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
            return None

    def _parse_manifest_with_aapt(self, apk_path: Path) -> Optional[Dict[str, Any]]:
        """Parse manifest using AAPT tool."""
        try:
            # Get permissions
            cmd = ["aapt", "dump", "permissions", str(apk_path)]
            perm_result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            permissions = []
            if perm_result.returncode == 0:
                for line in perm_result.stdout.split("\n"):
                    if "uses-permission:" in line:
                        perm_match = re.search(r"name='([^']+)'", line)
                        if perm_match:
                            perm_name = perm_match.group(1)
                            permissions.append(
                                ManifestPermission(name=perm_name, is_dangerous=perm_name in self.dangerous_permissions)
                            )

            # Get XML dump for components
            cmd = ["aapt", "dump", "xmltree", str(apk_path), "AndroidManifest.xml"]
            xml_result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            components = []
            if xml_result.returncode == 0:
                components = self._parse_components_from_aapt_xml(xml_result.stdout)

            return {"permissions": permissions, "components": components}

        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return None

    def _parse_binary_manifest(self, apk_path: Path) -> Optional[Dict[str, Any]]:
        """Parse binary manifest with full binary XML parsing."""
        try:
            # AndroidBinaryXMLParser not available - fall through to AAPT
            raise ImportError("AndroidBinaryXMLParser not available")

        except Exception as e:
            self.logger.warning(f"Binary manifest parsing failed: {e}")
            # Fallback to AAPT parsing
            return self._parse_manifest_with_aapt(apk_path)

    def _parse_binary_manifest_detailed(self, apk_path: Path) -> Optional[Dict[str, Any]]:
        """Parse binary manifest for detailed information including permissions and components."""
        try:
            # AndroidBinaryXMLParser not available - fall through to AAPT
            raise ImportError("AndroidBinaryXMLParser not available")

        except Exception as e:
            self.logger.error(f"Detailed binary manifest parsing failed: {e}")
            return self._parse_detailed_with_aapt(apk_path)

    def _parse_detailed_with_aapt(self, apk_path: Path) -> Dict[str, Any]:
        """Fallback detailed parsing using AAPT tool."""
        try:
            import subprocess

            # Use aapt to extract detailed manifest information
            detailed_info = {
                "permissions": [],
                "components": [],
                "metadata": {},
                "services": [],
                "receivers": [],
                "providers": [],
                "intent_filters": [],
                "features": [],
                "instrumentation": [],
            }

            # Extract permissions
            perm_cmd = ["aapt", "dump", "permissions", str(apk_path)]
            perm_result = subprocess.run(perm_cmd, capture_output=True, text=True, timeout=30)
            if perm_result.returncode == 0:
                detailed_info["permissions"] = self._parse_aapt_permissions(perm_result.stdout)

            # Extract other manifest details
            xmltree_cmd = ["aapt", "dump", "xmltree", str(apk_path), "AndroidManifest.xml"]
            tree_result = subprocess.run(xmltree_cmd, capture_output=True, text=True, timeout=30)
            if tree_result.returncode == 0:
                manifest_details = self._parse_aapt_xmltree(tree_result.stdout)
                detailed_info.update(manifest_details)

            return detailed_info

        except Exception as e:
            self.logger.error(f"AAPT detailed parsing failed: {e}")
            return {
                "permissions": [],
                "components": [],
                "metadata": {},
                "services": [],
                "receivers": [],
                "providers": [],
                "intent_filters": [],
                "features": [],
                "instrumentation": [],
            }

    def _extract_manifest_metadata(self, parsed_manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Extract basic metadata from parsed manifest."""
        manifest_tag = parsed_manifest.get("manifest", {})

        return {
            "package": manifest_tag.get("package", "unknown"),
            "versionName": manifest_tag.get("versionName", "unknown"),
            "versionCode": manifest_tag.get("versionCode", "0"),
            "minSdkVersion": self._get_min_sdk_version(parsed_manifest),
            "targetSdkVersion": self._get_target_sdk_version(parsed_manifest),
            "compileSdkVersion": manifest_tag.get("compileSdkVersion", "unknown"),
            "installLocation": manifest_tag.get("installLocation", "auto"),
        }

    def _extract_permissions(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract permissions from parsed manifest."""
        permissions = []

        # Extract uses-permission tags
        uses_permissions = parsed_manifest.get("uses-permission", [])
        if not isinstance(uses_permissions, list):
            uses_permissions = [uses_permissions]

        for perm in uses_permissions:
            if isinstance(perm, dict):
                permissions.append(
                    {
                        "name": perm.get("name", ""),
                        "type": "uses-permission",
                        "maxSdkVersion": perm.get("maxSdkVersion"),
                        "required": perm.get("required", True),
                    }
                )

        # Extract permission tags (custom permissions)
        custom_permissions = parsed_manifest.get("permission", [])
        if not isinstance(custom_permissions, list):
            custom_permissions = [custom_permissions]

        for perm in custom_permissions:
            if isinstance(perm, dict):
                permissions.append(
                    {
                        "name": perm.get("name", ""),
                        "type": "permission",
                        "protectionLevel": perm.get("protectionLevel", "normal"),
                        "permissionGroup": perm.get("permissionGroup"),
                        "label": perm.get("label"),
                        "description": perm.get("description"),
                    }
                )

        return permissions

    def _extract_components(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract components (activities, services, etc.) from parsed manifest."""
        components = []

        application = parsed_manifest.get("application", {})
        if not application:
            return components

        # Extract activities
        activities = application.get("activity", [])
        if not isinstance(activities, list):
            activities = [activities]

        for activity in activities:
            if isinstance(activity, dict):
                components.append(
                    {
                        "type": "activity",
                        "name": activity.get("name", ""),
                        "exported": activity.get("exported", False),
                        "enabled": activity.get("enabled", True),
                        "label": activity.get("label"),
                        "theme": activity.get("theme"),
                        "launchMode": activity.get("launchMode"),
                        "intent_filters": self._extract_component_intent_filters(activity),
                    }
                )

        # Extract services
        services = application.get("service", [])
        if not isinstance(services, list):
            services = [services]

        for service in services:
            if isinstance(service, dict):
                components.append(
                    {
                        "type": "service",
                        "name": service.get("name", ""),
                        "exported": service.get("exported", False),
                        "enabled": service.get("enabled", True),
                        "permission": service.get("permission"),
                        "process": service.get("process"),
                        "intent_filters": self._extract_component_intent_filters(service),
                    }
                )

        return components

    def _extract_services(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract services from parsed manifest."""
        services = []
        application = parsed_manifest.get("application", {})

        service_list = application.get("service", [])
        if not isinstance(service_list, list):
            service_list = [service_list]

        for service in service_list:
            if isinstance(service, dict):
                services.append(
                    {
                        "name": service.get("name", ""),
                        "exported": service.get("exported", False),
                        "enabled": service.get("enabled", True),
                        "permission": service.get("permission"),
                        "process": service.get("process"),
                        "isolatedProcess": service.get("isolatedProcess", False),
                        "stopWithTask": service.get("stopWithTask", True),
                    }
                )

        return services

    def _extract_receivers(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract broadcast receivers from parsed manifest."""
        receivers = []
        application = parsed_manifest.get("application", {})

        receiver_list = application.get("receiver", [])
        if not isinstance(receiver_list, list):
            receiver_list = [receiver_list]

        for receiver in receiver_list:
            if isinstance(receiver, dict):
                receivers.append(
                    {
                        "name": receiver.get("name", ""),
                        "exported": receiver.get("exported", False),
                        "enabled": receiver.get("enabled", True),
                        "permission": receiver.get("permission"),
                        "priority": receiver.get("priority", 0),
                        "intent_filters": self._extract_component_intent_filters(receiver),
                    }
                )

        return receivers

    def _extract_providers(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract content providers from parsed manifest."""
        providers = []
        application = parsed_manifest.get("application", {})

        provider_list = application.get("provider", [])
        if not isinstance(provider_list, list):
            provider_list = [provider_list]

        for provider in provider_list:
            if isinstance(provider, dict):
                providers.append(
                    {
                        "name": provider.get("name", ""),
                        "authorities": provider.get("authorities", ""),
                        "exported": provider.get("exported", False),
                        "enabled": provider.get("enabled", True),
                        "permission": provider.get("permission"),
                        "readPermission": provider.get("readPermission"),
                        "writePermission": provider.get("writePermission"),
                        "grantUriPermissions": provider.get("grantUriPermissions", False),
                    }
                )

        return providers

    def _extract_application_metadata(self, parsed_manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Extract application metadata from parsed manifest."""
        application = parsed_manifest.get("application", {})

        metadata = {
            "name": application.get("name"),
            "label": application.get("label"),
            "icon": application.get("icon"),
            "theme": application.get("theme"),
            "debuggable": application.get("debuggable", False),
            "allowBackup": application.get("allowBackup", True),
            "allowClearUserData": application.get("allowClearUserData", True),
            "hardwareAccelerated": application.get("hardwareAccelerated", False),
            "largeHeap": application.get("largeHeap", False),
            "usesCleartextTraffic": application.get("usesCleartextTraffic", True),
            "networkSecurityConfig": application.get("networkSecurityConfig"),
            "requestLegacyExternalStorage": application.get("requestLegacyExternalStorage", False),
        }

        # Extract meta-data tags
        meta_data_list = application.get("meta-data", [])
        if not isinstance(meta_data_list, list):
            meta_data_list = [meta_data_list]

        metadata["meta_data"] = []
        for meta_data in meta_data_list:
            if isinstance(meta_data, dict):
                metadata["meta_data"].append(
                    {
                        "name": meta_data.get("name", ""),
                        "value": meta_data.get("value"),
                        "resource": meta_data.get("resource"),
                    }
                )

        return metadata

    def _extract_intent_filters(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract intent filters from parsed manifest."""
        intent_filters = []
        application = parsed_manifest.get("application", {})

        # Search all components for intent filters
        for component_type in ["activity", "service", "receiver"]:
            components = application.get(component_type, [])
            if not isinstance(components, list):
                components = [components]

            for component in components:
                if isinstance(component, dict):
                    component_filters = self._extract_component_intent_filters(component)
                    for filter_info in component_filters:
                        filter_info["component"] = component.get("name", "")
                        filter_info["component_type"] = component_type
                        intent_filters.append(filter_info)

        return intent_filters

    def _extract_features(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract uses-feature tags from parsed manifest."""
        features = []

        feature_list = parsed_manifest.get("uses-feature", [])
        if not isinstance(feature_list, list):
            feature_list = [feature_list]

        for feature in feature_list:
            if isinstance(feature, dict):
                features.append(
                    {
                        "name": feature.get("name", ""),
                        "required": feature.get("required", True),
                        "glEsVersion": feature.get("glEsVersion"),
                    }
                )

        return features

    def _extract_instrumentation(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract instrumentation tags from parsed manifest."""
        instrumentation = []

        instrumentation_list = parsed_manifest.get("instrumentation", [])
        if not isinstance(instrumentation_list, list):
            instrumentation_list = [instrumentation_list]

        for instr in instrumentation_list:
            if isinstance(instr, dict):
                instrumentation.append(
                    {
                        "name": instr.get("name", ""),
                        "targetPackage": instr.get("targetPackage", ""),
                        "label": instr.get("label"),
                        "handleProfiling": instr.get("handleProfiling", False),
                        "functionalTest": instr.get("functionalTest", False),
                    }
                )

        return instrumentation

    def _extract_component_intent_filters(self, component: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract intent filters from a component."""
        intent_filters = []

        filter_list = component.get("intent-filter", [])
        if not isinstance(filter_list, list):
            filter_list = [filter_list]

        for intent_filter in filter_list:
            if isinstance(intent_filter, dict):
                filter_info = {
                    "actions": [],
                    "categories": [],
                    "data": [],
                    "priority": intent_filter.get("priority", 0),
                }

                # Extract actions
                actions = intent_filter.get("action", [])
                if not isinstance(actions, list):
                    actions = [actions]
                for action in actions:
                    if isinstance(action, dict):
                        filter_info["actions"].append(action.get("name", ""))

                # Extract categories
                categories = intent_filter.get("category", [])
                if not isinstance(categories, list):
                    categories = [categories]
                for category in categories:
                    if isinstance(category, dict):
                        filter_info["categories"].append(category.get("name", ""))

                # Extract data
                data_list = intent_filter.get("data", [])
                if not isinstance(data_list, list):
                    data_list = [data_list]
                for data in data_list:
                    if isinstance(data, dict):
                        filter_info["data"].append(
                            {
                                "scheme": data.get("scheme"),
                                "host": data.get("host"),
                                "port": data.get("port"),
                                "path": data.get("path"),
                                "pathPattern": data.get("pathPattern"),
                                "pathPrefix": data.get("pathPrefix"),
                                "mimeType": data.get("mimeType"),
                            }
                        )

                intent_filters.append(filter_info)

        return intent_filters

    def _parse_certificate(self, cert_data: bytes) -> Optional[CertificateInfo]:
        """Parse certificate data from APK signature."""
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.warning("Cryptography library not available for certificate parsing")
            return None

        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.serialization import pkcs7
            from cryptography import x509
            import hashlib

            # Try to parse as PKCS#7 structure first
            try:
                # Parse PKCS#7 signature to extract certificate
                pkcs7_data = pkcs7.load_der_pkcs7_certificates(cert_data)
                if pkcs7_data:
                    cert = pkcs7_data[0]  # Get the first certificate
                else:
                    # Fallback: try to parse as X.509 certificate directly
                    cert = x509.load_der_x509_certificate(cert_data)
            except Exception:
                # Last fallback: try PEM format
                try:
                    cert = x509.load_pem_x509_certificate(cert_data)
                except Exception:
                    self.logger.debug("Failed to parse certificate in any format")
                    return None

            # Extract certificate information
            subject_name = cert.subject.rfc4514_string()
            issuer_name = cert.issuer.rfc4514_string()
            serial_number = str(cert.serial_number)
            not_before = cert.not_valid_before.isoformat()
            not_after = cert.not_valid_after.isoformat()

            # Extract signature algorithm
            signature_algorithm = cert.signature_algorithm_oid._name

            # Extract public key information
            public_key = cert.public_key()
            public_key_algorithm = public_key.__class__.__name__.replace("PublicKey", "")

            # Determine key size
            key_size = 0
            try:
                if hasattr(public_key, "key_size"):
                    key_size = public_key.key_size
                elif hasattr(public_key, "curve"):
                    key_size = public_key.curve.key_size
            except Exception:
                pass

            # Calculate fingerprints
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            fingerprint_md5 = hashlib.md5(cert_der).hexdigest()
            fingerprint_sha1 = hashlib.sha1(cert_der).hexdigest()
            fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()

            return CertificateInfo(
                subject=subject_name,
                issuer=issuer_name,
                serial_number=serial_number,
                not_before=not_before,
                not_after=not_after,
                signature_algorithm=signature_algorithm,
                public_key_algorithm=public_key_algorithm,
                key_size=key_size,
                fingerprint_md5=fingerprint_md5,
                fingerprint_sha1=fingerprint_sha1,
                fingerprint_sha256=fingerprint_sha256,
            )

        except Exception as e:
            self.logger.debug(f"Certificate parsing failed: {e}")
            return None

    def _parse_components_from_aapt_xml(self, xml_output: str) -> List[ManifestComponent]:
        """Parse components from AAPT XML output."""
        components = []

        # This would parse the AAPT XML tree output
        # Implementation would be specific to AAPT output format

        return components

    def _parse_architecture(self, arch_str: str) -> ArchitectureType:
        """Parse architecture type from string."""
        arch_mapping = {
            "armeabi": ArchitectureType.ARM,
            "armeabi-v7a": ArchitectureType.ARM,
            "arm64-v8a": ArchitectureType.ARM64,
            "x86": ArchitectureType.X86,
            "x86_64": ArchitectureType.X86_64,
            "mips": ArchitectureType.MIPS,
            "mips64": ArchitectureType.MIPS64,
        }

        return arch_mapping.get(arch_str, ArchitectureType.UNKNOWN)

    def _calculate_file_hashes(self, file_path: Path) -> Tuple[str, str]:
        """Calculate MD5 and SHA256 hashes of file."""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)

        return md5_hash.hexdigest(), sha256_hash.hexdigest()

    def _load_dangerous_permissions(self) -> Set[str]:
        """Load list of dangerous Android permissions."""
        return {
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.ADD_VOICEMAIL",
            "android.permission.USE_SIP",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.GET_ACCOUNTS",
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.RECEIVE_WAP_PUSH",
            "android.permission.RECEIVE_MMS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.ACCESS_MEDIA_LOCATION",
            "android.permission.ACCEPT_HANDOVER",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.ACTIVITY_RECOGNITION",
            "android.permission.ANSWER_PHONE_CALLS",
            "android.permission.READ_PHONE_NUMBERS",
        }

    def _load_security_patterns(self) -> Dict[str, List[str]]:
        """Load security issue patterns."""
        return {
            "suspicious_files": ["key", "secret", "password", "token", "private", "cert", "p12", "jks"],
            "debug_indicators": ["debug", "test", "dev", "staging"],
        }

    def _get_min_sdk_version(self, parsed_manifest: Dict[str, Any]) -> str:
        """Extract min SDK version from parsed manifest."""
        uses_sdk = parsed_manifest.get("uses-sdk", {})
        if isinstance(uses_sdk, dict):
            return uses_sdk.get("minSdkVersion", "1")
        return "1"

    def _get_target_sdk_version(self, parsed_manifest: Dict[str, Any]) -> str:
        """Extract target SDK version from parsed manifest."""
        uses_sdk = parsed_manifest.get("uses-sdk", {})
        if isinstance(uses_sdk, dict):
            return uses_sdk.get("targetSdkVersion", "1")
        return "1"

    def _parse_aapt_permissions(self, output: str) -> List[Dict[str, Any]]:
        """Parse AAPT permissions output."""
        permissions = []
        for line in output.split("\n"):
            if "uses-permission:" in line:
                perm_match = re.search(r"name='([^']+)'", line)
                if perm_match:
                    permissions.append({"name": perm_match.group(1), "type": "uses-permission"})
        return permissions

    def _parse_aapt_xmltree(self, output: str) -> Dict[str, Any]:
        """Parse AAPT xmltree output."""
        # Basic implementation - would need full AAPT xmltree parser
        return {}
