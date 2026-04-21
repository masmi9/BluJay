"""
Enhanced Static Analysis - Manifest Analyzer Component

This module provides full AndroidManifest.xml analysis capabilities
including security configuration assessment, permission analysis, and component analysis.
"""

import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
import os

from core.apk_ctx import APKContext
from core.xml_safe import safe_parse
from core.manifest_parsing_utils import ANDROID_NS, extract_target_sdk, extract_min_sdk, is_component_exported
from .data_structures import ManifestAnalysis, AnalysisConfiguration

# Import AODS's existing working binary XML parsing infrastructure
try:
    from core.manifest_security_analyzer import AndroidManifestSecurityAnalyzer

    AODS_MANIFEST_PARSER_AVAILABLE = True
except ImportError:
    AODS_MANIFEST_PARSER_AVAILABLE = False


class ManifestAnalyzer:
    """Advanced AndroidManifest.xml analyzer."""

    def __init__(self, config: Optional[AnalysisConfiguration] = None):
        """Initialize the manifest analyzer."""
        self.config = config or AnalysisConfiguration()
        self.logger = logging.getLogger(__name__)

        # Initialize AODS's existing manifest parser
        self.aods_parser = None
        if AODS_MANIFEST_PARSER_AVAILABLE:
            try:
                self.aods_parser = AndroidManifestSecurityAnalyzer()
            except Exception as e:
                self.logger.warning(f"AODS manifest parser initialization failed: {e}")

    def analyze_manifest(self, apk_ctx: APKContext) -> Optional[ManifestAnalysis]:
        """Analyze AndroidManifest.xml for security issues."""
        try:
            manifest_path = self._get_manifest_path(apk_ctx)
            if not manifest_path or not os.path.exists(manifest_path):
                self.logger.warning("AndroidManifest.xml not found")
                return None

            # Use AODS's existing working manifest parser
            if self.aods_parser and hasattr(apk_ctx, "apk_path"):
                try:
                    aods_result = self.aods_parser.analyze_manifest(str(apk_ctx.apk_path))
                    if "error" not in aods_result:
                        # Convert AODS result to our format
                        return self._convert_aods_result_to_analysis(aods_result, apk_ctx)
                except Exception as e:
                    self.logger.debug(f"AODS parser failed: {e}")

            # Fallback to direct XML parsing (for text XML files)
            try:
                tree = safe_parse(manifest_path)
                root = tree.getroot()
            except ET.ParseError as _e:  # noqa: F841
                self.logger.error(
                    "Failed to parse AndroidManifest.xml: not well-formed (invalid token): line 1, column 0"
                )
                return None

            # Extract basic information
            package_name = root.get("package", "unknown")

            # Analyze components
            activities = self._analyze_activities(root)
            services = self._analyze_services(root)
            receivers = self._analyze_receivers(root)
            providers = self._analyze_providers(root)

            # Analyze permissions
            permissions = self._analyze_permissions(root)
            dangerous_permissions = self._identify_dangerous_permissions(permissions)

            # Analyze security features
            security_features = self._analyze_security_features(root)

            # Identify exported components
            exported_components = self._identify_exported_components(activities, services, receivers, providers)

            # Get SDK versions
            target_sdk = self._get_target_sdk(root)
            min_sdk = self._get_min_sdk(root)

            return ManifestAnalysis(
                package_name=package_name,
                target_sdk_version=target_sdk,  # Fixed parameter name
                min_sdk_version=min_sdk,  # Fixed parameter name
                permissions=permissions,
                activities=activities,
                services=services,
                receivers=receivers,
                providers=providers,
                security_features=security_features,
                exported_components=exported_components,
                dangerous_permissions=dangerous_permissions,
            )

        except ET.ParseError as e:
            self.logger.error(f"Failed to parse AndroidManifest.xml: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Manifest analysis failed: {e}")
            return None

    def _get_manifest_path(self, apk_ctx: APKContext) -> Optional[str]:
        """Get path to AndroidManifest.xml."""
        # Try to get from APK context
        if hasattr(apk_ctx, "manifest_path"):
            return apk_ctx.manifest_path

        # Try to construct from extraction path
        extraction_path = self._get_extraction_path(apk_ctx)
        if extraction_path:
            manifest_path = os.path.join(extraction_path, "AndroidManifest.xml")
            if os.path.exists(manifest_path):
                return manifest_path

        return None

    def _get_extraction_path(self, apk_ctx: APKContext) -> Optional[str]:
        """Get APK extraction path."""
        if hasattr(apk_ctx, "extraction_path"):
            return apk_ctx.extraction_path

        # Try to construct from APK path
        if apk_ctx.apk_path:
            apk_name = os.path.basename(apk_ctx.apk_path).replace(".apk", "")
            extraction_path = os.path.join(os.path.dirname(apk_ctx.apk_path), f"{apk_name}_extracted")
            if os.path.exists(extraction_path):
                return extraction_path

        return None

    def _analyze_activities(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Analyze activity components."""
        activities = []

        for activity in root.findall(".//activity"):
            activity_info = {
                "name": activity.get(f"{ANDROID_NS}name", "unknown"),
                "exported": self._is_exported(activity),
                "permissions": self._get_component_permissions(activity),
                "intent_filters": self._get_intent_filters(activity),
                "launch_mode": activity.get(f"{ANDROID_NS}launchMode"),
                "task_affinity": activity.get(f"{ANDROID_NS}taskAffinity"),
            }
            activities.append(activity_info)

        return activities

    def _analyze_services(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Analyze service components."""
        services = []

        for service in root.findall(".//service"):
            service_info = {
                "name": service.get(f"{ANDROID_NS}name", "unknown"),
                "exported": self._is_exported(service),
                "permissions": self._get_component_permissions(service),
                "intent_filters": self._get_intent_filters(service),
                "process": service.get(f"{ANDROID_NS}process"),
                "isolated": service.get(f"{ANDROID_NS}isolatedProcess") == "true",
            }
            services.append(service_info)

        return services

    def _analyze_receivers(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Analyze broadcast receiver components."""
        receivers = []

        for receiver in root.findall(".//receiver"):
            receiver_info = {
                "name": receiver.get(f"{ANDROID_NS}name", "unknown"),
                "exported": self._is_exported(receiver),
                "permissions": self._get_component_permissions(receiver),
                "intent_filters": self._get_intent_filters(receiver),
                "priority": receiver.get(f"{ANDROID_NS}priority"),
            }
            receivers.append(receiver_info)

        return receivers

    def _analyze_providers(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Analyze content provider components."""
        providers = []

        for provider in root.findall(".//provider"):
            provider_info = {
                "name": provider.get(f"{ANDROID_NS}name", "unknown"),
                "exported": self._is_exported(provider),
                "permissions": self._get_component_permissions(provider),
                "authorities": provider.get(f"{ANDROID_NS}authorities"),
                "grant_uri_permissions": provider.get(f"{ANDROID_NS}grantUriPermissions") == "true",
            }
            providers.append(provider_info)

        return providers

    def _analyze_permissions(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Analyze declared permissions."""
        permissions = []

        for permission in root.findall(".//uses-permission"):
            perm_info = {
                "name": permission.get(f"{ANDROID_NS}name", "unknown"),
                "max_sdk_version": permission.get(f"{ANDROID_NS}maxSdkVersion"),
                "type": "uses-permission",
            }
            permissions.append(perm_info)

        # Also check for permission definitions
        for permission in root.findall(".//permission"):
            perm_info = {
                "name": permission.get(f"{ANDROID_NS}name", "unknown"),
                "protection_level": permission.get(f"{ANDROID_NS}protectionLevel"),
                "label": permission.get(f"{ANDROID_NS}label"),
                "description": permission.get(f"{ANDROID_NS}description"),
                "type": "permission",
            }
            permissions.append(perm_info)

        return permissions

    def _analyze_security_features(self, root: ET.Element) -> Dict[str, Any]:
        """Analyze security-related features."""
        security_features = {}

        # Check application attributes
        app_element = root.find(".//application")
        if app_element is not None:
            security_features["debuggable"] = app_element.get(f"{ANDROID_NS}debuggable") == "true"

            security_features["allow_backup"] = app_element.get(f"{ANDROID_NS}allowBackup") != "false"

            security_features["uses_cleartext_traffic"] = app_element.get(f"{ANDROID_NS}usesCleartextTraffic") == "true"

            security_features["network_security_config"] = app_element.get(f"{ANDROID_NS}networkSecurityConfig")

        # Check SDK versions
        uses_sdk = root.find(".//uses-sdk")
        if uses_sdk is not None:
            security_features["target_sdk"] = uses_sdk.get(f"{ANDROID_NS}targetSdkVersion")
            security_features["min_sdk"] = uses_sdk.get(f"{ANDROID_NS}minSdkVersion")

        return security_features

    def _is_exported(self, component: ET.Element) -> bool:
        """Check if component is exported."""
        return is_component_exported(component)

    def _get_component_permissions(self, component: ET.Element) -> List[str]:
        """Get permissions required for component."""
        permissions = []

        permission = component.get(f"{ANDROID_NS}permission")
        if permission:
            permissions.append(permission)

        return permissions

    def _get_intent_filters(self, component: ET.Element) -> List[Dict[str, Any]]:
        """Get intent filters for component."""
        filters = []

        for intent_filter in component.findall(".//intent-filter"):
            filter_info = {
                "actions": [action.get(f"{ANDROID_NS}name") for action in intent_filter.findall(".//action")],
                "categories": [category.get(f"{ANDROID_NS}name") for category in intent_filter.findall(".//category")],
                "data": [self._get_data_info(data) for data in intent_filter.findall(".//data")],
            }
            filters.append(filter_info)

        return filters

    def _get_data_info(self, data: ET.Element) -> Dict[str, Any]:
        """Get data information from intent filter."""
        return {
            "scheme": data.get(f"{ANDROID_NS}scheme"),
            "host": data.get(f"{ANDROID_NS}host"),
            "path": data.get(f"{ANDROID_NS}path"),
            "mime_type": data.get(f"{ANDROID_NS}mimeType"),
        }

    def _identify_dangerous_permissions(self, permissions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify dangerous permissions."""
        dangerous_permission_patterns = [
            "CAMERA",
            "LOCATION",
            "RECORD_AUDIO",
            "READ_SMS",
            "SEND_SMS",
            "READ_CONTACTS",
            "WRITE_CONTACTS",
            "READ_PHONE_STATE",
            "CALL_PHONE",
            "READ_CALL_LOG",
            "WRITE_CALL_LOG",
            "READ_EXTERNAL_STORAGE",
            "WRITE_EXTERNAL_STORAGE",
            "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION",
            "RECORD_AUDIO",
            "READ_CALENDAR",
            "WRITE_CALENDAR",
        ]

        dangerous_permissions = []
        for perm in permissions:
            perm_name = perm.get("name", "")
            if any(pattern in perm_name for pattern in dangerous_permission_patterns):
                dangerous_permissions.append(perm)

        return dangerous_permissions

    def _identify_exported_components(
        self,
        activities: List[Dict[str, Any]],
        services: List[Dict[str, Any]],
        receivers: List[Dict[str, Any]],
        providers: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Identify exported components."""
        exported_components = []

        for activity in activities:
            if activity.get("exported", False):
                exported_components.append(
                    {
                        "name": activity["name"],
                        "type": "activity",
                        "permissions": activity.get("permissions", []),
                        "intent_filters": activity.get("intent_filters", []),
                    }
                )

        for service in services:
            if service.get("exported", False):
                exported_components.append(
                    {
                        "name": service["name"],
                        "type": "service",
                        "permissions": service.get("permissions", []),
                        "intent_filters": service.get("intent_filters", []),
                    }
                )

        for receiver in receivers:
            if receiver.get("exported", False):
                exported_components.append(
                    {
                        "name": receiver["name"],
                        "type": "receiver",
                        "permissions": receiver.get("permissions", []),
                        "intent_filters": receiver.get("intent_filters", []),
                    }
                )

        for provider in providers:
            if provider.get("exported", False):
                exported_components.append(
                    {
                        "name": provider["name"],
                        "type": "provider",
                        "permissions": provider.get("permissions", []),
                        "authorities": provider.get("authorities"),
                    }
                )

        return exported_components

    def _get_target_sdk(self, root: ET.Element) -> Optional[int]:
        """Get target SDK version."""
        return extract_target_sdk(root)

    def _get_min_sdk(self, root: ET.Element) -> Optional[int]:
        """Get minimum SDK version."""
        return extract_min_sdk(root)

    def _convert_aods_result_to_analysis(self, aods_result: Dict[str, Any], apk_ctx: APKContext) -> ManifestAnalysis:
        """Convert AODS manifest analysis result to our ManifestAnalysis format."""
        try:
            # Extract data from AODS result
            package_name = aods_result.get("package_name", "unknown")
            permissions = aods_result.get("permissions", [])

            # Create a basic ManifestAnalysis with available data
            analysis = ManifestAnalysis(
                package_name=package_name,
                activities=[],  # AODS doesn't provide detailed component analysis
                services=[],
                receivers=[],
                providers=[],
                permissions=permissions,
                dangerous_permissions=[p for p in permissions if "DANGEROUS" in str(p).upper()],
                security_features={
                    "uses_cleartext_traffic": aods_result.get("uses_cleartext_traffic", False),
                    "backup_allowed": aods_result.get("backup_allowed", True),
                    "debuggable": aods_result.get("debuggable", False),
                },
                exported_components=[],
                target_sdk_version=aods_result.get("target_sdk_version"),
                min_sdk_version=aods_result.get("min_sdk_version"),
                metadata={"parser_used": "AODS_AndroidManifestSecurityAnalyzer", "binary_xml_parsed": True},
            )

            self.logger.info("Successfully parsed AndroidManifest.xml using AODS infrastructure")
            return analysis

        except Exception as e:
            self.logger.error(f"Failed to convert AODS result: {e}")
            return None
