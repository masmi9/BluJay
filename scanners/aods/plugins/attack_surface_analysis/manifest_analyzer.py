"""
Manifest Analyzer Module for Attack Surface Analysis

This module handles Android manifest parsing and analysis for identifying
attack surface vectors and component vulnerabilities.
"""

import logging
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import yaml

from core.xml_safe import safe_parse
from core.manifest_parsing_utils import (
    ANDROID_NS,
    is_component_exported,
    extract_manifest_from_apk,
)
from .data_structures import AnalysisContext, ComponentType, AttackVector, ComponentSurface
from .confidence_calculator import AttackSurfaceConfidenceCalculator


class ManifestAnalyzer:
    """
    Analyzes Android manifest files for attack surface vulnerabilities.

    Handles manifest parsing, component extraction, and security analysis
    of exported components and their configurations.
    """

    def __init__(self, context: AnalysisContext, logger: logging.Logger):
        self.context = context
        self.logger = logger
        self.confidence_calculator = AttackSurfaceConfidenceCalculator()
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> Dict[str, Any]:
        """Load attack patterns from external configuration."""
        try:
            patterns_file = Path(__file__).parent / "attack_patterns_config.yaml"
            with open(patterns_file, "r") as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.logger.warning(f"Failed to load attack patterns: {e}")
            return {}

    def analyze_manifest(self) -> Tuple[Optional[ET.Element], List[ComponentSurface]]:
        """
        Analyze the Android manifest for attack surface components.

        Returns:
            Tuple of (manifest_root, component_surfaces)
        """
        try:
            # Extract and parse manifest
            manifest_root = self._parse_manifest()
            if manifest_root is None:
                return None, []

            # Analyze component surfaces
            component_surfaces = self._analyze_component_surfaces(manifest_root)

            return manifest_root, component_surfaces

        except Exception as e:
            self.logger.error(f"Manifest analysis failed: {e}")
            return None, []

    def _parse_manifest(self) -> Optional[ET.Element]:
        """Parse the Android manifest file."""
        try:
            # First try direct manifest path
            if os.path.exists(self.context.manifest_path):
                tree = safe_parse(self.context.manifest_path)
                return tree.getroot()

            # Try extracting from APK
            manifest_path = self._extract_manifest_from_apk()
            if manifest_path and os.path.exists(manifest_path):
                tree = safe_parse(manifest_path)
                return tree.getroot()

            self.logger.error("Could not locate or parse manifest file")
            return None

        except ET.ParseError as e:
            self.logger.error(f"XML parsing error: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Manifest parsing failed: {e}")
            return None

    def _extract_manifest_from_apk(self) -> Optional[Path]:
        """Extract AndroidManifest.xml from APK file."""
        try:
            if not os.path.exists(self.context.apk_path):
                return None
            apk_path_obj = Path(self.context.apk_path)
            temp_dir = apk_path_obj.parent / f"{apk_path_obj.stem}_temp"
            return extract_manifest_from_apk(self.context.apk_path, temp_dir)
        except Exception as e:
            self.logger.warning(f"Manifest extraction failed: {e}")
            return None

    def _analyze_component_surfaces(self, manifest_root: ET.Element) -> List[ComponentSurface]:
        """Analyze all components in the manifest for attack surfaces."""
        component_surfaces = []

        # Find application element
        app_element = manifest_root.find("application")
        if app_element is None:
            self.logger.warning("No application element found in manifest")
            return component_surfaces

        # Analyze each component type
        component_types = {
            "activity": ComponentType.ACTIVITY,
            "service": ComponentType.SERVICE,
            "receiver": ComponentType.RECEIVER,
            "provider": ComponentType.PROVIDER,
        }

        for component_tag, component_type in component_types.items():
            elements = app_element.findall(component_tag)
            for element in elements:
                surface = self._analyze_single_component(element, component_type.value)
                if surface:
                    component_surfaces.append(surface)

        return component_surfaces

    def _analyze_single_component(self, element: ET.Element, comp_type: str) -> Optional[ComponentSurface]:
        """Analyze a single component for attack surface vectors."""
        try:
            # Extract component details
            name = element.get(f"{ANDROID_NS}name", "")
            if not name:
                return None

            exported = self._is_component_exported(element)
            permissions = self._extract_component_permissions(element)
            intent_filters = self._extract_intent_filters(element)

            # Identify attack vectors
            attack_vectors = self._identify_attack_vectors(name, comp_type, exported, permissions, intent_filters)

            # Identify IPC interfaces
            ipc_interfaces = self._identify_ipc_interfaces(element, comp_type)

            # Identify deep links
            deep_links = self._identify_deep_links(intent_filters)

            # Calculate risk score
            risk_score = self._calculate_component_risk_score(exported, permissions, intent_filters, attack_vectors)

            # Determine exposure level
            exposure_level = self._determine_exposure_level(risk_score, exported)

            return ComponentSurface(
                component_name=name,
                component_type=comp_type,
                exported=exported,
                permissions=permissions,
                intent_filters=intent_filters,
                attack_vectors=attack_vectors,
                ipc_interfaces=ipc_interfaces,
                deep_links=deep_links,
                risk_score=risk_score,
                exposure_level=exposure_level,
            )

        except Exception as e:
            self.logger.error(f"Component analysis failed for {comp_type}: {e}")
            return None

    def _is_component_exported(self, element: ET.Element) -> bool:
        """Determine if a component is exported."""
        return is_component_exported(element)

    def _extract_component_permissions(self, element: ET.Element) -> List[str]:
        """Extract permissions protecting the component."""
        permissions = []

        # Direct permission attribute
        permission = element.get(f"{ANDROID_NS}permission")
        if permission:
            permissions.append(permission)

        # Permission from intent filters
        for intent_filter in element.findall("intent-filter"):
            filter_permission = intent_filter.get(f"{ANDROID_NS}permission")
            if filter_permission:
                permissions.append(filter_permission)

        return permissions

    def _extract_intent_filters(self, element: ET.Element) -> List[Dict[str, Any]]:
        """Extract intent filter configurations."""
        intent_filters = []

        for filter_elem in element.findall("intent-filter"):
            filter_data = {"actions": [], "categories": [], "data": []}

            # Extract actions
            for action in filter_elem.findall("action"):
                action_name = action.get(f"{ANDROID_NS}name")
                if action_name:
                    filter_data["actions"].append(action_name)

            # Extract categories
            for category in filter_elem.findall("category"):
                category_name = category.get(f"{ANDROID_NS}name")
                if category_name:
                    filter_data["categories"].append(category_name)

            # Extract data specifications
            for data in filter_elem.findall("data"):
                data_spec = {}
                for attr in ["scheme", "host", "port", "path", "pathPattern", "pathPrefix", "mimeType"]:
                    value = data.get(f"{ANDROID_NS}{attr}")
                    if value:
                        data_spec[attr] = value
                if data_spec:
                    filter_data["data"].append(data_spec)

            intent_filters.append(filter_data)

        return intent_filters

    def _identify_attack_vectors(
        self, name: str, comp_type: str, exported: bool, permissions: List[str], intent_filters: List[Dict]
    ) -> List[AttackVector]:
        """Identify potential attack vectors for the component."""
        attack_vectors = []

        if not exported:
            return attack_vectors

        # Pattern-based attack vectors
        for pattern in self.patterns.get("dangerous_actions", {}).get("patterns", []):
            for intent_filter in intent_filters:
                if any(pattern in action for action in intent_filter.get("actions", [])):
                    vector = self._create_pattern_attack_vector(name, comp_type, pattern, permissions)
                    attack_vectors.append(vector)

        # Intent-based attack vectors
        for intent_filter in intent_filters:
            for action in intent_filter.get("actions", []):
                if action in self.patterns.get("dangerous_actions", {}).get("patterns", []):
                    vector = self._create_intent_attack_vector(name, comp_type, action, intent_filter, permissions)
                    attack_vectors.append(vector)

        # Scheme-based attack vectors
        for intent_filter in intent_filters:
            for data_spec in intent_filter.get("data", []):
                scheme = data_spec.get("scheme", "")
                if scheme in self.patterns.get("sensitive_schemes", {}).get("patterns", []):
                    vector = self._create_scheme_attack_vector(name, comp_type, scheme, data_spec, permissions)
                    attack_vectors.append(vector)

        # Unprotected component vector
        if not permissions:
            vector = self._create_unprotected_attack_vector(name, comp_type, intent_filters)
            attack_vectors.append(vector)

        return attack_vectors

    def _create_pattern_attack_vector(
        self, name: str, comp_type: str, pattern: str, permissions: List[str]
    ) -> AttackVector:
        """Create attack vector for pattern-based findings."""
        evidence = {
            "pattern_type": "dangerous_actions",
            "exported": True,
            "permissions": permissions,
            "component_type": comp_type,
            "analysis_source": "manifest_analysis",
            "validation_sources": ["pattern_matching", "manifest_analysis"],
        }

        confidence = self.confidence_calculator.calculate_confidence(evidence)

        return AttackVector(
            vector_id=f"{name}_pattern_{hash(pattern) % 10000}",
            name=f"Dangerous Action Pattern: {pattern}",
            severity="MEDIUM",
            confidence=confidence,
            description=f"Component {name} exposes dangerous action {pattern}",
            component_type=comp_type,
            component_name=name,
            entry_point=pattern,
            attack_methods=["Intent manipulation", "Component access"],
            prerequisites=["External app access"] if not permissions else ["Permission acquisition"],
            impact="Unauthorized component access",
            remediation="Add proper permission protection or disable export",
            cwe_id="CWE-200",
            masvs_refs=["MSTG-PLATFORM-11"],
        )

    def _create_intent_attack_vector(
        self, name: str, comp_type: str, action: str, filter_data: Dict, permissions: List[str]
    ) -> AttackVector:
        """Create attack vector for intent-based findings."""
        evidence = {
            "pattern_type": "intent_filters",
            "exported": True,
            "permissions": permissions,
            "component_type": comp_type,
            "analysis_source": "manifest_analysis",
            "validation_sources": ["intent_analysis", "manifest_analysis"],
        }

        confidence = self.confidence_calculator.calculate_confidence(evidence)

        return AttackVector(
            vector_id=f"{name}_intent_{hash(action) % 10000}",
            name=f"Intent Filter Exposure: {action}",
            severity="HIGH" if not permissions else "MEDIUM",
            confidence=confidence,
            description=f"Component {name} accepts external intents for {action}",
            component_type=comp_type,
            component_name=name,
            entry_point=action,
            attack_methods=["Intent injection", "Action spoofing"],
            prerequisites=[] if not permissions else [f"Permission: {', '.join(permissions)}"],
            impact="Unauthorized intent handling",
            remediation="Validate intent sources and add permission checks",
            cwe_id="CWE-926",
            masvs_refs=["MSTG-PLATFORM-11", "MSTG-PLATFORM-1"],
        )

    def _create_scheme_attack_vector(
        self, name: str, comp_type: str, scheme: str, data_spec: Dict, permissions: List[str]
    ) -> AttackVector:
        """Create attack vector for scheme-based findings."""
        evidence = {
            "pattern_type": "sensitive_schemes",
            "exported": True,
            "permissions": permissions,
            "component_type": comp_type,
            "analysis_source": "manifest_analysis",
            "validation_sources": ["scheme_analysis", "manifest_analysis"],
        }

        confidence = self.confidence_calculator.calculate_confidence(evidence)

        return AttackVector(
            vector_id=f"{name}_scheme_{hash(scheme) % 10000}",
            name=f"Deep Link Vulnerability: {scheme}",
            severity="HIGH",
            confidence=confidence,
            description=f"Component {name} handles sensitive scheme {scheme}",
            component_type=comp_type,
            component_name=name,
            entry_point=scheme,
            attack_methods=["Deep link manipulation", "URL spoofing"],
            prerequisites=["Malicious app with matching intent"],
            impact="Unauthorized deep link access",
            remediation="Validate deep link parameters and add authentication",
            cwe_id="CWE-939",
            masvs_refs=["MSTG-PLATFORM-3"],
        )

    def _create_unprotected_attack_vector(self, name: str, comp_type: str, intent_filters: List[Dict]) -> AttackVector:
        """Create attack vector for unprotected components."""
        evidence = {
            "pattern_type": "unprotected_components",
            "exported": True,
            "permissions": [],
            "component_type": comp_type,
            "analysis_source": "manifest_analysis",
            "validation_sources": ["permission_analysis", "manifest_analysis"],
        }

        confidence = self.confidence_calculator.calculate_confidence(evidence)

        return AttackVector(
            vector_id=f"{name}_unprotected",
            name=f"Unprotected {comp_type.title()}",
            severity="HIGH",
            confidence=confidence,
            description=f"Component {name} is exported without permission protection",
            component_type=comp_type,
            component_name=name,
            entry_point="Direct component access",
            attack_methods=["Direct component invocation", "Intent manipulation"],
            prerequisites=["Any external app"],
            impact="Unauthorized component access",
            remediation="Add permission protection or disable export",
            cwe_id="CWE-200",
            masvs_refs=["MSTG-PLATFORM-11"],
        )

    def _identify_ipc_interfaces(self, element: ET.Element, comp_type: str) -> List[str]:
        """Identify IPC interfaces exposed by the component."""
        ipc_interfaces = []

        # Process-related attributes
        process = element.get(f"{ANDROID_NS}process")
        if process:
            ipc_interfaces.append(f"process: {process}")

        shared_user_id = element.get(f"{ANDROID_NS}sharedUserId")
        if shared_user_id:
            ipc_interfaces.append(f"sharedUserId: {shared_user_id}")

        # Provider-specific interfaces
        if comp_type == "provider":
            authorities = element.get(f"{ANDROID_NS}authorities")
            if authorities:
                ipc_interfaces.append(f"authorities: {authorities}")

        return ipc_interfaces

    def _identify_deep_links(self, intent_filters: List[Dict]) -> List[str]:
        """Identify deep linking capabilities."""
        deep_links = []

        for intent_filter in intent_filters:
            # Check for browsable category
            if "android.intent.category.BROWSABLE" in intent_filter.get("categories", []):
                for data_spec in intent_filter.get("data", []):
                    scheme = data_spec.get("scheme", "")
                    host = data_spec.get("host", "")
                    if scheme:
                        link = f"{scheme}://"
                        if host:
                            link += host
                        deep_links.append(link)

        return deep_links

    def _calculate_component_risk_score(
        self, exported: bool, permissions: List[str], intent_filters: List[Dict], attack_vectors: List[AttackVector]
    ) -> int:
        """Calculate risk score for the component."""
        risk_score = 0

        if exported:
            risk_score += 20

        if not permissions:
            risk_score += 30

        risk_score += len(intent_filters) * 10
        risk_score += len(attack_vectors) * 15

        # Cap at 100
        return min(100, risk_score)

    def _determine_exposure_level(self, risk_score: int, exported: bool) -> str:
        """Determine the exposure level based on risk score."""
        if not exported:
            return "Minimal"
        elif risk_score >= 80:
            return "Critical"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        else:
            return "Low"
