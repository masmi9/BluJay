"""
APKAnalyzer class for static analysis of APK files and manifest.

This module provides functionality for performing static analysis on Android APK
files, including manifest parsing, certificate analysis, permission extraction,
and identification of security-relevant configurations like debuggable mode.
"""

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from core.xml_safe import safe_parse
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class APKAnalyzer:
    """
    Analyzes APK files and AndroidManifest.xml for static security checks.

    This class handles the extraction and analysis of various security-relevant
    attributes from an APK file, focusing on manifest attributes, permissions,
    certificate details, and other static security indicators.

    Attributes:
        manifest_dir (str): Path to the directory containing the AndroidManifest.xml
        decompiled_dir (str): Path to the directory containing the decompiled APK
        strings (Dict): Dictionary of string resources extracted from the APK
    """

    def __init__(self, manifest_dir: str, decompiled_dir: str):
        """
        Initialize the APKAnalyzer with paths to the extracted APK content.

        Args:
            manifest_dir: Path to the directory containing AndroidManifest.xml
            decompiled_dir: Path to the directory containing decompiled APK code
        """
        self.manifest_dir = manifest_dir
        self.decompiled_dir = decompiled_dir
        self.strings = self._parse_strings()

    def _parse_strings(self) -> Dict[str, str]:
        """
        Parse string resources from the decompiled APK.

        Extracts string resources defined in the APK's resources to allow
        resolution of string references in the manifest and other files.

        Returns:
            Dict[str, str]: Dictionary mapping string resource IDs to their values
        """
        strings = {}
        try:
            # Look for strings.xml in res/values/
            strings_paths = [
                Path(self.decompiled_dir) / "res" / "values" / "strings.xml",
                Path(self.manifest_dir) / "res" / "values" / "strings.xml",
            ]

            for strings_path in strings_paths:
                if strings_path.exists():
                    tree = safe_parse(strings_path)
                    root = tree.getroot()

                    for string_elem in root.findall(".//string"):
                        name = string_elem.get("name")
                        value = string_elem.text or ""
                        if name:
                            strings[name] = value

                    # Also check string-array elements
                    for array_elem in root.findall(".//string-array"):
                        name = array_elem.get("name")
                        if name:
                            items = [item.text or "" for item in array_elem.findall("item")]
                            strings[name] = "|".join(items)

                    break  # Found strings, stop searching

        except ET.ParseError as e:
            logger.debug(f"Failed to parse strings.xml: {e}")
        except Exception as e:
            logger.debug(f"Error parsing string resources: {e}")

        return strings

    def resolve_string(self, value: str) -> Optional[str]:
        """
        Resolve a string reference to its actual value.

        Converts a string reference (like @string/app_name) to its
        actual value as defined in the APK's resources.

        Args:
            value: The string reference to resolve

        Returns:
            Optional[str]: The resolved string value, or the original value if not a reference,
                          or None if reference can't be resolved
        """
        if not value:
            return value

        # Check if this is a string reference
        if value.startswith("@string/"):
            string_name = value[8:]  # Remove "@string/" prefix
            return self.strings.get(string_name, value)

        # Check for resource ID reference (e.g., @0x7f0a0001)
        if value.startswith("@") and "0x" in value:
            # Can't resolve numeric references without R.txt mapping
            return value

        return value

    def validate_manifest(self) -> bool:
        """
        Validate the structure and content of the AndroidManifest.xml file.

        Checks if the manifest file exists, is well-formed XML, and contains
        the required elements for a valid Android application.

        Returns:
            bool: True if the manifest is valid, False otherwise
        """
        try:
            manifest_path = Path(self.manifest_dir) / "AndroidManifest.xml"

            if not manifest_path.exists():
                logger.debug(f"Manifest not found at {manifest_path}")
                return False

            # Try to parse the XML
            tree = safe_parse(manifest_path)
            root = tree.getroot()

            # Check for required root element
            if root.tag != "manifest":
                logger.debug(f"Invalid root element: {root.tag}")
                return False

            # Check for package attribute
            package = root.get("package")
            if not package:
                logger.debug("Missing package attribute in manifest")
                return False

            # Check for application element
            app_elem = root.find("application")
            if app_elem is None:
                logger.debug("Missing <application> element in manifest")
                return False

            return True

        except ET.ParseError as e:
            logger.debug(f"Manifest XML parse error: {e}")
            return False
        except Exception as e:
            logger.debug(f"Manifest validation error: {e}")
            return False

    def extract_deeplinks(self) -> List[str]:
        """
        Extract deep link definitions from the manifest.

        Identifies intent filters in the manifest that define deep links
        which could be used to launch the application from external sources.

        Returns:
            List[str]: List of deep link URI patterns defined in the app
        """
        deeplinks = []
        android_ns = "{http://schemas.android.com/apk/res/android}"

        try:
            manifest_path = Path(self.manifest_dir) / "AndroidManifest.xml"
            if not manifest_path.exists():
                return []

            tree = safe_parse(manifest_path)
            root = tree.getroot()

            # Find all intent-filters with data elements (deep links)
            for intent_filter in root.findall(".//intent-filter"):
                # Check if this intent filter has VIEW action and BROWSABLE category
                actions = [a.get(f"{android_ns}name") for a in intent_filter.findall("action")]
                categories = [c.get(f"{android_ns}name") for c in intent_filter.findall("category")]

                is_browsable = (
                    "android.intent.action.VIEW" in actions and "android.intent.category.BROWSABLE" in categories
                )

                # Extract data elements
                for data in intent_filter.findall("data"):
                    scheme = data.get(f"{android_ns}scheme", "")
                    host = data.get(f"{android_ns}host", "")
                    port = data.get(f"{android_ns}port", "")
                    path = data.get(f"{android_ns}path", "")
                    path_prefix = data.get(f"{android_ns}pathPrefix", "")
                    path_pattern = data.get(f"{android_ns}pathPattern", "")

                    # Build URI pattern
                    if scheme:
                        uri = scheme + "://"
                        if host:
                            uri += host
                            if port:
                                uri += ":" + port
                        if path:
                            uri += path
                        elif path_prefix:
                            uri += path_prefix + "*"
                        elif path_pattern:
                            uri += path_pattern

                        # Mark browsable deep links
                        if is_browsable:
                            uri += " [BROWSABLE]"

                        deeplinks.append(uri)

        except ET.ParseError as e:
            logger.debug(f"Failed to parse manifest for deeplinks: {e}")
        except Exception as e:
            logger.debug(f"Error extracting deeplinks: {e}")

        return deeplinks

    def extract_urls(self) -> Tuple[List[str], List[str]]:
        """
        Extract URLs from the application resources and code.

        Searches through resource files and decompiled code to find URLs
        that could indicate API endpoints, external services, or potential
        hardcoded credentials.

        Returns:
            Tuple[List[str], List[str]]: A tuple containing:
                - List of URLs found in resource files
                - List of URLs found in code files
        """
        resource_urls = set()
        code_urls = set()

        # URL pattern - matches http://, https://, and common schemes
        url_pattern = re.compile(
            r'https?://[^\s<>"\'`\)\]\}]+|' r'file://[^\s<>"\'`\)\]\}]+|' r'content://[^\s<>"\'`\)\]\}]+'
        )

        try:
            decompiled_path = Path(self.decompiled_dir)

            # Search resource files (XML)
            if decompiled_path.exists():
                res_path = decompiled_path / "res"
                if res_path.exists():
                    for xml_file in res_path.rglob("*.xml"):
                        try:
                            content = xml_file.read_text(encoding="utf-8", errors="ignore")
                            urls = url_pattern.findall(content)
                            resource_urls.update(urls)
                        except Exception:
                            continue

            # Search code files (smali, java)
            if decompiled_path.exists():
                # Search smali files
                for smali_file in decompiled_path.rglob("*.smali"):
                    try:
                        content = smali_file.read_text(encoding="utf-8", errors="ignore")
                        urls = url_pattern.findall(content)
                        code_urls.update(urls)
                    except Exception:
                        continue

                # Search java files (if JADX decompiled)
                for java_file in decompiled_path.rglob("*.java"):
                    try:
                        content = java_file.read_text(encoding="utf-8", errors="ignore")
                        urls = url_pattern.findall(content)
                        code_urls.update(urls)
                    except Exception:
                        continue

            # Also search strings dictionary
            for value in self.strings.values():
                if value:
                    urls = url_pattern.findall(value)
                    resource_urls.update(urls)

        except Exception as e:
            logger.debug(f"Error extracting URLs: {e}")

        # Filter out common non-interesting URLs
        exclude_patterns = [
            "schemas.android.com",
            "www.w3.org",
            "ns.adobe.com",
            "xml.org",
            "xmlpull.org",
        ]

        def is_interesting(url: str) -> bool:
            return not any(pattern in url for pattern in exclude_patterns)

        return (
            sorted([u for u in resource_urls if is_interesting(u)])[:500],
            sorted([u for u in code_urls if is_interesting(u)])[:500],
        )

    def get_certificate_details(self) -> Optional[Dict[str, str]]:
        """
        Extract certificate details from the APK signature.

        Analyzes the digital signature(s) used to sign the APK to extract
        information about the signing certificate, which can reveal
        security-relevant details about the app developer.

        Returns:
            Optional[Dict[str, str]]: A dictionary with certificate details or None if
                                     certificate information can't be extracted
        """
        try:
            # Look for certificate files in META-INF
            meta_inf_paths = [
                Path(self.decompiled_dir) / "original" / "META-INF",
                Path(self.decompiled_dir) / "META-INF",
                Path(self.manifest_dir) / "original" / "META-INF",
            ]

            cert_file = None
            for meta_inf in meta_inf_paths:
                if meta_inf.exists():
                    # Look for .RSA, .DSA, or .EC files
                    for ext in ["*.RSA", "*.DSA", "*.EC"]:
                        certs = list(meta_inf.glob(ext))
                        if certs:
                            cert_file = certs[0]
                            break
                if cert_file:
                    break

            if not cert_file:
                logger.debug("No certificate file found in META-INF")
                return None

            # Try to parse certificate using OpenSSL command if available
            import subprocess

            try:
                # Use openssl to parse the PKCS#7 certificate
                result = subprocess.run(
                    ["openssl", "pkcs7", "-inform", "DER", "-print_certs", "-text", "-noout"],
                    input=cert_file.read_bytes(),
                    capture_output=True,
                    timeout=10,
                )

                if result.returncode == 0:
                    cert_text = result.stdout.decode("utf-8", errors="ignore")

                    details = {}

                    # Extract common fields
                    issuer_match = re.search(r"Issuer:\s*(.+)", cert_text)
                    if issuer_match:
                        details["issuer"] = issuer_match.group(1).strip()

                    subject_match = re.search(r"Subject:\s*(.+)", cert_text)
                    if subject_match:
                        details["subject"] = subject_match.group(1).strip()

                    validity_start = re.search(r"Not Before:\s*(.+)", cert_text)
                    if validity_start:
                        details["valid_from"] = validity_start.group(1).strip()

                    validity_end = re.search(r"Not After\s*:\s*(.+)", cert_text)
                    if validity_end:
                        details["valid_until"] = validity_end.group(1).strip()

                    serial_match = re.search(r"Serial Number:\s*\n?\s*([^\n]+)", cert_text)
                    if serial_match:
                        details["serial_number"] = serial_match.group(1).strip()

                    sig_algo_match = re.search(r"Signature Algorithm:\s*(.+)", cert_text)
                    if sig_algo_match:
                        details["signature_algorithm"] = sig_algo_match.group(1).strip()

                    # Extract fingerprint
                    fingerprint_result = subprocess.run(
                        ["openssl", "pkcs7", "-inform", "DER", "-print_certs"],
                        input=cert_file.read_bytes(),
                        capture_output=True,
                        timeout=10,
                    )
                    if fingerprint_result.returncode == 0:
                        sha256_result = subprocess.run(
                            ["openssl", "x509", "-fingerprint", "-sha256", "-noout"],
                            input=fingerprint_result.stdout,
                            capture_output=True,
                            timeout=10,
                        )
                        if sha256_result.returncode == 0:
                            fp_match = re.search(r"SHA256 Fingerprint=(.+)", sha256_result.stdout.decode())
                            if fp_match:
                                details["sha256_fingerprint"] = fp_match.group(1).strip()

                    return details if details else None

            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("OpenSSL not available for certificate parsing")

            # Fallback: Return basic info about certificate file
            return {
                "certificate_file": cert_file.name,
                "certificate_size": str(cert_file.stat().st_size),
            }

        except Exception as e:
            logger.debug(f"Error extracting certificate details: {e}")
            return None

    def is_debuggable(self) -> bool:
        """
        Check if the APK is debuggable from the manifest.

        Examines the AndroidManifest.xml to determine if the application
        has the debuggable flag set to true, which can be a security risk
        in production applications.

        Returns:
            bool: True if the android:debuggable attribute is set to true,
                 False otherwise
        """
        android_ns = "{http://schemas.android.com/apk/res/android}"

        try:
            manifest_path = Path(self.manifest_dir) / "AndroidManifest.xml"
            if not manifest_path.exists():
                return False

            tree = safe_parse(manifest_path)
            root = tree.getroot()

            # Find the application element
            app_elem = root.find("application")
            if app_elem is not None:
                debuggable = app_elem.get(f"{android_ns}debuggable")
                return debuggable == "true"

            return False

        except ET.ParseError as e:
            logger.debug(f"Failed to parse manifest for debuggable flag: {e}")
            return False
        except Exception as e:
            logger.debug(f"Error checking debuggable flag: {e}")
            return False

    def get_permissions(self) -> List[str]:
        """
        Extract permissions requested by the APK from the manifest.

        Identifies all permission declarations in the AndroidManifest.xml,
        including standard Android permissions and any custom permissions
        defined by the application.

        Returns:
            List[str]: A list of permission strings requested by the application
        """
        permissions = []
        android_ns = "{http://schemas.android.com/apk/res/android}"

        try:
            manifest_path = Path(self.manifest_dir) / "AndroidManifest.xml"
            if not manifest_path.exists():
                return []

            tree = safe_parse(manifest_path)
            root = tree.getroot()

            # Find all uses-permission elements
            for perm in root.findall("uses-permission"):
                name = perm.get(f"{android_ns}name")
                if name:
                    permissions.append(name)

            # Also check uses-permission-sdk-23 (runtime permissions)
            for perm in root.findall("uses-permission-sdk-23"):
                name = perm.get(f"{android_ns}name")
                if name and name not in permissions:
                    permissions.append(name)

            # Check for custom permissions defined by the app
            for perm in root.findall("permission"):
                name = perm.get(f"{android_ns}name")
                if name:
                    permissions.append(f"[CUSTOM] {name}")

        except ET.ParseError as e:
            logger.debug(f"Failed to parse manifest for permissions: {e}")
        except Exception as e:
            logger.debug(f"Error extracting permissions: {e}")

        return permissions

    def get_native_libraries(self) -> Optional[List[str]]:
        """
        Extract native libraries (.so files) used by the APK.

        Scans the APK's lib/ directory to identify native code libraries
        that could indicate use of specific functionality or potential
        security concerns related to native code execution.

        Returns:
            Optional[List[str]]: A list of native library filenames or None if
                                the information can't be determined
        """
        libraries = []

        try:
            # Look for lib directories
            lib_paths = [
                Path(self.decompiled_dir) / "lib",
                Path(self.manifest_dir) / "lib",
            ]

            for lib_path in lib_paths:
                if lib_path.exists() and lib_path.is_dir():
                    # Scan for .so files in all architecture subdirectories
                    for so_file in lib_path.rglob("*.so"):
                        # Get architecture and library name
                        try:
                            rel_path = so_file.relative_to(lib_path)
                            parts = rel_path.parts

                            if len(parts) >= 2:
                                arch = parts[0]  # e.g., armeabi-v7a, arm64-v8a, x86
                                lib_name = parts[-1]
                                libraries.append(f"{arch}/{lib_name}")
                            else:
                                libraries.append(so_file.name)

                        except Exception:
                            libraries.append(so_file.name)

                    break  # Found lib directory, stop searching

            # Remove duplicates while preserving order
            seen = set()
            unique_libs = []
            for lib in libraries:
                if lib not in seen:
                    seen.add(lib)
                    unique_libs.append(lib)

            return unique_libs if unique_libs else None

        except Exception as e:
            logger.debug(f"Error extracting native libraries: {e}")
            return None

    def get_classes(self) -> List[str]:
        """
        Extract class names from the decompiled APK.

        Scans the decompiled directory to find all class files and extract
        their names for security analysis.

        Returns:
            List[str]: A list of class names found in the APK
        """
        classes = []

        try:
            from pathlib import Path

            # Search for .smali files in the decompiled directory
            decompiled_path = Path(self.decompiled_dir)
            if decompiled_path.exists():
                smali_files = list(decompiled_path.rglob("*.smali"))

                for smali_file in smali_files:
                    try:
                        # Extract class name from file path
                        relative_path = smali_file.relative_to(decompiled_path)
                        class_name = str(relative_path).replace("/", ".").replace("\\", ".").replace(".smali", "")

                        # Clean up class name
                        if class_name.startswith("smali."):
                            class_name = class_name[6:]  # Remove "smali." prefix

                        classes.append(class_name)

                    except Exception:
                        continue

            return classes[:1000]  # Limit to first 1000 classes for performance

        except Exception:
            return []

    def get_services(self) -> List[str]:
        """
        Extract service declarations from the AndroidManifest.xml.

        Identifies all service components declared in the manifest,
        which could be used for background processing or inter-app communication.

        Returns:
            List[str]: A list of service class names declared in the manifest
        """
        services = []

        try:
            from pathlib import Path

            manifest_path = Path(self.manifest_dir) / "AndroidManifest.xml"
            if manifest_path.exists():
                tree = safe_parse(manifest_path)
                root = tree.getroot()

                # Find all service elements
                for service in root.findall(".//service"):
                    name = service.get("{http://schemas.android.com/apk/res/android}name")
                    if name:
                        services.append(name)

        except Exception:
            pass

        return services

    def get_receivers(self) -> List[str]:
        """
        Extract broadcast receiver declarations from the AndroidManifest.xml.

        Identifies all broadcast receiver components declared in the manifest,
        which could be used for responding to system or application broadcasts.

        Returns:
            List[str]: A list of receiver class names declared in the manifest
        """
        receivers = []

        try:
            from pathlib import Path

            manifest_path = Path(self.manifest_dir) / "AndroidManifest.xml"
            if manifest_path.exists():
                tree = safe_parse(manifest_path)
                root = tree.getroot()

                # Find all receiver elements
                for receiver in root.findall(".//receiver"):
                    name = receiver.get("{http://schemas.android.com/apk/res/android}name")
                    if name:
                        receivers.append(name)

        except Exception:
            pass

        return receivers

    def get_activities(self) -> List[str]:
        """
        Extract activity declarations from the AndroidManifest.xml.

        Identifies all activity components declared in the manifest,
        which represent user interface screens in the application.

        Returns:
            List[str]: A list of activity class names declared in the manifest
        """
        activities = []

        try:
            from pathlib import Path

            manifest_path = Path(self.manifest_dir) / "AndroidManifest.xml"
            if manifest_path.exists():
                tree = safe_parse(manifest_path)
                root = tree.getroot()

                # Find all activity elements
                for activity in root.findall(".//activity"):
                    name = activity.get("{http://schemas.android.com/apk/res/android}name")
                    if name:
                        activities.append(name)

        except Exception:
            pass

        return activities

    def get_exported_components(self) -> Dict[str, List[str]]:
        """
        Extract exported components from the AndroidManifest.xml.

        Identifies components that are marked as exported=true, making them
        accessible to other applications and potentially vulnerable to attacks.

        Returns:
            Dict[str, List[str]]: Dictionary with component types as keys and
                                 lists of exported component names as values
        """
        exported = {"activities": [], "services": [], "receivers": [], "providers": []}

        try:
            from pathlib import Path

            manifest_path = Path(self.manifest_dir) / "AndroidManifest.xml"
            if manifest_path.exists():
                tree = safe_parse(manifest_path)
                root = tree.getroot()

                # Find exported activities
                for activity in root.findall(".//activity"):
                    exported_attr = activity.get("{http://schemas.android.com/apk/res/android}exported")
                    name = activity.get("{http://schemas.android.com/apk/res/android}name")

                    # Check if exported explicitly or has intent-filter (implicitly exported)
                    if (exported_attr == "true" or activity.find("intent-filter") is not None) and name:
                        exported["activities"].append(name)

                # Find exported services
                for service in root.findall(".//service"):
                    exported_attr = service.get("{http://schemas.android.com/apk/res/android}exported")
                    name = service.get("{http://schemas.android.com/apk/res/android}name")

                    if (exported_attr == "true" or service.find("intent-filter") is not None) and name:
                        exported["services"].append(name)

                # Find exported receivers
                for receiver in root.findall(".//receiver"):
                    exported_attr = receiver.get("{http://schemas.android.com/apk/res/android}exported")
                    name = receiver.get("{http://schemas.android.com/apk/res/android}name")

                    if (exported_attr == "true" or receiver.find("intent-filter") is not None) and name:
                        exported["receivers"].append(name)

                # Find exported providers
                for provider in root.findall(".//provider"):
                    exported_attr = provider.get("{http://schemas.android.com/apk/res/android}exported")
                    name = provider.get("{http://schemas.android.com/apk/res/android}name")

                    if exported_attr == "true" and name:
                        exported["providers"].append(name)

        except Exception:
            pass

        return exported

    def get_intent_filters(self) -> List[Dict[str, Any]]:
        """
        Extract intent filter information from the AndroidManifest.xml.

        Identifies intent filters defined for components, which specify
        the types of intents that components can respond to.

        Returns:
            List[Dict[str, Any]]: List of intent filter information
        """
        intent_filters = []

        try:
            from pathlib import Path

            manifest_path = Path(self.manifest_dir) / "AndroidManifest.xml"
            if manifest_path.exists():
                tree = safe_parse(manifest_path)
                root = tree.getroot()

                # Find all components with intent filters
                for component in root.findall(".//*[intent-filter]"):
                    component_name = component.get("{http://schemas.android.com/apk/res/android}name")
                    component_type = component.tag

                    for intent_filter in component.findall("intent-filter"):
                        filter_info = {
                            "component_name": component_name,
                            "component_type": component_type,
                            "actions": [],
                            "categories": [],
                            "data": [],
                        }

                        # Extract actions
                        for action in intent_filter.findall("action"):
                            action_name = action.get("{http://schemas.android.com/apk/res/android}name")
                            if action_name:
                                filter_info["actions"].append(action_name)

                        # Extract categories
                        for category in intent_filter.findall("category"):
                            category_name = category.get("{http://schemas.android.com/apk/res/android}name")
                            if category_name:
                                filter_info["categories"].append(category_name)

                        # Extract data specifications
                        for data in intent_filter.findall("data"):
                            data_info = {}
                            for attr in [
                                "scheme",
                                "host",
                                "port",
                                "path",
                                "pathPattern",
                                "pathPrefix",
                                "mimeType",
                            ]:
                                value = data.get(f"{{http://schemas.android.com/apk/res/android}}{attr}")
                                if value:
                                    data_info[attr] = value
                            if data_info:
                                filter_info["data"].append(data_info)

                        intent_filters.append(filter_info)

        except Exception:
            pass

        return intent_filters
