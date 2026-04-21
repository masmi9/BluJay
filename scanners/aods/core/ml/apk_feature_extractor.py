#!/usr/bin/env python3
"""
APK Feature Extractor for Malware Detection

Extracts structural, permission, and behavioral features from APK files
for use in machine learning-based malware detection.

Features extracted:
- Permission features (dangerous, normal, signature, custom)
- Component features (activities, services, receivers, providers)
- Manifest security features (debuggable, backup, cleartext)
- Code structure features (classes, methods, native libs)
- API usage patterns (reflection, crypto, network, SMS)
- Obfuscation indicators

Usage:
    from core.ml.apk_feature_extractor import APKFeatureExtractor

    extractor = APKFeatureExtractor()
    features = extractor.extract_features("/path/to/app.apk")
    feature_vector = extractor.to_numpy(features)
"""

import logging
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple
from xml.etree import ElementTree as ET

import numpy as np

logger = logging.getLogger(__name__)


# Android dangerous permissions (runtime permissions)
DANGEROUS_PERMISSIONS = {
    # Calendar
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    # Call log
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    # Camera
    "android.permission.CAMERA",
    # Contacts
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    # Location
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    # Microphone
    "android.permission.RECORD_AUDIO",
    # Phone
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    # Sensors
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    # SMS
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    # Storage
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_MEDIA_LOCATION",
}

# High-risk permissions often abused by malware
MALWARE_INDICATOR_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.CALL_PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.READ_PHONE_STATE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
}

# Suspicious API patterns commonly used by malware
SUSPICIOUS_API_PATTERNS = {
    "reflection": [
        "java.lang.reflect.",
        "dalvik.system.DexClassLoader",
        "dalvik.system.PathClassLoader",
        "java.lang.Class.forName",
        "java.lang.Class.getMethod",
        "java.lang.reflect.Method.invoke",
    ],
    "dynamic_loading": [
        "DexClassLoader",
        "PathClassLoader",
        "InMemoryDexClassLoader",
        "loadClass",
        "defineClass",
    ],
    "crypto": [
        "javax.crypto.",
        "Cipher.getInstance",
        "SecretKeySpec",
        "MessageDigest",
        "Mac.getInstance",
    ],
    "network": [
        "java.net.URL",
        "java.net.HttpURLConnection",
        "okhttp3.",
        "retrofit2.",
        "org.apache.http.",
        "android.webkit.WebView",
    ],
    "sms": [
        "android.telephony.SmsManager",
        "sendTextMessage",
        "sendMultipartTextMessage",
        "sendDataMessage",
    ],
    "device_admin": [
        "DevicePolicyManager",
        "DeviceAdminReceiver",
        "setActiveAdmin",
        "lockNow",
        "wipeData",
    ],
    "root_detection": [
        "/system/bin/su",
        "/system/xbin/su",
        "com.noshufou.android.su",
        "eu.chainfire.supersu",
        "test-keys",
    ],
    "anti_emulator": [
        "Build.FINGERPRINT",
        "Build.MODEL",
        "Build.MANUFACTURER",
        "Build.BRAND",
        "Build.DEVICE",
        "Build.PRODUCT",
        "android.os.SystemProperties",
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "goldfish",
    ],
    "data_exfiltration": [
        "getDeviceId",
        "getSubscriberId",
        "getSimSerialNumber",
        "getLine1Number",
        "getAccounts",
        "ContactsContract",
        "CallLog.Calls",
    ],
}

# Obfuscation indicators
OBFUSCATION_PATTERNS = {
    "proguard": ["proguard", "a.class", "b.class", "a/a.class", "a/b/a.class"],
    "short_names": re.compile(r"^[a-z]{1,2}$"),
    "random_names": re.compile(r"^[a-zA-Z0-9]{20,}$"),
}


@dataclass
class APKFeatures:
    """Container for extracted APK features."""

    # Basic info
    package_name: str = ""
    version_code: int = 0
    version_name: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    file_size: int = 0

    # Permissions
    permissions: List[str] = field(default_factory=list)
    dangerous_permissions: List[str] = field(default_factory=list)
    malware_indicator_permissions: List[str] = field(default_factory=list)
    custom_permissions: List[str] = field(default_factory=list)

    # Components
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    exported_components: int = 0

    # Manifest security
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext_traffic: bool = False
    network_security_config: bool = False

    # Code structure
    dex_count: int = 0
    class_count: int = 0
    method_count: int = 0
    native_libs: List[str] = field(default_factory=list)
    native_lib_count: int = 0

    # API usage
    api_patterns: Dict[str, int] = field(default_factory=dict)

    # Obfuscation
    obfuscation_score: float = 0.0
    short_class_names: int = 0

    # Assets and resources
    asset_count: int = 0
    has_embedded_apk: bool = False
    has_embedded_dex: bool = False
    has_encrypted_assets: bool = False

    # Certificate
    cert_count: int = 0

    # Intent filter & component features (T142 expansion)
    intent_filter_count: int = 0
    has_boot_completed_receiver: bool = False
    has_sms_received_receiver: bool = False
    has_accessibility_service: bool = False
    has_device_admin_receiver: bool = False
    has_notification_listener: bool = False
    boot_receiver_count: int = 0
    high_priority_receiver_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "package_name": self.package_name,
            "version_code": self.version_code,
            "version_name": self.version_name,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "file_size": self.file_size,
            "permissions": self.permissions,
            "dangerous_permissions": self.dangerous_permissions,
            "malware_indicator_permissions": self.malware_indicator_permissions,
            "custom_permissions": self.custom_permissions,
            "activities": self.activities,
            "services": self.services,
            "receivers": self.receivers,
            "providers": self.providers,
            "exported_components": self.exported_components,
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "uses_cleartext_traffic": self.uses_cleartext_traffic,
            "network_security_config": self.network_security_config,
            "dex_count": self.dex_count,
            "class_count": self.class_count,
            "method_count": self.method_count,
            "native_libs": self.native_libs,
            "native_lib_count": self.native_lib_count,
            "api_patterns": self.api_patterns,
            "obfuscation_score": self.obfuscation_score,
            "short_class_names": self.short_class_names,
            "asset_count": self.asset_count,
            "has_embedded_apk": self.has_embedded_apk,
            "has_embedded_dex": self.has_embedded_dex,
            "has_encrypted_assets": self.has_encrypted_assets,
            "cert_count": self.cert_count,
            "intent_filter_count": self.intent_filter_count,
            "has_boot_completed_receiver": self.has_boot_completed_receiver,
            "has_sms_received_receiver": self.has_sms_received_receiver,
            "has_accessibility_service": self.has_accessibility_service,
            "has_device_admin_receiver": self.has_device_admin_receiver,
            "has_notification_listener": self.has_notification_listener,
            "boot_receiver_count": self.boot_receiver_count,
            "high_priority_receiver_count": self.high_priority_receiver_count,
        }


class APKFeatureExtractor:
    """Extract features from APK files for malware detection."""

    # Feature vector size (expanded from 100 in T142 to include intent filter,
    # permission combination, and cross-feature interaction features)
    FEATURE_SIZE = 120

    def __init__(self, use_androguard: bool = True):
        """
        Initialize extractor.

        Args:
            use_androguard: Try to use androguard for detailed analysis
        """
        self.use_androguard = use_androguard
        self._androguard_available = False

        if use_androguard:
            try:
                # Try new androguard API first (4.x+)
                self._androguard_available = True
                self._androguard_new_api = True
            except ImportError:
                try:
                    # Fall back to old API (3.x)
                    self._androguard_available = True
                    self._androguard_new_api = False
                except ImportError:
                    logger.warning("androguard not available, using fallback extraction")

    def extract_features(self, apk_path: str) -> APKFeatures:
        """
        Extract features from an APK file.

        Args:
            apk_path: Path to APK file

        Returns:
            APKFeatures object with extracted features
        """
        apk_path = Path(apk_path)
        if not apk_path.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")

        features = APKFeatures()
        features.file_size = apk_path.stat().st_size

        if self._androguard_available:
            try:
                return self._extract_with_androguard(apk_path, features)
            except Exception as e:
                logger.warning(f"Androguard extraction failed, using fallback: {e}")

        return self._extract_fallback(apk_path, features)

    def _extract_with_androguard(self, apk_path: Path, features: APKFeatures) -> APKFeatures:
        """Extract features using androguard."""
        if getattr(self, "_androguard_new_api", False):
            from androguard.core.apk import APK
            from androguard.core.dex import DEX
        else:
            from androguard.core.bytecodes.apk import APK
            from androguard.core.bytecodes.dvm import DalvikVMFormat as DEX

        apk = APK(str(apk_path))

        # Basic info
        features.package_name = apk.get_package() or ""
        features.version_code = int(apk.get_androidversion_code() or 0)
        features.version_name = apk.get_androidversion_name() or ""
        features.min_sdk = int(apk.get_min_sdk_version() or 0)
        features.target_sdk = int(apk.get_target_sdk_version() or 0)

        # Permissions
        features.permissions = apk.get_permissions()
        features.dangerous_permissions = [p for p in features.permissions if p in DANGEROUS_PERMISSIONS]
        features.malware_indicator_permissions = [p for p in features.permissions if p in MALWARE_INDICATOR_PERMISSIONS]

        # Custom permissions (app-defined)
        declared = apk.get_declared_permissions()
        features.custom_permissions = list(declared) if declared else []

        # Components
        features.activities = apk.get_activities()
        features.services = apk.get_services()
        features.receivers = apk.get_receivers()
        features.providers = apk.get_providers()

        # Count exported components
        manifest = apk.get_android_manifest_xml()
        if manifest is not None:
            features.exported_components = self._count_exported_components(manifest)

        # Manifest security flags from XML
        android_ns = "{http://schemas.android.com/apk/res/android}"
        app_elem = manifest.find(".//application") if manifest is not None else None

        if app_elem is not None:
            # Debuggable
            debuggable = app_elem.get(f"{android_ns}debuggable")
            features.debuggable = debuggable == "true"

            # Allow backup (default True if not specified)
            backup = app_elem.get(f"{android_ns}allowBackup")
            features.allow_backup = backup != "false"

            # Cleartext traffic
            cleartext = app_elem.get(f"{android_ns}usesCleartextTraffic")
            features.uses_cleartext_traffic = cleartext == "true"

            # Network security config
            nsc = app_elem.get(f"{android_ns}networkSecurityConfig")
            features.network_security_config = nsc is not None

        # DEX analysis
        dex_files = [f for f in apk.get_files() if f.endswith(".dex")]
        features.dex_count = len(dex_files)

        # Analyze main DEX for code patterns
        try:
            dvm = None

            if getattr(self, "_androguard_new_api", False):
                # New API: get_all_dex returns generator of raw bytes
                dex_bytes_list = list(apk.get_all_dex())
                if dex_bytes_list:
                    # Parse bytes with DEX class
                    dvm = DEX(dex_bytes_list[0])
            else:
                # Old API
                dex = apk.get_dex()
                if dex:
                    dvm = DEX(dex)

            if dvm:
                features.class_count = len(list(dvm.get_classes()))
                features.method_count = len(list(dvm.get_methods()))

                # API pattern detection
                features.api_patterns = self._detect_api_patterns(dvm)

                # Obfuscation detection
                features.obfuscation_score, features.short_class_names = self._detect_obfuscation(dvm)
        except Exception as e:
            logger.debug(f"DEX analysis failed: {e}")

        # Native libraries
        features.native_libs = [f for f in apk.get_files() if f.endswith(".so") and "lib/" in f]
        features.native_lib_count = len(features.native_libs)

        # Assets analysis
        assets = [f for f in apk.get_files() if f.startswith("assets/")]
        features.asset_count = len(assets)
        features.has_embedded_apk = any(f.endswith(".apk") for f in apk.get_files())
        features.has_embedded_dex = any(f.endswith(".dex") and not f.startswith("classes") for f in apk.get_files())

        # Check for encrypted assets
        features.has_encrypted_assets = self._check_encrypted_assets(apk)

        # Certificate count
        features.cert_count = len(apk.get_certificates())

        # T142: Intent filter & component analysis from manifest
        if manifest is not None:
            self._extract_intent_filter_features(manifest, features)

        return features

    def _extract_intent_filter_features(self, manifest: ET.Element, features: APKFeatures) -> None:
        """Extract intent filter, receiver, and service features from manifest XML."""
        android_ns = "{http://schemas.android.com/apk/res/android}"
        intent_filter_count = 0
        boot_receiver_count = 0
        high_priority_count = 0

        # Scan all intent-filter elements
        for intent_filter in manifest.findall(".//intent-filter"):
            intent_filter_count += 1

            # Check priority
            priority_str = intent_filter.get(f"{android_ns}priority", "0")
            try:
                priority = int(priority_str)
                if priority >= 999:
                    high_priority_count += 1
            except (ValueError, TypeError):
                pass

            # Check for BOOT_COMPLETED action
            for action in intent_filter.findall("action"):
                action_name = action.get(f"{android_ns}name", "")
                if action_name == "android.intent.action.BOOT_COMPLETED":
                    boot_receiver_count += 1
                    features.has_boot_completed_receiver = True
                elif action_name == "android.provider.Telephony.SMS_RECEIVED":
                    features.has_sms_received_receiver = True

        features.intent_filter_count = intent_filter_count
        features.boot_receiver_count = boot_receiver_count
        features.high_priority_receiver_count = high_priority_count

        # Check for accessibility service declaration
        for service in manifest.findall(".//service"):
            permission = service.get(f"{android_ns}permission", "")
            if permission == "android.permission.BIND_ACCESSIBILITY_SERVICE":
                features.has_accessibility_service = True
            elif permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":
                features.has_notification_listener = True

            # Check meta-data for device admin
            for meta in service.findall("meta-data"):
                meta_name = meta.get(f"{android_ns}name", "")
                if meta_name == "android.app.device_admin":
                    features.has_device_admin_receiver = True

        # Also check receivers for device admin
        for receiver in manifest.findall(".//receiver"):
            permission = receiver.get(f"{android_ns}permission", "")
            if permission == "android.permission.BIND_DEVICE_ADMIN":
                features.has_device_admin_receiver = True
            for meta in receiver.findall("meta-data"):
                meta_name = meta.get(f"{android_ns}name", "")
                if meta_name == "android.app.device_admin":
                    features.has_device_admin_receiver = True

    def _extract_fallback(self, apk_path: Path, features: APKFeatures) -> APKFeatures:
        """Extract features using basic zipfile analysis (no androguard)."""
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                file_list = zf.namelist()

                # Count DEX files
                features.dex_count = sum(1 for f in file_list if f.endswith(".dex"))

                # Native libraries
                features.native_libs = [f for f in file_list if f.endswith(".so") and "lib/" in f]
                features.native_lib_count = len(features.native_libs)

                # Assets
                assets = [f for f in file_list if f.startswith("assets/")]
                features.asset_count = len(assets)
                features.has_embedded_apk = any(f.endswith(".apk") for f in file_list)
                features.has_embedded_dex = any(f.endswith(".dex") and not f.startswith("classes") for f in file_list)

                # Certificates
                features.cert_count = sum(
                    1 for f in file_list if f.startswith("META-INF/") and (f.endswith(".RSA") or f.endswith(".DSA"))
                )

                # Try to parse AndroidManifest.xml (binary format)
                if "AndroidManifest.xml" in file_list:
                    try:
                        zf.read("AndroidManifest.xml")
                        # Note: This is binary XML, needs special parsing
                        # For now, just check if it exists
                        features.class_count = len([f for f in file_list if f.endswith(".class")])
                    except Exception:
                        pass

        except zipfile.BadZipFile:
            logger.error(f"Invalid APK file: {apk_path}")

        return features

    def _count_exported_components(self, manifest: ET.Element) -> int:
        """Count exported components in manifest."""
        count = 0
        android_ns = "{http://schemas.android.com/apk/res/android}"

        for tag in ["activity", "service", "receiver", "provider"]:
            for elem in manifest.findall(f".//{tag}"):
                exported = elem.get(f"{android_ns}exported")

                # If exported is explicitly true
                if exported == "true":
                    count += 1
                # If has intent-filter and exported not explicitly false (pre-Android 12)
                elif exported != "false" and elem.find("intent-filter") is not None:
                    count += 1

        return count

    def _detect_api_patterns(self, dvm) -> Dict[str, int]:
        """Detect suspicious API usage patterns."""
        patterns: Dict[str, int] = {cat: 0 for cat in SUSPICIOUS_API_PATTERNS}

        try:
            for method in dvm.get_methods():
                code = method.get_code()
                if not code:
                    continue

                try:
                    # Get bytecode as string for pattern matching
                    bc = method.get_source() if hasattr(method, "get_source") else ""
                    if not bc:
                        continue

                    for category, api_list in SUSPICIOUS_API_PATTERNS.items():
                        for api in api_list:
                            if api in bc:
                                patterns[category] += 1
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"API pattern detection failed: {e}")

        return patterns

    def _detect_obfuscation(self, dvm) -> Tuple[float, int]:
        """Detect obfuscation indicators."""
        short_names = 0
        total_classes = 0

        try:
            for cls in dvm.get_classes():
                total_classes += 1
                name = cls.get_name()

                # Extract simple class name
                if "/" in name:
                    name = name.split("/")[-1]
                name = name.rstrip(";").lstrip("L")

                # Check for short names (ProGuard-style)
                if len(name) <= 2:
                    short_names += 1
        except Exception:
            pass

        if total_classes == 0:
            return 0.0, 0

        # Obfuscation score based on ratio of short names
        score = short_names / total_classes

        return score, short_names

    def _check_encrypted_assets(self, apk) -> bool:
        """Check for potentially encrypted assets."""
        try:
            for filename in apk.get_files():
                if not filename.startswith("assets/"):
                    continue

                # Check for common encrypted file extensions
                if any(filename.endswith(ext) for ext in [".enc", ".encrypted", ".dat", ".bin"]):
                    return True

                # Check for high entropy (encrypted) content
                try:
                    content = apk.get_file(filename)
                    if content and len(content) > 100:
                        entropy = self._calculate_entropy(content[:1000])
                        if entropy > 7.5:  # High entropy suggests encryption
                            return True
                except Exception:
                    continue
        except Exception:
            pass

        return False

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        entropy = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * np.log2(p)

        return entropy

    def to_numpy(self, features: APKFeatures) -> np.ndarray:
        """
        Convert APKFeatures to numpy feature vector for ML.

        Returns:
            numpy array of shape (120,) with normalized features
        """
        vec = np.zeros(self.FEATURE_SIZE)

        # 0-4: Basic info (5)
        vec[0] = np.log10(max(features.file_size, 1)) / 9  # Normalize to ~0-1
        vec[1] = features.min_sdk / 35  # Normalize by max SDK
        vec[2] = features.target_sdk / 35
        vec[3] = features.dex_count / 10  # Normalize by typical max
        vec[4] = features.cert_count / 5

        # 5-14: Permission counts (10)
        vec[5] = len(features.permissions) / 50
        vec[6] = len(features.dangerous_permissions) / 20
        vec[7] = len(features.malware_indicator_permissions) / 15
        vec[8] = len(features.custom_permissions) / 10

        # Specific dangerous permission indicators
        perm_set = set(features.permissions)
        vec[9] = 1 if "android.permission.SEND_SMS" in perm_set else 0
        vec[10] = 1 if "android.permission.READ_SMS" in perm_set else 0
        vec[11] = 1 if "android.permission.RECEIVE_BOOT_COMPLETED" in perm_set else 0
        vec[12] = 1 if "android.permission.SYSTEM_ALERT_WINDOW" in perm_set else 0
        vec[13] = 1 if "android.permission.INSTALL_PACKAGES" in perm_set else 0
        vec[14] = 1 if "android.permission.READ_PHONE_STATE" in perm_set else 0

        # 15-24: Component counts (10)
        vec[15] = len(features.activities) / 50
        vec[16] = len(features.services) / 20
        vec[17] = len(features.receivers) / 20
        vec[18] = len(features.providers) / 10
        vec[19] = features.exported_components / 20
        vec[20] = 1 if len(features.services) > 5 else 0  # Many services (suspicious)
        vec[21] = 1 if len(features.receivers) > 10 else 0  # Many receivers
        vec[22] = 1 if features.exported_components > 10 else 0  # Many exported
        vec[23] = features.native_lib_count / 20
        vec[24] = 1 if features.native_lib_count > 0 else 0  # Has native code

        # 25-29: Manifest security (5)
        vec[25] = 1 if features.debuggable else 0
        vec[26] = 1 if features.allow_backup else 0
        vec[27] = 1 if features.uses_cleartext_traffic else 0
        vec[28] = 1 if not features.network_security_config else 0  # Missing = risky
        vec[29] = 1 if features.min_sdk < 23 else 0  # Old SDK = less secure

        # 30-39: Code structure (10)
        vec[30] = features.class_count / 10000
        vec[31] = features.method_count / 100000
        vec[32] = features.obfuscation_score
        vec[33] = features.short_class_names / 1000
        vec[34] = 1 if features.obfuscation_score > 0.3 else 0  # Heavily obfuscated
        vec[35] = features.asset_count / 100
        vec[36] = 1 if features.has_embedded_apk else 0
        vec[37] = 1 if features.has_embedded_dex else 0
        vec[38] = 1 if features.has_encrypted_assets else 0
        vec[39] = 1 if features.dex_count > 1 else 0  # Multi-dex

        # 40-59: API patterns (20)
        api = features.api_patterns
        vec[40] = min(api.get("reflection", 0) / 50, 1)
        vec[41] = min(api.get("dynamic_loading", 0) / 20, 1)
        vec[42] = min(api.get("crypto", 0) / 30, 1)
        vec[43] = min(api.get("network", 0) / 50, 1)
        vec[44] = min(api.get("sms", 0) / 10, 1)
        vec[45] = min(api.get("device_admin", 0) / 5, 1)
        vec[46] = min(api.get("root_detection", 0) / 10, 1)
        vec[47] = min(api.get("anti_emulator", 0) / 10, 1)
        vec[48] = min(api.get("data_exfiltration", 0) / 20, 1)

        # Binary indicators for suspicious patterns
        vec[49] = 1 if api.get("reflection", 0) > 10 else 0
        vec[50] = 1 if api.get("dynamic_loading", 0) > 0 else 0
        vec[51] = 1 if api.get("sms", 0) > 0 else 0
        vec[52] = 1 if api.get("device_admin", 0) > 0 else 0
        vec[53] = 1 if api.get("root_detection", 0) > 0 else 0
        vec[54] = 1 if api.get("anti_emulator", 0) > 0 else 0
        vec[55] = 1 if api.get("data_exfiltration", 0) > 5 else 0

        # Combination features
        vec[56] = 1 if (api.get("sms", 0) > 0 and "android.permission.SEND_SMS" in perm_set) else 0
        vec[57] = 1 if (api.get("dynamic_loading", 0) > 0 and features.has_encrypted_assets) else 0
        vec[58] = 1 if (features.obfuscation_score > 0.3 and api.get("reflection", 0) > 10) else 0
        vec[59] = 1 if (len(features.malware_indicator_permissions) > 3 and features.exported_components > 5) else 0

        # 60-79: Permission-based features (20)
        dangerous_perms_list = [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.BODY_SENSORS",
            "android.permission.GET_ACCOUNTS",
            "android.permission.CALL_PHONE",
            "android.permission.ANSWER_PHONE_CALLS",
            "android.permission.ADD_VOICEMAIL",
            "android.permission.USE_SIP",
            "android.permission.RECEIVE_MMS",
            "android.permission.RECEIVE_WAP_PUSH",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        ]
        for i, perm in enumerate(dangerous_perms_list):
            vec[60 + i] = 1 if perm in perm_set else 0

        # 80-89: Size-based features (10)
        vec[80] = 1 if features.file_size < 100_000 else 0  # Tiny APK
        vec[81] = 1 if features.file_size > 50_000_000 else 0  # Large APK
        vec[82] = 1 if features.class_count < 100 else 0  # Very few classes
        vec[83] = 1 if features.class_count > 5000 else 0  # Many classes
        vec[84] = 1 if len(features.activities) < 2 else 0  # Few activities
        vec[85] = 1 if len(features.activities) == 0 else 0  # No activities
        vec[86] = 1 if features.method_count > 50000 else 0  # Many methods
        vec[87] = 1 if len(features.receivers) > len(features.activities) else 0
        vec[88] = 1 if len(features.services) > len(features.activities) else 0
        vec[89] = np.log10(max(features.method_count + 1, 1)) / 6

        # 90-99: Composite risk indicators (10)
        # Risk score based on malware indicators
        risk_score = 0
        risk_score += len(features.malware_indicator_permissions) * 0.1
        risk_score += features.obfuscation_score * 0.2
        risk_score += (1 if features.has_embedded_dex else 0) * 0.15
        risk_score += (1 if features.has_encrypted_assets else 0) * 0.1
        risk_score += min(api.get("dynamic_loading", 0) / 10, 0.2)
        risk_score += (1 if features.debuggable else 0) * 0.05
        risk_score += min(features.exported_components / 20, 0.1)

        vec[90] = min(risk_score, 1.0)
        vec[91] = 1 if risk_score > 0.3 else 0
        vec[92] = 1 if risk_score > 0.5 else 0
        vec[93] = 1 if risk_score > 0.7 else 0

        # Permission density
        if len(features.activities) + len(features.services) > 0:
            perm_density = len(features.permissions) / (len(features.activities) + len(features.services))
            vec[94] = min(perm_density / 5, 1)

        # API diversity score
        api_categories_used = sum(1 for v in api.values() if v > 0)
        vec[95] = api_categories_used / len(SUSPICIOUS_API_PATTERNS)

        # Native code risk
        vec[96] = 1 if (features.native_lib_count > 0 and features.obfuscation_score > 0.2) else 0

        # Targeting old devices (potential exploit target)
        vec[97] = 1 if features.target_sdk < 26 else 0

        # Multi-dex with obfuscation
        vec[98] = 1 if (features.dex_count > 1 and features.obfuscation_score > 0.2) else 0

        # Final composite malware probability estimate
        vec[99] = np.clip(risk_score * 1.5, 0, 1)

        # 100-104: Intent filter features (5)
        vec[100] = min(features.intent_filter_count / 50, 1)
        vec[101] = 1 if features.has_boot_completed_receiver else 0
        vec[102] = 1 if features.has_sms_received_receiver else 0
        vec[103] = features.boot_receiver_count / 5
        vec[104] = features.high_priority_receiver_count / 5

        # 105-109: Permission combination features (5)
        # Banking trojan combo: overlay + accessibility + internet
        has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in perm_set
        has_accessibility = features.has_accessibility_service
        has_internet = "android.permission.INTERNET" in perm_set
        vec[105] = 1 if (has_overlay and has_accessibility and has_internet) else 0

        # Spyware combo: camera + mic + location
        has_camera = "android.permission.CAMERA" in perm_set
        has_mic = "android.permission.RECORD_AUDIO" in perm_set
        has_location = "android.permission.ACCESS_FINE_LOCATION" in perm_set
        vec[106] = 1 if (has_camera and has_mic and has_location) else 0

        # SMS stealer combo: receive + read + send SMS
        has_receive_sms = "android.permission.RECEIVE_SMS" in perm_set
        has_read_sms = "android.permission.READ_SMS" in perm_set
        has_send_sms = "android.permission.SEND_SMS" in perm_set
        vec[107] = 1 if (has_receive_sms and has_read_sms) else 0

        # Ransomware combo: device admin + storage + alert window
        has_write_storage = "android.permission.WRITE_EXTERNAL_STORAGE" in perm_set
        vec[108] = 1 if (features.has_device_admin_receiver and has_write_storage and has_overlay) else 0

        # Data stealer combo: contacts + call log + phone state
        has_contacts = "android.permission.READ_CONTACTS" in perm_set
        has_call_log = "android.permission.READ_CALL_LOG" in perm_set
        has_phone_state = "android.permission.READ_PHONE_STATE" in perm_set
        vec[109] = 1 if (has_contacts and has_call_log and has_phone_state) else 0

        # 110-114: Receiver/service pattern features (5)
        vec[110] = 1 if features.has_accessibility_service else 0
        vec[111] = 1 if features.has_device_admin_receiver else 0
        vec[112] = 1 if features.has_notification_listener else 0
        # Boot receiver with SMS - common dropper/stealer pattern
        vec[113] = 1 if (features.has_boot_completed_receiver and has_send_sms) else 0
        # High-priority receiver with accessibility - overlay attack pattern
        vec[114] = 1 if (features.high_priority_receiver_count > 0 and has_accessibility) else 0

        # 115-119: Cross-feature malware interaction scores (5)
        # Malware "breadth" score: count of distinct malware combos triggered
        combo_count = int(vec[105]) + int(vec[106]) + int(vec[107]) + int(vec[108]) + int(vec[109])
        vec[115] = combo_count / 5

        # Evasion + payload indicator: obfuscation/anti-emulator + device admin/dynamic loading
        evasion = features.obfuscation_score > 0.3 or api.get("anti_emulator", 0) > 0
        payload = features.has_device_admin_receiver or api.get("dynamic_loading", 0) > 0
        vec[116] = 1 if (evasion and payload) else 0

        # Persistence + exfiltration: boot receiver + data exfiltration APIs
        persistence = features.has_boot_completed_receiver
        exfil = api.get("data_exfiltration", 0) > 3
        vec[117] = 1 if (persistence and exfil) else 0

        # Stealth score: native code + encrypted assets + obfuscation
        stealth_count = sum([
            features.native_lib_count > 0,
            features.has_encrypted_assets,
            features.obfuscation_score > 0.3,
            api.get("anti_emulator", 0) > 0,
            api.get("root_detection", 0) > 0,
        ])
        vec[118] = stealth_count / 5

        # Malware density: weighted sum of all malware-indicator features
        vec[119] = np.clip(
            (len(features.malware_indicator_permissions) * 0.05
             + combo_count * 0.15
             + stealth_count * 0.1
             + risk_score * 0.3),
            0, 1,
        )

        return vec

    @staticmethod
    def get_feature_names() -> List[str]:
        """Get names for all features in the vector."""
        names = [
            # 0-4: Basic info
            "file_size_log",
            "min_sdk_norm",
            "target_sdk_norm",
            "dex_count_norm",
            "cert_count_norm",
            # 5-14: Permission counts
            "total_perms",
            "dangerous_perms",
            "malware_indicator_perms",
            "custom_perms",
            "has_send_sms",
            "has_read_sms",
            "has_boot_completed",
            "has_system_alert",
            "has_install_packages",
            "has_read_phone_state",
            # 15-24: Component counts
            "activities_norm",
            "services_norm",
            "receivers_norm",
            "providers_norm",
            "exported_norm",
            "many_services",
            "many_receivers",
            "many_exported",
            "native_lib_count",
            "has_native_code",
            # 25-29: Manifest security
            "is_debuggable",
            "allow_backup",
            "cleartext_traffic",
            "no_network_security",
            "old_min_sdk",
            # 30-39: Code structure
            "class_count_norm",
            "method_count_norm",
            "obfuscation_score",
            "short_names_count",
            "heavily_obfuscated",
            "asset_count_norm",
            "has_embedded_apk",
            "has_embedded_dex",
            "has_encrypted_assets",
            "is_multidex",
            # 40-59: API patterns
            "reflection_count",
            "dynamic_loading_count",
            "crypto_count",
            "network_count",
            "sms_api_count",
            "device_admin_count",
            "root_detection_count",
            "anti_emulator_count",
            "data_exfil_count",
            "heavy_reflection",
            "uses_dynamic_loading",
            "uses_sms_api",
            "uses_device_admin",
            "uses_root_detection",
            "uses_anti_emulator",
            "heavy_data_exfil",
            "sms_with_perm",
            "dynamic_with_encrypted",
            "obfuscated_with_reflection",
            "risky_perms_with_exports",
            # 60-79: Individual dangerous permissions
            "perm_fine_location",
            "perm_coarse_location",
            "perm_camera",
            "perm_record_audio",
            "perm_read_contacts",
            "perm_write_contacts",
            "perm_read_calendar",
            "perm_write_calendar",
            "perm_read_call_log",
            "perm_write_call_log",
            "perm_body_sensors",
            "perm_get_accounts",
            "perm_call_phone",
            "perm_answer_phone",
            "perm_add_voicemail",
            "perm_use_sip",
            "perm_receive_mms",
            "perm_receive_wap",
            "perm_read_storage",
            "perm_write_storage",
            # 80-89: Size-based features
            "is_tiny_apk",
            "is_large_apk",
            "few_classes",
            "many_classes",
            "few_activities",
            "no_activities",
            "many_methods",
            "more_receivers_than_activities",
            "more_services_than_activities",
            "method_count_log",
            # 90-99: Composite risk indicators
            "risk_score",
            "risk_medium",
            "risk_high",
            "risk_critical",
            "perm_density",
            "api_diversity",
            "native_with_obfuscation",
            "targets_old_sdk",
            "multidex_with_obfuscation",
            "malware_probability",
            # 100-104: Intent filter features
            "intent_filter_count",
            "has_boot_receiver",
            "has_sms_receiver",
            "boot_receiver_count",
            "high_priority_receiver_count",
            # 105-109: Permission combination features
            "combo_banking_trojan",
            "combo_spyware",
            "combo_sms_stealer",
            "combo_ransomware",
            "combo_data_stealer",
            # 110-114: Receiver/service patterns
            "has_accessibility_service",
            "has_device_admin",
            "has_notification_listener",
            "boot_with_sms",
            "priority_with_accessibility",
            # 115-119: Cross-feature interactions
            "malware_combo_breadth",
            "evasion_with_payload",
            "persistence_with_exfil",
            "stealth_score",
            "malware_density",
        ]
        return names


def extract_features_from_apk(apk_path: str) -> Tuple[APKFeatures, np.ndarray]:
    """
    Convenience function to extract features from an APK.

    Args:
        apk_path: Path to APK file

    Returns:
        Tuple of (APKFeatures, numpy feature vector)
    """
    extractor = APKFeatureExtractor()
    features = extractor.extract_features(apk_path)
    vector = extractor.to_numpy(features)
    return features, vector
