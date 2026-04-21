"""
core.agent.orchestration_heuristic - Rule-based orchestration fallback (no LLM required).

Selects security analysis plugins based on APK manifest permissions and
component analysis when no LLM API key is available.  Reads the Android
manifest to identify permissions and maps them to relevant plugin categories.

Public API:
    run_heuristic_orchestration(apk_path, report_file, report_dir) -> OrchestrationResult
"""

from __future__ import annotations

import subprocess
import zipfile
from typing import Dict, List, Optional, Set, Tuple

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from .orchestration import (
    OrchestrationResult,
    PluginSelection,
    save_orchestration_to_report,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Core plugins that should always be included regardless of permissions.
# Names MUST match actual plugin directory names in plugins/.
_CORE_PLUGINS: List[Tuple[str, str]] = [
    ("enhanced_manifest_analysis", "Always required - manifest security analysis"),
    ("component_exploitation_plugin", "Always required - exported component exposure"),
    ("enhanced_detection_plugin", "Always required - credential leak / secrets detection"),
    ("crypto_vulnerability_detection", "Always required - cryptographic security fundamentals"),
]

# Permission → plugin directory mapping.
# Names MUST match actual plugin directory names in plugins/.
_PERMISSION_PLUGIN_MAP: Dict[str, List[Tuple[str, str, int]]] = {
    # (plugin_dir_name, reason, priority)
    "android.permission.INTERNET": [
        ("enhanced_network_security_analysis", "INTERNET permission - network attack surface", 1),
        ("network_cleartext_traffic", "INTERNET permission - cleartext traffic detection", 1),
        ("network_communication_tests", "INTERNET permission - network communication tests", 2),
        ("cert_pinning_analyzer", "INTERNET permission - certificate pinning analysis", 2),
    ],
    "android.permission.ACCESS_NETWORK_STATE": [
        ("enhanced_network_security_analysis", "Network state access - network analysis relevant", 2),
    ],
    "android.permission.CAMERA": [
        ("privacy_controls_analysis", "CAMERA permission - privacy controls for media", 2),
    ],
    "android.permission.RECORD_AUDIO": [
        ("privacy_controls_analysis", "RECORD_AUDIO permission - privacy controls for media", 2),
    ],
    "android.permission.READ_EXTERNAL_STORAGE": [
        ("insecure_data_storage", "External storage access - data-at-rest security", 1),
        ("enhanced_data_storage_modular", "External storage access - modular storage analysis", 1),
    ],
    "android.permission.WRITE_EXTERNAL_STORAGE": [
        ("insecure_data_storage", "External storage write - data-at-rest security", 1),
        ("enhanced_data_storage_modular", "External storage write - modular storage analysis", 1),
    ],
    "android.permission.MANAGE_EXTERNAL_STORAGE": [
        ("insecure_data_storage", "Full storage access - data-at-rest security", 1),
        ("enhanced_data_storage_modular", "Full storage access - modular storage analysis", 1),
    ],
    "android.permission.ACCESS_FINE_LOCATION": [
        ("privacy_leak_detection", "Fine location access - location privacy analysis", 1),
        ("tracking_analyzer", "Fine location access - tracking analysis", 2),
    ],
    "android.permission.ACCESS_COARSE_LOCATION": [
        ("privacy_leak_detection", "Coarse location access - location privacy analysis", 2),
    ],
    "android.permission.READ_CONTACTS": [
        ("privacy_leak_detection", "Contacts access - sensitive data handling", 1),
    ],
    "android.permission.READ_SMS": [
        ("privacy_leak_detection", "SMS access - sensitive data handling", 1),
    ],
    "android.permission.RECEIVE_SMS": [
        ("privacy_leak_detection", "SMS receive - sensitive data handling", 1),
    ],
    "android.permission.READ_CALL_LOG": [
        ("privacy_leak_detection", "Call log access - sensitive data handling", 2),
    ],
    "android.permission.USE_BIOMETRIC": [
        ("authentication_security_analysis", "Biometric auth - authentication security", 1),
        ("biometric_security_analysis", "Biometric auth - biometric implementation analysis", 1),
    ],
    "android.permission.USE_FINGERPRINT": [
        ("authentication_security_analysis", "Fingerprint auth - authentication security", 1),
        ("biometric_security_analysis", "Fingerprint auth - biometric implementation analysis", 1),
    ],
    "android.permission.BLUETOOTH": [
        ("attack_surface_analysis", "Bluetooth - IoT/device communication security", 2),
    ],
    "android.permission.BLUETOOTH_CONNECT": [
        ("attack_surface_analysis", "Bluetooth connect - IoT/device communication security", 2),
    ],
    "android.permission.NFC": [
        ("attack_surface_analysis", "NFC - near-field communication security", 2),
    ],
}

# Common manifest locations inside an APK
_MANIFEST_PATHS = [
    "AndroidManifest.xml",
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_permissions_from_manifest(manifest_text: str) -> Set[str]:
    """Extract permission names from manifest XML text."""
    permissions: Set[str] = set()
    # Look for uses-permission tags
    import re

    # Match android:name="..." in uses-permission elements
    for match in re.finditer(
        r'<uses-permission[^>]*android:name\s*=\s*"([^"]+)"', manifest_text
    ):
        permissions.add(match.group(1))
    return permissions


def _read_manifest_from_apk(apk_path: str) -> str:
    """Try to read AndroidManifest.xml from the APK.

    Attempts multiple strategies:
    1. aapt dump to get decoded manifest
    2. Direct ZIP extraction (binary XML, limited usefulness)
    """
    # Strategy 1: Use aapt to dump decoded manifest
    try:
        result = subprocess.run(
            ["aapt", "dump", "xmltree", apk_path, "AndroidManifest.xml"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # Strategy 2: Use aapt2 dump
    try:
        result = subprocess.run(
            ["aapt2", "dump", "xmltree", "--file", "AndroidManifest.xml", apk_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # Strategy 3: Direct ZIP read (may be binary XML but worth trying)
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in _MANIFEST_PATHS:
                if name in zf.namelist():
                    data = zf.read(name)
                    try:
                        return data.decode("utf-8", errors="replace")
                    except Exception:
                        return data.decode("latin-1", errors="replace")
    except (zipfile.BadZipFile, OSError, KeyError):
        pass

    return ""


def _extract_permissions_from_aapt(aapt_output: str) -> Set[str]:
    """Extract permissions from aapt xmltree dump output.

    aapt xmltree format uses lines like:
        A: android:name(0x01010003)="android.permission.INTERNET"
    """
    import re

    permissions: Set[str] = set()

    # aapt xmltree format
    for match in re.finditer(r'"(android\.permission\.[A-Z_]+)"', aapt_output):
        permissions.add(match.group(1))

    # Also try standard XML format in case the content is decoded XML
    for match in re.finditer(
        r'<uses-permission[^>]*android:name\s*=\s*"([^"]+)"', aapt_output
    ):
        permissions.add(match.group(1))

    return permissions


def _detect_manifest_features(
    manifest_text: str,
    selected_plugins: List[PluginSelection],
    seen_plugins: Set[str],
) -> None:
    """Detect WebView, deep link, and content provider usage from manifest.

    These features don't require specific permissions, so permission-only
    analysis misses them. Modifies selected_plugins/seen_plugins in place.
    """
    if not manifest_text:
        return

    import re

    text_lower = manifest_text.lower()

    # WebView detection: look for WebView-related activity names or intent filters
    webview_indicators = (
        "webview", "webkit", "browser", "chromeclient",
        "webviewclient", "shouldoverrideurlloading",
    )
    if any(kw in text_lower for kw in webview_indicators):
        if "webview_security_analyzer" not in seen_plugins:
            selected_plugins.append(PluginSelection(
                plugin_name="webview_security_analyzer",
                reason="WebView usage detected in manifest - WebView security analysis",
                priority=1,
                time_budget_seconds=120,
            ))
            seen_plugins.add("webview_security_analyzer")

    # Deep link / app link detection: intent-filters with VIEW action + data scheme
    deep_link_patterns = (
        re.compile(r'android\.intent\.action\.VIEW', re.IGNORECASE),
        re.compile(r'<data\s+[^>]*android:scheme\s*=', re.IGNORECASE),
        re.compile(r'android:autoVerify\s*=\s*"true"', re.IGNORECASE),
    )
    if any(p.search(manifest_text) for p in deep_link_patterns):
        if "deep_link_security" not in seen_plugins:
            selected_plugins.append(PluginSelection(
                plugin_name="deep_link_security",
                reason="Deep link / app link handlers detected - link injection analysis",
                priority=2,
                time_budget_seconds=120,
            ))
            seen_plugins.add("deep_link_security")

    # Content provider detection
    if "contentprovider" in text_lower or "<provider" in text_lower:
        if "attack_surface_analysis" not in seen_plugins:
            selected_plugins.append(PluginSelection(
                plugin_name="attack_surface_analysis",
                reason="Content providers detected - IPC attack surface analysis",
                priority=2,
                time_budget_seconds=120,
            ))
            seen_plugins.add("attack_surface_analysis")


def _detect_malware_indicators(
    permissions: Set[str],
    manifest_text: str,
    selected_plugins: List[PluginSelection],
    seen_plugins: Set[str],
) -> None:
    """Detect malware-indicative permission combos and manifest patterns.

    Triggers malware_detection plugin when suspicious permission combinations
    are present (banking trojan, spyware, ransomware, SMS stealer patterns).
    Modifies selected_plugins/seen_plugins in place.
    """
    if "malware_detection" in seen_plugins:
        return

    # Permission combos that strongly indicate malware
    # Banking trojan: overlay + accessibility + internet
    banking_combo = {
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.INTERNET",
    }
    # Spyware: camera + mic + location
    spyware_combo = {
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
    }
    # SMS stealer: receive + read SMS
    sms_combo = {
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
    }
    # Ransomware: device admin + storage
    ransomware_indicators = {
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    }
    # Data stealer: contacts + call log + phone
    data_stealer_combo = {
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_PHONE_STATE",
    }

    triggered_reasons: List[str] = []

    if banking_combo <= permissions:
        triggered_reasons.append("banking trojan combo (overlay+accessibility+internet)")
    if spyware_combo <= permissions:
        triggered_reasons.append("spyware combo (camera+mic+location)")
    if sms_combo <= permissions:
        triggered_reasons.append("SMS stealer combo (receive+read SMS)")
    if ransomware_indicators <= permissions:
        triggered_reasons.append("ransomware indicators (device admin+storage)")
    if data_stealer_combo <= permissions:
        triggered_reasons.append("data stealer combo (contacts+call_log+phone)")

    # Cryptominer: wake_lock + internet + boot_completed (persistent background mining)
    cryptominer_combo = {
        "android.permission.WAKE_LOCK",
        "android.permission.INTERNET",
        "android.permission.RECEIVE_BOOT_COMPLETED",
    }
    if cryptominer_combo <= permissions:
        triggered_reasons.append("cryptominer combo (wake_lock+internet+boot_completed)")

    # Also check manifest for accessibility service and device admin declarations
    if manifest_text:
        text_lower = manifest_text.lower()
        if "bind_accessibility_service" in text_lower:
            triggered_reasons.append("accessibility service declared in manifest")
        if "device_admin" in text_lower or "deviceadminreceiver" in text_lower:
            triggered_reasons.append("device admin receiver declared in manifest")
        if "boot_completed" in text_lower and sms_combo & permissions:
            triggered_reasons.append("boot receiver with SMS permissions")
        # Mining pool / stratum protocol references in manifest
        if "stratum" in text_lower or "coinhive" in text_lower or "cryptonight" in text_lower:
            triggered_reasons.append("mining protocol reference in manifest")

    # Also flag excessive dangerous permissions (>8 unique)
    dangerous_count = len(permissions & {
        "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS", "android.permission.READ_SMS",
        "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG", "android.permission.READ_PHONE_STATE",
        "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_DEVICE_ADMIN",
    })
    if dangerous_count >= 8:
        triggered_reasons.append(f"excessive dangerous permissions ({dangerous_count})")

    if triggered_reasons:
        reason_str = "; ".join(triggered_reasons[:3])
        selected_plugins.append(PluginSelection(
            plugin_name="malware_detection",
            reason=f"Malware indicators: {reason_str}",
            priority=1,
            time_budget_seconds=180,
        ))
        seen_plugins.add("malware_detection")

        # Also add native binary analysis for deeper inspection
        if "native_binary_analysis" not in seen_plugins:
            selected_plugins.append(PluginSelection(
                plugin_name="native_binary_analysis",
                reason="Malware indicators - native binary analysis for IoC scanning",
                priority=2,
                time_budget_seconds=120,
            ))
            seen_plugins.add("native_binary_analysis")


def _detect_native_code(
    apk_path: str,
    selected_plugins: list,
    seen_plugins: set,
) -> None:
    """Detect native .so libraries in APK and add native analysis plugin.

    Checks the APK for lib/*.so files. If native code is present and
    the native_binary_analysis plugin isn't already selected, adds it
    with appropriate priority based on library count and names.
    """
    if "native_binary_analysis" in seen_plugins:
        return

    try:
        import zipfile
        from pathlib import Path

        ap = Path(apk_path) if apk_path else None
        if not ap or not ap.exists():
            return

        so_count = 0
        so_names: List[str] = []
        has_crypto = False
        has_jni = False

        with zipfile.ZipFile(str(ap), "r") as zf:
            for entry in zf.namelist():
                if entry.endswith(".so") and entry.startswith("lib/"):
                    so_count += 1
                    name = entry.split("/")[-1].lower()
                    if name not in [n.lower() for n in so_names]:
                        so_names.append(entry.split("/")[-1])
                    if any(kw in name for kw in ("crypto", "ssl", "tls", "cipher")):
                        has_crypto = True
                    if any(kw in name for kw in ("jni", "native", "bridge")):
                        has_jni = True

        if so_count == 0:
            return

        # Determine priority based on what we found
        if has_crypto or has_jni:
            priority = 1
            reason = (
                f"APK contains {so_count} native libraries "
                f"({'crypto/TLS' if has_crypto else 'JNI'} code detected) - "
                f"native binary analysis critical for coverage"
            )
        elif so_count > 20:
            priority = 1
            reason = (
                f"APK contains {so_count} native libraries - "
                f"significant native codebase requires analysis"
            )
        else:
            priority = 2
            reason = f"APK contains {so_count} native libraries"

        from core.agent.orchestration import PluginSelection
        selected_plugins.append(
            PluginSelection(
                plugin_name="native_binary_analysis",
                reason=reason,
                priority=priority,
                time_budget_seconds=600 if so_count > 20 else 300,
            )
        )
        seen_plugins.add("native_binary_analysis")

        logger.debug(
            "orchestration_native_detected",
            so_count=so_count,
            has_crypto=has_crypto,
            has_jni=has_jni,
            sample_libs=so_names[:5],
        )
    except Exception as exc:
        logger.debug("orchestration_native_detection_failed", error=str(exc))


def _detect_attack_surfaces(permissions: Set[str]) -> List[str]:
    """Identify attack surfaces from permissions."""
    surfaces: List[str] = []

    network_perms = {"android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"}
    if permissions & network_perms:
        surfaces.append("network_communication")

    storage_perms = {
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
    }
    if permissions & storage_perms:
        surfaces.append("data_storage")

    auth_perms = {"android.permission.USE_BIOMETRIC", "android.permission.USE_FINGERPRINT"}
    if permissions & auth_perms:
        surfaces.append("authentication")

    location_perms = {"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"}
    if permissions & location_perms:
        surfaces.append("location_tracking")

    data_perms = {
        "android.permission.READ_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG",
    }
    if permissions & data_perms:
        surfaces.append("sensitive_data_access")

    media_perms = {"android.permission.CAMERA", "android.permission.RECORD_AUDIO"}
    if permissions & media_perms:
        surfaces.append("media_capture")

    iot_perms = {
        "android.permission.BLUETOOTH",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.NFC",
    }
    if permissions & iot_perms:
        surfaces.append("device_communication")

    # Malware indicators: excessive dangerous permissions or known combos
    malware_perms = {
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.INSTALL_PACKAGES",
        "android.permission.DELETE_PACKAGES",
    }
    if len(permissions & malware_perms) >= 2:
        surfaces.append("malware_indicators")

    return surfaces


def _detect_app_category(permissions: Set[str]) -> str:
    """Simple heuristic to detect app category from permissions."""
    perm_names = {p.split(".")[-1] for p in permissions}

    # Banking/fintech: biometric + internet (common combo)
    if {"USE_BIOMETRIC", "INTERNET"} <= perm_names:
        return "banking"

    # Media: camera or audio
    if perm_names & {"CAMERA", "RECORD_AUDIO"}:
        return "media"

    # IoT: bluetooth or NFC
    if perm_names & {"BLUETOOTH", "BLUETOOTH_CONNECT", "NFC"}:
        return "iot"

    # Data-heavy: contacts/SMS
    if perm_names & {"READ_CONTACTS", "READ_SMS", "RECEIVE_SMS"}:
        return "social"

    # Location-focused
    if perm_names & {"ACCESS_FINE_LOCATION"}:
        return "location"

    # Minimal permissions
    if len(permissions) <= 3:
        return "utility"

    return "general"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_heuristic_orchestration(
    apk_path: str,
    report_file: Optional[str] = None,
    report_dir: str = "reports",
) -> OrchestrationResult:
    """Run rule-based orchestration without an LLM.

    Reads the APK manifest to extract permissions and maps them to
    relevant plugin categories.  Always includes core plugins
    (manifest_analyzer, exported_components, hardcoded_secrets).

    Args:
        apk_path: Path to the APK file.
        report_file: Optional path to a report file for persisting results.
        report_dir: Directory containing report files (unused but kept for
            API compatibility with run_orchestration).

    Returns:
        OrchestrationResult with selected plugins based on permissions.
    """
    logger.info("heuristic_orchestration_start", apk_path=apk_path)

    # Read manifest and extract permissions
    manifest_text = _read_manifest_from_apk(apk_path)
    if manifest_text:
        permissions = _extract_permissions_from_aapt(manifest_text)
        logger.info(
            "heuristic_orchestration_permissions",
            count=len(permissions),
            permissions=sorted(permissions)[:10],
        )
    else:
        permissions = set()
        logger.warning(
            "heuristic_orchestration_no_manifest",
            apk_path=apk_path,
        )

    # Build plugin selections
    selected_plugins: List[PluginSelection] = []
    seen_plugins: Set[str] = set()

    # Always include core plugins
    for plugin_name, reason in _CORE_PLUGINS:
        selected_plugins.append(
            PluginSelection(
                plugin_name=plugin_name,
                reason=reason,
                priority=1,
                time_budget_seconds=120,
            )
        )
        seen_plugins.add(plugin_name)

    # Map permissions to plugins
    for perm in sorted(permissions):
        mappings = _PERMISSION_PLUGIN_MAP.get(perm, [])
        for plugin_name, reason, priority in mappings:
            if plugin_name not in seen_plugins:
                selected_plugins.append(
                    PluginSelection(
                        plugin_name=plugin_name,
                        reason=reason,
                        priority=priority,
                        time_budget_seconds=120 if priority <= 2 else 60,
                    )
                )
                seen_plugins.add(plugin_name)

    # Native code detection: check APK for .so libraries
    _detect_native_code(apk_path, selected_plugins, seen_plugins)

    # Malware detection: trigger on suspicious permission combinations
    _detect_malware_indicators(permissions, manifest_text, selected_plugins, seen_plugins)

    # Manifest-based detection: WebView, deep links, content providers
    _detect_manifest_features(manifest_text, selected_plugins, seen_plugins)

    # Detect attack surfaces and app category
    attack_surfaces = _detect_attack_surfaces(permissions)
    # Add WebView attack surface if WebView plugins were added
    if "webview_security_analyzer" in seen_plugins:
        if "webview" not in attack_surfaces:
            attack_surfaces.append("webview")
    # Add native_code attack surface if native analysis was selected
    if "native_binary_analysis" in seen_plugins:
        if "native_code" not in attack_surfaces:
            attack_surfaces.append("native_code")
    app_category = _detect_app_category(permissions)

    # Build reasoning
    if permissions:
        reasoning = (
            f"Heuristic orchestration based on {len(permissions)} manifest permissions. "
            f"Detected app category: {app_category}. "
            f"Attack surfaces: {', '.join(attack_surfaces) if attack_surfaces else 'minimal'}. "
            f"Selected {len(selected_plugins)} plugins ({len(_CORE_PLUGINS)} core + "
            f"{len(selected_plugins) - len(_CORE_PLUGINS)} permission-based)."
        )
    else:
        reasoning = (
            "Heuristic orchestration with no manifest permissions detected. "
            "Only core plugins selected. Consider running with a full scan profile."
        )

    # Estimate time
    estimated_seconds = sum(p.time_budget_seconds for p in selected_plugins)
    if estimated_seconds < 120:
        estimated_time = "1-2 minutes"
    elif estimated_seconds < 300:
        estimated_time = "3-5 minutes"
    elif estimated_seconds < 600:
        estimated_time = "5-10 minutes"
    else:
        estimated_time = f"{estimated_seconds // 60}+ minutes"

    result = OrchestrationResult(
        selected_plugins=selected_plugins,
        profile_name=f"heuristic-{app_category}",
        estimated_time=estimated_time,
        reasoning=reasoning,
        app_category=app_category,
        attack_surface=attack_surfaces,
        method="heuristic",
    )

    # Save to report if path provided
    if report_file:
        save_orchestration_to_report(result, report_file)

    logger.info(
        "heuristic_orchestration_complete",
        plugins=len(selected_plugins),
        app_category=app_category,
        attack_surfaces=attack_surfaces,
    )
    return result
