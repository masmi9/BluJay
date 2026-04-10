"""
Dangerous and notable Android permissions with risk classification.
Based on AOSP platform/frameworks/base/core/res/AndroidManifest.xml.
"""
from dataclasses import dataclass


@dataclass
class PermissionMeta:
    short_name: str
    protection_level: str  # normal | dangerous | signature | signatureOrSystem
    description: str
    risk: str  # none | low | medium | high | critical


# Subset of well-known permissions with risk context
_PERMISSION_DB: dict[str, PermissionMeta] = {
    # --- Critical ---
    "android.permission.READ_CONTACTS": PermissionMeta("READ_CONTACTS", "dangerous", "Read device contacts", "high"),
    "android.permission.WRITE_CONTACTS": PermissionMeta("WRITE_CONTACTS", "dangerous", "Write/delete contacts", "high"),
    "android.permission.READ_CALL_LOG": PermissionMeta("READ_CALL_LOG", "dangerous", "Read call history", "high"),
    "android.permission.WRITE_CALL_LOG": PermissionMeta("WRITE_CALL_LOG", "dangerous", "Modify call history", "high"),
    "android.permission.PROCESS_OUTGOING_CALLS": PermissionMeta("PROCESS_OUTGOING_CALLS", "dangerous", "Intercept/redirect calls", "critical"),
    "android.permission.READ_SMS": PermissionMeta("READ_SMS", "dangerous", "Read SMS messages", "critical"),
    "android.permission.SEND_SMS": PermissionMeta("SEND_SMS", "dangerous", "Send SMS (may incur charges)", "high"),
    "android.permission.RECEIVE_SMS": PermissionMeta("RECEIVE_SMS", "dangerous", "Intercept incoming SMS", "critical"),
    "android.permission.READ_PHONE_STATE": PermissionMeta("READ_PHONE_STATE", "dangerous", "Access phone ID, IMEI, call state", "high"),
    "android.permission.CALL_PHONE": PermissionMeta("CALL_PHONE", "dangerous", "Make phone calls without user interaction", "high"),
    "android.permission.RECORD_AUDIO": PermissionMeta("RECORD_AUDIO", "dangerous", "Record audio from microphone", "critical"),
    "android.permission.CAMERA": PermissionMeta("CAMERA", "dangerous", "Take photos/video without user interaction", "high"),
    "android.permission.ACCESS_FINE_LOCATION": PermissionMeta("ACCESS_FINE_LOCATION", "dangerous", "Precise GPS location", "high"),
    "android.permission.ACCESS_COARSE_LOCATION": PermissionMeta("ACCESS_COARSE_LOCATION", "dangerous", "Approximate network location", "medium"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": PermissionMeta("ACCESS_BACKGROUND_LOCATION", "dangerous", "Location access in background", "high"),
    "android.permission.READ_EXTERNAL_STORAGE": PermissionMeta("READ_EXTERNAL_STORAGE", "dangerous", "Read files on external storage", "medium"),
    "android.permission.WRITE_EXTERNAL_STORAGE": PermissionMeta("WRITE_EXTERNAL_STORAGE", "dangerous", "Write/delete files on external storage", "medium"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": PermissionMeta("MANAGE_EXTERNAL_STORAGE", "signature", "Broad file system access (Android 11+)", "high"),
    "android.permission.GET_ACCOUNTS": PermissionMeta("GET_ACCOUNTS", "dangerous", "List accounts on device", "medium"),
    "android.permission.USE_BIOMETRIC": PermissionMeta("USE_BIOMETRIC", "normal", "Use biometric hardware", "low"),
    "android.permission.USE_FINGERPRINT": PermissionMeta("USE_FINGERPRINT", "normal", "Use fingerprint sensor", "low"),
    # --- High ---
    "android.permission.INTERNET": PermissionMeta("INTERNET", "normal", "Full network access", "low"),
    "android.permission.RECEIVE_BOOT_COMPLETED": PermissionMeta("RECEIVE_BOOT_COMPLETED", "normal", "Start at device boot", "medium"),
    "android.permission.FOREGROUND_SERVICE": PermissionMeta("FOREGROUND_SERVICE", "normal", "Run foreground service", "low"),
    "android.permission.REQUEST_INSTALL_PACKAGES": PermissionMeta("REQUEST_INSTALL_PACKAGES", "signature", "Install APKs from unknown sources", "high"),
    "android.permission.INSTALL_PACKAGES": PermissionMeta("INSTALL_PACKAGES", "signatureOrSystem", "Silently install packages", "critical"),
    "android.permission.DELETE_PACKAGES": PermissionMeta("DELETE_PACKAGES", "signatureOrSystem", "Silently uninstall apps", "critical"),
    "android.permission.BIND_DEVICE_ADMIN": PermissionMeta("BIND_DEVICE_ADMIN", "signature", "Bind to device admin component", "critical"),
    "android.permission.CHANGE_NETWORK_STATE": PermissionMeta("CHANGE_NETWORK_STATE", "normal", "Change network connectivity", "low"),
    "android.permission.ACCESS_WIFI_STATE": PermissionMeta("ACCESS_WIFI_STATE", "normal", "View Wi-Fi connections", "low"),
    "android.permission.CHANGE_WIFI_STATE": PermissionMeta("CHANGE_WIFI_STATE", "normal", "Connect/disconnect Wi-Fi", "low"),
    "android.permission.BLUETOOTH": PermissionMeta("BLUETOOTH", "normal", "Pair with Bluetooth devices", "low"),
    "android.permission.BLUETOOTH_SCAN": PermissionMeta("BLUETOOTH_SCAN", "dangerous", "Scan Bluetooth devices (can reveal location)", "medium"),
    "android.permission.BLUETOOTH_CONNECT": PermissionMeta("BLUETOOTH_CONNECT", "dangerous", "Connect to Bluetooth devices", "medium"),
    "android.permission.NFC": PermissionMeta("NFC", "normal", "Use NFC hardware", "low"),
    "android.permission.VIBRATE": PermissionMeta("VIBRATE", "normal", "Control vibration", "none"),
    "android.permission.WAKE_LOCK": PermissionMeta("WAKE_LOCK", "normal", "Prevent phone from sleeping", "low"),
    "android.permission.USE_CREDENTIALS": PermissionMeta("USE_CREDENTIALS", "dangerous", "Use accounts stored on device", "high"),
    "android.permission.AUTHENTICATE_ACCOUNTS": PermissionMeta("AUTHENTICATE_ACCOUNTS", "dangerous", "Act as account authenticator", "high"),
    "android.permission.READ_SYNC_SETTINGS": PermissionMeta("READ_SYNC_SETTINGS", "normal", "Read sync settings", "none"),
    "android.permission.WRITE_SYNC_SETTINGS": PermissionMeta("WRITE_SYNC_SETTINGS", "normal", "Toggle sync on/off", "low"),
    "android.permission.SYSTEM_ALERT_WINDOW": PermissionMeta("SYSTEM_ALERT_WINDOW", "signature", "Draw over other apps", "high"),
    "android.permission.WRITE_SETTINGS": PermissionMeta("WRITE_SETTINGS", "signature", "Modify system settings", "medium"),
    "android.permission.DUMP": PermissionMeta("DUMP", "signatureOrSystem", "Retrieve system internal state", "critical"),
    "android.permission.READ_LOGS": PermissionMeta("READ_LOGS", "signatureOrSystem", "Read low-level system log buffers", "critical"),
    "android.permission.PACKAGE_USAGE_STATS": PermissionMeta("PACKAGE_USAGE_STATS", "signature", "Access app usage statistics", "medium"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": PermissionMeta("BIND_ACCESSIBILITY_SERVICE", "signature", "Bind to accessibility service (can read screen)", "critical"),
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": PermissionMeta("BIND_NOTIFICATION_LISTENER_SERVICE", "signature", "Read all notifications", "high"),
    "android.permission.CAPTURE_AUDIO_OUTPUT": PermissionMeta("CAPTURE_AUDIO_OUTPUT", "signatureOrSystem", "Capture audio output stream", "critical"),
    "android.permission.READ_PRIVILEGED_PHONE_STATE": PermissionMeta("READ_PRIVILEGED_PHONE_STATE", "signatureOrSystem", "Read privileged phone state including IMEI", "critical"),
}


def classify_permissions(permissions: list[str]) -> list[dict]:
    result = []
    for perm in permissions:
        meta = _PERMISSION_DB.get(perm)
        if meta:
            result.append({
                "name": perm,
                "short_name": meta.short_name,
                "protection_level": meta.protection_level,
                "description": meta.description,
                "risk": meta.risk,
            })
        else:
            # Unknown / custom permission
            short = perm.split(".")[-1] if "." in perm else perm
            result.append({
                "name": perm,
                "short_name": short,
                "protection_level": "unknown",
                "description": "Custom or unknown permission",
                "risk": "none",
            })
    return result
