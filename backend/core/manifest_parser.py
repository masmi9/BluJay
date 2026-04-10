"""
Parses the decoded AndroidManifest.xml produced by apktool.
apktool outputs a human-readable XML (not binary), so we use ElementTree.
"""
import json
import xml.etree.ElementTree as ET
from pathlib import Path

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _attr(el: ET.Element, local: str, default=None):
    """Get android: namespace attribute, falling back to plain attribute."""
    v = el.get(f"{{{ANDROID_NS}}}{local}")
    if v is not None:
        return v
    # Some apktool versions omit the namespace on root <manifest> attributes
    v = el.get(local)
    if v is not None:
        return v
    return default


def _bool_attr(el: ET.Element, local: str, default: bool = False) -> bool:
    val = _attr(el, local)
    if val is None:
        return default
    return val.lower() in ("true", "1")


def parse_manifest(manifest_path: Path) -> dict:
    tree = ET.parse(str(manifest_path))
    root = tree.getroot()

    def _parse_int(s: str | None) -> int | None:
        """Parse decimal or hex (0x...) integer strings."""
        if not s:
            return None
        try:
            return int(s, 0)
        except (ValueError, TypeError):
            return None

    package = root.get("package", "")
    version_name = _attr(root, "versionName")
    version_code = _parse_int(_attr(root, "versionCode"))

    # uses-sdk
    sdk_el = root.find("uses-sdk")
    min_sdk = target_sdk = None
    if sdk_el is not None:
        min_sdk = _parse_int(_attr(sdk_el, "minSdkVersion"))
        target_sdk = _parse_int(_attr(sdk_el, "targetSdkVersion"))

    # application element
    app_el = root.find("application")
    debuggable = False
    allow_backup = True
    network_security_config = False
    uses_cleartext_traffic = None
    if app_el is not None:
        debuggable = _bool_attr(app_el, "debuggable", False)
        allow_backup = _bool_attr(app_el, "allowBackup", True)
        network_security_config = _attr(app_el, "networkSecurityConfig") is not None
        ct = _attr(app_el, "usesCleartextTraffic")
        uses_cleartext_traffic = _bool_attr(app_el, "usesCleartextTraffic") if ct is not None else None

    # permissions
    permissions = [
        _attr(el, "name") or el.get("android:name", "")
        for el in root.findall("uses-permission")
    ]
    permissions = [p for p in permissions if p]

    # components
    components = []
    if app_el is not None:
        for tag, comp_type in (
            ("activity", "activity"),
            ("service", "service"),
            ("receiver", "receiver"),
            ("provider", "provider"),
        ):
            for el in app_el.findall(tag):
                name = _attr(el, "name") or ""
                exported_raw = _attr(el, "exported")
                # exported defaults: activities/receivers with intent-filters default to true
                intent_filters = el.findall("intent-filter")
                if exported_raw is None:
                    exported = len(intent_filters) > 0 and comp_type in ("activity", "receiver")
                else:
                    exported = exported_raw.lower() in ("true", "1")

                filters = []
                for f in intent_filters:
                    actions = [_attr(a, "name") or "" for a in f.findall("action")]
                    categories = [_attr(c, "name") or "" for c in f.findall("category")]
                    filters.append({"actions": actions, "categories": categories})

                components.append({
                    "name": name,
                    "type": comp_type,
                    "exported": exported,
                    "permission": _attr(el, "permission"),
                    "intent_filters": filters,
                })

    return {
        "package_name": package,
        "version_name": version_name,
        "version_code": version_code,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "debuggable": debuggable,
        "allow_backup": allow_backup,
        "network_security_config": network_security_config,
        "uses_cleartext_traffic": uses_cleartext_traffic,
        "permissions": permissions,
        "components": components,
    }
