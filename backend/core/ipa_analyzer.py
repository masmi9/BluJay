"""
iOS IPA analysis pipeline.
Unzips IPA, parses Info.plist, extracts entitlements, scans binary strings,
analyzes ATS config, and persists StaticFinding rows tagged platform="ios".
"""
from __future__ import annotations

import asyncio
import json
import plistlib
import re
import zipfile
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

# Binary printable strings (min 4 chars)
_STRINGS_RE = re.compile(rb"[\x20-\x7e]{4,}")

# ATS keys that indicate weak config
_ATS_RISK_KEYS = {
    "NSAllowsArbitraryLoads": ("high", "NSAllowsArbitraryLoads: true — arbitrary HTTP allowed"),
    "NSAllowsArbitraryLoadsForMedia": ("medium", "NSAllowsArbitraryLoadsForMedia: true"),
    "NSAllowsArbitraryLoadsInWebContent": ("medium", "NSAllowsArbitraryLoadsInWebContent: true"),
    "NSExceptionAllowsInsecureHTTPLoads": ("medium", "NSExceptionAllowsInsecureHTTPLoads in domain exception"),
}

# Entitlement risk levels
_ENTITLEMENT_RISKS: dict[str, tuple[str, str]] = {
    "com.apple.private.security.no-sandbox": ("critical", "App sandbox disabled"),
    "com.apple.private.security.container-required": ("high", "Private container security"),
    "get-task-allow": ("high", "get-task-allow: true — debuggable binary"),
    "com.apple.developer.icloud-services": ("medium", "iCloud services entitlement"),
    "com.apple.developer.push-notifications": ("low", "Push notification entitlement"),
    "aps-environment": ("info", "APNs environment entitlement"),
    "com.apple.security.network.server": ("low", "Network server entitlement"),
    "com.apple.security.network.client": ("info", "Network client entitlement"),
}

# Secret patterns in binary strings
_SECRET_PATTERNS = [
    (re.compile(r"(?:api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*\S{8,}", re.IGNORECASE), "high", "API key in binary strings"),
    (re.compile(r"(?:password|passwd)\s*[=:]\s*\S{6,}", re.IGNORECASE), "high", "Password in binary strings"),
    (re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"), "critical", "Private key in binary"),
    (re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{10,}"), "info", "Hardcoded URL in binary"),
    (re.compile(r"(?:access_token|bearer)\s*[=:]\s*\S{10,}", re.IGNORECASE), "high", "Token in binary strings"),
    (re.compile(r"(?:aws_secret|AKIA[0-9A-Z]{16})", re.IGNORECASE), "critical", "AWS credentials in binary"),
    (re.compile(r"(?:private_key|client_secret)\s*[=:]\s*\S{8,}", re.IGNORECASE), "high", "Credential in binary strings"),
    (re.compile(r"\b(?:MD5|RC4|DES)\b"), "medium", "Weak cryptography reference in binary"),
    (re.compile(r"\b(?:10|172|192)\.(?:\d{1,3}\.){2}\d{1,3}\b"), "low", "Hardcoded IP address in binary"),
    (re.compile(r"(?:sqlite|\.db|\.sqlite3?)\b", re.IGNORECASE), "info", "Database file reference in binary"),
]

# Known third-party framework risk data
_FRAMEWORK_RISKS: dict[str, tuple[str, str]] = {
    "AFNetworking": ("medium", "HTTP library — verify TLS/pinning configuration"),
    "Alamofire": ("medium", "HTTP library — verify TLS/pinning configuration"),
    "Firebase": ("low", "Google Firebase — verify data storage rules"),
    "FirebaseAuth": ("low", "Firebase Auth — verify token handling"),
    "FirebaseDatabase": ("low", "Firebase Realtime DB — verify security rules"),
    "Crashlytics": ("info", "Crashlytics — crash reports may expose sensitive data"),
    "Fabric": ("info", "Fabric crash reporting"),
    "Realm": ("low", "Realm database — verify encryption is enabled"),
    "SQLCipher": ("info", "Encrypted SQLite — good practice"),
    "OpenSSL": ("medium", "OpenSSL — verify version for known CVEs"),
    "libcrypto": ("medium", "Crypto library — verify secure usage"),
    "WebKit": ("medium", "WebKit — verify content/JS injection protections"),
    "JavaScriptCore": ("medium", "JavaScriptCore — potential code injection risk"),
    "AdSupport": ("low", "Ad tracking — IDFA collection"),
    "AppTrackingTransparency": ("info", "App tracking transparency framework"),
    "LocalAuthentication": ("info", "Biometric auth — good practice"),
    "CryptoKit": ("info", "Apple CryptoKit — modern crypto"),
    "CommonCrypto": ("info", "CommonCrypto — verify secure API usage"),
    "MessageUI": ("info", "Email/SMS UI framework"),
    "RevenueCat": ("info", "In-app purchase SDK"),
    "Stripe": ("low", "Payment SDK — verify PCI compliance"),
    "Braintree": ("low", "Payment SDK — verify PCI compliance"),
    "Mixpanel": ("info", "Analytics SDK — data collection"),
    "Amplitude": ("info", "Analytics SDK — data collection"),
    "Intercom": ("info", "Customer messaging SDK"),
    "OneSignal": ("info", "Push notification SDK"),
    "Lottie": ("info", "Animation library"),
    "SDWebImage": ("info", "Image loading library"),
    "Kingfisher": ("info", "Image caching library"),
    "SnapKit": ("info", "UI layout library"),
    "RxSwift": ("info", "Reactive programming library"),
    "Combine": ("info", "Apple Combine framework"),
    "SwiftyJSON": ("info", "JSON parsing library"),
    "KeychainSwift": ("info", "Keychain wrapper — good practice"),
    "SwiftKeychainWrapper": ("info", "Keychain wrapper — good practice"),
}

# Privacy permission keys and their risk levels
_PRIVACY_KEYS: dict[str, tuple[str, str]] = {
    "NSLocationAlwaysAndWhenInUseUsageDescription": ("high", "Location (always + in use)"),
    "NSLocationAlwaysUsageDescription": ("high", "Location (always — background)"),
    "NSLocationWhenInUseUsageDescription": ("medium", "Location (while using app)"),
    "NSCameraUsageDescription": ("medium", "Camera"),
    "NSMicrophoneUsageDescription": ("medium", "Microphone"),
    "NSContactsUsageDescription": ("high", "Contacts"),
    "NSPhotoLibraryUsageDescription": ("medium", "Photo library read"),
    "NSPhotoLibraryAddUsageDescription": ("low", "Photo library write"),
    "NSFaceIDUsageDescription": ("low", "Face ID"),
    "NSHealthShareUsageDescription": ("critical", "Health data read"),
    "NSHealthUpdateUsageDescription": ("critical", "Health data write"),
    "NSMotionUsageDescription": ("low", "Motion & fitness"),
    "NSBluetoothAlwaysUsageDescription": ("medium", "Bluetooth"),
    "NSBluetoothPeripheralUsageDescription": ("medium", "Bluetooth peripheral"),
    "NSLocalNetworkUsageDescription": ("low", "Local network"),
    "NSSpeechRecognitionUsageDescription": ("medium", "Speech recognition"),
    "NSCalendarsUsageDescription": ("medium", "Calendars"),
    "NSRemindersUsageDescription": ("low", "Reminders"),
    "NSHomeKitUsageDescription": ("high", "HomeKit devices"),
    "NSUserTrackingUsageDescription": ("high", "Cross-app tracking (ATT)"),
    "NSSiriUsageDescription": ("medium", "Siri & dictation"),
    "NSAppleMusicUsageDescription": ("low", "Apple Music library"),
    "NFCReaderUsageDescription": ("medium", "NFC reading"),
}


# rule_id mappings — must match keys in finding_enricher._ENRICHMENTS
_ATS_RULE_IDS: dict[str, str] = {
    "NSAllowsArbitraryLoads": "ios_ats_allows_arbitrary_loads",
    "NSAllowsArbitraryLoadsForMedia": "ios_ats_allows_media",
    "NSAllowsArbitraryLoadsInWebContent": "ios_ats_allows_web_content",
    "NSExceptionAllowsInsecureHTTPLoads": "ios_ats_domain_exception",
}

_ATS_DESCRIPTIONS: dict[str, str] = {
    "NSAllowsArbitraryLoads": (
        "NSAllowsArbitraryLoads disables App Transport Security globally, permitting unencrypted "
        "HTTP connections to all domains. Session tokens, credentials, and user data may be "
        "transmitted without encryption."
    ),
    "NSAllowsArbitraryLoadsForMedia": (
        "NSAllowsArbitraryLoadsForMedia disables ATS for media URLs, allowing unencrypted "
        "HTTP streaming content to be loaded."
    ),
    "NSAllowsArbitraryLoadsInWebContent": (
        "NSAllowsArbitraryLoadsInWebContent disables ATS for content loaded inside WKWebView, "
        "allowing mixed HTTP/HTTPS pages."
    ),
    "NSExceptionAllowsInsecureHTTPLoads": (
        "A per-domain ATS exception permits unencrypted HTTP to the specified domain, exposing "
        "traffic to that host to on-path interception."
    ),
}

_ENTITLEMENT_RULE_IDS: dict[str, str] = {
    "com.apple.private.security.no-sandbox": "ios_entitlement_no_sandbox",
    "get-task-allow": "ios_entitlement_get_task_allow",
    "com.apple.developer.icloud-services": "ios_entitlement_icloud",
}

_ENTITLEMENT_DESCRIPTIONS: dict[str, str] = {
    "com.apple.private.security.no-sandbox": (
        "The app sandbox is fully disabled. The app can access files outside its container "
        "and interact with system resources normally restricted to privileged processes."
    ),
    "get-task-allow": (
        "The binary is marked as debuggable via the get-task-allow entitlement. An attacker "
        "with local device access can attach LLDB to the running process and inspect memory, "
        "extract secrets, or bypass control flow."
    ),
    "com.apple.developer.icloud-services": (
        "The app is entitled for iCloud services. Verify that data synced to iCloud does not "
        "include sensitive credentials or session tokens."
    ),
}

_FRAMEWORK_RULE_IDS: dict[str, str] = {
    "WebKit": "ios_framework_webkit",
    "JavaScriptCore": "ios_framework_webkit",
    "OpenSSL": "ios_framework_openssl",
    "libcrypto": "ios_framework_openssl",
    "AFNetworking": "ios_framework_networking",
    "Alamofire": "ios_framework_networking",
}

_PERMISSION_RULE_IDS: dict[str, str] = {
    "NSLocationAlwaysAndWhenInUseUsageDescription": "perm_access_fine_location",
    "NSLocationAlwaysUsageDescription": "perm_access_fine_location",
    "NSLocationWhenInUseUsageDescription": "perm_access_fine_location",
    "NSCameraUsageDescription": "perm_camera",
    "NSMicrophoneUsageDescription": "perm_record_audio",
    "NSContactsUsageDescription": "perm_read_contacts",
    "NSHealthShareUsageDescription": "ios_perm_health",
    "NSHealthUpdateUsageDescription": "ios_perm_health",
    "NSUserTrackingUsageDescription": "ios_perm_tracking",
}

_BINARY_RULE_IDS: dict[str, str] = {
    "API key in binary strings": "ios_binary_api_key",
    "Password in binary strings": "ios_binary_password",
    "Private key in binary": "ios_binary_private_key",
    "Hardcoded URL in binary": "ios_binary_hardcoded_url",
    "Token in binary strings": "ios_binary_token",
    "AWS credentials in binary": "ios_binary_aws_credentials",
    "Credential in binary strings": "ios_binary_credential",
    "Weak cryptography reference in binary": "ios_binary_weak_crypto",
    "Hardcoded IP address in binary": "ios_binary_hardcoded_ip",
    "Database file reference in binary": "ios_binary_database_reference",
}

_BINARY_DESCRIPTIONS: dict[str, str] = {
    "API key in binary strings": (
        "A potential API key was found embedded in the app binary. Hardcoded credentials can be "
        "extracted from any IPA file using `strings` — no jailbreak or device access required."
    ),
    "Password in binary strings": (
        "A potential hardcoded password was found in the app binary. Passwords embedded in "
        "binaries are trivially extractable and may allow direct access to backend services."
    ),
    "Private key in binary": (
        "A private key (RSA/EC/PEM) is embedded in the binary. It can be extracted to impersonate "
        "the server, decrypt TLS traffic, or forge signed tokens."
    ),
    "Hardcoded URL in binary": (
        "A hardcoded URL was found in the binary. This may reveal internal API endpoints, staging "
        "environments, or infrastructure details not intended to be public."
    ),
    "Token in binary strings": (
        "A session or bearer token was found hardcoded in the binary. Hardcoded tokens may grant "
        "authenticated API access without valid credentials."
    ),
    "AWS credentials in binary": (
        "AWS access key credentials are hardcoded in the binary. These can be extracted from any "
        "IPA file and used to access AWS resources directly."
    ),
    "Credential in binary strings": (
        "Hardcoded credentials (private key or client secret) were found in the binary. They can "
        "be extracted without device access."
    ),
    "Weak cryptography reference in binary": (
        "References to deprecated or broken cryptographic algorithms (MD5, RC4, DES) were found "
        "in the binary. Data protected with these primitives provides significantly weaker security "
        "than modern alternatives."
    ),
    "Hardcoded IP address in binary": (
        "A hardcoded internal IP address was found, potentially revealing network topology or "
        "internal infrastructure ranges."
    ),
    "Database file reference in binary": (
        "A local database file reference was found. Unencrypted SQLite databases are accessible "
        "in plaintext on jailbroken devices or from device backups."
    ),
}


def _norm(name: str) -> str:
    """Normalize zip entry path separators to forward slashes."""
    return name.replace("\\", "/")


def _find_app_bundle(zf: zipfile.ZipFile) -> str | None:
    """Return path prefix of the .app bundle inside the IPA."""
    for name in zf.namelist():
        n = _norm(name)
        if re.match(r"Payload/[^/]+\.app/", n):
            return re.match(r"(Payload/[^/]+\.app/)", n).group(1)
    return None


def _parse_plist(data: bytes) -> dict:
    try:
        return plistlib.loads(data)
    except Exception:
        return {}


def _parse_ats(info_plist: dict) -> tuple[dict, list[dict]]:
    """Return (ats_dict, list_of_findings)."""
    ats = info_plist.get("NSAppTransportSecurity", {})
    findings = []

    def _check(d: dict, domain: str = ""):
        for key, (sev, msg) in _ATS_RISK_KEYS.items():
            if d.get(key) is True:
                ctx = f"NSAppTransportSecurity > NSExceptionDomains > {domain} > {key}" if domain else f"NSAppTransportSecurity > {key}"
                findings.append({
                    "severity": sev,
                    "title": msg,
                    "description": _ATS_DESCRIPTIONS.get(key, msg),
                    "category": "ios_ats",
                    "file_path": "Info.plist",
                    "rule_id": _ATS_RULE_IDS.get(key),
                    "evidence": json.dumps({"match": f"{key}: true", "context": ctx}),
                })
        for dom, exc in d.get("NSExceptionDomains", {}).items():
            _check(exc, domain=dom)

    _check(ats)
    return ats, findings


def _extract_entitlements(app_path: str, zf: zipfile.ZipFile) -> list[dict]:
    """Try to read embedded.mobileprovision or <App>.entitlements."""
    entitlements = {}
    for name in zf.namelist():
        n = _norm(name)
        if n.startswith(app_path) and (
            n.endswith("embedded.mobileprovision") or n.endswith(".entitlements")
        ):
            try:
                data = zf.read(name)
                # mobileprovision is a signed CMS blob — extract plist with regex
                plist_match = re.search(rb"<plist.*?</plist>", data, re.DOTALL)
                if plist_match:
                    parsed = _parse_plist(plist_match.group(0))
                    entitlements.update(parsed.get("Entitlements", parsed))
            except Exception:
                pass
    return [
        {
            "key": k,
            "value": str(v),
            "risk_level": _ENTITLEMENT_RISKS.get(k, ("info", ""))[0],
            "description": _ENTITLEMENT_RISKS.get(k, ("info", k))[1] or k,
        }
        for k, v in entitlements.items()
    ]


def _scan_binary_strings(binary_data: bytes) -> list[dict]:
    # Deduplicate by pattern title — collect up to 3 example matches each.
    # Without deduplication a large binary generates hundreds of "Weak cryptography
    # reference" findings (one per string containing "MD5"), which inflates the score.
    seen: dict[str, dict] = {}  # title → {severity, examples[]}

    strings = _STRINGS_RE.findall(binary_data)
    for s in strings:
        text = s.decode(errors="replace")
        for pattern, sev, title in _SECRET_PATTERNS:
            if pattern.search(text):
                if title not in seen:
                    seen[title] = {"severity": sev, "examples": []}
                if len(seen[title]["examples"]) < 3:
                    seen[title]["examples"].append(text[:300])
                break  # one pattern match per string

    findings = []
    for title, data in seen.items():
        examples = data["examples"]
        findings.append({
            "severity": data["severity"],
            "title": title,
            "description": _BINARY_DESCRIPTIONS.get(title, title),
            "category": "ios_binary",
            "file_path": "<binary>",
            "rule_id": _BINARY_RULE_IDS.get(title),
            "evidence": json.dumps({
                "match": examples[0] if examples else "",
                "context": "\n---\n".join(examples),
            }),
        })
    return findings


def _detect_frameworks(zf: zipfile.ZipFile, app_path: str) -> list[dict]:
    """Detect embedded frameworks and dylibs inside the .app bundle."""
    seen: set[str] = set()
    results: list[dict] = []
    sev_order = ["critical", "high", "medium", "low", "info"]

    for name in zf.namelist():
        n = _norm(name)
        # .framework bundles inside Frameworks/
        m = re.match(r"(Payload/[^/]+\.app/)Frameworks/([^/]+)\.framework/", n)
        if m and m.group(1) == app_path:
            fw_name = m.group(2)
            if fw_name not in seen:
                seen.add(fw_name)
                risk_level, note = _FRAMEWORK_RISKS.get(fw_name, ("info", "Third-party framework"))
                results.append({"name": fw_name, "risk_level": risk_level, "note": note, "type": "framework"})
            continue
        # .dylib files anywhere inside the bundle
        m2 = re.match(r"(Payload/[^/]+\.app/)(?:.+/)([^/]+)\.dylib$", n)
        if m2 and m2.group(1) == app_path:
            lib_name = m2.group(2)
            if lib_name not in seen:
                seen.add(lib_name)
                risk_level, note = _FRAMEWORK_RISKS.get(lib_name, ("info", "Dynamic library"))
                results.append({"name": lib_name, "risk_level": risk_level, "note": note, "type": "dylib"})

    results.sort(key=lambda x: (sev_order.index(x["risk_level"]) if x["risk_level"] in sev_order else 99, x["name"]))
    return results


def _parse_permissions(info_plist: dict) -> list[dict]:
    """Extract privacy usage description keys with risk ratings."""
    permissions = []
    for key, (risk_level, description) in _PRIVACY_KEYS.items():
        if key in info_plist:
            permissions.append({
                "key": key,
                "description": description,
                "usage_string": str(info_plist[key])[:400],
                "risk_level": risk_level,
            })
    sev_order = ["critical", "high", "medium", "low", "info"]
    permissions.sort(key=lambda x: sev_order.index(x["risk_level"]) if x["risk_level"] in sev_order else 99)
    return permissions


def _parse_url_schemes(info_plist: dict) -> list[dict]:
    """Extract custom URL schemes from CFBundleURLTypes."""
    schemes = []
    for item in info_plist.get("CFBundleURLTypes", []):
        for scheme in item.get("CFBundleURLSchemes", []):
            role = item.get("CFBundleTypeRole", "")
            schemes.append({
                "scheme": scheme,
                "identifier": item.get("CFBundleURLName", ""),
                "role": role if isinstance(role, str) else str(role),
            })
    return schemes


async def run_ipa_analysis(
    analysis_id: int,
    ipa_path: str,
    progress_queue: asyncio.Queue | None,
    db_factory,
) -> None:
    from models.analysis import Analysis, StaticFinding

    def _push(stage: str, pct: int, msg: str):
        if progress_queue:
            try:
                progress_queue.put_nowait({"type": "progress", "stage": stage, "pct": pct, "message": msg})
            except Exception:
                pass

    _push("unzip", 5, "Extracting IPA…")

    try:
        with zipfile.ZipFile(ipa_path, "r") as zf:
            all_names = zf.namelist()
            logger.info("IPA zip entries (first 20)", analysis_id=analysis_id,
                        entries=all_names[:20], total=len(all_names))

            # Build a normalized-name → original-name lookup so we can read
            # entries regardless of whether 7-zip packed them with \ or /
            name_map = {_norm(n): n for n in all_names}

            app_path = _find_app_bundle(zf)
            logger.info("app_path found", analysis_id=analysis_id, app_path=app_path)
            if not app_path:
                raise ValueError("No .app bundle found in IPA")

            # Info.plist — try exact match first, then case-insensitive,
            # then fall back to any top-level plist in the .app bundle
            _push("plist", 20, "Parsing Info.plist…")
            info_plist: dict = {}

            def _find_plist_entry() -> str | None:
                # 1. Exact match
                exact = app_path + "Info.plist"
                if exact in name_map:
                    return exact
                # 2. Case-insensitive match for Info.plist
                for key in name_map:
                    if key.lower() == exact.lower():
                        return key
                # 3. Any .plist directly inside the .app bundle (not in subdirs)
                candidates = []
                for key in name_map:
                    if (key.startswith(app_path) and key.endswith(".plist")
                            and key[len(app_path):].count("/") == 0
                            and not key.endswith("/")):
                        candidates.append(key)
                logger.info("plist candidates", analysis_id=analysis_id,
                            candidates=candidates)
                # Prefer Info.plist case-insensitively, then alphabetically
                for c in candidates:
                    if c.rsplit("/", 1)[-1].lower() == "info.plist":
                        return c
                return candidates[0] if candidates else None

            plist_entry = _find_plist_entry()
            logger.info("plist resolved", analysis_id=analysis_id, entry=plist_entry)
            if plist_entry:
                info_plist = _parse_plist(zf.read(name_map[plist_entry]))

            bundle_id = info_plist.get("CFBundleIdentifier")
            min_ios = info_plist.get("MinimumOSVersion") or info_plist.get("LSMinimumSystemVersion")

            # ATS
            _push("ats", 35, "Analyzing ATS config…")
            ats_dict, ats_findings = _parse_ats(info_plist)

            # Entitlements
            _push("entitlements", 50, "Extracting entitlements…")
            entitlements = _extract_entitlements(app_path, zf)

            # Binary strings scan — find the main executable
            _push("binary", 65, "Scanning binary strings…")
            binary_findings: list[dict] = []
            exec_name = info_plist.get("CFBundleExecutable", "")
            exec_key = None
            if exec_name:
                candidate = app_path + exec_name
                if candidate in name_map:
                    exec_key = candidate
                else:
                    # case-insensitive fallback
                    for k in name_map:
                        if k.lower() == candidate.lower():
                            exec_key = k
                            break
            if not exec_key:
                # Last resort: any file directly inside .app with no extension (typical Mach-O)
                for k in name_map:
                    if (k.startswith(app_path)
                            and k[len(app_path):].count("/") == 0
                            and "." not in k[len(app_path):]
                            and not k.endswith("/")):
                        exec_key = k
                        break
            if exec_key:
                binary_data = zf.read(name_map[exec_key])
                loop = asyncio.get_event_loop()
                binary_findings = await loop.run_in_executor(None, _scan_binary_strings, binary_data)

            # Framework detection
            _push("frameworks", 75, "Detecting frameworks…")
            framework_results = _detect_frameworks(zf, app_path)

    except Exception as exc:
        logger.error("IPA analysis failed", analysis_id=analysis_id, error=str(exc))
        async with db_factory() as db:
            analysis = await db.get(Analysis, analysis_id)
            if analysis:
                analysis.status = "failed"
                analysis.error_message = str(exc)
                await db.commit()
        return

    # Persist results
    _push("persist", 85, "Saving results…")
    async with db_factory() as db:
        analysis = await db.get(Analysis, analysis_id)
        if not analysis:
            return

        analysis.platform = "ios"
        analysis.bundle_id = bundle_id
        analysis.min_ios_version = str(min_ios) if min_ios else None
        analysis.ats_config_json = json.dumps(ats_dict)

        all_findings = ats_findings + binary_findings
        for ent in entitlements:
            if ent["risk_level"] in ("critical", "high"):
                all_findings.append({
                    "severity": ent["risk_level"],
                    "title": ent["description"],
                    "description": _ENTITLEMENT_DESCRIPTIONS.get(ent["key"], ent["description"]),
                    "category": "ios_entitlement",
                    "file_path": "embedded.mobileprovision",
                    "rule_id": _ENTITLEMENT_RULE_IDS.get(ent["key"]),
                    "evidence": json.dumps({
                        "match": f"{ent['key']} = {ent['value']}",
                        "context": f"Entitlement: {ent['key']} = {ent['value']}",
                    }),
                })

        for fw in framework_results:
            if fw["risk_level"] in ("critical", "high", "medium"):
                all_findings.append({
                    "severity": fw["risk_level"],
                    "title": f"{fw['name']} framework detected",
                    "description": f"{fw['name']} is bundled with the app. {fw['note']}",
                    "category": "ios_framework",
                    "file_path": f"Frameworks/{fw['name']}.framework",
                    "rule_id": _FRAMEWORK_RULE_IDS.get(fw["name"]),
                    "evidence": json.dumps({
                        "match": fw["name"],
                        "context": fw["note"],
                    }),
                })

        permissions = _parse_permissions(info_plist)
        for perm in permissions:
            if perm["risk_level"] in ("critical", "high"):
                all_findings.append({
                    "severity": perm["risk_level"],
                    "title": f"Sensitive permission: {perm['description']}",
                    "description": (
                        f"The app declares {perm['key']}, requesting access to {perm['description'].lower()}. "
                        f"Usage justification: \"{perm['usage_string']}\""
                    ),
                    "category": "ios_permission",
                    "file_path": "Info.plist",
                    "rule_id": _PERMISSION_RULE_IDS.get(perm["key"]),
                    "evidence": json.dumps({
                        "match": perm["key"],
                        "context": f"{perm['key']}: {perm['usage_string']}",
                    }),
                })

        for f in all_findings:
            db.add(StaticFinding(
                analysis_id=analysis_id,
                category=f.get("category", "ios"),
                severity=f["severity"],
                title=f["title"],
                description=f.get("description") or f["title"],
                file_path=f.get("file_path"),
                evidence=f.get("evidence"),
                rule_id=f.get("rule_id"),
            ))

        analysis.status = "complete"
        await db.commit()

    _push("done", 100, "IPA analysis complete")
    logger.info("IPA analysis complete", analysis_id=analysis_id, bundle_id=bundle_id)
