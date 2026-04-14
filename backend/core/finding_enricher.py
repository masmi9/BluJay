"""
Maps rule_id → {impact, attack_path} for known static finding rules.
Computed at query time — no DB migration required.
"""

_ENRICHMENTS: dict[str, dict[str, str]] = {
    # ── Manifest issues ──────────────────────────────────────────────────────
    "manifest_debuggable": {
        "impact": (
            "An attacker with physical or ADB access to the device can attach a debugger to the "
            "running app process, inspect and modify memory, extract secrets, and bypass control flow."
        ),
        "attack_path": (
            "1. Connect Android device via USB or ADB-over-TCP. "
            "2. Run `adb jdwp` to discover the debuggable PID. "
            "3. Forward the JDWP port: `adb forward tcp:8700 jdwp:<pid>`. "
            "4. Connect jdb or Android Studio debugger to localhost:8700. "
            "5. Set breakpoints, inspect variables, extract encryption keys or session tokens at runtime."
        ),
    },
    "manifest_allow_backup": {
        "impact": (
            "Shared-storage or ADB backups allow an attacker to extract the full app data directory "
            "(databases, SharedPreferences, files) without root access, exposing credentials, session "
            "tokens, and personal user data."
        ),
        "attack_path": (
            "1. Connect device via USB with USB debugging enabled. "
            "2. Run `adb backup -noapk com.example.app backup.ab`. "
            "3. Convert archive: `java -jar abe.jar unpack backup.ab backup.tar`. "
            "4. Extract tar and browse app/databases/, app/shared_prefs/ for credentials and tokens."
        ),
    },
    "manifest_cleartext": {
        "impact": (
            "HTTP traffic is not encrypted. An on-path attacker on the same Wi-Fi network or controlling "
            "network infrastructure can read and modify all app communication, including credentials, "
            "session tokens, and PII."
        ),
        "attack_path": (
            "1. Position on the same Wi-Fi network (or use ARP spoofing). "
            "2. Run `mitmproxy` or `Wireshark` to capture plaintext HTTP traffic. "
            "3. Observe authentication tokens, API keys, and user data in cleartext. "
            "4. Optionally inject malicious responses to manipulate app behaviour."
        ),
    },

    # ── Exported components ──────────────────────────────────────────────────
    "exported_component_no_permission": {
        "impact": (
            "Any third-party app on the device can invoke this component without restrictions. "
            "Depending on component type this may allow privilege escalation, data exfiltration "
            "through unprotected content providers, or triggering sensitive functionality silently."
        ),
        "attack_path": (
            "1. Install a malicious companion app on the same device. "
            "2. Use `am start`, `am broadcast`, or `ContentResolver` to invoke the exported component. "
            "3. For activities: launch deep-link or implicit intent to access sensitive screens. "
            "4. For providers: query/update URIs without any permission check. "
            "5. For services/receivers: trigger background operations or data exfiltration."
        ),
    },

    # ── Dangerous permissions ─────────────────────────────────────────────────
    "perm_read_contacts": {
        "impact": "Access to the full device contact list enables harvesting names, phone numbers, and email addresses of all contacts.",
        "attack_path": (
            "1. App silently reads ContactsContract at runtime. "
            "2. Exfiltrate contact list to remote server via background service or WorkManager job."
        ),
    },
    "perm_read_sms": {
        "impact": "SMS read access allows the app to capture OTP codes, 2FA messages, and private conversations, enabling account takeover.",
        "attack_path": (
            "1. Register a BroadcastReceiver for android.provider.Telephony.SMS_RECEIVED. "
            "2. Intercept incoming OTP messages before the legitimate SMS app processes them. "
            "3. Exfiltrate codes to attacker-controlled server to bypass 2FA."
        ),
    },
    "perm_record_audio": {
        "impact": "Microphone access allows the app to eavesdrop on conversations and meetings when the device is in the user's vicinity.",
        "attack_path": (
            "1. Start AudioRecord in a foreground or background service. "
            "2. Stream or store audio without visible UI indication. "
            "3. Exfiltrate audio files to remote server."
        ),
    },
    "perm_access_fine_location": {
        "impact": "Precise GPS location tracking enables real-time surveillance of user movements, home/work address discovery, and physical profiling.",
        "attack_path": (
            "1. Request ACCESS_FINE_LOCATION at runtime. "
            "2. Register a LocationListener or use FusedLocationProviderClient in a background service. "
            "3. Periodically report coordinates to a remote endpoint."
        ),
    },
    "perm_camera": {
        "impact": "Camera access allows silent photo or video capture, enabling visual surveillance of the user's environment.",
        "attack_path": (
            "1. Open Camera2 API in a background service with a 1×1 transparent SurfaceTexture. "
            "2. Capture images or video without displaying a camera preview to the user. "
            "3. Exfiltrate media to a remote server."
        ),
    },
    "perm_read_call_log": {
        "impact": "Call log access reveals who the user communicates with, call frequency, and timing, enabling social graph reconstruction.",
        "attack_path": (
            "1. Query CallLog.Calls content provider. "
            "2. Correlate inbound/outbound numbers and timestamps. "
            "3. Exfiltrate to profile social relationships."
        ),
    },
    "perm_process_outgoing_calls": {
        "impact": "Allows the app to intercept and redirect outgoing calls, enabling toll fraud or call hijacking.",
        "attack_path": (
            "1. Register receiver for android.intent.action.NEW_OUTGOING_CALL. "
            "2. Read and modify the dialled number in the BroadcastReceiver. "
            "3. Redirect calls to premium-rate numbers."
        ),
    },
    "perm_write_settings": {
        "impact": "Modifying system settings can disable security controls (e.g., screen lock timeout) or change network configuration.",
        "attack_path": (
            "1. Call Settings.System.putInt()/putString() to alter device behaviour. "
            "2. Disable screen lock timeout or airplane mode toggle to maintain persistence."
        ),
    },
    "perm_install_packages": {
        "impact": "Allows silent installation of additional APKs, enabling dropper-style malware distribution.",
        "attack_path": (
            "1. Download secondary APK payload from a remote server. "
            "2. Call PackageInstaller API to silently install without user interaction (on rooted/enterprise devices)."
        ),
    },
    "perm_receive_boot_completed": {
        "impact": "The app auto-starts after every device reboot, enabling persistent background surveillance or adware.",
        "attack_path": (
            "1. Register receiver for android.intent.action.BOOT_COMPLETED. "
            "2. Start background tracking or C2 service at every device boot without user awareness."
        ),
    },

    # ── Hardcoded secrets ────────────────────────────────────────────────────
    "aws_access_key": {
        "impact": (
            "Hardcoded AWS access keys grant the bearer direct access to AWS resources. Depending on "
            "attached IAM policies this may include S3 buckets, EC2, RDS, Lambda, or full account control."
        ),
        "attack_path": (
            "1. Extract key from APK using `jadx` or `apktool` — no device needed. "
            "2. Configure AWS CLI: `aws configure` with the extracted key. "
            "3. Enumerate accessible services: `aws sts get-caller-identity`, `aws s3 ls`. "
            "4. Exfiltrate data from S3, pivot to other services, or escalate privileges via IAM."
        ),
    },
    "google_api_key": {
        "impact": (
            "A leaked Google API key can be abused to make authenticated requests to Google APIs "
            "(Maps, Firebase, Cloud) billing charges to the app owner or accessing restricted data."
        ),
        "attack_path": (
            "1. Extract key from APK resources or compiled code. "
            "2. Make API requests: `curl 'https://maps.googleapis.com/maps/api/geocode/json?address=test&key=API_KEY'`. "
            "3. Enumerate enabled APIs and exploit any with no IP/referrer restrictions."
        ),
    },
    "firebase_url": {
        "impact": (
            "An exposed Firebase Realtime Database URL with weak or no security rules allows "
            "unauthenticated read or write of user data."
        ),
        "attack_path": (
            "1. Extract the Firebase URL from the APK. "
            "2. Attempt unauthenticated read: `curl https://<project>.firebaseio.com/.json`. "
            "3. If rules are permissive, dump or overwrite the entire database."
        ),
    },
    "jwt_token": {
        "impact": (
            "A hardcoded JWT token may grant persistent authenticated access to an API without "
            "requiring login credentials, bypassing authentication entirely."
        ),
        "attack_path": (
            "1. Extract JWT from APK string resources or code. "
            "2. Decode payload at jwt.io to understand claims (user ID, role, expiry). "
            "3. Use token in API requests: `Authorization: Bearer <token>`. "
            "4. If non-expiring or with admin claims, access privileged API endpoints."
        ),
    },
    "private_key": {
        "impact": (
            "An embedded private key (RSA/EC/PEM) can be used to impersonate the server, decrypt "
            "TLS traffic, or sign fraudulent data."
        ),
        "attack_path": (
            "1. Extract the PEM block from the APK. "
            "2. Use `openssl` to verify: `openssl rsa -in key.pem -check`. "
            "3. If it corresponds to a TLS certificate, perform MITM attacks against other clients. "
            "4. If used for JWT signing, forge arbitrary tokens."
        ),
    },
    "hardcoded_password": {
        "impact": (
            "A hardcoded password may allow direct access to backend services, databases, or admin "
            "panels if credentials are reused or shared across environments."
        ),
        "attack_path": (
            "1. Extract password from APK via string search in decompiled source. "
            "2. Identify the service it authenticates against from surrounding code (URLs, DB config). "
            "3. Attempt login with the credential against the identified endpoint."
        ),
    },
    "slack_token": {
        "impact": "A leaked Slack token allows reading private channels, messages, and files, potentially exposing internal communications and credentials.",
        "attack_path": (
            "1. Extract token from APK. "
            "2. Call Slack API: `curl https://slack.com/api/conversations.list -H 'Authorization: Bearer xoxb-...'`. "
            "3. Read channel history, download files, or post messages."
        ),
    },
    "stripe_key": {
        "impact": "A live Stripe secret key enables charging arbitrary cards, issuing refunds, and accessing customer payment data.",
        "attack_path": (
            "1. Extract Stripe key from APK. "
            "2. Use Stripe API to list customers or charges: `curl https://api.stripe.com/v1/customers -u sk_live_...`. "
            "3. Issue charges or retrieve PAN data depending on permissions."
        ),
    },
    "high_entropy_string": {
        "impact": (
            "High-entropy strings often represent API keys, tokens, or encryption keys embedded in "
            "the binary that could grant access to external services."
        ),
        "attack_path": (
            "1. Identify the context of the string in the surrounding source code. "
            "2. Determine which service or cryptographic operation it is used for. "
            "3. Test the string as a credential against identified endpoints or use it to decrypt local data."
        ),
    },
    "basic_auth_url": {
        "impact": "Hardcoded credentials embedded in a URL expose username and password directly and may allow access to the targeted service.",
        "attack_path": (
            "1. Extract the URL from decompiled source. "
            "2. Decode base64 credentials if present. "
            "3. Authenticate directly to the service using the extracted credentials."
        ),
    },

    # ── iOS ATS ──────────────────────────────────────────────────────────────
    "ios_ats_allows_arbitrary_loads": {
        "impact": (
            "NSAllowsArbitraryLoads disables App Transport Security globally, permitting unencrypted "
            "HTTP connections to all domains. Session tokens, credentials, and PII may be transmitted "
            "without encryption, visible to any on-path observer."
        ),
        "attack_path": (
            "1. Connect to the same Wi-Fi network as the device (or use ARP spoofing). "
            "2. Run `mitmproxy` or `Burp Suite` — the app will not reject HTTP. "
            "3. Observe API requests and responses in cleartext. "
            "4. Extract session tokens, user data, or credentials from HTTP traffic."
        ),
    },
    "ios_ats_allows_media": {
        "impact": "NSAllowsArbitraryLoadsForMedia permits unencrypted HTTP for media URLs, enabling an on-path attacker to replace streamed media with malicious content.",
        "attack_path": (
            "1. Position on the same network as the device. "
            "2. Use mitmproxy to intercept and replace the HTTP media stream with attacker-controlled content."
        ),
    },
    "ios_ats_allows_web_content": {
        "impact": "NSAllowsArbitraryLoadsInWebContent permits mixed content inside WKWebView, allowing HTTP resources to load in an otherwise HTTPS page.",
        "attack_path": (
            "1. Position on the same network. "
            "2. Intercept HTTP sub-resources loaded inside the WebView. "
            "3. Replace with malicious JavaScript to perform XSS within the app's WebView context."
        ),
    },
    "ios_ats_domain_exception": {
        "impact": "A per-domain ATS exception permits unencrypted HTTP to the excepted domain. Traffic to that host is exposed to on-path interception.",
        "attack_path": (
            "1. Identify the excepted domain from the Info.plist. "
            "2. Position on the same network and run mitmproxy. "
            "3. Intercept cleartext HTTP traffic to the excepted domain."
        ),
    },

    # ── iOS entitlements ─────────────────────────────────────────────────────
    "ios_entitlement_get_task_allow": {
        "impact": (
            "get-task-allow: true marks the binary as debuggable. On a jailbroken device or a device "
            "provisioned with the same team ID, an attacker can attach LLDB to the running process, "
            "inspect memory, extract secrets, and bypass control flow."
        ),
        "attack_path": (
            "1. Install the app on a jailbroken device or developer device with matching provisioning. "
            "2. Attach LLDB: `lldb -p $(pidof AppName)` or use Xcode → Debug → Attach to Process. "
            "3. Set breakpoints on authentication or decryption routines. "
            "4. Inspect registers and heap memory to extract session tokens or encryption keys at runtime."
        ),
    },
    "ios_entitlement_no_sandbox": {
        "impact": (
            "The app sandbox is fully disabled. The app can read and write files outside its container, "
            "access other apps' data directories, and interact with system resources normally restricted "
            "to privileged processes."
        ),
        "attack_path": (
            "1. Exploit any code execution vulnerability in the app. "
            "2. With sandbox disabled, traverse the filesystem: access other apps' Documents/, "
            "Library/, and Keychain data. "
            "3. Read or modify system configuration files to establish persistence."
        ),
    },
    "ios_entitlement_icloud": {
        "impact": "iCloud services entitlement means app data may be synced to Apple's servers and accessible from other devices signed into the same Apple ID, including devices that may not be under the user's direct control.",
        "attack_path": (
            "1. If an attacker gains access to the victim's Apple ID, they can retrieve iCloud-synced app data from any device or via iCloud.com. "
            "2. Verify which data types are synced (NSUbiquitousKeyValueStore, CloudKit, iCloud Documents) and whether sensitive credentials or tokens are included."
        ),
    },

    # ── iOS binary findings ──────────────────────────────────────────────────
    "ios_binary_api_key": {
        "impact": (
            "API keys hardcoded in the Mach-O binary can be extracted by anyone with access to the IPA "
            "file using standard tools. No jailbreak or device access is required — the IPA is "
            "downloadable via ipatool or from a device backup."
        ),
        "attack_path": (
            "1. Obtain the IPA (from App Store via ipatool, or from a device using frida-ios-dump). "
            "2. Extract binary strings: `strings Payload/AppName.app/AppName | grep -iE 'key|secret|token'`. "
            "3. Identify the associated service from surrounding strings or embedded URLs. "
            "4. Authenticate to the API using the extracted key."
        ),
    },
    "ios_binary_aws_credentials": {
        "impact": (
            "AWS credentials hardcoded in the binary grant direct access to AWS resources. "
            "Depending on the attached IAM policy this may include S3 buckets, Lambda, RDS, or full "
            "account control. Extraction requires only the IPA file — no device access needed."
        ),
        "attack_path": (
            "1. Obtain and unzip the IPA. "
            "2. Run `strings <binary> | grep -E 'AKIA[0-9A-Z]{16}'` to locate the access key. "
            "3. Configure AWS CLI: `aws configure` with the extracted key and secret. "
            "4. Enumerate permissions: `aws sts get-caller-identity && aws s3 ls`. "
            "5. Exfiltrate data or escalate privileges via IAM policy misconfigurations."
        ),
    },
    "ios_binary_private_key": {
        "impact": (
            "An embedded private key (RSA/EC/PEM) can be extracted to impersonate the server, "
            "decrypt captured TLS sessions, or forge signed data such as JWTs."
        ),
        "attack_path": (
            "1. Extract PEM block from the binary using `strings` or a hex editor. "
            "2. Verify with `openssl rsa -in key.pem -check`. "
            "3. If the key corresponds to a TLS certificate, perform MITM attacks against other clients. "
            "4. If used for JWT signing, forge tokens with arbitrary claims."
        ),
    },
    "ios_binary_token": {
        "impact": "A hardcoded session or bearer token grants authenticated API access without credentials. If the token does not expire, an attacker who extracts it has persistent access.",
        "attack_path": (
            "1. Extract the token from the binary using `strings` or radare2. "
            "2. Use the token in API requests: `Authorization: Bearer <token>`. "
            "3. If the token carries admin or elevated claims, access privileged endpoints."
        ),
    },
    "ios_binary_weak_crypto": {
        "impact": (
            "References to MD5, RC4, or DES indicate use of cryptographically broken algorithms. "
            "Data protected with these primitives provides significantly weaker confidentiality and "
            "integrity than modern alternatives (AES-GCM, SHA-256, ChaCha20-Poly1305)."
        ),
        "attack_path": (
            "1. Identify where the weak algorithm is used via static analysis (Hopper, radare2) or "
            "Frida hooks on CommonCrypto/CCCrypt. "
            "2. If used for password hashing, apply MD5 rainbow tables to recover passwords from "
            "any leaked hash. "
            "3. If used for symmetric encryption, brute-force or apply known-plaintext attacks "
            "against the weak cipher."
        ),
    },
    "ios_binary_credential": {
        "impact": "Hardcoded credentials (private key or client secret) in the binary can be extracted by any party with access to the IPA file.",
        "attack_path": (
            "1. Extract the IPA and locate the credential using `strings` or `grep`. "
            "2. Identify the associated service from surrounding code context. "
            "3. Authenticate to the service using the extracted credential."
        ),
    },
    "ios_binary_password": {
        "impact": "A hardcoded password in the binary may allow direct access to backend services or databases if the credential is shared across environments.",
        "attack_path": (
            "1. Extract the binary and search for the password: `strings <binary> | grep -i passwd`. "
            "2. Identify the service it authenticates against from surrounding URLs or class names. "
            "3. Attempt login with the extracted credential."
        ),
    },
    "ios_binary_hardcoded_ip": {
        "impact": "Hardcoded internal IP addresses reveal network topology, internal host ranges, or staging infrastructure that should not be visible outside the organisation.",
        "attack_path": (
            "1. Extract IP addresses from the binary. "
            "2. Attempt direct connections to identified hosts from the internet or a compromised "
            "network position. "
            "3. Use exposed IPs to map internal infrastructure for targeted attacks."
        ),
    },
    "ios_binary_hardcoded_url": {
        "impact": "Hardcoded URLs may expose internal API endpoints, staging servers, admin panels, or infrastructure details that are not intended to be public.",
        "attack_path": (
            "1. Extract URLs from the binary using `strings`. "
            "2. Identify non-production, admin, or internal endpoints. "
            "3. Probe identified endpoints for unauthenticated access or information disclosure."
        ),
    },
    "ios_binary_database_reference": {
        "impact": "Local database file references indicate on-device data storage. Unencrypted SQLite databases are accessible in plaintext on jailbroken devices or from iTunes/iCloud backups.",
        "attack_path": (
            "1. On a jailbroken device, locate the database at the referenced path in the app's "
            "Library/Application Support/ or Documents/ directory. "
            "2. Copy the .sqlite file using Filza or `afc`. "
            "3. Open with `DB Browser for SQLite` to inspect stored data."
        ),
    },

    # ── iOS permissions ───────────────────────────────────────────────────────
    "ios_perm_health": {
        "impact": (
            "HealthKit access allows reading highly sensitive medical information including heart rate, "
            "blood glucose, menstrual cycle data, medications, and step count. Health data is protected "
            "under HIPAA and its unauthorised collection or disclosure carries regulatory exposure."
        ),
        "attack_path": (
            "1. App requests HealthKit authorization at runtime via HKHealthStore.requestAuthorization. "
            "2. If granted, queries are executed silently in the background via HKSampleQuery. "
            "3. Health records are exfiltrated to a remote server without visible UI indication."
        ),
    },
    "ios_perm_tracking": {
        "impact": (
            "NSUserTrackingUsageDescription indicates the app uses the App Tracking Transparency "
            "framework to request cross-app tracking consent. If granted (or on iOS <14.5), the IDFA "
            "is read and shared with ad networks to build behavioural profiles linking the user's "
            "activity across apps and websites."
        ),
        "attack_path": (
            "1. App displays ATT prompt at launch. "
            "2. If user consents, app reads IDFA via ASIdentifierManager. "
            "3. IDFA is shared with third-party SDKs (analytics, ad networks) embedded in the app. "
            "4. Ad networks correlate IDFA activity across their publisher network to build a "
            "detailed cross-app behavioural profile."
        ),
    },

    # ── iOS framework findings ────────────────────────────────────────────────
    "ios_framework_webkit": {
        "impact": (
            "WebKit (WKWebView/UIWebView) renders web content inside the app. If untrusted URLs or "
            "user-controlled data are passed to the WebView, an attacker may inject JavaScript that "
            "executes in the app's context, calls exposed native message handlers, or accesses "
            "Keychain data via custom URL schemes."
        ),
        "attack_path": (
            "1. Use Frida to inspect `WKWebView loadURL:` calls and identify what URLs are loaded. "
            "2. Check if WKScriptMessageHandler exposes sensitive native methods (file access, "
            "token retrieval). "
            "3. If the app loads attacker-influenced URLs, craft a payload that calls the exposed "
            "handler with malicious parameters. "
            "4. Alternatively, intercept HTTP sub-resources and inject JavaScript via mitmproxy."
        ),
    },
    "ios_framework_openssl": {
        "impact": (
            "A bundled OpenSSL dylib may contain known CVEs. Outdated versions are vulnerable to "
            "memory corruption, certificate validation bypass (Heartbleed-class), or protocol "
            "downgrade attacks (POODLE, BEAST). Unlike system frameworks, bundled libraries are "
            "not patched by iOS updates."
        ),
        "attack_path": (
            "1. Extract the OpenSSL dylib from the IPA. "
            "2. Check version: `strings libssl.dylib | grep -E 'OpenSSL [0-9]'`. "
            "3. Cross-reference the version against the OpenSSL CVE database. "
            "4. If a relevant CVE exists and the library handles TLS, assess exploitability in the "
            "app's network communication context."
        ),
    },
    "ios_framework_networking": {
        "impact": "Third-party HTTP libraries (AFNetworking, Alamofire) have historically had TLS certificate validation disabled by default in certain configurations, enabling MITM attacks even over HTTPS.",
        "attack_path": (
            "1. Use Frida or static analysis to check if TLS validation or certificate pinning is "
            "disabled in the library's session configuration. "
            "2. If disabled, route traffic through Burp Suite without SSL kill switch. "
            "3. Intercept and modify HTTPS traffic without triggering a certificate error."
        ),
    },
}

# Generic fallbacks by category when no specific rule_id match exists
_CATEGORY_FALLBACKS: dict[str, dict[str, str]] = {
    "hardcoded_secret": {
        "impact": "Hardcoded secrets embedded in the APK can be extracted by any party who decompiles the application, granting access to the associated service.",
        "attack_path": (
            "1. Decompile APK with `jadx` or `apktool`. "
            "2. Search source for the identified string. "
            "3. Determine the associated service from context and attempt authentication."
        ),
    },
    "manifest_issue": {
        "impact": "Insecure manifest configuration weakens the application's security posture and may be exploited to extract data or manipulate behaviour.",
        "attack_path": "Review the specific manifest attribute and apply the recommended remediation.",
    },
    "insecure_config": {
        "impact": "Insecure transport or configuration settings expose data in transit or weaken cryptographic protections.",
        "attack_path": "An on-path attacker can intercept or tamper with traffic that should have been protected.",
    },
    "exported_component": {
        "impact": "Exported components without access controls are reachable by any installed app on the device.",
        "attack_path": "A malicious app can invoke the component via Intent or ContentResolver to trigger unintended behaviour or access data.",
    },
    "dangerous_permission": {
        "impact": "The requested permission provides access to sensitive device resources or user data.",
        "attack_path": "If the permission is misused by the app or exploited through a vulnerability, it enables access to sensitive information.",
    },
    # iOS-specific category fallbacks
    "ios_ats": {
        "impact": "App Transport Security is misconfigured, weakening or disabling TLS enforcement for some or all network connections. An on-path attacker may be able to intercept or modify traffic.",
        "attack_path": (
            "1. Connect to the same Wi-Fi network as the device. "
            "2. Run mitmproxy or Burp Suite. "
            "3. Observe that the app does not reject the intercepting proxy's certificate for affected domains."
        ),
    },
    "ios_binary": {
        "impact": "Sensitive strings found in the Mach-O binary can be extracted from any IPA file without device access or a jailbreak, using standard binary analysis tools.",
        "attack_path": (
            "1. Obtain the IPA (via ipatool from the App Store or from a device backup). "
            "2. Unzip and run `strings Payload/*.app/<executable>` to extract all printable strings. "
            "3. Search output for credentials, keys, or internal URLs. "
            "4. Use extracted data to authenticate against associated services."
        ),
    },
    "ios_entitlement": {
        "impact": "The app holds a sensitive entitlement that grants elevated capabilities beyond standard sandboxed apps, potentially enabling privilege escalation or sensitive data access.",
        "attack_path": (
            "1. Extract entitlements: `codesign -d --entitlements :- <binary>`. "
            "2. Identify the specific entitlement and the privilege it grants. "
            "3. Exploit the capability in the context of a compromised or jailbroken device."
        ),
    },
    "ios_framework": {
        "impact": "A third-party framework is bundled with the app. Bundled frameworks are not updated by iOS security patches — if the framework contains a known vulnerability, the app remains exposed until the developer ships an update.",
        "attack_path": (
            "1. Identify the framework version from strings in the dylib or its Info.plist. "
            "2. Check the framework's public CVE/security advisory history. "
            "3. Assess whether any known vulnerability applies to the app's usage context."
        ),
    },
    "ios_permission": {
        "impact": "The app declares a privacy-sensitive permission that grants access to device data or sensors. If the permission is misused or accessed by a malicious SDK bundled in the app, it enables data collection beyond the stated purpose.",
        "attack_path": (
            "1. Identify which SDK or code path requests the permission at runtime using Frida. "
            "2. Verify that the usage matches the stated purpose in the usage description string. "
            "3. Check whether third-party analytics or ad SDKs in the app can access the granted permission."
        ),
    },
}


def enrich(rule_id: str | None, category: str | None) -> dict[str, str | None]:
    """Return {impact, attack_path} for a finding.  Falls back to category default, then None."""
    if rule_id and rule_id in _ENRICHMENTS:
        return _ENRICHMENTS[rule_id]
    if category and category in _CATEGORY_FALLBACKS:
        return _CATEGORY_FALLBACKS[category]
    return {"impact": None, "attack_path": None}
