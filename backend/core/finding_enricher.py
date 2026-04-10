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
}


def enrich(rule_id: str | None, category: str | None) -> dict[str, str | None]:
    """Return {impact, attack_path} for a finding.  Falls back to category default, then None."""
    if rule_id and rule_id in _ENRICHMENTS:
        return _ENRICHMENTS[rule_id]
    if category and category in _CATEGORY_FALLBACKS:
        return _CATEGORY_FALLBACKS[category]
    return {"impact": None, "attack_path": None}
