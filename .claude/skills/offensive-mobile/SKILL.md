# Mobile (Android + iOS) — Offensive Testing Methodology

## Overview
This methodology covers comprehensive mobile application penetration testing across Android and iOS platforms. It encompasses static analysis, dynamic instrumentation, attack surface mapping, data storage auditing, API testing, and cloud misconfiguration exploitation.

## Core Testing Areas

**Static Analysis**: Decompiling APKs with apktool/jadx (Android) or class-dump/Hopper (iOS) to identify endpoints, secrets, and exported components.

**Dynamic Testing**: Installing on rooted/jailbroken devices with Frida and Objection to intercept traffic, bypass protections, and hook runtime functions.

**IPC/Export Surface**: Testing Android's exported activities, services, ContentProviders, and iOS URL schemes/XPC services for authorization bypasses.

**Storage Security**: Auditing SharedPreferences, SQLite databases, Keychain implementations, and external storage for insecure credential storage.

**Cloud Misconfigurations**: Identifying Firebase Realtime DB, Firestore, S3, and GCS exposure through embedded URLs and unauth access testing.

**Biometric Bypass**: Hooking authentication callbacks to bypass unbound biometric flows without accessing the underlying cryptographic keys.

**WebView Vulnerabilities**: Testing `addJavascriptInterface` exposure, file:// protocol access, and script message handlers for code execution.

## BluJay Integration

Use these BluJay endpoints to execute this methodology:

### Static Analysis
- `POST /api/analyses` — AODS/IODS scanner (APK/IPA upload + full static scan)
- `POST /api/scanner/scan-url` — passive checks against a URL
- `GET /api/scanner/findings` — review all findings

### Dynamic Testing
- `GET /api/frida/processes/{serial}` — enumerate processes
- `POST /api/frida/sessions` — attach Frida to a package
- `POST /api/frida/sessions/{id}/scripts` — load builtin or custom script
  - builtin_name: `ssl_pinning_bypass`, `root_detection_bypass`, `crypto_hooks`, `method_tracer`
  - builtin_name: `biometric_bypass` — bypass unbound BiometricPrompt / FingerprintManager
  - builtin_name: `android_storage_audit` — hook SharedPreferences + SQLiteDatabase reads/writes
  - builtin_name: `ios_ssl_pinning_bypass`, `ios_jailbreak_bypass`, `ios_keychain_dump`
- `POST /api/objection/start` — launch Objection session

### IPC / Export Surface
- `POST /api/devices/{serial}/drozer/attack-surface/{package}` — enumerate exported components
- `POST /api/devices/{serial}/drozer/run` — run arbitrary drozer module
- `POST /api/devices/{serial}/drozer/setup` — install drozer agent + set up port forward

### Storage Security
- Load `android_storage_audit` Frida script → monitors SharedPreferences + SQLite in real time
- Load `ios_keychain_dump` Frida script → intercepts SecItemCopyMatching on iOS
- `GET /api/scanner/findings?scan_type=passive` — review static storage findings from analysis

### Cloud Misconfigurations
- `POST /api/recon/start` with `check_buckets: true` — S3/GCS/Azure bucket discovery
- `POST /api/cloud/test` — Firebase, GCS, S3 misconfiguration checks

### Biometric Bypass
- Attach Frida: `POST /api/frida/sessions`
- Load builtin: `POST /api/frida/sessions/{id}/scripts` with `builtin_name: "biometric_bypass"`
- Monitor events: `GET /api/frida/events?session_id={id}`

### Domain / API Recon
- `POST /api/domain-osint/start` — full passive OSINT on target domain (DNS, crt.sh, passive DNS, Shodan, ExternalDNS TXT/K8s intel)

## Key Tools
- **Android**: Magisk, LSPosed, Frida server, drozer, APKsigner
- **iOS**: Jailbreak tools (palera1n/checkra1n), Filza, iproxy, Objection
- **Both**: Burp Suite/Mitmproxy, apktool, jadx, class-dump, truffleHog

## Workflow

1. **Recon** — `POST /api/analyses` to upload APK/IPA and run full static scan. Review findings for endpoints, secrets (built-in regex + entropy scanner covers AWS/GCP/Azure/GitHub/Stripe/JWT/etc.), exported components.
2. **Setup proxy** — `POST /api/proxy/start`, `POST /api/devices/{serial}/proxy/set`
3. **Attach Frida** — enumerate processes, attach, load SSL pinning bypass + crypto hooks
4. **Dynamic surface** — run drozer attack surface scan against package
5. **Storage audit** — load `android_storage_audit` or `ios_keychain_dump` while exercising app flows
6. **Biometric** — if auth prompt appears, load `biometric_bypass`
7. **Cloud** — run `POST /api/cloud/test` + `POST /api/recon/start`
8. **Report** — `POST /api/report` to generate findings report
