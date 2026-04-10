"""
core.cli.finding_processing - Finding extraction and text parsing (Track 46).

Pure data-processing functions with no dyna.py state dependencies.
"""

import re
from typing import Dict, List, Any

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

# Phase 9.6: Invalid title patterns that should not become finding titles
_INVALID_FINDING_TITLES = frozenset(
    {
        "success",
        "error",
        "unknown",
        "failed",
        "complete",
        "ok",
        "done",
        "true",
        "false",
        "none",
        "null",
        "n/a",
        "na",
        "",
        # Too-generic titles that are not actionable findings
        "security issue",
        "security finding",
        "vulnerability",
        "issue found",
    }
)

# Phase 9.6: Plugin summary patterns - these are summaries, not individual findings
# Phase 10.1: Added always-return v2 plugin adapter patterns (2026-01-28)
_PLUGIN_SUMMARY_PATTERNS = frozenset(
    {
        "apk information extraction",
        "apk signing certificate analysis",
        "enhanced manifest analysis",
        "enhanced improper platform usage analysis",
        "insecure data storage analysis",
        # v2 plugin adapters that always return summary findings
        "advanced pattern integration summary",
        "advanced pattern integration",
        "component security analysis",
        "component analyzer",
        "enhanced detection overview",
        "enhanced detection plugin",
        # Track 71: Plugin status reports that are not vulnerability findings
        "enhanced data storage analysis",
        "advanced ssl/tls analysis",
        "webview security analysis",
        "jadx static analysis",
    }
)


def _is_valid_finding_title(title: str) -> bool:
    """
    Check if a title is a valid vulnerability finding title.

    Phase 9.6: Prevents plugin return statuses and summaries from becoming finding titles.

    Args:
        title: The title string to validate

    Returns:
        True if title is valid for a finding, False otherwise
    """
    if not title or not isinstance(title, str):
        return False

    title_lower = title.strip().lower()

    # Check against invalid status strings
    if title_lower in _INVALID_FINDING_TITLES:
        return False

    # Check against plugin summary patterns
    if title_lower in _PLUGIN_SUMMARY_PATTERNS:
        return False

    # Skip titles that are just plugin status markers (✅, ❌, etc.)
    if title_lower.startswith(("✅", "❌", "⏰", "⚠️")):
        # These are plugin execution status markers, not finding titles
        return False

    # Track 60.1 Fix 2: Reject count-pattern titles like "8 issues", "3 findings"
    if re.match(r"^\d+\s+(issues?|findings?|results?|items?|vulnerabilit(y|ies))$", title_lower):
        return False

    # Track 71: Reject raw plugin name titles (all lowercase with underscores, no spaces)
    if re.match(r"^[a-z][a-z0-9_]+$", title_lower) and "_" in title_lower:
        return False

    # Track 71: Reject titles ending with status suffixes like "(Pass)", "(Fail)", "(Error)"
    if re.search(r"\(\s*(pass|fail|error|success|ok|skipped)\s*\)\s*$", title_lower):
        return False

    return True


def _extract_findings_from_content(content, plugin_name: str) -> list:
    """
    Extract actual vulnerability findings from plugin content.

    Phase 9.6: Properly extracts nested vulnerabilities from plugin results
    instead of treating summaries as single findings.

    Args:
        content: Plugin result content (dict, list, or other)
        plugin_name: Name of the source plugin

    Returns:
        List of finding dictionaries
    """
    findings = []

    if isinstance(content, dict):
        # Check for nested vulnerabilities
        if "vulnerabilities" in content and isinstance(content["vulnerabilities"], list):
            for vuln in content["vulnerabilities"]:
                if isinstance(vuln, dict):
                    # Validate nested vulnerability has a proper title
                    vuln_title = vuln.get("title", vuln.get("name", ""))
                    if _is_valid_finding_title(vuln_title):
                        finding = dict(vuln)
                        finding["plugin_source"] = plugin_name
                        findings.append(finding)

        # Check for findings key
        elif "findings" in content and isinstance(content["findings"], list):
            for finding in content["findings"]:
                if isinstance(finding, dict):
                    finding_title = finding.get("title", finding.get("name", ""))
                    if _is_valid_finding_title(finding_title):
                        f_copy = dict(finding)
                        f_copy["plugin_source"] = plugin_name
                        findings.append(f_copy)

        # Single finding with valid title
        elif "title" in content or "name" in content:
            title = content.get("title", content.get("name", ""))
            if _is_valid_finding_title(title):
                finding = dict(content)
                finding["plugin_source"] = plugin_name
                findings.append(finding)

    elif isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                # Check if item contains nested findings (e.g., Semgrep plugin result)
                if "findings" in item and isinstance(item["findings"], list):
                    for finding in item["findings"]:
                        if isinstance(finding, dict):
                            finding_title = finding.get("title", finding.get("name", ""))
                            if _is_valid_finding_title(finding_title):
                                f_copy = dict(finding)
                                f_copy["plugin_source"] = plugin_name
                                findings.append(f_copy)
                # Check if item contains nested vulnerabilities
                elif "vulnerabilities" in item and isinstance(item["vulnerabilities"], list):
                    for vuln in item["vulnerabilities"]:
                        if isinstance(vuln, dict):
                            vuln_title = vuln.get("title", vuln.get("name", ""))
                            if _is_valid_finding_title(vuln_title):
                                v_copy = dict(vuln)
                                v_copy["plugin_source"] = plugin_name
                                findings.append(v_copy)
                # Single finding item with valid title
                else:
                    item_title = item.get("title", item.get("name", ""))
                    if _is_valid_finding_title(item_title):
                        finding = dict(item)
                        finding["plugin_source"] = plugin_name
                        findings.append(finding)

    return findings


def _parse_vulnerabilities_from_text_report(report_text, plugin_name, structured_plugin_names=None):
    """
    Parse vulnerabilities from text report format, matching orchestrator logic.

    Args:
        report_text (str): The plugin's text report
        plugin_name (str): Name of the plugin for context
        structured_plugin_names (set, optional): Plugin names that already returned
            structured PluginResult findings. When provided, any plugin in this set
            is skipped (auto-detection). Falls back to a hardcoded blocklist when
            not provided.

    Returns:
        List[Dict]: List of vulnerability dictionaries
    """
    import re

    vulnerabilities = []

    # Phase 9.6: Validate input - skip if report_text is just a status string
    if not report_text or not isinstance(report_text, str):
        return []

    report_text_lower = report_text.strip().lower()

    # Skip if the entire report is just a status word
    if report_text_lower in _INVALID_FINDING_TITLES:
        return []

    # Skip if report is very short and looks like a status message
    if len(report_text.strip()) < 20 and not any(
        marker in report_text_lower
        for marker in ["vulnerability", "finding", "security", "critical", "high", "medium", "low", "warning"]
    ):
        return []

    # Track 81: Skip plugins that already returned structured findings.
    # The caller (execution_parallel.py) tracks _plugins_with_structured_findings
    # and passes it here. This replaces the old hardcoded blocklist.
    if structured_plugin_names and plugin_name in structured_plugin_names:
        return []

    # Hardcoded fallback for callers that don't pass structured_plugin_names
    _KNOWN_STRUCTURED_PLUGINS = frozenset({
        "enhanced_manifest_analysis",
        "enhanced_static_analysis",
        "jadx_static_analysis",
        "network_cleartext_traffic",
        "improper_platform_usage",
        "insecure_data_storage",
    })

    if plugin_name in _KNOWN_STRUCTURED_PLUGINS:
        return []

    # First, try to extract explicit findings count
    findings_match = re.search(r"Security Findings:\s*(\d+)", report_text)
    if findings_match:
        findings_count = int(findings_match.group(1))
        logger.debug("Found explicit findings count in plugin", findings_count=findings_count, plugin_name=plugin_name)

        # Create generic vulnerabilities based on findings count
        # This matches the orchestrator's counting logic without hardcoding report formats
        for i in range(findings_count):
            vulnerability = {
                "title": f"{plugin_name} Security Finding #{i + 1}",
                "severity": "MEDIUM",  # Default severity
                "description": f"Security issue detected by {plugin_name} plugin analysis",
                "plugin_source": plugin_name,
                "type": "CONFIGURATION_FLAW",
                "finding_number": i + 1,
                "total_findings": findings_count,
            }
            vulnerabilities.append(vulnerability)

        return vulnerabilities

    # Track 42: Line-by-line severity marker parsing (emoji patterns removed - unsafe)
    finding_patterns = [
        (r"CRITICAL:", "CRITICAL"),
        (r"HIGH:", "HIGH"),
        (r"MEDIUM:", "MEDIUM"),
        (r"LOW:", "LOW"),
    ]

    for line in report_text.splitlines():
        line_stripped = line.strip()
        if not line_stripped or len(line_stripped) < 10:
            continue
        for pattern, severity in finding_patterns:
            if re.match(rf"^\s*{pattern}\s+\S", line_stripped):
                # Extract the text after the severity marker as the finding title
                after_marker = re.sub(rf"^{pattern}\s*", "", line_stripped).strip()
                # Track 60.1 Fix 2: Skip count summaries like "8 issues"
                if re.match(r"^\d+\s+(issues?|findings?|results?|items?|vulnerabilit(y|ies))$", after_marker.lower()):
                    break
                if len(after_marker) > 5:  # Must have substantive content
                    vulnerability = {
                        "title": after_marker[:120],
                        "severity": severity,
                        "description": f"Issue detected by {plugin_name}: {after_marker}",
                        "plugin_source": plugin_name,
                        "type": "CONFIGURATION_FLAW",
                    }
                    vulnerabilities.append(vulnerability)
                break  # One finding per line max

    return vulnerabilities


def _extract_severity_from_pattern(pattern):
    """Extract severity level from regex pattern."""
    if "CRITICAL" in pattern or "🔴" in pattern:
        return "CRITICAL"
    elif "HIGH" in pattern or "❌" in pattern:
        return "HIGH"
    elif "MEDIUM" in pattern or "⚠️" in pattern:
        return "MEDIUM"
    elif "LOW" in pattern or "🟡" in pattern:
        return "LOW"
    else:
        return "MEDIUM"  # Default


def _create_canonical_findings(json_results: Dict[str, Any], logger) -> List[Dict]:
    """
    Merge all vulnerability containers into a single canonical list.

    This fixes the container assembly/synchronization problem where findings
    exist in one container but not others.

    Deduplication uses a stable composite key:
    (plugin_source, title, evidence.file_path, evidence.line_number)

    NOTE: This is stage-1 (plugin-scoped) dedup. Stage-2 (cross-plugin) dedup
    in final_report_serializer._canonical_key() uses (title, category, file_path,
    cwe_id) WITHOUT plugin_source, intentionally merging equivalent findings
    from different plugins. The two stages are complementary by design.
    """
    # Collect from all containers.
    # IMPORTANT: 'vulnerabilities' (classifier output with classification dict and correct
    # severity) MUST come before 'enhanced_vulnerabilities' (EVRE output that independently
    # re-classifies severity and strips classification dict). First occurrence wins in dedup,
    # so the classifier's truth-source findings take priority.
    all_containers = [
        ("vulnerabilities", json_results.get("vulnerabilities", [])),
        ("enhanced_vulnerabilities", json_results.get("enhanced_vulnerabilities", [])),
        ("vulnerability_findings", json_results.get("vulnerability_findings", [])),
        ("findings", json_results.get("findings", [])),
    ]

    # Log container sizes before merge
    for name, container in all_containers:
        if container:
            logger.debug(f"Container '{name}' has {len(container)} findings before merge")

    # Merge with dedup by stable composite key
    seen_keys = set()
    canonical = []

    for container_name, container in all_containers:
        if not isinstance(container, list):
            continue
        for finding in container:
            if not isinstance(finding, dict):
                continue

            # Build stable composite key
            evidence = finding.get("evidence", {})
            if isinstance(evidence, dict):
                file_path = evidence.get("file_path", "")
                line_number = evidence.get("line_number", 0)
            else:
                file_path = ""
                line_number = 0

            # Normalize file_path for dedup: same Java class from different
            # absolute paths (e.g., /tmp/jadx_... vs workspace/.../sources/...)
            # should be treated as the same finding.
            norm_path = str(file_path)
            for marker in ("/sources/", "/smali/"):
                if marker in norm_path:
                    norm_path = norm_path[norm_path.index(marker) + len(marker) :]
                    break

            # Track 60: Normalize title for better dedup (strip emoji prefixes, casefold)
            raw_title = str(finding.get("title", ""))
            norm_title = (
                re.sub(r"^[\U0001f300-\U0001f9ff\u2600-\u27bf\u2702-\u27b0\s]+", "", raw_title).strip().casefold()
            )

            key = (
                str(finding.get("plugin_source", finding.get("source", ""))),
                norm_title,
                norm_path,
                int(line_number) if isinstance(line_number, (int, float)) else 0,
            )

            # Skip empty keys (likely invalid findings)
            if key == ("", "", "", 0):
                continue

            if key not in seen_keys:
                seen_keys.add(key)
                canonical.append(finding)

    # Evidence normalization and recommendation improvement
    _normalize_finding_evidence(canonical)
    _improve_recommendations(canonical)

    logger.info(
        f"Created canonical findings list: {len(canonical)} unique findings from {sum(len(c) for _, c in all_containers if isinstance(c, list))} total"  # noqa: E501
    )

    return canonical


def _normalize_finding_evidence(findings: list) -> None:
    """Promote nested evidence fields to top-level and set manifest defaults.

    Must run as the LAST pass before JSON write - earlier normalization/enrichment
    passes may create fresh dicts that lose previously-set fields.
    """
    # Filter out low-confidence evidenceless meta-findings (FP gate)
    findings[:] = [
        f for f in findings
        if not (
            isinstance(f.get("confidence"), (int, float))
            and f["confidence"] < 0.25
            and not f.get("file_path")
            and not f.get("code_snippet")
        )
    ]

    for finding in findings:
        evidence = finding.get("evidence")
        if isinstance(evidence, dict):
            # Promote evidence.code_snippet or evidence.content to top-level code_snippet.
            # Do NOT promote evidence.description - it just repeats the finding
            # description and creates a fake "code" snippet in the report.
            if not finding.get("code_snippet"):
                snippet = evidence.get("code_snippet") or evidence.get("content")
                if snippet:
                    desc = finding.get("description", "")
                    # Only promote if it looks like real code, not just the description repeated
                    if snippet != desc and snippet != finding.get("title", ""):
                        finding["code_snippet"] = snippet

            # Promote evidence.file_path to top-level file_path if missing
            if not finding.get("file_path") and evidence.get("file_path"):
                finding["file_path"] = evidence["file_path"]

            # Promote evidence.line_number to top-level if missing
            if not finding.get("line_number") and evidence.get("line_number"):
                finding["line_number"] = evidence["line_number"]

        # Manifest findings: set file_path to AndroidManifest.xml
        plugin_src = finding.get("plugin_source", "")
        if not finding.get("file_path") and "manifest" in plugin_src:
            finding["file_path"] = "AndroidManifest.xml"
            if isinstance(evidence, dict) and not evidence.get("file_path"):
                evidence["file_path"] = "AndroidManifest.xml"

        # Normalize workspace path leaks in file_path
        # e.g. app://workspace/DIVA_2570b954_decompiled/AndroidManifest.xml → AndroidManifest.xml
        fp = finding.get("file_path", "") or ""
        if "_decompiled/" in fp:
            # Strip everything up to and including _decompiled/
            _, _, tail = fp.partition("_decompiled/")
            if tail:
                finding["file_path"] = tail
                if isinstance(evidence, dict):
                    evidence["file_path"] = tail

        # Downgrade "Dangerous Intent Action" for standard system intents
        # VIEW, SEND, BOOT_COMPLETED, CONNECTIVITY_CHANGE etc. are normal app
        # functionality - rating them HIGH inflates severity on production apps
        title = finding.get("title", "")
        if "Dangerous Intent Action" in title and finding.get("severity") == "HIGH":
            finding["severity"] = "MEDIUM"
            classification = finding.get("classification")
            if isinstance(classification, dict):
                classification["severity"] = "MEDIUM"

        # Downgrade "Exported X Without Permission" from CRITICAL to HIGH.
        # The VulnerabilityClassifier rule (precedence 9) assigns CRITICAL, but
        # the plugin (enhanced_manifest_analysis) assigns HIGH - which is the
        # correct severity for exported components (they are access-control
        # issues, not RCE/data-breach level).  _convert_to_security_finding()
        # in unified_facade.py overrides top-level severity with
        # classification.severity, inflating to CRITICAL in the standard path.
        if (
            "Without Permission" in title
            and title.startswith("Exported ")
            and finding.get("severity") == "CRITICAL"
        ):
            finding["severity"] = "HIGH"
            classification = finding.get("classification")
            if isinstance(classification, dict):
                classification["severity"] = "HIGH"

        # Default line_number to None (not 0) - 0 is misleading
        if "line_number" not in finding:
            finding["line_number"] = None

    # Remove "Manifest Security Exported Components" when individual exported
    # component findings already exist (duplicate concept)
    has_individual_exported = any(
        f.get("title", "").startswith("Exported ") and "Without Permission" in f.get("title", "") for f in findings
    )
    if has_individual_exported:
        findings[:] = [f for f in findings if f.get("title") != "Manifest Security Exported Components"]


# Mapping of finding categories/CWEs to specific actionable recommendations
_RECOMMENDATION_MAP = {
    "CWE-926": 'Add android:exported="false" or define a custom permission with android:protectionLevel="signature" for each exported component.',  # noqa: E501
    "CWE-1104": "Raise minSdkVersion to at least 23 (Android 6.0) to enforce runtime permissions and benefit from modern security APIs.",  # noqa: E501
    "CWE-489": 'Set android:debuggable="false" in the release build manifest and verify via build variants.',
    "CWE-200": 'Set android:allowBackup="false" or implement a BackupAgent with encryption to protect sensitive data from ADB backup extraction.',  # noqa: E501
    "CWE-693": 'Enable network security config with cleartextTrafficPermitted="false" and certificate pinning for API endpoints.',  # noqa: E501
    "CWE-250": "Remove unnecessary dangerous permissions. Use runtime permission requests with clear rationale and degrade gracefully when denied.",  # noqa: E501
    "CWE-732": 'Restrict content provider access with android:exported="false" or require a signature-level permission via android:readPermission/android:writePermission.',  # noqa: E501
    "CWE-927": "Validate all incoming Intent data. Use explicit intents where possible and verify the calling package with getCallingPackage() before processing sensitive actions.",  # noqa: E501
    "CWE-89": "Use parameterized queries (selectionArgs) in ContentResolver and SQLiteDatabase calls. Never concatenate user input into SQL strings.",  # noqa: E501
    "CWE-94": "Avoid dynamic DEX/class loading. If required, verify integrity (hash/signature) of loaded code and restrict to app-private directories.",  # noqa: E501
    "CWE-749": "Restrict exposed dangerous methods: disable WebView JavaScript unless required, use @JavascriptInterface sparingly, and minimize setAccessible(true) usage.",  # noqa: E501
    "CWE-470": "Avoid Class.forName() with user-controlled input. Use explicit class references or a whitelist of allowed class names.",  # noqa: E501
    "CWE-427": "Load native libraries only from the APK's lib/ directory. Verify library integrity before loading and avoid user-controlled library names.",  # noqa: E501
    "CWE-1021": "Set filterTouchesWhenObscured=true on security-sensitive Views or check FLAG_WINDOW_IS_OBSCURED in onTouchEvent to prevent tapjacking.",  # noqa: E501
    "CWE-330": "Replace java.util.Random and Math.random() with java.security.SecureRandom for cryptographic operations, tokens, keys, and nonces.",  # noqa: E501
    "CWE-916": "Use PBKDF2WithHmacSHA256 with at least 600,000 iterations, or Argon2. Never derive keys directly from String.getBytes().",  # noqa: E501
    "CWE-798": "Remove hardcoded credentials and API keys. Use Android Keystore, EncryptedSharedPreferences, or a secure secrets manager.",  # noqa: E501
    "CWE-312": "Use EncryptedSharedPreferences (Jetpack Security) or Android Keystore for sensitive data. Never store plaintext credentials or tokens.",  # noqa: E501
    "CWE-319": "Enforce TLS for all network connections via network_security_config.xml with cleartextTrafficPermitted=false. Pin certificates for sensitive endpoints.",  # noqa: E501
    "CWE-359": "Minimize collection of device identifiers and PII. Use ANDROID_ID or app-scoped IDs instead of hardware identifiers. Obtain explicit consent.",  # noqa: E501
    "CWE-601": "Use exact-match redirect URIs with app-scheme or verified HTTPS endpoints. Validate redirect targets against a whitelist.",  # noqa: E501
    "CWE-287": "Enforce strong authentication: use CryptoObject-based biometric auth with Keystore-bound keys, or authorization code flow with PKCE for OAuth. Validate credentials server-side.",  # noqa: E501
    "CWE-326": "Require user authentication for sensitive Keystore entries via setUserAuthenticationRequired(true) in KeyGenParameterSpec.",  # noqa: E501
    "CWE-401": "Avoid static references to Context or View objects. Use WeakReference for callbacks and clear listeners in onDestroy/onStop.",  # noqa: E501
    "CWE-320": "Use modern cryptographic primitives: AES-GCM for symmetric encryption, ECDSA/Ed25519 for signing, SecureRandom for PRNG.",  # noqa: E501
    "CWE-327": "Replace deprecated cryptographic algorithms (DES, 3DES, ECB mode, RC4) with AES-GCM for encryption and HMAC-SHA256 for authentication.",  # noqa: E501
}

_TITLE_RECOMMENDATION_MAP = {
    "exported activities": 'Restrict exported activities: set android:exported="false" or guard with a signature-level permission. Validate all Intent extras from external callers.',  # noqa: E501
    "exported services": 'Restrict exported services: set android:exported="false" or guard with a signature-level permission. Bind-only services should never be exported.',  # noqa: E501
    "exported receivers": 'Restrict exported receivers: set android:exported="false" for receivers that handle app-internal broadcasts only.',  # noqa: E501
    "exported providers": 'Restrict exported providers: set android:exported="false" or add android:readPermission/android:writePermission with protectionLevel="signature".',  # noqa: E501
    "cleartext traffic": 'Disable cleartext traffic: add a network_security_config.xml with cleartextTrafficPermitted="false" and pin certificates for sensitive API domains.',  # noqa: E501
    "dangerous permission": "Justify each dangerous permission in a privacy manifest. Request at runtime with rationale, handle denial gracefully, and remove unused permissions.",  # noqa: E501
    "excessive permissions": "Audit all declared permissions against actual usage. Remove any permission not required for core functionality.",  # noqa: E501
    "grant uri permissions": 'Scope URI grants to the minimum path and use FLAG_GRANT_READ_URI_PERMISSION only where needed. Avoid grantUriPermissions="true" on the provider element.',  # noqa: E501
    "world-accessible content provider": 'Set android:exported="false" on the provider and use a FileProvider with explicit URI grants instead of world-readable paths.',  # noqa: E501
    "unprotected system broadcast": "Register system broadcast receivers with an intent filter restricted to the specific action and guard with a permission if exported.",  # noqa: E501
    "weak custom permission": 'Declare custom permissions with android:protectionLevel="signature" to ensure only same-signing-key apps can use them.',  # noqa: E501
    "debug/test component": "Remove or disable debug/test components in release builds. Use BuildConfig.DEBUG guards and exclude test activities from the release manifest.",  # noqa: E501
    "sql injection": "Use parameterized queries (selectionArgs) in ContentResolver and SQLiteDatabase calls. Never concatenate user input into SQL strings.",  # noqa: E501
    "low minimum sdk": "Raise minSdkVersion to at least 23 (Android 6.0) to enforce runtime permissions and benefit from modern security APIs.",  # noqa: E501
    "dangerous intent action": "Validate all incoming Intent data. Use explicit intents where possible and verify the calling package with getCallingPackage() before processing sensitive actions.",  # noqa: E501
    "clipboard": "Clear clipboard data after a short delay. On API 33+ use PendingIntent-based expiry. Avoid placing sensitive data (passwords, tokens, CC numbers) on the clipboard.",  # noqa: E501
    "biometric": "Use setUserAuthenticationRequired(true) with KeyGenParameterSpec to bind cryptographic keys to biometric auth. Implement CryptoObject-based authentication rather than callback-only flows.",  # noqa: E501
    "command execution": "Avoid Runtime.exec() with user-controlled input. Use ProcessBuilder with explicit argument lists and validate/sanitize all command parameters against an allowlist.",  # noqa: E501
    "runtime command": "Avoid Runtime.exec() with user-controlled input. Use ProcessBuilder with explicit argument lists and validate/sanitize all command parameters against an allowlist.",  # noqa: E501
    "no data deletion": "Implement data deletion methods (SharedPreferences.Editor.clear(), File.delete()) to support user data erasure requests per GDPR Article 17 / right to erasure.",  # noqa: E501
    "accessibility bypass": "Minimize use of setAccessible(true). If required, restrict to specific fields/methods and document the security justification. Consider using MethodHandles instead.",  # noqa: E501
    "deprecated permission": "Migrate to scoped storage APIs (MediaStore, SAF) instead of broad storage permissions. Remove deprecated permissions from the manifest.",  # noqa: E501
    "emulator detection": "Emulator/root detection is a defensive measure. Ensure detection logic is obfuscated and cannot be easily bypassed. Combine with SafetyNet/Play Integrity API.",  # noqa: E501
    "root detection": "Emulator/root detection is a defensive measure. Ensure detection logic is obfuscated and cannot be easily bypassed. Combine with SafetyNet/Play Integrity API.",  # noqa: E501
    "webview javascript": "Disable JavaScript in WebViews unless strictly necessary. When required, restrict to trusted origins and use @JavascriptInterface annotation only for explicitly exposed methods.",  # noqa: E501
    "javascript enabled": "Disable JavaScript in WebViews unless strictly necessary. When required, restrict to trusted origins and use @JavascriptInterface annotation only for explicitly exposed methods.",  # noqa: E501
    "javascript execution": "Disable JavaScript in WebViews unless strictly necessary. When required, restrict to trusted origins and use @JavascriptInterface annotation only for explicitly exposed methods.",  # noqa: E501
    "broken hash": "Replace broken hash algorithms (MD5, SHA-1) with SHA-256 or SHA-3. For password hashing use bcrypt, scrypt, or Argon2.",  # noqa: E501
    "logging pii": "Avoid logging sensitive information. Use ProGuard/R8 to strip debug logs in release builds.",  # noqa: E501
    "device fingerprinting": "Minimize collection of device identifiers and PII. Use ANDROID_ID or app-scoped IDs instead of hardware identifiers. Obtain explicit consent.",  # noqa: E501
    "tapjacking": "Set filterTouchesWhenObscured=true on security-sensitive Views or check FLAG_WINDOW_IS_OBSCURED in onTouchEvent to prevent tapjacking.",  # noqa: E501
    "overlay protection": "Set filterTouchesWhenObscured=true on security-sensitive Views or check FLAG_WINDOW_IS_OBSCURED in onTouchEvent to prevent tapjacking.",  # noqa: E501
    "sharedpreferences": "Use EncryptedSharedPreferences (Jetpack Security) or Android Keystore for sensitive data. Never store plaintext credentials or tokens.",  # noqa: E501
    "hardcoded credential": "Remove hardcoded credentials and API keys. Use Android Keystore, EncryptedSharedPreferences, or a secure secrets manager.",  # noqa: E501
    "hardcoded secret": "Remove hardcoded credentials and API keys. Use Android Keystore, EncryptedSharedPreferences, or a secure secrets manager.",  # noqa: E501
    "hardcoded api key": "Remove hardcoded credentials and API keys. Use Android Keystore, EncryptedSharedPreferences, or a secure secrets manager.",  # noqa: E501
}


def _improve_recommendations(findings: list) -> None:
    """Replace generic recommendations with specific, actionable ones."""
    generic_phrases = {
        "review and remediate",
        "apply defense-in-depth",
        "implement proper authorization",
        "address this finding immediately",
        "review this finding and consider",
    }

    for finding in findings:
        rec = finding.get("recommendation", "")
        is_generic = any(phrase in rec.lower() for phrase in generic_phrases)

        # Try title-based lookup FIRST - it's more specific than CWE
        # (e.g., CWE-200 covers both backup and clipboard, but title disambiguates)
        title_lower = finding.get("title", "").lower()
        title_matched = False
        for pattern, specific_rec in _TITLE_RECOMMENDATION_MAP.items():
            if pattern in title_lower:
                finding["recommendation"] = specific_rec
                title_matched = True
                break
        if title_matched:
            continue

        if not is_generic and rec:
            continue  # Already has a specific recommendation

        # CWE-based lookup as fallback
        cwe = finding.get("cwe_id", "")
        if cwe and cwe in _RECOMMENDATION_MAP:
            finding["recommendation"] = _RECOMMENDATION_MAP[cwe]
            continue

        # Legacy: title-based lookup for remaining unmatched (already handled above)
        # kept for safety but shouldn't reach here
        for pattern, specific_rec in _TITLE_RECOMMENDATION_MAP.items():
            if pattern in title_lower:
                finding["recommendation"] = specific_rec
                break


def _sync_all_containers(json_results: Dict[str, Any], canonical: List[Dict], logger) -> None:
    """
    Synchronize all vulnerability containers to use the canonical list.

    This ensures:
    len(vulnerabilities) == len(enhanced_vulnerabilities) == len(vulnerability_findings) == len(findings)
    """
    json_results["vulnerabilities"] = canonical
    json_results["enhanced_vulnerabilities"] = canonical
    json_results["vulnerability_findings"] = canonical
    json_results["findings"] = canonical

    # Update counts in summary if present
    if "summary" in json_results and isinstance(json_results["summary"], dict):
        json_results["summary"]["total_findings"] = len(canonical)
        json_results["summary"]["findings_count"] = len(canonical)

    # Update top-level findings_count
    if "findings_count" in json_results:
        json_results["findings_count"] = len(canonical)

    logger.info(f"Synchronized all containers to {len(canonical)} findings")
