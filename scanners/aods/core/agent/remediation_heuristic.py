"""
core.agent.remediation_heuristic - Rule-based remediation fallback (no LLM required).

Generates code fix templates for common CWE patterns when no LLM API key
is available.  Uses a CWE-to-fix-pattern dictionary to produce concrete
before/after code snippets.

Public API:
    run_heuristic_remediation(report_file, report_dir) -> RemediationResult
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)

from .remediation import (
    FindingRemediation,
    RemediationResult,
    save_remediation_to_report,
)

# ---------------------------------------------------------------------------
# CWE-to-fix templates
# ---------------------------------------------------------------------------

_CWE_FIX_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "CWE-312": {
        "vulnerability_type": "Cleartext Storage of Sensitive Information",
        "current_code": (
            "SharedPreferences prefs = getSharedPreferences(\"app\", MODE_PRIVATE);\n"
            "prefs.edit().putString(\"token\", sensitiveToken).apply();"
        ),
        "fixed_code": (
            "import androidx.security.crypto.EncryptedSharedPreferences;\n"
            "import androidx.security.crypto.MasterKey;\n\n"
            "MasterKey masterKey = new MasterKey.Builder(context)\n"
            "    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build();\n"
            "SharedPreferences prefs = EncryptedSharedPreferences.create(\n"
            "    context, \"app_secure\", masterKey,\n"
            "    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,\n"
            "    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);\n"
            "prefs.edit().putString(\"token\", sensitiveToken).apply();"
        ),
        "explanation": "Replace SharedPreferences with EncryptedSharedPreferences from Jetpack Security.",
        "difficulty": "easy",
        "references": [
            "https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences"
        ],
        "test_suggestion": "Verify data is encrypted on disk: inspect app_secure.xml in /data/data/<pkg>/shared_prefs/",
    },
    "CWE-89": {
        "vulnerability_type": "SQL Injection",
        "current_code": (
            "String query = \"SELECT * FROM users WHERE id = '\" + userId + \"'\";\n"
            "Cursor c = db.rawQuery(query, null);"
        ),
        "fixed_code": (
            "String query = \"SELECT * FROM users WHERE id = ?\";\n"
            "Cursor c = db.rawQuery(query, new String[]{userId});"
        ),
        "explanation": "Use parameterized queries with placeholder (?) to prevent SQL injection.",
        "difficulty": "easy",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://developer.android.com/reference/android/database/sqlite/"
            "SQLiteDatabase#rawQuery",
        ],
        "test_suggestion": "Test with SQL metacharacters as input: userId = \"1' OR '1'='1\"",
    },
    "CWE-327": {
        "vulnerability_type": "Use of Broken or Risky Cryptographic Algorithm",
        "current_code": (
            "MessageDigest md = MessageDigest.getInstance(\"MD5\");\n"
            "byte[] hash = md.digest(data.getBytes());"
        ),
        "fixed_code": (
            "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\n"
            "byte[] hash = md.digest(data.getBytes(StandardCharsets.UTF_8));"
        ),
        "explanation": "Replace MD5/SHA-1 with SHA-256 or stronger. For password hashing, use bcrypt/Argon2.",
        "difficulty": "easy",
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography"
        ],
        "test_suggestion": "Verify hashing output length matches SHA-256 (32 bytes / 64 hex chars)",
    },
    "CWE-926": {
        "vulnerability_type": "Improper Export of Android Application Components",
        "current_code": (
            "<activity android:name=\".InternalActivity\"\n"
            "    android:exported=\"true\" />"
        ),
        "fixed_code": (
            "<activity android:name=\".InternalActivity\"\n"
            "    android:exported=\"false\" />"
        ),
        "explanation": "Set exported=false for components not intended for external access. "
        "If external access is needed, add a custom permission.",
        "difficulty": "easy",
        "references": [
            "https://developer.android.com/guide/topics/manifest/activity-element#exported"
        ],
        "test_suggestion": "Attempt to launch the activity via adb: adb shell am start -n <pkg>/.InternalActivity",
    },
    "CWE-295": {
        "vulnerability_type": "Improper Certificate Validation",
        "current_code": (
            "TrustManager[] trustAll = new TrustManager[] {\n"
            "    new X509TrustManager() {\n"
            "        public void checkClientTrusted(X509Certificate[] certs, String t) {}\n"
            "        public void checkServerTrusted(X509Certificate[] certs, String t) {}\n"
            "        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }\n"
            "    }\n"
            "};"
        ),
        "fixed_code": (
            "// Use default trust manager (validates certificates)\n"
            "// For certificate pinning, use network_security_config.xml:\n"
            "// res/xml/network_security_config.xml:\n"
            "// <network-security-config>\n"
            "//   <domain-config>\n"
            "//     <domain includeSubdomains=\"true\">api.example.com</domain>\n"
            "//     <pin-set expiration=\"2025-01-01\">\n"
            "//       <pin digest=\"SHA-256\">BASE64_ENCODED_HASH</pin>\n"
            "//     </pin-set>\n"
            "//   </domain-config>\n"
            "// </network-security-config>\n"
            "SSLContext ctx = SSLContext.getInstance(\"TLS\");\n"
            "ctx.init(null, null, null);  // Uses default trust manager"
        ),
        "explanation": (
            "Remove custom TrustManager that accepts all certificates. "
            "Use Android's Network Security Config for pinning."
        ),
        "difficulty": "moderate",
        "references": [
            "https://developer.android.com/privacy-and-security/security-config"
        ],
        "test_suggestion": "Attempt MITM with a proxy (e.g., Burp Suite) - connection should fail with cert error",
    },
    "CWE-321": {
        "vulnerability_type": "Use of Hard-coded Cryptographic Key",
        "current_code": (
            "private static final String SECRET_KEY = \"MyHardcodedKey123\";\n"
            "SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), \"AES\");"
        ),
        "fixed_code": (
            "import android.security.keystore.KeyGenParameterSpec;\n"
            "import android.security.keystore.KeyProperties;\n\n"
            "KeyGenerator keyGen = KeyGenerator.getInstance(\n"
            "    KeyProperties.KEY_ALGORITHM_AES, \"AndroidKeyStore\");\n"
            "keyGen.init(new KeyGenParameterSpec.Builder(\"my_key\",\n"
            "    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)\n"
            "    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)\n"
            "    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)\n"
            "    .build());\n"
            "SecretKey key = keyGen.generateKey();"
        ),
        "explanation": "Use Android KeyStore to generate and store keys securely instead of hardcoding.",
        "difficulty": "moderate",
        "references": [
            "https://developer.android.com/privacy-and-security/keystore"
        ],
        "test_suggestion": "Grep decompiled source for the old hardcoded key - should not appear",
    },
    "CWE-749": {
        "vulnerability_type": "Exposed Dangerous Method or Function (WebView)",
        "current_code": (
            "webView.getSettings().setJavaScriptEnabled(true);\n"
            "webView.getSettings().setAllowFileAccess(true);\n"
            "webView.addJavascriptInterface(new MyInterface(), \"Android\");"
        ),
        "fixed_code": (
            "webView.getSettings().setJavaScriptEnabled(true);  // Only if JS is required\n"
            "webView.getSettings().setAllowFileAccess(false);\n"
            "webView.getSettings().setAllowFileAccessFromFileURLs(false);\n"
            "webView.getSettings()"
            ".setAllowUniversalAccessFromFileURLs(false);\n"
            "// Only expose @JavascriptInterface annotated methods\n"
            "webView.addJavascriptInterface(new SafeInterface(), \"Android\");"
        ),
        "explanation": (
            "Restrict WebView file access and ensure JavaScript interfaces "
            "use @JavascriptInterface annotation."
        ),
        "difficulty": "moderate",
        "references": [
            "https://developer.android.com/develop/ui/views/layout/webapps/best-practices"
        ],
        "test_suggestion": "Load file:///data/data/<pkg>/... URL in WebView - should be blocked",
    },
    "CWE-532": {
        "vulnerability_type": "Insertion of Sensitive Information into Log File",
        "current_code": (
            "Log.d(TAG, \"User token: \" + authToken);\n"
            "Log.i(TAG, \"Password: \" + password);"
        ),
        "fixed_code": (
            "if (BuildConfig.DEBUG) {\n"
            "    Log.d(TAG, \"Auth operation completed\");\n"
            "}\n"
            "// Never log sensitive data; use ProGuard/R8 to strip debug logs in release"
        ),
        "explanation": "Remove sensitive data from log statements. Guard debug logs with BuildConfig.DEBUG.",
        "difficulty": "easy",
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2023-risks/m8-security-misconfiguration"
        ],
        "test_suggestion": "Run 'adb logcat | grep -i token' with release build - should find no sensitive data",
    },
    "CWE-319": {
        "vulnerability_type": "Cleartext Transmission of Sensitive Information",
        "current_code": (
            "// AndroidManifest.xml\n"
            "<application android:usesCleartextTraffic=\"true\">"
        ),
        "fixed_code": (
            "// AndroidManifest.xml\n"
            "<application\n"
            "    android:usesCleartextTraffic=\"false\"\n"
            "    android:networkSecurityConfig=\"@xml/network_security_config\">\n\n"
            "// res/xml/network_security_config.xml\n"
            "<network-security-config>\n"
            "    <base-config cleartextTrafficPermitted=\"false\" />\n"
            "</network-security-config>"
        ),
        "explanation": "Disable cleartext traffic and enforce HTTPS via Network Security Config.",
        "difficulty": "easy",
        "references": [
            "https://developer.android.com/privacy-and-security/security-config"
        ],
        "test_suggestion": "Attempt HTTP connection - should throw CleartextNotPermittedException",
    },
    "CWE-200": {
        "vulnerability_type": "Exposure of Sensitive Information",
        "current_code": (
            "try {\n"
            "    processPayment(card);\n"
            "} catch (Exception e) {\n"
            "    Toast.makeText(this, e.toString(), Toast.LENGTH_LONG).show();\n"
            "}"
        ),
        "fixed_code": (
            "try {\n"
            "    processPayment(card);\n"
            "} catch (Exception e) {\n"
            "    Log.e(TAG, \"Payment error\", e);  // Log internally only\n"
            "    Toast.makeText(this, \"Payment failed. Please try again.\",\n"
            "        Toast.LENGTH_LONG).show();\n"
            "}"
        ),
        "explanation": "Show generic error messages to users; log detailed errors internally only.",
        "difficulty": "easy",
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2023-risks/m8-security-misconfiguration"
        ],
        "test_suggestion": "Trigger the error condition and verify no stack trace shown to user",
    },
    "CWE-798": {
        "vulnerability_type": "Use of Hard-coded Password",
        "current_code": (
            "public class DatabaseHelper {\n"
            "    private static final String DB_PASSWORD = \"s3cretP@ss!\";\n\n"
            "    public DatabaseHelper(Context context) {\n"
            "        SQLiteDatabase db = SQLiteDatabase.openOrCreateDatabase(\n"
            "            context.getDatabasePath(\"app.db\"), DB_PASSWORD, null);\n"
            "    }\n"
            "}"
        ),
        "fixed_code": (
            "import android.security.keystore.KeyGenParameterSpec;\n"
            "import android.security.keystore.KeyProperties;\n"
            "import java.security.KeyStore;\n\n"
            "public class DatabaseHelper {\n"
            "    public DatabaseHelper(Context context) {\n"
            "        // Retrieve password from Android KeyStore or secure config\n"
            "        String dbPassword = getSecurePassword(context);\n"
            "        SQLiteDatabase db = SQLiteDatabase.openOrCreateDatabase(\n"
            "            context.getDatabasePath(\"app.db\"), dbPassword, null);\n"
            "    }\n\n"
            "    private String getSecurePassword(Context context) {\n"
            "        KeyStore ks = KeyStore.getInstance(\"AndroidKeyStore\");\n"
            "        ks.load(null);\n"
            "        // Derive password from KeyStore-backed key\n"
            "        KeyStore.SecretKeyEntry entry =\n"
            "            (KeyStore.SecretKeyEntry) ks.getEntry(\"db_key\", null);\n"
            "        return Base64.encodeToString(\n"
            "            entry.getSecretKey().getEncoded(), Base64.NO_WRAP);\n"
            "    }\n"
            "}"
        ),
        "explanation": (
            "Never hardcode passwords or credentials in source code. "
            "Use Android KeyStore for key management or retrieve secrets from a "
            "secure server-side configuration at runtime."
        ),
        "difficulty": "moderate",
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2023-risks/m8-security-misconfiguration"
        ],
        "test_suggestion": "Grep decompiled APK for the old password literal - it should not appear in any class",
    },
    "CWE-502": {
        "vulnerability_type": "Deserialization of Untrusted Data",
        "current_code": (
            "InputStream is = socket.getInputStream();\n"
            "ObjectInputStream ois = new ObjectInputStream(is);\n"
            "UserProfile profile = (UserProfile) ois.readObject();"
        ),
        "fixed_code": (
            "import com.google.gson.Gson;\n"
            "import com.google.gson.JsonSyntaxException;\n\n"
            "BufferedReader reader = new BufferedReader(\n"
            "    new InputStreamReader(socket.getInputStream(),\n"
            "        StandardCharsets.UTF_8));\n"
            "String json = reader.readLine();\n"
            "if (json == null || json.length() > MAX_PAYLOAD_SIZE) {\n"
            "    throw new SecurityException(\"Invalid payload\");\n"
            "}\n"
            "Gson gson = new Gson();\n"
            "UserProfile profile = gson.fromJson(json, UserProfile.class);\n"
            "if (profile == null || !profile.isValid()) {\n"
            "    throw new SecurityException(\"Validation failed\");\n"
            "}"
        ),
        "explanation": (
            "Replace Java ObjectInputStream deserialization with a safe format "
            "like JSON (Gson/Moshi). Java deserialization can lead to remote code "
            "execution via gadget chains. Always validate parsed objects."
        ),
        "difficulty": "complex",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
            "07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests"
        ],
        "test_suggestion": (
            "Send a crafted serialized object with an unexpected class - deserialization should be rejected"
        ),
    },
    "CWE-862": {
        "vulnerability_type": "Missing Authorization",
        "current_code": (
            "@Override\n"
            "protected void doPost(HttpServletRequest req, HttpServletResponse resp) {\n"
            "    String userId = req.getParameter(\"user_id\");\n"
            "    userService.deleteAccount(userId);  // No auth check!\n"
            "    resp.setStatus(200);\n"
            "}"
        ),
        "fixed_code": (
            "@Override\n"
            "protected void doPost(HttpServletRequest req, HttpServletResponse resp) {\n"
            "    // Verify caller is authenticated\n"
            "    String callerToken = req.getHeader(\"Authorization\");\n"
            "    if (callerToken == null || !authManager.isValidToken(callerToken)) {\n"
            "        resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);\n"
            "        return;\n"
            "    }\n"
            "    // Verify caller is authorized for this action\n"
            "    String callerId = authManager.getUserId(callerToken);\n"
            "    String targetId = req.getParameter(\"user_id\");\n"
            "    if (!callerId.equals(targetId) && !authManager.isAdmin(callerId)) {\n"
            "        resp.sendError(HttpServletResponse.SC_FORBIDDEN);\n"
            "        return;\n"
            "    }\n"
            "    userService.deleteAccount(targetId);\n"
            "    resp.setStatus(200);\n"
            "}"
        ),
        "explanation": (
            "Every sensitive endpoint must verify both authentication (who is calling) "
            "and authorization (are they allowed). Enforce ownership checks - users "
            "should only modify their own resources unless they have admin privileges."
        ),
        "difficulty": "moderate",
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2023-risks/m3-insecure-authentication-authorization"
        ],
        "test_suggestion": "Call the endpoint with another user's token - should return 403 Forbidden",
    },
    "CWE-330": {
        "vulnerability_type": "Use of Insufficiently Random Values",
        "current_code": (
            "import java.util.Random;\n\n"
            "Random rng = new Random();\n"
            "String sessionId = String.valueOf(rng.nextLong());\n"
            "String otp = String.format(\"%06d\", rng.nextInt(1000000));"
        ),
        "fixed_code": (
            "import java.security.SecureRandom;\n\n"
            "SecureRandom rng = new SecureRandom();\n"
            "byte[] sessionBytes = new byte[32];\n"
            "rng.nextBytes(sessionBytes);\n"
            "String sessionId = Base64.encodeToString(sessionBytes, Base64.URL_SAFE | Base64.NO_WRAP);\n"
            "String otp = String.format(\"%06d\", rng.nextInt(1000000));"
        ),
        "explanation": (
            "java.util.Random is a linear congruential generator with predictable output. "
            "Use java.security.SecureRandom for any security-sensitive randomness "
            "(session tokens, OTPs, cryptographic nonces)."
        ),
        "difficulty": "easy",
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography"
        ],
        "test_suggestion": "Generate 1000 tokens and verify no duplicates; confirm SecureRandom provider in use",
    },
    "CWE-94": {
        "vulnerability_type": "Improper Control of Generation of Code (Code Injection)",
        "current_code": (
            "// Loading DEX from external storage - attacker can replace the file\n"
            "String dexPath = Environment.getExternalStorageDirectory()\n"
            "    + \"/plugins/module.dex\";\n"
            "DexClassLoader loader = new DexClassLoader(\n"
            "    dexPath, getCacheDir().getPath(), null, getClassLoader());\n"
            "Class<?> cls = loader.loadClass(\"com.plugin.Entry\");"
        ),
        "fixed_code": (
            "import java.security.MessageDigest;\n\n"
            "// Only load DEX from app-private storage after signature verification\n"
            "File dexFile = new File(getFilesDir(), \"plugins/module.dex\");\n"
            "if (!dexFile.exists()) {\n"
            "    throw new SecurityException(\"Plugin not found\");\n"
            "}\n"
            "// Verify file integrity before loading\n"
            "byte[] fileHash = computeSha256(dexFile);\n"
            "if (!MessageDigest.isEqual(fileHash, EXPECTED_PLUGIN_HASH)) {\n"
            "    throw new SecurityException(\"Plugin signature mismatch\");\n"
            "}\n"
            "DexClassLoader loader = new DexClassLoader(\n"
            "    dexFile.getAbsolutePath(), getCodeCacheDir().getPath(),\n"
            "    null, getClassLoader());\n"
            "Class<?> cls = loader.loadClass(\"com.plugin.Entry\");"
        ),
        "explanation": (
            "Never load code (DEX, JAR, SO) from external storage or untrusted sources. "
            "Store plugins in app-private directories and verify their SHA-256 hash "
            "against a known-good digest before loading."
        ),
        "difficulty": "complex",
        "references": [
            "https://developer.android.com/privacy-and-security/risks/unsafe-dynamic-code-loading"
        ],
        "test_suggestion": "Replace the plugin DEX with a tampered copy - loading should fail with signature mismatch",
    },
    "CWE-22": {
        "vulnerability_type": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
        "current_code": (
            "String filename = request.getParameter(\"file\");\n"
            "File target = new File(getFilesDir(), filename);\n"
            "FileInputStream fis = new FileInputStream(target);\n"
            "// Attacker sends file=../../shared_prefs/secrets.xml"
        ),
        "fixed_code": (
            "String filename = request.getParameter(\"file\");\n"
            "File baseDir = getFilesDir();\n"
            "File target = new File(baseDir, filename).getCanonicalFile();\n\n"
            "// Validate resolved path is within the allowed directory\n"
            "if (!target.getPath().startsWith(baseDir.getCanonicalPath() + File.separator)) {\n"
            "    throw new SecurityException(\"Path traversal attempt blocked\");\n"
            "}\n"
            "if (!target.exists()) {\n"
            "    throw new FileNotFoundException(\"File not found\");\n"
            "}\n"
            "FileInputStream fis = new FileInputStream(target);"
        ),
        "explanation": (
            "Always canonicalize user-supplied file paths with getCanonicalFile() and "
            "verify the resolved path stays within the intended base directory. "
            "Reject any path containing '..' sequences after canonicalization."
        ),
        "difficulty": "moderate",
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal"
        ],
        "test_suggestion": "Request file=../../etc/passwd - should be rejected with SecurityException",
    },
    "CWE-693": {
        "vulnerability_type": "Protection Mechanism Failure",
        "current_code": (
            "public class RootCheck {\n"
            "    public static boolean isRooted() {\n"
            "        // Easily bypassed single check\n"
            "        return new File(\"/system/app/Superuser.apk\").exists();\n"
            "    }\n"
            "}"
        ),
        "fixed_code": (
            "public class RootCheck {\n"
            "    public static boolean isRooted() {\n"
            "        return checkSuBinary() || checkSuperuserApk()\n"
            "            || checkMagisk() || checkBusybox()\n"
            "            || checkRWSystem() || checkDangerousProps();\n"
            "    }\n\n"
            "    private static boolean checkSuBinary() {\n"
            "        String[] paths = {\"/system/bin/su\", \"/system/xbin/su\",\n"
            "            \"/sbin/su\", \"/data/local/xbin/su\"};\n"
            "        for (String path : paths) {\n"
            "            if (new File(path).exists()) return true;\n"
            "        }\n"
            "        return false;\n"
            "    }\n\n"
            "    private static boolean checkSuperuserApk() {\n"
            "        return new File(\"/system/app/Superuser.apk\").exists();\n"
            "    }\n\n"
            "    private static boolean checkMagisk() {\n"
            "        return new File(\"/sbin/.magisk\").exists()\n"
            "            || new File(\"/data/adb/magisk\").exists();\n"
            "    }\n\n"
            "    private static boolean checkBusybox() {\n"
            "        return new File(\"/system/xbin/busybox\").exists();\n"
            "    }\n\n"
            "    private static boolean checkRWSystem() {\n"
            "        // Check if /system is mounted read-write\n"
            "        try {\n"
            "            Process p = Runtime.getRuntime().exec(\"mount\");\n"
            "            BufferedReader br = new BufferedReader(\n"
            "                new InputStreamReader(p.getInputStream()));\n"
            "            String line;\n"
            "            while ((line = br.readLine()) != null) {\n"
            "                if (line.contains(\"/system\") && line.contains(\"rw\")) {\n"
            "                    return true;\n"
            "                }\n"
            "            }\n"
            "        } catch (Exception ignored) {}\n"
            "        return false;\n"
            "    }\n\n"
            "    private static boolean checkDangerousProps() {\n"
            "        try {\n"
            "            String prop = System.getProperty(\"ro.debuggable\");\n"
            "            return \"1\".equals(prop);\n"
            "        } catch (Exception ignored) {}\n"
            "        return false;\n"
            "    }\n"
            "}"
        ),
        "explanation": (
            "A single root detection check is trivially bypassed with Frida or Xposed. "
            "Implement multiple orthogonal checks (su binary, Magisk, busybox, "
            "RW /system, dangerous properties) so attackers must patch all of them."
        ),
        "difficulty": "moderate",
        "references": [
            "https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0004/"
        ],
        "test_suggestion": "Run on a rooted device with Magisk - all individual checks should trigger",
    },
    "CWE-79": {
        "vulnerability_type": "Cross-site Scripting (XSS) in WebView",
        "current_code": (
            "String userInput = getIntent().getStringExtra(\"url\");\n"
            "webView.getSettings().setJavaScriptEnabled(true);\n"
            "webView.loadUrl(userInput);  // Attacker sends javascript:alert(1)"
        ),
        "fixed_code": (
            "String userInput = getIntent().getStringExtra(\"url\");\n\n"
            "// Validate URL scheme - only allow https\n"
            "Uri uri = Uri.parse(userInput);\n"
            "if (uri == null || !\"https\".equals(uri.getScheme())) {\n"
            "    Log.w(TAG, \"Blocked non-HTTPS URL: \" + userInput);\n"
            "    return;\n"
            "}\n\n"
            "// Allowlist trusted domains\n"
            "String host = uri.getHost();\n"
            "if (host == null || !ALLOWED_HOSTS.contains(host)) {\n"
            "    Log.w(TAG, \"Blocked untrusted host: \" + host);\n"
            "    return;\n"
            "}\n\n"
            "webView.getSettings().setJavaScriptEnabled(true);\n"
            "// Add Content Security Policy via WebViewClient\n"
            "webView.setWebViewClient(new WebViewClient() {\n"
            "    @Override\n"
            "    public void onPageFinished(WebView view, String url) {\n"
            "        view.evaluateJavascript(\n"
            "            \"var meta=document.createElement('meta');\"\n"
            "            + \"meta.httpEquiv='Content-Security-Policy';\"\n"
            "            + \"meta.content=\\\"default-src 'self' https:;\\\";\"\n"
            "            + \"document.head.appendChild(meta);\",\n"
            "            null);\n"
            "    }\n"
            "});\n"
            "webView.loadUrl(uri.toString());"
        ),
        "explanation": (
            "Never pass unsanitized user input to WebView.loadUrl(). Validate the URL "
            "scheme (reject javascript:, data:, file:), enforce an HTTPS-only allowlist "
            "of trusted domains, and inject a Content Security Policy to limit script execution."
        ),
        "difficulty": "moderate",
        "references": [
            "https://developer.android.com/develop/ui/views/layout/webapps/best-practices"
        ],
        "test_suggestion": "Pass javascript:alert(document.cookie) as URL - should be blocked before loadUrl",
    },
    # --- Additional templates (Item 9 expansion) ---
    "CWE-250": {
        "vulnerability_type": "Unnecessary Privileges",
        "current_code": '<uses-permission android:name="android.permission.READ_CONTACTS" />',
        "fixed_code": (
            "<!-- Remove unnecessary permissions from AndroidManifest.xml -->\n"
            "<!-- Only keep permissions actually used by the app -->\n"
            '<!-- <uses-permission android:name="android.permission.READ_CONTACTS" /> -->'
        ),
        "explanation": (
            "Remove permissions that are not required for core app functionality. "
            "Each unnecessary permission expands the attack surface and violates "
            "the principle of least privilege."
        ),
        "difficulty": "easy",
        "references": ["https://developer.android.com/training/permissions/requesting"],
        "test_suggestion": "Verify app functions correctly after removing the permission",
    },
    "CWE-284": {
        "vulnerability_type": "Improper Access Control",
        "current_code": (
            '// No permission check before sensitive operation\n'
            'public void performAdminAction() {\n'
            '    deleteAllData();\n'
            '}'
        ),
        "fixed_code": (
            'public void performAdminAction() {\n'
            '    if (!SecurityManager.hasRole(currentUser, "admin")) {\n'
            '        throw new SecurityException("Admin role required");\n'
            '    }\n'
            '    deleteAllData();\n'
            '}'
        ),
        "explanation": (
            "Enforce access control checks before sensitive operations. Verify "
            "caller identity and role/permission before executing privileged actions."
        ),
        "difficulty": "moderate",
        "references": ["https://cwe.mitre.org/data/definitions/284.html"],
        "test_suggestion": "Call sensitive method without required role - should throw SecurityException",
    },
    "CWE-326": {
        "vulnerability_type": "Inadequate Encryption Strength",
        "current_code": (
            'KeyGenerator keyGen = KeyGenerator.getInstance("AES");\n'
            'keyGen.init(64); // Weak key size'
        ),
        "fixed_code": (
            'KeyGenerator keyGen = KeyGenerator.getInstance("AES");\n'
            'keyGen.init(256); // Strong key size (AES-256)'
        ),
        "explanation": (
            "Use AES-256 for symmetric encryption. Key sizes below 128 bits are "
            "considered weak. For RSA, use at least 2048 bits."
        ),
        "difficulty": "easy",
        "references": ["https://developer.android.com/privacy-and-security/cryptography"],
        "test_suggestion": "Verify generated key length is 256 bits",
    },
    "CWE-329": {
        "vulnerability_type": "Not Using an Unpredictable IV with CBC Mode",
        "current_code": (
            'byte[] iv = new byte[16]; // All zeros IV\n'
            'IvParameterSpec ivSpec = new IvParameterSpec(iv);\n'
            'cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);'
        ),
        "fixed_code": (
            'SecureRandom random = new SecureRandom();\n'
            'byte[] iv = new byte[12]; // 12-byte IV for GCM\n'
            'random.nextBytes(iv);\n'
            'GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);\n'
            'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\n'
            'cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);'
        ),
        "explanation": (
            "Always use a unique, random IV for each encryption operation. Prefer "
            "AES/GCM over AES/CBC as GCM provides both confidentiality and integrity. "
            "Never reuse IVs with the same key."
        ),
        "difficulty": "moderate",
        "references": ["https://cwe.mitre.org/data/definitions/329.html"],
        "test_suggestion": "Encrypt same plaintext twice - ciphertexts must differ (different IVs)",
    },
    "CWE-338": {
        "vulnerability_type": "Use of Cryptographically Weak PRNG",
        "current_code": 'int token = new java.util.Random().nextInt();',
        "fixed_code": (
            'import java.security.SecureRandom;\n'
            'SecureRandom secureRandom = new SecureRandom();\n'
            'byte[] token = new byte[32];\n'
            'secureRandom.nextBytes(token);'
        ),
        "explanation": (
            "java.util.Random is predictable and must not be used for security-sensitive "
            "values. Use java.security.SecureRandom for tokens, keys, nonces, and session IDs."
        ),
        "difficulty": "easy",
        "references": ["https://cwe.mitre.org/data/definitions/338.html"],
        "test_suggestion": "Generate 1000 tokens and verify no collisions; check entropy",
    },
    "CWE-352": {
        "vulnerability_type": "Cross-Site Request Forgery (CSRF)",
        "current_code": (
            '// Deep link handler without origin validation\n'
            '@Override\n'
            'public void onCreate(Bundle savedInstanceState) {\n'
            '    Uri data = getIntent().getData();\n'
            '    processAction(data.getQueryParameter("action"));\n'
            '}'
        ),
        "fixed_code": (
            '@Override\n'
            'public void onCreate(Bundle savedInstanceState) {\n'
            '    Uri data = getIntent().getData();\n'
            '    if (data == null) return;\n'
            '    // Validate referrer/origin\n'
            '    String referrer = getReferrer() != null ? getReferrer().getHost() : "";\n'
            '    if (!TRUSTED_ORIGINS.contains(referrer)) {\n'
            '        Log.w(TAG, "Blocked deep link from untrusted origin: " + referrer);\n'
            '        return;\n'
            '    }\n'
            '    // Validate CSRF token from deep link\n'
            '    String csrfToken = data.getQueryParameter("csrf_token");\n'
            '    if (!CsrfValidator.isValid(csrfToken)) return;\n'
            '    processAction(data.getQueryParameter("action"));\n'
            '}'
        ),
        "explanation": (
            "Deep links and intent handlers that perform state-changing operations "
            "must validate the caller's origin and include CSRF tokens to prevent "
            "cross-app request forgery attacks."
        ),
        "difficulty": "moderate",
        "references": ["https://cwe.mitre.org/data/definitions/352.html"],
        "test_suggestion": "Send deep link intent from untrusted app - action should be blocked",
    },
    "CWE-379": {
        "vulnerability_type": "Creation of Temporary File in Directory with Insecure Permissions",
        "current_code": (
            'File tempFile = new File("/sdcard/temp_data.txt");\n'
            'FileWriter writer = new FileWriter(tempFile);'
        ),
        "fixed_code": (
            '// Use app-private internal storage\n'
            'File tempFile = File.createTempFile("data_", ".tmp", getCacheDir());\n'
            'tempFile.deleteOnExit();\n'
            'try (FileWriter writer = new FileWriter(tempFile)) {\n'
            '    writer.write(data);\n'
            '}'
        ),
        "explanation": (
            "Never write temporary files to external storage (world-readable). "
            "Use getCacheDir() or getFilesDir() for app-private temporary files "
            "and call deleteOnExit() or explicit cleanup."
        ),
        "difficulty": "easy",
        "references": ["https://developer.android.com/training/data-storage/app-specific"],
        "test_suggestion": "Verify temp file is created in app-private directory, not /sdcard/",
    },
    "CWE-384": {
        "vulnerability_type": "Session Fixation",
        "current_code": (
            '// Reusing session ID after authentication\n'
            'public void onLoginSuccess(User user) {\n'
            '    session.setAttribute("user", user);\n'
            '    // Session ID not regenerated!\n'
            '}'
        ),
        "fixed_code": (
            'public void onLoginSuccess(User user) {\n'
            '    // Invalidate old session and create new one\n'
            '    String oldSessionId = session.getId();\n'
            '    session.invalidate();\n'
            '    HttpSession newSession = request.getSession(true);\n'
            '    newSession.setAttribute("user", user);\n'
            '    Log.d(TAG, "Session regenerated on login");\n'
            '}'
        ),
        "explanation": (
            "Always regenerate the session ID after successful authentication. "
            "Invalidate the old session to prevent session fixation attacks where "
            "an attacker pre-sets the session ID."
        ),
        "difficulty": "easy",
        "references": ["https://cwe.mitre.org/data/definitions/384.html"],
        "test_suggestion": "Compare session ID before and after login - must be different",
    },
    "CWE-489": {
        "vulnerability_type": "Active Debug Code / Debuggable Application",
        "current_code": 'android:debuggable="true"',
        "fixed_code": (
            '<!-- Remove or set to false in release builds -->\n'
            'android:debuggable="false"\n'
            '<!-- Better: let build system control this via buildTypes -->\n'
            '<!-- debuggable is automatically false for release builds in Gradle -->'
        ),
        "explanation": (
            "android:debuggable=\"true\" allows debugger attachment, memory inspection, "
            "and bypassing security controls. Ensure this is false in release builds. "
            "Gradle sets this automatically - remove the manual override."
        ),
        "difficulty": "easy",
        "references": ["https://developer.android.com/studio/publish/preparing"],
        "test_suggestion": "Check ApplicationInfo.FLAG_DEBUGGABLE is not set in release APK",
    },
    "CWE-522": {
        "vulnerability_type": "Insufficiently Protected Credentials",
        "current_code": (
            'SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);\n'
            'prefs.edit().putString("password", password).apply();'
        ),
        "fixed_code": (
            'import androidx.security.crypto.EncryptedSharedPreferences;\n'
            'import androidx.security.crypto.MasterKey;\n\n'
            'MasterKey masterKey = new MasterKey.Builder(context)\n'
            '    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)\n'
            '    .build();\n'
            'SharedPreferences prefs = EncryptedSharedPreferences.create(\n'
            '    context, "auth_secure", masterKey,\n'
            '    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,\n'
            '    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM\n'
            ');\n'
            '// Store password hash, never plaintext\n'
            'String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());\n'
            'prefs.edit().putString("password_hash", hashedPassword).apply();'
        ),
        "explanation": (
            "Never store passwords in plaintext. Use EncryptedSharedPreferences for "
            "storage and bcrypt/scrypt/Argon2 for hashing. Consider using Android "
            "Keystore for credential management."
        ),
        "difficulty": "moderate",
        "references": ["https://developer.android.com/topic/security/data"],
        "test_suggestion": "Read stored credential from SharedPreferences - must not be plaintext",
    },
    "CWE-732": {
        "vulnerability_type": "Incorrect Permission Assignment for Critical Resource",
        "current_code": (
            'FileOutputStream fos = openFileOutput("secrets.txt", MODE_WORLD_READABLE);'
        ),
        "fixed_code": (
            '// Use MODE_PRIVATE - only this app can access\n'
            'FileOutputStream fos = openFileOutput("secrets.txt", MODE_PRIVATE);'
        ),
        "explanation": (
            "Never use MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE for file creation. "
            "Use MODE_PRIVATE to restrict access to the creating app. For sharing data "
            "with other apps, use a FileProvider with explicit permissions."
        ),
        "difficulty": "easy",
        "references": ["https://developer.android.com/training/data-storage/app-specific"],
        "test_suggestion": "Verify file permissions are 0600 (owner read/write only)",
    },
    "CWE-918": {
        "vulnerability_type": "Server-Side Request Forgery (SSRF)",
        "current_code": (
            '// User-controlled URL passed directly to HTTP client\n'
            'String url = intent.getStringExtra("target_url");\n'
            'OkHttpClient client = new OkHttpClient();\n'
            'Request request = new Request.Builder().url(url).build();\n'
            'Response response = client.newCall(request).execute();'
        ),
        "fixed_code": (
            'String url = intent.getStringExtra("target_url");\n'
            '// Validate URL against allowlist\n'
            'Uri parsed = Uri.parse(url);\n'
            'if (!"https".equals(parsed.getScheme())) {\n'
            '    throw new SecurityException("Only HTTPS URLs allowed");\n'
            '}\n'
            'if (!ALLOWED_HOSTS.contains(parsed.getHost())) {\n'
            '    throw new SecurityException("Host not in allowlist: " + parsed.getHost());\n'
            '}\n'
            '// Block internal/private IPs\n'
            'InetAddress addr = InetAddress.getByName(parsed.getHost());\n'
            'if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()) {\n'
            '    throw new SecurityException("Internal addresses blocked");\n'
            '}\n'
            'OkHttpClient client = new OkHttpClient();\n'
            'Request request = new Request.Builder().url(url).build();\n'
            'Response response = client.newCall(request).execute();'
        ),
        "explanation": (
            "Validate and restrict user-supplied URLs before making HTTP requests. "
            "Enforce HTTPS-only, use a hostname allowlist, and block internal/private "
            "IP addresses to prevent SSRF attacks."
        ),
        "difficulty": "moderate",
        "references": ["https://cwe.mitre.org/data/definitions/918.html"],
        "test_suggestion": "Pass http://127.0.0.1/ and http://169.254.169.254/ - both should be blocked",
    },
    "CWE-939": {
        "vulnerability_type": "Improper Authorization in Handler for Custom URL Scheme",
        "current_code": (
            '<!-- Deep link handler with no verification -->\n'
            '<intent-filter>\n'
            '    <action android:name="android.intent.action.VIEW" />\n'
            '    <data android:scheme="myapp" android:host="transfer" />\n'
            '</intent-filter>'
        ),
        "fixed_code": (
            '<!-- Use Android App Links with Digital Asset Links verification -->\n'
            '<intent-filter android:autoVerify="true">\n'
            '    <action android:name="android.intent.action.VIEW" />\n'
            '    <category android:name="android.intent.category.DEFAULT" />\n'
            '    <category android:name="android.intent.category.BROWSABLE" />\n'
            '    <data android:scheme="https" android:host="myapp.example.com"\n'
            '          android:pathPrefix="/transfer" />\n'
            '</intent-filter>\n'
            '<!-- Verify in handler: -->\n'
            '// Validate caller and require authentication\n'
            'if (!isUserAuthenticated()) {\n'
            '    startActivity(new Intent(this, LoginActivity.class));\n'
            '    return;\n'
            '}'
        ),
        "explanation": (
            "Custom URL schemes (myapp://) can be invoked by any app. Use Android App "
            "Links (https:// with autoVerify) instead, and always validate the user is "
            "authenticated before processing deep link actions."
        ),
        "difficulty": "moderate",
        "references": ["https://developer.android.com/training/app-links/verify-android-applinks"],
        "test_suggestion": "Invoke deep link without authentication - should redirect to login",
    },
    "CWE-1104": {
        "vulnerability_type": "Use of Unmaintained Third-Party Components",
        "current_code": (
            "// build.gradle\n"
            "implementation 'com.squareup.okhttp3:okhttp:3.14.9' // End-of-life version"
        ),
        "fixed_code": (
            "// build.gradle - update to latest maintained version\n"
            "implementation 'com.squareup.okhttp3:okhttp:4.12.0'\n"
            "// Run: ./gradlew dependencyUpdates to find outdated deps"
        ),
        "explanation": (
            "Third-party libraries with known vulnerabilities or no active maintenance "
            "pose a supply chain risk. Update to the latest stable version and monitor "
            "for CVEs using tools like OWASP Dependency-Check or Snyk."
        ),
        "difficulty": "easy",
        "references": ["https://owasp.org/www-project-dependency-check/"],
        "test_suggestion": "Run dependency vulnerability scan - no CRITICAL CVEs in direct dependencies",
    },
    "CWE-78": {
        "vulnerability_type": "OS Command Injection",
        "current_code": (
            'Runtime.getRuntime().exec("ping " + userInput);'
        ),
        "fixed_code": (
            '// Use ProcessBuilder with explicit argument list (no shell interpolation)\n'
            'ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", sanitizedHost);\n'
            'pb.redirectErrorStream(true);\n'
            'Process p = pb.start();'
        ),
        "explanation": (
            "Never pass user input to Runtime.exec() or ProcessBuilder via a single "
            "shell command string. Use argument arrays to prevent shell metacharacter injection."
        ),
        "difficulty": "moderate",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
        "test_suggestion": "Pass input with shell metacharacters (;, |, &&) - should not execute injected commands",
    },
    "CWE-611": {
        "vulnerability_type": "XML External Entity (XXE) Injection",
        "current_code": (
            'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n'
            'DocumentBuilder db = dbf.newDocumentBuilder();\n'
            'Document doc = db.parse(xmlInput);'
        ),
        "fixed_code": (
            'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n'
            'dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
            'dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);\n'
            'dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);\n'
            'DocumentBuilder db = dbf.newDocumentBuilder();\n'
            'Document doc = db.parse(xmlInput);'
        ),
        "explanation": (
            "Disable external entity processing in XML parsers to prevent XXE attacks "
            "that can read local files, perform SSRF, or cause denial of service."
        ),
        "difficulty": "easy",
        "references": ["https://cwe.mitre.org/data/definitions/611.html"],
        "test_suggestion": "Parse XML with DOCTYPE containing external entity - should reject or ignore",
    },
    "CWE-297": {
        "vulnerability_type": "Improper Validation of Certificate with Host Mismatch",
        "current_code": (
            'HostnameVerifier allHostsValid = (hostname, session) -> true;\n'
            'HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);'
        ),
        "fixed_code": (
            '// Use the default HostnameVerifier - it validates hostname against certificate\n'
            '// If custom pinning is needed, use OkHttp CertificatePinner:\n'
            'CertificatePinner pinner = new CertificatePinner.Builder()\n'
            '    .add("api.example.com", "sha256/AAAA...")\n'
            '    .build();'
        ),
        "explanation": (
            "Never override HostnameVerifier to accept all hosts. This disables TLS "
            "hostname validation, allowing man-in-the-middle attacks."
        ),
        "difficulty": "easy",
        "references": ["https://cwe.mitre.org/data/definitions/297.html"],
        "test_suggestion": "Connect to server with mismatched certificate - should fail with SSLHandshakeException",
    },
    "CWE-757": {
        "vulnerability_type": "Selection of Less-Secure Algorithm During Negotiation",
        "current_code": (
            'SSLContext sslContext = SSLContext.getInstance("TLSv1");\n'
            'sslContext.init(null, null, null);'
        ),
        "fixed_code": (
            'SSLContext sslContext = SSLContext.getInstance("TLSv1.3");\n'
            'sslContext.init(null, null, null);\n'
            '// Or use OkHttp which defaults to TLS 1.2+:\n'
            '// ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS).build();'
        ),
        "explanation": (
            "Use TLS 1.2 or 1.3 - never TLS 1.0 or 1.1 which have known vulnerabilities "
            "(BEAST, POODLE). Android 10+ disables TLS 1.0/1.1 by default."
        ),
        "difficulty": "easy",
        "references": ["https://cwe.mitre.org/data/definitions/757.html"],
        "test_suggestion": "Attempt TLS 1.0 connection - should fail or warn",
    },
    "CWE-919": {
        "vulnerability_type": "Weaknesses in Mobile Applications",
        "current_code": (
            '// Sensitive data stored in app sandbox without encryption\n'
            'File sensitiveFile = new File(getFilesDir(), "user_data.json");\n'
            'FileWriter fw = new FileWriter(sensitiveFile);'
        ),
        "fixed_code": (
            'import androidx.security.crypto.EncryptedFile;\n'
            'import androidx.security.crypto.MasterKey;\n\n'
            'MasterKey masterKey = new MasterKey.Builder(context)\n'
            '    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)\n'
            '    .build();\n'
            'EncryptedFile encryptedFile = new EncryptedFile.Builder(context,\n'
            '    new File(getFilesDir(), "user_data.json"),\n'
            '    masterKey, EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB)\n'
            '    .build();'
        ),
        "explanation": (
            "Use AndroidX Security Crypto (EncryptedFile, EncryptedSharedPreferences) "
            "for sensitive data at rest. The app sandbox is not sufficient protection "
            "on rooted devices or via backup extraction."
        ),
        "difficulty": "moderate",
        "references": ["https://cwe.mitre.org/data/definitions/919.html"],
        "test_suggestion": "Read stored file on rooted device - should be encrypted, not plaintext",
    },
    "CWE-942": {
        "vulnerability_type": "Permissive Cross-domain Policy with Untrusted Domains",
        "current_code": (
            'webView.getSettings().setAllowUniversalAccessFromFileURLs(true);\n'
            'webView.getSettings().setAllowFileAccessFromFileURLs(true);'
        ),
        "fixed_code": (
            'webView.getSettings().setAllowUniversalAccessFromFileURLs(false);\n'
            'webView.getSettings().setAllowFileAccessFromFileURLs(false);\n'
            'webView.getSettings().setAllowFileAccess(false); // Disable file:// entirely\n'
            '// Load content via https:// only'
        ),
        "explanation": (
            "Disable universal file access in WebView to prevent cross-origin attacks "
            "where a malicious page loaded in the WebView reads local files or other "
            "origins' data."
        ),
        "difficulty": "easy",
        "references": ["https://cwe.mitre.org/data/definitions/942.html"],
        "test_suggestion": "Load file:// URL in WebView - should be blocked",
    },
}

# Map common titles to CWE IDs for matching
_TITLE_TO_CWE: Dict[str, str] = {
    "insecure storage": "CWE-312",
    "cleartext storage": "CWE-312",
    "sql injection": "CWE-89",
    "weak crypto": "CWE-327",
    "broken cryptography": "CWE-327",
    "exported activity": "CWE-926",
    "exported service": "CWE-926",
    "exported receiver": "CWE-926",
    "exported provider": "CWE-926",
    "certificate validation": "CWE-295",
    "certificate pinning": "CWE-295",
    "hardcoded key": "CWE-321",
    "hardcoded secret": "CWE-321",
    "hardcoded credential": "CWE-321",
    "webview": "CWE-749",
    "javascript interface": "CWE-749",
    "sensitive log": "CWE-532",
    "logging": "CWE-532",
    "cleartext traffic": "CWE-319",
    "cleartext http": "CWE-319",
    "information disclosure": "CWE-200",
    "information exposure": "CWE-200",
    "hardcoded password": "CWE-798",
    "deserialization": "CWE-502",
    "missing authorization": "CWE-862",
    "missing authentication": "CWE-862",
    "insecure random": "CWE-330",
    "weak random": "CWE-330",
    "code injection": "CWE-94",
    "dynamic code": "CWE-94",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "root detection": "CWE-693",
    "tampering": "CWE-693",
    "cross-site scripting": "CWE-79",
    "xss": "CWE-79",
    # New mappings (Item 9 expansion)
    "unnecessary permission": "CWE-250",
    "excessive permission": "CWE-250",
    "access control": "CWE-284",
    "improper access": "CWE-284",
    "weak key": "CWE-326",
    "key size": "CWE-326",
    "static iv": "CWE-329",
    "predictable iv": "CWE-329",
    "weak prng": "CWE-338",
    "predictable random": "CWE-338",
    "csrf": "CWE-352",
    "request forgery": "CWE-352",
    "temp file": "CWE-379",
    "temporary file": "CWE-379",
    "session fixation": "CWE-384",
    "debuggable": "CWE-489",
    "debug mode": "CWE-489",
    "credential storage": "CWE-522",
    "world readable": "CWE-732",
    "world writable": "CWE-732",
    "ssrf": "CWE-918",
    "server-side request": "CWE-918",
    "custom url scheme": "CWE-939",
    "deep link": "CWE-939",
    "unmaintained": "CWE-1104",
    "outdated library": "CWE-1104",
    "outdated dependency": "CWE-1104",
}


# ---------------------------------------------------------------------------
# Remediation logic
# ---------------------------------------------------------------------------


def _match_cwe(finding: Dict[str, Any]) -> str:
    """Try to match a finding to a CWE template key."""
    # Direct CWE match
    cwe_id = finding.get("cwe_id", "") or finding.get("cwe", "")
    if cwe_id and cwe_id in _CWE_FIX_TEMPLATES:
        return cwe_id

    # Normalize CWE format (e.g., "CWE-89" from "89")
    if cwe_id:
        normalized = cwe_id if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}"
        if normalized in _CWE_FIX_TEMPLATES:
            return normalized

    # Title-based matching
    title = (finding.get("title", "") or "").lower()
    for pattern, cwe in _TITLE_TO_CWE.items():
        if pattern in title:
            return cwe

    return ""


def _remediate_finding(finding: Dict[str, Any]) -> FindingRemediation:
    """Generate a remediation for a single finding using templates."""
    title = finding.get("title", "Unknown Finding")
    cwe_id = _match_cwe(finding)

    if cwe_id and cwe_id in _CWE_FIX_TEMPLATES:
        template = _CWE_FIX_TEMPLATES[cwe_id]
        return FindingRemediation(
            finding_title=title,
            vulnerability_type=template["vulnerability_type"],
            cwe_id=cwe_id,
            current_code=template["current_code"],
            fixed_code=template["fixed_code"],
            explanation=template["explanation"],
            difficulty=template["difficulty"],
            breaking_changes="",
            references=template["references"],
            test_suggestion=template["test_suggestion"],
        )

    # No template match - provide generic guidance with severity-based effort
    severity = (finding.get("severity", "") or "MEDIUM").upper()
    if severity in ("CRITICAL", "HIGH"):
        difficulty = "complex"
    elif severity in ("LOW", "INFO"):
        difficulty = "easy"
    else:
        difficulty = "moderate"
    return FindingRemediation(
        finding_title=title,
        vulnerability_type=finding.get("vulnerability_type", ""),
        cwe_id=finding.get("cwe_id", "") or finding.get("cwe", ""),
        current_code="",
        fixed_code="",
        explanation=f"No automated fix template available for this finding. "
        f"Manual code review recommended for {severity} severity issue.",
        difficulty=difficulty,
        breaking_changes="",
        references=[],
        test_suggestion="Manually verify the finding and apply appropriate fix.",
    )


def _assess_overall_effort(remediations: List[FindingRemediation]) -> str:
    """Compute overall effort from individual remediation difficulties."""
    if not remediations:
        return "easy"
    difficulty_scores = {"easy": 1, "moderate": 2, "complex": 3}
    total = sum(difficulty_scores.get(r.difficulty, 2) for r in remediations)
    avg = total / len(remediations)
    if avg <= 1.3:
        return "easy"
    if avg <= 2.3:
        return "moderate"
    return "complex"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_heuristic_remediation(
    report_file: str,
    report_dir: str = "reports",
) -> RemediationResult:
    """Run rule-based remediation without an LLM.

    Reads the scan report JSON, matches findings to CWE fix templates,
    and generates before/after code snippets.

    Args:
        report_file: Path to the JSON scan report.
        report_dir: Directory containing report files (unused but kept for
            API compatibility with run_remediation).

    Returns:
        RemediationResult with code patches and difficulty estimates.
    """
    logger.info("heuristic_remediation_start", report_file=report_file)

    rp = Path(report_file)
    if not rp.exists():
        logger.warning("heuristic_remediation_report_not_found", path=report_file)
        return RemediationResult(
            summary=f"Report file not found: {report_file}",
            method="heuristic",
        )

    try:
        with open(rp, "r") as f:
            report_data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("heuristic_remediation_read_error", path=report_file, error=str(e))
        return RemediationResult(
            summary=f"Failed to read report: {e}",
            method="heuristic",
        )

    # Extract findings from report
    findings = report_data.get("vulnerabilities", report_data.get("findings", []))
    if not findings:
        return RemediationResult(
            summary="No findings to remediate",
            total_findings=0,
            total_with_patches=0,
            method="heuristic",
        )

    # Focus on HIGH+ findings first, then MEDIUM
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_order.get((f.get("severity", "") or "MEDIUM").upper(), 3),
    )

    remediations = [_remediate_finding(f) for f in sorted_findings]
    with_patches = [r for r in remediations if r.fixed_code]

    overall_effort = _assess_overall_effort(remediations)

    summary_parts = [
        f"Heuristic remediation for {len(findings)} findings:",
        f"  {len(with_patches)} with automated fix templates",
        f"  {len(remediations) - len(with_patches)} requiring manual review",
        f"  Overall effort: {overall_effort}",
        "",
        "Note: This remediation was generated using rule-based templates "
        "(no LLM). Code patches are generic and should be adapted to your "
        "specific codebase.",
    ]

    result = RemediationResult(
        remediations=remediations,
        summary="\n".join(summary_parts),
        total_findings=len(findings),
        total_with_patches=len(with_patches),
        overall_effort=overall_effort,
        method="heuristic",
    )

    # Save to report
    save_remediation_to_report(result, report_file)

    logger.info(
        "heuristic_remediation_complete",
        findings=len(findings),
        with_patches=len(with_patches),
    )
    return result
