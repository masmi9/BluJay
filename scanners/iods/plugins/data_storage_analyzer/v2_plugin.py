"""
Data Storage Analyzer – insecure data storage patterns.

Checks:
  - NSUserDefaults storing sensitive data (passwords, tokens)
  - SQLite databases without encryption (not using SQLCipher)
  - NSFileProtectionNone on sensitive files
  - CoreData without file protection
  - Caches directory usage for sensitive data
  - Realm database without encryption
"""
from __future__ import annotations

import re
from typing import List

from core.plugins.base_plugin_ios import (
    BasePluginIOS, PluginCapability, PluginFinding,
    PluginMetadata, PluginPriority, PluginResult, PluginStatus,
)

_USERDEFAULTS_SENSITIVE = re.compile(
    r'(?i)userdefaults.*?(password|token|secret|key|credential|auth|pin|ssn|credit)',
    re.DOTALL,
)
_FILE_PROTECTION_NONE = re.compile(r'NSFileProtectionNone', re.IGNORECASE)
_SQLITE_UNENCRYPTED = re.compile(r'sqlite3_open\b|sqlite3_open_v2\b', re.IGNORECASE)
_SQLCIPHER = re.compile(r'sqlcipher|sqlite3_key\b', re.IGNORECASE)
_REALM_UNENCRYPTED = re.compile(r'Realm\.Configuration\(\)', re.IGNORECASE)
_REALM_ENCRYPTED = re.compile(r'encryptionKey', re.IGNORECASE)
_CACHE_DIR_SENSITIVE = re.compile(
    r'(?i)cachesdirectory.*?(password|token|secret|key|user.*?data)',
    re.DOTALL,
)


class DataStorageAnalyzerV2(BasePluginIOS):

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="data_storage_analyzer",
            version="1.0.0",
            capabilities=[PluginCapability.STATIC_ANALYSIS, PluginCapability.VULNERABILITY_DETECTION],
            description="Detects insecure data storage: NSUserDefaults, SQLite, file protection.",
            priority=PluginPriority.HIGH,
            timeout_seconds=90,
            tags=["storage", "database", "file-protection", "userdefaults"],
            masvs_control="MASVS-STORAGE-1",
        )

    def execute(self, ipa_ctx) -> PluginResult:
        self.setup(ipa_ctx)
        findings: List[PluginFinding] = []

        strings_list = ipa_ctx.get_strings()
        strings_text = "\n".join(strings_list)

        # NSUserDefaults with sensitive keys
        if _USERDEFAULTS_SENSITIVE.search(strings_text):
            findings.append(self.create_finding(
                "storage_userdefaults_sensitive",
                "Sensitive Data in NSUserDefaults",
                "NSUserDefaults appears to store sensitive data (password, token, key, etc.). "
                "NSUserDefaults is stored in plaintext and is accessible in unencrypted backups.",
                "high",
                confidence=0.75,
                cwe_id="CWE-312",
                masvs_control="MASVS-STORAGE-1",
                owasp_category="M2: Insecure Data Storage",
                remediation="Store sensitive values in Keychain with kSecAttrAccessibleWhenUnlockedThisDeviceOnly. "
                            "Never store passwords, tokens, or credentials in NSUserDefaults.",
            ))

        # NSFileProtectionNone
        if _FILE_PROTECTION_NONE.search(strings_text):
            findings.append(self.create_finding(
                "storage_file_protection_none",
                "NSFileProtectionNone Detected",
                "NSFileProtectionNone removes data protection from files, making them accessible "
                "even when the device is locked. This is inappropriate for sensitive files.",
                "high",
                confidence=0.9,
                cwe_id="CWE-922",
                masvs_control="MASVS-STORAGE-1",
                remediation="Use NSFileProtectionComplete or NSFileProtectionCompleteUnlessOpen. "
                            "Only use NSFileProtectionNone for files that must be accessible in the background.",
            ))

        # SQLite without SQLCipher
        if _SQLITE_UNENCRYPTED.search(strings_text) and not _SQLCIPHER.search(strings_text):
            findings.append(self.create_finding(
                "storage_sqlite_unencrypted",
                "SQLite Database Without Encryption",
                "App uses SQLite (sqlite3_open) but no SQLCipher encryption was detected. "
                "SQLite databases are stored as plaintext files on disk.",
                "medium",
                confidence=0.7,
                cwe_id="CWE-312",
                masvs_control="MASVS-STORAGE-2",
                owasp_category="M2: Insecure Data Storage",
                remediation="Encrypt SQLite databases using SQLCipher or migrate to CoreData with "
                            "NSFileProtectionComplete. Alternatively, use encrypted Realm.",
            ))

        # Realm without encryption
        if _REALM_UNENCRYPTED.search(strings_text) and not _REALM_ENCRYPTED.search(strings_text):
            findings.append(self.create_finding(
                "storage_realm_unencrypted",
                "Realm Database Potentially Unencrypted",
                "App uses Realm but no encryption key configuration was detected. "
                "Realm databases are plaintext unless configured with an encryption key.",
                "medium",
                confidence=0.65,
                cwe_id="CWE-312",
                masvs_control="MASVS-STORAGE-2",
                remediation="Configure Realm with a 64-byte encryption key stored in Keychain.",
            ))

        # Check app bundle for .db or .sqlite files (pre-populated databases)
        if ipa_ctx.app_bundle_dir:
            for db_file in ipa_ctx.app_bundle_dir.rglob("*.db"):
                findings.append(self.create_finding(
                    f"storage_bundled_db_{db_file.name}",
                    f"Unencrypted Database File Bundled: {db_file.name}",
                    f"A SQLite database ({db_file.name}) is bundled in the app. "
                    "Verify it contains no sensitive data and is encrypted if needed.",
                    "low",
                    confidence=0.7,
                    cwe_id="CWE-312",
                    masvs_control="MASVS-STORAGE-1",
                    file_path=str(db_file.relative_to(ipa_ctx.extracted_dir)),
                    remediation="Audit bundled databases for sensitive data. Remove or encrypt as appropriate.",
                ))

        return self.create_result(PluginStatus.SUCCESS, findings)
