"""Remediation generation, priority, implementation steps, validation checklist."""

from typing import Dict, List


class RemediationMixin:
    """Remediation guidance generation."""

    def _generate_remediation(self, pattern_info: Dict, code_evidence: Dict) -> Dict:
        """Generate specific remediation guidance based on OWASP category and pattern type."""
        pattern_type = self._safe_extract(pattern_info, "type", "unknown", str)
        owasp_category = self._safe_extract(pattern_info, "owasp", "", str)

        default_template = {
            "action": "Review and address the identified security concern",
            "fix_example": "// Implement appropriate security controls based on OWASP guidelines",
            "apis": ["Security best practices"],
        }

        owasp_template_mapping = {
            "M1: Improper Platform Usage": "improper_platform_usage",
            "M2: Insecure Data Storage": "insecure_data_storage",
            "M3: Insecure Communication": "insecure_communication",
            "M4: Insecure Authentication": "insecure_authentication",
            "M5: Insufficient Cryptography": "insufficient_cryptography",
            "M6: Insecure Authorization": "insecure_authorization",
            "M7: Client Code Quality": "client_code_quality",
            "M8: Code Tampering": "code_tampering",
            "M9: Reverse Engineering": "reverse_engineering",
            "M10: Extraneous Functionality": "extraneous_functionality",
        }

        template_key = owasp_template_mapping.get(owasp_category, pattern_type)
        template = self.remediation_templates.get(template_key, default_template)

        if template == default_template and pattern_type != "unknown":
            pattern_mappings = {
                "m1": "improper_platform_usage",
                "m2": "insecure_data_storage",
                "m3": "insecure_communication",
                "m4": "insecure_authentication",
                "m5": "insufficient_cryptography",
                "m6": "insecure_authorization",
                "m7": "client_code_quality",
                "m8": "code_tampering",
                "m9": "reverse_engineering",
                "m10": "extraneous_functionality",
                "m1_improper_platform_usage": "improper_platform_usage",
                "m2_insecure_data_storage": "insecure_data_storage",
                "m3_insecure_communication": "insecure_communication",
                "m4_insecure_authentication": "insecure_authentication",
                "m5_insufficient_cryptography": "insufficient_cryptography",
                "m6_insecure_authorization": "insecure_authorization",
                "m7_client_code_quality": "client_code_quality",
                "m8_code_tampering": "code_tampering",
                "m9_reverse_engineering": "reverse_engineering",
                "m10_extraneous_functionality": "extraneous_functionality",
                "hardcoded_secret": "insufficient_cryptography",
                "hardcoded_secrets": "insufficient_cryptography",
                "weak_encryption": "insufficient_cryptography",
                "cleartext_traffic": "insecure_communication",
                "exported_component": "improper_platform_usage",
                "debug_enabled": "code_tampering",
                "sql_injection": "client_code_quality",
                "xss": "client_code_quality",
                "injection": "client_code_quality",
                "insecure_storage": "insecure_data_storage",
                "external_storage": "insecure_data_storage",
                "shared_preferences": "insecure_data_storage",
                "sqlite_insecure": "client_code_quality",
                "dangerous_permission": "improper_platform_usage",
                "permission": "improper_platform_usage",
                "exported": "improper_platform_usage",
                "weak_cipher": "insufficient_cryptography",
                "weak_hash": "insufficient_cryptography",
                "http_cleartext": "insecure_communication",
                "certificate": "insecure_communication",
                "tls": "insecure_communication",
                "webview": "client_code_quality",
                "javascript": "client_code_quality",
                "deserialization": "client_code_quality",
                "buffer_overflow": "client_code_quality",
                "weak_password": "insecure_authentication",
                "auth": "insecure_authentication",
                "session": "insecure_authentication",
                "access_control": "insecure_authorization",
                "authorization": "insecure_authorization",
                "privilege": "insecure_authorization",
                "debuggable": "code_tampering",
                "backup_enabled": "insecure_data_storage",
                "root_detection": "code_tampering",
                "emulator_detection": "code_tampering",
                "obfuscation": "reverse_engineering",
                "string_analysis": "reverse_engineering",
                "binary_analysis": "reverse_engineering",
            }

            pattern_lower = pattern_type.lower()

            if pattern_lower in pattern_mappings:
                template = self.remediation_templates.get(pattern_mappings[pattern_lower], default_template)
            else:
                for key, mapped_template in pattern_mappings.items():
                    if key in pattern_lower or pattern_lower in key:
                        template = self.remediation_templates.get(mapped_template, default_template)
                        break

        specific_action = self._safe_extract(template, "action", default_template["action"], str)
        code_fix_example = self._safe_extract(template, "fix_example", default_template["fix_example"], str)

        vulnerable_code = self._safe_extract(code_evidence, "vulnerable_code", "", str)
        if vulnerable_code and template != default_template:
            if pattern_type == "sql_injection":
                if "execSQL" in vulnerable_code:
                    specific_action = "Replace execSQL() with parameterized ContentValues or prepared statements to prevent SQL injection attacks"  # noqa: E501
                    code_fix_example = code_fix_example + f"""

// Current vulnerable code:
{vulnerable_code}

// Recommended fix using ContentValues:
ContentValues values = new ContentValues();
values.put("column_name", userInput);
long result = db.insert("table_name", null, values);"""
                elif "rawQuery" in vulnerable_code:
                    specific_action = "Replace rawQuery() with parameterized queries using selection arguments to prevent SQL injection"  # noqa: E501
                    code_fix_example = code_fix_example + f"""

// Current vulnerable code:
{vulnerable_code}

// Recommended fix with selection arguments:
Cursor cursor = db.rawQuery("SELECT * FROM table WHERE column=?", new String[]{{userInput}});"""

        return {
            "specific_action": specific_action,
            "code_fix_example": code_fix_example,
            "api_references": self._safe_extract(template, "apis", default_template["apis"], list),
            "owasp_category": owasp_category if owasp_category else "General Security",
            "remediation_priority": self._determine_remediation_priority(pattern_info, code_evidence),
            "implementation_steps": self._generate_implementation_steps(template_key, specific_action),
            "validation_checklist": self._generate_validation_checklist(template_key),
        }

    def _determine_remediation_priority(self, pattern_info: Dict, code_evidence: Dict) -> str:
        """Determine remediation priority based on vulnerability characteristics."""
        severity = self._safe_extract(pattern_info, "severity", "MEDIUM", str)
        owasp_category = self._safe_extract(pattern_info, "owasp", "", str)

        high_priority_categories = [
            "M3: Insecure Communication",
            "M4: Insecure Authentication",
            "M5: Insufficient Cryptography",
            "M7: Client Code Quality",
        ]

        if severity.upper() in ["CRITICAL", "HIGH"] or owasp_category in high_priority_categories:
            return "HIGH"
        elif severity.upper() == "MEDIUM":
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_implementation_steps(self, template_key: str, specific_action: str) -> List[str]:
        """Generate step-by-step implementation guidance."""
        step_templates = {
            "insecure_communication": [
                "1. Update all HTTP URLs to HTTPS in your application",
                "2. Configure Network Security Config to disable cleartext traffic",
                "3. Implement certificate pinning for API endpoints",
                "4. Test network requests to ensure they use secure connections",
            ],
            "insufficient_cryptography": [
                "1. Identify all cryptographic operations in your code",
                "2. Replace weak algorithms (MD5, DES) with strong alternatives",
                "3. Use Android Keystore for key generation and storage",
                "4. Implement proper key derivation using PBKDF2 or similar",
                "5. Test cryptographic operations with security tools",
            ],
            "insecure_data_storage": [
                "1. Audit all data storage locations in your application",
                "2. Replace SharedPreferences with EncryptedSharedPreferences",
                "3. Encrypt sensitive data before storing in databases",
                "4. Use Android Keystore for encryption key management",
                "5. Validate storage security with static analysis tools",
            ],
            "client_code_quality": [
                "1. Implement input validation for all user inputs",
                "2. Use parameterized queries for database operations",
                "3. Apply output encoding for WebView content",
                "4. Add Content Security Policy headers",
                "5. Test with OWASP ZAP or similar security scanners",
            ],
        }

        return step_templates.get(
            template_key,
            [
                "1. Review the specific vulnerability details",
                "2. " + specific_action,
                "3. Test the implementation thoroughly",
                "4. Validate the fix with security testing tools",
            ],
        )

    def _generate_validation_checklist(self, template_key: str) -> List[str]:
        """Generate validation checklist for remediation verification."""
        checklist_templates = {
            "insecure_communication": [
                "All network requests use HTTPS protocol",
                "Certificate pinning is implemented for critical APIs",
                "Network Security Config disables cleartext traffic",
                "TLS version 1.2 or higher is enforced",
            ],
            "insufficient_cryptography": [
                "No weak algorithms (MD5, DES, RC4) are used",
                "AES-256 with GCM mode is used for encryption",
                "Keys are generated using AndroidKeyStore",
                "Proper random number generation is implemented",
            ],
            "insecure_data_storage": [
                "No sensitive data is stored in plain text",
                "EncryptedSharedPreferences is used for sensitive preferences",
                "Database encryption is enabled for sensitive data",
                "File permissions are properly restricted",
            ],
            "client_code_quality": [
                "All user inputs are validated and sanitized",
                "Parameterized queries are used for database operations",
                "Output encoding is applied to prevent XSS",
                "Content Security Policy is implemented",
            ],
        }

        return checklist_templates.get(
            template_key,
            [
                "Security vulnerability has been addressed",
                "Fix has been tested and validated",
                "Code follows security best practices",
                "Implementation meets OWASP guidelines",
            ],
        )
