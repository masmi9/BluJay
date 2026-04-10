"""Vulnerability creation, description generation, severity determination."""

import os
from typing import Dict, Optional

from core.evre._dataclasses import EnhancedVulnerabilityReport


class VulnCreationMixin:
    """Create enhanced vulnerability reports with descriptions and severity."""

    def _enhance_single_finding(self, finding):
        """Extract the enhancement logic for a single finding"""
        try:
            if not isinstance(finding, dict):
                return None

            title = finding.get("title", finding.get("name", "Unknown Vulnerability"))
            if not isinstance(title, str):
                title = str(title)

            description = finding.get("description", "")
            if not isinstance(description, str):
                description = str(description)

            severity = finding.get("severity", "MEDIUM")
            if isinstance(severity, dict):
                severity = severity.get("level", severity.get("value", severity.get("severity", "MEDIUM")))
            elif isinstance(severity, list):
                severity = severity[0] if severity else "MEDIUM"
            elif not isinstance(severity, str):
                severity = str(severity) if severity else "MEDIUM"

            severity_map = {
                "CRITICAL": "CRITICAL",
                "HIGH": "HIGH",
                "MEDIUM": "MEDIUM",
                "LOW": "LOW",
                "INFO": "INFO",
                "INFORMATIONAL": "INFO",
            }
            severity = severity_map.get(severity.upper(), "MEDIUM")

            def safe_field_extract(field_name, default_value, expected_type=str):
                """Safely extract and convert field values to expected types"""
                value = finding.get(field_name, default_value)
                if isinstance(value, dict) and expected_type != dict:
                    if "value" in value:
                        return expected_type(value["value"])
                    elif "level" in value:
                        return expected_type(value["level"])
                    elif field_name in value:
                        return expected_type(value[field_name])
                    else:
                        return expected_type(str(value))
                elif isinstance(value, list) and expected_type != list:
                    return expected_type(value[0] if value else default_value)
                else:
                    return expected_type(value) if value is not None else expected_type(default_value)

            safe_finding = {
                "title": title,
                "description": description,
                "severity": severity,
                "confidence": safe_field_extract("confidence", 0.8, float),
                "file_path": safe_field_extract("file_path", "unknown", str),
                "line_number": safe_field_extract("line_number", 0, int),
                "evidence": safe_field_extract("evidence", "", str),
                "plugin_name": safe_field_extract("plugin_name", "unknown", str),
                "cwe_id": safe_field_extract("cwe_id", "CWE-200", str),
                "masvs_control": safe_field_extract("masvs_control", "MASVS-GENERAL", str),
                "vulnerability_type": safe_field_extract("vulnerability_type", "Unknown", str),
                "source": safe_field_extract("source", "static_analysis", str),
                "recommendations": safe_field_extract("recommendations", [], list),
                "filter_confidence": safe_field_extract("filter_confidence", 0.8, float),
                "filter_category": safe_field_extract("filter_category", "unknown", str),
                "adjusted_severity": safe_field_extract("adjusted_severity", severity, str),
                "filter_reasoning": safe_field_extract("filter_reasoning", "", str),
                "filter_evidence": safe_field_extract("filter_evidence", "", str),
            }

            enhanced_vuln = self._create_enhanced_vulnerability(safe_finding, 0, {})
            return enhanced_vuln

        except Exception:
            return None

    def _create_enhanced_vulnerability(
        self, finding: Dict, index: int, app_context: Dict
    ) -> Optional[EnhancedVulnerabilityReport]:
        """Create enhanced vulnerability report with actual code analysis"""
        if not isinstance(finding, dict):
            finding_str = str(finding)
            finding = {
                "title": f"Plugin Finding {index}",
                "description": f"Finding from plugin: {finding_str}",
                "content": finding_str,
            }

        title = finding.get("title", f"Vulnerability-{index}")
        description = str(finding.get("description", ""))
        content = str(finding.get("content", ""))

        self.logger.debug(f"Processing finding {index}: {title[:60]}")

        full_content = f"{title} {description} {content}"

        if self._is_plugin_status_only(title, full_content):
            self.logger.debug(f"FILTERED (plugin status): {title[:100]}")
            return None

        pattern_info = self._detect_vulnerability_pattern(full_content)
        if not pattern_info:
            pattern_info = self._classify_owasp_mobile_pattern(title, description, content)
            self.logger.debug(f"FALLBACK pattern for: {title[:50]} -> {pattern_info.get('type', 'Unknown')}")

        code_evidence = self._extract_code_evidence(full_content, pattern_info)

        # Context validation for SSRF/GDPR (A/B gated via env)
        try:
            ab_pct = float(os.getenv("AODS_PATTERN_CONTEXT_AB_PCT", "1"))
            force = os.getenv("AODS_PATTERN_CONTEXT_FORCE", "0") == "1"
            import random

            bucket = random.random() < ab_pct or force
        except Exception:
            bucket = True

        if bucket:
            try:
                from core.pattern_governance import PatternContextValidator

                validator = PatternContextValidator()
                file_path = code_evidence.get("file_path", finding.get("file_path", "unknown"))
                category = (pattern_info.get("type") or "").lower()
                if "ssrf" in category:
                    vres = validator.validate_ssrf_context(full_content, file_path or "")
                    if not vres.is_valid:
                        self.logger.debug(f"Context validation dropped SSRF finding at {file_path}: {vres.reasoning}")
                        return None
                elif "gdpr" in category or "privacy" in category:
                    vres = validator.validate_gdpr_context(full_content, file_path or "")
                    if not vres.is_valid:
                        self.logger.debug(f"Context validation dropped GDPR finding at {file_path}: {vres.reasoning}")
                        return None
                    pattern_info["owasp"] = pattern_info.get("owasp", "Compliance")
                    if "severity" in pattern_info and str(pattern_info["severity"]).upper() in ["CRITICAL", "HIGH"]:
                        pattern_info["severity"] = "MEDIUM"
            except Exception:
                pass

        remediation = self._generate_remediation(pattern_info, code_evidence)
        severity = self._determine_severity(pattern_info, code_evidence)

        if isinstance(severity, str):
            severity_dict = {
                "severity": severity,
                "original_severity": severity,
                "adjusted_severity": severity,
                "severity_reasoning": "Based on pattern analysis and code evidence",
            }
        elif isinstance(severity, dict):
            severity_dict = severity
        else:
            severity_dict = {
                "severity": "MEDIUM",
                "original_severity": "MEDIUM",
                "adjusted_severity": "MEDIUM",
                "severity_reasoning": "Default severity assigned due to unexpected format",
            }

        enhanced_vuln = {
            "id": self._generate_unique_vulnerability_id(finding, index),
            "title": title,
            "description": self._create_enhanced_description(full_content, pattern_info, code_evidence),
            "severity": severity_dict["adjusted_severity"],
            "confidence": finding.get("confidence", 0.8),
            "file_path": code_evidence.get("file_path", "unknown"),
            "line_number": code_evidence.get("line_number", 0),
            "method_name": code_evidence.get("method_name", ""),
            "class_name": code_evidence.get("class_name", ""),
            "vulnerable_code": code_evidence.get("vulnerable_code", ""),
            "surrounding_context": code_evidence.get("surrounding_context", ""),
            "pattern_matches": code_evidence.get("pattern_matches", []),
            "specific_remediation": remediation.get("specific_action", ""),
            "code_fix_example": remediation.get("code_fix_example", ""),
            "api_references": remediation.get("api_references", []),
            "original_severity": severity_dict["original_severity"],
            "adjusted_severity": severity_dict["adjusted_severity"],
            "severity_reasoning": severity_dict["severity_reasoning"],
            "vulnerable_pattern": pattern_info.get("type", ""),
            "masvs_control": pattern_info.get("masvs", "MASVS-GENERAL"),
            "owasp_category": pattern_info.get("owasp", "M10: Extraneous Functionality"),
            "cwe_id": pattern_info.get("cwe", "CWE-200"),
        }

        def safe_list_conversion(value, convert_func=str):
            """Safely convert value to list of strings"""
            if value is None:
                return []
            if isinstance(value, list):
                return [convert_func(item) for item in value]
            if isinstance(value, (str, dict)):
                return [convert_func(value)]
            return [convert_func(value)]

        return EnhancedVulnerabilityReport(
            id=str(enhanced_vuln["id"]),
            title=str(enhanced_vuln["title"]),
            description=str(enhanced_vuln["description"]),
            severity=str(enhanced_vuln["severity"]),
            confidence=float(enhanced_vuln["confidence"]) if enhanced_vuln["confidence"] else 0.8,
            file_path=str(enhanced_vuln["file_path"]),
            line_number=int(enhanced_vuln["line_number"]) if enhanced_vuln["line_number"] else 0,
            method_name=str(enhanced_vuln["method_name"]),
            class_name=str(enhanced_vuln["class_name"]),
            vulnerable_code=str(enhanced_vuln["vulnerable_code"]),
            surrounding_context=str(enhanced_vuln["surrounding_context"]),
            pattern_matches=safe_list_conversion(enhanced_vuln["pattern_matches"]),
            specific_remediation=str(enhanced_vuln["specific_remediation"]),
            code_fix_example=str(enhanced_vuln["code_fix_example"]),
            api_references=safe_list_conversion(enhanced_vuln["api_references"]),
            original_severity=str(enhanced_vuln["original_severity"]),
            adjusted_severity=str(enhanced_vuln["adjusted_severity"]),
            severity_reasoning=str(enhanced_vuln["severity_reasoning"]),
            vulnerable_pattern=str(enhanced_vuln["vulnerable_pattern"]),
            masvs_control=str(enhanced_vuln["masvs_control"]),
            owasp_category=str(enhanced_vuln["owasp_category"]),
            cwe_id=str(enhanced_vuln["cwe_id"]),
        )

    def _determine_severity(self, pattern_info: Dict, code_evidence: Dict) -> Dict:
        """Determine severity based on pattern and evidence"""
        base_severity = pattern_info.get("severity", "MEDIUM")

        if isinstance(base_severity, list):
            base_severity = base_severity[0] if base_severity else "MEDIUM"
        elif not isinstance(base_severity, str):
            base_severity = str(base_severity) if base_severity else "MEDIUM"

        severity_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "INFO"}

        normalized_severity = severity_map.get(base_severity.upper(), "MEDIUM")

        return {
            "severity": normalized_severity,
            "original_severity": base_severity,
            "adjusted_severity": normalized_severity,
            "severity_reasoning": "Based on pattern analysis and code evidence",
        }

    def _clean_title(self, title: str) -> str:
        """Clean and standardize vulnerability title"""
        return title.replace("_", " ").title()

    def _create_enhanced_description(self, content: str, pattern_info: Dict, code_evidence: Dict) -> str:
        """Create contextual description explaining the specific vulnerability and its impact"""
        vulnerability_type = self._safe_extract(pattern_info, "type", "Unknown", str)
        owasp_category = self._safe_extract(pattern_info, "owasp", "", str)

        desc = self._generate_contextual_description(vulnerability_type, owasp_category, code_evidence)

        severity = self._safe_extract(pattern_info, "severity", "MEDIUM", str)
        vulnerable_code = self._safe_extract(code_evidence, "vulnerable_code", "", str)
        if not any(risk_phrase in desc for risk_phrase in ["poses a", "security risk", "should be addressed"]):
            if vulnerable_code and vulnerable_code not in [
                "",
                "[Configuration/Metadata Issue - No Source Code Location]",
            ]:
                vulnerable_code = vulnerable_code.strip()
                if vulnerable_code and len(vulnerable_code) < 200:
                    desc += f" The vulnerable code pattern identified is: `{vulnerable_code}`."
        if not any(risk_phrase in desc for risk_phrase in ["poses a", "security risk", "should be addressed"]):
            if severity == "CRITICAL":
                desc += " This vulnerability poses a critical security risk and should be addressed immediately."
            elif severity == "HIGH":
                desc += " This vulnerability poses a high security risk and should be addressed as a priority."
            elif severity == "MEDIUM":
                desc += " This vulnerability poses a moderate security risk and should be addressed in the next development cycle."  # noqa: E501
            elif severity == "LOW":
                desc += (
                    " This vulnerability poses a low security risk but should still be remediated for defense in depth."
                )

        return desc

    def _generate_contextual_description(
        self, vulnerability_type: str, owasp_category: str, code_evidence: Dict
    ) -> str:
        """Generate specific, contextual descriptions explaining what the vulnerability is and why it's dangerous"""
        file_path = self._safe_extract(code_evidence, "file_path", "", str)
        line_number = self._safe_extract(code_evidence, "line_number", 0, int)
        class_name = self._safe_extract(code_evidence, "class_name", "", str)
        vulnerable_code = self._safe_extract(code_evidence, "vulnerable_code", "", str)

        description_templates = {
            "m1": "This application contains improperly configured Android components that can be exploited by malicious applications",  # noqa: E501
            "improper_platform_usage": "This application uses Android platform features in an insecure manner that exposes functionality to unauthorized access",  # noqa: E501
            "exported_component": "This application exposes Android components (activities, services, or broadcast receivers) without proper permission checks, allowing malicious apps to interact with them",  # noqa: E501
            "dangerous_permission": "This application requests Android permissions that could allow access to sensitive user data or device capabilities beyond what is necessary for the app's functionality",  # noqa: E501
            "permission": "This application has permission-related security issues that could allow unauthorized access to protected functionality",  # noqa: E501
            "m2": "This application stores sensitive data without proper encryption or access controls, making it accessible to attackers who gain device access",  # noqa: E501
            "insecure_data_storage": "This application stores sensitive information in locations that lack proper encryption or access controls",  # noqa: E501
            "insecure_storage": "This application uses insecure storage mechanisms that could expose sensitive data to unauthorized access",  # noqa: E501
            "external_storage": "This application stores sensitive data on external storage where it can be accessed by other applications",  # noqa: E501
            "backup_enabled": "This application allows automatic backup of its data, which could expose sensitive information through cloud backups or local backup files",  # noqa: E501
            "shared_preferences": "This application stores sensitive data in shared preferences without proper encryption",  # noqa: E501
            "m3": "This application uses insecure network communication that can be intercepted or manipulated by attackers",  # noqa: E501
            "insecure_communication": "This application communicates over networks without proper encryption or certificate validation",  # noqa: E501
            "cleartext_traffic": "This application sends sensitive data over unencrypted HTTP connections that can be intercepted",  # noqa: E501
            "certificate": "This application has improper SSL/TLS certificate validation that could allow man-in-the-middle attacks",  # noqa: E501
            "m4": "This application implements weak or bypassable authentication mechanisms",
            "insecure_authentication": "This application has authentication weaknesses that could allow unauthorized access to user accounts",  # noqa: E501
            "weak_password": "This application accepts weak passwords that can be easily guessed or brute-forced",
            "m5": "This application uses weak or outdated cryptographic algorithms that can be broken by attackers",
            "insufficient_cryptography": "This application implements cryptography in a way that provides insufficient protection against attacks",  # noqa: E501
            "weak_encryption": "This application uses cryptographic algorithms or key sizes that are considered weak by current standards",  # noqa: E501
            "weak_cipher": "This application uses encryption ciphers that have known vulnerabilities or are considered obsolete",  # noqa: E501
            "weak_hash": "This application uses hash algorithms that are cryptographically broken and vulnerable to collision attacks",  # noqa: E501
            "hardcoded_key": "This application contains cryptographic keys or secrets embedded directly in the source code",  # noqa: E501
            "hardcoded_secret": "This application contains sensitive credentials or secrets hardcoded in the source code where they can be easily extracted",  # noqa: E501
            "m6": "This application has authorization flaws that allow users to access functionality they shouldn't be able to access",  # noqa: E501
            "insecure_authorization": "This application fails to properly verify user permissions before allowing access to sensitive functionality",  # noqa: E501
            "m7": "This application contains code quality issues that introduce security vulnerabilities",
            "client_code_quality": "This application has code quality issues that create security vulnerabilities",
            "sql_injection": "This application constructs SQL queries in a way that allows attackers to inject malicious SQL code",  # noqa: E501
            "webview": "This application uses WebView components with insecure settings that could allow script injection attacks",  # noqa: E501
            "injection": "This application is vulnerable to injection attacks where user input is not properly validated",  # noqa: E501
            "m8": "This application lacks protection against code modification and reverse engineering",
            "code_tampering": "This application is vulnerable to code tampering and lacks runtime application self-protection",  # noqa: E501
            "debuggable": "This application has debugging enabled in production, which allows attackers to attach debuggers and analyze runtime behavior",  # noqa: E501
            "root_detection": "This application lacks proper detection of rooted/jailbroken devices where security controls may be bypassed",  # noqa: E501
            "m9": "This application lacks protection against reverse engineering and code analysis",
            "reverse_engineering": "This application is vulnerable to reverse engineering attacks that could expose sensitive algorithms or secrets",  # noqa: E501
            "m10": "This application contains unnecessary functionality that increases the attack surface",
            "extraneous_functionality": "This application includes debugging, testing, or administrative functionality that should not be present in production builds",  # noqa: E501
        }

        desc = ""
        pattern_lower = vulnerability_type.lower()

        if pattern_lower in description_templates:
            desc = description_templates[pattern_lower]
        else:
            for pattern, template in description_templates.items():
                if pattern in pattern_lower or pattern_lower in pattern:
                    desc = template
                    break

            if not desc:
                owasp_descriptions = {
                    "M1: Improper Platform Usage": "This application uses Android platform features in an insecure manner",  # noqa: E501
                    "M2: Insecure Data Storage": "This application stores sensitive data without proper security controls",  # noqa: E501
                    "M3: Insecure Communication": "This application uses insecure network communication protocols",
                    "M4: Insecure Authentication": "This application has authentication security weaknesses",
                    "M5: Insufficient Cryptography": "This application uses insufficient or weak cryptographic protections",  # noqa: E501
                    "M6: Insecure Authorization": "This application has authorization bypass vulnerabilities",
                    "M7: Client Code Quality": "This application has code quality issues that create security vulnerabilities",  # noqa: E501
                    "M8: Code Tampering": "This application lacks protection against code modification attacks",
                    "M9: Reverse Engineering": "This application is vulnerable to reverse engineering attacks",
                    "M10: Extraneous Functionality": "This application contains unnecessary functionality that increases security risk",  # noqa: E501
                }
                desc = owasp_descriptions.get(
                    owasp_category, "This application contains a security vulnerability that requires attention"
                )

        if file_path and file_path not in ["", "unknown", "system_analysis", "aods_framework"]:
            desc += f". This issue was identified in {file_path}"
            if line_number > 0:
                desc += f" at line {line_number}"
            if class_name and class_name not in ["", "unknown"]:
                desc += f" within the {class_name} class"
            desc += "."

        if vulnerable_code and vulnerable_code not in ["", "[Configuration/Metadata Issue - No Source Code Location]"]:
            if len(vulnerable_code) < 100:
                desc += f" The problematic code pattern found is: {vulnerable_code}."

        return desc
