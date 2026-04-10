"""Pattern initialization, detection, OWASP classification, and status filtering."""

import os
import re
from typing import Dict, Optional


class PatternsMixin:
    """Vulnerability pattern loading, detection, and OWASP classification."""

    def _init_vulnerability_patterns(self):
        """Load vulnerability patterns from external YAML configuration files with integrated coordination"""
        import yaml
        import random

        # Load patterns from configuration files
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config", "vulnerability_patterns.yaml"
        )
        kotlin_config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config", "kotlin_vulnerability_patterns.yaml"
        )
        framework_config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "config",
            "framework_vulnerability_patterns.yaml",
        )

        try:
            # Load main patterns (Java/Smali)
            with open(config_path, "r", encoding="utf-8") as f:
                patterns_config = yaml.safe_load(f)

            # INTEGRATION FIX: Extract global exclusions for coordinated filtering
            self.global_exclusions = patterns_config.get("global_exclusions", [])
            if self.global_exclusions:
                self.logger.info(
                    "Loaded global exclusions for coordinated filtering", count=len(self.global_exclusions)
                )

            # Load Kotlin patterns
            kotlin_patterns = {}
            try:
                with open(kotlin_config_path, "r", encoding="utf-8") as f:
                    kotlin_patterns = yaml.safe_load(f)
                self.logger.info("Loaded Kotlin-specific pattern modules", count=len(kotlin_patterns))
            except Exception as e:
                self.logger.warning("Could not load Kotlin patterns", path=kotlin_config_path, error=str(e))

            # Load Framework patterns
            framework_patterns = {}
            try:
                with open(framework_config_path, "r", encoding="utf-8") as f:
                    framework_patterns = yaml.safe_load(f)
                self.logger.info("Loaded framework-specific pattern modules", count=len(framework_patterns))
            except Exception as e:
                self.logger.warning("Could not load framework patterns", path=framework_config_path, error=str(e))

            # Apply simple runtime overrides for HTTP mode toggles (optional)
            try:
                http_mode = os.getenv("AODS_HTTP_MODE", "").strip().lower()
                if isinstance(patterns_config, dict):
                    a14 = patterns_config.get("android_14_pattern_control", {}) or {}
                    if http_mode == "internal":
                        a14["enable_http_strict"] = False
                        a14["enable_http_rfc1918_allowed"] = True
                    elif http_mode == "strict":
                        a14["enable_http_strict"] = True
                        a14["enable_http_rfc1918_allowed"] = False
                    # GDPR gating (env/profile controlled)
                    gdpr_env = os.getenv("AODS_ENABLE_GDPR", "").strip().lower()
                    gdpr_mode = os.getenv("AODS_GDPR", "auto").strip().lower()
                    app_profile = os.getenv("AODS_APP_PROFILE", "production").strip().lower()
                    if gdpr_env in ("1", "true", "yes", "on"):
                        a14["enable_gdpr_policy_patterns"] = True
                    elif gdpr_env in ("0", "false", "no", "off"):
                        a14["enable_gdpr_policy_patterns"] = False
                    else:
                        if gdpr_mode == "auto":
                            a14["enable_gdpr_policy_patterns"] = app_profile in (
                                "production",
                                "prod",
                                "eu",
                                "gdpr",
                                "compliance",
                            )
                        elif gdpr_mode in ("on", "enable", "enabled"):
                            a14["enable_gdpr_policy_patterns"] = True
                        elif gdpr_mode in ("off", "disable", "disabled"):
                            a14["enable_gdpr_policy_patterns"] = False
                    # Enable job constraints conditionally
                    job_env = os.getenv("AODS_ENABLE_JOB_CONSTRAINTS", "").strip().lower()
                    job_mode = os.getenv("AODS_JOB_CONSTRAINTS", "auto").strip().lower()
                    app_profile = os.getenv("AODS_APP_PROFILE", "production").strip().lower()
                    if job_env in ("1", "true", "yes", "on"):
                        a14["enable_job_constraints_patterns"] = True
                    elif job_env in ("0", "false", "no", "off"):
                        a14["enable_job_constraints_patterns"] = False
                    else:
                        if job_mode == "auto":
                            a14["enable_job_constraints_patterns"] = app_profile in (
                                "production",
                                "prod",
                                "qa",
                                "staging",
                            )
                        elif job_mode in ("on", "enable", "enabled"):
                            a14["enable_job_constraints_patterns"] = True
                        elif job_mode in ("off", "disable", "disabled"):
                            a14["enable_job_constraints_patterns"] = False
                    patterns_config["android_14_pattern_control"] = a14
            except Exception:
                pass

            # Convert loaded patterns to expected format - flatten hierarchical structure
            self.vulnerability_patterns = {}

            def flatten_patterns(patterns_dict, source_name=""):
                """Flatten hierarchical pattern structure to make patterns accessible by their category names"""
                for category_name, category_data in patterns_dict.items():
                    if (
                        isinstance(category_data, dict)
                        and category_name
                        not in [
                            "version",
                            "last_updated",
                            "created",
                            "file_filters",
                            "deduplication",
                            "context_extraction",
                            "global_exclusions",
                        ]
                        and not str(category_name).endswith("_DISABLED")
                    ):
                        if "patterns" in category_data and isinstance(category_data.get("patterns"), list):
                            android_controls = {}
                            try:
                                android_controls = patterns_config.get("android_14_pattern_control", {}) or {}
                            except Exception:
                                android_controls = {}

                            filtered_top = []
                            for p in category_data.get("patterns", []):
                                if isinstance(p, dict):
                                    enabled_by = p.get("enabled_by")
                                    if (
                                        enabled_by
                                        and enabled_by in android_controls
                                        and not bool(android_controls.get(enabled_by, False))
                                    ):
                                        continue
                                filtered_top.append(p)

                            if filtered_top:
                                cat_copy = category_data.copy()
                                cat_copy["patterns"] = filtered_top
                                self.vulnerability_patterns[category_name] = cat_copy
                                if source_name:
                                    self.logger.debug(
                                        "Loaded pattern category", category=category_name, source=source_name
                                    )

                        android_controls = {}
                        try:
                            android_controls = patterns_config.get("android_14_pattern_control", {}) or {}
                        except Exception:
                            android_controls = {}

                        for subcategory_name, subcategory_data in category_data.items():
                            if not (
                                isinstance(subcategory_data, dict)
                                and "patterns" in subcategory_data
                                and isinstance(subcategory_data.get("patterns"), list)
                            ):
                                continue

                            filtered_patterns = []
                            for p in subcategory_data.get("patterns", []):
                                if isinstance(p, dict):
                                    enabled_by = p.get("enabled_by")
                                    if enabled_by and enabled_by in android_controls:
                                        if not bool(android_controls.get(enabled_by, False)):
                                            continue
                                filtered_patterns.append(p)

                            if not filtered_patterns:
                                continue

                            cat_copy = subcategory_data.copy()
                            cat_copy["patterns"] = filtered_patterns
                            self.vulnerability_patterns[subcategory_name] = cat_copy
                            if source_name:
                                self.logger.debug(
                                    "Loaded pattern subcategory", subcategory=subcategory_name, source=source_name
                                )

            # Add main patterns (Java/Smali)
            flatten_patterns(patterns_config, "main config")

            # Add Kotlin patterns
            flatten_patterns(kotlin_patterns, "Kotlin config")

            # Add Framework patterns
            flatten_patterns(framework_patterns, "framework config")

            # Conditional WebView hardening enablement
            try:
                auto = os.getenv("AODS_WEBVIEW_HARDENING_AUTO", "1") == "1"
                force = os.getenv("AODS_WEBVIEW_HARDENING_FORCE", "0") == "1"
                ab_pct = float(os.getenv("AODS_WEBVIEW_HARDENING_AB_PCT", "0.25"))
                in_bucket = (random.random() < ab_pct) or force
                if auto and in_bucket:
                    webview_signals = 0
                    signal_patterns = [
                        r"android\.webkit\.WebView",
                        r"WebSettings\.setJavaScriptEnabled\s*\(",
                        r"addJavascriptInterface\s*\(",
                        r"evaluateJavascript\s*\(",
                        r"setWebViewClient\s*\(",
                        r"setWebChromeClient\s*\(",
                        r"webview\s*\.\s*(?:loadUrl|loadData)\s*\(",
                    ]
                    try:
                        for fi in self.source_files.values():
                            if not isinstance(fi, dict):
                                continue
                            text = fi.get("content", "")
                            if not text:
                                continue
                            if any(re.search(p, text, re.IGNORECASE) for p in signal_patterns):
                                webview_signals += 1
                                if webview_signals >= 2:
                                    break
                    except Exception:
                        pass
                    if webview_signals >= 2 or force:
                        if "webview_vulnerabilities" in patterns_config:
                            self.vulnerability_patterns["webview_vulnerabilities"] = patterns_config[
                                "webview_vulnerabilities"
                            ]
                        if "webview_csrf_vulnerabilities" in patterns_config:
                            self.vulnerability_patterns["webview_csrf_vulnerabilities"] = patterns_config[
                                "webview_csrf_vulnerabilities"
                            ]
                        self.logger.info("Conditional WebView hardening enabled", signals=webview_signals)
            except Exception:
                pass

            total_patterns = len(self.vulnerability_patterns)
            self.logger.info("Loaded vulnerability pattern categories from config", total_categories=total_patterns)

        except Exception as e:
            self.logger.warning(
                "Could not load vulnerability patterns, falling back to minimal built-in patterns",
                path=config_path,
                error=str(e),
            )

            self.vulnerability_patterns = {
                "hardcoded_secrets": {
                    "patterns": [
                        r'String\s+(?:password|secret|key|token)\s*=\s*"([^"]{6,})"',
                        r'const-string\s+v\d+,\s*"(?:password|secret|key|token)[^"]*"',
                    ],
                    "content_keywords": ["password", "secret", "key", "token"],
                    "severity": "CRITICAL",
                    "cwe": "CWE-798",
                    "masvs": "MASVS-CRYPTO-1",
                    "owasp": "M7: Client Code Quality",
                },
                "sql_injection": {
                    "patterns": [
                        r'execSQL\s*\(\s*"[^"]*"\s*\+\s*[^)]+\)',
                        r"invoke-virtual.*execSQL.*Ljava/lang/String;",
                    ],
                    "content_keywords": ["execSQL", "rawQuery", "SELECT", "INSERT"],
                    "severity": "CRITICAL",
                    "cwe": "CWE-89",
                    "masvs": "MASVS-CODE-2",
                    "owasp": "M1: Improper Platform Usage",
                },
            }

    def _detect_vulnerability_pattern(self, content: str) -> Optional[Dict]:
        """Detect vulnerability pattern organically based on content analysis"""
        content_lower = content.lower()

        for pattern_name, pattern_info in self.vulnerability_patterns.items():
            patterns_list = self._safe_extract(pattern_info, "patterns", [], list)
            for pattern_obj in patterns_list:
                if isinstance(pattern_obj, dict):
                    pattern_str = pattern_obj.get("pattern", "")
                    if not pattern_str:
                        continue
                elif isinstance(pattern_obj, str):
                    pattern_str = pattern_obj
                else:
                    continue

                if pattern_str and re.search(pattern_str, content, re.IGNORECASE):
                    if isinstance(pattern_obj, dict):
                        pattern_severity = pattern_obj.get(
                            "severity", self._safe_extract(pattern_info, "severity", "MEDIUM", str)
                        )
                        pattern_cwe = pattern_obj.get("cwe_id", self._safe_extract(pattern_info, "cwe", "CWE-200", str))
                        pattern_owasp = pattern_obj.get(
                            "owasp_category",
                            self._safe_extract(pattern_info, "owasp", "M10: Extraneous Functionality", str),
                        )
                        pattern_id = pattern_obj.get("id")
                    else:
                        pattern_severity = self._safe_extract(pattern_info, "severity", "MEDIUM", str)
                        pattern_cwe = self._safe_extract(pattern_info, "cwe", "CWE-200", str)
                        pattern_owasp = self._safe_extract(pattern_info, "owasp", "M10: Extraneous Functionality", str)
                        pattern_id = None

                    try:
                        if pattern_id == "file_uri_exposed_001" and self._has_fileprovider_configured():
                            self.logger.debug("Suppressed file_uri_exposed_001 due to FileProvider present in manifest")
                            continue
                    except Exception:
                        pass

                    return {
                        "id": pattern_id,
                        "type": pattern_name,
                        "severity": pattern_severity,
                        "cwe": pattern_cwe,
                        "masvs": self._safe_extract(pattern_info, "masvs", "MASVS-GENERAL", str),
                        "owasp": pattern_owasp,
                        "matched_pattern": pattern_str,
                    }

        # Check by keywords if no regex match
        keyword_mappings = {
            ("sql", "injection", "query"): "sql_injection",
            ("hardcoded", "secret", "password"): "hardcoded_secrets",
            ("md5", "des", "weak"): "weak_crypto",
            ("http", "cleartext"): "cleartext_http",
            ("storage", "preferences"): "insecure_storage",
            ("log", "logging"): "insecure_logging",
            ("uri.fromfile",): "file_uri_exposure",
            ("fileprovider.geturiforfile",): "file_uri_exposure_negative",
        }

        for keywords, pattern_name in keyword_mappings.items():
            if any(keyword in content_lower for keyword in keywords):
                if pattern_name == "file_uri_exposure_negative":
                    continue
                pattern_info = self.vulnerability_patterns.get(pattern_name, {})
                inferred_id = None
                if pattern_name == "file_uri_exposure":
                    try:
                        for p in self._safe_extract(pattern_info, "patterns", [], list):
                            if isinstance(p, dict) and p.get("id"):
                                inferred_id = p.get("id")
                                break
                    except Exception:
                        inferred_id = None
                return {
                    "id": inferred_id,
                    "type": pattern_name,
                    "severity": self._safe_extract(pattern_info, "severity", "MEDIUM", str),
                    "cwe": self._safe_extract(pattern_info, "cwe", "CWE-200", str),
                    "masvs": self._safe_extract(pattern_info, "masvs", "MASVS-GENERAL", str),
                    "owasp": self._safe_extract(pattern_info, "owasp", "M10: Extraneous Functionality", str),
                    "matched_pattern": None,
                }

        return None

    def _classify_owasp_mobile_pattern(self, title: str, description: str, content: str) -> Dict[str, str]:
        """
        **PATTERN CLASSIFICATION FIX**: Classify vulnerability into specific OWASP Mobile Top 10 categories.
        """
        combined_text = f"{title} {description} {content}".lower()

        classification_patterns = {
            "M1": {
                "category": "M1: Improper Platform Usage",
                "keywords": [
                    "permission",
                    "intent",
                    "exported",
                    "component",
                    "manifest",
                    "activity",
                    "service",
                    "receiver",
                    "provider",
                    "platform",
                    "api misuse",
                ],
                "severity": "MEDIUM",
                "cwe": "CWE-20",
                "masvs": "MASVS-PLATFORM-1",
            },
            "M2": {
                "category": "M2: Insecure Data Storage",
                "keywords": [
                    "storage",
                    "file",
                    "database",
                    "shared_preferences",
                    "sqlite",
                    "cache",
                    "keychain",
                    "realm",
                    "internal storage",
                    "external storage",
                ],
                "severity": "HIGH",
                "cwe": "CWE-922",
                "masvs": "MASVS-STORAGE-1",
            },
            "M3": {
                "category": "M3: Insecure Communication",
                "keywords": [
                    "http",
                    "ssl",
                    "tls",
                    "certificate",
                    "network",
                    "cleartext",
                    "traffic",
                    "communication",
                    "pinning",
                    "https",
                ],
                "severity": "HIGH",
                "cwe": "CWE-319",
                "masvs": "MASVS-NETWORK-1",
            },
            "M4": {
                "category": "M4: Insecure Authentication",
                "keywords": [
                    "authentication",
                    "login",
                    "session",
                    "token",
                    "oauth",
                    "biometric",
                    "password",
                    "credential",
                    "auth",
                ],
                "severity": "HIGH",
                "cwe": "CWE-287",
                "masvs": "MASVS-AUTH-1",
            },
            "M5": {
                "category": "M5: Insufficient Cryptography",
                "keywords": [
                    "crypto",
                    "encryption",
                    "decrypt",
                    "hash",
                    "key",
                    "cipher",
                    "algorithm",
                    "aes",
                    "des",
                    "rsa",
                    "md5",
                    "sha",
                    "random",
                ],
                "severity": "HIGH",
                "cwe": "CWE-327",
                "masvs": "MASVS-CRYPTO-1",
            },
            "M6": {
                "category": "M6: Insecure Authorization",
                "keywords": [
                    "authorization",
                    "access control",
                    "privilege",
                    "role",
                    "permission check",
                    "authorization bypass",
                    "privilege escalation",
                ],
                "severity": "HIGH",
                "cwe": "CWE-285",
                "masvs": "MASVS-AUTH-2",
            },
            "M7": {
                "category": "M7: Client Code Quality",
                "keywords": [
                    "injection",
                    "xss",
                    "sql injection",
                    "buffer overflow",
                    "code quality",
                    "input validation",
                    "sanitization",
                    "webview",
                ],
                "severity": "HIGH",
                "cwe": "CWE-79",
                "masvs": "MASVS-CODE-1",
            },
            "M8": {
                "category": "M8: Code Tampering",
                "keywords": [
                    "tamper",
                    "debug",
                    "obfuscation",
                    "anti-debug",
                    "hooking",
                    "frida",
                    "modification",
                    "integrity",
                    "binary protection",
                ],
                "severity": "MEDIUM",
                "cwe": "CWE-693",
                "masvs": "MASVS-RESILIENCE-1",
            },
            "M9": {
                "category": "M9: Reverse Engineering",
                "keywords": [
                    "reverse engineering",
                    "source code",
                    "binary analysis",
                    "decompilation",
                    "code protection",
                    "intellectual property",
                ],
                "severity": "MEDIUM",
                "cwe": "CWE-200",
                "masvs": "MASVS-RESILIENCE-2",
            },
            "M10": {
                "category": "M10: Extraneous Functionality",
                "keywords": [
                    "backdoor",
                    "test code",
                    "developer",
                    "hidden functionality",
                    "debug mode",
                    "test endpoints",
                    "developer tools",
                ],
                "severity": "MEDIUM",
                "cwe": "CWE-489",
                "masvs": "MASVS-RESILIENCE-3",
            },
        }

        specific_classifications = {
            "md5": {
                "type": "m5",
                "severity": "HIGH",
                "cwe": "CWE-327",
                "masvs": "MASVS-CRYPTO-1",
                "owasp": "M5: Insufficient Cryptography",
            },
            "sha1": {
                "type": "m5",
                "severity": "HIGH",
                "cwe": "CWE-327",
                "masvs": "MASVS-CRYPTO-1",
                "owasp": "M5: Insufficient Cryptography",
            },
            "des": {
                "type": "m5",
                "severity": "HIGH",
                "cwe": "CWE-327",
                "masvs": "MASVS-CRYPTO-1",
                "owasp": "M5: Insufficient Cryptography",
            },
            "broken hash": {
                "type": "m5",
                "severity": "HIGH",
                "cwe": "CWE-327",
                "masvs": "MASVS-CRYPTO-1",
                "owasp": "M5: Insufficient Cryptography",
            },
            "secret detected": {
                "type": "m7",
                "severity": "CRITICAL",
                "cwe": "CWE-798",
                "masvs": "MASVS-CODE-1",
                "owasp": "M7: Client Code Quality",
            },
            "hardcoded": {
                "type": "m7",
                "severity": "CRITICAL",
                "cwe": "CWE-798",
                "masvs": "MASVS-CODE-1",
                "owasp": "M7: Client Code Quality",
            },
            "password": {
                "type": "m7",
                "severity": "CRITICAL",
                "cwe": "CWE-798",
                "masvs": "MASVS-CODE-1",
                "owasp": "M7: Client Code Quality",
            },
            "backup enabled": {
                "type": "m2",
                "severity": "MEDIUM",
                "cwe": "CWE-200",
                "masvs": "MASVS-STORAGE-1",
                "owasp": "M2: Insecure Data Storage",
            },
            "exported": {
                "type": "m1",
                "severity": "MEDIUM",
                "cwe": "CWE-200",
                "masvs": "MASVS-PLATFORM-1",
                "owasp": "M1: Improper Platform Usage",
            },
            "permission": {
                "type": "m1",
                "severity": "MEDIUM",
                "cwe": "CWE-200",
                "masvs": "MASVS-PLATFORM-1",
                "owasp": "M1: Improper Platform Usage",
            },
            "target sdk": {
                "type": "m1",
                "severity": "MEDIUM",
                "cwe": "CWE-200",
                "masvs": "MASVS-PLATFORM-1",
                "owasp": "M1: Improper Platform Usage",
            },
            "minimum sdk": {
                "type": "m1",
                "severity": "MEDIUM",
                "cwe": "CWE-200",
                "masvs": "MASVS-PLATFORM-1",
                "owasp": "M1: Improper Platform Usage",
            },
        }

        for pattern, classification in specific_classifications.items():
            if pattern in combined_text:
                return classification

        category_scores = {}
        for category_id, pattern in classification_patterns.items():
            score = sum(1 for keyword in pattern["keywords"] if keyword in combined_text)
            if score > 0:
                category_scores[category_id] = score

        if category_scores:
            best_category = max(category_scores, key=category_scores.get)
            pattern = classification_patterns[best_category]
            return {
                "type": pattern["category"].lower().replace(" ", "_"),
                "severity": pattern["severity"],
                "cwe": pattern["cwe"],
                "masvs": pattern["masvs"],
                "owasp": pattern["category"],
            }

        return {
            "type": "extraneous_functionality",
            "severity": "MEDIUM",
            "cwe": "CWE-489",
            "masvs": "MASVS-RESILIENCE-3",
            "owasp": "M10: Extraneous Functionality",
        }

    def _is_plugin_status_only(self, title: str, content: str) -> bool:
        """Check if finding is just a plugin status message (not a real vulnerability)."""
        if title.startswith("\u2705"):
            return True

        status_patterns = [
            "plugin executed successfully",
            "analysis complete",
            "scan finished",
            "processing complete",
            "execution completed",
        ]

        content_lower = content.lower()
        if any(pattern in content_lower for pattern in status_patterns):
            vuln_indicators = [
                "vulnerability",
                "exploit",
                "insecure",
                "weakness",
                "flaw",
                "risk",
                "threat",
                "injection",
                "xss",
                "traversal",
                "hardcoded",
                "debug enabled",
                "backup enabled",
                "cleartext",
                "weak encryption",
            ]
            if not any(indicator in content_lower for indicator in vuln_indicators):
                return True

        return False

    def _is_informational_only(self, content: str) -> bool:
        """Check if finding is informational only and should not be treated as a vulnerability."""
        content_lower = content.lower()

        status_indicators = [
            "\u2705",
            "\u2713",
            "plugin executed successfully",
            "analysis complete",
            "scan finished",
            "processing complete",
        ]

        plugin_status_patterns = [
            "runtime_decryption_analysis",
            "enhanced_android_security_plugin",
            "advanced_dynamic_analysis_modules",
            "advanced_pattern_integration",
            "advanced_ssl_tls_analyzer",
            "enhanced_static_analysis",
            "frida_dynamic_analysis",
        ]

        if any(indicator in content for indicator in status_indicators):
            return True

        if any(pattern in content_lower for pattern in plugin_status_patterns):
            vulnerability_keywords = ["vulnerability", "exploit", "insecure", "weakness", "flaw", "risk", "threat"]
            if not any(vuln_keyword in content_lower for vuln_keyword in vulnerability_keywords):
                return True

        info_keywords = ["information", "extraction", "discovery", "analysis complete", "report"]
        if any(keyword in content_lower for keyword in info_keywords) and "vulnerability" not in content_lower:
            return True

        return False
