"""QA framework: global exclusions, dedup, smart filtering, validation."""

import re
from typing import Dict, List, Any, Tuple


class QAMixin:
    """Quality assurance, filtering, and deduplication methods."""

    def _apply_global_exclusions(self, findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
        """Apply intelligent global exclusions - filter noise while preserving real vulnerabilities."""
        filtered = []
        stats = {
            "preserved_vulnerabilities": 0,
            "library_vulns": 0,
            "test_vulns": 0,
            "config_vulns": 0,
            "excluded_noise": 0,
        }

        for finding in findings:
            file_path = finding.get("file_path", "")

            if self._is_real_vulnerability_in_excluded_context(finding):
                filtered.append(finding)
                stats["preserved_vulnerabilities"] += 1

                if any(lib in file_path for lib in ["okhttp3", "retrofit", "androidx", "android/support"]):
                    stats["library_vulns"] += 1
                elif any(test in file_path for test in ["test", "debug", "sample", "demo"]):
                    stats["test_vulns"] += 1
                elif file_path.endswith((".xml", ".json", ".properties")):
                    stats["config_vulns"] += 1

                continue

            should_exclude = False
            for exclusion_pattern in self.global_exclusions:
                try:
                    if re.search(exclusion_pattern, file_path):
                        should_exclude = True
                        stats["excluded_noise"] += 1
                        break
                except re.error:
                    continue

            if not should_exclude:
                filtered.append(finding)

        return filtered, stats

    def _apply_unified_deduplication(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply unified deduplication using existing framework."""
        try:
            from core.unified_deduplication_framework import create_deduplication_engine, DeduplicationStrategy
            import hashlib
            import os

            for v in vulnerabilities:
                try:
                    code = str(v.get("surrounding_context") or v.get("vulnerable_code") or "")
                    v["context_window_hash"] = hashlib.sha256(code.encode("utf-8", "ignore")).hexdigest()
                except Exception:
                    continue

            engine = create_deduplication_engine(DeduplicationStrategy.INTELLIGENT)
            try:
                sim_env = os.getenv("AODS_DEDUP_SIMILARITY")
                if sim_env and hasattr(engine, "set_similarity_threshold"):
                    engine.set_similarity_threshold(float(sim_env))  # type: ignore
            except Exception:
                pass

            result = engine.deduplicate_findings(vulnerabilities)

            deduped = result.unique_findings
            removed = len(vulnerabilities) - len(deduped)

            self.logger.info("Unified deduplication completed", removed=removed, unique=len(deduped))
            return deduped

        except Exception as e:
            self.logger.warning("Unified deduplication failed, using fallback", error=str(e))
            seen = set()
            unique = []

            for vuln in vulnerabilities:
                signature = (vuln.get("title", ""), vuln.get("file_path", ""), vuln.get("line_number", 0))
                if signature not in seen:
                    seen.add(signature)
                    unique.append(vuln)

            return unique

    def _dedupe_webview_js_bridge(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Collapse duplicate WebView JS-bridge related findings across categories."""
        groups: Dict[str, Dict[str, Any]] = {}
        for finding in vulnerabilities:
            text = (finding.get("matched_pattern") or "") + " " + (finding.get("evidence") or "")
            title = finding.get("title") or ""
            ftype = finding.get("type") or ""
            file_path = finding.get("file_path") or finding.get("file") or ""
            line = finding.get("line_number") or finding.get("line") or 0
            ctx_hash = finding.get("context_window_hash") or ""

            is_webview_related = any(
                key in (title + " " + ftype).lower() for key in ["webview", "javascript", "js bridge"]
            ) or (re.search(r"addJavascriptInterface|setJavaScriptEnabled", text, re.IGNORECASE) is not None)
            if not is_webview_related:
                key = f"OTHER::{file_path}:{line}:{ctx_hash}:{hash(title + ftype)}"
                groups[key] = finding
                continue

            anchor = ctx_hash or f"{file_path}:{line}"
            key = f"WEBVIEW::{anchor}"

            current = groups.get(key)
            if current is None:
                groups[key] = finding
            else:

                def sev_rank(f):
                    sev = (f.get("severity") or "").upper()
                    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                    return order.get(sev, 0)

                better = finding if sev_rank(finding) > sev_rank(current) else current
                if better is current and text and "addJavascriptInterface" in text and "evidence" in current:
                    current["evidence"] = f"{current.get('evidence', '')}; addJavascriptInterface detected"
                groups[key] = better

        return list(groups.values())

    def _is_real_vulnerability_in_excluded_context(self, finding: Dict[str, Any]) -> bool:
        """Intelligent detection of real vulnerabilities in typically excluded contexts."""
        file_path = finding.get("file_path", "")
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        vulnerable_code = finding.get("vulnerable_code", "")
        severity = finding.get("severity", "UNKNOWN")
        confidence = finding.get("confidence", 0)

        if confidence >= 0.8 and severity in ["CRITICAL", "HIGH"]:
            return True

        library_vulnerability_indicators = [
            "certificate",
            "ssl",
            "tls",
            "hostname",
            "trust",
            "verify",
            "insecure",
            "cleartext",
            "http://",
            "unencrypted",
            "authentication",
            "authorization",
            "token",
            "session",
            "credential",
            "password",
            "secret",
            "api_key",
            "injection",
            "sql",
            "xss",
            "script",
            "command",
            "path traversal",
            "directory traversal",
            "weak cipher",
            "md5",
            "sha1",
            "des",
            "rc4",
            "hardcoded",
            "encryption",
            "cryptography",
            "webview",
            "javascript",
            "file://",
            "content://",
            "exported",
            "permission",
            "intent",
        ]

        text_to_check = f"{title} {description} {vulnerable_code}".lower()
        vulnerability_score = sum(1 for indicator in library_vulnerability_indicators if indicator in text_to_check)

        if any(lib in file_path for lib in ["okhttp3", "retrofit", "volley", "gson"]):
            network_vulns = ["certificate", "ssl", "hostname", "trust", "cleartext"]
            if any(vuln in text_to_check for vuln in network_vulns):
                return True

        if any(lib in file_path for lib in ["androidx", "android/support"]):
            android_vulns = ["webview", "exported", "permission", "intent", "file://"]
            if any(vuln in text_to_check for vuln in android_vulns):
                return True

        if any(test_indicator in file_path for test_indicator in ["test", "debug", "sample", "demo"]):
            production_affecting = [
                "hardcoded",
                "credential",
                "secret",
                "password",
                "api_key",
                "production",
                "staging",
                "real",
                "actual",
            ]
            if any(indicator in text_to_check for indicator in production_affecting):
                return True

        if "$" in file_path and any(
            kotlin_artifact in file_path for kotlin_artifact in ["$serializer", "$Companion", "$WhenMappings"]
        ):
            if vulnerability_score == 0 and confidence < 0.5:
                return False

        if file_path.endswith((".xml", ".json", ".properties")):
            config_vulns = ["password", "secret", "key", "token", "credential", "debuggable", "allowbackup", "exported"]
            if any(vuln in text_to_check for vuln in config_vulns):
                return True

        if vulnerability_score >= 2 and confidence >= 0.6:
            return True

        critical_patterns = [
            "sql injection",
            "xss",
            "command injection",
            "path traversal",
            "hardcoded secret",
            "hardcoded password",
            "insecure random",
            "weak encryption",
            "certificate validation",
        ]

        if any(pattern in text_to_check for pattern in critical_patterns):
            return True

        return False

    def _apply_comprehensive_qa(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply full quality assurance using existing framework."""
        try:
            from core.comprehensive_quality_assurance_framework import ComprehensiveQualityAssuranceFramework

            self.logger.info("Applying full QA", count=len(vulnerabilities))

            vuln_dicts = []
            for vuln in vulnerabilities:
                if hasattr(vuln, "__dict__"):
                    vuln_dicts.append(vuln.__dict__)
                elif hasattr(vuln, "_asdict"):
                    vuln_dicts.append(vuln._asdict())
                elif hasattr(vuln, "get"):
                    vuln_dicts.append(vuln)
                else:
                    vuln_dict = {}
                    for attr in dir(vuln):
                        if not attr.startswith("_"):
                            try:
                                vuln_dict[attr] = getattr(vuln, attr)
                            except Exception:
                                continue
                    vuln_dicts.append(vuln_dict)

            qa_framework = ComprehensiveQualityAssuranceFramework()

            summary_stats = {
                "total_findings": len(vuln_dicts),
                "severity_breakdown": self._get_severity_breakdown(vuln_dicts),
                "confidence_distribution": self._get_confidence_distribution(vuln_dicts),
            }

            processed_vulnerabilities, qa_report = qa_framework.process_vulnerability_dataset(
                vuln_dicts,
                summary_stats=summary_stats,
                context={"source": "enhanced_vulnerability_reporting_engine"},
                source_roots=getattr(self, "source_roots", []),
            )

            original_count = len(vulnerabilities)
            final_count = len(processed_vulnerabilities)
            improvement_count = original_count - final_count

            self.logger.info(
                "Full QA complete",
                original=original_count,
                final=final_count,
                quality_improvements=improvement_count,
                overall_quality_score=round(qa_report.metrics.overall_quality_score, 1),
                production_ready=qa_report.metrics.production_readiness,
            )

            self.qa_report = qa_report

            return processed_vulnerabilities

        except Exception as e:
            self.logger.warning("Full QA failed, continuing without", error=str(e))
            return vulnerabilities

    def _apply_smart_filtering_coordination(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply smart filtering coordination using existing system."""
        try:
            from core.smart_filtering_coordinator import get_smart_filtering_coordinator

            self.logger.info("Applying smart filtering coordination", count=len(vulnerabilities))

            coordinator = get_smart_filtering_coordinator()

            app_context = getattr(self, "app_context", {})

            if not app_context or app_context.get("apk_path") == "unknown":
                apk_path = getattr(self, "apk_path", "unknown")
                package_name = getattr(self, "target_package", "unknown")

                app_context = {"package_name": package_name, "target_apk": apk_path, "apk_path": apk_path}

            if "apk_path" not in app_context and hasattr(self, "apk_path"):
                app_context["apk_path"] = self.apk_path

            vuln_dicts = []
            for vuln in vulnerabilities:
                if hasattr(vuln, "__dict__"):
                    vuln_dicts.append(vuln.__dict__)
                elif hasattr(vuln, "_asdict"):
                    vuln_dicts.append(vuln._asdict())
                else:
                    vuln_dicts.append(vuln)

            filtering_result = coordinator.coordinate_smart_filtering(vuln_dicts, app_context)

            filtered_vulnerabilities = filtering_result.filtered_findings_list or []

            original_count = len(vulnerabilities)
            filtered_count = len(filtered_vulnerabilities)
            removed_count = original_count - filtered_count

            self.logger.info(
                "Smart filtering coordination complete",
                original=original_count,
                filtered=filtered_count,
                removed=removed_count,
                confidence_improvement=round(filtering_result.confidence_improvement, 2),
            )

            return filtered_vulnerabilities

        except Exception as e:
            self.logger.warning("Smart filtering coordination failed, continuing without", error=str(e))
            return vulnerabilities

    def _apply_result_validation(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply result validation pipeline using existing system."""
        try:
            from core.result_validation_pipeline import get_validation_pipeline

            self.logger.info("Applying result validation", count=len(vulnerabilities))

            vuln_dicts = []
            for vuln in vulnerabilities:
                if hasattr(vuln, "__dict__"):
                    vuln_dicts.append(vuln.__dict__)
                elif hasattr(vuln, "_asdict"):
                    vuln_dicts.append(vuln._asdict())
                elif hasattr(vuln, "get"):
                    vuln_dicts.append(vuln)
                else:
                    vuln_dict = {}
                    for attr in dir(vuln):
                        if not attr.startswith("_"):
                            try:
                                vuln_dict[attr] = getattr(vuln, attr)
                            except Exception:
                                continue
                    vuln_dicts.append(vuln_dict)

            validation_pipeline = get_validation_pipeline()

            validated_vulnerabilities = []
            validation_stats = {"passed": 0, "failed": 0, "sanitized": 0}

            for vuln in vuln_dicts:
                validation_result = validation_pipeline.validate_plugin_result(
                    plugin_name="enhanced_vulnerability_reporting_engine", result=vuln
                )

                if hasattr(validation_result, "is_valid") and validation_result.is_valid:
                    if hasattr(validation_result, "sanitized_result"):
                        validated_vulnerabilities.append(validation_result.sanitized_result)
                        validation_stats["passed"] += 1

                        if validation_result.sanitized_result != vuln:
                            validation_stats["sanitized"] += 1
                    else:
                        validated_vulnerabilities.append(vuln)
                        validation_stats["passed"] += 1
                else:
                    validation_stats["failed"] += 1
                    validated_vulnerabilities.append(vuln)
                    if hasattr(validation_result, "errors") and validation_result.errors:
                        self.logger.debug(
                            "Validation failed for finding",
                            title=vuln.get("title", "unknown"),
                            error=validation_result.errors[0],
                        )

            self.logger.info(
                "Result validation complete",
                passed=validation_stats["passed"],
                failed=validation_stats["failed"],
                sanitized=validation_stats["sanitized"],
            )

            return validated_vulnerabilities

        except Exception as e:
            self.logger.warning("Result validation failed, continuing without", error=str(e))
            return vulnerabilities

    def _apply_conservative_qa(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply conservative quality assurance that preserves real vulnerabilities."""
        try:
            self.logger.info("Applying conservative QA", count=len(vulnerabilities))

            vuln_dicts = []
            for vuln in vulnerabilities:
                if hasattr(vuln, "__dict__"):
                    vuln_dicts.append(vuln.__dict__)
                elif hasattr(vuln, "_asdict"):
                    vuln_dicts.append(vuln._asdict())
                elif hasattr(vuln, "get"):
                    vuln_dicts.append(vuln)
                else:
                    vuln_dict = {}
                    for attr in dir(vuln):
                        if not attr.startswith("_"):
                            try:
                                vuln_dict[attr] = getattr(vuln, attr)
                            except Exception:
                                continue
                    vuln_dicts.append(vuln_dict)

            filtered_vulnerabilities = []
            seen_combinations = set()

            for vuln in vuln_dicts:
                title = vuln.get("title", "").lower()
                severity = vuln.get("severity", "UNKNOWN")
                confidence = vuln.get("confidence", 0.0)
                file_path = vuln.get("file_path", "")
                vulnerable_code = vuln.get("vulnerable_code", "")

                if severity in ["CRITICAL", "HIGH"]:
                    self.logger.debug("Preserving high-severity finding", severity=severity, title=title)
                    filtered_vulnerabilities.append(vuln)
                    continue

                if confidence >= 0.7:
                    self.logger.debug("Preserving high-confidence finding", confidence=confidence, title=title)
                    filtered_vulnerabilities.append(vuln)
                    continue

                critical_patterns = [
                    "sql injection",
                    "hardcoded credential",
                    "hardcoded secret",
                    "backup enabled",
                    "exported component",
                    "weak cipher",
                    "insecure storage",
                    "certificate",
                    "authentication",
                ]

                if any(pattern in title.lower() for pattern in critical_patterns):
                    self.logger.debug("Preserving critical pattern finding", title=title)
                    filtered_vulnerabilities.append(vuln)
                    continue

                dup_key = f"{title}_{file_path}_{vulnerable_code[:50]}"
                if dup_key not in seen_combinations:
                    seen_combinations.add(dup_key)
                    filtered_vulnerabilities.append(vuln)
                else:
                    self.logger.debug("Removing duplicate finding", title=title)

            original_count = len(vuln_dicts)
            final_count = len(filtered_vulnerabilities)
            removed_count = original_count - final_count

            self.logger.info(
                "Conservative QA complete",
                original=original_count,
                final=final_count,
                removed_duplicates=removed_count,
                preservation_rate_pct=round((final_count / original_count) * 100, 1),
            )

            return filtered_vulnerabilities

        except Exception as e:
            self.logger.warning("Conservative QA failed, continuing without", error=str(e))
            return vulnerabilities

    def _validate_coordination_effectiveness(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate that all coordination systems have been effectively applied."""
        validation_results = {
            "coordination_status": "SUCCESS",
            "issues_detected": [],
            "quality_metrics": {},
            "recommendations": [],
        }

        try:
            self.logger.info("Validating coordination effectiveness", count=len(vulnerabilities))

            issues = []

            title_counts = {}
            for vuln in vulnerabilities:
                title = vuln.get("title", "Unknown")
                title_counts[title] = title_counts.get(title, 0) + 1

            excessive_duplicates = {title: count for title, count in title_counts.items() if count > 3}
            if excessive_duplicates:
                issues.append(f"Excessive duplicates found: {excessive_duplicates}")
                validation_results["coordination_status"] = "WARNING"

            metadata_issues = sum(
                1
                for v in vulnerabilities
                if v.get("vulnerable_code") == "[Configuration/Metadata Issue - No Source Code Location]"
            )
            if metadata_issues > 0:
                issues.append(f"Found {metadata_issues} metadata issues despite filtering")
                validation_results["coordination_status"] = "WARNING"

            library_paths = ["androidx", "android/support", "okhttp3", "retrofit"]
            library_noise = []
            for vuln in vulnerabilities:
                file_path = vuln.get("file_path", "")
                if any(lib in file_path for lib in library_paths):
                    if not self._is_real_vulnerability_in_excluded_context(vuln):
                        library_noise.append(vuln.get("title", "Unknown"))

            if library_noise:
                issues.append(f"Potential library noise: {len(library_noise)} findings")
                validation_results["coordination_status"] = "WARNING"

            confidence_dist = self._get_confidence_distribution(vulnerabilities)
            low_confidence_pct = (confidence_dist["low"] / len(vulnerabilities) * 100) if vulnerabilities else 0

            if low_confidence_pct > 30:
                issues.append(f"High percentage of low confidence findings: {low_confidence_pct:.1f}%")
                validation_results["coordination_status"] = "WARNING"

            unknown_sources = sum(1 for v in vulnerabilities if "unknown" in v.get("file_path", "").lower())
            if unknown_sources > len(vulnerabilities) * 0.1:
                issues.append(f"Many findings with unknown source attribution: {unknown_sources}")
                validation_results["coordination_status"] = "WARNING"

            validation_results["issues_detected"] = issues

            validation_results["quality_metrics"] = {
                "total_findings": len(vulnerabilities),
                "duplicate_groups": len(excessive_duplicates),
                "metadata_issues": metadata_issues,
                "library_noise_count": len(library_noise),
                "low_confidence_percentage": low_confidence_pct,
                "unknown_source_count": unknown_sources,
                "confidence_distribution": confidence_dist,
                "severity_breakdown": self._get_severity_breakdown(vulnerabilities),
            }

            recommendations = []
            if excessive_duplicates:
                recommendations.append("Consider enhancing deduplication strategy")
            if metadata_issues > 0:
                recommendations.append("Improve source file attribution validation")
            if library_noise:
                recommendations.append("Refine library vulnerability detection")
            if low_confidence_pct > 30:
                recommendations.append("Review pattern confidence thresholds")

            validation_results["recommendations"] = recommendations

            if len(issues) == 0:
                validation_results["coordination_status"] = "SUCCESS"
                self.logger.info("Coordination validation: All systems working effectively")
            elif len(issues) <= 2:
                validation_results["coordination_status"] = "WARNING"
                self.logger.warning("Coordination validation: Minor issues detected", issue_count=len(issues))
            else:
                validation_results["coordination_status"] = "FAILURE"
                self.logger.error("Coordination validation: Multiple issues detected", issue_count=len(issues))

            self.logger.info(
                "Final quality metrics",
                total_findings=len(vulnerabilities),
                high_confidence=confidence_dist["high"],
                medium_confidence=confidence_dist["medium"],
                low_confidence=confidence_dist["low"],
                duplicate_groups=len(excessive_duplicates),
                metadata_issues=metadata_issues,
            )

            return validation_results

        except Exception as e:
            self.logger.error("Coordination validation failed", error=str(e))
            return {
                "coordination_status": "ERROR",
                "issues_detected": [f"Validation error: {e}"],
                "quality_metrics": {},
                "recommendations": ["Fix coordination validation system"],
            }
