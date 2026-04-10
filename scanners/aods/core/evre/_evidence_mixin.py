"""Code evidence extraction, source file search, manifest snippets."""

import os
import re
from typing import Dict, List, Optional


class EvidenceMixin:
    """Code evidence extraction from decompiled source files."""

    def _extract_code_evidence(self, content: str, pattern_info: Dict) -> Dict:
        """Extract actual code evidence from decompiled source files"""
        evidence = {
            "file_path": "unknown",
            "line_number": 0,
            "method_name": "",
            "class_name": "",
            "vulnerable_code": "",
            "surrounding_context": "",
            "pattern_matches": [],
        }

        if not self.source_files:
            self.logger.debug("No source files available for evidence extraction")
            return evidence

        # Strategy 1: Find relevant source file using pattern matching
        file_info = self._find_relevant_source_file(content, pattern_info)
        if file_info:
            evidence["file_path"] = self._safe_extract(file_info, "path", "unknown", str)

            code_match = self._find_vulnerable_code_in_file(file_info, pattern_info)
            if code_match:
                evidence.update(code_match)
                self.logger.debug(f"Found evidence in {evidence['file_path']} at line {evidence.get('line_number', 0)}")
                return evidence

        # Strategy 2: Search all high-priority files if specific file search failed
        app_files = [
            f for f in self.source_files.values() if f.get("is_app_file", False) and f.get("priority_score", 0) >= 100
        ]

        for file_info in app_files[:5]:
            code_match = self._find_vulnerable_code_in_file(file_info, pattern_info)
            if code_match:
                evidence["file_path"] = self._safe_extract(file_info, "path", "unknown", str)
                evidence.update(code_match)
                self.logger.debug(
                    f"Found evidence via app file scan in {evidence['file_path']} at line {evidence.get('line_number', 0)}"  # noqa: E501
                )
                return evidence

        # Strategy 3: If still no evidence, search based on content keywords
        if "file_path" in evidence and evidence["file_path"] != "unknown":
            evidence = self._extract_basic_evidence_from_content(content, evidence["file_path"])

        return evidence

    def _extract_basic_evidence_from_content(self, content: str, file_path: str) -> Dict:
        """Extract actual source code instead of descriptions"""
        evidence = {
            "file_path": file_path,
            "line_number": 1,
            "method_name": "",
            "class_name": "",
            "vulnerable_code": "",
            "surrounding_context": "",
            "pattern_matches": [],
        }

        actual_code = self._extract_actual_source_code(file_path, content)
        if actual_code:
            evidence.update(actual_code)
        else:
            if file_path.endswith("AndroidManifest.xml"):
                evidence["vulnerable_code"] = self._extract_manifest_snippet(file_path, content)
                evidence["surrounding_context"] = "AndroidManifest.xml configuration"
            else:
                evidence["vulnerable_code"] = "[Configuration/Metadata Issue - No Source Code Location]"
                evidence["surrounding_context"] = "Issue detected in application configuration or metadata"

        if file_path and "/" in file_path:
            file_name = file_path.split("/")[-1]
            if file_name.endswith(".java"):
                evidence["class_name"] = file_name[:-5]

        return evidence

    def _find_relevant_source_file(self, content: str, pattern_info: Dict) -> Optional[Dict]:
        """Find the most relevant source file based on vulnerability patterns and keywords"""
        if not self.source_files:
            return None

        content_keywords = self._safe_extract(pattern_info, "content_keywords", [], list)
        patterns_to_check = self._safe_extract(pattern_info, "patterns", [], list)
        matched_pattern = self._safe_extract(pattern_info, "matched_pattern", None, str)
        if matched_pattern:
            patterns_to_check.append(matched_pattern)

        vulnerability_type = self._safe_extract(pattern_info, "type", "", str).lower()

        if "crypto" in vulnerability_type:
            content_keywords.extend(["md5", "sha1", "des", "cipher", "messagedigest", "encryption"])
        elif "secret" in vulnerability_type or "password" in vulnerability_type:
            content_keywords.extend(["password", "secret", "key", "token", "credential"])
        elif "platform" in vulnerability_type:
            content_keywords.extend(["permission", "exported", "activity", "service", "receiver"])

        file_scores = []
        processed_paths = set()

        for filename, file_info in self.source_files.items():
            full_path = self._safe_extract(file_info, "full_path", "", str)
            if full_path in processed_paths:
                continue
            processed_paths.add(full_path)

            score = 0
            file_content_raw = self._safe_extract(file_info, "content", "", str)
            file_content = file_content_raw.lower()
            file_path = self._safe_extract(file_info, "path", filename, str).lower()

            priority_score = self._safe_extract(file_info, "priority_score", 1, int)
            is_app_file = self._safe_extract(file_info, "is_app_file", False, bool)

            score += priority_score

            for pattern in patterns_to_check:
                if pattern and re.search(pattern, file_content_raw, re.IGNORECASE):
                    pattern_boost = 100 if is_app_file else 10
                    score += pattern_boost

            for keyword in content_keywords:
                keyword_count = file_content.count(keyword.lower())
                score += keyword_count * 2

            vulnerability_terms = [
                "insecure",
                "crypto",
                "storage",
                "network",
                "sql",
                "logging",
                "auth",
                "session",
                "security",
                "vulnerability",
                "exploit",
            ]
            for term in vulnerability_terms:
                if term in file_path:
                    score += 5

            security_patterns = [
                "activity",
                "service",
                "provider",
                "receiver",
                "helper",
                "manager",
                "util",
                "database",
                "db",
                "client",
                "api",
            ]
            for pattern in security_patterns:
                if pattern in file_path:
                    score += 1

            if score > 0:
                file_scores.append((score, file_info))

        if file_scores:
            file_scores.sort(key=lambda x: x[0], reverse=True)
            return file_scores[0][1]

        return None

    def _find_vulnerable_code_in_file(self, file_info: Dict, pattern_info: Dict) -> Optional[Dict]:
        """Find vulnerable code snippet in the source file"""
        self._safe_extract(file_info, "content", "", str)
        lines = self._safe_extract(file_info, "lines", [], list)

        patterns_to_check = self._safe_extract(pattern_info, "patterns", [], list)
        matched_pattern = self._safe_extract(pattern_info, "matched_pattern", None, str)
        if matched_pattern:
            patterns_to_check.append(matched_pattern)

        vulnerability_type = self._safe_extract(pattern_info, "type", "", str).lower()
        if "crypto" in vulnerability_type or "md5" in vulnerability_type:
            patterns_to_check.extend(
                [
                    r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
                    r'MessageDigest\.getInstance\s*\(\s*["\']SHA1["\']',
                    r'Cipher\.getInstance\s*\(\s*["\'][^"\']*DES[^"\']*["\']',
                ]
            )
        elif "secret" in vulnerability_type or "password" in vulnerability_type:
            patterns_to_check.extend(
                [r'password\s*=\s*["\'][^"\']+["\']', r'secret\s*=\s*["\'][^"\']+["\']', r'key\s*=\s*["\'][^"\']+["\']']
            )

        for pattern in patterns_to_check:
            if not pattern:
                continue

            for line_num, line in enumerate(lines, 1):
                if not isinstance(line, str):
                    continue

                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    start_line = max(0, line_num - 5)
                    end_line = min(len(lines), line_num + 5)
                    context_lines = lines[start_line:end_line]

                    method_name = self._find_containing_method(lines, line_num)
                    class_name = self._find_containing_class(lines, line_num)

                    return {
                        "line_number": line_num,
                        "method_name": method_name,
                        "class_name": class_name,
                        "vulnerable_code": line.strip(),
                        "surrounding_context": "\n".join(str(line) for line in context_lines if isinstance(line, str)),
                        "pattern_matches": [match.group(0)],
                    }

        return None

    def _find_containing_method(self, lines: List[str], target_line: int) -> str:
        """Find the method containing the target line"""
        for i in range(target_line - 1, -1, -1):
            match = re.search(r"(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\([^)]*\)\s*\{", lines[i])
            if match:
                return match.group(1)
        return ""

    def _find_containing_class(self, lines: List[str], target_line: int) -> str:
        """Find the class containing the target line"""
        for i in range(target_line - 1, -1, -1):
            match = re.search(r"(?:public|private)?\s*class\s+(\w+)", lines[i])
            if match:
                return match.group(1)
        return ""

    def _extract_actual_source_code(self, file_path: str, description_content: str) -> Optional[Dict]:
        """Extract real source code for vulnerabilities"""
        if not self.source_files or not file_path:
            return None

        if file_path != "unknown":
            direct_match = self._find_source_file_by_path(file_path)
            if direct_match:
                code_snippet = self._extract_relevant_code_from_file(direct_match, description_content)
                if code_snippet:
                    return code_snippet

        app_files = [f for f in self.source_files.get("files", []) if self._is_app_source_file(f.get("path", ""))]

        for file_info in app_files[:10]:
            code_snippet = self._extract_relevant_code_from_file(file_info, description_content)
            if code_snippet:
                return code_snippet

        return None

    def _find_source_file_by_path(self, target_path: str) -> Optional[Dict]:
        """Find source file information by path"""
        for file_info in self.source_files.get("files", []):
            file_path = file_info.get("path", "")
            if target_path in file_path or file_path.endswith(target_path.split("/")[-1]):
                return file_info
        return None

    def _is_app_source_file(self, file_path: str) -> bool:
        """Check if file is part of the target application (not library/framework)"""
        if not file_path:
            return False

        app_indicators = [self.target_package.replace(".", "/"), "src/main/java", "/java/", "/kotlin/"]

        library_indicators = ["android/support", "androidx/", "com/google", "okhttp", "retrofit"]

        for indicator in app_indicators:
            if indicator in file_path:
                return True

        for indicator in library_indicators:
            if indicator in file_path:
                return False

        return False

    def _extract_relevant_code_from_file(self, file_info: Dict, description_content: str) -> Optional[Dict]:
        """Extract relevant code snippet from a source file based on vulnerability context"""
        file_path = file_info.get("path", "")
        lines = file_info.get("lines", [])

        if not lines:
            return None

        keywords = self._extract_vulnerability_keywords(description_content)

        for line_num, line in enumerate(lines, 1):
            if not isinstance(line, str):
                continue

            line_lower = line.lower()

            for keyword in keywords:
                if keyword.lower() in line_lower:
                    return self._create_code_evidence(lines, line_num, file_path, line)

            vulnerability_patterns = [
                r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
                r'password\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r"rawQuery\s*\(",
                r"execSQL\s*\(",
                r"rawQuery\s*\(\s*sb[0-9]*\s*,",
                r"rawQuery\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\.toString\s*\(\s*\)",
                r'append\s*\(\s*["\']SELECT.*FROM.*WHERE.*["\']',
                r"append\s*\(\s*editText.*getText",
                r'android:exported\s*=\s*["\']true["\']',
                r'android:allowBackup\s*=\s*["\']true["\']',
            ]

            for pattern in vulnerability_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    return self._create_code_evidence(lines, line_num, file_path, line)

        return None

    def _extract_vulnerability_keywords(self, description: str) -> List[str]:
        """Extract relevant keywords from vulnerability description for code search"""
        keywords = []

        if "md5" in description.lower() or "hash" in description.lower():
            keywords.extend(["MD5", "MessageDigest", "getInstance"])

        if "secret" in description.lower() or "password" in description.lower():
            keywords.extend(["password", "secret", "key"])

        if "sql" in description.lower() or "injection" in description.lower():
            keywords.extend(
                [
                    "rawQuery",
                    "execSQL",
                    "query",
                    "StringBuilder",
                    "append",
                    "SELECT",
                    "WHERE",
                    "FROM",
                    "editText",
                    "getText",
                ]
            )

        if "exported" in description.lower():
            keywords.extend(["exported", "android:exported"])

        if "backup" in description.lower():
            keywords.extend(["allowBackup", "android:allowBackup"])

        if "sdk" in description.lower():
            keywords.extend(["targetSdkVersion", "minSdkVersion"])

        return keywords

    def _create_code_evidence(self, lines: List[str], line_num: int, file_path: str, matched_line: str) -> Dict:
        """Create code evidence structure with actual source code"""
        start_line = max(0, line_num - 3)
        end_line = min(len(lines), line_num + 3)
        context_lines = lines[start_line:end_line]

        method_name = self._find_containing_method(lines, line_num)
        class_name = self._find_containing_class(lines, line_num)

        return {
            "file_path": file_path,
            "line_number": line_num,
            "method_name": method_name,
            "class_name": class_name,
            "vulnerable_code": matched_line.strip(),
            "surrounding_context": "\n".join(str(line) for line in context_lines if isinstance(line, str)),
            "pattern_matches": [matched_line.strip()],
        }

    def _extract_manifest_snippet(self, file_path: str, description_content: str) -> str:
        """Extract relevant XML snippet from AndroidManifest.xml"""
        manifest_paths = []
        # Prefer current APK's decompiled manifest (avoids cross-app contamination)
        if hasattr(self, "decompiled_path") and self.decompiled_path:
            scoped = os.path.join(self.decompiled_path, "AndroidManifest.xml")
            if os.path.exists(scoped):
                manifest_paths.append(scoped)
        # Fallback: workspace-level manifest only (no glob across other APKs)
        workspace_manifest = os.path.join(self.workspace_dir, "AndroidManifest.xml")
        if workspace_manifest not in manifest_paths:
            manifest_paths.append(workspace_manifest)

        for manifest_path in manifest_paths:
            if os.path.exists(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
                        manifest_content = f.read()

                    if "sdk" in description_content.lower():
                        sdk_match = re.search(r"<uses-sdk[^>]*>", manifest_content, re.IGNORECASE)
                        if sdk_match:
                            return sdk_match.group(0)

                    if "backup" in description_content.lower():
                        backup_match = re.search(
                            r'android:allowBackup\s*=\s*["\'][^"\']*["\']', manifest_content, re.IGNORECASE
                        )
                        if backup_match:
                            app_start = manifest_content.rfind("<application", 0, backup_match.start())
                            if app_start != -1:
                                app_end = manifest_content.find(">", backup_match.end())
                                if app_end != -1:
                                    return manifest_content[app_start : app_end + 1]
                            return backup_match.group(0)

                    if "exported" in description_content.lower():
                        exported_match = re.search(
                            r'android:exported\s*=\s*["\']true["\']', manifest_content, re.IGNORECASE
                        )
                        if exported_match:
                            component_start = manifest_content.rfind("<", 0, exported_match.start())
                            component_end = manifest_content.find(">", exported_match.end())
                            if component_start != -1 and component_end != -1:
                                return manifest_content[component_start : component_end + 1]
                            return exported_match.group(0)

                    return manifest_content[:200] + "..." if len(manifest_content) > 200 else manifest_content

                except Exception as e:
                    self.logger.debug(f"Failed to read manifest {manifest_path}: {e}")
                    continue

        return "[AndroidManifest.xml - Unable to locate file for code extraction]"
