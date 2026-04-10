"""DynamicPackageFilter - standalone class for APK file classification."""

from typing import Dict, List, Any


class DynamicPackageFilter:
    """
    **ENHANCED DYNAMIC FILTERING**: Fast, efficient filtering with configurable sensitivity

    Now supports configurable filtering sensitivity.
    """

    def __init__(self, target_package: str, app_structure: Dict, logger, config_manager=None):
        self.target_package = target_package
        self.app_structure = app_structure
        self.logger = logger

        # **ENHANCEMENT**: Add configurable filtering support
        try:
            from core.cross_apk_filter_config import get_default_cross_apk_config

            self.config_manager = config_manager or get_default_cross_apk_config()
            self.logger.info(
                f"**ENHANCED FILTERING**: Using {self.config_manager.config.sensitivity.value} sensitivity"
            )
        except ImportError:
            self.config_manager = None
            self.logger.warning("Cross-APK filter config not available - using default behavior")

        # Simple target package path for fast matching
        self.target_path = target_package.replace(".", "/")

        # Known cross-APK patterns (minimal set)
        self.cross_apk_indicators = ["injuredandroid", "secretdiary", "corellium", "b3nac", "ennesoft"]

        # Library indicators
        self.library_indicators = ["google", "android", "support", "androidx", "okhttp", "retrofit"]

        # Add configurable indicators if available
        if self.config_manager:
            self.cross_apk_indicators.extend(self.config_manager.config.additional_cross_apk_indicators)
            self.library_indicators.extend(self.config_manager.config.additional_library_indicators)

    def classify_file(self, file_path: str, relative_path: str) -> Dict[str, Any]:
        """
        **ENHANCED CLASSIFICATION**: Fast heuristics with configurable sensitivity

        Now applies configurable filtering sensitivity for Solution 6 compliance.
        """
        path_lower = relative_path.lower()

        # **Fast App Detection**: Direct package match
        if self.target_path in relative_path:
            base_result = {
                "category": "app",
                "confidence": 1.0,
                "priority": 100,
                "reasons": [f"Direct target package match: {self.target_path}"],
                "should_include": True,
            }

        # **Fast Cross-APK Detection**: Known problematic patterns
        elif any(indicator in path_lower for indicator in self.cross_apk_indicators):
            matched_indicator = next(indicator for indicator in self.cross_apk_indicators if indicator in path_lower)
            base_result = {
                "category": "cross_apk",
                "confidence": 0.9,
                "priority": 0,
                "reasons": [f"Cross-APK indicator: {matched_indicator}"],
                "should_include": False,
            }

        # **Fast Library Detection**: Common library patterns
        elif any(indicator in path_lower for indicator in self.library_indicators):
            matched_indicator = next(indicator for indicator in self.library_indicators if indicator in path_lower)
            base_result = {
                "category": "library",
                "confidence": 0.7,
                "priority": 50,
                "reasons": [f"Library indicator: {matched_indicator}"],
                "should_include": True,
            }

        # **ADVANCED UNKNOWN APP DETECTION**: Enhanced heuristics for cross-APK detection
        else:
            base_result = self._analyze_unknown_file(relative_path, file_path)

        # **ENHANCEMENT**: Apply configurable filtering if available
        # BUT: Advanced detection takes precedence over configuration
        if self.config_manager and base_result.get("detection_method") != "advanced_heuristics":
            enhanced_decision = self.config_manager.get_filtering_decision(base_result, file_path, self.target_package)

            # Merge enhanced decision with base result
            base_result.update(
                {
                    "enhanced_should_include": enhanced_decision["enhanced_should_include"],
                    "enhanced_confidence": enhanced_decision["enhanced_confidence"],
                    "configuration_applied": True,
                    "sensitivity_level": enhanced_decision["sensitivity_level"],
                    "thresholds_used": enhanced_decision["thresholds_used"],
                }
            )

            # Use enhanced decision for final should_include
            base_result["should_include"] = enhanced_decision["enhanced_should_include"]
        elif base_result.get("detection_method") == "advanced_heuristics":
            # Advanced detection - preserve the decision
            base_result.update(
                {
                    "configuration_applied": False,
                    "advanced_detection_preserved": True,
                    "override_reason": "Advanced heuristics take precedence over configuration",
                }
            )

        return base_result

    def _analyze_unknown_file(self, relative_path: str, file_path: str) -> Dict[str, Any]:
        """
        **ADVANCED UNKNOWN APP DETECTION**

        Uses multiple heuristics to detect unknown cross-APK files:
        1. Package structure analysis
        2. Reverse domain analysis
        3. Statistical outlier detection
        4. Naming convention analysis
        5. File distribution patterns
        """
        reasons = []
        cross_apk_score = 0.0

        # Convert file path to package notation for analysis
        package_path = relative_path.replace("/", ".").replace(".java", "").replace(".kt", "")
        package_parts = [p for p in package_path.split(".") if p and not p.startswith("com") or p == "com"]

        # **1. PACKAGE STRUCTURE ANALYSIS**
        structure_score = self._analyze_package_structure(package_parts, relative_path)
        cross_apk_score += structure_score
        if structure_score > 0.3:
            reasons.append(f"Package structure mismatch (score: {structure_score:.2f})")

        # **2. REVERSE DOMAIN ANALYSIS**
        domain_score = self._analyze_domain_mismatch(package_parts, relative_path)
        cross_apk_score += domain_score
        if domain_score > 0.4:
            reasons.append(f"Different organization domain (score: {domain_score:.2f})")

        # **3. STATISTICAL OUTLIER DETECTION**
        outlier_score = self._detect_statistical_outlier(package_parts, relative_path)
        cross_apk_score += outlier_score
        if outlier_score > 0.2:
            reasons.append(f"Statistical outlier package (score: {outlier_score:.2f})")

        # **4. NAMING CONVENTION ANALYSIS**
        naming_score = self._analyze_naming_patterns(package_parts, relative_path)
        cross_apk_score += naming_score
        if naming_score > 0.3:
            reasons.append(f"Suspicious naming pattern (score: {naming_score:.2f})")

        # **5. FILE DISTRIBUTION ANALYSIS**
        distribution_score = self._analyze_file_distribution(package_parts, relative_path)
        cross_apk_score += distribution_score
        if distribution_score > 0.2:
            reasons.append(f"Isolated file cluster (score: {distribution_score:.2f})")

        # **FINAL CLASSIFICATION DECISION**
        total_score = min(cross_apk_score, 1.0)  # Cap at 1.0

        if total_score >= 0.7:
            # High confidence cross-APK detection
            return {
                "category": "cross_apk_detected",
                "confidence": total_score,
                "priority": 0,
                "reasons": ["ADVANCED DETECTION: Unknown cross-APK app"] + reasons,
                "should_include": False,
                "detection_method": "advanced_heuristics",
                "heuristic_scores": {
                    "structure": structure_score,
                    "domain": domain_score,
                    "outlier": outlier_score,
                    "naming": naming_score,
                    "distribution": distribution_score,
                    "total": total_score,
                },
            }
        elif total_score >= 0.4:
            # Medium confidence - suspicious but include with warning
            return {
                "category": "suspicious_unknown",
                "confidence": 0.6 - (total_score * 0.2),  # Reduce confidence based on suspicion
                "priority": 15,
                "reasons": ["ADVANCED DETECTION: Suspicious unknown file"] + reasons,
                "should_include": True,
                "detection_method": "advanced_heuristics",
                "requires_review": True,
                "heuristic_scores": {
                    "structure": structure_score,
                    "domain": domain_score,
                    "outlier": outlier_score,
                    "naming": naming_score,
                    "distribution": distribution_score,
                    "total": total_score,
                },
            }
        else:
            # Low suspicion - likely legitimate unknown file
            return {
                "category": "unknown_legitimate",
                "confidence": 0.5 + (0.3 * (1 - total_score)),  # Higher confidence if less suspicious
                "priority": 25,
                "reasons": ["ADVANCED DETECTION: Unknown file (likely legitimate)"]
                + (reasons if reasons else ["Low suspicion score"]),
                "should_include": True,
                "detection_method": "advanced_heuristics",
                "heuristic_scores": {
                    "structure": structure_score,
                    "domain": domain_score,
                    "outlier": outlier_score,
                    "naming": naming_score,
                    "distribution": distribution_score,
                    "total": total_score,
                },
            }

    def _analyze_package_structure(self, package_parts: List[str], relative_path: str) -> float:
        """Analyze package structure for cross-APK indicators."""
        if not package_parts:
            return 0.0

        target_parts = self.target_package.split(".")
        score = 0.0

        # Check reverse domain notation (com.company.app vs org.other.app)
        if len(package_parts) >= 2 and len(target_parts) >= 2:
            # Compare top-level domain
            if package_parts[0] != target_parts[0]:  # Different TLD (com vs org)
                score += 0.3

            # Compare organization/company name
            if len(package_parts) >= 2 and len(target_parts) >= 2:
                if package_parts[1] != target_parts[1]:  # Different company
                    score += 0.4

        # Check package depth variance
        target_depth = len(target_parts)
        file_depth = len(package_parts)
        depth_diff = abs(file_depth - target_depth)

        if depth_diff > 3:  # Significantly different depth
            score += min(0.2, depth_diff * 0.05)

        return min(score, 1.0)

    def _analyze_domain_mismatch(self, package_parts: List[str], relative_path: str) -> float:
        """Detect organization/domain mismatches."""
        if len(package_parts) < 2:
            return 0.0

        target_parts = self.target_package.split(".")
        if len(target_parts) < 2:
            return 0.0

        score = 0.0

        # Extract domain components
        file_domain = ".".join(package_parts[:2]) if len(package_parts) >= 2 else ""
        target_domain = ".".join(target_parts[:2]) if len(target_parts) >= 2 else ""

        if file_domain and target_domain and file_domain != target_domain:
            # Check for known test/demo domains
            test_domains = ["com.example", "org.test", "net.demo", "io.github", "com.github"]
            if file_domain in test_domains:
                score += 0.5  # Test domains are suspicious
            else:
                score += 0.4  # Different real domain

        # Check for suspicious organization names
        if len(package_parts) >= 2:
            org_name = package_parts[1].lower()
            suspicious_orgs = ["test", "demo", "example", "sample", "temp", "debug", "hack", "exploit"]
            if org_name in suspicious_orgs:
                score += 0.3

        return min(score, 1.0)

    def _detect_statistical_outlier(self, package_parts: List[str], relative_path: str) -> float:
        """Detect statistically rare packages that might be cross-APK."""
        if not hasattr(self, "app_structure") or not self.app_structure:
            return 0.0

        score = 0.0

        # Extract root package for frequency analysis
        if package_parts:
            root_package = package_parts[0] if len(package_parts) == 1 else ".".join(package_parts[:2])

            # Count occurrences of this package pattern in app structure
            total_files = len(self.app_structure.get("files", []))
            if total_files > 10:  # Only analyze if we have sufficient data
                package_files = sum(
                    1 for f in self.app_structure.get("files", []) if root_package in f.replace("/", ".")
                )

                frequency = package_files / total_files

                # If this package appears in <5% of files, it's suspicious
                if frequency < 0.05 and package_files < 3:
                    score += 0.3

                # If it's completely isolated (only 1 file), very suspicious
                if package_files == 1:
                    score += 0.2

        return min(score, 1.0)

    def _analyze_naming_patterns(self, package_parts: List[str], relative_path: str) -> float:
        """Analyze naming patterns for suspicious indicators."""
        import re as _re

        score = 0.0

        # Check for suspicious keywords in package names
        suspicious_keywords = [
            "hack",
            "exploit",
            "crack",
            "bypass",
            "inject",
            "payload",
            "malware",
            "virus",
            "trojan",
            "backdoor",
            "rootkit",
            "test",
            "demo",
            "sample",
            "example",
            "temp",
            "debug",
        ]

        package_text = ".".join(package_parts).lower()
        for keyword in suspicious_keywords:
            if keyword in package_text:
                if keyword in ["hack", "exploit", "crack", "malware", "virus"]:
                    score += 0.4  # High suspicion for malicious terms
                else:
                    score += 0.2  # Medium suspicion for test terms

        # Check for version-like suffixes (common in test apps)
        if _re.search(r"v\d+|_\d+\.\d+|test\d+", package_text):
            score += 0.2

        # Check for random-looking identifiers
        if any(
            len(part) > 10 and part.isalnum() and sum(c.isdigit() for c in part) > len(part) * 0.3
            for part in package_parts
        ):
            score += 0.3  # Random identifiers are suspicious

        return min(score, 1.0)

    def _analyze_file_distribution(self, package_parts: List[str], relative_path: str) -> float:
        """Analyze file distribution patterns for isolation detection."""
        if not hasattr(self, "app_structure") or not self.app_structure:
            return 0.0

        score = 0.0

        if package_parts:
            # Check if this package is isolated from main app structure
            base_package = package_parts[0] if len(package_parts) >= 1 else ""
            target_base = self.target_package.split(".")[0] if self.target_package else ""

            if base_package and target_base and base_package != target_base:
                # Different base package - check isolation
                related_files = [f for f in self.app_structure.get("files", []) if base_package in f.replace("/", ".")]

                if len(related_files) <= 3:  # Very isolated
                    score += 0.3
                elif len(related_files) <= 10:  # Somewhat isolated
                    score += 0.1

        return min(score, 1.0)
