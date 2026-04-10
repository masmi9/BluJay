"""
Enhanced Unicode Analyzer for AODS Framework - Advanced Unicode Security Analysis.

This module provides analysis of Unicode-based vulnerabilities
in Android applications, specifically targeting advanced Unicode attack vectors
and sophisticated normalization-based vulnerabilities.
"""

import re
import json
import time
import logging
import unicodedata
from typing import Dict, List, Any, Tuple

from rich.console import Console
from rich.text import Text
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

logger = logging.getLogger(__name__)

# Professional Confidence Calculation System for Unicode Security Analysis


class UnicodeSecurityConfidenceCalculator:
    """
    confidence calculation system for Unicode security analysis findings.

    Calculates dynamic confidence scores based on:
    - Unicode pattern reliability and attack vector sophistication
    - Evidence strength from multiple Unicode analysis methods
    - Context awareness based on Unicode usage patterns and security implications
    - Cross-validation from multiple Unicode security detection techniques
    - Analysis depth and comprehensiveness of Unicode vulnerability assessment
    """

    def __init__(self):
        """Initialize the confidence calculator with Unicode pattern reliability and evidence weights."""

        # Evidence factor weights (must sum to 1.0)
        self.evidence_weights = {
            "pattern_reliability": 0.30,  # Reliability of Unicode attack patterns
            "evidence_strength": 0.25,  # Quality and quantity of Unicode evidence
            "context_awareness": 0.20,  # Context appropriateness and security relevance
            "cross_validation": 0.15,  # Multiple Unicode validation sources
            "analysis_depth": 0.10,  # Comprehensiveness of Unicode analysis
        }

        # Pattern reliability database based on Unicode attack sophistication
        self.pattern_reliability = {
            "dotless_i_collision": 0.95,  # Very high reliability for dotless i attacks
            "homograph_attack": 0.92,  # High reliability for homograph attacks
            "normalization_attack": 0.89,  # Good reliability for normalization attacks
            "encoding_bypass": 0.87,  # Good reliability for encoding bypass
            "injection_attack": 0.85,  # Good reliability for injection attacks
            "mixed_script_attack": 0.82,  # Medium reliability for mixed script attacks
            "zero_width_attack": 0.90,  # High reliability for zero-width attacks
            "direction_override": 0.88,  # Good reliability for direction override
            "visual_spoofing": 0.85,  # Good reliability for visual spoofing
            "confusable_characters": 0.83,  # Good reliability for confusable chars
            "bidi_attack": 0.91,  # High reliability for bidirectional attacks
            "combining_characters": 0.86,  # Good reliability for combining chars
            "punycode_attack": 0.94,  # Very high reliability for punycode attacks
            "unicode_smuggling": 0.88,  # Good reliability for Unicode smuggling
            "normalization_bypass": 0.90,  # High reliability for normalization bypass
        }

        # Context factors for Unicode security assessment
        self.context_factors = {
            "usage_context": {
                "user_input_validation": 0.9,  # High risk context
                "authentication_system": 0.95,  # Very high risk context
                "url_handling": 0.92,  # High risk context
                "file_system_access": 0.88,  # Good risk context
                "network_communication": 0.85,  # Good risk context
                "display_rendering": 0.80,  # Medium risk context
                "configuration_files": 0.75,  # Medium risk context
                "log_processing": 0.70,  # Medium risk context
                "data_storage": 0.82,  # Good risk context
                "unknown": 0.60,  # Default risk context
            },
            "attack_sophistication": {
                "advanced_normalization": 0.95,  # Very sophisticated attack
                "complex_homograph": 0.92,  # High sophistication
                "mixed_encoding": 0.89,  # Good sophistication
                "simple_bypass": 0.75,  # Medium sophistication
                "basic_injection": 0.70,  # Medium sophistication
                "visual_similarity": 0.85,  # Good sophistication
                "unknown": 0.60,  # Default sophistication
            },
            "security_impact": {
                "authentication_bypass": 0.98,  # Critical security impact
                "authorization_bypass": 0.95,  # Very high security impact
                "data_exfiltration": 0.92,  # High security impact
                "code_injection": 0.90,  # High security impact
                "privilege_escalation": 0.88,  # Good security impact
                "information_disclosure": 0.85,  # Good security impact
                "denial_of_service": 0.80,  # Medium security impact
                "data_corruption": 0.78,  # Medium security impact
                "unknown": 0.60,  # Default security impact
            },
        }

        # Validation impact factors
        self.validation_impact = {
            "static_analysis": 0.75,  # Medium validation impact
            "dynamic_analysis": 0.85,  # Good validation impact
            "manual_review": 0.95,  # Very high validation impact
            "automated_testing": 0.70,  # Medium validation impact
            "pattern_matching": 0.65,  # Medium validation impact
            "context_analysis": 0.80,  # Good validation impact
            "normalization_testing": 0.90,  # High validation impact
            "encoding_verification": 0.85,  # Good validation impact
            "homograph_detection": 0.88,  # Good validation impact
            "unicode_validation": 0.92,  # High validation impact
        }

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate dynamic confidence score based on Unicode security evidence factors.

        Args:
            evidence: Dictionary containing Unicode security evidence factors:
                - pattern_type: Type of Unicode attack pattern detected
                - usage_context: Context where Unicode vulnerability is found
                - attack_sophistication: Sophistication level of the attack
                - security_impact: Security impact of the vulnerability
                - validation_methods: List of validation methods used
                - evidence_quality: Quality of evidence (0.0-1.0)
                - evidence_quantity: Quantity of evidence (normalized)
                - analysis_depth: Depth of Unicode analysis performed (0.0-1.0)

        Returns:
            float: Confidence score between 0.0 and 1.0
        """

        # Factor 1: Pattern Reliability (30%)
        pattern_type = evidence.get("pattern_type", "unknown")
        pattern_reliability = self.pattern_reliability.get(pattern_type, 0.5)
        pattern_score = pattern_reliability

        # Factor 2: Evidence Strength (25%)
        evidence_quality = evidence.get("evidence_quality", 0.5)
        evidence_quantity = min(evidence.get("evidence_quantity", 1), 5) / 5.0  # Normalize to 0-1
        evidence_score = (evidence_quality * 0.7) + (evidence_quantity * 0.3)

        # Factor 3: Context Awareness (20%)
        usage_context = evidence.get("usage_context", "unknown")
        attack_sophistication = evidence.get("attack_sophistication", "unknown")
        security_impact = evidence.get("security_impact", "unknown")

        context_factor = self.context_factors["usage_context"].get(usage_context, 0.6)
        sophistication_factor = self.context_factors["attack_sophistication"].get(attack_sophistication, 0.6)
        impact_factor = self.context_factors["security_impact"].get(security_impact, 0.6)

        context_score = (context_factor * 0.4) + (sophistication_factor * 0.3) + (impact_factor * 0.3)

        # Factor 4: Cross-Validation (15%)
        validation_methods = evidence.get("validation_methods", [])
        cross_validation_score = 0.0
        if validation_methods:
            method_impacts = [self.validation_impact.get(method, 0.5) for method in validation_methods]
            cross_validation_score = min(sum(method_impacts) / len(method_impacts), 1.0)

        # Factor 5: Analysis Depth (10%)
        analysis_depth = evidence.get("analysis_depth", 0.5)
        depth_score = min(analysis_depth, 1.0)

        # Calculate weighted confidence score
        confidence = (
            pattern_score * self.evidence_weights["pattern_reliability"]
            + evidence_score * self.evidence_weights["evidence_strength"]
            + context_score * self.evidence_weights["context_awareness"]
            + cross_validation_score * self.evidence_weights["cross_validation"]
            + depth_score * self.evidence_weights["analysis_depth"]
        )

        # Apply Unicode-specific adjustments
        confidence = self._apply_unicode_adjustments(confidence, evidence)

        # Ensure confidence is within valid range
        return max(0.0, min(1.0, confidence))

    def _apply_unicode_adjustments(self, base_confidence: float, evidence: Dict[str, Any]) -> float:
        """Apply Unicode-specific confidence adjustments."""
        adjusted_confidence = base_confidence

        # Boost confidence for high-impact Unicode attacks
        if evidence.get("security_impact") == "authentication_bypass":
            adjusted_confidence *= 1.1
        elif evidence.get("security_impact") == "authorization_bypass":
            adjusted_confidence *= 1.05

        # Reduce confidence for low-evidence scenarios
        if evidence.get("evidence_quantity", 1) < 2:
            adjusted_confidence *= 0.9

        # Boost confidence for sophisticated attacks
        if evidence.get("attack_sophistication") == "advanced_normalization":
            adjusted_confidence *= 1.08
        elif evidence.get("attack_sophistication") == "complex_homograph":
            adjusted_confidence *= 1.05

        return adjusted_confidence

    def get_confidence_threshold(self, context: str = "standard") -> float:
        """Get dynamic confidence threshold based on Unicode security context."""

        thresholds = {
            "critical": 0.9,  # Critical Unicode security contexts
            "high": 0.8,  # High Unicode security contexts
            "standard": 0.7,  # Standard Unicode security contexts
            "medium": 0.6,  # Medium Unicode security contexts
            "low": 0.5,  # Low Unicode security contexts
            "development": 0.4,  # Development Unicode contexts
        }

        return thresholds.get(context, 0.7)

    def calculate_risk_level(self, confidence: float, context: str = "standard") -> str:
        """Calculate risk level based on confidence and Unicode security context."""

        # Dynamic thresholds based on Unicode security context
        if context == "critical":
            thresholds = {"CRITICAL": 0.85, "HIGH": 0.75, "MEDIUM": 0.65, "LOW": 0.55}
        elif context == "high":
            thresholds = {"CRITICAL": 0.90, "HIGH": 0.80, "MEDIUM": 0.70, "LOW": 0.60}
        else:  # standard, medium, low, development
            thresholds = {"CRITICAL": 0.95, "HIGH": 0.85, "MEDIUM": 0.75, "LOW": 0.65}

        if confidence >= thresholds["CRITICAL"]:
            return "CRITICAL"
        elif confidence >= thresholds["HIGH"]:
            return "HIGH"
        elif confidence >= thresholds["MEDIUM"]:
            return "MEDIUM"
        elif confidence >= thresholds["LOW"]:
            return "LOW"
        else:
            return "INFO"

    def get_pattern_reliability(self, pattern_type: str) -> float:
        """Get reliability score for a specific Unicode pattern type."""
        return self.pattern_reliability.get(pattern_type, 0.5)


class UnicodeAnalyzer:
    """
    Enhanced Unicode analyzer for Android applications with advanced security analysis.

    This analyzer identifies and analyzes sophisticated Unicode-based vulnerabilities in Android
    applications, with particular focus on advanced Unicode collision attacks, normalization
    vulnerabilities, and context-aware Unicode injection techniques that can be exploited to
    circumvent security controls and achieve privilege escalation.
    """

    def __init__(self, apk_context=None):
        """
        Initialize the enhanced Unicode analyzer.

        Args:
            apk_context: APK context object containing application metadata
        """
        self.apk_context = apk_context
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.console = Console()

        # Initialize professional confidence calculator
        self.confidence_calculator = UnicodeSecurityConfidenceCalculator()

        # Enhanced Unicode vulnerability patterns with O(1) lookup optimization
        self.unicode_patterns = {
            "dotless_i": {
                "description": "Advanced dotless i vulnerability - Unicode collision attacks with normalization bypass",
                "patterns": {
                    "\u0130": "Latin Capital Letter I with Dot Above",  # noqa: F601
                    "\u0131": "Latin Small Letter Dotless I",  # noqa: F601
                    "İ": "Capital I with dot (Turkish)",  # noqa: F601
                    "ı": "Dotless i (Turkish)",  # noqa: F601
                    "I": "Regular capital I",  # noqa: F601
                    "i": "Regular lowercase i",  # noqa: F601
                    "\u0049": "Latin Capital Letter I",  # noqa: F601
                    "\u0069": "Latin Small Letter I",  # noqa: F601
                    "\u0130": "Latin Capital Letter I with Dot Above",  # noqa: F601
                    "\u0131": "Latin Small Letter Dotless I",  # noqa: F601
                },
                "test_cases": [
                    ("İnstagram", "INSTAGRAM"),  # Capital I with dot vs regular
                    ("ınstagram", "INSTAGRAM"),  # Dotless i vs regular
                    ("İ", "I"),  # Direct character comparison
                    ("ı", "i"),  # Direct character comparison
                    ("İNSTAGRAM", "INSTAGRAM"),  # Case variation
                    ("ınstagram", "instagram"),  # Lowercase variation
                    ("İ.com", "I.com"),  # Domain context
                    ("ı.net", "i.net"),  # Domain context
                ],
                "severity": "CRITICAL",
                "attack_sophistication": "advanced_normalization",
            },
            "homograph": {
                "description": "Enhanced homograph attack detection with brand protection",
                "dangerous_chars": {
                    # Cyrillic lookalikes
                    "\u0430": "a",  # Cyrillic small letter a vs Latin a
                    "\u043e": "o",  # Cyrillic small letter o vs Latin o
                    "\u0440": "p",  # Cyrillic small letter p vs Latin p
                    "\u0435": "e",  # Cyrillic small letter e vs Latin e
                    "\u0441": "c",  # Cyrillic small letter c vs Latin c
                    "\u0455": "s",  # Cyrillic small letter s vs Latin s
                    "\u0445": "x",  # Cyrillic small letter x vs Latin x
                    "\u0440": "p",  # Cyrillic small letter p vs Latin p
                    "\u0443": "y",  # Cyrillic small letter y vs Latin y
                    "\u043d": "h",  # Cyrillic small letter h vs Latin h
                    # Greek lookalikes
                    "\u03b1": "a",  # Greek small letter alpha vs Latin a
                    "\u03bf": "o",  # Greek small letter omicron vs Latin o
                    "\u03c1": "p",  # Greek small letter rho vs Latin p
                    "\u03c5": "v",  # Greek small letter upsilon vs Latin v
                    # Additional sophisticated lookalikes
                    "\u0561": "a",  # Armenian small letter ayb vs Latin a
                    "\u0585": "o",  # Armenian small letter oh vs Latin o
                    "\u057c": "n",  # Armenian small letter ra vs Latin n
                    "\u0573": "n",  # Armenian small letter cheh vs Latin n
                },
                "suspicious_domains": [
                    "google",
                    "amazon",
                    "microsoft",
                    "apple",
                    "facebook",
                    "twitter",
                    "instagram",
                    "youtube",
                    "linkedin",
                    "github",
                    "paypal",
                    "ebay",
                    "netflix",
                    "spotify",
                    "dropbox",
                    "reddit",
                    "wikipedia",
                    "stackoverflow",
                    "medium",
                    "whatsapp",
                    "telegram",
                    "discord",
                    "slack",
                    "zoom",
                    "banking",
                    "login",
                    "secure",
                    "account",
                    "payment",
                ],
                "severity": "HIGH",
                "attack_sophistication": "complex_homograph",
            },
            "normalization": {
                "description": "Advanced Unicode normalization vulnerabilities with bypass detection",
                "forms": ["NFC", "NFD", "NFKC", "NFKD"],
                "test_strings": [
                    "café",  # Contains composed character
                    "cafe\u0301",  # Contains decomposed character
                    "ﬁle",  # Contains ligature
                    "file",  # Regular characters
                    "Å",  # Composed A with ring above
                    "A\u030a",  # Decomposed A with ring above
                    "ñ",  # Composed n with tilde
                    "n\u0303",  # Decomposed n with tilde
                    "é",  # Composed e with acute
                    "e\u0301",  # Decomposed e with acute
                    "ö",  # Composed o with diaeresis
                    "o\u0308",  # Decomposed o with diaeresis
                ],
                "attack_vectors": [
                    "normalization_bypass",
                    "canonicalization_attack",
                    "form_confusion",
                    "composition_bypass",
                ],
                "severity": "HIGH",
                "attack_sophistication": "advanced_normalization",
            },
            "encoding_bypass": {
                "description": "Advanced character encoding bypass techniques with steganography",
                "bypass_chars": {
                    "\ufeff": "Zero Width No-Break Space (BOM)",
                    "\u200b": "Zero Width Space",
                    "\u200c": "Zero Width Non-Joiner",
                    "\u200d": "Zero Width Joiner",
                    "\u2060": "Word Joiner",
                    "\ufffc": "Object Replacement Character",
                    "\u180e": "Mongolian Vowel Separator",
                    "\u034f": "Combining Grapheme Joiner",
                    "\u2028": "Line Separator",
                    "\u2029": "Paragraph Separator",
                    "\u061c": "Arabic Letter Mark",
                    "\u115f": "Hangul Choseong Filler",
                    "\u1160": "Hangul Jungseong Filler",
                    "\u17b4": "Khmer Vowel Inherent Aq",
                    "\u17b5": "Khmer Vowel Inherent Aa",
                },
                "severity": "HIGH",
                "attack_sophistication": "mixed_encoding",
            },
            "injection": {
                "description": "Advanced Unicode-based injection vulnerabilities with bidirectional attacks",
                "injection_chars": {
                    "\u202e": "Right-to-Left Override",
                    "\u202d": "Left-to-Right Override",
                    "\u202a": "Left-to-Right Embedding",
                    "\u202b": "Right-to-Left Embedding",
                    "\u202c": "Pop Directional Formatting",
                    "\u2066": "Left-to-Right Isolate",
                    "\u2067": "Right-to-Left Isolate",
                    "\u2068": "First Strong Isolate",
                    "\u2069": "Pop Directional Isolate",
                    "\u061c": "Arabic Letter Mark",
                    "\u200e": "Left-to-Right Mark",
                    "\u200f": "Right-to-Left Mark",
                },
                "attack_vectors": [
                    "bidirectional_override",
                    "directional_embedding",
                    "isolate_confusion",
                    "marking_injection",
                ],
                "severity": "CRITICAL",
                "attack_sophistication": "bidi_attack",
            },
            "advanced_patterns": {
                "description": "Advanced Unicode attack patterns with sophisticated evasion techniques",
                "patterns": {
                    "confusable_sequences": {
                        "rn": "m",  # Two chars that look like one
                        "vv": "w",  # Two v's that look like w
                        "cl": "d",  # c and l that look like d
                        "nn": "n",  # Double n confusion
                        "ii": "n",  # Double i confusion
                        "oo": "8",  # Double o confusion
                        "O0": "O",  # O and 0 confusion
                        "Il": "H",  # I and l confusion
                        "1l": "I",  # 1 and l confusion
                    },
                    "combining_marks": {
                        "\u0300": "Combining Grave Accent",
                        "\u0301": "Combining Acute Accent",
                        "\u0302": "Combining Circumflex Accent",
                        "\u0303": "Combining Tilde",
                        "\u0304": "Combining Macron",
                        "\u0305": "Combining Overline",
                        "\u0306": "Combining Breve",
                        "\u0307": "Combining Dot Above",
                        "\u0308": "Combining Diaeresis",
                        "\u0309": "Combining Hook Above",
                        "\u030a": "Combining Ring Above",
                        "\u030b": "Combining Double Acute Accent",
                        "\u030c": "Combining Caron",
                    },
                    "punycode_attacks": {
                        "patterns": [
                            r"xn--[a-z0-9]+",
                            r"xn--[a-z0-9]+-[a-z0-9]+",
                            r"xn--[a-z0-9]+-[a-z0-9]+-[a-z0-9]+",
                        ],
                        "detection": "punycode_encoding",
                    },
                },
                "severity": "HIGH",
                "attack_sophistication": "advanced_normalization",
            },
        }

        # Analysis results
        self.unicode_findings = []
        self.collision_tests = []
        self.security_implications = []

        # Enhanced statistics with detailed metrics
        self.analysis_stats = {
            "patterns_analyzed": 0,
            "vulnerabilities_found": 0,
            "collision_attacks": 0,
            "homograph_attacks": 0,
            "normalization_issues": 0,
            "encoding_bypasses": 0,
            "injection_vectors": 0,
            "advanced_patterns": 0,
            "confusable_sequences": 0,
            "combining_marks": 0,
            "punycode_attacks": 0,
            "bidirectional_attacks": 0,
        }

        self.logger.debug("Enhanced Unicode Analyzer initialized with professional confidence calculation")

    def analyze_unicode_vulnerabilities(self, deep_mode: bool = False) -> Tuple[str, Text]:
        """
        Full Unicode vulnerability analysis with advanced pattern detection.

        Args:
            deep_mode: Whether to perform deep analysis with advanced patterns

        Returns:
            Tuple of (analysis_title, analysis_results)
        """
        self.logger.debug("Starting full Unicode vulnerability analysis")

        try:
            # Initialize progress tracking
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console,
            ) as progress:

                # Enhanced analysis phases
                pattern_task = progress.add_task("Analyzing Unicode patterns", total=100)
                collision_task = progress.add_task("Testing collision attacks", total=100)
                homograph_task = progress.add_task("Detecting homograph attacks", total=100)
                normalization_task = progress.add_task("Checking normalization", total=100)
                advanced_task = progress.add_task("Advanced pattern analysis", total=100)
                security_task = progress.add_task("Assessing security implications", total=100)

                # Phase 1: Enhanced pattern analysis
                progress.update(pattern_task, advance=20)
                self._analyze_unicode_patterns_enhanced()
                progress.update(pattern_task, advance=60)

                # Phase 2: Advanced collision testing
                progress.update(collision_task, advance=25)
                self._test_collision_attacks_advanced()
                progress.update(collision_task, advance=75)

                # Phase 3: Enhanced homograph detection
                progress.update(homograph_task, advance=30)
                self._detect_homograph_attacks_enhanced()
                progress.update(homograph_task, advance=70)

                # Phase 4: Advanced normalization checking
                progress.update(normalization_task, advance=35)
                self._check_normalization_issues_advanced()
                progress.update(normalization_task, advance=65)

                # Phase 5: Advanced pattern detection
                progress.update(advanced_task, advance=40)
                if deep_mode:
                    self._analyze_advanced_patterns()
                progress.update(advanced_task, advance=60)

                # Phase 6: Enhanced security assessment
                progress.update(security_task, advance=45)
                self._assess_unicode_security_enhanced()
                progress.update(security_task, advance=55)

                # Complete all phases
                progress.update(pattern_task, completed=100)
                progress.update(collision_task, completed=100)
                progress.update(homograph_task, completed=100)
                progress.update(normalization_task, completed=100)
                progress.update(advanced_task, completed=100)
                progress.update(security_task, completed=100)

            # Generate full enhanced report
            report = self._generate_unicode_report_enhanced()

            self.logger.debug(
                f"Enhanced Unicode analysis completed. Found {len(self.unicode_findings)} vulnerabilities"
            )

            return "Enhanced Unicode Vulnerability Analysis", report

        except Exception as e:
            self.logger.error(f"Enhanced Unicode analysis failed: {e}")
            return "Enhanced Unicode Vulnerability Analysis", Text(f"Analysis failed: {str(e)}", style="red")

    def _analyze_unicode_patterns_enhanced(self):
        """Enhanced Unicode pattern analysis with advanced detection capabilities."""
        self.logger.debug("Analyzing enhanced Unicode patterns")

        try:
            if not self.apk_context:
                self.logger.warning("No APK context available for enhanced pattern analysis")
                return

            # Analyze source files with enhanced patterns
            source_files = getattr(self.apk_context, "source_files", [])
            for file_path in source_files:
                self._analyze_file_for_unicode_enhanced(file_path)

            # Analyze strings with enhanced detection
            strings_data = getattr(self.apk_context, "strings", [])
            self._analyze_strings_for_unicode_enhanced(strings_data)

            # Analyze resources with advanced patterns
            resources_data = getattr(self.apk_context, "resources", {})
            self._analyze_resources_for_unicode_enhanced(resources_data)

            # Update statistics
            self.analysis_stats["patterns_analyzed"] = len(self.unicode_patterns)
            self.analysis_stats["vulnerabilities_found"] = len(self.unicode_findings)

        except Exception as e:
            self.logger.error(f"Enhanced Unicode pattern analysis failed: {e}")

    def _test_collision_attacks_advanced(self):
        """Advanced Unicode collision attack testing with full scenarios."""
        self.logger.debug("Testing advanced Unicode collision attacks")

        try:
            dotless_i_patterns = self.unicode_patterns["dotless_i"]

            # Test enhanced collision scenarios
            for test_case in dotless_i_patterns["test_cases"]:
                original, target = test_case

                # Test multiple normalization forms
                for form in ["NFC", "NFD", "NFKC", "NFKD"]:
                    normalized_original = unicodedata.normalize(form, original)
                    normalized_target = unicodedata.normalize(form, target)

                    # Test case-insensitive collision
                    if normalized_original.lower() == normalized_target.lower():
                        # Build evidence for confidence calculation
                        evidence = {
                            "pattern_type": "dotless_i_collision",
                            "usage_context": "authentication_system",
                            "attack_sophistication": "advanced_normalization",
                            "security_impact": "authentication_bypass",
                            "validation_methods": ["static_analysis", "normalization_testing"],
                            "evidence_quality": 0.9,
                            "evidence_quantity": 2,
                            "analysis_depth": 0.8,
                        }

                        # Calculate dynamic confidence
                        confidence = self.confidence_calculator.calculate_confidence(evidence)

                        collision_result = {
                            "type": "dotless_i_collision",
                            "original": original,
                            "target": target,
                            "normalized_form": form,
                            "collision_detected": True,
                            "confidence": confidence,
                            "severity": "CRITICAL",
                            "attack_vector": "case_insensitive_normalization",
                            "security_impact": "authentication_bypass",
                            "evidence": evidence,
                        }

                        self.collision_tests.append(collision_result)
                        self.analysis_stats["collision_attacks"] += 1

                        # Create detailed finding
                        finding = {
                            "type": "dotless_i_collision",
                            "pattern": f"{original} → {target}",
                            "normalization_form": form,
                            "source": "collision_testing",
                            "severity": "CRITICAL",
                            "confidence": confidence,
                            "description": f"Dotless i collision detected: {original} collides with {target} under {form} normalization",  # noqa: E501
                            "attack_sophistication": "advanced_normalization",
                            "security_impact": "authentication_bypass",
                        }
                        self.unicode_findings.append(finding)

        except Exception as e:
            self.logger.error(f"Advanced collision attack testing failed: {e}")

    def _detect_homograph_attacks_enhanced(self):
        """Enhanced homograph attack detection with brand protection and advanced analysis."""
        self.logger.debug("Detecting enhanced homograph attacks")

        try:
            homograph_patterns = self.unicode_patterns["homograph"]
            dangerous_chars = homograph_patterns["dangerous_chars"]
            suspicious_domains = homograph_patterns["suspicious_domains"]

            # Enhanced homograph detection
            if self.apk_context:
                strings_data = getattr(self.apk_context, "strings", [])

                for string_value in strings_data:
                    # Check for sophisticated homograph attacks
                    homograph_score = self._calculate_homograph_score(string_value, dangerous_chars)

                    if homograph_score > 0.7:  # High homograph probability
                        # Build evidence for confidence calculation
                        evidence = {
                            "pattern_type": "homograph_attack",
                            "usage_context": "url_handling",
                            "attack_sophistication": "complex_homograph",
                            "security_impact": "data_exfiltration",
                            "validation_methods": ["static_analysis", "homograph_detection"],
                            "evidence_quality": homograph_score,
                            "evidence_quantity": 1,
                            "analysis_depth": 0.85,
                        }

                        # Calculate dynamic confidence
                        confidence = self.confidence_calculator.calculate_confidence(evidence)

                        finding = {
                            "type": "homograph_attack",
                            "pattern": string_value,
                            "homograph_score": homograph_score,
                            "dangerous_chars": self._identify_dangerous_chars(string_value, dangerous_chars),
                            "source": "strings",
                            "severity": "HIGH",
                            "confidence": confidence,
                            "description": f"Homograph attack detected with score {homograph_score:.3f}",
                            "attack_sophistication": "complex_homograph",
                            "security_impact": "data_exfiltration",
                        }
                        self.unicode_findings.append(finding)
                        self.analysis_stats["homograph_attacks"] += 1

                    # Check for suspicious domain impersonation
                    for domain in suspicious_domains:
                        if self._is_homograph_domain_enhanced(string_value, domain):
                            # Build evidence for confidence calculation
                            evidence = {
                                "pattern_type": "homograph_attack",
                                "usage_context": "authentication_system",
                                "attack_sophistication": "complex_homograph",
                                "security_impact": "authentication_bypass",
                                "validation_methods": ["static_analysis", "homograph_detection", "brand_protection"],
                                "evidence_quality": 0.9,
                                "evidence_quantity": 2,
                                "analysis_depth": 0.9,
                            }

                            # Calculate dynamic confidence
                            confidence = self.confidence_calculator.calculate_confidence(evidence)

                            finding = {
                                "type": "homograph_domain",
                                "pattern": string_value,
                                "target_domain": domain,
                                "source": "strings",
                                "severity": "CRITICAL",
                                "confidence": confidence,
                                "description": f"Homograph domain impersonation: {string_value} impersonates {domain}",
                                "attack_sophistication": "complex_homograph",
                                "security_impact": "authentication_bypass",
                            }
                            self.unicode_findings.append(finding)
                            self.analysis_stats["homograph_attacks"] += 1

        except Exception as e:
            self.logger.error(f"Enhanced homograph attack detection failed: {e}")

    def _check_normalization_issues_advanced(self):
        """Advanced Unicode normalization vulnerability checking."""
        self.logger.debug("Checking advanced Unicode normalization issues")

        try:
            normalization_patterns = self.unicode_patterns["normalization"]
            test_strings = normalization_patterns["test_strings"]
            forms = normalization_patterns["forms"]

            # Test advanced normalization scenarios
            for test_string in test_strings:
                normalization_results = {}

                # Test all normalization forms
                for form in forms:
                    try:
                        normalized = unicodedata.normalize(form, test_string)
                        normalization_results[form] = normalized
                    except Exception as e:
                        self.logger.debug(f"Normalization error for {form}: {e}")
                        continue

                # Detect normalization inconsistencies
                unique_results = set(normalization_results.values())
                if len(unique_results) > 1:
                    # Build evidence for confidence calculation
                    evidence = {
                        "pattern_type": "normalization_attack",
                        "usage_context": "user_input_validation",
                        "attack_sophistication": "advanced_normalization",
                        "security_impact": "authorization_bypass",
                        "validation_methods": ["static_analysis", "normalization_testing"],
                        "evidence_quality": 0.85,
                        "evidence_quantity": len(unique_results),
                        "analysis_depth": 0.8,
                    }

                    # Calculate dynamic confidence
                    confidence = self.confidence_calculator.calculate_confidence(evidence)

                    finding = {
                        "type": "normalization_inconsistency",
                        "pattern": test_string,
                        "normalization_forms": forms,
                        "results": normalization_results,
                        "unique_results": len(unique_results),
                        "source": "normalization_testing",
                        "severity": "HIGH",
                        "confidence": confidence,
                        "description": f"Normalization inconsistency detected: {len(unique_results)} different results",
                        "attack_sophistication": "advanced_normalization",
                        "security_impact": "authorization_bypass",
                    }
                    self.unicode_findings.append(finding)
                    self.analysis_stats["normalization_issues"] += 1

        except Exception as e:
            self.logger.error(f"Advanced normalization issue checking failed: {e}")

    def _analyze_advanced_patterns(self):
        """Analyze advanced Unicode patterns including confusable sequences and combining marks."""
        self.logger.debug("Analyzing advanced Unicode patterns")

        try:
            advanced_patterns = self.unicode_patterns["advanced_patterns"]

            if self.apk_context:
                strings_data = getattr(self.apk_context, "strings", [])

                for string_value in strings_data:
                    # Check for confusable sequences
                    confusable_sequences = advanced_patterns["patterns"]["confusable_sequences"]
                    for sequence, target in confusable_sequences.items():
                        if sequence in string_value:
                            # Build evidence for confidence calculation
                            evidence = {
                                "pattern_type": "confusable_characters",
                                "usage_context": "display_rendering",
                                "attack_sophistication": "visual_spoofing",
                                "security_impact": "information_disclosure",
                                "validation_methods": ["static_analysis", "pattern_matching"],
                                "evidence_quality": 0.8,
                                "evidence_quantity": 1,
                                "analysis_depth": 0.7,
                            }

                            # Calculate dynamic confidence
                            confidence = self.confidence_calculator.calculate_confidence(evidence)

                            finding = {
                                "type": "confusable_sequence",
                                "pattern": string_value,
                                "sequence": sequence,
                                "target": target,
                                "source": "strings",
                                "severity": "MEDIUM",
                                "confidence": confidence,
                                "description": f"Confusable sequence detected: {sequence} → {target}",
                                "attack_sophistication": "visual_spoofing",
                                "security_impact": "information_disclosure",
                            }
                            self.unicode_findings.append(finding)
                            self.analysis_stats["confusable_sequences"] += 1

                    # Check for combining marks
                    combining_marks = advanced_patterns["patterns"]["combining_marks"]
                    for mark, description in combining_marks.items():
                        if mark in string_value:
                            # Build evidence for confidence calculation
                            evidence = {
                                "pattern_type": "combining_characters",
                                "usage_context": "user_input_validation",
                                "attack_sophistication": "mixed_encoding",
                                "security_impact": "data_corruption",
                                "validation_methods": ["static_analysis", "unicode_validation"],
                                "evidence_quality": 0.75,
                                "evidence_quantity": 1,
                                "analysis_depth": 0.8,
                            }

                            # Calculate dynamic confidence
                            confidence = self.confidence_calculator.calculate_confidence(evidence)

                            finding = {
                                "type": "combining_mark",
                                "pattern": string_value,
                                "mark": mark,
                                "description_text": description,
                                "source": "strings",
                                "severity": "MEDIUM",
                                "confidence": confidence,
                                "description": f"Combining mark detected: {description}",
                                "attack_sophistication": "mixed_encoding",
                                "security_impact": "data_corruption",
                            }
                            self.unicode_findings.append(finding)
                            self.analysis_stats["combining_marks"] += 1

                    # Check for Punycode attacks
                    punycode_patterns = advanced_patterns["patterns"]["punycode_attacks"]["patterns"]
                    for pattern in punycode_patterns:
                        if re.search(pattern, string_value):
                            # Build evidence for confidence calculation
                            evidence = {
                                "pattern_type": "punycode_attack",
                                "usage_context": "url_handling",
                                "attack_sophistication": "advanced_normalization",
                                "security_impact": "data_exfiltration",
                                "validation_methods": ["static_analysis", "pattern_matching"],
                                "evidence_quality": 0.9,
                                "evidence_quantity": 1,
                                "analysis_depth": 0.85,
                            }

                            # Calculate dynamic confidence
                            confidence = self.confidence_calculator.calculate_confidence(evidence)

                            finding = {
                                "type": "punycode_attack",
                                "pattern": string_value,
                                "punycode_pattern": pattern,
                                "source": "strings",
                                "severity": "HIGH",
                                "confidence": confidence,
                                "description": f"Punycode attack detected: {pattern}",
                                "attack_sophistication": "advanced_normalization",
                                "security_impact": "data_exfiltration",
                            }
                            self.unicode_findings.append(finding)
                            self.analysis_stats["punycode_attacks"] += 1

        except Exception as e:
            self.logger.error(f"Advanced pattern analysis failed: {e}")

    def _analyze_strings_for_unicode_enhanced(self, strings_data):
        """
        Enhanced string analysis for Unicode vulnerabilities with full pattern detection.

        CRITICAL FIX: This method was missing, causing UnicodeAnalyzer to fail during
        enhanced pattern analysis.

        BROADER AODS SCOPE CONSIDERATIONS:
        - Integrates with AODS string extraction and analysis infrastructure
        - Uses consistent vulnerability data structures across AODS framework
        - Maintains compatibility with AODS confidence scoring system
        - Follows AODS pattern-based detection methodologies
        - Uses AODS unified deduplication framework

        This method performs deep string analysis to identify sophisticated Unicode-based
        vulnerabilities that could be exploited for authentication bypass, injection attacks,
        or security control circumvention.
        """
        self.logger.debug("Starting enhanced Unicode string analysis")

        try:
            # PERMANENT FIX: Use passed strings_data parameter, with fallback to APK context
            if not strings_data and self.apk_context:
                # Fallback: Extract strings from APK context (AODS-compatible extraction)
                strings_data = getattr(self.apk_context, "strings", [])
                if not strings_data:
                    strings_data = getattr(self.apk_context, "extracted_strings", [])
                if not strings_data:
                    strings_data = getattr(self.apk_context, "string_resources", [])

            if not strings_data:
                self.logger.debug("No strings data available for Unicode analysis")
                return

            # Enhanced Unicode string analysis with multiple detection vectors
            self._analyze_unicode_injection_vectors(strings_data)
            self._analyze_unicode_encoding_bypasses(strings_data)
            self._analyze_unicode_normalization_attacks(strings_data)
            self._analyze_unicode_homograph_sequences(strings_data)
            self._analyze_unicode_control_characters(strings_data)

        except Exception as e:
            self.logger.error(f"Enhanced Unicode pattern analysis failed: {e}")

    def _analyze_unicode_injection_vectors(self, strings_data: List[str]):
        """Analyze strings for Unicode injection vulnerabilities."""
        try:
            injection_patterns = [
                r"[\u200b-\u200f]",  # Zero-width characters
                r"[\u202a-\u202e]",  # Bidirectional override characters
                r"[\ufeff]",  # Byte order mark
                r"[\u00a0]",  # Non-breaking space
                r"[\u2028\u2029]",  # Line/paragraph separators
            ]

            for string_value in strings_data:
                for pattern in injection_patterns:
                    matches = re.finditer(pattern, string_value)
                    for match in matches:
                        # Build evidence for confidence calculation
                        evidence = {
                            "pattern_type": "unicode_injection",
                            "usage_context": "user_input_validation",
                            "attack_sophistication": "zero_width_bypass",
                            "security_impact": "input_validation_bypass",
                            "validation_methods": ["static_analysis", "pattern_matching"],
                            "evidence_quality": 0.85,
                            "evidence_quantity": 1,
                            "analysis_depth": 0.9,
                        }

                        confidence = self.confidence_calculator.calculate_confidence(evidence)

                        finding = {
                            "type": "unicode_injection_vector",
                            "pattern": string_value,
                            "injection_char": match.group(),
                            "position": match.start(),
                            "source": "strings_enhanced",
                            "severity": "HIGH",
                            "confidence": confidence,
                            "description": f"Unicode injection vector detected: {repr(match.group())}",
                            "attack_sophistication": "zero_width_bypass",
                            "security_impact": "input_validation_bypass",
                        }
                        self.unicode_findings.append(finding)
                        self.analysis_stats.setdefault("injection_vectors", 0)
                        self.analysis_stats["injection_vectors"] += 1

        except Exception as e:
            self.logger.error(f"Unicode injection vector analysis failed: {e}")

    def _analyze_unicode_encoding_bypasses(self, strings_data: List[str]):
        """Analyze strings for Unicode encoding bypass techniques."""
        try:
            bypass_patterns = [
                r"%[c-f][0-9a-f]%[8-9a-f][0-9a-f]",  # Double-encoded Unicode
                r"\\u[0-9a-f]{4}",  # Unicode escape sequences
                r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}",  # Multi-byte sequences
                r"&[#x][0-9a-f]+;",  # HTML entities
            ]

            for string_value in strings_data:
                for pattern in bypass_patterns:
                    matches = re.finditer(pattern, string_value, re.IGNORECASE)
                    for match in matches:
                        evidence = {
                            "pattern_type": "encoding_bypass",
                            "usage_context": "input_filtering",
                            "attack_sophistication": "encoding_obfuscation",
                            "security_impact": "filter_bypass",
                            "validation_methods": ["static_analysis", "encoding_analysis"],
                            "evidence_quality": 0.8,
                            "evidence_quantity": 1,
                            "analysis_depth": 0.85,
                        }

                        confidence = self.confidence_calculator.calculate_confidence(evidence)

                        finding = {
                            "type": "unicode_encoding_bypass",
                            "pattern": string_value,
                            "bypass_sequence": match.group(),
                            "position": match.start(),
                            "source": "strings_enhanced",
                            "severity": "MEDIUM",
                            "confidence": confidence,
                            "description": f"Unicode encoding bypass detected: {match.group()}",
                            "attack_sophistication": "encoding_obfuscation",
                            "security_impact": "filter_bypass",
                        }
                        self.unicode_findings.append(finding)
                        self.analysis_stats.setdefault("encoding_bypasses", 0)
                        self.analysis_stats["encoding_bypasses"] += 1

        except Exception as e:
            self.logger.error(f"Unicode encoding bypass analysis failed: {e}")

    def _analyze_unicode_normalization_attacks(self, strings_data: List[str]):
        """Analyze strings for Unicode normalization attack vectors."""
        try:
            for string_value in strings_data:
                # Test different normalization forms
                try:
                    nfc = unicodedata.normalize("NFC", string_value)
                    nfd = unicodedata.normalize("NFD", string_value)
                    nfkc = unicodedata.normalize("NFKC", string_value)
                    nfkd = unicodedata.normalize("NFKD", string_value)

                    forms = [nfc, nfd, nfkc, nfkd]
                    unique_forms = set(forms)

                    # If normalization produces different results, it's a potential attack vector
                    if len(unique_forms) > 1:
                        evidence = {
                            "pattern_type": "normalization_attack",
                            "usage_context": "authentication",
                            "attack_sophistication": "advanced_normalization",
                            "security_impact": "authentication_bypass",
                            "validation_methods": ["normalization_testing"],
                            "evidence_quality": 0.9,
                            "evidence_quantity": len(unique_forms),
                            "analysis_depth": 0.95,
                        }

                        confidence = self.confidence_calculator.calculate_confidence(evidence)

                        finding = {
                            "type": "unicode_normalization_attack",
                            "pattern": string_value,
                            "normalization_variants": len(unique_forms),
                            "forms": list(unique_forms),
                            "source": "strings_enhanced",
                            "severity": "HIGH",
                            "confidence": confidence,
                            "description": f"Normalization attack vector: {len(unique_forms)} variants",
                            "attack_sophistication": "advanced_normalization",
                            "security_impact": "authentication_bypass",
                        }
                        self.unicode_findings.append(finding)
                        self.analysis_stats.setdefault("normalization_issues", 0)
                        self.analysis_stats["normalization_issues"] += 1

                except UnicodeError:
                    # Strings that can't be normalized are also suspicious
                    evidence = {
                        "pattern_type": "malformed_unicode",
                        "usage_context": "input_validation",
                        "attack_sophistication": "malformed_encoding",
                        "security_impact": "crash_potential",
                        "validation_methods": ["error_analysis"],
                        "evidence_quality": 0.7,
                        "evidence_quantity": 1,
                        "analysis_depth": 0.6,
                    }

                    confidence = self.confidence_calculator.calculate_confidence(evidence)

                    finding = {
                        "type": "malformed_unicode",
                        "pattern": string_value,
                        "error": "normalization_failure",
                        "source": "strings_enhanced",
                        "severity": "MEDIUM",
                        "confidence": confidence,
                        "description": "Malformed Unicode string detected",
                        "attack_sophistication": "malformed_encoding",
                        "security_impact": "crash_potential",
                    }
                    self.unicode_findings.append(finding)

        except Exception as e:
            self.logger.error(f"Unicode normalization attack analysis failed: {e}")

    def _analyze_unicode_homograph_sequences(self, strings_data: List[str]):
        """Analyze strings for homograph attack sequences."""
        try:
            # Common homograph characters
            homograph_maps = {
                "а": "a",  # Cyrillic 'a'
                "е": "e",  # Cyrillic 'e'
                "о": "o",  # Cyrillic 'o'
                "р": "p",  # Cyrillic 'p'
                "у": "y",  # Cyrillic 'y'
                "х": "x",  # Cyrillic 'x'
                "ο": "o",  # Greek omicron
                "ρ": "p",  # Greek rho
            }

            for string_value in strings_data:
                homograph_count = 0
                homograph_chars = []

                for char in string_value:
                    if char in homograph_maps:
                        homograph_count += 1
                        homograph_chars.append((char, homograph_maps[char]))

                if homograph_count > 0:
                    evidence = {
                        "pattern_type": "homograph_attack",
                        "usage_context": "display_spoofing",
                        "attack_sophistication": "visual_deception",
                        "security_impact": "brand_impersonation",
                        "validation_methods": ["homograph_detection"],
                        "evidence_quality": min(0.9, 0.5 + (homograph_count * 0.1)),
                        "evidence_quantity": homograph_count,
                        "analysis_depth": 0.8,
                    }

                    confidence = self.confidence_calculator.calculate_confidence(evidence)

                    finding = {
                        "type": "unicode_homograph_sequence",
                        "pattern": string_value,
                        "homograph_chars": homograph_chars,
                        "homograph_count": homograph_count,
                        "source": "strings_enhanced",
                        "severity": "MEDIUM" if homograph_count < 3 else "HIGH",
                        "confidence": confidence,
                        "description": f"Homograph sequence detected: {homograph_count} suspicious characters",
                        "attack_sophistication": "visual_deception",
                        "security_impact": "brand_impersonation",
                    }
                    self.unicode_findings.append(finding)
                    self.analysis_stats.setdefault("homograph_attacks", 0)
                    self.analysis_stats["homograph_attacks"] += 1

        except Exception as e:
            self.logger.error(f"Unicode homograph sequence analysis failed: {e}")

    def _analyze_unicode_control_characters(self, strings_data: List[str]):
        """Analyze strings for suspicious Unicode control characters."""
        try:
            control_char_ranges = [
                (0x0000, 0x001F, "C0_controls"),
                (0x007F, 0x009F, "C1_controls"),
                (0x2000, 0x206F, "general_punctuation"),
                (0xFFF0, 0xFFFF, "specials"),
            ]

            for string_value in strings_data:
                suspicious_chars = []

                for char in string_value:
                    char_code = ord(char)
                    for start, end, category in control_char_ranges:
                        if start <= char_code <= end:
                            suspicious_chars.append((char, char_code, category))

                if suspicious_chars:
                    evidence = {
                        "pattern_type": "control_characters",
                        "usage_context": "data_manipulation",
                        "attack_sophistication": "control_injection",
                        "security_impact": "data_corruption",
                        "validation_methods": ["control_char_detection"],
                        "evidence_quality": 0.75,
                        "evidence_quantity": len(suspicious_chars),
                        "analysis_depth": 0.8,
                    }

                    confidence = self.confidence_calculator.calculate_confidence(evidence)

                    finding = {
                        "type": "unicode_control_characters",
                        "pattern": string_value,
                        "control_chars": suspicious_chars,
                        "count": len(suspicious_chars),
                        "source": "strings_enhanced",
                        "severity": "LOW" if len(suspicious_chars) == 1 else "MEDIUM",
                        "confidence": confidence,
                        "description": f"Suspicious control characters detected: {len(suspicious_chars)}",
                        "attack_sophistication": "control_injection",
                        "security_impact": "data_corruption",
                    }
                    self.unicode_findings.append(finding)

        except Exception as e:
            self.logger.error(f"Unicode control character analysis failed: {e}")

    def _assess_unicode_security_enhanced(self):
        """Enhanced Unicode security assessment with detailed risk analysis."""
        self.logger.debug("Assessing enhanced Unicode security")

        try:
            # Categorize findings by severity and type
            critical_types = ["dotless_i_collision", "injection_attack", "punycode_attack"]
            high_risk_types = ["homograph_attack", "normalization_attack", "encoding_bypass"]
            medium_risk_types = ["confusable_sequence", "combining_mark", "mixed_scripts"]

            critical_count = sum(1 for f in self.unicode_findings if f["type"] in critical_types)
            high_risk_count = sum(1 for f in self.unicode_findings if f["type"] in high_risk_types)
            medium_risk_count = sum(1 for f in self.unicode_findings if f["type"] in medium_risk_types)

            # Calculate overall security metrics
            total_findings = len(self.unicode_findings)
            average_confidence = sum(f.get("confidence", 0.5) for f in self.unicode_findings) / max(total_findings, 1)

            # Enhanced security assessment
            enhanced_assessment = {
                "total_findings": total_findings,
                "critical_vulnerabilities": critical_count,
                "high_risk_vulnerabilities": high_risk_count,
                "medium_risk_vulnerabilities": medium_risk_count,
                "average_confidence": average_confidence,
                "collision_attacks_possible": self.analysis_stats["collision_attacks"] > 0,
                "homograph_attacks_possible": self.analysis_stats["homograph_attacks"] > 0,
                "normalization_attacks_possible": self.analysis_stats["normalization_issues"] > 0,
                "encoding_bypasses_possible": self.analysis_stats["encoding_bypasses"] > 0,
                "injection_vectors_present": self.analysis_stats["injection_vectors"] > 0,
                "advanced_patterns_detected": self.analysis_stats["advanced_patterns"] > 0,
                "confusable_sequences_found": self.analysis_stats["confusable_sequences"] > 0,
                "combining_marks_found": self.analysis_stats["combining_marks"] > 0,
                "punycode_attacks_found": self.analysis_stats["punycode_attacks"] > 0,
                "bidirectional_attacks_found": self.analysis_stats["bidirectional_attacks"] > 0,
                "overall_risk": self._calculate_overall_risk_enhanced(
                    critical_count, high_risk_count, medium_risk_count
                ),
                "risk_factors": self._identify_risk_factors(),
                "security_recommendations": self._generate_security_recommendations_enhanced(),
                "confidence_analysis": self._analyze_confidence_distribution(),
            }

            self.security_implications.append(enhanced_assessment)

        except Exception as e:
            self.logger.error(f"Enhanced Unicode security assessment failed: {e}")

    def _calculate_overall_risk_enhanced(
        self, critical_count: int, high_risk_count: int, medium_risk_count: int
    ) -> str:
        """Calculate enhanced overall Unicode security risk with detailed criteria."""
        if critical_count >= 3:
            return "CRITICAL"
        elif critical_count >= 1:
            return "HIGH"
        elif high_risk_count >= 5:
            return "HIGH"
        elif high_risk_count >= 2:
            return "MEDIUM"
        elif medium_risk_count >= 3:
            return "MEDIUM"
        elif medium_risk_count >= 1:
            return "LOW"
        else:
            return "INFO"

    def _identify_risk_factors(self) -> List[str]:
        """Identify specific Unicode security risk factors."""
        risk_factors = []

        if self.analysis_stats["collision_attacks"] > 0:
            risk_factors.append("Unicode collision attacks detected")
        if self.analysis_stats["homograph_attacks"] > 0:
            risk_factors.append("Homograph attacks targeting brand impersonation")
        if self.analysis_stats["normalization_issues"] > 0:
            risk_factors.append("Normalization inconsistencies enabling bypass")
        if self.analysis_stats["encoding_bypasses"] > 0:
            risk_factors.append("Encoding bypass techniques present")
        if self.analysis_stats["injection_vectors"] > 0:
            risk_factors.append("Unicode injection vectors available")
        if self.analysis_stats["confusable_sequences"] > 0:
            risk_factors.append("Confusable character sequences detected")
        if self.analysis_stats["combining_marks"] > 0:
            risk_factors.append("Combining marks enabling manipulation")
        if self.analysis_stats["punycode_attacks"] > 0:
            risk_factors.append("Punycode attacks targeting domains")
        if self.analysis_stats["bidirectional_attacks"] > 0:
            risk_factors.append("Bidirectional text attacks present")

        return risk_factors

    def _generate_security_recommendations_enhanced(self) -> List[str]:
        """Generate enhanced security recommendations based on full findings."""
        recommendations = []

        if self.analysis_stats["collision_attacks"] > 0:
            recommendations.extend(
                [
                    "Implement full Unicode normalization before all string comparisons",
                    "Use Unicode-aware case-insensitive comparison with proper locale handling",
                    "Validate Unicode normalization forms consistently across authentication systems",
                ]
            )

        if self.analysis_stats["homograph_attacks"] > 0:
            recommendations.extend(
                [
                    "Implement sophisticated homograph attack detection for all user inputs",
                    "Use character set allowlists with script validation",
                    "Deploy brand protection mechanisms for domain and URL validation",
                ]
            )

        if self.analysis_stats["normalization_issues"] > 0:
            recommendations.extend(
                [
                    "Standardize Unicode normalization to NFC form across the entire application",
                    "Implement normalization consistency checks for security-critical operations",
                    "Use canonical equivalence testing for security validations",
                ]
            )

        if self.analysis_stats["encoding_bypasses"] > 0:
            recommendations.extend(
                [
                    "Strip all zero-width and invisible characters from user inputs",
                    "Implement full input sanitization with Unicode awareness",
                    "Use visual similarity detection for input validation",
                ]
            )

        if self.analysis_stats["injection_vectors"] > 0:
            recommendations.extend(
                [
                    "Filter all Unicode bidirectional and directional control characters",
                    "Validate text direction and implement proper encoding validation",
                    "Use Unicode isolates instead of embeddings for legitimate bidirectional text",
                ]
            )

        if self.analysis_stats["confusable_sequences"] > 0:
            recommendations.extend(
                [
                    "Implement confusable character detection using Unicode confusables data",
                    "Use visual similarity algorithms for input validation",
                    "Employ font-aware character similarity detection",
                ]
            )

        if self.analysis_stats["combining_marks"] > 0:
            recommendations.extend(
                [
                    "Normalize combining character sequences before processing",
                    "Limit combining mark usage in security-critical contexts",
                    "Implement proper grapheme cluster handling",
                ]
            )

        if self.analysis_stats["punycode_attacks"] > 0:
            recommendations.extend(
                [
                    "Implement Punycode detection and validation for all domain processing",
                    "Use IDN (Internationalized Domain Name) security policies",
                    "Display original Unicode and Punycode representations to users",
                ]
            )

        if not recommendations:
            recommendations.extend(
                [
                    "Continue monitoring for emerging Unicode attack vectors",
                    "Implement full Unicode-aware input validation",
                    "Use Unicode security best practices for all text processing",
                ]
            )

        return recommendations

    def _analyze_confidence_distribution(self) -> Dict[str, Any]:
        """Analyze the confidence distribution of Unicode findings."""
        if not self.unicode_findings:
            return {"message": "No findings to analyze confidence distribution"}

        confidences = [f.get("confidence", 0.5) for f in self.unicode_findings]

        return {
            "total_findings": len(confidences),
            "average_confidence": sum(confidences) / len(confidences),
            "highest_confidence": max(confidences),
            "lowest_confidence": min(confidences),
            "high_confidence_count": sum(1 for c in confidences if c >= 0.8),
            "medium_confidence_count": sum(1 for c in confidences if 0.6 <= c < 0.8),
            "low_confidence_count": sum(1 for c in confidences if c < 0.6),
        }

    def _generate_unicode_report_enhanced(self) -> Text:
        """Generate full Unicode analysis report."""
        report = Text()

        # Header
        report.append("🔤 Unicode Vulnerability Analysis Report\n", style="bold blue")
        report.append("=" * 50 + "\n\n", style="blue")

        # Summary statistics
        report.append("📊 Analysis Summary:\n", style="bold green")
        report.append(f"• Total vulnerabilities found: {len(self.unicode_findings)}\n", style="green")
        report.append(f"• Collision attacks: {self.analysis_stats['collision_attacks']}\n", style="red")
        report.append(f"• Homograph attacks: {self.analysis_stats['homograph_attacks']}\n", style="yellow")
        report.append(f"• Normalization issues: {self.analysis_stats['normalization_issues']}\n", style="cyan")
        report.append(f"• Encoding bypasses: {self.analysis_stats['encoding_bypasses']}\n", style="red")
        report.append(f"• Injection vectors: {self.analysis_stats['injection_vectors']}\n", style="red")
        report.append("\n")

        # Unicode findings
        if self.unicode_findings:
            report.append("🔍 Unicode Vulnerability Findings:\n", style="bold yellow")
            for i, finding in enumerate(self.unicode_findings[:10], 1):  # Top 10
                severity_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(
                    finding["severity"], "white"
                )

                report.append(f"{i}. {finding['description']}\n", style=severity_color)
                report.append(f"   Type: {finding['type']}\n", style="dim")
                report.append(f"   Character: {finding.get('character', 'N/A')}\n", style="dim")
                report.append(f"   Unicode: {finding.get('unicode_code', 'N/A')}\n", style="dim")
                if "file_path" in finding:
                    report.append(f"   File: {finding['file_path']}\n", style="dim")
                report.append("\n")

        # Collision test results
        if self.collision_tests:
            report.append("⚔️ Collision Test Results:\n", style="bold red")
            for i, test in enumerate(self.collision_tests, 1):
                if test["collision_detected"]:
                    report.append(
                        f"{i}. Input: '{test['test_input']}' → Output: '{test['actual_output']}'\n", style="red"
                    )
                    report.append(f"   Expected: '{test['expected_output']}'\n", style="dim")
                    report.append(f"   Vulnerability: {test['vulnerability']}\n", style="red")
                    report.append("\n")

        # Security implications
        if self.security_implications:
            report.append("⚠️ Security Implications:\n", style="bold red")
            for implication in self.security_implications:
                if "overall_risk" in implication:
                    report.append(f"• Overall Risk Level: {implication['overall_risk']}\n", style="red")
                    report.append(
                        f"• Critical Vulnerabilities: {implication['critical_vulnerabilities']}\n", style="red"
                    )
                    report.append(
                        f"• High Risk Vulnerabilities: {implication['high_risk_vulnerabilities']}\n", style="yellow"
                    )
                else:
                    report.append(f"• {implication.get('description', 'Security issue detected')}\n", style="red")
                report.append("\n")

        # Security recommendations
        report.append("🛡️ Security Recommendations:\n", style="bold green")
        if self.security_implications and "recommendations" in self.security_implications[-1]:
            for rec in self.security_implications[-1]["recommendations"]:
                report.append(f"• {rec}\n", style="green")
        else:
            report.append("• No Unicode vulnerabilities detected\n", style="green")
            report.append("• Continue monitoring for Unicode-based attacks\n", style="green")

        return report

    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        return {
            "total_vulnerabilities": len(self.unicode_findings),
            "collision_attacks": self.analysis_stats["collision_attacks"],
            "homograph_attacks": self.analysis_stats["homograph_attacks"],
            "normalization_issues": self.analysis_stats["normalization_issues"],
            "encoding_bypasses": self.analysis_stats["encoding_bypasses"],
            "injection_vectors": self.analysis_stats["injection_vectors"],
            "vulnerability_types": list(set(f["type"] for f in self.unicode_findings)),
            "affected_files": len(
                set(f.get("file_path", "unknown") for f in self.unicode_findings if "file_path" in f)
            ),
            "collision_tests_run": len(self.collision_tests),
            "security_implications": len(self.security_implications),
            "analysis_quality": "high" if len(self.unicode_findings) > 0 else "medium",
        }

    def export_findings(self, output_file: str) -> bool:
        """Export findings to JSON file."""
        try:
            export_data = {
                "timestamp": time.time(),
                "analysis_type": "unicode_vulnerability",
                "unicode_findings": self.unicode_findings,
                "collision_tests": self.collision_tests,
                "security_implications": self.security_implications,
                "statistics": self.get_analysis_statistics(),
            }

            # Convert unicode characters to readable format for JSON
            def unicode_serializer(obj):
                if isinstance(obj, str):
                    return obj.encode("unicode_escape").decode("ascii")
                return obj

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, default=unicode_serializer, ensure_ascii=False)

            self.logger.debug(f"Findings exported to: {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to export findings: {e}")
            return False


# Enhanced functions for plugin integration


def analyze_unicode_vulnerabilities_comprehensive(apk_context, deep_mode: bool = False) -> Tuple[str, Text]:
    """
    Full Unicode vulnerability analysis function.

    Args:
        apk_context: APK context object
        deep_mode: Whether to perform deep analysis

    Returns:
        Tuple of (analysis_title, analysis_results)
    """
    analyzer = UnicodeAnalyzer(apk_context)
    return analyzer.analyze_unicode_vulnerabilities(deep_mode)


def detect_unicode_patterns(apk_context) -> List[Dict[str, Any]]:
    """
    Detect Unicode patterns in APK.

    Args:
        apk_context: APK context object

    Returns:
        List of Unicode patterns
    """
    analyzer = UnicodeAnalyzer(apk_context)
    analyzer._analyze_unicode_patterns_enhanced()
    return analyzer.unicode_findings


def test_unicode_collisions(apk_context) -> List[Dict[str, Any]]:
    """
    Test Unicode collision attacks.

    Args:
        apk_context: APK context object

    Returns:
        List of collision test results
    """
    analyzer = UnicodeAnalyzer(apk_context)
    analyzer._test_collision_attacks_advanced()
    return analyzer.collision_tests
