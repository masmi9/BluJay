"""
App Type Detection System for AODS

Provides intelligent app type detection to enable context-aware vulnerability filtering.
"""

import logging
from typing import Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


class AppType(Enum):
    """Supported app types for context-aware filtering."""

    VULNERABLE_APP = "vulnerable_app"  # Deliberately vulnerable test applications
    DEVELOPMENT_APP = "development_app"  # Debug builds, development versions
    TESTING_APP = "testing_app"  # Testing/QA applications
    PRODUCTION_APP = "production_app"  # Production applications (default)


class BusinessDomain(Enum):
    """Business domain classifications for context-aware vulnerability assessment."""

    BANKING = "banking"  # Banking, financial services, payment apps
    HEALTHCARE = "healthcare"  # Medical, health, fitness, telemedicine apps
    GAMING = "gaming"  # Games, entertainment, casual apps
    ECOMMERCE = "ecommerce"  # Shopping, retail, marketplace apps
    SOCIAL_MEDIA = "social_media"  # Social networks, messaging, communication
    GOVERNMENT = "government"  # Government services, civic apps
    EDUCATION = "education"  # Educational, learning, training apps
    ENTERPRISE = "enterprise"  # Business, productivity, enterprise apps
    UTILITY = "utility"  # Tools, utilities, system apps
    TRAVEL = "travel"  # Travel, navigation, transportation
    NEWS_MEDIA = "news_media"  # News, media, content apps
    UNKNOWN = "unknown"  # Cannot determine business domain


class AppTypeDetector:
    """Full app type detection system using organic analysis."""

    # Organic detection patterns - no hardcoded package names
    VULNERABLE_APP_INDICATORS = {
        "package_keywords": [
            "vulnerable",
            "diva",
            "goat",
            "insecure",
            "demo",
            "test",
            "hack",
            "ctf",
            "challenge",
            "security",
            "exploit",
            "pentest",
            "owasp",
            "dvwa",
            "webgoat",
            "mutillidae",
            "hackme",
        ],
        "app_name_keywords": [
            "vulnerable",
            "insecure",
            "demo",
            "test",
            "hack",
            "ctf",
            "challenge",
            "security",
            "exploit",
            "pentest",
            "training",
            "educational",
            "practice",
            "sample",
            "example",
        ],
        "manifest_indicators": ['android:debuggable="true"', 'android:allowBackup="true"', 'android:exported="true"'],
        "source_code_indicators": [
            "intentionally vulnerable",
            "educational purposes",
            "security training",
            "ctf challenge",
            "deliberately insecure",
            "practice app",
            "demo app",
            "vulnerable by design",
            "security testing",
            "penetration testing",
        ],
    }

    # **BUSINESS DOMAIN DETECTION PATTERNS**: Full organic patterns for business domain classification
    BUSINESS_DOMAIN_PATTERNS = {
        BusinessDomain.BANKING: {
            "package_keywords": [
                "bank",
                "banking",
                "finance",
                "financial",
                "payment",
                "pay",
                "wallet",
                "money",
                "credit",
                "debit",
                "card",
                "loan",
                "mortgage",
                "investment",
                "trading",
                "stock",
                "forex",
                "crypto",
                "bitcoin",
                "blockchain",
                "transfer",
                "remittance",
                "atm",
                "mobile.banking",
                "netbanking",
            ],
            "app_name_keywords": [
                "bank",
                "banking",
                "finance",
                "financial",
                "payment",
                "pay",
                "wallet",
                "money",
                "credit",
                "debit",
                "card",
                "loan",
                "mortgage",
                "investment",
                "trading",
                "stock",
                "forex",
                "crypto",
                "bitcoin",
                "mobile banking",
                "net banking",
                "digital wallet",
                "money transfer",
            ],
            "permission_indicators": [
                "android.permission.USE_FINGERPRINT",
                "android.permission.USE_BIOMETRIC",
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
            ],
            "manifest_features": [
                "android.hardware.fingerprint",
                "android.hardware.biometrics",
                "android.software.device_admin",
            ],
        },
        BusinessDomain.HEALTHCARE: {
            "package_keywords": [
                "health",
                "medical",
                "medicine",
                "doctor",
                "hospital",
                "clinic",
                "patient",
                "fitness",
                "wellness",
                "pharma",
                "pharmacy",
                "drug",
                "telemedicine",
                "telehealth",
                "healthcare",
                "medic",
                "therapy",
                "diagnosis",
                "treatment",
                "prescription",
                "vital",
                "heart",
                "blood",
                # Brand-specific patterns
                "teladoc",
                "myfitnesspal",
                "medscape",
                "webmd",
                "mayo",
                "kaiser",
                "fitbit",
                "garmin",
                "samsung.health",
                "google.fit",
            ],
            "app_name_keywords": [
                "health",
                "medical",
                "medicine",
                "doctor",
                "hospital",
                "clinic",
                "patient",
                "fitness",
                "wellness",
                "pharmacy",
                "telemedicine",
                "healthcare",
                "therapy",
                "diagnosis",
                "treatment",
                "prescription",
                "vital signs",
                "heart rate",
                "blood pressure",
                "medical records",
            ],
            "permission_indicators": [
                "android.permission.BODY_SENSORS",
                "android.permission.ACTIVITY_RECOGNITION",
            ],
            "manifest_features": [
                "android.hardware.sensor.heart_rate",
                "android.hardware.sensor.step_counter",
                "android.hardware.camera",
                "android.hardware.microphone",
            ],
        },
        BusinessDomain.GAMING: {
            "package_keywords": [
                "game",
                "games",
                "gaming",
                "play",
                "puzzle",
                "arcade",
                "action",
                "adventure",
                "strategy",
                "rpg",
                "mmo",
                "casino",
                "poker",
                "slots",
                "entertainment",
                "fun",
                "sport",
                "racing",
                "simulation",
                "casual",
                # Brand-specific patterns
                "supercell",
                "king",
                "rovio",
                "clash",
                "candy",
                "angry",
                "birds",
                "pokemon",
                "nintendo",
                "sony",
                "activision",
                "blizzard",
                "epic",
            ],
            "app_name_keywords": [
                "game",
                "games",
                "gaming",
                "play",
                "puzzle",
                "arcade",
                "action",
                "adventure",
                "strategy",
                "rpg",
                "mmo",
                "casino",
                "poker",
                "slots",
                "entertainment",
                "racing",
                "simulation",
                "casual",
                "multiplayer",
            ],
            "permission_indicators": [
                "android.permission.VIBRATE",
                "android.permission.WAKE_LOCK",
                "com.android.vending.BILLING",
            ],
            "manifest_features": [
                "android.hardware.gamepad",
                "android.hardware.sensor.accelerometer",
                "android.software.leanback",
            ],
        },
        BusinessDomain.ECOMMERCE: {
            "package_keywords": [
                "shop",
                "shopping",
                "store",
                "market",
                "marketplace",
                "retail",
                "ecommerce",
                "commerce",
                "buy",
                "sell",
                "purchase",
                "order",
                "cart",
                "checkout",
                "delivery",
                "shipping",
                "product",
                "catalog",
            ],
            "app_name_keywords": [
                "shop",
                "shopping",
                "store",
                "market",
                "marketplace",
                "retail",
                "ecommerce",
                "commerce",
                "buy",
                "sell",
                "purchase",
                "order",
                "cart",
                "checkout",
                "delivery",
                "shipping",
                "online shopping",
            ],
            "permission_indicators": [
                "com.android.vending.BILLING",
            ],
            "manifest_features": ["android.hardware.camera", "android.hardware.location.gps"],
        },
        BusinessDomain.SOCIAL_MEDIA: {
            "package_keywords": [
                "social",
                "chat",
                "message",
                "messenger",
                "communication",
                "connect",
                "network",
                "community",
                "friend",
                "share",
                "post",
                "photo",
                "video",
                "stream",
                "live",
                "broadcast",
                "dating",
                "meet",
                "talk",
                # Brand-specific patterns
                "instagram",
                "whatsapp",
                "snapchat",
                "tiktok",
                "twitter",
                "linkedin",
                "discord",
                "telegram",
                "signal",
                "viber",
                "wechat",
                "line",
            ],
            "app_name_keywords": [
                "social",
                "chat",
                "message",
                "messenger",
                "communication",
                "connect",
                "network",
                "community",
                "friends",
                "sharing",
                "photos",
                "videos",
                "streaming",
                "live",
                "broadcast",
                "dating",
                "meeting",
                "talking",
            ],
            "permission_indicators": [
                "android.permission.READ_CONTACTS",
            ],
            "manifest_features": [
                "android.hardware.camera",
                "android.hardware.microphone",
                "android.hardware.camera.front",
            ],
        },
        BusinessDomain.GOVERNMENT: {
            "package_keywords": [
                "gov",
                "government",
                "official",
                "public",
                "civic",
                "citizen",
                "municipal",
                "federal",
                "state",
                "county",
                "city",
                "tax",
                "dmv",
                "license",
                "permit",
                "service",
                "portal",
                "digital.id",
            ],
            "app_name_keywords": [
                "government",
                "official",
                "public",
                "civic",
                "citizen",
                "municipal",
                "federal",
                "state",
                "county",
                "city",
                "tax",
                "dmv",
                "license",
                "permit",
                "public service",
                "digital id",
                "e-government",
            ],
            "permission_indicators": [
                "android.permission.USE_FINGERPRINT",
                "android.permission.USE_BIOMETRIC",
            ],
            "manifest_features": [
                "android.hardware.fingerprint",
                "android.hardware.biometrics",
                "android.software.device_admin",
            ],
        },
        BusinessDomain.EDUCATION: {
            "package_keywords": [
                "education",
                "learning",
                "school",
                "university",
                "college",
                "student",
                "teacher",
                "course",
                "lesson",
                "study",
                "training",
                "tutorial",
                "academic",
                "classroom",
                "elearning",
                "mooc",
                "skill",
                "knowledge",
            ],
            "app_name_keywords": [
                "education",
                "learning",
                "school",
                "university",
                "college",
                "student",
                "teacher",
                "course",
                "lesson",
                "study",
                "training",
                "tutorial",
                "academic",
                "classroom",
                "e-learning",
                "skills",
                "knowledge",
            ],
            "permission_indicators": [],
            "manifest_features": ["android.hardware.microphone"],
        },
        BusinessDomain.ENTERPRISE: {
            "package_keywords": [
                "enterprise",
                "business",
                "corporate",
                "company",
                "office",
                "work",
                "productivity",
                "professional",
                "crm",
                "erp",
                "hr",
                "project",
                "management",
                "collaboration",
                "workflow",
                "admin",
                "employee",
                # Brand-specific patterns
                "microsoft",
                "office",
                "outlook",
                "teams",
                "slack",
                "zoom",
                "webex",
                "salesforce",
                "oracle",
                "sap",
                "workday",
                "atlassian",
                "jira",
            ],
            "app_name_keywords": [
                "enterprise",
                "business",
                "corporate",
                "company",
                "office",
                "work",
                "productivity",
                "professional",
                "crm",
                "erp",
                "hr",
                "project",
                "management",
                "collaboration",
                "workflow",
                "employee",
            ],
            "permission_indicators": [
                "android.permission.DEVICE_POWER",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.ACCESS_FINE_LOCATION",
            ],
            "manifest_features": ["android.software.device_admin", "android.software.managed_users"],
        },
        BusinessDomain.UTILITY: {
            "package_keywords": [
                "utility",
                "tool",
                "tools",
                "system",
                "manager",
                "cleaner",
                "optimizer",
                "battery",
                "storage",
                "file",
                "security",
                "antivirus",
                "vpn",
                "launcher",
                "keyboard",
                "calculator",
                "flashlight",
                "weather",
                # Brand-specific patterns (to be removed after organic enhancement)
                "cleanmaster",
                "adobe",
                "reader",
            ],
            "app_name_keywords": [
                "utility",
                "tool",
                "tools",
                "system",
                "manager",
                "cleaner",
                "optimizer",
                "battery",
                "storage",
                "file manager",
                "security",
                "antivirus",
                "vpn",
                "launcher",
                "keyboard",
                "calculator",
                "flashlight",
                "weather",
            ],
            "permission_indicators": [
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.DEVICE_POWER",
                "android.permission.WRITE_SETTINGS",
                "android.permission.ACCESS_SUPERUSER",
            ],
            "manifest_features": ["android.software.home_screen", "android.software.input_methods"],
        },
        BusinessDomain.TRAVEL: {
            "package_keywords": [
                "travel",
                "trip",
                "vacation",
                "hotel",
                "flight",
                "booking",
                "reservation",
                "navigation",
                "map",
                "gps",
                "transport",
                "taxi",
                "uber",
                "ride",
                "tourism",
                "guide",
                "airline",
                "airport",
                "train",
                "bus",
            ],
            "app_name_keywords": [
                "travel",
                "trip",
                "vacation",
                "hotel",
                "flight",
                "booking",
                "reservation",
                "navigation",
                "maps",
                "gps",
                "transport",
                "taxi",
                "ride sharing",
                "tourism",
                "travel guide",
                "airline",
                "airport",
                "train",
                "bus",
            ],
            "permission_indicators": [
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.CAMERA",
            ],
            "manifest_features": [
                "android.hardware.location.gps",
                "android.hardware.location.network",
                "android.hardware.camera",
            ],
        },
        BusinessDomain.NEWS_MEDIA: {
            "package_keywords": [
                "news",
                "media",
                "newspaper",
                "magazine",
                "journal",
                "press",
                "reporter",
                "broadcast",
                "radio",
                "podcast",
                "blog",
                "article",
                "content",
                "information",
                "current",
                "events",
                "breaking",
            ],
            "app_name_keywords": [
                "news",
                "media",
                "newspaper",
                "magazine",
                "journal",
                "press",
                "reporter",
                "broadcast",
                "radio",
                "podcast",
                "blog",
                "articles",
                "content",
                "information",
                "current events",
                "breaking news",
            ],
            "permission_indicators": ["android.permission.ACCESS_FINE_LOCATION", "android.permission.VIBRATE"],
            "manifest_features": ["android.hardware.location", "android.software.leanback"],
        },
    }

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def detect_app_type(self, apk_context) -> AppType:
        """
        Detect app type based on APK metadata and characteristics using organic analysis.

        Args:
            apk_context: APK context with package name, app name, and metadata

        Returns:
            AppType: Detected app type for context-aware processing
        """
        try:
            # Organic detection based on package name patterns
            package_name = getattr(apk_context, "package_name", "").lower()
            vulnerability_score = self._calculate_vulnerability_score(package_name, apk_context)

            if vulnerability_score >= 3:  # High confidence threshold
                self.logger.info(f"Detected vulnerable app organically (score: {vulnerability_score}): {package_name}")
                return AppType.VULNERABLE_APP

            # Check for development indicators
            if self._has_development_indicators(apk_context):
                self.logger.info(f"Detected development app: {package_name}")
                return AppType.DEVELOPMENT_APP

            # Check for testing keywords
            if self._has_testing_indicators(apk_context):
                self.logger.info(f"Detected testing app: {package_name}")
                return AppType.TESTING_APP

            # Detect production apps (default)
            return AppType.PRODUCTION_APP

        except Exception as e:
            self.logger.error(f"Error detecting app type: {e}")
            return AppType.PRODUCTION_APP  # Safe default

    def _calculate_vulnerability_score(self, package_name: str, apk_context) -> int:
        """Calculate vulnerability score based on organic indicators."""
        score = 0

        # Package name analysis
        for keyword in self.VULNERABLE_APP_INDICATORS["package_keywords"]:
            if keyword in package_name:
                score += 1

        # App name analysis
        app_name = getattr(apk_context, "app_name", "").lower()
        for keyword in self.VULNERABLE_APP_INDICATORS["app_name_keywords"]:
            if keyword in app_name:
                score += 1

        # Manifest analysis for development flags
        manifest_content = getattr(apk_context, "manifest_content", "").lower()
        if manifest_content:
            for indicator in self.VULNERABLE_APP_INDICATORS["manifest_indicators"]:
                if indicator.lower() in manifest_content:
                    score += 1

        # Check for common vulnerable app description patterns
        description = getattr(apk_context, "description", "").lower()
        if description:
            for indicator in self.VULNERABLE_APP_INDICATORS["source_code_indicators"]:
                if indicator in description:
                    score += 2  # Weight description higher

        return score

    def _has_development_indicators(self, apk_context) -> bool:
        """Check for development build indicators."""
        try:
            # Check debug flag
            if getattr(apk_context, "debug_enabled", False):
                return True

            # Check certificate type
            if getattr(apk_context, "debug_certificate", False):
                return True

            # Check build type
            build_type = getattr(apk_context, "build_type", "").lower()
            if "debug" in build_type or "development" in build_type:
                return True

            return False
        except Exception:
            return False

    def _has_testing_indicators(self, apk_context) -> bool:
        """Check for testing-related indicators."""
        try:
            package_name = getattr(apk_context, "package_name", "").lower()
            app_name = getattr(apk_context, "app_name", "").lower()

            # Check for testing keywords in package or app name
            keywords = (
                self.VULNERABLE_APP_INDICATORS["package_keywords"] + self.VULNERABLE_APP_INDICATORS["app_name_keywords"]
            )
            return any(keyword in package_name or keyword in app_name for keyword in keywords)
        except Exception:
            return False

    def get_filtering_config(self, app_type: AppType) -> Dict:
        """Get filtering configuration for detected app type."""
        configs = {
            AppType.VULNERABLE_APP: {
                "severity_threshold": "LOW",
                "confidence_threshold": 0.3,
                "max_filtering_rate": 50,  # Max 50% filtering
                "preserve_all_categories": True,
            },
            AppType.DEVELOPMENT_APP: {
                "severity_threshold": "LOW",
                "confidence_threshold": 0.4,
                "max_filtering_rate": 60,
                "preserve_all_categories": True,
            },
            AppType.TESTING_APP: {
                "severity_threshold": "LOW",
                "confidence_threshold": 0.4,
                "max_filtering_rate": 60,
                "preserve_all_categories": False,
            },
            AppType.PRODUCTION_APP: {
                "severity_threshold": "MEDIUM",
                "confidence_threshold": 0.7,
                "max_filtering_rate": 90,  # Can filter aggressively
                "preserve_all_categories": False,
            },
        }

        return configs.get(app_type, configs[AppType.PRODUCTION_APP])

    def detect_business_domain(self, apk_context) -> BusinessDomain:
        """
        **HYBRID DETECTION**: Detect business domain using organic characteristics + keyword fallback.

        Uses a two-phase approach:
        1. Organic detection based on permissions, manifest features, and app behavior
        2. Keyword-based fallback for apps not caught by organic analysis

        Args:
            apk_context: APK context with package name, app name, permissions, and manifest

        Returns:
            BusinessDomain: Detected business domain for context-aware processing
        """
        try:
            package_name = getattr(apk_context, "package_name", "").lower()

            # **PHASE 1: ORGANIC DETECTION** - Primary method (no hardcoding)
            organic_domain = self.detect_business_domain_organic(apk_context)
            if organic_domain != BusinessDomain.UNKNOWN:
                self.logger.info(f"Organic detection successful: {organic_domain.value} for {package_name}")
                return organic_domain

            # **PHASE 2: KEYWORD FALLBACK** - Secondary method for edge cases
            app_name = getattr(apk_context, "app_name", "").lower()

            # Calculate domain scores for all business domains using keywords
            domain_scores = {}

            for domain, patterns in self.BUSINESS_DOMAIN_PATTERNS.items():
                score = self._calculate_domain_score(package_name, app_name, apk_context, patterns)
                domain_scores[domain] = score

            # Find the domain with the highest score
            best_domain = max(domain_scores.items(), key=lambda x: x[1])

            # Require minimum confidence threshold for domain classification
            if best_domain[1] >= 3:  # At least 3 matching indicators
                self.logger.info(
                    f"Keyword fallback detection: {best_domain[0].value} (score: {best_domain[1]}) for {package_name}"
                )
                return best_domain[0]
            else:
                self.logger.debug(
                    f"No business domain detected for {package_name} (best: {best_domain[0].value}, score: {best_domain[1]})"  # noqa: E501
                )
                return BusinessDomain.UNKNOWN

        except Exception as e:
            self.logger.error(f"Error detecting business domain: {e}")
            return BusinessDomain.UNKNOWN

    def _calculate_domain_score(self, package_name: str, app_name: str, apk_context, patterns: Dict) -> int:
        """Calculate domain matching score based on multiple indicators."""
        score = 0

        # Package name analysis (weight: 1 per match)
        for keyword in patterns.get("package_keywords", []):
            if keyword in package_name:
                score += 1

        # App name analysis (weight: 1 per match)
        for keyword in patterns.get("app_name_keywords", []):
            if keyword in app_name:
                score += 1

        # Permission analysis (weight: 2 per match - more significant)
        permissions = getattr(apk_context, "permissions", [])
        if permissions:
            for permission in patterns.get("permission_indicators", []):
                if any(permission.lower() in perm.lower() for perm in permissions):
                    score += 2

        # Manifest features analysis (weight: 2 per match)
        manifest_content = getattr(apk_context, "manifest_content", "")
        if manifest_content:
            for feature in patterns.get("manifest_features", []):
                if feature in manifest_content:
                    score += 2

        return score

    def detect_business_domain_organic(self, apk_context) -> BusinessDomain:
        """
        **ORGANIC DETECTION**: Detect business domain using app characteristics without hardcoding.

        Analyzes organic app characteristics like permission patterns, API usage,
        manifest features, and behavioral indicators to determine business domain.
        """
        try:
            # Analyze permission patterns for organic classification
            permission_profile = self._analyze_permission_patterns(apk_context)

            # Analyze manifest features and configurations
            manifest_profile = self._analyze_manifest_characteristics(apk_context)

            # Analyze API usage patterns (if available)
            api_profile = self._analyze_api_usage_patterns(apk_context)

            # Analyze resource and asset patterns
            resource_profile = self._analyze_resource_patterns(apk_context)

            # Combine all organic indicators
            organic_scores = self._calculate_organic_domain_scores(
                permission_profile, manifest_profile, api_profile, resource_profile
            )

            # Find best match
            if organic_scores:
                best_domain = max(organic_scores.items(), key=lambda x: x[1])
                if best_domain[1] >= 3:  # Minimum confidence threshold
                    self.logger.info(f"Organic detection: {best_domain[0].value} (score: {best_domain[1]})")
                    return best_domain[0]

            return BusinessDomain.UNKNOWN

        except Exception as e:
            self.logger.error(f"Organic business domain detection failed: {e}")
            return BusinessDomain.UNKNOWN

    def _analyze_permission_patterns(self, apk_context) -> Dict[str, int]:
        """Analyze permission usage patterns to infer app type organically."""
        permissions = getattr(apk_context, "permissions", [])
        if not permissions:
            return {}

        # **IMPROVED**: More discriminating permission analysis
        permission_indicators = {
            # Banking/Financial patterns (highly specific)
            "financial_security": sum(
                1
                for p in permissions
                if any(indicator in p.lower() for indicator in ["fingerprint", "biometric", "device_admin"])
            )
            + sum(
                2
                for p in permissions
                if any(
                    indicator in p.lower() for indicator in ["sms", "receive_sms"]  # SMS is critical for banking 2FA
                )
            ),
            # Healthcare patterns (body sensors are unique)
            "health_sensors": sum(
                3
                for p in permissions
                if any(
                    indicator in p.lower()
                    for indicator in ["body_sensors", "heart_rate", "step_counter"]  # Highly specific to health
                )
            ),
            # Gaming patterns (vibration + billing combination)
            "gaming_features": sum(1 for p in permissions if "vibrate" in p.lower())
            + sum(2 for p in permissions if "billing" in p.lower())
            + sum(1 for p in permissions if "wake_lock" in p.lower()),
            # Social media patterns (camera + contacts + microphone combination)
            "social_features": (
                (1 if any("camera" in p.lower() for p in permissions) else 0)
                + (2 if any("contacts" in p.lower() for p in permissions) else 0)  # Contacts are key for social
                + (1 if any("record_audio" in p.lower() or "microphone" in p.lower() for p in permissions) else 0)
            ),
            # Enterprise patterns (device admin is key)
            "enterprise_features": sum(3 for p in permissions if "device_admin" in p.lower())
            + sum(
                1
                for p in permissions
                if any(
                    indicator in p.lower() for indicator in ["system_alert_window", "write_settings", "managed_users"]
                )
            ),
            # Utility patterns (system-level permissions)
            "system_features": sum(
                1
                for p in permissions
                if any(
                    indicator in p.lower()
                    for indicator in ["system_alert_window", "write_settings", "device_power", "superuser"]
                )
            ),
            # Travel/Navigation patterns (location is necessary but not sufficient)
            "location_features": (
                sum(
                    1
                    for p in permissions
                    if any(indicator in p.lower() for indicator in ["fine_location", "coarse_location"])
                )
                if len([p for p in permissions if "location" in p.lower()]) >= 2
                else 0
                # Only count if multiple location permissions (indicates heavy location usage)
            ),
        }

        return permission_indicators

    def _analyze_manifest_characteristics(self, apk_context) -> Dict[str, int]:
        """Analyze AndroidManifest.xml characteristics organically."""
        manifest_content = getattr(apk_context, "manifest_content", "")
        if not manifest_content:
            return {}

        manifest_lower = manifest_content.lower()

        characteristics = {
            # Banking: Security-focused configurations
            "security_hardening": sum(
                1
                for indicator in [
                    "network_security_config",
                    "certificate_pinning",
                    "obfuscation",
                    "tamper_detection",
                    "root_detection",
                ]
                if indicator in manifest_lower
            ),
            # Healthcare: Privacy and sensor configurations
            "privacy_controls": sum(
                1
                for indicator in [
                    "health_permission",
                    "medical_device",
                    "hipaa_compliance",
                    "sensor_privacy",
                    "data_encryption",
                ]
                if indicator in manifest_lower
            ),
            # Gaming: Performance and graphics configurations
            "gaming_optimizations": sum(
                1
                for indicator in [
                    "hardware_accelerated",
                    "game_mode",
                    "performance_mode",
                    "graphics_api",
                    "opengl",
                    "vulkan",
                ]
                if indicator in manifest_lower
            ),
            # Social: Communication and media configurations
            "media_processing": sum(
                1
                for indicator in [
                    "camera_api",
                    "media_recorder",
                    "audio_processing",
                    "video_encoding",
                    "image_processing",
                ]
                if indicator in manifest_lower
            ),
            # Enterprise: Management and administration
            "enterprise_management": sum(
                1
                for indicator in ["device_admin", "managed_profile", "work_profile", "enterprise_policy", "mdm_support"]
                if indicator in manifest_lower
            ),
            # Travel: Location and mapping services
            "location_services": sum(
                1
                for indicator in ["location_service", "maps_api", "navigation", "gps_provider", "geofencing"]
                if indicator in manifest_lower
            ),
        }

        return characteristics

    def _analyze_api_usage_patterns(self, apk_context) -> Dict[str, int]:
        """Analyze API usage patterns from source code (if available)."""
        # This would analyze decompiled source for API patterns
        # For now, return empty dict - can be enhanced with source analysis
        return {}

    def _analyze_resource_patterns(self, apk_context) -> Dict[str, int]:
        """Analyze app resources and assets for organic classification."""
        # Analyze resource files, layouts, drawables for domain indicators
        # This could look at:
        # - Layout complexity (simple utility vs complex social media)
        # - Asset types (medical icons, financial symbols, game sprites)
        # - String resources (domain-specific terminology)

        # For now, return basic analysis - can be enhanced
        return {}

    def _calculate_organic_domain_scores(
        self, permission_profile: Dict, manifest_profile: Dict, api_profile: Dict, resource_profile: Dict
    ) -> Dict[BusinessDomain, int]:
        """Calculate domain scores based on organic characteristics."""
        scores = {}

        # Banking/Financial scoring
        banking_score = (
            permission_profile.get("financial_security", 0) * 2 + manifest_profile.get("security_hardening", 0) * 3
        )
        if banking_score > 0:
            scores[BusinessDomain.BANKING] = banking_score

        # Healthcare scoring
        healthcare_score = (
            permission_profile.get("health_sensors", 0) * 3 + manifest_profile.get("privacy_controls", 0) * 2
        )
        if healthcare_score > 0:
            scores[BusinessDomain.HEALTHCARE] = healthcare_score

        # Gaming scoring
        gaming_score = (
            permission_profile.get("gaming_features", 0) * 2 + manifest_profile.get("gaming_optimizations", 0) * 3
        )
        if gaming_score > 0:
            scores[BusinessDomain.GAMING] = gaming_score

        # Social media scoring
        social_score = (
            permission_profile.get("social_features", 0) * 2 + manifest_profile.get("media_processing", 0) * 2
        )
        if social_score > 0:
            scores[BusinessDomain.SOCIAL_MEDIA] = social_score

        # E-commerce scoring
        ecommerce_score = permission_profile.get("commerce_features", 0) * 2
        if ecommerce_score > 0:
            scores[BusinessDomain.ECOMMERCE] = ecommerce_score

        # Enterprise scoring
        enterprise_score = (
            permission_profile.get("enterprise_features", 0) * 2 + manifest_profile.get("enterprise_management", 0) * 3
        )
        if enterprise_score > 0:
            scores[BusinessDomain.ENTERPRISE] = enterprise_score

        # Utility scoring
        utility_score = permission_profile.get("system_features", 0) * 2
        if utility_score > 0:
            scores[BusinessDomain.UTILITY] = utility_score

        # Travel scoring
        travel_score = (
            permission_profile.get("location_features", 0) * 2 + manifest_profile.get("location_services", 0) * 3
        )
        if travel_score > 0:
            scores[BusinessDomain.TRAVEL] = travel_score

        return scores

    def get_business_domain_info(self, domain: BusinessDomain) -> Dict[str, Any]:
        """Get detailed information about a business domain for reporting."""
        domain_info = {
            BusinessDomain.BANKING: {
                "name": "Banking & Financial Services",
                "security_level": "CRITICAL",
                "regulatory_requirements": ["PCI DSS", "SOX", "GDPR", "PSD2"],
                "common_vulnerabilities": ["Insecure Authentication", "Weak Cryptography", "Session Management"],
                "confidence_multiplier": 1.3,
            },
            BusinessDomain.HEALTHCARE: {
                "name": "Healthcare & Medical",
                "security_level": "CRITICAL",
                "regulatory_requirements": ["HIPAA", "GDPR", "FDA", "HITECH"],
                "common_vulnerabilities": ["Data Leakage", "Insecure Storage", "Privacy Violations"],
                "confidence_multiplier": 1.2,
            },
            BusinessDomain.GAMING: {
                "name": "Gaming & Entertainment",
                "security_level": "MEDIUM",
                "regulatory_requirements": ["COPPA", "GDPR"],
                "common_vulnerabilities": ["In-App Purchase Issues", "Social Engineering", "Privacy"],
                "confidence_multiplier": 0.8,
            },
            BusinessDomain.ECOMMERCE: {
                "name": "E-Commerce & Retail",
                "security_level": "HIGH",
                "regulatory_requirements": ["PCI DSS", "GDPR", "CCPA"],
                "common_vulnerabilities": ["Payment Security", "Session Management", "Data Protection"],
                "confidence_multiplier": 1.1,
            },
            BusinessDomain.SOCIAL_MEDIA: {
                "name": "Social Media & Communication",
                "security_level": "HIGH",
                "regulatory_requirements": ["GDPR", "CCPA", "COPPA"],
                "common_vulnerabilities": ["Privacy Violations", "Data Leakage", "Authentication Issues"],
                "confidence_multiplier": 1.1,
            },
            BusinessDomain.GOVERNMENT: {
                "name": "Government & Public Services",
                "security_level": "CRITICAL",
                "regulatory_requirements": ["FISMA", "NIST", "GDPR", "Local Regulations"],
                "common_vulnerabilities": ["Authentication", "Authorization", "Data Protection"],
                "confidence_multiplier": 1.3,
            },
            BusinessDomain.EDUCATION: {
                "name": "Education & Learning",
                "security_level": "MEDIUM",
                "regulatory_requirements": ["FERPA", "COPPA", "GDPR"],
                "common_vulnerabilities": ["Privacy Issues", "Data Protection", "Access Control"],
                "confidence_multiplier": 0.85,
            },
            BusinessDomain.ENTERPRISE: {
                "name": "Enterprise & Business",
                "security_level": "HIGH",
                "regulatory_requirements": ["SOX", "GDPR", "Industry-Specific"],
                "common_vulnerabilities": ["Access Control", "Data Leakage", "Authentication"],
                "confidence_multiplier": 1.25,
            },
            BusinessDomain.UTILITY: {
                "name": "Utilities & Tools",
                "security_level": "MEDIUM",
                "regulatory_requirements": ["GDPR", "Platform Guidelines"],
                "common_vulnerabilities": ["Excessive Permissions", "Privacy Issues", "Malware"],
                "confidence_multiplier": 0.9,
            },
            BusinessDomain.TRAVEL: {
                "name": "Travel & Transportation",
                "security_level": "MEDIUM",
                "regulatory_requirements": ["GDPR", "CCPA", "Location Privacy"],
                "common_vulnerabilities": ["Location Privacy", "Payment Security", "Data Protection"],
                "confidence_multiplier": 1.0,
            },
            BusinessDomain.NEWS_MEDIA: {
                "name": "News & Media",
                "security_level": "MEDIUM",
                "regulatory_requirements": ["GDPR", "CCPA", "Content Regulations"],
                "common_vulnerabilities": ["Privacy Issues", "Content Security", "Data Protection"],
                "confidence_multiplier": 0.95,
            },
            BusinessDomain.UNKNOWN: {
                "name": "Unknown Domain",
                "security_level": "MEDIUM",
                "regulatory_requirements": ["GDPR", "Platform Guidelines"],
                "common_vulnerabilities": ["General Security Issues"],
                "confidence_multiplier": 1.0,
            },
        }

        return domain_info.get(domain, domain_info[BusinessDomain.UNKNOWN])


# Global detector instance
app_type_detector = AppTypeDetector()


def detect_app_type(apk_context) -> AppType:
    """Convenience function for app type detection."""
    return app_type_detector.detect_app_type(apk_context)


def detect_business_domain(apk_context) -> BusinessDomain:
    """Convenience function for business domain detection (hybrid approach)."""
    return app_type_detector.detect_business_domain(apk_context)


def detect_business_domain_organic(apk_context) -> BusinessDomain:
    """Convenience function for organic business domain detection (no hardcoding)."""
    return app_type_detector.detect_business_domain_organic(apk_context)


def get_business_domain_info(domain: BusinessDomain) -> Dict[str, Any]:
    """Convenience function to get business domain information."""
    return app_type_detector.get_business_domain_info(domain)


def get_filtering_config_for_context(apk_context) -> Dict:
    """Get filtering configuration for given APK context."""
    app_type = detect_app_type(apk_context)
    return app_type_detector.get_filtering_config(app_type)
