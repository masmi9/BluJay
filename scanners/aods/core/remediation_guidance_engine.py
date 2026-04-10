#!/usr/bin/env python3
"""
Remediation Guidance Engine - Simple & Practical
===============================================

Provides automated, actionable remediation guidance for detected vulnerabilities.
Focuses on specific fix recommendations, code examples, and effort estimation.

Design Principles:
- Actionable guidance: Specific, implementable fix recommendations
- Code-level examples: Practical before/after code demonstrations
- Effort estimation: Realistic time and complexity assessments
- Priority-based: Risk-driven remediation roadmap
- Well-thought-out: Precise, surgical guidance for each vulnerability type
"""

from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


class RemediationPriority(Enum):
    """Priority levels for remediation tasks."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RemediationComplexity(Enum):
    """Complexity levels for remediation implementation."""

    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    ARCHITECTURAL = "architectural"


@dataclass
class RemediationStep:
    """Individual step in remediation process."""

    step_number: int
    title: str
    description: str
    code_example: Optional[str] = None
    verification_method: str = ""
    estimated_hours: float = 0.0
    complexity: RemediationComplexity = RemediationComplexity.SIMPLE


@dataclass
class RemediationGuidance:
    """Complete remediation guidance for a vulnerability."""

    guidance_id: str
    vulnerability_id: str
    vulnerability_title: str
    priority: RemediationPriority
    overall_complexity: RemediationComplexity
    estimated_total_hours: float
    fix_summary: str
    detailed_description: str
    root_cause_analysis: str
    remediation_steps: List[RemediationStep] = field(default_factory=list)
    code_examples: Dict[str, str] = field(default_factory=dict)
    verification_checklist: List[str] = field(default_factory=list)
    best_practices: List[str] = field(default_factory=list)
    prevention_measures: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert RemediationGuidance to dictionary for serialization."""
        return {
            "guidance_id": self.guidance_id,
            "vulnerability_id": self.vulnerability_id,
            "vulnerability_title": self.vulnerability_title,
            "priority": self.priority.value if hasattr(self.priority, "value") else str(self.priority),
            "overall_complexity": (
                self.overall_complexity.value
                if hasattr(self.overall_complexity, "value")
                else str(self.overall_complexity)
            ),
            "estimated_total_hours": self.estimated_total_hours,
            "fix_summary": self.fix_summary,
            "detailed_description": self.detailed_description,
            "root_cause_analysis": self.root_cause_analysis,
            "remediation_steps": [
                {
                    "step_number": step.step_number,
                    "title": step.title,
                    "description": step.description,
                    "code_example": step.code_example,
                    "verification_method": step.verification_method,
                    "estimated_hours": step.estimated_hours,
                    "complexity": step.complexity.value if hasattr(step.complexity, "value") else str(step.complexity),
                }
                for step in self.remediation_steps
            ],
            "code_examples": self.code_examples,
            "verification_checklist": self.verification_checklist,
            "best_practices": self.best_practices,
            "prevention_measures": self.prevention_measures,
            "references": self.references,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


class RemediationGuidanceEngine:
    """
    Automated remediation guidance engine for AODS vulnerabilities.

    Features:
    - Specific fix recommendations for each vulnerability type
    - Code-level remediation examples and best practices
    - Priority-based remediation roadmap
    - Effort estimation for each fix (hours/complexity)
    - Verification steps for remediation validation
    """

    def __init__(self):
        """Initialize remediation guidance engine."""
        self.logger = logger

        # Remediation knowledge base
        self.remediation_templates = self._initialize_remediation_templates()

        # Effort estimation models
        self.effort_models = self._initialize_effort_models()

        # Priority calculation weights
        self.priority_weights = self._initialize_priority_weights()

        # Generated guidance tracking
        self.generated_guidance: Dict[str, RemediationGuidance] = {}

        # Guidance generation statistics
        self.generation_stats = {
            "total_generated": 0,
            "by_priority": {priority.value: 0 for priority in RemediationPriority},
            "by_complexity": {complexity.value: 0 for complexity in RemediationComplexity},
            "total_estimated_hours": 0.0,
            "generation_errors": 0,
        }

        self.logger.info("Remediation Guidance Engine initialized")

    def generate_remediation_guidance(self, vulnerability: Dict[str, Any]) -> Optional[RemediationGuidance]:
        """
        Generate full remediation guidance for a vulnerability.

        Args:
            vulnerability: Vulnerability dictionary with details

        Returns:
            RemediationGuidance or None if not applicable
        """
        try:
            # Generate vulnerability ID
            vuln_id = self._generate_vulnerability_id(vulnerability)

            # Determine remediation template
            template_key = self._determine_remediation_template(vulnerability)
            if not template_key:
                return None

            # Calculate priority and complexity
            priority = self._calculate_remediation_priority(vulnerability)
            complexity = self._estimate_remediation_complexity(vulnerability)

            # Generate guidance from template
            guidance = self._generate_guidance_from_template(template_key, vulnerability, vuln_id, priority, complexity)

            # Calculate effort estimation
            guidance.estimated_total_hours = self._calculate_total_effort(guidance)

            # Store generated guidance
            self.generated_guidance[guidance.guidance_id] = guidance

            # Update statistics
            self.generation_stats["total_generated"] += 1
            self.generation_stats["by_priority"][priority.value] += 1
            self.generation_stats["by_complexity"][complexity.value] += 1
            self.generation_stats["total_estimated_hours"] += guidance.estimated_total_hours

            return guidance

        except Exception as e:
            self.logger.error(f"Remediation guidance generation failed: {e}")
            self.generation_stats["generation_errors"] += 1
            return None

    def _determine_remediation_template(self, vulnerability: Dict[str, Any]) -> Optional[str]:
        """Determine which remediation template to use."""

        category = str(vulnerability.get("category", "")).lower()
        title = str(vulnerability.get("title", "")).lower()
        description = str(vulnerability.get("description", "")).lower()

        # Map vulnerability characteristics to remediation templates
        # Check CSRF first to avoid conflict with 'token' in hardcoded credentials
        if (
            any(
                term in category + title + description
                for term in ["csrf", "request.*forgery", "cwe-352", "session_fixation", "clickjacking"]
            )
            or (
                "cross-site" in category + title + description
                and any(term in category + title + description for term in ["request", "forgery"])
            )
            or (
                "token" in category + title + description
                and any(
                    term in category + title + description
                    for term in ["missing", "validation", "state", "origin", "referrer"]
                )
            )
        ):
            return "csrf_remediation"
        elif any(
            term in category + title + description
            for term in [
                "hardcoded",
                "hard-coded",
                "secret",
                "api_key",
                "apikey",
                "password",
                "private_key",
                "privatekey",
                "credential",
            ]
        ):
            return "hardcoded_credentials_remediation"
        elif any(
            term in category + title + description
            for term in [
                "component",
                "export",
                "exported",
                "intent",
                "activity",
                "service",
                "receiver",
                "provider",
                "manifest",
                "cwe-926",
            ]
        ):
            return "component_export_remediation"
        elif any(
            term in category + title + description
            for term in [
                "path",
                "traversal",
                "directory",
                "file",
                "cwe-22",
                "path_traversal",
                "../",
                "..\\",
                "zip",
                "extraction",
            ]
        ):
            return "path_traversal_remediation"
        elif any(
            term in category + title + description
            for term in [
                "deserialization",
                "deserialize",
                "serialization",
                "serialize",
                "cwe-502",
                "objectinputstream",
                "readobject",
                "gson",
                "jackson",
                "binaryformatter",
                "xmldecoder",
                "xstream",
            ]
        ):
            return "insecure_deserialization_remediation"
        elif any(
            term in category + title + description
            for term in [
                "android-14",
                "api-34",
                "target-sdk",
                "permission-model",
                "edge-to-edge",
                "predictive-back",
                "android14",
                "targetsdkversion",
                "compilesdkversion",
                "security-update",
                "patch-level",
            ]
        ):
            return "android_14_security_remediation"
        elif any(
            term in category + title + description
            for term in [
                "gdpr",
                "compliance",
                "consent",
                "data-subject",
                "privacy-policy",
                "data-protection",
                "legal-basis",
                "data-minimization",
                "retention",
                "cross-border",
                "breach-notification",
                "children-data",
            ]
        ):
            return "gdpr_compliance_remediation"
        elif any(
            term in category + title + description
            for term in [
                "privacy",
                "leak",
                "pii",
                "personal",
                "sensitive",
                "logging",
                "log",
                "debug",
                "analytics",
                "tracking",
                "ccpa",
                "clipboard",
                "location",
                "contact",
                "device",
                "advertising",
            ]
        ):
            return "privacy_leak_remediation"
        elif any(
            term in category + title + description
            for term in [
                "xss",
                "cross-site",
                "scripting",
                "javascript",
                "eval",
                "innerhtml",
                "document.write",
                "evaluatejavascript",
                "dom-based",
                "reflected",
                "stored",
                "persistent",
            ]
        ):
            return "xss_remediation"
        elif any(
            term in category + title + description
            for term in [
                "webview",
                "bridge",
                "addjavascriptinterface",
                "csp",
                "content-security-policy",
                "file",
                "access",
                "universal",
                "hybrid",
            ]
        ):
            return "webview_security_remediation"
        elif any(
            term in category + title + description
            for term in [
                "broadcast",
                "receiver",
                "intent",
                "ipc",
                "exported",
                "permission",
                "boot_completed",
                "connectivity_change",
                "system_broadcast",
            ]
        ):
            return "broadcast_receiver_remediation"
        elif any(
            term in category + title + description
            for term in [
                "ssl",
                "tls",
                "certificate",
                "pinning",
                "trust",
                "hostname",
                "verifier",
                "https",
                "x509",
                "cipher",
                "protocol",
            ]
        ):
            return "ssl_tls_security_remediation"
        elif any(
            term in category + title + description
            for term in [
                "sql",
                "injection",
                "cwe-89",
                "execsql",
                "rawquery",
                "parameterized",
                "prepared",
                "statement",
                "string_concatenation",
                "database_query",
            ]
        ):
            return "sql_injection_remediation"
        elif any(
            term in category + title + description
            for term in [
                "ssrf",
                "server-side",
                "cwe-918",
                "url",
                "internal",
                "metadata",
                "network",
                "unvalidated",
                "dns",
                "rebinding",
                "localhost",
                "webhook",
                "callback",
            ]
        ):
            return "ssrf_remediation"
        elif any(term in category + title + description for term in ["auth", "login", "session"]):
            return "authentication_remediation"
        elif any(term in category + title + description for term in ["crypto", "encryption", "ssl", "tls"]):
            return "crypto_remediation"
        elif any(term in category + title + description for term in ["storage", "file", "data"]):
            return "storage_remediation"
        elif any(term in category + title + description for term in ["network", "communication"]):
            return "network_remediation"
        elif any(term in category + title + description for term in ["config", "manifest", "permission"]):
            return "configuration_remediation"
        elif any(term in category + title + description for term in ["validation", "input"]):
            return "input_validation_remediation"
        else:
            return "generic_remediation"

    def _calculate_remediation_priority(self, vulnerability: Dict[str, Any]) -> RemediationPriority:
        """Calculate remediation priority based on vulnerability characteristics."""

        severity = str(vulnerability.get("severity", "medium")).lower()
        category = str(vulnerability.get("category", "")).lower()

        # Base priority from severity
        severity_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 1}.get(severity, 2)

        # Category-based adjustments
        high_risk_categories = [
            "injection",
            "authentication",
            "authorization",
            "crypto",
            "session",
            "hardcoded",
            "credential",
            "secret",
            "api_key",
            "password",
            "token",
            "private_key",
        ]

        # Critical security categories get higher elevation
        critical_security_categories = [
            "hardcoded",
            "credential",
            "secret",
            "api_key",
            "password",
            "token",
            "private_key",
            "component",
            "export",
            "exported",
            "intent",
            "activity",
            "service",
            "receiver",
            "provider",
            "manifest",
            "path",
            "traversal",
            "directory",
            "file",
            "path_traversal",
            "../",
            "..\\",
            "zip",
            "extraction",
            "deserialization",
            "deserialize",
            "serialization",
            "serialize",
            "parcelable",
            "parcel",
            "bundle",
            "objectinputstream",
            "readobject",
            "binaryformatter",
            "json.parse",
            "xmldecoder",
            "bridge",
            "webview",
            "privacy",
            "pii",
            "personal",
            "sensitive",
            "gdpr",
            "ccpa",
            "logging",
            "debug",
            "analytics",
            "tracking",
            "clipboard",
            "location",
            "contact",
            "advertising",
            "leak",
            "broadcast",
            "ipc",
            "boot_completed",
            "connectivity_change",
            "system_broadcast",
            "inter-process",
            "permission",
            "signature",
            "intent-filter",
            "ordered_broadcast",
            "ssl",
            "tls",
            "certificate",
            "pinning",
            "trust",
            "hostname",
            "verifier",
            "https",
            "x509",
            "cipher",
            "xss",
            "cross-site",
            "scripting",
            "javascript",
            "webview",
            "eval",
            "innerhtml",
            "document.write",
            "sql",
            "injection",
            "execsql",
            "rawquery",
            "parameterized",
            "prepared",
            "statement",
            "csrf",
            "cross-site",
            "request",
            "forgery",
            "token",
            "state",
            "origin",
            "referrer",
            "ssrf",
            "server-side",
            "url",
            "request",
            "internal",
            "metadata",
            "network",
            "dns",
            "gdpr",
            "compliance",
            "consent",
            "data-subject",
            "privacy-policy",
            "data-protection",
            "legal-basis",
            "android-14",
            "api-34",
            "target-sdk",
            "permission-model",
            "edge-to-edge",
            "predictive-back",
        ]

        if any(cat in category for cat in critical_security_categories):
            severity_priority += 2  # Higher elevation for credential-related vulnerabilities
        elif any(cat in category for cat in high_risk_categories):
            severity_priority += 1

        # Map to priority enum
        if severity_priority >= 5:
            return RemediationPriority.CRITICAL
        elif severity_priority >= 4:
            return RemediationPriority.HIGH
        elif severity_priority >= 3:
            return RemediationPriority.MEDIUM
        else:
            return RemediationPriority.LOW

    def _estimate_remediation_complexity(self, vulnerability: Dict[str, Any]) -> RemediationComplexity:
        """Estimate remediation complexity based on vulnerability type."""

        category = str(vulnerability.get("category", "")).lower()
        title = str(vulnerability.get("title", "")).lower()

        # Architectural changes required
        if any(term in category + title for term in ["architecture", "design", "framework"]):
            return RemediationComplexity.ARCHITECTURAL

        # Complex changes
        elif any(term in category + title for term in ["authentication", "authorization", "crypto", "session"]):
            return RemediationComplexity.COMPLEX

        # Moderate changes
        elif any(term in category + title for term in ["storage", "network", "config"]):
            return RemediationComplexity.MODERATE

        # Simple fixes
        else:
            return RemediationComplexity.SIMPLE

    def _generate_guidance_from_template(
        self,
        template_key: str,
        vulnerability: Dict[str, Any],
        vuln_id: str,
        priority: RemediationPriority,
        complexity: RemediationComplexity,
    ) -> RemediationGuidance:
        """Generate remediation guidance from template."""

        template = self.remediation_templates.get(template_key, self.remediation_templates["generic_remediation"])

        # Create guidance instance
        guidance = RemediationGuidance(
            guidance_id=self._generate_guidance_id(),
            vulnerability_id=vuln_id,
            vulnerability_title=vulnerability.get("title", "Unknown Vulnerability"),
            priority=priority,
            overall_complexity=complexity,
            estimated_total_hours=0.0,  # Will be calculated later
            fix_summary=template["fix_summary"].format(
                vuln_title=vulnerability.get("title", "Unknown"), location=vulnerability.get("location", "unknown")
            ),
            detailed_description=template["detailed_description"],
            root_cause_analysis=template["root_cause_analysis"],
        )

        # Generate remediation steps from template
        for step_template in template["steps"]:
            step = RemediationStep(
                step_number=step_template["step_number"],
                title=step_template["title"],
                description=step_template["description"].format(
                    location=vulnerability.get("location", "unknown"),
                    file_path=vulnerability.get("file_path", "unknown"),
                ),
                code_example=step_template.get("code_example"),
                verification_method=step_template["verification_method"],
                estimated_hours=step_template["estimated_hours"],
                complexity=RemediationComplexity(step_template["complexity"]),
            )
            guidance.remediation_steps.append(step)

        # Add code examples
        guidance.code_examples = template.get("code_examples", {})

        # Add verification checklist
        guidance.verification_checklist = template.get("verification_checklist", [])

        # Add best practices
        guidance.best_practices = template.get("best_practices", [])

        # Add prevention measures
        guidance.prevention_measures = template.get("prevention_measures", [])

        # Add references
        guidance.references = template.get("references", [])

        # Add metadata
        guidance.metadata = {
            "template_used": template_key,
            "vulnerability_category": vulnerability.get("category", "unknown"),
            "vulnerability_severity": vulnerability.get("severity", "unknown"),
            "generation_method": "template_based",
        }

        return guidance

    def _calculate_total_effort(self, guidance: RemediationGuidance) -> float:
        """Calculate total effort estimation for remediation."""

        base_hours = sum(step.estimated_hours for step in guidance.remediation_steps)

        # Complexity multipliers
        complexity_multipliers = {
            RemediationComplexity.SIMPLE: 1.0,
            RemediationComplexity.MODERATE: 1.5,
            RemediationComplexity.COMPLEX: 2.5,
            RemediationComplexity.ARCHITECTURAL: 4.0,
        }

        multiplier = complexity_multipliers.get(guidance.overall_complexity, 1.0)

        # Priority adjustments (urgent work often takes longer)
        priority_adjustments = {
            RemediationPriority.CRITICAL: 1.2,
            RemediationPriority.HIGH: 1.1,
            RemediationPriority.MEDIUM: 1.0,
            RemediationPriority.LOW: 0.9,
        }

        priority_adjustment = priority_adjustments.get(guidance.priority, 1.0)

        return round(base_hours * multiplier * priority_adjustment, 1)

    def _initialize_remediation_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize remediation templates from YAML config file."""
        import yaml

        config_path = Path(__file__).parent.parent / "config" / "remediation_templates.yaml"
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                templates = yaml.safe_load(f)
            if isinstance(templates, dict):
                return templates
        except Exception as e:
            self.logger.warning(f"Failed to load remediation templates: {e}")
        return self._fallback_generic_template()

    def _fallback_generic_template(self) -> Dict[str, Dict[str, Any]]:
        """Provide minimal fallback template if YAML file is unavailable."""
        return {
            "generic_remediation": {
                "fix_summary": "Review and remediate the security issue: {vuln_title}",
                "detailed_description": "A security vulnerability was detected that requires manual review and remediation.",  # noqa: E501
                "root_cause_analysis": "Security best practices were not followed in the implementation.",
                "steps": [
                    {
                        "step_number": 1,
                        "title": "Review the vulnerability",
                        "description": "Examine the code at {location} in {file_path} to understand the security issue.",  # noqa: E501
                        "code_example": None,
                        "verification_method": "Manual code review",
                        "estimated_hours": 2.0,
                        "complexity": "moderate",
                    }
                ],
                "code_examples": {},
                "verification_checklist": ["Verify the fix addresses the root cause", "Run security tests"],
                "best_practices": ["Follow OWASP security guidelines"],
                "prevention_measures": ["Implement security code review process"],
                "references": ["OWASP Mobile Security Testing Guide"],
            }
        }

    def _initialize_effort_models(self) -> Dict[str, Dict[str, float]]:
        """Initialize effort estimation models."""

        return {
            "base_hours_by_complexity": {"simple": 2.0, "moderate": 4.0, "complex": 8.0, "architectural": 16.0},
            "category_multipliers": {
                "injection": 1.2,
                "authentication": 1.5,
                "crypto": 1.3,
                "network": 1.4,
                "storage": 1.1,
                "configuration": 0.8,
                "validation": 0.9,
            },
        }

    def _initialize_priority_weights(self) -> Dict[str, float]:
        """Initialize priority calculation weights."""

        return {
            "severity_weight": 0.4,
            "category_weight": 0.3,
            "exploitability_weight": 0.2,
            "business_impact_weight": 0.1,
        }

    def _generate_vulnerability_id(self, vulnerability: Dict[str, Any]) -> str:
        """Generate unique vulnerability ID."""
        import hashlib

        title = vulnerability.get("title", "unknown")
        location = vulnerability.get("location", "unknown")
        category = vulnerability.get("category", "unknown")

        id_string = f"{title}_{location}_{category}"
        return hashlib.md5(id_string.encode()).hexdigest()[:12]

    def _generate_guidance_id(self) -> str:
        """Generate unique guidance ID."""
        import hashlib
        import time

        timestamp = str(time.time())
        return f"remediation_{hashlib.md5(timestamp.encode()).hexdigest()[:8]}"

    def get_guidance_by_id(self, guidance_id: str) -> Optional[RemediationGuidance]:
        """Get remediation guidance by ID."""
        return self.generated_guidance.get(guidance_id)

    def get_generation_statistics(self) -> Dict[str, Any]:
        """Get remediation guidance generation statistics."""
        return {
            **self.generation_stats,
            "total_stored_guidance": len(self.generated_guidance),
            "average_hours_per_vulnerability": (
                self.generation_stats["total_estimated_hours"] / self.generation_stats["total_generated"]
                if self.generation_stats["total_generated"] > 0
                else 0
            ),
        }

    def generate_remediation_roadmap(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate priority-based remediation roadmap for multiple vulnerabilities."""

        try:
            # Generate guidance for all vulnerabilities
            guidance_list = []
            for vulnerability in vulnerabilities:
                guidance = self.generate_remediation_guidance(vulnerability)
                if guidance:
                    guidance_list.append(guidance)

            # Sort by priority and estimated hours
            priority_order = {
                RemediationPriority.CRITICAL: 4,
                RemediationPriority.HIGH: 3,
                RemediationPriority.MEDIUM: 2,
                RemediationPriority.LOW: 1,
            }

            guidance_list.sort(key=lambda g: (priority_order[g.priority], -g.estimated_total_hours), reverse=True)

            # Calculate roadmap statistics
            total_hours = sum(g.estimated_total_hours for g in guidance_list)
            priority_breakdown = {}
            complexity_breakdown = {}

            for guidance in guidance_list:
                priority = guidance.priority.value
                complexity = guidance.overall_complexity.value

                priority_breakdown[priority] = priority_breakdown.get(priority, 0) + 1
                complexity_breakdown[complexity] = complexity_breakdown.get(complexity, 0) + 1

            return {
                "roadmap_summary": {
                    "total_vulnerabilities": len(guidance_list),
                    "total_estimated_hours": total_hours,
                    "estimated_weeks": round(total_hours / 40, 1),  # Assuming 40-hour work weeks
                    "priority_breakdown": priority_breakdown,
                    "complexity_breakdown": complexity_breakdown,
                },
                "remediation_sequence": [
                    {
                        "sequence_number": i + 1,
                        "guidance_id": guidance.guidance_id,
                        "vulnerability_title": guidance.vulnerability_title,
                        "priority": guidance.priority.value,
                        "complexity": guidance.overall_complexity.value,
                        "estimated_hours": guidance.estimated_total_hours,
                        "fix_summary": guidance.fix_summary,
                    }
                    for i, guidance in enumerate(guidance_list)
                ],
                "milestone_planning": self._generate_milestone_planning(guidance_list),
            }

        except Exception as e:
            self.logger.error(f"Remediation roadmap generation failed: {e}")
            return {"error": str(e)}

    def _generate_milestone_planning(self, guidance_list: List[RemediationGuidance]) -> List[Dict[str, Any]]:
        """Generate milestone planning for remediation roadmap."""

        milestones = []
        current_milestone = []
        current_hours = 0.0
        milestone_threshold = 40.0  # 1 week of work
        milestone_number = 1

        for guidance in guidance_list:
            if current_hours + guidance.estimated_total_hours > milestone_threshold and current_milestone:
                # Create milestone
                milestones.append(
                    {
                        "milestone_number": milestone_number,
                        "milestone_name": f"Remediation Sprint {milestone_number}",
                        "total_hours": current_hours,
                        "vulnerabilities_count": len(current_milestone),
                        "vulnerabilities": current_milestone.copy(),
                    }
                )

                # Start new milestone
                milestone_number += 1
                current_milestone = []
                current_hours = 0.0

            current_milestone.append(
                {
                    "vulnerability_title": guidance.vulnerability_title,
                    "priority": guidance.priority.value,
                    "estimated_hours": guidance.estimated_total_hours,
                }
            )
            current_hours += guidance.estimated_total_hours

        # Add final milestone if there are remaining items
        if current_milestone:
            milestones.append(
                {
                    "milestone_number": milestone_number,
                    "milestone_name": f"Remediation Sprint {milestone_number}",
                    "total_hours": current_hours,
                    "vulnerabilities_count": len(current_milestone),
                    "vulnerabilities": current_milestone,
                }
            )

        return milestones

    def export_guidance(self, guidance_id: str, output_path: str) -> bool:
        """Export remediation guidance to file."""
        try:
            guidance = self.generated_guidance.get(guidance_id)
            if not guidance:
                return False

            import json

            # Convert to serializable format
            export_data = {
                "guidance_id": guidance.guidance_id,
                "vulnerability_id": guidance.vulnerability_id,
                "vulnerability_title": guidance.vulnerability_title,
                "priority": guidance.priority.value,
                "overall_complexity": guidance.overall_complexity.value,
                "estimated_total_hours": guidance.estimated_total_hours,
                "fix_summary": guidance.fix_summary,
                "detailed_description": guidance.detailed_description,
                "root_cause_analysis": guidance.root_cause_analysis,
                "remediation_steps": [
                    {
                        "step_number": step.step_number,
                        "title": step.title,
                        "description": step.description,
                        "code_example": step.code_example,
                        "verification_method": step.verification_method,
                        "estimated_hours": step.estimated_hours,
                        "complexity": step.complexity.value,
                    }
                    for step in guidance.remediation_steps
                ],
                "code_examples": guidance.code_examples,
                "verification_checklist": guidance.verification_checklist,
                "best_practices": guidance.best_practices,
                "prevention_measures": guidance.prevention_measures,
                "references": guidance.references,
                "timestamp": guidance.timestamp,
                "metadata": guidance.metadata,
            }

            with open(output_path, "w") as f:
                json.dump(export_data, f, indent=2)

            return True

        except Exception as e:
            self.logger.error(f"Guidance export failed: {e}")
            return False

    def clear_generated_guidance(self):
        """Clear all generated guidance."""
        self.generated_guidance.clear()
        self.generation_stats = {
            "total_generated": 0,
            "by_priority": {priority.value: 0 for priority in RemediationPriority},
            "by_complexity": {complexity.value: 0 for complexity in RemediationComplexity},
            "total_estimated_hours": 0.0,
            "generation_errors": 0,
        }
        self.logger.info("Generated remediation guidance cleared")


# Simple integration test
if __name__ == "__main__":
    logger.info("Testing Remediation Guidance Engine")

    # Create engine
    engine = RemediationGuidanceEngine()

    # Test vulnerabilities
    test_vulnerabilities = [
        {
            "title": "SQL Injection in Login Form",
            "category": "injection",
            "severity": "critical",
            "location": "LoginActivity.java:45",
            "description": "SQL injection vulnerability in user authentication",
        },
        {
            "title": "Weak SSL Configuration",
            "category": "network",
            "severity": "high",
            "location": "NetworkManager.java:78",
            "description": "SSL certificate validation bypass",
        },
        {
            "title": "Insecure Data Storage",
            "category": "storage",
            "severity": "medium",
            "location": "DataHelper.java:123",
            "description": "Sensitive data stored in plaintext",
        },
    ]

    # Test remediation guidance generation
    for i, vulnerability in enumerate(test_vulnerabilities, 1):
        logger.info("Testing vulnerability", test_number=i, title=vulnerability["title"])

        guidance = engine.generate_remediation_guidance(vulnerability)

        if guidance:
            logger.info(
                "Guidance generated",
                fix_summary=guidance.fix_summary,
                priority=guidance.priority.value,
                complexity=guidance.overall_complexity.value,
                estimated_hours=guidance.estimated_total_hours,
                steps=len(guidance.remediation_steps),
            )

            # Show first step
            if guidance.remediation_steps:
                step = guidance.remediation_steps[0]
                logger.info("First step", title=step.title, estimated_hours=step.estimated_hours)
        else:
            logger.warning("No guidance generated")

    # Test roadmap generation
    logger.info("Testing Remediation Roadmap Generation")
    roadmap = engine.generate_remediation_roadmap(test_vulnerabilities)

    if "roadmap_summary" in roadmap:
        summary = roadmap["roadmap_summary"]
        milestones = roadmap.get("milestone_planning", [])
        logger.info(
            "Roadmap generated",
            total_vulnerabilities=summary["total_vulnerabilities"],
            total_hours=summary["total_estimated_hours"],
            estimated_weeks=summary["estimated_weeks"],
            priority_breakdown=summary["priority_breakdown"],
            milestones=len(milestones),
        )

    # Test statistics
    stats = engine.get_generation_statistics()
    logger.info(
        "Generation statistics",
        total_generated=stats["total_generated"],
        average_hours=round(stats["average_hours_per_vulnerability"], 1),
        priority_distribution=stats["by_priority"],
    )

    logger.info("Remediation Guidance Engine test completed")
