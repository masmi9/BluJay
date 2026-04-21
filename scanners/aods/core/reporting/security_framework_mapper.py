#!/usr/bin/env python3
"""
Security Framework Mapper - Simple & Practical
==============================================

Maps vulnerabilities to multiple security frameworks for compliance reporting.
Focus: Simple, effective, non-over-engineered solution.

Supported Frameworks:
- CWE (Common Weakness Enumeration)
- MITRE ATT&CK Mobile
- MASVS v2.0 (Mobile Application Security Verification Standard)
- OWASP Top 10 Mobile 2024
- NIST Cybersecurity Framework
- ISO 27001/27002 Security Controls
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path
import os

try:
    from core.logging_config import get_logger

    _module_logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    _module_logger = stdlib_logging.getLogger(__name__)


@dataclass
class SecurityFrameworkMapping:
    """Security framework mapping for a vulnerability."""

    cwe_id: Optional[str] = None
    cwe_name: Optional[str] = None
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    masvs_categories: List[str] = field(default_factory=list)
    owasp_mobile_categories: List[str] = field(default_factory=list)
    nist_controls: List[str] = field(default_factory=list)
    iso_controls: List[str] = field(default_factory=list)


@dataclass
class ComplianceScore:
    """Compliance scoring for security frameworks."""

    framework_name: str
    total_requirements: int
    covered_requirements: int
    coverage_percentage: float
    compliance_status: str  # Excellent, Good, Fair, Poor
    gap_areas: List[str] = field(default_factory=list)


class SecurityFrameworkMapper:
    """
    Simple security framework mapper for vulnerability compliance.

    Design Principles:
    - Static mapping databases for reliability
    - Simple lookup mechanisms
    - Clear compliance scoring
    - Easy maintenance and updates
    """

    def __init__(self):
        """Initialize with framework mapping databases."""
        try:
            from core.logging_config import get_logger

            self.logger = get_logger(__name__)
        except ImportError:
            import logging as stdlib_logging

            self.logger = stdlib_logging.getLogger(__name__)

        # Initialize mapping databases
        self.cwe_mappings = self._init_cwe_mappings()
        self.mitre_mappings = self._init_mitre_mappings()
        self.masvs_mappings = self._init_masvs_mappings()
        self.owasp_mappings = self._init_owasp_mappings()
        self.nist_mappings = self._init_nist_mappings()
        self.iso_mappings = self._init_iso_mappings()

        # Load authoritative sources metadata
        self.sources_meta: Dict[str, Any] = self._load_sources_metadata()
        self.logger.info("Security Framework Mapper initialized with 6 frameworks and sources metadata")

    def _load_sources_metadata(self) -> Dict[str, Any]:
        """Load authoritative mapping sources metadata from YAML if present."""
        try:
            cfg = os.getenv("AODS_MAPPING_SOURCES_PATH") or str(Path("configs/security_framework_mappings.yml"))
            p = Path(cfg)
            if not p.exists():
                return {}
            try:
                import yaml  # type: ignore
            except Exception:
                return {}
            data = yaml.safe_load(p.read_text(encoding="utf-8", errors="replace")) or {}
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def map_vulnerability(self, vulnerability: Dict[str, Any]) -> SecurityFrameworkMapping:
        """
        Map a vulnerability to all security frameworks.

        Args:
            vulnerability: Vulnerability dictionary with category, severity, etc.

        Returns:
            SecurityFrameworkMapping with all framework mappings
        """
        try:
            # Extract vulnerability characteristics
            category = str(vulnerability.get("category", "unknown")).lower()
            title = str(vulnerability.get("title") or vulnerability.get("name") or "").lower()
            description = str(vulnerability.get("description", "")).lower()

            # Create full mapping
            mapping = SecurityFrameworkMapping()

            # Map to CWE
            mapping.cwe_id, mapping.cwe_name = self._map_to_cwe(category, title, description)

            # Map to MITRE ATT&CK Mobile
            mapping.mitre_tactics, mapping.mitre_techniques = self._map_to_mitre(category, title)

            # Map to MASVS v2.0
            mapping.masvs_categories = self._map_to_masvs(category, title)

            # Map to OWASP Top 10 Mobile 2024
            mapping.owasp_mobile_categories = self._map_to_owasp(category, title)

            # Map to NIST Cybersecurity Framework
            mapping.nist_controls = self._map_to_nist(category, title)

            # Map to ISO 27001/27002
            mapping.iso_controls = self._map_to_iso(category, title)

            return mapping

        except Exception as e:
            self.logger.error(f"Framework mapping failed: {e}")
            return SecurityFrameworkMapping()  # Return empty mapping

    def calculate_compliance_scores(self, vulnerabilities: List[Dict[str, Any]]) -> List[ComplianceScore]:
        """Calculate compliance scores for all frameworks."""
        try:
            # Map all vulnerabilities
            mappings = [self.map_vulnerability(vuln) for vuln in vulnerabilities]

            # Calculate scores for each framework
            scores = []

            # CWE Coverage
            cwe_score = self._calculate_cwe_compliance(mappings)
            scores.append(cwe_score)

            # MITRE ATT&CK Coverage
            mitre_score = self._calculate_mitre_compliance(mappings)
            scores.append(mitre_score)

            # MASVS Coverage
            masvs_score = self._calculate_masvs_compliance(mappings)
            scores.append(masvs_score)

            # OWASP Top 10 Mobile Coverage
            owasp_score = self._calculate_owasp_compliance(mappings)
            scores.append(owasp_score)

            # NIST Framework Coverage
            nist_score = self._calculate_nist_compliance(mappings)
            scores.append(nist_score)

            # ISO 27001/27002 Coverage
            iso_score = self._calculate_iso_compliance(mappings)
            scores.append(iso_score)

            return scores

        except Exception as e:
            self.logger.error(f"Compliance scoring failed: {e}")
            return []

    def generate_compliance_report(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate full compliance report."""
        try:
            # Calculate compliance scores
            scores = self.calculate_compliance_scores(vulnerabilities)

            # Generate framework mappings
            framework_mappings = {}
            for vuln in vulnerabilities:
                vuln_id = vuln.get("id", f"vuln_{len(framework_mappings)}")
                framework_mappings[vuln_id] = self.map_vulnerability(vuln)

            # Calculate overall compliance
            overall_score = sum(score.coverage_percentage for score in scores) / len(scores) if scores else 0

            # Determine overall status
            if overall_score >= 90:
                overall_status = "Excellent"
            elif overall_score >= 75:
                overall_status = "Good"
            elif overall_score >= 60:
                overall_status = "Fair"
            else:
                overall_status = "Poor"

            return {
                "compliance_summary": {
                    "overall_score": round(overall_score, 1),
                    "overall_status": overall_status,
                    "total_vulnerabilities": len(vulnerabilities),
                    "frameworks_analyzed": len(scores),
                },
                "framework_scores": {
                    score.framework_name: {
                        "coverage_percentage": score.coverage_percentage,
                        "status": score.compliance_status,
                        "covered_requirements": score.covered_requirements,
                        "total_requirements": score.total_requirements,
                        "gap_areas": score.gap_areas,
                    }
                    for score in scores
                },
                "vulnerability_mappings": {
                    vuln_id: {
                        "cwe": {"id": mapping.cwe_id, "name": mapping.cwe_name},
                        "mitre_attack": {"tactics": mapping.mitre_tactics, "techniques": mapping.mitre_techniques},
                        "masvs": mapping.masvs_categories,
                        "owasp_mobile": mapping.owasp_mobile_categories,
                        "nist": mapping.nist_controls,
                        "iso": mapping.iso_controls,
                    }
                    for vuln_id, mapping in framework_mappings.items()
                },
            }

        except Exception as e:
            self.logger.error(f"Compliance report generation failed: {e}")
            return {"error": str(e)}

    def _init_cwe_mappings(self) -> Dict[str, Dict[str, str]]:
        """Initialize CWE mappings database."""
        return {
            "injection": {"id": "CWE-89", "name": "SQL Injection"},
            "sql": {"id": "CWE-89", "name": "SQL Injection"},
            "xss": {"id": "CWE-79", "name": "Cross-site Scripting"},
            "crypto": {"id": "CWE-327", "name": "Use of Broken Cryptographic Algorithm"},
            "authentication": {"id": "CWE-287", "name": "Improper Authentication"},
            "authorization": {"id": "CWE-285", "name": "Improper Authorization"},
            "session": {"id": "CWE-384", "name": "Session Fixation"},
            "validation": {"id": "CWE-20", "name": "Improper Input Validation"},
            "buffer": {"id": "CWE-120", "name": "Buffer Copy without Checking Size"},
            "memory": {"id": "CWE-119", "name": "Improper Restriction of Operations within Memory Buffer"},
            "path": {"id": "CWE-22", "name": "Path Traversal"},
            "file": {"id": "CWE-434", "name": "Unrestricted Upload of File"},
            "network": {"id": "CWE-319", "name": "Cleartext Transmission of Sensitive Information"},
            "ssl": {"id": "CWE-295", "name": "Improper Certificate Validation"},
            "storage": {"id": "CWE-312", "name": "Cleartext Storage of Sensitive Information"},
            "permission": {"id": "CWE-276", "name": "Incorrect Default Permissions"},
            "information": {"id": "CWE-200", "name": "Information Exposure"},
            "disclosure": {"id": "CWE-200", "name": "Information Exposure"},
            "secrets": {"id": "CWE-798", "name": "Use of Hard-coded Credentials"},
            "hardcoded": {"id": "CWE-798", "name": "Use of Hard-coded Credentials"},
            "deserialization": {"id": "CWE-502", "name": "Deserialization of Untrusted Data"},
            "components": {"id": "CWE-1104", "name": "Use of Unmaintained Third Party Components"},
            "logging": {"id": "CWE-778", "name": "Insufficient Logging"},
            "misc": {"id": "CWE-693", "name": "Protection Mechanism Failure"},
        }

    def _init_mitre_mappings(self) -> Dict[str, Dict[str, List[str]]]:
        """Initialize MITRE ATT&CK Mobile mappings."""
        return {
            "injection": {"tactics": ["TA0027"], "techniques": ["T1575"]},  # Execution  # Native Code
            "crypto": {"tactics": ["TA0030"], "techniques": ["T1533"]},  # Collection  # Data from Local System
            "network": {
                "tactics": ["TA0030", "TA0031"],  # Collection, Command and Control
                "techniques": ["T1437", "T1571"],  # Standard Application Layer Protocol
            },
            "storage": {
                "tactics": ["TA0030"],  # Collection
                "techniques": ["T1533", "T1532"],  # Data from Local System
            },
            "authentication": {"tactics": ["TA0028"], "techniques": ["T1411"]},  # Credential Access  # Input Capture
            "permission": {
                "tactics": ["TA0029"],  # Privilege Escalation
                "techniques": ["T1404"],  # Exploitation for Privilege Escalation
            },
            "information": {"tactics": ["TA0030"], "techniques": ["T1533"]},  # Collection  # Data from Local System
        }

    def _init_masvs_mappings(self) -> Dict[str, List[str]]:
        """Initialize MASVS v2.0 mappings."""
        return {
            "storage": ["MASVS-STORAGE-1", "MASVS-STORAGE-2"],
            "crypto": ["MASVS-CRYPTO-1", "MASVS-CRYPTO-2"],
            "authentication": ["MASVS-AUTH-1", "MASVS-AUTH-2", "MASVS-AUTH-3"],
            "network": ["MASVS-NETWORK-1", "MASVS-NETWORK-2"],
            "platform": ["MASVS-PLATFORM-1", "MASVS-PLATFORM-2", "MASVS-PLATFORM-3"],
            "code": ["MASVS-CODE-1", "MASVS-CODE-2", "MASVS-CODE-3", "MASVS-CODE-4"],
            "resilience": ["MASVS-RESILIENCE-1", "MASVS-RESILIENCE-2", "MASVS-RESILIENCE-3", "MASVS-RESILIENCE-4"],
            "privacy": ["MASVS-PRIVACY-1", "MASVS-PRIVACY-2", "MASVS-PRIVACY-3", "MASVS-PRIVACY-4"],
        }

    def _init_owasp_mappings(self) -> Dict[str, List[str]]:
        """Initialize OWASP Top 10 Mobile 2024 mappings."""
        return {
            "validation": ["M01-Improper-Platform-Usage"],
            "storage": ["M02-Insecure-Data-Storage"],
            "communication": ["M03-Insecure-Communication"],
            "authentication": ["M04-Insecure-Authentication"],
            "crypto": ["M05-Insufficient-Cryptography"],
            "authorization": ["M06-Insecure-Authorization"],
            "code": ["M07-Client-Code-Quality"],
            "tampering": ["M08-Code-Tampering"],
            "engineering": ["M09-Reverse-Engineering"],
            "functionality": ["M10-Extraneous-Functionality"],
        }

    def _init_nist_mappings(self) -> Dict[str, List[str]]:
        """Initialize NIST Cybersecurity Framework mappings."""
        return {
            "authentication": ["ID.AM-1", "PR.AC-1", "PR.AC-7"],
            "crypto": ["PR.DS-1", "PR.DS-2", "PR.DS-5"],
            "network": ["PR.AC-5", "PR.DS-2", "DE.CM-1"],
            "storage": ["PR.DS-1", "PR.DS-3", "PR.DS-8"],
            "logging": ["DE.AE-3", "DE.CM-1", "DE.CM-7"],
            "validation": ["PR.DS-2", "DE.CM-1"],
            "components": ["ID.SC-2", "PR.DS-6"],
            "access": ["PR.AC-1", "PR.AC-3", "PR.AC-4"],
        }

    def _init_iso_mappings(self) -> Dict[str, List[str]]:
        """Initialize ISO 27001/27002 mappings."""
        return {
            "authentication": ["A.9.2.1", "A.9.2.2", "A.9.2.6"],
            "crypto": ["A.10.1.1", "A.10.1.2"],
            "network": ["A.13.1.1", "A.13.2.1"],
            "storage": ["A.8.2.3", "A.11.2.9"],
            "access": ["A.9.1.1", "A.9.1.2", "A.9.4.1"],
            "logging": ["A.12.4.1", "A.12.4.2", "A.12.4.3"],
            "components": ["A.12.6.1", "A.14.2.1"],
            "incident": ["A.16.1.1", "A.16.1.2"],
        }

    def _map_to_cwe(self, category: str, title: str, description: str) -> tuple:
        """Map vulnerability to CWE."""
        cat_lower = category.lower()
        title_lower = title.lower()
        desc_lower = description.lower()
        for key, cwe_info in self.cwe_mappings.items():
            if key in cat_lower or key in title_lower or key in desc_lower:
                return cwe_info["id"], cwe_info["name"]

        # Default CWE for unknown categories
        return "CWE-693", "Protection Mechanism Failure"

    def _map_to_mitre(self, category: str, title: str) -> tuple:
        """Map vulnerability to MITRE ATT&CK Mobile."""
        cat_lower = category.lower()
        title_lower = title.lower()
        for key, mitre_info in self.mitre_mappings.items():
            if key in cat_lower or key in title_lower:
                return mitre_info["tactics"], mitre_info["techniques"]

        # Default MITRE mapping
        return ["TA0027"], ["T1575"]  # Execution -> Native Code

    def _map_to_masvs(self, category: str, title: str) -> List[str]:
        """Map vulnerability to MASVS v2.0."""
        categories = []
        cat_lower = category.lower()
        title_lower = title.lower()
        for key, masvs_cats in self.masvs_mappings.items():
            if key in cat_lower or key in title_lower:
                categories.extend(masvs_cats)

        return categories if categories else ["MASVS-CODE-1"]  # Default

    def _map_to_owasp(self, category: str, title: str) -> List[str]:
        """Map vulnerability to OWASP Top 10 Mobile 2024."""
        categories = []
        cat_lower = category.lower()
        title_lower = title.lower()
        for key, owasp_cats in self.owasp_mappings.items():
            if key in cat_lower or key in title_lower:
                categories.extend(owasp_cats)

        return categories if categories else ["M07-Client-Code-Quality"]  # Default

    def _map_to_nist(self, category: str, title: str) -> List[str]:
        """Map vulnerability to NIST Cybersecurity Framework."""
        controls = []
        cat_lower = category.lower()
        title_lower = title.lower()
        for key, nist_controls in self.nist_mappings.items():
            if key in cat_lower or key in title_lower:
                controls.extend(nist_controls)

        return controls if controls else ["PR.DS-1"]  # Default

    def _map_to_iso(self, category: str, title: str) -> List[str]:
        """Map vulnerability to ISO 27001/27002."""
        controls = []
        for key, iso_controls in self.iso_mappings.items():
            if key in category or key in title:
                controls.extend(iso_controls)

        return controls if controls else ["A.12.6.1"]  # Default

    def _calculate_cwe_compliance(self, mappings: List[SecurityFrameworkMapping]) -> ComplianceScore:
        """Calculate CWE compliance score."""
        unique_cwes = set()
        for mapping in mappings:
            if mapping.cwe_id:
                unique_cwes.add(mapping.cwe_id)

        # Estimate total CWE categories relevant to mobile (simplified)
        total_relevant_cwes = 25
        coverage = min(len(unique_cwes) / total_relevant_cwes * 100, 100)

        return ComplianceScore(
            framework_name="CWE",
            total_requirements=total_relevant_cwes,
            covered_requirements=len(unique_cwes),
            coverage_percentage=coverage,
            compliance_status=self._get_compliance_status(coverage),
            gap_areas=["Memory Safety", "Input Validation"] if coverage < 80 else [],
        )

    def _calculate_mitre_compliance(self, mappings: List[SecurityFrameworkMapping]) -> ComplianceScore:
        """Calculate MITRE ATT&CK compliance score."""
        unique_tactics = set()
        unique_techniques = set()

        for mapping in mappings:
            unique_tactics.update(mapping.mitre_tactics)
            unique_techniques.update(mapping.mitre_techniques)

        # Mobile ATT&CK has ~14 tactics and ~100+ techniques (simplified)
        total_tactics = 14
        coverage = min(len(unique_tactics) / total_tactics * 100, 100)

        return ComplianceScore(
            framework_name="MITRE_ATT&CK_Mobile",
            total_requirements=total_tactics,
            covered_requirements=len(unique_tactics),
            coverage_percentage=coverage,
            compliance_status=self._get_compliance_status(coverage),
            gap_areas=["Defense Evasion", "Persistence"] if coverage < 70 else [],
        )

    def _calculate_masvs_compliance(self, mappings: List[SecurityFrameworkMapping]) -> ComplianceScore:
        """Calculate MASVS v2.0 compliance score."""
        unique_categories = set()
        for mapping in mappings:
            unique_categories.update(mapping.masvs_categories)

        # MASVS v2.0 has 8 main categories with ~40 requirements
        total_requirements = 40
        coverage = min(len(unique_categories) / total_requirements * 100, 100)

        return ComplianceScore(
            framework_name="MASVS_v2.0",
            total_requirements=total_requirements,
            covered_requirements=len(unique_categories),
            coverage_percentage=coverage,
            compliance_status=self._get_compliance_status(coverage),
            gap_areas=["Resilience", "Privacy"] if coverage < 75 else [],
        )

    def _calculate_owasp_compliance(self, mappings: List[SecurityFrameworkMapping]) -> ComplianceScore:
        """Calculate OWASP Top 10 Mobile compliance score."""
        unique_categories = set()
        for mapping in mappings:
            unique_categories.update(mapping.owasp_mobile_categories)

        # OWASP Top 10 Mobile has 10 categories
        total_categories = 10
        coverage = min(len(unique_categories) / total_categories * 100, 100)

        return ComplianceScore(
            framework_name="OWASP_Top10_Mobile_2024",
            total_requirements=total_categories,
            covered_requirements=len(unique_categories),
            coverage_percentage=coverage,
            compliance_status=self._get_compliance_status(coverage),
            gap_areas=["Code Tampering", "Reverse Engineering"] if coverage < 80 else [],
        )

    def _calculate_nist_compliance(self, mappings: List[SecurityFrameworkMapping]) -> ComplianceScore:
        """Calculate NIST Cybersecurity Framework compliance score."""
        unique_controls = set()
        for mapping in mappings:
            unique_controls.update(mapping.nist_controls)

        # NIST CSF has ~100+ controls (simplified for mobile context)
        total_controls = 50  # Mobile-relevant subset
        coverage = min(len(unique_controls) / total_controls * 100, 100)

        return ComplianceScore(
            framework_name="NIST_Cybersecurity_Framework",
            total_requirements=total_controls,
            covered_requirements=len(unique_controls),
            coverage_percentage=coverage,
            compliance_status=self._get_compliance_status(coverage),
            gap_areas=["Detection", "Response"] if coverage < 70 else [],
        )

    def _calculate_iso_compliance(self, mappings: List[SecurityFrameworkMapping]) -> ComplianceScore:
        """Calculate ISO 27001/27002 compliance score."""
        unique_controls = set()
        for mapping in mappings:
            unique_controls.update(mapping.iso_controls)

        # ISO 27002 has 114 controls (mobile-relevant subset)
        total_controls = 60  # Mobile-relevant subset
        coverage = min(len(unique_controls) / total_controls * 100, 100)

        return ComplianceScore(
            framework_name="ISO_27001_27002",
            total_requirements=total_controls,
            covered_requirements=len(unique_controls),
            coverage_percentage=coverage,
            compliance_status=self._get_compliance_status(coverage),
            gap_areas=["Business Continuity", "Supplier Relationships"] if coverage < 75 else [],
        )

    def _get_compliance_status(self, coverage_percentage: float) -> str:
        """Get compliance status based on coverage percentage."""
        if coverage_percentage >= 90:
            return "Excellent"
        elif coverage_percentage >= 75:
            return "Good"
        elif coverage_percentage >= 60:
            return "Fair"
        else:
            return "Poor"


# Simple integration test
if __name__ == "__main__":
    _module_logger.info("Testing Security Framework Mapper")

    # Test mapper
    mapper = SecurityFrameworkMapper()

    # Test vulnerabilities
    test_vulnerabilities = [
        {"title": "SQL Injection in Login", "category": "injection", "severity": "critical"},
        {"title": "Weak SSL Configuration", "category": "network", "severity": "high"},
        {"title": "Hardcoded API Key", "category": "secrets", "severity": "critical"},
        {"title": "Insecure Data Storage", "category": "storage", "severity": "medium"},
        {"title": "Missing Authentication", "category": "authentication", "severity": "high"},
    ]

    # Test individual mapping
    mapping = mapper.map_vulnerability(test_vulnerabilities[0])
    _module_logger.info(
        "SQL Injection mapping",
        cwe_id=mapping.cwe_id,
        cwe_name=mapping.cwe_name,
        mitre_tactics=mapping.mitre_tactics,
        masvs_categories=mapping.masvs_categories,
    )

    # Test compliance report
    report = mapper.generate_compliance_report(test_vulnerabilities)
    _module_logger.info(
        "Compliance report generated",
        overall_score=report["compliance_summary"]["overall_score"],
        overall_status=report["compliance_summary"]["overall_status"],
        frameworks_analyzed=report["compliance_summary"]["frameworks_analyzed"],
    )

    # Show framework scores
    for framework, score in report["framework_scores"].items():
        _module_logger.info(
            "Framework score",
            framework=framework,
            coverage_pct=round(score["coverage_percentage"], 1),
            status=score["status"],
        )

    _module_logger.info("Security Framework Mapper test completed")
