"""EnhancedVulnerabilityReport dataclass."""

from dataclasses import dataclass
from typing import List


@dataclass
class EnhancedVulnerabilityReport:
    """Enhanced vulnerability report with detailed technical information"""

    id: str  # **ID FIX**: Renamed from vulnerability_id to match JSON output expectations
    title: str
    description: str
    severity: str
    confidence: float

    # Technical location details
    file_path: str
    line_number: int
    method_name: str
    class_name: str

    # Code evidence
    vulnerable_code: str
    surrounding_context: str
    pattern_matches: List[str]

    # Remediation details
    specific_remediation: str
    code_fix_example: str
    api_references: List[str]

    # Classification details
    original_severity: str
    adjusted_severity: str
    severity_reasoning: str
    vulnerable_pattern: str

    # Standards compliance
    masvs_control: str
    owasp_category: str
    cwe_id: str

    def get(self, key: str, default=None):
        """Dictionary-like get method for compatibility with deduplication framework."""
        return getattr(self, key, default)
