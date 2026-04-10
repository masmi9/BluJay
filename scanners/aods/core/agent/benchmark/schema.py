"""
core.agent.benchmark.schema - Benchmark case definitions.

Defines the expected output for each agent type on a given report,
enabling automated scoring against ground truth.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class TriageBenchmarkCase(BaseModel):
    """Expected triage output for a specific report."""

    model_config = ConfigDict(extra="forbid")

    report_file: str = Field(..., description="Path to the scan report JSON")
    apk_name: str = Field("", description="Human-readable APK name")
    expected_classifications: Dict[str, str] = Field(
        default_factory=dict,
        description="finding_title → expected classification (confirmed_tp, likely_tp, needs_review, likely_fp, informational)",
    )
    expected_tp_titles: List[str] = Field(
        default_factory=list,
        description="Findings that should be classified as TP (confirmed_tp or likely_tp)",
    )
    expected_fp_titles: List[str] = Field(
        default_factory=list,
        description="Findings that should be classified as FP (likely_fp)",
    )
    expected_informational_titles: List[str] = Field(
        default_factory=list,
        description="Findings that should be classified as informational",
    )
    notes: str = Field("", description="Notes about this benchmark case")


class RemediationBenchmarkCase(BaseModel):
    """Expected remediation output for a specific report."""

    model_config = ConfigDict(extra="forbid")

    report_file: str
    apk_name: str = ""
    expected_cwe_coverage: List[str] = Field(
        default_factory=list,
        description="CWEs that should have remediation patches",
    )
    expected_min_patches: int = Field(0, description="Minimum number of patches expected")
    notes: str = ""


class NarrationBenchmarkCase(BaseModel):
    """Expected narration quality criteria."""

    model_config = ConfigDict(extra="forbid")

    report_file: str
    apk_name: str = ""
    expected_risk_rating: str = Field("", description="Expected risk rating: CRITICAL, HIGH, MEDIUM, LOW")
    expected_min_attack_chains: int = Field(0, description="Minimum attack chains expected")
    expected_min_priority_findings: int = Field(0, description="Minimum priority findings expected")
    notes: str = ""


class BenchmarkSuite(BaseModel):
    """Collection of benchmark cases for evaluation."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Suite name")
    description: str = Field("", description="Suite description")
    triage_cases: List[TriageBenchmarkCase] = Field(default_factory=list)
    remediation_cases: List[RemediationBenchmarkCase] = Field(default_factory=list)
    narration_cases: List[NarrationBenchmarkCase] = Field(default_factory=list)
