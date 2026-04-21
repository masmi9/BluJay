#!/usr/bin/env python3
"""
Pattern Registry Schema - Pydantic V2 models for the centralized pattern registry.

Defines the contract for registry entries that unify vulnerability_patterns.yaml
and semgrep MASTG rules into a single auditable catalog.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PatternRegistryEntry(BaseModel):
    """A single pattern in the governance registry."""

    model_config = ConfigDict(extra="forbid")

    id: str
    source: str = Field(
        description="Origin: 'vulnerability_patterns' or 'semgrep_mastg'"
    )
    source_file: str = Field(description="Relative path to the file defining this pattern")
    owner: str = "@aods-core"
    version: str = "1.0.0"
    status: str = Field(default="active", description="active | experimental | deprecated")
    severity: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    masvs_control: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    risk: str = "medium"
    confidence_base: Optional[float] = None
    test_links: List[str] = Field(default_factory=list)
    last_reviewed: str
    title: str = ""
    category: str = ""
    subcategory: str = ""

    @field_validator("status")
    @classmethod
    def _validate_status(cls, v: str) -> str:
        allowed = {"active", "experimental", "deprecated"}
        if v not in allowed:
            raise ValueError(f"status must be one of {allowed}, got '{v}'")
        return v

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        if v.upper() not in allowed:
            raise ValueError(f"severity must be one of {allowed}, got '{v}'")
        return v.upper()


class PatternRegistry(BaseModel):
    """Top-level registry wrapping all pattern entries."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    generated_at: str = ""
    pattern_config_version: str = ""
    sources: Dict[str, int] = Field(default_factory=dict)
    patterns: List[PatternRegistryEntry] = Field(default_factory=list)
