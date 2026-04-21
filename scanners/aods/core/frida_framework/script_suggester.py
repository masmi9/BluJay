from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Any, Optional


@dataclass
class APKAnalysisSignals:
    """Standardized APK analysis signals used by suggesters.

    This structure is intentionally minimal to allow safe scaffolding.
    Populate fields progressively as signal sources become available.
    """

    package_name: Optional[str] = None
    classes: List[str] = None
    methods: List[str] = None
    libraries: Dict[str, str] = None
    manifest_features: Dict[str, Any] = None
    permissions: List[str] = None
    native_libraries: List[str] = None
    obfuscation_indicators: Dict[str, Any] = None

    @classmethod
    def minimal(cls, package_name: Optional[str]) -> "APKAnalysisSignals":
        return cls(
            package_name=package_name,
            classes=[],
            methods=[],
            libraries={},
            manifest_features={},
            permissions=[],
            native_libraries=[],
            obfuscation_indicators={},
        )


@dataclass
class ScriptSuggestion:
    template_id: str
    params: Dict[str, Any]
    reason: str
    score: float = 0.0


class FridaScriptSuggester:
    """Interface for Frida script suggesters."""

    def suggest(self, signals: APKAnalysisSignals) -> List[ScriptSuggestion]:
        raise NotImplementedError
