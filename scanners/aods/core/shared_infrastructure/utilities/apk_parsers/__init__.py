"""
APK parsing and analysis utilities package.

Provides full APK analysis including validation, manifest parsing,
certificate analysis, DEX inspection, native library analysis, and security
assessment. This package replaces the former monolithic apk_parsers.py module
while maintaining full backward compatibility.
"""

from pathlib import Path
from typing import Dict, Optional, Union, Any

# Enums and shared dataclasses
from ._types import (
    APKValidationResult,
    ArchitectureType,
    APKMetadata,
    ManifestPermission,
    ManifestComponent,
    APKAnalysisResult,
)

# Specialized analyzers
from .certificate_analyzer import CertificateInfo, CertificateAnalyzer
from .dex_analyzer import DEXInfo, DEXAnalyzer
from .native_library_analyzer import NativeLibraryInfo, NativeLibraryAnalyzer
from .structure_analyzer import APKStructureInfo, APKStructureAnalyzer

# Core modules
from .validator import APKValidator
from .parser import APKParser
from .manifest_parser import ManifestParser

# Orchestrators
from .analyzer import APKAnalyzer
from .security_analysis import APKSecurityAnalysisResult, APKSecurityAnalysis

# ---------------------------------------------------------------------------
# Singleton instances and convenience functions
# (replicate the original module-level API exactly)
# ---------------------------------------------------------------------------

_manifest_parser = None


def get_manifest_parser() -> ManifestParser:
    """Get global manifest parser instance."""
    global _manifest_parser
    if _manifest_parser is None:
        _manifest_parser = ManifestParser()
    return _manifest_parser


def parse_manifest(apk_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
    """Parse Android manifest using global parser."""
    return get_manifest_parser().parse_manifest(apk_path)


_apk_parser = None


def get_apk_parser() -> APKParser:
    """Get global APK parser instance."""
    global _apk_parser
    if _apk_parser is None:
        _apk_parser = APKParser()
    return _apk_parser


def parse_apk(apk_path: Union[str, Path], **kwargs) -> APKAnalysisResult:
    """Parse APK using global parser."""
    return get_apk_parser().parse_apk(apk_path, **kwargs)


def validate_apk(apk_path: Union[str, Path]) -> APKValidationResult:
    """Validate APK structure using global parser."""
    return get_apk_parser().validate_apk_structure(Path(apk_path))


def extract_apk_metadata(apk_path: Union[str, Path]) -> Optional[APKMetadata]:
    """Extract APK metadata using global parser."""
    return get_apk_parser().extract_apk_metadata(Path(apk_path))


__all__ = [
    # Classes
    "APKValidator",
    "APKAnalyzer",
    "APKParser",
    "ManifestParser",
    "CertificateAnalyzer",
    "DEXAnalyzer",
    "NativeLibraryAnalyzer",
    "APKStructureAnalyzer",
    "APKSecurityAnalysis",
    # Convenience functions
    "parse_apk",
    "validate_apk",
    "extract_apk_metadata",
    "parse_manifest",
    "get_apk_parser",
    "get_manifest_parser",
    # Data structures and enums
    "APKValidationResult",
    "ArchitectureType",
    "APKMetadata",
    "APKAnalysisResult",
    "CertificateInfo",
    "ManifestPermission",
    "ManifestComponent",
    "NativeLibraryInfo",
    "DEXInfo",
    "APKStructureInfo",
    "APKSecurityAnalysisResult",
]
