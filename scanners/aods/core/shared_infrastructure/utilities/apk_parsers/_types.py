"""Shared enums, dataclasses, and type definitions for APK parsing."""

from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class APKValidationResult(Enum):
    """APK validation results."""

    VALID = "valid"
    INVALID_STRUCTURE = "invalid_structure"
    MISSING_MANIFEST = "missing_manifest"
    CORRUPTED = "corrupted"
    UNSIGNED = "unsigned"
    INVALID_SIGNATURE = "invalid_signature"


class ArchitectureType(Enum):
    """Android architecture types."""

    ARM = "arm"
    ARM64 = "arm64"
    X86 = "x86"
    X86_64 = "x86_64"
    MIPS = "mips"
    MIPS64 = "mips64"
    UNKNOWN = "unknown"


@dataclass
class APKMetadata:
    """Container for APK metadata."""

    package_name: str
    version_name: str
    version_code: int
    min_sdk_version: int
    target_sdk_version: int
    compile_sdk_version: Optional[int] = None
    app_name: Optional[str] = None
    main_activity: Optional[str] = None
    file_size: int = 0
    file_hash_md5: str = ""
    file_hash_sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk_version": self.min_sdk_version,
            "target_sdk_version": self.target_sdk_version,
            "compile_sdk_version": self.compile_sdk_version,
            "app_name": self.app_name,
            "main_activity": self.main_activity,
            "file_size": self.file_size,
            "file_hash_md5": self.file_hash_md5,
            "file_hash_sha256": self.file_hash_sha256,
        }


@dataclass
class ManifestPermission:
    """Android manifest permission."""

    name: str
    protection_level: str = "unknown"
    is_dangerous: bool = False
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "protection_level": self.protection_level,
            "is_dangerous": self.is_dangerous,
            "description": self.description,
        }


@dataclass
class ManifestComponent:
    """Android manifest component (activity, service, receiver, provider)."""

    component_type: str  # activity, service, receiver, provider
    name: str
    exported: bool = False
    enabled: bool = True
    intent_filters: List[Dict[str, Any]] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "component_type": self.component_type,
            "name": self.name,
            "exported": self.exported,
            "enabled": self.enabled,
            "intent_filters": self.intent_filters,
            "permissions": self.permissions,
            "metadata": self.metadata,
        }


@dataclass
class APKAnalysisResult:
    """Complete APK analysis result."""

    apk_path: Path
    validation_result: APKValidationResult
    metadata: Optional[APKMetadata] = None
    permissions: List[ManifestPermission] = field(default_factory=list)
    components: List[ManifestComponent] = field(default_factory=list)
    certificates: List[Any] = field(default_factory=list)
    native_libraries: List[Any] = field(default_factory=list)
    dex_files: List[str] = field(default_factory=list)
    assets: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)
    analysis_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "apk_path": str(self.apk_path),
            "validation_result": self.validation_result.value,
            "metadata": self.metadata.to_dict() if self.metadata else None,
            "permissions": [p.to_dict() for p in self.permissions],
            "components": [c.to_dict() for c in self.components],
            "certificates": [cert.to_dict() for cert in self.certificates],
            "native_libraries": [lib.to_dict() for lib in self.native_libraries],
            "dex_files": self.dex_files,
            "assets": self.assets,
            "resources": self.resources,
            "security_issues": self.security_issues,
            "analysis_time": self.analysis_time,
        }
