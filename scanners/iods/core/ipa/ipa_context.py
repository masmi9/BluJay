"""
IPAContext – central analysis session object for an iOS IPA file.

Mirrors AODS APKContext: lazy source loading, workspace isolation,
decompiled output paths, plist cache, analysis ID.
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


class LazySourceFiles:
    """Lazily loads source files from the decompiled output directory."""

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self._base_dir = base_dir
        self._cache: Dict[str, str] = {}
        self._file_list: Optional[List[Path]] = None

    def set_base_dir(self, base_dir: Path) -> None:
        self._base_dir = base_dir
        self._cache.clear()
        self._file_list = None

    def get_files(self, extensions: Optional[List[str]] = None) -> List[Path]:
        """Return list of source files, optionally filtered by extension."""
        if self._base_dir is None or not self._base_dir.exists():
            return []
        if self._file_list is None:
            self._file_list = list(self._base_dir.rglob("*"))
        if extensions:
            return [f for f in self._file_list if f.suffix in extensions and f.is_file()]
        return [f for f in self._file_list if f.is_file()]

    def read_file(self, path: Path) -> Optional[str]:
        """Read and cache a file's content."""
        key = str(path)
        if key not in self._cache:
            try:
                self._cache[key] = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                return None
        return self._cache[key]

    def search_pattern(self, pattern: str, extensions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Search for a regex pattern across source files. Returns matches with file/line info."""
        import re
        matches = []
        for filepath in self.get_files(extensions):
            content = self.read_file(filepath)
            if content is None:
                continue
            for i, line in enumerate(content.splitlines(), 1):
                if re.search(pattern, line):
                    matches.append({
                        "file": str(filepath),
                        "line_number": i,
                        "line": line.strip(),
                    })
        return matches


class IPAContext:
    """
    Central context object for an IPA analysis session.

    Provides access to:
    - IPA metadata (bundle ID, display name, version)
    - Decompiled output paths (strings, otool, class-dump, plist)
    - Lazy source file access
    - Results cache shared across plugins
    """

    def __init__(self, ipa_path: str, workspace_root: str = "workspace") -> None:
        self.ipa_path = Path(ipa_path).resolve()
        self.analysis_id = str(uuid.uuid4())[:8]
        self.app_name = self.ipa_path.stem

        # Workspace isolation
        self.workspace_dir = Path(workspace_root) / f"{self.app_name}_{self.analysis_id}"
        self.decompiled_dir = self.workspace_dir / "decompiled"
        self.reports_dir = self.workspace_dir / "reports"

        # Tool output directories
        self.otool_dir = self.decompiled_dir / "otool"
        self.strings_dir = self.decompiled_dir / "strings"
        self.classdump_dir = self.decompiled_dir / "classdump"
        self.plist_dir = self.decompiled_dir / "plist"
        self.entitlements_dir = self.decompiled_dir / "entitlements"
        self.binary_dir = self.decompiled_dir / "binary"

        # IPA extraction directory
        self.extracted_dir = self.decompiled_dir / "extracted"
        self.app_bundle_dir: Optional[Path] = None  # Set after extraction

        # Metadata (populated by extractor)
        self.bundle_id: str = ""
        self.display_name: str = ""
        self.bundle_version: str = ""
        self.short_version: str = ""
        self.minimum_os_version: str = ""
        self.platform: str = "iOS"
        self.binary_path: Optional[Path] = None
        self.info_plist: Dict[str, Any] = {}
        self.entitlements: Dict[str, Any] = {}

        # Binary security flags (populated by binary_security_analyzer)
        self.has_pie: Optional[bool] = None
        self.has_arc: Optional[bool] = None
        self.has_stack_canary: Optional[bool] = None
        self.symbols_stripped: Optional[bool] = None
        self.bitcode_enabled: Optional[bool] = None

        # Lazy source file access
        self.source_files = LazySourceFiles()

        # Shared results cache
        self._results_cache: Dict[str, Any] = {}

        # Scan metadata
        self.scan_mode: str = "safe"
        self.scan_profile: str = "standard"
        self.is_vulnerable_app_mode: bool = False
        self.ml_enabled: bool = True

        # Extracted strings cache
        self._strings_cache: Optional[List[str]] = None

    def setup_workspace(self) -> None:
        """Create workspace directories."""
        for d in [
            self.workspace_dir, self.decompiled_dir, self.reports_dir,
            self.otool_dir, self.strings_dir, self.classdump_dir,
            self.plist_dir, self.entitlements_dir, self.binary_dir,
            self.extracted_dir,
        ]:
            d.mkdir(parents=True, exist_ok=True)

    def get_cached(self, key: str) -> Optional[Any]:
        return self._results_cache.get(key)

    def set_cached(self, key: str, value: Any) -> None:
        self._results_cache[key] = value

    def get_strings(self) -> List[str]:
        """Return cached binary strings."""
        if self._strings_cache is not None:
            return self._strings_cache
        strings_file = self.strings_dir / "binary_strings.txt"
        if strings_file.exists():
            self._strings_cache = strings_file.read_text(errors="replace").splitlines()
        else:
            self._strings_cache = []
        return self._strings_cache

    def get_info_plist_value(self, key: str, default: Any = None) -> Any:
        """Retrieve a value from Info.plist by key."""
        return self.info_plist.get(key, default)

    def get_entitlement(self, key: str, default: Any = None) -> Any:
        """Retrieve an entitlement value by key."""
        return self.entitlements.get(key, default)

    def summary(self) -> Dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "ipa_path": str(self.ipa_path),
            "app_name": self.app_name,
            "bundle_id": self.bundle_id,
            "display_name": self.display_name,
            "version": self.short_version,
            "platform": self.platform,
            "scan_mode": self.scan_mode,
            "scan_profile": self.scan_profile,
        }
