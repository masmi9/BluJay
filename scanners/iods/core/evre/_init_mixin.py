"""EVRE Init Mixin – source discovery and pattern loading."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List


class EVREInitMixin:
    def _init_engine(self) -> None:
        """Initialize source file lists and pattern data."""
        self._source_files: List[Path] = []
        self._pattern_data: Dict[str, Any] = {}
        self._used_finding_ids: set = set()
        self._load_patterns()
        self._discover_sources()

    def _load_patterns(self) -> None:
        import yaml
        patterns_path = Path(__file__).parent.parent.parent / "config" / "ios_vulnerability_patterns.yaml"
        if patterns_path.exists():
            try:
                with open(patterns_path) as f:
                    self._pattern_data = yaml.safe_load(f) or {}
            except Exception:
                self._pattern_data = {}

    def _discover_sources(self) -> None:
        ipa_ctx = getattr(self, "ipa_ctx", None)
        if ipa_ctx and ipa_ctx.app_bundle_dir and ipa_ctx.app_bundle_dir.exists():
            self._source_files = [
                f for f in ipa_ctx.app_bundle_dir.rglob("*") if f.is_file()
            ]
