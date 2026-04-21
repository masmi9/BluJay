#!/usr/bin/env python3
"""
Plugin Registry V3 (Skeleton)

Experimental registry with simple metadata caching for plugin discovery.
Opt-in via environment variable AODS_PLUGIN_REGISTRY_V3=1 by consumers.
This module is standalone and does not alter existing discovery flows unless used.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class RegistryConfig:
    plugins_dir: Path
    cache_file: Path
    ttl_seconds: int = 24 * 60 * 60  # 24h default
    exclude_substrings: List[str] = field(default_factory=lambda: ["/__pycache__/", "/tests/", "/archive/"])


class PluginRegistryV3:
    """
    Experimental plugin registry with JSON cache of discovered modules.
    """

    def __init__(self, config: Optional[RegistryConfig] = None):
        root = Path(__file__).resolve().parents[2]
        ttl = int(os.environ.get("AODS_PLUGIN_REGISTRY_TTL_S", "86400") or "86400")
        default_cache = root / "artifacts" / "plugin_registry" / "registry_cache.json"
        self.config = config or RegistryConfig(
            plugins_dir=root / "plugins",
            cache_file=default_cache,
            ttl_seconds=ttl,
        )
        self.config.cache_file.parent.mkdir(parents=True, exist_ok=True)

    def _now(self) -> float:
        return time.time()

    def _is_excluded(self, path: Path) -> bool:
        s = str(path).replace("\\", "/").lower()
        return any(substr in s for substr in self.config.exclude_substrings)

    def _compute_signature(self) -> Dict[str, Any]:
        """
        Compute a lightweight signature for cache invalidation based on max mtime
        and plugin count under the plugins directory.
        """
        base = self.config.plugins_dir
        max_mtime = 0.0
        count = 0
        if base.exists():
            for p in base.rglob("*.py"):
                if self._is_excluded(p):
                    continue
                try:
                    mt = p.stat().st_mtime
                    if mt > max_mtime:
                        max_mtime = mt
                    count += 1
                except Exception:
                    continue
        return {"max_mtime": max_mtime, "count": count}

    def discover_modules(self) -> List[str]:
        """
        Discover plugin modules under plugins/ as importable module names.
        """
        base = self.config.plugins_dir
        modules: List[str] = []
        if not base.exists():
            return modules
        for py in base.rglob("*.py"):
            if self._is_excluded(py):
                continue
            rel = py.relative_to(Path(__file__).resolve().parents[2])
            mod = ".".join(rel.with_suffix("").parts)
            modules.append(mod)
        return modules

    def discover_plugin_files(self) -> List[Path]:
        """
        Discover candidate plugin files for analysis, preferring package __init__.py
        and common entry files like v2_plugin.py.
        """
        base = self.config.plugins_dir
        files: List[Path] = []
        if not base.exists():
            return files
        for py in base.rglob("*.py"):
            if self._is_excluded(py):
                continue
            name = py.name
            # Include package initializers and common entry points; skip private helper files
            if name == "__init__.py" or name in {"v2_plugin.py", "plugin.py"} or not name.startswith("_"):
                files.append(py)
        return files

    def load_cache(self) -> Optional[Dict[str, Any]]:
        f = self.config.cache_file
        if not f.exists():
            return None
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            return None
        ts = float(data.get("timestamp", 0))
        if self._now() - ts > self.config.ttl_seconds:
            return None
        # signature mismatch invalidates cache
        sig = data.get("signature") or {}
        if sig != self._compute_signature():
            return None
        return data

    def save_cache(self, modules: List[str]) -> None:
        data = {
            "timestamp": self._now(),
            "modules": modules,
            "count": len(modules),
            "signature": self._compute_signature(),
        }
        self.config.cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_modules(self) -> List[str]:
        cached = self.load_cache()
        if cached:
            return list(cached.get("modules", []))
        modules = self.discover_modules()
        self.save_cache(modules)
        return modules
