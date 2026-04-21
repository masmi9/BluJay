"""
Lazy source files dictionary for memory-efficient JADX source loading.

Instead of reading all .java file contents into memory at APKContext creation,
this dict subclass populates keys immediately (for len(), bool(), keys(), in)
but defers reading file contents until first access.
"""

import logging
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)

_NOT_LOADED = object()  # sentinel to distinguish unloaded from empty-string


class LazySourceFiles(dict):
    """Dict[str, str] that lazily loads file contents on first access.

    Keys are populated immediately (file paths as strings).
    Values are loaded on-demand: first access reads file content and caches it.
    """

    def __init__(self, java_files: Optional[List[Path]] = None):
        super().__init__()
        # Pre-populate keys with sentinel values
        for f in java_files or []:
            super().__setitem__(str(f), _NOT_LOADED)

    def _load_value(self, key: str) -> str:
        """Read file content from disk and cache it."""
        try:
            with open(key, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"Failed to read {key}: {e}")
            content = ""
        super().__setitem__(key, content)
        return content

    def __getitem__(self, key: str) -> str:
        value = super().__getitem__(key)
        if value is _NOT_LOADED:
            return self._load_value(key)
        return value

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        try:
            return self[key]
        except KeyError:
            return default

    def values(self) -> Iterator[str]:  # type: ignore[override]
        for key in self:
            yield self[key]

    def items(self) -> Iterator[Tuple[str, str]]:  # type: ignore[override]
        for key in self:
            yield key, self[key]

    def __contains__(self, key: object) -> bool:
        return super().__contains__(key)

    def __repr__(self) -> str:
        loaded = sum(1 for v in super().values() if v is not _NOT_LOADED)
        return f"<LazySourceFiles keys={len(self)} loaded={loaded}>"
