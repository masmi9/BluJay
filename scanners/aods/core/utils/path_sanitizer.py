"""
Utilities for sanitizing source file paths in reports to prevent leakage of
absolute host paths and to provide stable, logical path representations.
"""

from __future__ import annotations

import os
from typing import Optional

KNOWN_ROOT_MARKERS = (
    os.sep + "jadx_decompiled" + os.sep,
    os.sep + "decompiled" + os.sep,
    os.sep + "sources" + os.sep,
    os.sep + "src" + os.sep,
    os.sep + "smali" + os.sep,
    os.sep + "java" + os.sep,
)


def _strip_to_marker(path: str) -> Optional[str]:
    # Find the most specific (deepest) marker - gives the shortest tail.
    best: Optional[str] = None
    for marker in KNOWN_ROOT_MARKERS:
        idx = path.find(marker)
        if idx != -1:
            tail = path[idx + len(marker) :].lstrip(os.sep)
            if best is None or len(tail) < len(best):
                best = tail
    return best


def sanitize_source_path(raw_path: Optional[str]) -> Optional[str]:
    """
    Convert a potentially absolute filesystem path to a logical, non-leaking path.
    - Prefer segment after known source markers (e.g., decompiled/, src/, smali/)
    - Else, attempt relpath to CWD; if still absolute-like, fallback to basename
    - Normalize separators and prefix with app:// to explicitly denote logical origin
    """
    if not raw_path or not isinstance(raw_path, str):
        return raw_path

    path = raw_path.replace("\\", "/")

    # If already logical (e.g., app://...), return normalized form
    if path.startswith("app://") or path.startswith("pkg://"):
        return path

    # If absolute, strip to known marker or convert to relative
    if path.startswith("/") or ":/" in path[:4]:
        marker_tail = _strip_to_marker(path)
        if marker_tail:
            path = marker_tail
        elif path.startswith("/tmp/"):
            # Fallback for /tmp/ paths without known markers: use basename
            path = os.path.basename(raw_path)
        else:
            try:
                rel = os.path.relpath(raw_path, os.getcwd()).replace("\\", "/")
                # Avoid leading ../ sequences leaking structure
                while rel.startswith("../"):
                    rel = rel[3:]
                path = rel
            except Exception:
                path = os.path.basename(raw_path)

    # Ensure no leading slash remains
    path = path.lstrip("/")

    return f"app://{path}" if not path.startswith("app://") else path
