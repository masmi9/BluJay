"""Restricted pickle unpickler for ML model deserialization and cache safety.

Prevents arbitrary code execution via tampered pickle files by whitelisting
only known-safe modules (sklearn, numpy, scipy, and Python builtins).

Also provides ``safe_cache_loads`` for internal cache deserialization that
blocks known-dangerous modules while allowing general Python types.

Usage:
    from core.ml.safe_pickle import safe_load

    with open("model.pkl", "rb") as f:
        data = safe_load(f)
"""

from __future__ import annotations

import io
import pickle
from typing import IO, Any, FrozenSet

# Top-level module prefixes allowed during unpickling.
# Covers sklearn, numpy, scipy, and Python stdlib types that appear in
# serialized ML model dicts/arrays.
_ALLOWED_TOP_MODULES: FrozenSet[str] = frozenset({
    # Scientific computing
    "sklearn",
    "numpy",
    "scipy",
    "joblib",
    # Sklearn internal Cython modules (top-level in pickle, e.g., _loss.CyHalfBinomialLoss)
    "_loss",
    # Python builtins & stdlib used by pickle protocol
    "builtins",
    "collections",
    "copyreg",
    "_codecs",
    "_collections_abc",
    "copy",
    "functools",
    "operator",
    "abc",
    "re",
    # Needed for defaultdict, OrderedDict, namedtuple inside model dicts
    "collections.abc",
})


class _RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that rejects classes from disallowed modules."""

    def find_class(self, module: str, name: str) -> Any:
        top = module.split(".")[0]
        if top in _ALLOWED_TOP_MODULES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(
            f"Restricted unpickler blocked: {module}.{name}"
        )


def safe_load(f: IO[bytes]) -> Any:
    """Deserialize pickle data with module restrictions.

    Only allows sklearn, numpy, scipy, and Python stdlib types.
    Raises pickle.UnpicklingError if a forbidden class is encountered.
    """
    return _RestrictedUnpickler(f).load()


def safe_loads(data: bytes) -> Any:
    """Deserialize pickle bytes with module restrictions."""
    return _RestrictedUnpickler(io.BytesIO(data)).load()


def safe_joblib_load(path: Any) -> Any:
    """Safe replacement for joblib.load() with module restrictions.

    joblib.load() internally uses pickle and can execute arbitrary code
    via tampered model files. This function reads the file and
    deserializes via our restricted unpickler instead.

    For compressed joblib files (.gz, .bz2, .lzma, .xz), delegates to
    joblib.load() after monkey-patching pickle.Unpickler. For plain
    .pkl files, uses our RestrictedUnpickler directly.
    """
    from pathlib import Path

    p = Path(path)
    suffix = "".join(p.suffixes).lower()

    # Compressed formats require joblib's decompression layer
    if any(ext in suffix for ext in (".gz", ".bz2", ".lzma", ".xz", ".z")):
        import joblib
        import pickle as _pickle_mod

        original_unpickler = _pickle_mod.Unpickler
        try:
            _pickle_mod.Unpickler = _RestrictedUnpickler  # type: ignore[misc]
            return joblib.load(p)
        finally:
            _pickle_mod.Unpickler = original_unpickler  # type: ignore[misc]

    # Plain pickle - use restricted unpickler directly
    with open(p, "rb") as f:
        return _RestrictedUnpickler(f).load()


# ── Cache-safe deserialization (blocklist approach) ──────────────────── #

_BLOCKED_MODULES: FrozenSet[str] = frozenset({
    "os", "posix", "nt",
    "subprocess", "commands", "shutil",
    "sys", "importlib",
    "code", "codeop", "compileall",
    "ctypes", "multiprocessing",
    "signal", "socket", "http",
    "pty", "webbrowser",
    "runpy", "pkgutil",
})


class _CacheRestrictedUnpickler(pickle.Unpickler):
    """Unpickler that blocks known-dangerous modules.

    Unlike ``_RestrictedUnpickler`` (allowlist for ML models), this uses a
    blocklist - appropriate for internal cache data where the cached types
    are diverse but we still want to prevent code-execution payloads if the
    cache storage (e.g. SQLite) is tampered with.
    """

    def find_class(self, module: str, name: str) -> Any:
        top = module.split(".")[0]
        if top in _BLOCKED_MODULES:
            raise pickle.UnpicklingError(
                f"Cache unpickler blocked dangerous module: {module}.{name}"
            )
        return super().find_class(module, name)


def safe_cache_loads(data: bytes) -> Any:
    """Deserialize pickle bytes with dangerous-module blocking.

    Intended for internal cache data (serialized by the same process).
    Blocks modules that could execute arbitrary code (os, subprocess, etc.)
    while allowing general Python types the cache may contain.
    """
    return _CacheRestrictedUnpickler(io.BytesIO(data)).load()
