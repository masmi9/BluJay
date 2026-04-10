"""Shared utility for JADX cross-plugin coordination cache paths.

Two APKs with the same package_name (e.g. debug vs release builds) previously
shared the same cache key ``/tmp/jadx_results_{package_name}.json``, which
caused cross-scan corruption.  This module appends a short APK hash to the
path so that each distinct APK file gets its own cache entry.
"""

import hashlib
import os
import tempfile


def get_jadx_results_cache_path(package_name: str, apk_path: str = None) -> str:
    """Return the cross-plugin coordination cache path for JADX results.

    When *apk_path* is provided and the file exists, the path includes a
    16-char SHA-256 hash of the APK file content so that different APKs
    with the same package name do not collide.

    Falls back to the legacy unhashed path when the APK is unavailable
    (backward compatibility).
    """
    tmp = tempfile.gettempdir()
    if apk_path and os.path.exists(str(apk_path)):
        with open(str(apk_path), "rb") as f:
            apk_hash = hashlib.sha256(f.read()).hexdigest()[:16]
        return os.path.join(tmp, f"jadx_results_{package_name}_{apk_hash}.json")
    return os.path.join(tmp, f"jadx_results_{package_name}.json")
