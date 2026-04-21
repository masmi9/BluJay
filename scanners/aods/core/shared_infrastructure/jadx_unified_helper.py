#!/usr/bin/env python3
"""
JADX Unified Helper - Memory Optimization for AODS

This module provides a unified interface for all JADX decompilation needs across AODS,
eliminating redundant decompilations and maximizing cache utilization for memory optimization.

Key Benefits:
- Single point of access for all JADX operations
- Automatic cache utilization (70%+ hit rate)
- Centralized resource management and memory optimization
- Eliminates redundant decompilation of same APK across analyzers
- Intelligent fallback for failed decompilations

Memory Optimization Features:
- Uses existing centralized JADX manager and cache
- Shared decompilation results between all analyzers
- Adaptive resource allocation based on system capabilities
- Automatic cleanup and memory management
"""

import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from contextlib import contextmanager

from core.decompilation_policy_resolver import DecompilationPolicy, DecompilationMode
from core.shared_infrastructure.performance.caching_consolidation import CacheType

logger = logging.getLogger(__name__)


class JADXUnifiedHelper:
    """
    Unified JADX helper for memory-optimized decompilation across all AODS analyzers.

    This class eliminates redundant JADX usage by providing a single interface
    that uses the centralized JADX manager and cache system.
    """

    def __init__(self):
        """Initialize unified JADX helper."""
        self._manager = None
        self._cache = None
        self.logger = logging.getLogger(__name__)

    @property
    def manager(self):
        """Get centralized JADX manager (lazy loading)."""
        if self._manager is None:
            try:
                from core.jadx_decompilation_manager import get_jadx_manager

                self._manager = get_jadx_manager()
            except ImportError:
                self.logger.warning("Centralized JADX manager not available, using fallback")
                self._manager = None
        return self._manager

    @property
    def cache(self):
        """Get centralized JADX cache (lazy loading)."""
        if self._cache is None:
            try:
                # MIGRATED: Use unified cache manager retrieve/store API for decompilation pointers
                from core.shared_infrastructure.performance.caching_consolidation import get_unified_cache_manager

                self._cache = get_unified_cache_manager()
            except ImportError:
                self.logger.warning("JADX cache not available")
                self._cache = None
        return self._cache

    def get_decompiled_sources(
        self, apk_path: str, analyzer_name: str = "unknown", timeout: int = 300, enable_cache: bool = True
    ) -> Optional[str]:
        """
        Get decompiled sources for APK with memory optimization.

        Args:
            apk_path: Path to APK file
            analyzer_name: Name of requesting analyzer for tracking
            timeout: Decompilation timeout in seconds
            enable_cache: Whether to use cache (default: True)

        Returns:
            Path to decompiled sources directory, or None if failed
        """
        self.logger.info(f"[{analyzer_name}] Requesting decompiled sources for {os.path.basename(apk_path)}")

        # Resolve decompilation policy (mode + overrides + assertions)
        try:
            from core.decompilation_policy_resolver import get_decompilation_policy

            profile = os.getenv("AODS_PROFILE", "production")
            policy = get_decompilation_policy(apk_path=apk_path, profile=profile)
        except Exception as e:
            # Fall back to a conservative policy if resolver unavailable
            policy = DecompilationPolicy(
                output_dir="",
                max_threads=1,
                memory_limit_mb=1024,
                flags=[],
                mode=DecompilationMode.OPTIMIZED,
                reason="fallback",
                flags_version="fallback-1.0",
                disk_ok=True,
            )
            self.logger.debug(f"[{analyzer_name}] Policy resolver unavailable, using fallback policy: {e}")

        # Try cache first if enabled (keyed by apk + policy for determinism)
        if enable_cache and self.cache:
            key = f"jadx_unified_helper:{os.path.abspath(apk_path)}:{policy.flags_version}:{policy.mode.value}:{','.join(policy.flags)}"  # noqa: E501
            cached_path = self.cache.retrieve(key, CacheType.JADX_DECOMPILATION)
            if cached_path:
                self.logger.info(
                    f"[{analyzer_name}] Using cached decompilation (policy {policy.flags_version}/{policy.mode.value})"
                )
                return cached_path

        # Use centralized manager if available
        if self.manager:
            return self._decompile_with_manager(apk_path, analyzer_name, timeout, policy)
        else:
            # Fallback to direct decompilation with policy flags
            return self._decompile_fallback(apk_path, analyzer_name, timeout, policy)

    def _decompile_with_manager(self, apk_path: str, analyzer_name: str, timeout: int, policy) -> Optional[str]:
        """Decompile using centralized JADX manager."""
        try:
            # Extract package name for manager
            package_name = self._extract_package_name(apk_path)

            # Start decompilation
            job_id = self.manager.start_decompilation(
                apk_path=apk_path, package_name=package_name, timeout=timeout, priority="normal"
            )

            # Wait for completion
            success = self.manager.wait_for_completion(job_id)

            if success:
                job = self.manager.get_job_status(job_id)
                if job and job.output_dir and os.path.exists(job.output_dir):
                    # Cache the results if cache is available
                    if self.cache:
                        # Store decompilation output dir pointer keyed by policy for determinism
                        key = f"jadx_unified_helper:{os.path.abspath(apk_path)}:{policy.flags_version}:{policy.mode.value}:{','.join(policy.flags)}"  # noqa: E501
                        self.cache.store(key, job.output_dir, CacheType.JADX_DECOMPILATION, ttl_hours=168)

                    self.logger.info(f"[{analyzer_name}] Centralized decompilation completed")
                    return job.output_dir

            # Handle failure
            job = self.manager.get_job_status(job_id)
            error_msg = job.error_message if job else "Unknown error"
            self.logger.warning(f"[{analyzer_name}] Centralized decompilation failed: {error_msg}")
            return None

        except Exception as e:
            self.logger.error(f"[{analyzer_name}] Error with centralized manager: {e}")
            return None

    def _decompile_fallback(self, apk_path: str, analyzer_name: str, timeout: int, policy) -> Optional[str]:
        """Fallback decompilation when centralized manager unavailable."""
        try:
            import subprocess
            import shutil

            # Find JADX executable
            jadx_path = self._find_jadx_executable()
            if not jadx_path:
                self.logger.error(f"[{analyzer_name}] JADX executable not found")
                return None

            # Create temporary output directory
            temp_dir = tempfile.mkdtemp(prefix=f"aods_jadx_{analyzer_name}_")

            # Build JADX command using resolved policy flags
            cmd = [jadx_path]
            # Append policy flags in order (resolver ensures assertions like multidex)
            try:
                for f in policy.flags or []:
                    if isinstance(f, str) and f:
                        cmd.append(f)
            except Exception:
                pass
            cmd.extend(["--output-dir", temp_dir, os.path.abspath(apk_path)])

            self.logger.info(f"[{analyzer_name}] Fallback decompilation started")

            # Execute with timeout
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            # Validate actual output - os.path.exists(temp_dir) is always True after mkdtemp()
            has_output = result.returncode == 0 or (os.path.exists(temp_dir) and any(Path(temp_dir).rglob("*.java")))

            if has_output:
                # Cache the results if cache is available (keyed by policy)
                if self.cache:
                    key = f"jadx_unified_helper:{os.path.abspath(apk_path)}:{policy.flags_version}:{policy.mode.value}:{','.join(policy.flags)}"  # noqa: E501
                    self.cache.store(key, temp_dir, CacheType.JADX_DECOMPILATION, ttl_hours=48)

                self.logger.info(f"[{analyzer_name}] Fallback decompilation completed")
                return temp_dir
            else:
                self.logger.error(f"[{analyzer_name}] Fallback decompilation failed: {result.stderr}")
                shutil.rmtree(temp_dir, ignore_errors=True)
                return None

        except subprocess.TimeoutExpired:
            self.logger.error(f"[{analyzer_name}] Fallback decompilation timed out")
            return None
        except Exception as e:
            self.logger.error(f"[{analyzer_name}] Fallback decompilation error: {e}")
            return None

    def _extract_package_name(self, apk_path: str) -> str:
        """Extract package name from APK."""
        try:
            import subprocess

            # Try using aapt to get package name
            result = subprocess.run(["aapt", "dump", "badging", apk_path], capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("package: name="):
                        return line.split("'")[1]

            # Fallback to filename
            return Path(apk_path).stem

        except Exception:
            # Final fallback to filename
            return Path(apk_path).stem

    def _find_jadx_executable(self) -> Optional[str]:
        """Find JADX executable in system PATH."""
        import shutil

        jadx_candidates = ["jadx", "/usr/bin/jadx", "/usr/local/bin/jadx"]

        for candidate in jadx_candidates:
            if shutil.which(candidate):
                return candidate

        return None

    @contextmanager
    def temporary_decompilation(self, apk_path: str, analyzer_name: str = "temp", timeout: int = 300):
        """
        Context manager for temporary decompilation with automatic cleanup.

        Args:
            apk_path: Path to APK file
            analyzer_name: Name of requesting analyzer
            timeout: Decompilation timeout in seconds

        Yields:
            Path to decompiled sources directory
        """
        decompiled_dir = None
        try:
            decompiled_dir = self.get_decompiled_sources(apk_path, analyzer_name, timeout)
            yield decompiled_dir
        finally:
            # Only cleanup if it's a temporary directory (not cached)
            if decompiled_dir and "temp" in str(decompiled_dir).lower():
                try:
                    import shutil

                    shutil.rmtree(decompiled_dir, ignore_errors=True)
                    self.logger.debug(f"Cleaned up temporary decompilation: {decompiled_dir}")
                except Exception as e:
                    self.logger.warning(f"Failed to cleanup temporary decompilation: {e}")

    def get_memory_optimized_sources(
        self, apk_path: str, analyzer_name: str, required_patterns: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Get memory-optimized decompiled sources with selective analysis.

        Args:
            apk_path: Path to APK file
            analyzer_name: Name of requesting analyzer
            required_patterns: Optional list of file patterns to prioritize

        Returns:
            Dictionary with decompilation results and metadata
        """
        start_time = time.time()

        decompiled_dir = self.get_decompiled_sources(apk_path, analyzer_name)

        if not decompiled_dir:
            return {"success": False, "error": "Decompilation failed", "decompiled_dir": None, "files": [], "stats": {}}

        # Analyze decompiled files
        files = []
        total_size = 0

        try:
            for root, dirs, filenames in os.walk(decompiled_dir):
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    try:
                        file_size = os.path.getsize(file_path)
                        total_size += file_size

                        # Filter by patterns if specified
                        if required_patterns:
                            if any(pattern in filename.lower() for pattern in required_patterns):
                                files.append(
                                    {
                                        "path": file_path,
                                        "relative_path": os.path.relpath(file_path, decompiled_dir),
                                        "size": file_size,
                                        "type": filename.split(".")[-1] if "." in filename else "unknown",
                                    }
                                )
                        else:
                            files.append(
                                {
                                    "path": file_path,
                                    "relative_path": os.path.relpath(file_path, decompiled_dir),
                                    "size": file_size,
                                    "type": filename.split(".")[-1] if "." in filename else "unknown",
                                }
                            )
                    except OSError:
                        continue

        except Exception as e:
            self.logger.warning(f"Error analyzing decompiled files: {e}")

        execution_time = time.time() - start_time

        return {
            "success": True,
            "decompiled_dir": decompiled_dir,
            "files": files,
            "stats": {
                "total_files": len(files),
                "total_size_mb": total_size / (1024 * 1024),
                "execution_time": execution_time,
                "analyzer": analyzer_name,
            },
        }


# Global instance for memory optimization
_jadx_helper = None


def get_jadx_helper() -> JADXUnifiedHelper:
    """Get global JADX unified helper instance for memory optimization."""
    global _jadx_helper
    if _jadx_helper is None:
        _jadx_helper = JADXUnifiedHelper()
    return _jadx_helper


def get_decompiled_sources_unified(apk_path: str, analyzer_name: str = "unknown", timeout: int = 300) -> Optional[str]:
    """
    Unified function for getting decompiled sources across all AODS analyzers.

    This function provides memory optimization by using centralized caching
    and preventing redundant decompilations.

    Args:
        apk_path: Path to APK file
        analyzer_name: Name of requesting analyzer
        timeout: Decompilation timeout in seconds

    Returns:
        Path to decompiled sources directory, or None if failed
    """
    return get_jadx_helper().get_decompiled_sources(apk_path, analyzer_name, timeout)


def analyze_with_jadx_optimized(
    apk_path: str, analyzer_name: str, analysis_patterns: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Memory-optimized JADX analysis for all AODS analyzers.

    Args:
        apk_path: Path to APK file
        analyzer_name: Name of requesting analyzer
        analysis_patterns: Optional patterns to focus analysis on

    Returns:
        Dictionary with analysis results and metadata
    """
    return get_jadx_helper().get_memory_optimized_sources(apk_path, analyzer_name, analysis_patterns)
