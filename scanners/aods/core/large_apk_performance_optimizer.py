#!/usr/bin/env python3
"""
Large APK Performance Optimizer
===============================

Aggressive performance optimization system specifically designed for large APKs (>200MB)
to achieve target analysis time of <20 seconds for 400MB+ applications.

Target: Reduce TikTok analysis time from 28.42s to <20s (30% improvement)

Key Optimizations:
- Intelligent parallel processing with dynamic worker allocation
- Memory-efficient streaming analysis with prefetching
- Aggressive result caching with fingerprint-based cache keys
- Smart file prioritization based on security value
- Resource-aware processing with real-time adaptation
- Plugin execution optimization with dependency analysis

Performance Targets:
- <20s analysis time for 400MB+ APKs
- 50%+ reduction in memory usage through streaming
- 3x improvement in parallel processing efficiency
- 90%+ cache hit rate for repeated analysis patterns

"""

import logging
import mmap
import os
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Any, Callable
import psutil

logger = logging.getLogger(__name__)

# MIGRATED: PerformanceMetrics class replaced with unified infrastructure
# from core.shared_infrastructure.monitoring.performance_tracker import get_unified_performance_tracker
# Original class removed - now using Dict[str, Any] with unified performance tracker

# Removed orphaned @property methods from a deprecated class to fix indentation error


@dataclass
class FileAnalysisPriority:
    """Priority classification for file analysis optimization."""

    path: str
    size_bytes: int
    priority_score: float
    analysis_type: str
    estimated_time_ms: float


from core.shared_infrastructure.performance.caching_consolidation import (  # noqa: E402
    get_unified_cache_manager,
)

# FIX: Use existing adapter to unified cache manager to avoid NameError
from core.performance_enhancement_suite import IntelligentCacheManager  # noqa: E402


class SmartFileClassifier:
    """Intelligent file classification for optimized analysis prioritization."""

    def __init__(self):
        # High-value file patterns for security analysis
        self.high_priority_patterns = {
            "manifest": {"weight": 1.0, "patterns": ["AndroidManifest.xml"]},
            "config": {"weight": 0.9, "patterns": [".properties", ".json", ".xml", ".yml", ".yaml"]},
            "source": {"weight": 0.8, "patterns": [".java", ".kt", ".js"]},
            "native": {"weight": 0.7, "patterns": [".so", ".dll"]},
            "resources": {"weight": 0.6, "patterns": ["strings.xml", "values.xml"]},
            "assets": {"weight": 0.5, "patterns": ["assets/", "www/"]},
            "smali": {"weight": 0.4, "patterns": [".smali"]},
        }

        # File size impact on analysis time (empirical data)
        self.size_time_multipliers = {
            (0, 1024): 0.1,  # <1KB: Very fast
            (1024, 10240): 0.3,  # 1-10KB: Fast
            (10240, 102400): 0.6,  # 10-100KB: Medium
            (102400, 1048576): 1.0,  # 100KB-1MB: Normal
            (1048576, 10485760): 2.0,  # 1-10MB: Slow
            (10485760, float("inf")): 5.0,  # >10MB: Very slow
        }

    def classify_files(self, zip_file: zipfile.ZipFile, max_files: int = 1000) -> List[FileAnalysisPriority]:
        """Classify and prioritize files for optimal analysis order."""
        file_priorities = []

        for file_info in zip_file.infolist():
            if file_info.is_dir():
                continue

            # Calculate priority score
            priority_score = self._calculate_priority_score(file_info)

            # Estimate analysis time
            estimated_time = self._estimate_analysis_time(file_info)

            # Determine analysis type
            analysis_type = self._determine_analysis_type(file_info.filename)

            file_priorities.append(
                FileAnalysisPriority(
                    path=file_info.filename,
                    size_bytes=file_info.file_size,
                    priority_score=priority_score,
                    analysis_type=analysis_type,
                    estimated_time_ms=estimated_time,
                )
            )

        # Sort by priority score (descending) and estimated time (ascending)
        file_priorities.sort(key=lambda f: (-f.priority_score, f.estimated_time_ms))

        # Limit to max_files for large APKs
        return file_priorities[:max_files]

    def _calculate_priority_score(self, file_info) -> float:
        """Calculate security analysis priority score for file."""
        score = 0.0
        filename = file_info.filename.lower()

        # Pattern-based scoring
        for category, config in self.high_priority_patterns.items():
            for pattern in config["patterns"]:
                if pattern.lower() in filename:
                    score = max(score, config["weight"])
                    break

        # Size penalty for very large files (diminishing returns)
        size_factor = 1.0
        if file_info.file_size > 1048576:  # >1MB
            size_factor = 0.8
        elif file_info.file_size > 10485760:  # >10MB
            size_factor = 0.5

        return score * size_factor

    def _estimate_analysis_time(self, file_info) -> float:
        """Estimate analysis time in milliseconds."""
        base_time = 10.0  # Base 10ms per file

        # Apply size multiplier
        for (min_size, max_size), multiplier in self.size_time_multipliers.items():
            if min_size <= file_info.file_size < max_size:
                return base_time * multiplier

        return base_time

    def _determine_analysis_type(self, filename: str) -> str:
        """Determine the type of analysis needed for the file."""
        filename_lower = filename.lower()

        if "androidmanifest.xml" in filename_lower:
            return "manifest"
        elif any(ext in filename_lower for ext in [".java", ".kt"]):
            return "source_code"
        elif any(ext in filename_lower for ext in [".xml", ".json"]):
            return "config"
        elif ".so" in filename_lower:
            return "native"
        elif ".smali" in filename_lower:
            return "bytecode"
        else:
            return "generic"


class AdaptiveResourceManager:
    """Dynamic resource allocation based on system capacity and APK characteristics."""

    def __init__(self):
        self.system_cores = psutil.cpu_count()
        self.system_memory_gb = psutil.virtual_memory().total / (1024**3)
        self.baseline_metrics = self._establish_baseline()

    def _establish_baseline(self) -> Dict[str, float]:
        """Establish system performance baseline."""
        return {
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_io": sum(psutil.disk_io_counters()[:2]) if psutil.disk_io_counters() else 0,
        }

    def calculate_optimal_workers(self, apk_size_mb: float, analysis_type: str = "full") -> int:
        """Calculate optimal worker count based on system resources and APK size."""
        # Base workers on CPU cores
        base_workers = max(2, self.system_cores - 1)  # Leave 1 core for system

        # APK size adjustment
        if apk_size_mb > 500:
            # Very large APKs: Use fewer workers to prevent memory pressure
            size_factor = 0.5
        elif apk_size_mb > 200:
            # Large APKs: Moderate worker count
            size_factor = 0.7
        else:
            # Normal APKs: Full parallelization
            size_factor = 1.0

        # Memory availability adjustment
        memory_factor = min(1.0, self.system_memory_gb / 8.0)  # Scale based on 8GB baseline

        # Current system load adjustment
        current_cpu = psutil.cpu_percent(interval=0.1)
        load_factor = max(0.3, 1.0 - (current_cpu / 100.0))

        optimal_workers = int(base_workers * size_factor * memory_factor * load_factor)
        return max(2, min(optimal_workers, 8))  # Min 2, Max 8 workers

    def should_use_process_pool(self, analysis_type: str, worker_count: int) -> bool:
        """Determine if process pool is better than thread pool for the analysis."""
        # Use process pool for CPU-intensive analysis with sufficient memory
        if self.system_memory_gb >= 8 and worker_count <= 4:
            return analysis_type in ["source_code", "bytecode", "native"]
        return False


class LargeAPKPerformanceOptimizer:
    """Main performance optimizer for large APK analysis."""

    def __init__(self):
        # Prefer adapter; fallback to unified cache manager to avoid NameError
        try:
            self.cache_manager = IntelligentCacheManager()
        except Exception:
            self.cache_manager = get_unified_cache_manager()
        self.file_classifier = SmartFileClassifier()
        self.resource_manager = AdaptiveResourceManager()
        self.metrics = None

    def optimize_analysis(
        self, apk_path: str, analysis_functions: Dict[str, Callable], target_time_seconds: float = 20.0
    ) -> Dict[str, Any]:
        """
        Optimize APK analysis to achieve target performance.

        Args:
            apk_path: Path to APK file
            analysis_functions: Dictionary of analysis functions to run
            target_time_seconds: Target analysis time (default 20s)

        Returns:
            Optimized analysis results with performance metrics
        """
        # MIGRATED: Use dict-based metrics with unified performance tracker
        from core.shared_infrastructure.monitoring.performance_tracker import get_unified_performance_tracker

        self.performance_tracker = get_unified_performance_tracker()
        self.metrics = {"start_time": time.time()}  # Using unified tracker's dict-based metrics
        apk_size_mb = os.path.getsize(apk_path) / (1024 * 1024)

        logger.info(f"🚀 Starting optimized analysis for {apk_size_mb:.1f}MB APK")
        logger.info(f"⏱️ Target time: {target_time_seconds}s")

        try:
            # Check cache first
            cache_key = self.cache_manager._generate_cache_key(apk_path, "full", None)
            cached_result = self.cache_manager.get(cache_key)
            if cached_result:
                logger.info("✅ Using cached analysis result")
                self.metrics["cache_hits"] = 1
                self.metrics["end_time"] = time.time()
                # Compute simple totals
                self.metrics["total_time"] = self.metrics["end_time"] - self.metrics.get(
                    "start_time", self.metrics["end_time"]
                )
                cached_result["performance_metrics"] = self.metrics
                return cached_result

            self.metrics["cache_misses"] = 1

            # Memory-mapped file access for large APKs
            with open(apk_path, "rb") as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    results = self._analyze_with_memory_mapping(mm, apk_path, analysis_functions, target_time_seconds)

            # Cache results for future use
            self.cache_manager.put(cache_key, results)

            self.metrics["end_time"] = time.time()
            # Derive totals
            self.metrics["total_time"] = self.metrics["end_time"] - self.metrics.get(
                "start_time", self.metrics["end_time"]
            )
            # Throughput estimation if bytes_processed available
            try:
                bytes_processed = float(self.metrics.get("bytes_processed", 0.0))
                seconds = max(1e-6, float(self.metrics.get("total_time", 0.0)))
                self.metrics["throughput_mb_per_second"] = (bytes_processed / (1024.0 * 1024.0)) / seconds
            except Exception:
                self.metrics["throughput_mb_per_second"] = 0.0
            results["performance_metrics"] = self.metrics

            analysis_time = self.metrics.get("total_time", 0.0)
            logger.info(f"✅ Analysis completed in {analysis_time:.2f}s")

            if analysis_time <= target_time_seconds:
                logger.info(f"🎯 Target achieved! ({analysis_time:.2f}s <= {target_time_seconds}s)")
            else:
                logger.warning(f"⚠️ Target missed by {analysis_time - target_time_seconds:.2f}s")

            return results

        except Exception as e:
            logger.error(f"❌ Optimization failed: {e}")
            self.metrics["end_time"] = time.time()
            return {"error": str(e), "performance_metrics": self.metrics, "analysis_results": {}}

    def _analyze_with_memory_mapping(
        self, memory_map: mmap.mmap, apk_path: str, analysis_functions: Dict[str, Callable], target_time: float
    ) -> Dict[str, Any]:
        """Perform analysis using memory-mapped file for efficiency."""
        with zipfile.ZipFile(memory_map, "r") as zip_file:
            # Classify and prioritize files
            file_priorities = self.file_classifier.classify_files(
                zip_file, max_files=2000  # Increased limit for better coverage
            )

            self.metrics["files_processed"] = len(file_priorities)
            self.metrics["bytes_processed"] = sum(f.size_bytes for f in file_priorities)

            # Calculate optimal resource allocation
            worker_count = self.resource_manager.calculate_optimal_workers(os.path.getsize(apk_path) / (1024 * 1024))

            logger.info(f"📊 Processing {len(file_priorities)} files with {worker_count} workers")

            # Execute analysis with parallel processing
            results = self._execute_parallel_analysis(
                zip_file, file_priorities, analysis_functions, worker_count, target_time
            )

            return results

    def _execute_parallel_analysis(
        self,
        zip_file: zipfile.ZipFile,
        file_priorities: List[FileAnalysisPriority],
        analysis_functions: Dict[str, Callable],
        worker_count: int,
        target_time: float,
    ) -> Dict[str, Any]:
        """Execute analysis with optimized parallel processing."""
        results = {"analysis_results": {}, "files_analyzed": 0, "optimization_applied": True}

        # Time budget allocation: 70% for file analysis, 30% for post-processing
        file_analysis_budget = target_time * 0.7
        start_time = time.time()

        # Batch files for optimal processing
        batch_size = max(50, len(file_priorities) // worker_count)
        file_batches = [file_priorities[i : i + batch_size] for i in range(0, len(file_priorities), batch_size)]

        # Use process pool for CPU-intensive work if system allows
        use_process_pool = self.resource_manager.should_use_process_pool("full", worker_count)

        executor_class = ProcessPoolExecutor if use_process_pool else ThreadPoolExecutor

        with executor_class(max_workers=worker_count) as executor:
            # Submit analysis tasks
            future_to_batch = {}
            for batch in file_batches:
                future = executor.submit(self._analyze_file_batch, zip_file, batch, analysis_functions)
                future_to_batch[future] = batch

            # Collect results with time monitoring
            for future in as_completed(future_to_batch, timeout=file_analysis_budget):
                try:
                    # Use Future.result() with timeout instead of non-existent get()
                    batch_results = future.result(timeout=5.0)  # 5s per batch max

                    # Merge batch results
                    for analysis_type, findings in batch_results.items():
                        if analysis_type not in results["analysis_results"]:
                            results["analysis_results"][analysis_type] = []
                        results["analysis_results"][analysis_type].extend(findings)

                    results["files_analyzed"] += len(future_to_batch[future])

                    # Check time budget
                    elapsed = time.time() - start_time
                    if elapsed > file_analysis_budget:
                        logger.warning(f"⏱️ Time budget exceeded, stopping at {elapsed:.1f}s")
                        break

                except Exception as e:
                    logger.warning(f"Batch analysis failed: {e}")
                    continue

        # Calculate parallel efficiency
        elapsed_time = time.time() - start_time
        theoretical_sequential_time = sum(f.estimated_time_ms for f in file_priorities) / 1000
        self.metrics["parallel_efficiency"] = theoretical_sequential_time / elapsed_time if elapsed_time > 0 else 1.0

        logger.info(f"📈 Parallel efficiency: {self.metrics['parallel_efficiency']:.2f}x")

        return results

    def _analyze_file_batch(
        self, zip_file: zipfile.ZipFile, file_batch: List[FileAnalysisPriority], analysis_functions: Dict[str, Callable]
    ) -> Dict[str, List]:
        """Analyze a batch of files efficiently."""
        batch_results = {}

        for file_priority in file_batch:
            try:
                # Read file content efficiently
                file_content = zip_file.read(file_priority.path)

                # Skip empty files
                if not file_content:
                    continue

                # Convert to string for analysis
                try:
                    if file_priority.analysis_type in ["source_code", "config", "manifest"]:
                        content_str = file_content.decode("utf-8", errors="ignore")
                    else:
                        # For binary files, extract strings efficiently
                        content_str = self._extract_strings_fast(file_content)
                except Exception:
                    continue

                # Apply relevant analysis functions
                for analysis_name, analysis_func in analysis_functions.items():
                    try:
                        findings = analysis_func(content_str, file_priority.path)
                        if findings:
                            if analysis_name not in batch_results:
                                batch_results[analysis_name] = []
                            batch_results[analysis_name].extend(findings)
                    except Exception as e:
                        logger.debug(f"Analysis {analysis_name} failed for {file_priority.path}: {e}")
                        continue

            except Exception as e:
                logger.debug(f"Failed to process {file_priority.path}: {e}")
                continue

        return batch_results

    def _extract_strings_fast(self, binary_content: bytes, min_length: int = 4) -> str:
        """Fast string extraction from binary content."""
        # Extract printable ASCII strings efficiently
        strings = []
        current_string = ""

        for byte in binary_content[:10240]:  # Limit to first 10KB for performance
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""

        # Add final string if valid
        if len(current_string) >= min_length:
            strings.append(current_string)

        return "\n".join(strings[:100])  # Limit to 100 strings

    def get_optimization_report(self) -> Dict[str, Any]:
        """Generate detailed optimization performance report."""
        if not self.metrics:
            return {}

        total_time = float(self.metrics.get("total_time", 0.0))
        cache_hits = int(self.metrics.get("cache_hits", 0))
        cache_misses = int(self.metrics.get("cache_misses", 0))
        cache_requests = cache_hits + cache_misses
        return {
            "analysis_time_seconds": total_time,
            "throughput_mb_per_second": float(self.metrics.get("throughput_mb_per_second", 0.0)),
            "files_processed": int(self.metrics.get("files_processed", 0)),
            "cache_hit_rate": (cache_hits / cache_requests) if cache_requests > 0 else 0.0,
            "parallel_efficiency": float(self.metrics.get("parallel_efficiency", 0.0)),
            "memory_peak_mb": float(self.metrics.get("memory_peak_mb", 0.0)),
            "optimization_effectiveness": min(100, (20.0 / total_time) * 100) if total_time > 0 else 0,
        }
