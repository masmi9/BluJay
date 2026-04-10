#!/usr/bin/env python3
"""
Scan Statistics Collector - Simple & Practical
==============================================

Collects full scan statistics for AODS reports.
Focus: Simple, efficient, non-over-engineered solution.

Key Features:
- Scan timing data (start, end, duration)
- Plugin execution statistics (success/failure rates)
- File analysis coverage metrics
- Basic performance monitoring
- Configuration and version tracking
"""

import time
import psutil
import threading
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

try:
    from core.logging_config import get_logger

    _module_logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    _module_logger = stdlib_logging.getLogger(__name__)


@dataclass
class PluginStatistics:
    """Simple plugin execution statistics."""

    plugin_name: str
    execution_time_ms: float
    success: bool
    error_message: Optional[str] = None
    files_processed: int = 0
    vulnerabilities_found: int = 0


@dataclass
class ScanStatistics:
    """Full scan statistics data structure."""

    # Timing information
    scan_start_time: datetime
    scan_end_time: Optional[datetime] = None
    total_duration_seconds: float = 0.0

    # Plugin statistics
    plugins_executed: int = 0
    plugins_successful: int = 0
    plugins_failed: int = 0
    plugin_details: List[PluginStatistics] = field(default_factory=list)

    # File analysis coverage
    total_files_discovered: int = 0
    files_analyzed: int = 0
    files_skipped: int = 0
    coverage_percentage: float = 0.0

    # Performance metrics
    peak_memory_mb: float = 0.0
    avg_cpu_percent: float = 0.0

    # Configuration tracking
    aods_version: str = "2.1.0"
    scan_mode: str = "deep"
    target_package: str = "Unknown"
    apk_size_mb: float = 0.0

    # Results summary
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0


class ScanStatisticsCollector:
    """
    Simple scan statistics collector.

    Design Principles:
    - Minimal overhead on scan performance
    - Simple data collection and aggregation
    - Easy integration with existing pipeline
    - Clear, actionable metrics
    """

    def __init__(self):
        """Initialize with simple configuration."""
        try:
            from core.logging_config import get_logger

            self.logger = get_logger(__name__)
        except ImportError:
            import logging as stdlib_logging

            self.logger = stdlib_logging.getLogger(__name__)

        # Statistics tracking
        self.statistics = ScanStatistics(scan_start_time=datetime.now())
        self.plugin_start_times: Dict[str, float] = {}

        # Performance monitoring
        self.performance_samples: List[Dict[str, float]] = []
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None

        # Thread safety
        self._lock = threading.RLock()

        self.logger.info("Scan Statistics Collector initialized")

    def start_scan(self, target_package: str, scan_mode: str = "deep", apk_size_mb: float = 0.0) -> None:
        """Start scan statistics collection."""
        with self._lock:
            self.statistics.scan_start_time = datetime.now()
            self.statistics.target_package = target_package
            self.statistics.scan_mode = scan_mode
            self.statistics.apk_size_mb = apk_size_mb

            # Start performance monitoring
            self._start_performance_monitoring()

            self.logger.info("Scan statistics collection started", target_package=target_package)

    def end_scan(self) -> None:
        """End scan statistics collection."""
        with self._lock:
            self.statistics.scan_end_time = datetime.now()
            self.statistics.total_duration_seconds = (
                self.statistics.scan_end_time - self.statistics.scan_start_time
            ).total_seconds()

            # Stop performance monitoring
            self._stop_performance_monitoring()

            # Calculate coverage percentage
            if self.statistics.total_files_discovered > 0:
                self.statistics.coverage_percentage = (
                    self.statistics.files_analyzed / self.statistics.total_files_discovered
                ) * 100

            self.logger.info("Scan completed", duration_seconds=round(self.statistics.total_duration_seconds, 2))

    def record_plugin_start(self, plugin_name: str) -> None:
        """Record plugin execution start."""
        with self._lock:
            self.plugin_start_times[plugin_name] = time.time()

    def record_plugin_end(
        self,
        plugin_name: str,
        success: bool,
        error_message: Optional[str] = None,
        files_processed: int = 0,
        vulnerabilities_found: int = 0,
    ) -> None:
        """Record plugin execution end."""
        with self._lock:
            start_time = self.plugin_start_times.get(plugin_name, time.time())
            execution_time_ms = (time.time() - start_time) * 1000

            # Create plugin statistics
            plugin_stats = PluginStatistics(
                plugin_name=plugin_name,
                execution_time_ms=execution_time_ms,
                success=success,
                error_message=error_message,
                files_processed=files_processed,
                vulnerabilities_found=vulnerabilities_found,
            )

            self.statistics.plugin_details.append(plugin_stats)
            self.statistics.plugins_executed += 1

            if success:
                self.statistics.plugins_successful += 1
            else:
                self.statistics.plugins_failed += 1

            # Clean up start time
            if plugin_name in self.plugin_start_times:
                del self.plugin_start_times[plugin_name]

    def record_file_analysis(self, total_files: int, analyzed_files: int, skipped_files: int = 0) -> None:
        """Record file analysis statistics."""
        with self._lock:
            self.statistics.total_files_discovered = total_files
            self.statistics.files_analyzed = analyzed_files
            self.statistics.files_skipped = skipped_files

    def record_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> None:
        """Record vulnerability statistics."""
        with self._lock:
            self.statistics.total_vulnerabilities = len(vulnerabilities)

            # Count by severity
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

            for vuln in vulnerabilities:
                severity = str(vuln.get("severity", "medium")).lower()
                if severity in ["critical", "severe"]:
                    severity_counts["critical"] += 1
                elif severity in ["high", "major"]:
                    severity_counts["high"] += 1
                elif severity in ["medium", "moderate", "warning"]:
                    severity_counts["medium"] += 1
                else:
                    severity_counts["low"] += 1

            self.statistics.critical_vulnerabilities = severity_counts["critical"]
            self.statistics.high_vulnerabilities = severity_counts["high"]
            self.statistics.medium_vulnerabilities = severity_counts["medium"]
            self.statistics.low_vulnerabilities = severity_counts["low"]

    def get_statistics(self) -> ScanStatistics:
        """Get current scan statistics."""
        with self._lock:
            return self.statistics

    def get_statistics_summary(self) -> Dict[str, Any]:
        """Get statistics summary for reports."""
        with self._lock:
            stats = self.statistics

            # Calculate success rate
            success_rate = 0.0
            if stats.plugins_executed > 0:
                success_rate = (stats.plugins_successful / stats.plugins_executed) * 100

            # Get top performing plugins
            top_plugins = sorted(
                [p for p in stats.plugin_details if p.success], key=lambda x: x.vulnerabilities_found, reverse=True
            )[:5]

            # Get slowest plugins
            slowest_plugins = sorted(stats.plugin_details, key=lambda x: x.execution_time_ms, reverse=True)[:3]

            return {
                "scan_overview": {
                    "start_time": stats.scan_start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "end_time": (
                        stats.scan_end_time.strftime("%Y-%m-%d %H:%M:%S") if stats.scan_end_time else "In Progress"
                    ),
                    "total_duration": f"{stats.total_duration_seconds:.2f}s",
                    "target_package": stats.target_package,
                    "scan_mode": stats.scan_mode,
                    "aods_version": stats.aods_version,
                },
                "plugin_performance": {
                    "total_plugins": stats.plugins_executed,
                    "successful_plugins": stats.plugins_successful,
                    "failed_plugins": stats.plugins_failed,
                    "success_rate_percent": f"{success_rate:.1f}%",
                    "top_performing_plugins": [
                        {
                            "name": p.plugin_name,
                            "vulnerabilities_found": p.vulnerabilities_found,
                            "execution_time_ms": f"{p.execution_time_ms:.1f}ms",
                        }
                        for p in top_plugins
                    ],
                    "slowest_plugins": [
                        {"name": p.plugin_name, "execution_time_ms": f"{p.execution_time_ms:.1f}ms"}
                        for p in slowest_plugins
                    ],
                },
                "file_analysis": {
                    "total_files_discovered": stats.total_files_discovered,
                    "files_analyzed": stats.files_analyzed,
                    "files_skipped": stats.files_skipped,
                    "coverage_percentage": f"{stats.coverage_percentage:.1f}%",
                },
                "performance_metrics": {
                    "peak_memory_mb": f"{stats.peak_memory_mb:.1f}MB",
                    "avg_cpu_percent": f"{stats.avg_cpu_percent:.1f}%",
                    "apk_size_mb": f"{stats.apk_size_mb:.1f}MB",
                },
                "vulnerability_summary": {
                    "total_vulnerabilities": stats.total_vulnerabilities,
                    "critical": stats.critical_vulnerabilities,
                    "high": stats.high_vulnerabilities,
                    "medium": stats.medium_vulnerabilities,
                    "low": stats.low_vulnerabilities,
                },
            }

    def _start_performance_monitoring(self) -> None:
        """Start background performance monitoring."""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitor_performance, daemon=True)
        self.monitoring_thread.start()

    def _stop_performance_monitoring(self) -> None:
        """Stop background performance monitoring."""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=1.0)

        # Calculate averages
        if self.performance_samples:
            self.statistics.peak_memory_mb = max(s["memory_mb"] for s in self.performance_samples)
            self.statistics.avg_cpu_percent = sum(s["cpu_percent"] for s in self.performance_samples) / len(
                self.performance_samples
            )

    def _monitor_performance(self) -> None:
        """Background performance monitoring thread."""
        try:
            process = psutil.Process()

            while self.monitoring_active:
                try:
                    # Get memory usage
                    memory_info = process.memory_info()
                    memory_mb = memory_info.rss / (1024 * 1024)  # Convert to MB

                    # Get CPU usage
                    cpu_percent = process.cpu_percent()

                    # Store sample
                    sample = {"timestamp": time.time(), "memory_mb": memory_mb, "cpu_percent": cpu_percent}

                    with self._lock:
                        self.performance_samples.append(sample)

                        # Keep only last 100 samples to avoid memory growth
                        if len(self.performance_samples) > 100:
                            self.performance_samples = self.performance_samples[-100:]

                    time.sleep(2.0)  # Sample every 2 seconds

                except psutil.NoSuchProcess:
                    break
                except Exception as e:
                    self.logger.warning(f"Performance monitoring error: {e}")
                    time.sleep(5.0)  # Wait longer on error

        except Exception as e:
            self.logger.error(f"Performance monitoring thread failed: {e}")

    def export_detailed_statistics(self) -> Dict[str, Any]:
        """Export detailed statistics for analysis."""
        with self._lock:
            stats = self.statistics

            return {
                "scan_metadata": {
                    "start_time": stats.scan_start_time.isoformat(),
                    "end_time": stats.scan_end_time.isoformat() if stats.scan_end_time else None,
                    "duration_seconds": stats.total_duration_seconds,
                    "target_package": stats.target_package,
                    "scan_mode": stats.scan_mode,
                    "aods_version": stats.aods_version,
                    "apk_size_mb": stats.apk_size_mb,
                },
                "plugin_details": [
                    {
                        "name": p.plugin_name,
                        "execution_time_ms": p.execution_time_ms,
                        "success": p.success,
                        "error_message": p.error_message,
                        "files_processed": p.files_processed,
                        "vulnerabilities_found": p.vulnerabilities_found,
                    }
                    for p in stats.plugin_details
                ],
                "file_analysis": {
                    "total_discovered": stats.total_files_discovered,
                    "analyzed": stats.files_analyzed,
                    "skipped": stats.files_skipped,
                    "coverage_percent": stats.coverage_percentage,
                },
                "performance_samples": self.performance_samples,
                "vulnerability_counts": {
                    "total": stats.total_vulnerabilities,
                    "critical": stats.critical_vulnerabilities,
                    "high": stats.high_vulnerabilities,
                    "medium": stats.medium_vulnerabilities,
                    "low": stats.low_vulnerabilities,
                },
            }


# Simple integration test
if __name__ == "__main__":
    _module_logger.info("Testing Scan Statistics Collector")

    # Test collector
    collector = ScanStatisticsCollector()

    # Simulate scan
    collector.start_scan("com.test.app", "deep", 15.5)

    # Simulate plugin executions
    collector.record_plugin_start("sql_injection_detector")
    time.sleep(0.1)  # Simulate work
    collector.record_plugin_end("sql_injection_detector", True, None, 25, 3)

    collector.record_plugin_start("crypto_analyzer")
    time.sleep(0.05)  # Simulate work
    collector.record_plugin_end("crypto_analyzer", True, None, 10, 1)

    collector.record_plugin_start("network_scanner")
    time.sleep(0.02)  # Simulate work
    collector.record_plugin_end("network_scanner", False, "Network timeout", 0, 0)

    # Simulate file analysis
    collector.record_file_analysis(150, 145, 5)

    # Simulate vulnerabilities
    mock_vulnerabilities = [
        {"severity": "critical"},
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "high"},
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "low"},
    ]
    collector.record_vulnerabilities(mock_vulnerabilities)

    # End scan
    time.sleep(0.1)  # Let performance monitoring collect samples
    collector.end_scan()

    # Get statistics
    stats = collector.get_statistics()
    summary = collector.get_statistics_summary()

    _module_logger.info(
        "Scan statistics test results",
        duration_s=round(stats.total_duration_seconds, 2),
        plugins_executed=stats.plugins_executed,
        success_rate=summary["plugin_performance"]["success_rate_percent"],
        files_analyzed=stats.files_analyzed,
        files_discovered=stats.total_files_discovered,
        coverage_pct=round(stats.coverage_percentage, 1),
        vulnerabilities=stats.total_vulnerabilities,
        peak_memory_mb=round(stats.peak_memory_mb, 1),
    )

    _module_logger.info("Scan Statistics Collector test completed")
