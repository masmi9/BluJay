#!/usr/bin/env python3
"""
AODS Data Synchronization Engine
===============================

Advanced data synchronization system providing automated, incremental updates
of external security data sources with intelligent scheduling and error handling.

Features:
- Multi-source data synchronization coordination
- Incremental updates with change detection
- Intelligent scheduling and retry mechanisms
- Data quality validation and filtering
- Performance monitoring and optimization
- Conflict resolution and data integrity assurance
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class SyncStatus(Enum):
    """Synchronization status enumeration."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class DataSourceType(Enum):
    """Data source type enumeration."""

    CVE_NVD = "cve_nvd"
    THREAT_INTEL = "threat_intel"
    EXPLOIT_DB = "exploit_db"
    MALWARE_INDICATORS = "malware_indicators"
    SECURITY_ADVISORIES = "security_advisories"
    CUSTOM_FEED = "custom_feed"


@dataclass
class SyncConfiguration:
    """Synchronization configuration for a data source."""

    source_id: str
    source_type: DataSourceType
    enabled: bool = True
    sync_interval: int = 3600  # seconds
    batch_size: int = 1000
    max_retries: int = 3
    timeout: int = 300  # seconds
    priority: int = 5  # 1-10, higher is higher priority
    data_filters: Dict[str, Any] = field(default_factory=dict)
    custom_params: Dict[str, Any] = field(default_factory=dict)
    last_sync: Optional[datetime] = None
    next_sync: Optional[datetime] = None
    consecutive_failures: int = 0


@dataclass
class SyncResult:
    """Result of a synchronization operation."""

    source_id: str
    status: SyncStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    records_processed: int = 0
    records_updated: int = 0
    records_added: int = 0
    records_failed: int = 0
    error_message: Optional[str] = None
    data_quality_score: float = 1.0
    performance_metrics: Dict[str, float] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        """Get sync duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.now(datetime.UTC) - self.start_time).total_seconds()

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.records_processed == 0:
            return 1.0
        return (self.records_processed - self.records_failed) / self.records_processed


class DataSynchronizer:
    """
    Advanced data synchronization orchestrator.

    Manages automated synchronization of multiple external data sources with
    intelligent scheduling, error handling, and performance optimization.
    """

    def __init__(self, config_path: Optional[str] = None):
        """Initialize data synchronizer."""
        self.config = self._load_config(config_path)

        # Synchronization state
        self.sync_configs: Dict[str, SyncConfiguration] = {}
        self.sync_results: Dict[str, List[SyncResult]] = {}
        self.active_syncs: Dict[str, asyncio.Task] = {}

        # Synchronization handlers
        self.sync_handlers: Dict[DataSourceType, Callable] = {}

        # Thread pool for parallel operations
        self.executor = ThreadPoolExecutor(max_workers=self.config.get("max_parallel_syncs", 4))

        # Event system
        self.sync_events = asyncio.Queue()

        # Performance monitoring
        self.performance_stats = {
            "total_syncs": 0,
            "successful_syncs": 0,
            "failed_syncs": 0,
            "avg_sync_time": 0.0,
            "data_quality_avg": 0.0,
        }

        # Control flags
        self._running = False
        self._shutdown_event = asyncio.Event()

        logger.info("Data Synchronizer initialized with advanced orchestration")

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load synchronizer configuration."""
        default_config = {
            "max_parallel_syncs": 4,
            "scheduler_interval": 60,  # Check every minute
            "retry_delay_base": 60,  # Base retry delay in seconds
            "max_retry_delay": 3600,  # Max retry delay (1 hour)
            "data_quality_threshold": 0.8,
            "performance_monitoring": True,
            "event_logging": True,
        }

        if config_path and Path(config_path).exists():
            try:
                with open(config_path, "r") as f:
                    config = json.load(f)
                default_config.update(config)
            except Exception as e:
                logger.error(f"Failed to load config from {config_path}: {e}")

        return default_config

    def register_sync_handler(self, source_type: DataSourceType, handler: Callable) -> None:
        """Register synchronization handler for a data source type."""
        self.sync_handlers[source_type] = handler
        logger.info(f"Registered sync handler for {source_type.value}")

    def add_data_source(self, config: SyncConfiguration) -> None:
        """Add data source for synchronization."""
        # Validate configuration
        if not config.source_id:
            raise ValueError("Source ID is required")

        if config.source_type not in self.sync_handlers:
            logger.warning(f"No handler registered for {config.source_type.value}")

        # Calculate next sync time
        if config.last_sync:
            config.next_sync = config.last_sync + timedelta(seconds=config.sync_interval)
        else:
            config.next_sync = datetime.now(datetime.UTC)

        self.sync_configs[config.source_id] = config
        self.sync_results[config.source_id] = []

        logger.info(f"Added data source: {config.source_id} ({config.source_type.value})")

    def remove_data_source(self, source_id: str) -> bool:
        """Remove data source from synchronization."""
        if source_id in self.sync_configs:
            # Cancel active sync if running
            if source_id in self.active_syncs:
                self.active_syncs[source_id].cancel()
                del self.active_syncs[source_id]

            del self.sync_configs[source_id]
            if source_id in self.sync_results:
                del self.sync_results[source_id]

            logger.info(f"Removed data source: {source_id}")
            return True
        return False

    def update_sync_config(self, source_id: str, updates: Dict[str, Any]) -> bool:
        """Update synchronization configuration for a data source."""
        if source_id not in self.sync_configs:
            return False

        config = self.sync_configs[source_id]

        # Update configuration fields
        for key, value in updates.items():
            if hasattr(config, key):
                setattr(config, key, value)

        # Recalculate next sync if interval changed
        if "sync_interval" in updates and config.last_sync:
            config.next_sync = config.last_sync + timedelta(seconds=config.sync_interval)

        logger.info(f"Updated sync config for {source_id}")
        return True

    async def sync_data_source(self, source_id: str, force: bool = False) -> SyncResult:
        """Synchronize a specific data source."""
        if source_id not in self.sync_configs:
            raise ValueError(f"Unknown data source: {source_id}")

        config = self.sync_configs[source_id]

        # Check if sync is needed
        if not force and config.next_sync and datetime.now(datetime.UTC) < config.next_sync:
            raise ValueError(f"Sync not yet due for {source_id}")

        # Check if source is enabled
        if not config.enabled:
            raise ValueError(f"Data source {source_id} is disabled")

        # Create sync result
        result = SyncResult(source_id=source_id, status=SyncStatus.RUNNING, start_time=datetime.now(datetime.UTC))

        try:
            logger.info(f"Starting sync for {source_id}")

            # Get sync handler
            handler = self.sync_handlers.get(config.source_type)
            if not handler:
                raise ValueError(f"No handler for {config.source_type.value}")

            # Execute sync with timeout
            sync_task = asyncio.create_task(self._execute_sync_with_timeout(handler, config, result))

            # Track active sync
            self.active_syncs[source_id] = sync_task

            try:
                await sync_task
            finally:
                if source_id in self.active_syncs:
                    del self.active_syncs[source_id]

            # Update configuration
            config.last_sync = datetime.now(datetime.UTC)
            config.next_sync = config.last_sync + timedelta(seconds=config.sync_interval)
            config.consecutive_failures = 0

            result.status = SyncStatus.COMPLETED
            result.end_time = datetime.now(datetime.UTC)

            # Update performance stats
            self._update_performance_stats(result)

            logger.info(
                f"Sync completed for {source_id}: {result.records_processed} processed, "
                f"{result.records_added} added, {result.records_updated} updated"
            )

        except asyncio.CancelledError:
            result.status = SyncStatus.CANCELLED
            result.end_time = datetime.now(datetime.UTC)
            logger.info(f"Sync cancelled for {source_id}")

        except Exception as e:
            result.status = SyncStatus.FAILED
            result.end_time = datetime.now(datetime.UTC)
            result.error_message = str(e)

            # Update failure count
            config.consecutive_failures += 1

            # Calculate exponential backoff for next sync
            backoff_delay = min(
                self.config["retry_delay_base"] * (2**config.consecutive_failures), self.config["max_retry_delay"]
            )
            config.next_sync = datetime.now(datetime.UTC) + timedelta(seconds=backoff_delay)

            logger.error(f"Sync failed for {source_id}: {e}")

        # Store result
        self.sync_results[source_id].append(result)

        # Keep only last 100 results per source
        if len(self.sync_results[source_id]) > 100:
            self.sync_results[source_id] = self.sync_results[source_id][-100:]

        # Emit sync event
        await self.sync_events.put(
            {
                "type": "sync_completed",
                "source_id": source_id,
                "status": result.status.value,
                "timestamp": datetime.now(datetime.UTC).isoformat(),
            }
        )

        return result

    async def _execute_sync_with_timeout(
        self, handler: Callable, config: SyncConfiguration, result: SyncResult
    ) -> None:
        """Execute sync handler with timeout."""
        try:
            # Call sync handler
            sync_data = await asyncio.wait_for(handler(config), timeout=config.timeout)

            # Process sync results
            if isinstance(sync_data, dict):
                result.records_processed = sync_data.get("processed", 0)
                result.records_added = sync_data.get("added", 0)
                result.records_updated = sync_data.get("updated", 0)
                result.records_failed = sync_data.get("failed", 0)
                result.data_quality_score = sync_data.get("quality_score", 1.0)
                result.performance_metrics = sync_data.get("performance", {})

            # Validate data quality
            if result.data_quality_score < self.config["data_quality_threshold"]:
                logger.warning(f"Low data quality for {config.source_id}: {result.data_quality_score}")

        except asyncio.TimeoutError:
            raise Exception(f"Sync timeout after {config.timeout} seconds")

    def _update_performance_stats(self, result: SyncResult) -> None:
        """Update global performance statistics."""
        self.performance_stats["total_syncs"] += 1

        if result.status == SyncStatus.COMPLETED:
            self.performance_stats["successful_syncs"] += 1
        else:
            self.performance_stats["failed_syncs"] += 1

        # Update averages
        total = self.performance_stats["total_syncs"]

        # Average sync time
        current_avg_time = self.performance_stats["avg_sync_time"]
        new_avg_time = ((current_avg_time * (total - 1)) + result.duration) / total
        self.performance_stats["avg_sync_time"] = new_avg_time

        # Average data quality
        current_avg_quality = self.performance_stats["data_quality_avg"]
        new_avg_quality = ((current_avg_quality * (total - 1)) + result.data_quality_score) / total
        self.performance_stats["data_quality_avg"] = new_avg_quality

    async def sync_all_sources(self, force: bool = False) -> Dict[str, SyncResult]:
        """Synchronize all enabled data sources."""
        results = {}

        # Get sources that need syncing
        sources_to_sync = []
        current_time = datetime.now(datetime.UTC)

        for source_id, config in self.sync_configs.items():
            if not config.enabled:
                continue

            if force or not config.next_sync or current_time >= config.next_sync:
                sources_to_sync.append((source_id, config.priority))

        # Sort by priority (higher priority first)
        sources_to_sync.sort(key=lambda x: x[1], reverse=True)

        logger.info(f"Syncing {len(sources_to_sync)} data sources")

        # Execute syncs with concurrency control
        semaphore = asyncio.Semaphore(self.config["max_parallel_syncs"])

        async def sync_with_semaphore(source_id: str):
            async with semaphore:
                return await self.sync_data_source(source_id, force)

        # Create sync tasks
        sync_tasks = [sync_with_semaphore(source_id) for source_id, _ in sources_to_sync]

        # Execute syncs
        if sync_tasks:
            completed_syncs = await asyncio.gather(*sync_tasks, return_exceptions=True)

            for i, result in enumerate(completed_syncs):
                source_id = sources_to_sync[i][0]
                if isinstance(result, Exception):
                    logger.error(f"Sync failed for {source_id}: {result}")
                    # Create failed result
                    failed_result = SyncResult(
                        source_id=source_id,
                        status=SyncStatus.FAILED,
                        start_time=datetime.now(datetime.UTC),
                        end_time=datetime.now(datetime.UTC),
                        error_message=str(result),
                    )
                    results[source_id] = failed_result
                else:
                    results[source_id] = result

        return results

    async def start_scheduler(self) -> None:
        """Start the automatic synchronization scheduler."""
        if self._running:
            return

        self._running = True
        self._shutdown_event.clear()

        logger.info("Starting data synchronization scheduler")

        try:
            while self._running:
                try:
                    # Check for pending syncs
                    await self.sync_all_sources()

                    # Wait for next scheduler interval or shutdown
                    try:
                        await asyncio.wait_for(self._shutdown_event.wait(), timeout=self.config["scheduler_interval"])
                        break  # Shutdown requested
                    except asyncio.TimeoutError:
                        continue  # Continue scheduling

                except Exception as e:
                    logger.error(f"Scheduler error: {e}")
                    await asyncio.sleep(60)  # Wait before retrying

        finally:
            self._running = False
            logger.info("Data synchronization scheduler stopped")

    async def stop_scheduler(self) -> None:
        """Stop the synchronization scheduler."""
        if not self._running:
            return

        logger.info("Stopping data synchronization scheduler")

        # Cancel all active syncs
        for source_id, task in list(self.active_syncs.items()):
            logger.info(f"Cancelling active sync for {source_id}")
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Signal shutdown
        self._shutdown_event.set()

        # Wait for scheduler to stop
        while self._running:
            await asyncio.sleep(0.1)

    def get_sync_status(self, source_id: Optional[str] = None) -> Dict[str, Any]:
        """Get synchronization status for sources."""
        if source_id:
            if source_id not in self.sync_configs:
                return {}

            config = self.sync_configs[source_id]
            recent_results = self.sync_results.get(source_id, [])
            last_result = recent_results[-1] if recent_results else None

            return {
                "source_id": source_id,
                "source_type": config.source_type.value,
                "enabled": config.enabled,
                "last_sync": config.last_sync.isoformat() if config.last_sync else None,
                "next_sync": config.next_sync.isoformat() if config.next_sync else None,
                "consecutive_failures": config.consecutive_failures,
                "is_active": source_id in self.active_syncs,
                "last_result": (
                    {
                        "status": last_result.status.value,
                        "records_processed": last_result.records_processed,
                        "duration": last_result.duration,
                        "success_rate": last_result.success_rate,
                    }
                    if last_result
                    else None
                ),
            }
        else:
            # Get status for all sources
            status = {
                "scheduler_running": self._running,
                "total_sources": len(self.sync_configs),
                "active_syncs": len(self.active_syncs),
                "performance_stats": self.performance_stats.copy(),
                "sources": {},
            }

            for sid in self.sync_configs:
                status["sources"][sid] = self.get_sync_status(sid)

            return status

    def get_sync_history(self, source_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get synchronization history for a data source."""
        if source_id not in self.sync_results:
            return []

        results = self.sync_results[source_id][-limit:]

        return [
            {
                "status": result.status.value,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat() if result.end_time else None,
                "duration": result.duration,
                "records_processed": result.records_processed,
                "records_added": result.records_added,
                "records_updated": result.records_updated,
                "records_failed": result.records_failed,
                "success_rate": result.success_rate,
                "data_quality_score": result.data_quality_score,
                "error_message": result.error_message,
            }
            for result in results
        ]

    async def force_sync(self, source_id: str) -> SyncResult:
        """Force immediate synchronization of a data source."""
        return await self.sync_data_source(source_id, force=True)

    def pause_source(self, source_id: str) -> bool:
        """Pause synchronization for a data source."""
        if source_id not in self.sync_configs:
            return False

        self.sync_configs[source_id].enabled = False

        # Cancel active sync if running
        if source_id in self.active_syncs:
            self.active_syncs[source_id].cancel()

        logger.info(f"Paused synchronization for {source_id}")
        return True

    def resume_source(self, source_id: str) -> bool:
        """Resume synchronization for a data source."""
        if source_id not in self.sync_configs:
            return False

        self.sync_configs[source_id].enabled = True

        # Reset next sync time
        config = self.sync_configs[source_id]
        config.next_sync = datetime.now(datetime.UTC)

        logger.info(f"Resumed synchronization for {source_id}")
        return True

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get detailed performance metrics."""
        metrics = {
            "global_stats": self.performance_stats.copy(),
            "source_metrics": {},
            "system_metrics": {
                "active_syncs": len(self.active_syncs),
                "total_sources": len(self.sync_configs),
                "enabled_sources": sum(1 for config in self.sync_configs.values() if config.enabled),
                "scheduler_running": self._running,
            },
        }

        # Calculate per-source metrics
        for source_id, results in self.sync_results.items():
            if not results:
                continue

            recent_results = results[-10:]  # Last 10 syncs

            metrics["source_metrics"][source_id] = {
                "total_syncs": len(results),
                "recent_success_rate": sum(1 for r in recent_results if r.status == SyncStatus.COMPLETED)
                / len(recent_results),
                "avg_duration": sum(r.duration for r in recent_results) / len(recent_results),
                "avg_records_processed": sum(r.records_processed for r in recent_results) / len(recent_results),
                "avg_data_quality": sum(r.data_quality_score for r in recent_results) / len(recent_results),
                "last_sync": recent_results[-1].start_time.isoformat() if recent_results else None,
            }

        return metrics

    async def cleanup_old_results(self, days: int = 30) -> int:
        """Clean up old synchronization results."""
        cutoff_date = datetime.now(datetime.UTC) - timedelta(days=days)
        cleaned_count = 0

        for source_id in self.sync_results:
            original_count = len(self.sync_results[source_id])
            self.sync_results[source_id] = [
                result for result in self.sync_results[source_id] if result.start_time > cutoff_date
            ]
            cleaned_count += original_count - len(self.sync_results[source_id])

        logger.info(f"Cleaned up {cleaned_count} old sync results")
        return cleaned_count
