#!/usr/bin/env python3
"""
AODS External Data Pipeline Manager
==================================

Central coordination system for external data integration pipeline providing
unified management, orchestration, and monitoring of all external data sources.

Features:
- Unified pipeline orchestration and coordination
- Multi-source data synchronization management
- Real-time monitoring and health checks
- Performance optimization and resource management
- Data quality validation and governance
- Error handling and recovery mechanisms
- Integration with AODS core vulnerability detection
"""

import asyncio
import logging
from datetime import datetime, timedelta, UTC
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor

from .cve_nvd_client import CVENVDClient
from .vulnerability_database import VulnerabilityDatabase, VulnerabilityRecord
from .data_synchronizer import DataSynchronizer, SyncConfiguration, SyncResult, DataSourceType
from .threat_intel import ThreatIntelligenceProcessor, FeedConfiguration

logger = logging.getLogger(__name__)


class PipelineStatus(Enum):
    """Pipeline operational status."""

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    PAUSING = "pausing"
    PAUSED = "paused"
    ERROR = "error"
    RECOVERING = "recovering"


class HealthStatus(Enum):
    """Component health status."""

    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class PipelineConfiguration:
    """External data pipeline configuration."""

    # Core settings
    enabled: bool = True
    auto_start: bool = True
    sync_interval: int = 3600  # Global sync interval in seconds

    # Performance settings
    max_concurrent_syncs: int = 4
    batch_processing_size: int = 1000
    memory_threshold_mb: int = 1024
    cpu_threshold_percent: float = 80.0

    # Data quality settings
    quality_threshold: float = 0.8
    validation_enabled: bool = True
    data_retention_days: int = 365

    # Integration settings
    vulnerability_correlation: bool = True
    real_time_enrichment: bool = True
    intelligence_scoring: bool = True

    # Monitoring settings
    health_check_interval: int = 300  # 5 minutes
    metrics_collection: bool = True
    alerting_enabled: bool = True

    # Error handling
    max_retry_attempts: int = 3
    error_recovery_enabled: bool = True
    circuit_breaker_threshold: int = 5


@dataclass
class ComponentHealth:
    """Health status of pipeline components."""

    component: str
    status: HealthStatus
    last_check: datetime
    metrics: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class PipelineMetrics:
    """Full pipeline performance metrics."""

    # Processing metrics
    total_records_processed: int = 0
    records_per_minute: float = 0.0
    data_quality_average: float = 0.0
    error_rate: float = 0.0

    # Performance metrics
    avg_processing_time: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0

    # Source metrics
    active_sources: int = 0
    failed_sources: int = 0
    last_sync_time: Optional[datetime] = None

    # Intelligence metrics
    threat_intelligence_records: int = 0
    vulnerability_records: int = 0
    iocs_processed: int = 0
    correlations_found: int = 0


class ExternalDataPipelineManager:
    """
    Full external data pipeline orchestrator.

    Provides unified management and coordination of all external data sources
    with advanced monitoring, performance optimization, and integration capabilities.
    """

    def __init__(self, config: Optional[PipelineConfiguration] = None):
        """Initialize external data pipeline manager."""
        self.config = config or PipelineConfiguration()

        # Pipeline status
        self.status = PipelineStatus.STOPPED
        self.start_time: Optional[datetime] = None

        # Core components
        self.cve_client: Optional[CVENVDClient] = None
        self.vulnerability_db: Optional[VulnerabilityDatabase] = None
        self.data_synchronizer: Optional[DataSynchronizer] = None
        self.threat_intel: Optional[ThreatIntelligenceProcessor] = None

        # Component health tracking
        self.component_health: Dict[str, ComponentHealth] = {}

        # Pipeline metrics
        self.metrics = PipelineMetrics()
        self.metrics_history: List[Tuple[datetime, PipelineMetrics]] = []

        # Event system
        self.event_queue = asyncio.Queue()
        self.event_handlers: Dict[str, List[Callable]] = {}

        # Background tasks
        self.background_tasks: List[asyncio.Task] = []

        # Thread pool for CPU-intensive operations
        self.executor = ThreadPoolExecutor(max_workers=4)

        # Control flags
        self._shutdown_event = asyncio.Event()
        self._health_check_task: Optional[asyncio.Task] = None
        self._metrics_task: Optional[asyncio.Task] = None

        logger.info("External Data Pipeline Manager initialized")

    async def initialize_components(self, component_configs: Dict[str, Any] = None) -> None:
        """Initialize all pipeline components."""
        logger.info("Initializing external data pipeline components")

        configs = component_configs or {}

        try:
            # Initialize vulnerability database
            self.vulnerability_db = VulnerabilityDatabase(
                configs.get("vulnerability_db", {}).get("db_path", "data/vulnerability_database.db")
            )
            self._update_component_health("vulnerability_database", HealthStatus.HEALTHY)

            # Initialize CVE/NVD client
            self.cve_client = CVENVDClient(configs.get("cve_nvd", {}))
            self._update_component_health("cve_nvd_client", HealthStatus.HEALTHY)

            # Initialize data synchronizer
            self.data_synchronizer = DataSynchronizer(configs.get("data_synchronizer", {}))
            self._setup_synchronizer_handlers()
            self._update_component_health("data_synchronizer", HealthStatus.HEALTHY)

            # Initialize threat intelligence processor
            self.threat_intel = ThreatIntelligenceProcessor(configs.get("threat_intel", {}))
            self._setup_threat_intel_feeds(configs.get("threat_feeds", []))
            self._update_component_health("threat_intelligence", HealthStatus.HEALTHY)

            # Set up data synchronization sources
            await self._setup_data_sources(configs.get("data_sources", []))

            logger.info("All pipeline components initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            self.status = PipelineStatus.ERROR
            raise

    def _setup_synchronizer_handlers(self) -> None:
        """Set up data synchronization handlers."""
        if not self.data_synchronizer:
            return

        # Register CVE/NVD sync handler
        async def cve_nvd_sync_handler(config: SyncConfiguration) -> Dict[str, Any]:
            if not self.cve_client:
                raise Exception("CVE/NVD client not initialized")

            # Determine sync period based on config
            days = config.custom_params.get("sync_days", 30)
            stats = await self.cve_client.sync_cve_database(days)

            # Convert CVE data to vulnerability records and store
            recent_cves = await self.cve_client.fetch_recent_cves(days=7)  # Get recent for storage
            stored_count = 0

            for cve_data in recent_cves:
                # Convert to VulnerabilityRecord
                vuln_record = VulnerabilityRecord(
                    id=cve_data.cve_id,
                    source="CVE/NVD",
                    title=f"CVE {cve_data.cve_id}",
                    description=cve_data.description,
                    severity=cve_data.severity,
                    cvss_score=cve_data.cvss_score,
                    cvss_vector=cve_data.cvss_vector,
                    published_date=cve_data.published_date,
                    modified_date=cve_data.modified_date,
                    affected_products=[
                        {"name": prod.get("cpe", ""), "vendor": "", "version_range": ""}
                        for prod in cve_data.affected_products
                    ],
                    references=cve_data.references,
                    cwe_ids=cve_data.cwe_ids,
                    tags=["cve", "nvd"],
                    exploit_available=cve_data.exploit_available,
                    patch_available=cve_data.patch_available,
                    threat_intelligence=cve_data.threat_intelligence,
                )

                if self.vulnerability_db and self.vulnerability_db.store_vulnerability(vuln_record):
                    stored_count += 1

            return {
                "processed": stats.total_processed,
                "added": stats.new_cves,
                "updated": stats.updated_cves,
                "failed": stats.errors,
                "stored_in_db": stored_count,
                "quality_score": 0.95,  # CVE/NVD has high quality
                "performance": {
                    "sync_time": stats.processing_time,
                    "records_per_second": stats.total_processed / max(stats.processing_time, 1),
                },
            }

        # Register threat intelligence sync handler
        async def threat_intel_sync_handler(config: SyncConfiguration) -> Dict[str, Any]:
            if not self.threat_intel:
                raise Exception("Threat intelligence processor not initialized")

            # Update all threat intelligence feeds
            results = await self.threat_intel.update_all_feeds()

            total_processed = sum(r.get("records_processed", 0) for r in results.values())
            total_errors = sum(r.get("errors", 0) for r in results.values())

            # Store threat intelligence as vulnerability records
            stored_count = 0
            if self.vulnerability_db:
                for intel in self.threat_intel.intelligence_cache.values():
                    # Convert to VulnerabilityRecord
                    vuln_record = VulnerabilityRecord(
                        id=f"INTEL-{intel.id}",
                        source=f"ThreatIntel-{intel.source}",
                        title=intel.title,
                        description=intel.description,
                        severity=intel.severity,
                        cvss_score=intel.risk_score,
                        cvss_vector="",
                        published_date=intel.published_date,
                        modified_date=intel.modified_date,
                        tags=intel.tags + ["threat_intelligence"],
                        threat_intelligence={
                            "confidence": intel.confidence,
                            "threat_type": intel.threat_type.value,
                            "iocs": intel.iocs,
                            "mitre_techniques": intel.mitre_techniques,
                            "threat_actors": intel.threat_actors,
                            "campaigns": intel.campaigns,
                        },
                    )

                    if self.vulnerability_db.store_vulnerability(vuln_record):
                        stored_count += 1

            success_rate = (total_processed - total_errors) / max(total_processed, 1)

            return {
                "processed": total_processed,
                "added": stored_count,
                "updated": 0,
                "failed": total_errors,
                "quality_score": success_rate,
                "performance": {"feeds_updated": len(results), "success_rate": success_rate},
            }

        # Register handlers
        self.data_synchronizer.register_sync_handler(DataSourceType.CVE_NVD, cve_nvd_sync_handler)
        self.data_synchronizer.register_sync_handler(DataSourceType.THREAT_INTEL, threat_intel_sync_handler)

    def _setup_threat_intel_feeds(self, feed_configs: List[Dict[str, Any]]) -> None:
        """Set up threat intelligence feeds."""
        if not self.threat_intel:
            return

        for feed_config in feed_configs:
            try:
                from .threat_intel import FeedFormat

                # Convert config to FeedConfiguration
                feed = FeedConfiguration(
                    feed_id=feed_config["id"],
                    name=feed_config["name"],
                    url=feed_config["url"],
                    format=FeedFormat(feed_config.get("format", "json")),
                    enabled=feed_config.get("enabled", True),
                    update_interval=feed_config.get("update_interval", 3600),
                    authentication=feed_config.get("authentication"),
                    headers=feed_config.get("headers", {}),
                    reliability_score=feed_config.get("reliability_score", 1.0),
                )

                self.threat_intel.add_feed(feed)
                logger.info(f"Added threat intelligence feed: {feed.name}")

            except Exception as e:
                logger.error(f"Failed to add threat intelligence feed {feed_config.get('id', 'unknown')}: {e}")

    async def _setup_data_sources(self, source_configs: List[Dict[str, Any]]) -> None:
        """Set up data synchronization sources."""
        if not self.data_synchronizer:
            return

        for source_config in source_configs:
            try:
                # Convert config to SyncConfiguration
                sync_config = SyncConfiguration(
                    source_id=source_config["id"],
                    source_type=DataSourceType(source_config["type"]),
                    enabled=source_config.get("enabled", True),
                    sync_interval=source_config.get("sync_interval", self.config.sync_interval),
                    batch_size=source_config.get("batch_size", self.config.batch_processing_size),
                    max_retries=source_config.get("max_retries", self.config.max_retry_attempts),
                    timeout=source_config.get("timeout", 300),
                    priority=source_config.get("priority", 5),
                    custom_params=source_config.get("custom_params", {}),
                )

                self.data_synchronizer.add_data_source(sync_config)
                logger.info(f"Added data source: {sync_config.source_id}")

            except Exception as e:
                logger.error(f"Failed to add data source {source_config.get('id', 'unknown')}: {e}")

    def _update_component_health(
        self,
        component: str,
        status: HealthStatus,
        errors: List[str] = None,
        warnings: List[str] = None,
        metrics: Dict[str, Any] = None,
    ) -> None:
        """Update component health status."""
        self.component_health[component] = ComponentHealth(
            component=component,
            status=status,
            last_check=datetime.now(UTC),
            metrics=metrics or {},
            errors=errors or [],
            warnings=warnings or [],
        )

    async def start_pipeline(self) -> None:
        """Start the external data pipeline."""
        if self.status != PipelineStatus.STOPPED:
            logger.warning(f"Pipeline already running (status: {self.status.value})")
            return

        logger.info("Starting external data pipeline")
        self.status = PipelineStatus.STARTING

        try:
            # Verify components are initialized
            if not all([self.vulnerability_db, self.cve_client, self.data_synchronizer, self.threat_intel]):
                raise Exception("Pipeline components not properly initialized")

            # Start data synchronizer scheduler
            if self.data_synchronizer:
                asyncio.create_task(self.data_synchronizer.start_scheduler())

            # Start background monitoring tasks
            await self._start_background_tasks()

            self.status = PipelineStatus.RUNNING
            self.start_time = datetime.now(UTC)

            # Emit pipeline started event
            await self._emit_event(
                "pipeline_started",
                {"timestamp": self.start_time.isoformat(), "components": list(self.component_health.keys())},
            )

            logger.info("External data pipeline started successfully")

        except Exception as e:
            self.status = PipelineStatus.ERROR
            logger.error(f"Failed to start pipeline: {e}")
            raise

    async def stop_pipeline(self) -> None:
        """Stop the external data pipeline."""
        if self.status == PipelineStatus.STOPPED:
            return

        logger.info("Stopping external data pipeline")

        # Stop data synchronizer
        if self.data_synchronizer:
            await self.data_synchronizer.stop_scheduler()

        # Stop background tasks
        await self._stop_background_tasks()

        self.status = PipelineStatus.STOPPED

        # Emit pipeline stopped event
        await self._emit_event("pipeline_stopped", {"timestamp": datetime.now(UTC).isoformat()})

        logger.info("External data pipeline stopped")

    async def pause_pipeline(self) -> None:
        """Pause the external data pipeline."""
        if self.status != PipelineStatus.RUNNING:
            return

        logger.info("Pausing external data pipeline")
        self.status = PipelineStatus.PAUSING

        # Pause data synchronizer (stop scheduling new syncs)
        if self.data_synchronizer:
            for source_id in self.data_synchronizer.sync_configs:
                self.data_synchronizer.pause_source(source_id)

        self.status = PipelineStatus.PAUSED
        logger.info("External data pipeline paused")

    async def resume_pipeline(self) -> None:
        """Resume the external data pipeline."""
        if self.status != PipelineStatus.PAUSED:
            return

        logger.info("Resuming external data pipeline")

        # Resume data synchronizer
        if self.data_synchronizer:
            for source_id in self.data_synchronizer.sync_configs:
                self.data_synchronizer.resume_source(source_id)

        self.status = PipelineStatus.RUNNING
        logger.info("External data pipeline resumed")

    async def _start_background_tasks(self) -> None:
        """Start background monitoring and maintenance tasks."""
        # Health check task
        if self.config.health_check_interval > 0:
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            self.background_tasks.append(self._health_check_task)

        # Metrics collection task
        if self.config.metrics_collection:
            self._metrics_task = asyncio.create_task(self._metrics_collection_loop())
            self.background_tasks.append(self._metrics_task)

        # Event processing task
        event_task = asyncio.create_task(self._event_processing_loop())
        self.background_tasks.append(event_task)

    async def _stop_background_tasks(self) -> None:
        """Stop all background tasks."""
        # Signal shutdown
        self._shutdown_event.set()

        # Cancel all background tasks
        for task in self.background_tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        self.background_tasks.clear()
        self._shutdown_event.clear()

    async def _health_check_loop(self) -> None:
        """Background health check monitoring loop."""
        while not self._shutdown_event.is_set():
            try:
                await self._perform_health_checks()

                # Wait for next check or shutdown
                try:
                    await asyncio.wait_for(self._shutdown_event.wait(), timeout=self.config.health_check_interval)
                    break  # Shutdown requested
                except asyncio.TimeoutError:
                    continue

            except Exception as e:
                logger.error(f"Health check error: {e}")
                await asyncio.sleep(60)  # Wait before retrying

    async def _perform_health_checks(self) -> None:
        """Perform health checks on all components."""
        # Check vulnerability database
        if self.vulnerability_db:
            try:
                stats = self.vulnerability_db.get_database_statistics()
                if stats.get("total_vulnerabilities", 0) > 0:
                    self._update_component_health("vulnerability_database", HealthStatus.HEALTHY, metrics=stats)
                else:
                    self._update_component_health(
                        "vulnerability_database", HealthStatus.WARNING, warnings=["No vulnerabilities in database"]
                    )
            except Exception as e:
                self._update_component_health("vulnerability_database", HealthStatus.CRITICAL, errors=[str(e)])

        # Check CVE/NVD client
        if self.cve_client:
            try:
                stats = self.cve_client.get_database_stats()
                self._update_component_health("cve_nvd_client", HealthStatus.HEALTHY, metrics=stats)
            except Exception as e:
                self._update_component_health("cve_nvd_client", HealthStatus.CRITICAL, errors=[str(e)])

        # Check data synchronizer
        if self.data_synchronizer:
            try:
                status = self.data_synchronizer.get_sync_status()
                failed_sources = status.get("sources", {})
                critical_failures = sum(
                    1
                    for s in failed_sources.values()
                    if s.get("consecutive_failures", 0) > self.config.circuit_breaker_threshold
                )

                if critical_failures > 0:
                    self._update_component_health(
                        "data_synchronizer",
                        HealthStatus.CRITICAL,
                        errors=[f"{critical_failures} sources have critical failures"],
                    )
                elif status.get("active_syncs", 0) > 0:
                    self._update_component_health("data_synchronizer", HealthStatus.HEALTHY, metrics=status)
                else:
                    self._update_component_health(
                        "data_synchronizer", HealthStatus.WARNING, warnings=["No active synchronizations"]
                    )
            except Exception as e:
                self._update_component_health("data_synchronizer", HealthStatus.CRITICAL, errors=[str(e)])

        # Check threat intelligence processor
        if self.threat_intel:
            try:
                stats = self.threat_intel.get_statistics()
                self._update_component_health("threat_intelligence", HealthStatus.HEALTHY, metrics=stats)
            except Exception as e:
                self._update_component_health("threat_intelligence", HealthStatus.CRITICAL, errors=[str(e)])

    async def _metrics_collection_loop(self) -> None:
        """Background metrics collection loop."""
        while not self._shutdown_event.is_set():
            try:
                await self._collect_metrics()

                # Wait for next collection
                try:
                    await asyncio.wait_for(self._shutdown_event.wait(), timeout=60)  # Collect metrics every minute
                    break
                except asyncio.TimeoutError:
                    continue

            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(60)

    async def _collect_metrics(self) -> None:
        """Collect full pipeline metrics."""
        new_metrics = PipelineMetrics()

        # Collect vulnerability database metrics
        if self.vulnerability_db:
            try:
                db_stats = self.vulnerability_db.get_database_statistics()
                new_metrics.vulnerability_records = db_stats.get("total_vulnerabilities", 0)
            except Exception as e:
                logger.error(f"Failed to collect vulnerability DB metrics: {e}")

        # Collect threat intelligence metrics
        if self.threat_intel:
            try:
                intel_stats = self.threat_intel.get_statistics()
                new_metrics.threat_intelligence_records = intel_stats.get("cached_intelligence", 0)
                new_metrics.iocs_processed = intel_stats.get("indexed_iocs", 0)
            except Exception as e:
                logger.error(f"Failed to collect threat intelligence metrics: {e}")

        # Collect synchronizer metrics
        if self.data_synchronizer:
            try:
                sync_metrics = self.data_synchronizer.get_performance_metrics()
                global_stats = sync_metrics.get("global_stats", {})

                new_metrics.total_records_processed = global_stats.get("total_syncs", 0)
                new_metrics.avg_processing_time = global_stats.get("avg_sync_time", 0.0)
                new_metrics.data_quality_average = global_stats.get("data_quality_avg", 0.0)
                new_metrics.error_rate = global_stats.get("failed_syncs", 0) / max(
                    global_stats.get("total_syncs", 1), 1
                )

                system_metrics = sync_metrics.get("system_metrics", {})
                new_metrics.active_sources = system_metrics.get("enabled_sources", 0)
                new_metrics.failed_sources = system_metrics.get("total_sources", 0) - system_metrics.get(
                    "enabled_sources", 0
                )

            except Exception as e:
                logger.error(f"Failed to collect synchronizer metrics: {e}")

        # Calculate processing rate
        if len(self.metrics_history) > 0:
            last_metrics = self.metrics_history[-1][1]
            time_diff = (datetime.now(UTC) - self.metrics_history[-1][0]).total_seconds() / 60  # minutes

            if time_diff > 0:
                record_diff = new_metrics.total_records_processed - last_metrics.total_records_processed
                new_metrics.records_per_minute = record_diff / time_diff

        # Store current metrics
        self.metrics = new_metrics
        self.metrics_history.append((datetime.now(UTC), new_metrics))

        # Keep only last 24 hours of metrics
        cutoff_time = datetime.now(UTC) - timedelta(hours=24)
        self.metrics_history = [
            (timestamp, metrics) for timestamp, metrics in self.metrics_history if timestamp > cutoff_time
        ]

    async def _event_processing_loop(self) -> None:
        """Background event processing loop."""
        while not self._shutdown_event.is_set():
            try:
                # Wait for events with timeout
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                await self._process_event(event)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Event processing error: {e}")

    async def _process_event(self, event: Dict[str, Any]) -> None:
        """Process pipeline events."""
        event_type = event.get("type", "unknown")

        # Call registered event handlers
        handlers = self.event_handlers.get(event_type, [])
        for handler in handlers:
            try:
                await handler(event)
            except Exception as e:
                logger.error(f"Event handler error for {event_type}: {e}")

        # Built-in event processing
        if event_type == "sync_completed":
            # Update metrics based on sync results
            pass
        elif event_type == "component_error":
            # Handle component errors
            component = event.get("component")
            if component and self.config.error_recovery_enabled:
                await self._attempt_component_recovery(component)

    async def _attempt_component_recovery(self, component: str) -> None:
        """Attempt to recover a failed component."""
        logger.info(f"Attempting recovery for component: {component}")

        try:
            if component == "data_synchronizer" and self.data_synchronizer:
                # Restart synchronizer if it's stopped
                pass  # Implementation depends on specific requirements

            # Update health status
            self._update_component_health(component, HealthStatus.RECOVERING)

        except Exception as e:
            logger.error(f"Failed to recover component {component}: {e}")
            self._update_component_health(component, HealthStatus.CRITICAL, errors=[str(e)])

    async def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Emit pipeline event."""
        event = {"type": event_type, "timestamp": datetime.now(UTC).isoformat(), **data}

        await self.event_queue.put(event)

    def register_event_handler(self, event_type: str, handler: Callable) -> None:
        """Register event handler for specific event type."""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)

    async def force_sync_all(self) -> Dict[str, Any]:
        """Force immediate synchronization of all data sources."""
        if not self.data_synchronizer:
            raise Exception("Data synchronizer not initialized")

        logger.info("Forcing synchronization of all data sources")
        return await self.data_synchronizer.sync_all_sources(force=True)

    async def force_sync_source(self, source_id: str) -> SyncResult:
        """Force immediate synchronization of specific data source."""
        if not self.data_synchronizer:
            raise Exception("Data synchronizer not initialized")

        logger.info(f"Forcing synchronization of data source: {source_id}")
        return await self.data_synchronizer.force_sync(source_id)

    def get_pipeline_status(self) -> Dict[str, Any]:
        """Get full pipeline status."""
        uptime = None
        if self.start_time:
            uptime = (datetime.now(UTC) - self.start_time).total_seconds()

        return {
            "status": self.status.value,
            "uptime_seconds": uptime,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "components": {
                name: {
                    "status": health.status.value,
                    "last_check": health.last_check.isoformat(),
                    "errors": health.errors,
                    "warnings": health.warnings,
                    "metrics": health.metrics,
                }
                for name, health in self.component_health.items()
            },
            "metrics": {
                "total_records_processed": self.metrics.total_records_processed,
                "records_per_minute": self.metrics.records_per_minute,
                "data_quality_average": self.metrics.data_quality_average,
                "error_rate": self.metrics.error_rate,
                "active_sources": self.metrics.active_sources,
                "failed_sources": self.metrics.failed_sources,
                "vulnerability_records": self.metrics.vulnerability_records,
                "threat_intelligence_records": self.metrics.threat_intelligence_records,
                "iocs_processed": self.metrics.iocs_processed,
            },
            "configuration": {
                "enabled": self.config.enabled,
                "sync_interval": self.config.sync_interval,
                "max_concurrent_syncs": self.config.max_concurrent_syncs,
                "quality_threshold": self.config.quality_threshold,
                "vulnerability_correlation": self.config.vulnerability_correlation,
                "real_time_enrichment": self.config.real_time_enrichment,
            },
        }

    def get_metrics_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get metrics history for specified time period."""
        cutoff_time = datetime.now(UTC) - timedelta(hours=hours)

        return [
            {
                "timestamp": timestamp.isoformat(),
                "metrics": {
                    "total_records_processed": metrics.total_records_processed,
                    "records_per_minute": metrics.records_per_minute,
                    "data_quality_average": metrics.data_quality_average,
                    "error_rate": metrics.error_rate,
                    "vulnerability_records": metrics.vulnerability_records,
                    "threat_intelligence_records": metrics.threat_intelligence_records,
                    "iocs_processed": metrics.iocs_processed,
                },
            }
            for timestamp, metrics in self.metrics_history
            if timestamp > cutoff_time
        ]

    async def cleanup_old_data(self, days: int = None) -> Dict[str, int]:
        """Clean up old data across all components."""
        days = days or self.config.data_retention_days
        logger.info(f"Cleaning up data older than {days} days")

        cleanup_results = {}

        # Clean up vulnerability database
        if self.vulnerability_db:
            try:
                cleaned = self.vulnerability_db.cleanup_old_data(days)
                cleanup_results["vulnerability_database"] = cleaned
            except Exception as e:
                logger.error(f"Failed to cleanup vulnerability database: {e}")
                cleanup_results["vulnerability_database"] = 0

        # Clean up synchronizer results
        if self.data_synchronizer:
            try:
                cleaned = await self.data_synchronizer.cleanup_old_results(days)
                cleanup_results["sync_results"] = cleaned
            except Exception as e:
                logger.error(f"Failed to cleanup sync results: {e}")
                cleanup_results["sync_results"] = 0

        return cleanup_results

    async def optimize_performance(self) -> Dict[str, Any]:
        """Optimize pipeline performance."""
        logger.info("Optimizing pipeline performance")

        optimization_results = {}

        # Optimize vulnerability database
        if self.vulnerability_db:
            try:
                self.vulnerability_db.vacuum_database()
                optimization_results["vulnerability_database"] = "optimized"
            except Exception as e:
                logger.error(f"Failed to optimize vulnerability database: {e}")
                optimization_results["vulnerability_database"] = f"failed: {e}"

        return optimization_results
