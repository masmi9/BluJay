#!/usr/bin/env python3
"""
Multi-Tenant Boundary Manager
============================

Unified multi-tenant boundary management system for AODS that provides:
- Tenant-aware paths and file isolation
- Resource allocation and quotas
- Security boundaries and access controls
- Audit logging and compliance tracking
- Integration with canonical architecture components

This system ensures complete tenant separation while maintaining performance
and providing a clean API for all AODS components.
"""

import logging
import os
import tempfile
import uuid
import time
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import threading

# Core AODS imports
try:
    from core.finding.canonical_schema_v1 import CanonicalFinding

    CANONICAL_SCHEMA_AVAILABLE = True
except ImportError:
    CANONICAL_SCHEMA_AVAILABLE = False

logger = logging.getLogger(__name__)


class TenantTier(Enum):
    """Tenant subscription tiers with different resource allocations."""

    FREE = "free"
    BASIC = "basic"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    UNLIMITED = "unlimited"


class IsolationLevel(Enum):
    """Levels of tenant isolation."""

    SHARED = "shared"  # Shared resources, logical separation
    ISOLATED = "isolated"  # Dedicated resources, process separation
    STRICT = "strict"  # Full isolation with sandboxing


class AccessLevel(Enum):
    """Tenant access levels for different operations."""

    READ_ONLY = "read_only"
    STANDARD = "standard"
    ELEVATED = "elevated"
    ADMIN = "admin"


@dataclass
class ResourceQuota:
    """Resource quotas for a tenant."""

    # Compute resources
    max_cpu_cores: float = 2.0
    max_memory_mb: float = 2048.0
    max_disk_gb: float = 10.0
    max_network_mbps: float = 100.0
    max_gpu_units: float = 0.0

    # AODS-specific limits
    max_concurrent_scans: int = 2
    max_apk_size_mb: float = 100.0
    max_scan_duration_minutes: int = 60
    max_findings_per_scan: int = 1000
    max_evidence_size_mb: float = 50.0

    # Storage limits
    max_storage_gb: float = 5.0
    max_cache_size_mb: float = 500.0
    max_log_retention_days: int = 30

    # API limits
    max_api_calls_per_hour: int = 1000
    max_api_calls_per_day: int = 10000

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class TenantConfiguration:
    """Complete tenant configuration."""

    tenant_id: str
    tenant_name: str
    tier: TenantTier
    isolation_level: IsolationLevel
    access_level: AccessLevel

    # Resource management
    resource_quota: ResourceQuota = field(default_factory=ResourceQuota)

    # Security settings
    enable_audit_logging: bool = True
    enable_data_encryption: bool = True
    enable_network_isolation: bool = False
    allowed_ip_ranges: List[str] = field(default_factory=list)

    # Operational settings
    created_at: datetime = field(default_factory=datetime.now)
    last_activity: Optional[datetime] = None
    is_active: bool = True

    # Custom settings
    custom_settings: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data["tier"] = self.tier.value
        data["isolation_level"] = self.isolation_level.value
        data["access_level"] = self.access_level.value
        data["created_at"] = self.created_at.isoformat()
        data["last_activity"] = self.last_activity.isoformat() if self.last_activity else None
        return data


@dataclass
class TenantContext:
    """Runtime context for tenant operations."""

    tenant_id: str
    session_id: str
    user_id: Optional[str] = None
    request_id: Optional[str] = None

    # Paths and isolation
    base_path: Optional[Path] = None
    temp_path: Optional[Path] = None
    cache_path: Optional[Path] = None
    output_path: Optional[Path] = None

    # Resource tracking
    allocated_resources: Dict[str, float] = field(default_factory=dict)
    current_usage: Dict[str, float] = field(default_factory=dict)

    # Security context
    access_token: Optional[str] = None
    permissions: Set[str] = field(default_factory=set)

    # Audit trail
    created_at: datetime = field(default_factory=datetime.now)
    operations: List[Dict[str, Any]] = field(default_factory=list)

    def add_operation(self, operation: str, details: Dict[str, Any] = None):
        """Add an operation to the audit trail."""
        self.operations.append(
            {"operation": operation, "timestamp": datetime.now().isoformat(), "details": details or {}}
        )


@dataclass
class ResourceUsage:
    """Current resource usage for a tenant."""

    tenant_id: str
    timestamp: datetime

    # Compute usage
    cpu_usage_percent: float = 0.0
    memory_usage_mb: float = 0.0
    disk_usage_gb: float = 0.0
    network_usage_mbps: float = 0.0

    # AODS-specific usage
    active_scans: int = 0
    total_findings: int = 0
    cache_size_mb: float = 0.0

    # API usage
    api_calls_last_hour: int = 0
    api_calls_today: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


class TenantPathManager:
    """Manages tenant-specific file paths and isolation."""

    def __init__(self, base_directory: str = None):
        """Initialize path manager."""
        if base_directory is None:
            base_directory = os.path.join(tempfile.gettempdir(), "aods_tenants")
        self.base_directory = Path(base_directory)
        self.base_directory.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # Path templates
        self.path_templates = {
            "tenant_root": "{base}/{tenant_id}",
            "scans": "{tenant_root}/scans",
            "cache": "{tenant_root}/cache",
            "temp": "{tenant_root}/temp",
            "outputs": "{tenant_root}/outputs",
            "logs": "{tenant_root}/logs",
            "evidence": "{tenant_root}/evidence",
            "reports": "{tenant_root}/reports",
        }

    def get_tenant_path(self, tenant_id: str, path_type: str = "tenant_root") -> Path:
        """Get tenant-specific path."""
        if path_type not in self.path_templates:
            raise ValueError(f"Unknown path type: {path_type}")

        template = self.path_templates[path_type]
        tenant_root = self.base_directory / tenant_id

        path_str = template.format(base=self.base_directory, tenant_id=tenant_id, tenant_root=tenant_root)

        path = Path(path_str)
        path.mkdir(parents=True, exist_ok=True)

        return path

    def create_tenant_structure(self, tenant_id: str) -> Dict[str, Path]:
        """Create complete directory structure for tenant."""
        paths = {}

        for path_type in self.path_templates.keys():
            paths[path_type] = self.get_tenant_path(tenant_id, path_type)

        # Set appropriate permissions
        tenant_root = paths["tenant_root"]
        os.chmod(tenant_root, 0o750)  # Owner read/write/execute, group read/execute

        self.logger.info(f"Created tenant directory structure for {tenant_id}")
        return paths

    def cleanup_tenant_data(self, tenant_id: str, older_than_days: int = 30) -> bool:
        """Clean up old tenant data."""
        try:
            tenant_root = self.get_tenant_path(tenant_id, "tenant_root")
            cutoff_time = time.time() - (older_than_days * 24 * 3600)

            cleaned_files = 0
            for root, dirs, files in os.walk(tenant_root):
                for file in files:
                    file_path = Path(root) / file
                    if file_path.stat().st_mtime < cutoff_time:
                        file_path.unlink()
                        cleaned_files += 1

            self.logger.info(f"Cleaned {cleaned_files} old files for tenant {tenant_id}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to cleanup tenant data for {tenant_id}: {e}")
            return False

    def get_tenant_disk_usage(self, tenant_id: str) -> float:
        """Get total disk usage for tenant in GB."""
        try:
            tenant_root = self.get_tenant_path(tenant_id, "tenant_root")
            total_size = 0

            for root, dirs, files in os.walk(tenant_root):
                for file in files:
                    file_path = Path(root) / file
                    total_size += file_path.stat().st_size

            return total_size / (1024**3)  # Convert to GB

        except Exception as e:
            self.logger.error(f"Failed to calculate disk usage for tenant {tenant_id}: {e}")
            return 0.0


class TenantResourceMonitor:
    """Monitors and enforces tenant resource usage."""

    def __init__(self):
        """Initialize resource monitor."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.usage_history: Dict[str, List[ResourceUsage]] = {}
        self.active_contexts: Dict[str, TenantContext] = {}
        self._lock = threading.RLock()

    def track_resource_usage(self, tenant_id: str, usage: ResourceUsage) -> None:
        """Track resource usage for a tenant."""
        with self._lock:
            if tenant_id not in self.usage_history:
                self.usage_history[tenant_id] = []

            self.usage_history[tenant_id].append(usage)

            # Keep only last 24 hours of data
            cutoff_time = datetime.now() - timedelta(hours=24)
            self.usage_history[tenant_id] = [u for u in self.usage_history[tenant_id] if u.timestamp > cutoff_time]

    def check_resource_limits(self, tenant_id: str, config: TenantConfiguration) -> Dict[str, bool]:
        """Check if tenant is within resource limits."""
        if tenant_id not in self.usage_history:
            return {"within_limits": True}

        recent_usage = self.usage_history[tenant_id]
        if not recent_usage:
            return {"within_limits": True}

        latest_usage = recent_usage[-1]
        quota = config.resource_quota

        checks = {
            "cpu_within_limits": latest_usage.cpu_usage_percent <= (quota.max_cpu_cores * 100),
            "memory_within_limits": latest_usage.memory_usage_mb <= quota.max_memory_mb,
            "disk_within_limits": latest_usage.disk_usage_gb <= quota.max_disk_gb,
            "network_within_limits": latest_usage.network_usage_mbps <= quota.max_network_mbps,
            "scans_within_limits": latest_usage.active_scans <= quota.max_concurrent_scans,
            "api_calls_within_limits": latest_usage.api_calls_last_hour <= quota.max_api_calls_per_hour,
        }

        checks["within_limits"] = all(checks.values())
        return checks

    def get_resource_utilization(self, tenant_id: str) -> Dict[str, float]:
        """Get current resource utilization percentages."""
        if tenant_id not in self.usage_history or not self.usage_history[tenant_id]:
            return {}

        latest_usage = self.usage_history[tenant_id][-1]

        return {
            "cpu_utilization": latest_usage.cpu_usage_percent,
            "memory_utilization_mb": latest_usage.memory_usage_mb,
            "disk_utilization_gb": latest_usage.disk_usage_gb,
            "network_utilization_mbps": latest_usage.network_usage_mbps,
            "active_scans": latest_usage.active_scans,
            "api_calls_per_hour": latest_usage.api_calls_last_hour,
        }


class TenantAuditLogger:
    """Handles audit logging for tenant operations."""

    def __init__(self, log_directory: str = None):
        """Initialize audit logger."""
        if log_directory is None:
            log_directory = os.path.join(tempfile.gettempdir(), "aods_tenant_logs")
        self.log_directory = Path(log_directory)
        self.log_directory.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def log_tenant_operation(
        self, tenant_id: str, operation: str, details: Dict[str, Any], user_id: str = None
    ) -> None:
        """Log a tenant operation for audit purposes."""
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "tenant_id": tenant_id,
            "user_id": user_id,
            "operation": operation,
            "details": details,
            "session_id": details.get("session_id"),
            "request_id": details.get("request_id"),
        }

        # Write to tenant-specific log file
        log_file = self.log_directory / f"tenant_{tenant_id}_audit.log"

        try:
            with open(log_file, "a") as f:
                f.write(json.dumps(audit_entry) + "\n")

        except Exception as e:
            self.logger.error(f"Failed to write audit log for tenant {tenant_id}: {e}")

    def get_audit_trail(
        self, tenant_id: str, start_time: datetime = None, end_time: datetime = None
    ) -> List[Dict[str, Any]]:
        """Get audit trail for a tenant."""
        log_file = self.log_directory / f"tenant_{tenant_id}_audit.log"

        if not log_file.exists():
            return []

        audit_entries = []

        try:
            with open(log_file, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        entry_time = datetime.fromisoformat(entry["timestamp"])

                        # Filter by time range if specified
                        if start_time and entry_time < start_time:
                            continue
                        if end_time and entry_time > end_time:
                            continue

                        audit_entries.append(entry)

                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue

        except Exception as e:
            self.logger.error(f"Failed to read audit log for tenant {tenant_id}: {e}")

        return audit_entries


class MultiTenantBoundaryManager:
    """
    Main multi-tenant boundary management system.

    Provides unified tenant isolation, resource management, and security
    boundaries for all AODS operations.
    """

    def __init__(self, base_directory: str = None, log_directory: str = None):
        """Initialize boundary manager."""
        if base_directory is None:
            base_directory = os.path.join(tempfile.gettempdir(), "aods_tenants")
        if log_directory is None:
            log_directory = os.path.join(tempfile.gettempdir(), "aods_tenant_logs")
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # Initialize components
        self.path_manager = TenantPathManager(base_directory)
        self.resource_monitor = TenantResourceMonitor()
        self.audit_logger = TenantAuditLogger(log_directory)

        # Tenant registry
        self.tenant_configs: Dict[str, TenantConfiguration] = {}
        self.active_contexts: Dict[str, TenantContext] = {}

        # Thread safety
        self._lock = threading.RLock()

        # Load default tier configurations
        self._initialize_default_tiers()

        self.logger.info("Multi-Tenant Boundary Manager initialized")

    def _initialize_default_tiers(self) -> None:
        """Initialize default tier configurations."""
        self.tier_defaults = {
            TenantTier.FREE: ResourceQuota(
                max_cpu_cores=1.0,
                max_memory_mb=1024.0,
                max_disk_gb=2.0,
                max_concurrent_scans=1,
                max_apk_size_mb=50.0,
                max_scan_duration_minutes=30,
                max_findings_per_scan=100,
                max_api_calls_per_hour=100,
            ),
            TenantTier.BASIC: ResourceQuota(
                max_cpu_cores=2.0,
                max_memory_mb=2048.0,
                max_disk_gb=5.0,
                max_concurrent_scans=2,
                max_apk_size_mb=100.0,
                max_scan_duration_minutes=60,
                max_findings_per_scan=500,
                max_api_calls_per_hour=500,
            ),
            TenantTier.PROFESSIONAL: ResourceQuota(
                max_cpu_cores=4.0,
                max_memory_mb=4096.0,
                max_disk_gb=20.0,
                max_concurrent_scans=5,
                max_apk_size_mb=200.0,
                max_scan_duration_minutes=120,
                max_findings_per_scan=2000,
                max_api_calls_per_hour=2000,
            ),
            TenantTier.ENTERPRISE: ResourceQuota(
                max_cpu_cores=8.0,
                max_memory_mb=8192.0,
                max_disk_gb=100.0,
                max_concurrent_scans=10,
                max_apk_size_mb=500.0,
                max_scan_duration_minutes=240,
                max_findings_per_scan=10000,
                max_api_calls_per_hour=10000,
            ),
            TenantTier.UNLIMITED: ResourceQuota(
                max_cpu_cores=16.0,
                max_memory_mb=16384.0,
                max_disk_gb=500.0,
                max_concurrent_scans=50,
                max_apk_size_mb=1000.0,
                max_scan_duration_minutes=480,
                max_findings_per_scan=50000,
                max_api_calls_per_hour=50000,
            ),
        }

    def create_tenant(
        self,
        tenant_name: str,
        tier: TenantTier,
        isolation_level: IsolationLevel = IsolationLevel.ISOLATED,
        access_level: AccessLevel = AccessLevel.STANDARD,
        custom_quota: Optional[ResourceQuota] = None,
    ) -> TenantConfiguration:
        """Create a new tenant with proper boundaries."""
        tenant_id = str(uuid.uuid4())

        # Get resource quota
        resource_quota = custom_quota or self.tier_defaults[tier]

        # Create tenant configuration
        config = TenantConfiguration(
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            tier=tier,
            isolation_level=isolation_level,
            access_level=access_level,
            resource_quota=resource_quota,
        )

        with self._lock:
            # Create directory structure
            paths = self.path_manager.create_tenant_structure(tenant_id)

            # Register tenant
            self.tenant_configs[tenant_id] = config

            # Log tenant creation
            self.audit_logger.log_tenant_operation(
                tenant_id=tenant_id,
                operation="tenant_created",
                details={
                    "tenant_name": tenant_name,
                    "tier": tier.value,
                    "isolation_level": isolation_level.value,
                    "access_level": access_level.value,
                    "paths": {k: str(v) for k, v in paths.items()},
                },
            )

        self.logger.info(f"Created tenant: {tenant_name} ({tier.value}) - ID: {tenant_id}")
        return config

    def create_tenant_context(self, tenant_id: str, user_id: str = None, request_id: str = None) -> TenantContext:
        """Create a runtime context for tenant operations."""
        if tenant_id not in self.tenant_configs:
            raise ValueError(f"Unknown tenant: {tenant_id}")

        session_id = str(uuid.uuid4())

        # Get tenant paths
        paths = {
            "base_path": self.path_manager.get_tenant_path(tenant_id, "tenant_root"),
            "temp_path": self.path_manager.get_tenant_path(tenant_id, "temp"),
            "cache_path": self.path_manager.get_tenant_path(tenant_id, "cache"),
            "output_path": self.path_manager.get_tenant_path(tenant_id, "outputs"),
        }

        # Create context
        context = TenantContext(
            tenant_id=tenant_id, session_id=session_id, user_id=user_id, request_id=request_id, **paths
        )

        # Set permissions based on access level
        config = self.tenant_configs[tenant_id]
        if config.access_level == AccessLevel.READ_ONLY:
            context.permissions = {"read"}
        elif config.access_level == AccessLevel.STANDARD:
            context.permissions = {"read", "write", "scan"}
        elif config.access_level == AccessLevel.ELEVATED:
            context.permissions = {"read", "write", "scan", "admin_read"}
        elif config.access_level == AccessLevel.ADMIN:
            context.permissions = {"read", "write", "scan", "admin_read", "admin_write"}

        with self._lock:
            self.active_contexts[session_id] = context

        # Log context creation
        self.audit_logger.log_tenant_operation(
            tenant_id=tenant_id,
            operation="context_created",
            details={
                "session_id": session_id,
                "user_id": user_id,
                "request_id": request_id,
                "permissions": list(context.permissions),
            },
            user_id=user_id,
        )

        return context

    def validate_tenant_access(self, context: TenantContext, operation: str, resource: str = None) -> bool:
        """Validate if tenant has access to perform operation."""
        tenant_id = context.tenant_id

        if tenant_id not in self.tenant_configs:
            return False

        config = self.tenant_configs[tenant_id]

        # Check if tenant is active
        if not config.is_active:
            return False

        # Check resource limits
        limits_check = self.resource_monitor.check_resource_limits(tenant_id, config)
        if not limits_check["within_limits"]:
            self.logger.warning(f"Tenant {tenant_id} exceeds resource limits")
            return False

        # Check permissions
        required_permissions = {
            "read": {"read"},
            "write": {"write"},
            "scan": {"scan"},
            "admin": {"admin_read", "admin_write"},
        }

        operation_type = operation.split("_")[0]  # e.g., 'scan_apk' -> 'scan'
        required = required_permissions.get(operation_type, {"read"})

        if not required.issubset(context.permissions):
            return False

        # Log access attempt
        context.add_operation(operation, {"resource": resource, "access_granted": True})

        return True

    def isolate_findings(self, context: TenantContext, findings: List[CanonicalFinding]) -> List[CanonicalFinding]:
        """Apply tenant-specific isolation to findings."""
        if not CANONICAL_SCHEMA_AVAILABLE:
            return findings

        tenant_id = context.tenant_id
        config = self.tenant_configs[tenant_id]

        # Apply tenant labeling
        isolated_findings = []
        for finding in findings:
            # Create a copy to avoid modifying original
            isolated_finding = CanonicalFinding(
                finding_id=finding.finding_id,
                title=finding.title,
                description=finding.description,
                category=finding.category,
                severity=finding.severity,
                confidence=finding.confidence,
                evidence=finding.evidence,
                remediation=finding.remediation,
                detector_name=finding.detector_name,
            )

            # Add tenant metadata
            isolated_finding.tenant_id = tenant_id
            isolated_finding.tenant_name = config.tenant_name
            isolated_finding.isolation_level = config.isolation_level.value

            # Apply access controls based on isolation level
            if config.isolation_level == IsolationLevel.STRICT:
                # In strict mode, sanitize sensitive information
                if hasattr(isolated_finding, "evidence"):
                    for evidence in isolated_finding.evidence:
                        if hasattr(evidence, "content"):
                            # Hash sensitive content for strict isolation
                            evidence.content = hashlib.sha256(evidence.content.encode()).hexdigest()[:16] + "..."

            isolated_findings.append(isolated_finding)

        # Log findings isolation
        context.add_operation(
            "isolate_findings", {"findings_count": len(findings), "isolation_level": config.isolation_level.value}
        )

        return isolated_findings

    def get_tenant_summary(self, tenant_id: str) -> Dict[str, Any]:
        """Get full tenant summary."""
        if tenant_id not in self.tenant_configs:
            return {}

        config = self.tenant_configs[tenant_id]

        # Get resource utilization
        utilization = self.resource_monitor.get_resource_utilization(tenant_id)

        # Get disk usage
        disk_usage = self.path_manager.get_tenant_disk_usage(tenant_id)

        # Get recent audit entries
        recent_audit = self.audit_logger.get_audit_trail(tenant_id, start_time=datetime.now() - timedelta(hours=24))

        return {
            "tenant_id": tenant_id,
            "tenant_name": config.tenant_name,
            "tier": config.tier.value,
            "isolation_level": config.isolation_level.value,
            "access_level": config.access_level.value,
            "is_active": config.is_active,
            "created_at": config.created_at.isoformat(),
            "last_activity": config.last_activity.isoformat() if config.last_activity else None,
            "resource_quota": config.resource_quota.to_dict(),
            "current_utilization": utilization,
            "disk_usage_gb": disk_usage,
            "recent_operations": len(recent_audit),
            "active_sessions": len([ctx for ctx in self.active_contexts.values() if ctx.tenant_id == tenant_id]),
        }

    def cleanup_tenant_resources(self, tenant_id: str, cleanup_data: bool = False) -> bool:
        """Clean up tenant resources."""
        try:
            # Remove active contexts
            with self._lock:
                contexts_to_remove = [
                    session_id for session_id, ctx in self.active_contexts.items() if ctx.tenant_id == tenant_id
                ]

                for session_id in contexts_to_remove:
                    del self.active_contexts[session_id]

            # Clean up old data if requested
            if cleanup_data:
                self.path_manager.cleanup_tenant_data(tenant_id)

            # Log cleanup
            self.audit_logger.log_tenant_operation(
                tenant_id=tenant_id,
                operation="tenant_cleanup",
                details={"cleanup_data": cleanup_data, "contexts_removed": len(contexts_to_remove)},
            )

            self.logger.info(f"Cleaned up resources for tenant {tenant_id}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to cleanup tenant {tenant_id}: {e}")
            return False

    def get_all_tenants(self) -> Dict[str, Dict[str, Any]]:
        """Get summary of all tenants."""
        return {tenant_id: self.get_tenant_summary(tenant_id) for tenant_id in self.tenant_configs.keys()}


# Convenience functions
def create_boundary_manager(
    base_directory: str = None, log_directory: str = None
) -> MultiTenantBoundaryManager:
    """Create and configure a boundary manager."""
    return MultiTenantBoundaryManager(base_directory, log_directory)


def get_default_tenant_config(tier: TenantTier = TenantTier.BASIC) -> TenantConfiguration:
    """Get a default tenant configuration for testing."""
    manager = create_boundary_manager()
    return manager.create_tenant(tenant_name=f"Default {tier.value.title()} Tenant", tier=tier)


# Export main components
__all__ = [
    "MultiTenantBoundaryManager",
    "TenantConfiguration",
    "TenantContext",
    "ResourceQuota",
    "ResourceUsage",
    "TenantTier",
    "IsolationLevel",
    "AccessLevel",
    "TenantPathManager",
    "TenantResourceMonitor",
    "TenantAuditLogger",
    "create_boundary_manager",
    "get_default_tenant_config",
]
