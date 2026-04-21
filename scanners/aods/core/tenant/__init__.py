#!/usr/bin/env python3
"""
AODS Multi-Tenant Package
=========================

Full multi-tenant boundary management system for AODS.

This package provides:
- Tenant isolation and boundary management
- Resource allocation and monitoring
- Security boundaries and access controls
- Audit logging and compliance tracking
- Integration with canonical architecture

Key Components:
- MultiTenantBoundaryManager: Main boundary management system
- TenantConfiguration: Tenant configuration and settings
- TenantContext: Runtime context for tenant operations
- ResourceQuota: Resource allocation and limits
- TenantPathManager: File system isolation
- TenantResourceMonitor: Resource usage tracking
- TenantAuditLogger: Audit and compliance logging
"""

from .boundary_manager import (
    MultiTenantBoundaryManager,
    TenantConfiguration,
    TenantContext,
    ResourceQuota,
    ResourceUsage,
    TenantTier,
    IsolationLevel,
    AccessLevel,
    TenantPathManager,
    TenantResourceMonitor,
    TenantAuditLogger,
    create_boundary_manager,
    get_default_tenant_config,
)

# Package metadata
__version__ = "1.0.0"
__author__ = "AODS Development Team"

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
