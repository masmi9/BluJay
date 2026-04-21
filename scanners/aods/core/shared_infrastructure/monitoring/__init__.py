#!/usr/bin/env python3
"""
AODS Unified Monitoring Framework

Provides component health monitoring for AODS infrastructure.

Key Components:
- HealthChecker: Component health assessment and validation

Usage:
    from core.shared_infrastructure.monitoring import get_health_checker

    health = get_health_checker()
    health_status = health.check_component_health('analysis_engine')
"""

from .health_checker import HealthChecker, HealthStatus, ComponentHealth, HealthCheckResult, get_health_checker

__all__ = [
    "HealthChecker",
    "HealthStatus",
    "ComponentHealth",
    "HealthCheckResult",
    "get_health_checker",
]

__version__ = "1.0.0"
__author__ = "AODS Development Team"
__description__ = "Unified monitoring framework for AODS security analysis platform"
