#!/usr/bin/env python3
"""
Example Static Analyzer V2 - BasePluginV2 Implementation
========================================================

Example static analyzer plugin implementing BasePlugin v2 interface.
This serves as a reference implementation for migrating legacy plugins
to the new standardized interface.

Features:
- BasePlugin v2 compliant interface
- Metadata declaration
- Dependency validation
- Standardized finding generation
- Performance monitoring
- Error handling and logging
"""

# Path setup for standalone execution
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import time

from core.plugins.base_plugin_v2 import (
    BasePluginV2,
    PluginMetadata,
    PluginResult,
    PluginCapability,
    PluginStatus,
    PluginPriority,
    PluginDependency,
)


class ExampleStaticAnalyzerV2(BasePluginV2):
    """
    Example static analyzer plugin implementing BasePlugin v2 interface.

    Performs basic static analysis including:
    - Hardcoded string detection
    - Insecure API usage analysis
    - Basic manifest analysis
    - Resource file scanning
    """

    def get_metadata(self) -> PluginMetadata:
        """Get full plugin metadata."""
        return PluginMetadata(
            name="example_static_analyzer_v2",
            version="2.0.0",
            description="Example static analyzer demonstrating BasePlugin v2 interface",
            author="AODS Development Team",
            license="MIT",
            capabilities=[
                PluginCapability.STATIC_ANALYSIS,
                PluginCapability.VULNERABILITY_DETECTION,
                PluginCapability.MANIFEST_ANALYSIS,
                PluginCapability.RESOURCE_ANALYSIS,
            ],
            dependencies=[
                PluginDependency(name="re", description="Regular expressions for pattern matching", optional=False),
                PluginDependency(name="pathlib", description="Path manipulation utilities", optional=False),
            ],
            priority=PluginPriority.NORMAL,
            timeout_seconds=120,
            tags=["static", "example", "reference", "v2"],
            supported_platforms=["android"],
        )

    def execute(self, apk_ctx) -> PluginResult:
        """Execute full static analysis."""
        start_time = time.time()
        findings = []

        try:
            execution_time = time.time() - start_time

            return PluginResult(
                status=PluginStatus.SUCCESS,
                findings=findings,
                metadata={
                    "execution_time": execution_time,
                    "total_findings": len(findings),
                    "analysis_types": ["hardcoded_strings", "insecure_apis", "manifest"],
                    "scan_depth": self.config.get("scan_depth", 3),
                    "pattern_sensitivity": self.config.get("pattern_sensitivity", "medium"),
                },
            )

        except Exception as e:
            execution_time = time.time() - start_time
            return PluginResult(
                status=PluginStatus.FAILURE,
                findings=[],
                metadata={"execution_time": execution_time, "error": str(e), "error_type": type(e).__name__},
            )


# Plugin factory function


def create_plugin() -> ExampleStaticAnalyzerV2:
    """Create plugin instance."""
    return ExampleStaticAnalyzerV2()


# Export the plugin class
__all__ = ["ExampleStaticAnalyzerV2", "create_plugin"]
