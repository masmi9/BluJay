"""
AODS Plugin Package

This package contains all security analysis plugins for the Automated OWASP Dynamic Scan framework.
Each plugin is designed to detect specific types of vulnerabilities in Android applications.

Plugin Structure:
- Directory-based plugins: Each plugin has its own directory with __init__.py
- Single-file plugins: Standalone .py files with run_plugin() function
- All plugins should implement the standard AODS plugin interface
"""

# AODS Plugin Facade initialized - Phase 0 structure ready for Phase 3 implementation
import logging

logger = logging.getLogger(__name__)
logger.info("AODS Plugin Facade initialized - Phase 0 structure ready for Phase 3 implementation")
