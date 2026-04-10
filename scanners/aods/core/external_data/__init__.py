"""
AODS External Data Integration Pipeline
======================================

Full external data integration framework providing:
- CVE/NVD vulnerability database integration
- Threat intelligence feed processing
- External security dataset ingestion
- Data quality validation and enrichment
- Real-time data synchronization and caching
- Intelligence-enhanced vulnerability detection

This framework completes the AODS security testing platform by integrating
external threat intelligence and vulnerability databases for enhanced
detection accuracy and contextual security analysis.
"""

__version__ = "1.0.0"
__author__ = "AODS Development Team"

from .cve_nvd_client import CVENVDClient
from .vulnerability_database import VulnerabilityDatabase
from .pipeline_manager import ExternalDataPipelineManager

# Core external data components
__all__ = [
    "CVENVDClient",
    "VulnerabilityDatabase",
    "ExternalDataPipelineManager",
]

# Framework metadata
FRAMEWORK_INFO = {
    "name": "AODS External Data Integration Pipeline",
    "version": __version__,
    "description": "Full external threat intelligence and vulnerability data integration",
    "components": [
        "CVE/NVD Integration",
        "Threat Intelligence Processing",
        "External Dataset Pipeline",
        "Data Quality Validation",
        "Incremental Update System",
        "Intelligence Enrichment Engine",
    ],
    "data_sources": [
        "CVE/NVD Database",
        "MITRE ATT&CK Framework",
        "OWASP Vulnerability Database",
        "Exploit Database",
        "Malware Indicators",
        "Security Advisories",
        "Threat Intelligence Feeds",
    ],
}

# Configuration defaults
DEFAULT_CONFIG = {
    "cve_nvd": {
        "api_base_url": "https://services.nvd.nist.gov/rest/json",
        "api_version": "v2",
        "rate_limit": 50,  # requests per minute
        "update_interval": 3600,  # 1 hour
        "max_retry_attempts": 3,
        "request_timeout": 30,
    },
    "threat_intel": {
        "update_interval": 1800,  # 30 minutes
        "source_timeout": 60,
        "max_feed_size": "100MB",
        "quality_threshold": 0.7,
    },
    "data_pipeline": {
        "batch_size": 1000,
        "parallel_workers": 4,
        "cache_ttl": 86400,  # 24 hours
        "validation_strict": True,
    },
    "storage": {
        "database_path": "data/external_data.db",
        "cache_path": "data/external_cache",
        "backup_retention": 30,  # days
        "compression": True,
    },
}
