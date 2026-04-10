"""
IODS Feature Flags – environment-driven capability toggles.
"""
from __future__ import annotations

import os

# ML pipeline
ML_ENABLED = os.environ.get("IODS_DISABLE_ML", "0") not in ("1", "true", "yes")
ML_CACHE_ENABLED = os.environ.get("IODS_ML_CACHE", "1") == "1"
ML_FP_THRESHOLD = float(os.environ.get("IODS_ML_FP_THRESHOLD", "0.15"))

# Execution
RESOURCE_SAFE = os.environ.get("IODS_RESOURCE_SAFE", "0") == "1"
MAX_EXTERNAL_PROCS = int(os.environ.get("IODS_MAX_EXTERNAL_PROCS", "2"))
TOOL_EXECUTOR_THREADS = int(os.environ.get("IODS_TOOL_EXECUTOR_THREADS", "4"))
PARALLEL_WORKERS = int(os.environ.get("IODS_PARALLEL_WORKERS", "2"))

# Analysis toggles
STATIC_ONLY = os.environ.get("IODS_STATIC_ONLY", "0") == "1"
DYNAMIC_ENABLED = os.environ.get("IODS_DYNAMIC_ENABLE", "0") == "1"
FRIDA_ENABLE = os.environ.get("IODS_FRIDA_ENABLE", "0") == "1"

# App profile
APP_PROFILE = os.environ.get("IODS_APP_PROFILE", "production")

# Reporting
REFERENCE_ONLY = os.environ.get("IODS_REFERENCE_ONLY", "0") == "1"
TENANT_ID = os.environ.get("IODS_TENANT_ID", "default")

# Graceful shutdown
GRACEFUL_SHUTDOWN_AVAILABLE = False  # Simplified; can be extended

# Agent system
AGENT_ENABLED = os.environ.get("IODS_AGENT_ENABLE", "0") == "1"
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
