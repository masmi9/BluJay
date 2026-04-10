"""
core.agent.report_lock - Shared lock for concurrent report file writes.

When the pipeline runs agents in parallel (e.g., triage + verify), multiple
agents may attempt read-modify-write on the same report JSON simultaneously.
This module provides a single process-wide lock to serialise those writes.

Usage:
    from core.agent.report_lock import report_write_lock

    with report_write_lock:
        # read report, modify, write back
"""

from __future__ import annotations

import threading

# Process-wide lock for report file read-modify-write cycles.
# All save_*_to_report() and _write_pipeline_context() must acquire this.
report_write_lock = threading.Lock()
