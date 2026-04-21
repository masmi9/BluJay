"""
IODS Execution Orchestrator – run_main() entry point.
"""
from __future__ import annotations

import sys

from core.logging_config import get_logger
from core.cli.execution_setup import initialize_execution

logger = get_logger(__name__)


def run_main(args) -> int:
    """
    Main execution entry point. Dispatches to standard or batch scan.

    Returns exit code.
    """
    ctx = initialize_execution(args)

    # Validate inputs
    if not getattr(args, "ipa", None) and not getattr(args, "batch_targets", None):
        ctx.output_mgr.error("No input specified. Use --ipa <path> or --batch-targets <file>.")
        return 2

    # Batch mode
    if getattr(args, "batch_targets", None):
        return _run_batch(ctx)

    # Single IPA scan
    from core.cli.execution_standard import run_standard_scan
    return run_standard_scan(ctx)


def _run_batch(ctx) -> int:
    """Run analysis on multiple IPA files from a targets file."""
    import os
    from pathlib import Path
    from core.cli.execution_standard import run_standard_scan

    targets_file = Path(ctx.args.batch_targets)
    if not targets_file.exists():
        ctx.output_mgr.error(f"Batch targets file not found: {targets_file}")
        return 2

    targets = [
        line.strip() for line in targets_file.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

    if not targets:
        ctx.output_mgr.error("No targets found in batch file.")
        return 2

    logger.info("Starting batch scan", count=len(targets))
    exit_code = 0

    for ipa_path in targets:
        if not os.path.exists(ipa_path):
            ctx.output_mgr.warning(f"IPA not found, skipping: {ipa_path}")
            continue
        ctx.args.ipa = ipa_path
        rc = run_standard_scan(ctx)
        if rc != 0:
            exit_code = rc

    return exit_code
