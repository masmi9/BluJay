"""
core.autoresearch.safety - Config backup, validation, rollback, signal handling.

Safety invariants:
1. Backup created before any experiment begins
2. All params validated against bounds before application
3. Atomic config writes (.tmp + os.rename())
4. Auto-revert on scan failure
5. SIGINT/SIGTERM handler restores original config
"""

from __future__ import annotations

import signal
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)

from .config import ParameterBounds
from .parameter_space import REPO_ROOT, THRESHOLDS_PATH, VULN_PATTERNS_PATH

BACKUP_DIR = REPO_ROOT / "data" / "autoresearch" / "backups"


def create_backup() -> Path:
    """Copy current config files to a timestamped backup directory.

    Returns:
        Path to the backup directory.
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = BACKUP_DIR / ts
    backup_path.mkdir(parents=True, exist_ok=True)

    for src in (THRESHOLDS_PATH, VULN_PATTERNS_PATH):
        if src.exists():
            shutil.copy2(str(src), str(backup_path / src.name))

    logger.info("backup_created", path=str(backup_path))
    return backup_path


def restore_backup(backup_path: Path) -> None:
    """Restore config files from a backup directory."""
    if not backup_path.is_dir():
        raise FileNotFoundError(f"Backup directory not found: {backup_path}")

    for filename, dest in [
        ("ml_thresholds.json", THRESHOLDS_PATH),
        ("vulnerability_patterns.yaml", VULN_PATTERNS_PATH),
    ]:
        src = backup_path / filename
        if src.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dest))

    logger.info("backup_restored", path=str(backup_path))


def get_latest_backup() -> Optional[Path]:
    """Find the most recent backup directory."""
    if not BACKUP_DIR.exists():
        return None
    backups = sorted(BACKUP_DIR.iterdir(), reverse=True)
    for b in backups:
        if b.is_dir():
            return b
    return None


def validate_params(
    params: Dict[str, float],
    bounds: List[ParameterBounds],
) -> List[str]:
    """Validate parameter values against their bounds.

    Returns:
        List of violation messages. Empty list = all valid.
    """
    violations = []
    bounds_by_name = {b.name: b for b in bounds}

    for name, value in params.items():
        bound = bounds_by_name.get(name)
        if bound is None:
            violations.append(f"Unknown parameter: {name}")
            continue

        if value < bound.min_value:
            violations.append(
                f"{name}={value:.4f} below minimum {bound.min_value:.4f}"
            )
        if value > bound.max_value:
            violations.append(
                f"{name}={value:.4f} above maximum {bound.max_value:.4f}"
            )

    return violations


_original_handlers: Dict[int, Any] = {}
_restore_callback: Optional[Callable] = None


def install_signal_handler(original_snapshot: Dict[str, Any]) -> None:
    """Install SIGINT/SIGTERM handler that restores original config on abort."""
    from .parameter_space import revert_to

    def _handler(signum: int, frame: Any) -> None:
        sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
        logger.warning("signal_received", signal=sig_name, msg="Restoring original config")
        try:
            revert_to(original_snapshot)
            logger.info("config_restored_on_signal", signal=sig_name)
        except Exception as e:
            logger.error("restore_on_signal_failed", error=str(e))
        # Re-raise with original handler
        original = _original_handlers.get(signum)
        if original and callable(original):
            original(signum, frame)
        else:
            raise SystemExit(1)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            _original_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, _handler)
        except (OSError, ValueError):
            pass

    global _restore_callback
    _restore_callback = lambda: revert_to(original_snapshot)  # noqa: E731


def uninstall_signal_handler() -> None:
    """Restore original signal handlers."""
    for sig, handler in _original_handlers.items():
        try:
            signal.signal(sig, handler)
        except (OSError, ValueError):
            pass
    _original_handlers.clear()

    global _restore_callback
    _restore_callback = None
