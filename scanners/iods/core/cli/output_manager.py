"""
IODS OutputManager – Rich console output for scan progress and results.
"""
from __future__ import annotations

import sys
from typing import Any, Dict, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from core.logging_config import get_logger

logger = get_logger(__name__)

_SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "blue",
}


class OutputManager:
    """Manages console output during a scan."""

    def __init__(self, verbose: bool = False, quiet: bool = False) -> None:
        self.verbose = verbose
        self.quiet = quiet
        self._console = Console(stderr=True) if RICH_AVAILABLE else None

    def _print(self, msg: str, style: str = "") -> None:
        if self.quiet:
            return
        if RICH_AVAILABLE and self._console:
            self._console.print(msg, style=style)
        else:
            print(msg, file=sys.stderr)

    def banner(self, version: str = "1.0.0") -> None:
        if self.quiet:
            return
        msg = f"IODS v{version} – iOS Security Analysis Framework"
        if RICH_AVAILABLE and self._console:
            self._console.print(Panel(msg, style="bold blue"))
        else:
            print("=" * 60, file=sys.stderr)
            print(msg, file=sys.stderr)
            print("=" * 60, file=sys.stderr)

    def scan_start(self, ipa_path: str, mode: str, profile: str) -> None:
        self._print(f"[bold]Target:[/bold] {ipa_path}", "")
        self._print(f"[bold]Mode:[/bold]   {mode}   [bold]Profile:[/bold] {profile}", "")

    def plugin_progress(self, name: str, status: str, elapsed: float, findings: int) -> None:
        if not self.verbose:
            return
        color = "green" if status == "success" else "red"
        self._print(
            f"  [{color}]{status:12}[/{color}] {name:<40} {elapsed:5.1f}s  {findings} findings"
        )

    def scan_complete(self, summary: Dict[str, Any]) -> None:
        counts = summary.get("severity_counts", {})
        total = summary.get("total_findings", 0)
        self._print(f"\n[bold]Scan complete[/bold] – {total} findings total", "")
        for sev in ("critical", "high", "medium", "low", "info"):
            n = counts.get(sev, 0)
            if n > 0:
                color = _SEVERITY_COLORS.get(sev, "white")
                self._print(f"  [{color}]{sev.upper():10}[/{color}] {n}")

    def report_saved(self, path: str) -> None:
        self._print(f"[green]Report:[/green] {path}")

    def error(self, msg: str) -> None:
        self._print(f"[bold red]ERROR:[/bold red] {msg}")

    def warning(self, msg: str) -> None:
        if not self.quiet:
            self._print(f"[yellow]WARN:[/yellow] {msg}")

    def info(self, msg: str) -> None:
        if self.verbose:
            self._print(f"[blue]INFO:[/blue] {msg}")
