"""
core.cli - Decomposed modules from dyna.py (Track 46).

Provides the CLI orchestration layer for AODS. The main entry point
remains ``dyna.py``; this package houses the extracted subsystems.
"""

from pathlib import Path

# Canonical project root, used by all cli modules to resolve config/plugin paths.
# core/cli/__init__.py  →  parents[2]  →  project root
REPO_ROOT = Path(__file__).resolve().parents[2]
