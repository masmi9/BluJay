# core/analyzer.py
import os
from typing import Callable, Dict, List

# Robust imports that work when running from project root (preferred)
try:
    from languages.python.py_parser import run_analysis as run_py_analysis
except ModuleNotFoundError:
    # Fallback if someone runs from a subdir; requires package-relative context
    from ..languages.python.py_parser import run_analysis as run_py_analysis  # type: ignore

try:
    from languages.java.java_parser import run_analysis as run_java_analysis
except ModuleNotFoundError:
    from ..languages.java.java_parser import run_analysis as run_java_analysis  # type: ignore


EXCLUDE_DIRS = {".git", ".hg", ".svn", ".idea", ".vscode", ".venv", "venv", "__pycache__", "node_modules", "build", "dist"}


class Analyzer:
    def __init__(self, language: str):
        self.language = (language or "").lower().strip()

        # Map language to analyzer function and extension(s)
        self.analyzers: Dict[str, Callable[[str], List[dict]]] = {
            "python": run_py_analysis,
            "java": run_java_analysis,
        }
        self.extensions: Dict[str, tuple] = {
            "python": (".py",),
            "java": (".java",),
        }

        if self.language not in self.analyzers:
            raise ValueError(f"Unsupported language: {self.language}. Supported: {', '.join(self.analyzers.keys())}")

    def _should_skip_dir(self, dirname: str) -> bool:
        base = os.path.basename(dirname)
        return base in EXCLUDE_DIRS or base.startswith(".")

    def run(self, input_path: str) -> List[dict]:
        analyzer_func = self.analyzers[self.language]
        exts = self.extensions[self.language]
        results: List[dict] = []

        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input path does not exist: {input_path}")

        # If a single file was passed, analyze it directly (when extension matches)
        if os.path.isfile(input_path):
            if input_path.endswith(exts):
                try:
                    results.extend(analyzer_func(input_path))
                except Exception as e:
                    # Don’t explode the whole run on one bad file
                    results.append({"file": input_path, "error": f"Analyzer error: {e}"})
            return results

        # Otherwise, walk a directory
        for root, dirs, files in os.walk(input_path):
            # Prune noisy dirs
            dirs[:] = [d for d in dirs if not self._should_skip_dir(os.path.join(root, d))]

            for fname in files:
                if not fname.endswith(exts):
                    continue
                full_path = os.path.join(root, fname)
                try:
                    results.extend(analyzer_func(full_path))
                except Exception as e:
                    results.append({"file": full_path, "error": f"Analyzer error: {e}"})
        return results
