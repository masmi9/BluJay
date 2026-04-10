"""EVRE Evidence Mixin – enrich findings with code snippets and context."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List


class EVREEvidenceMixin:
    def _enrich_evidence(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add surrounding code context to each finding."""
        for finding in findings:
            file_path = finding.get("file_path")
            line_no = finding.get("line_number")
            if file_path and line_no:
                context = self._get_code_context(Path(file_path), line_no, context_lines=3)
                if context:
                    finding["evidence"]["code_context"] = context
        return findings

    def _get_code_context(self, file_path: Path, line_no: int, context_lines: int = 3) -> str:
        """Extract surrounding lines around a finding."""
        try:
            if not file_path.exists():
                return ""
            lines = file_path.read_text(errors="replace").splitlines()
            start = max(0, line_no - context_lines - 1)
            end = min(len(lines), line_no + context_lines)
            context_block = []
            for i, line in enumerate(lines[start:end], start=start + 1):
                prefix = ">>>" if i == line_no else "   "
                context_block.append(f"{prefix} {i:4}: {line}")
            return "\n".join(context_block)
        except Exception:
            return ""
